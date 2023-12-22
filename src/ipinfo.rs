//   Copyright 2019-2024 IPinfo library developers
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use std::{collections::HashMap, num::NonZeroUsize, time::Duration};

use crate::{
    cache_key, is_bogon,
    localization::{Localization, StaticTables},
    IpDetails, IpError, BATCH_MAX_SIZE, BATCH_REQ_TIMEOUT_DEFAULT, VERSION,
};

use lru::LruCache;
use serde_json::json;

use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE, USER_AGENT,
};

use tokio::time::timeout;

const COUNTRY_FLAG_URL: &str =
    "https://cdn.ipinfo.io/static/images/countries-flags/";

const BASE_URL: &str = "https://ipinfo.io";
const BASE_URL_V6: &str = "https://v6.ipinfo.io";

/// IpInfo structure configuration.
pub struct IpInfoConfig {
    /// IPinfo access token.
    pub token: Option<String>,

    /// The timeout of HTTP requests. (default: 3 seconds)
    pub timeout: Duration,

    /// The size of the LRU cache. (default: 100 IPs)
    pub cache_size: usize,
}

impl Default for IpInfoConfig {
    fn default() -> Self {
        Self {
            token: None,
            timeout: Duration::from_secs(3),
            cache_size: 100,
        }
    }
}

/// IpInfo.io requests context structure.
pub struct IpInfo<T: Localization = StaticTables> {
    token: Option<String>,
    client: reqwest::Client,
    cache: LruCache<String, IpDetails>,
    localization: T,
}

pub struct BatchReqOpts {
    batch_size: u64,
    timeout_per_batch: Duration,
    timeout_total: Option<Duration>,
}

impl Default for BatchReqOpts {
    fn default() -> Self {
        Self {
            batch_size: BATCH_MAX_SIZE,
            timeout_per_batch: BATCH_REQ_TIMEOUT_DEFAULT,
            timeout_total: None,
        }
    }
}

impl IpInfo<StaticTables> {
    /// Construct a new IpInfo structure with custom configuration and default localization tables.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::IpInfo;
    ///
    /// let ipinfo = IpInfo::new(Default::default()).expect("should construct");
    /// ```
    pub fn new(config: IpInfoConfig) -> Result<Self, IpError> {
        Self::new_with_localization_tables(config, StaticTables::default())
    }

    /// Construct a new IpInfo structure with default configuration and default localization tables.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::IpInfo;
    ///
    /// let ipinfo = IpInfo::with_defaults().expect("should construct");
    /// ```
    pub fn with_defaults() -> Result<Self, IpError> {
        Self::new(Default::default())
    }
}

impl<T: Localization> IpInfo<T> {
    /// Construct a new IpInfo structure with custom configuration and localization tables.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{IpInfo, BorrowedTables};
    ///
    /// // Custom EU countries
    /// let eu = vec!["DE".to_string(), "FR".to_string()];
    /// let localization = BorrowedTables {
    ///     eu: &eu,
    ///     ..Default::default()
    /// };
    ///
    /// let ipinfo = IpInfo::new_with_localization_tables(Default::default(), localization).expect("should construct");
    /// ```
    pub fn new_with_localization_tables(
        config: IpInfoConfig,
        localization: T,
    ) -> Result<Self, IpError> {
        let client =
            reqwest::Client::builder().timeout(config.timeout).build()?;

        let ipinfo_obj = Self {
            client,
            token: config.token,
            cache: LruCache::new(
                NonZeroUsize::new(config.cache_size).unwrap(),
            ),
            localization,
        };

        Ok(ipinfo_obj)
    }

    /// Lookup IPDetails for a list of one or more IP addresses.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipinfo::{IpInfo, BatchReqOpts};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut ipinfo = IpInfo::new(Default::default()).expect("should construct");
    ///     let res = ipinfo.lookup_batch(&["8.8.8.8"], BatchReqOpts::default()).await.expect("should run");
    /// }
    /// ```
    pub async fn lookup_batch(
        &mut self,
        ips: &[&str],
        batch_config: BatchReqOpts,
    ) -> Result<HashMap<String, IpDetails>, IpError> {
        // Handle the total timeout condition
        if let Some(total_timeout) = batch_config.timeout_total {
            match timeout(total_timeout, self._lookup_batch(ips, batch_config))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(err!(TimeOutError)),
            }
        } else {
            self._lookup_batch(ips, batch_config).await
        }
    }

    // Internal lookup_batch function. This ignores the total timeout condition
    async fn _lookup_batch(
        &mut self,
        ips: &[&str],
        batch_config: BatchReqOpts,
    ) -> Result<HashMap<String, IpDetails>, IpError> {
        let mut results: HashMap<String, IpDetails> = HashMap::new();

        // Collect a list of ips we need to lookup.
        // Filters out bogons and cache hits
        let mut work = vec![];
        for ip in ips.iter() {
            if is_bogon(ip) {
                results.insert(
                    ip.to_string(),
                    IpDetails {
                        ip: ip.to_string(),
                        bogon: Some(true),
                        ..Default::default()
                    },
                );
            } else if let Some(detail) = self.cache.get(&cache_key(ip)) {
                results.insert(ip.to_string(), detail.clone());
            } else {
                work.push(*ip);
            }
        }

        let client = reqwest::Client::builder()
            .timeout(batch_config.timeout_per_batch)
            .build()?;

        // Remove duplicates
        work.sort();
        work.dedup();

        // Make batched requests
        for batch in work.chunks(batch_config.batch_size as usize) {
            let response = self.batch_request(client.clone(), batch).await?;
            results.extend(response);
        }

        // Add country_name and EU status to response
        for detail in results.values_mut() {
            self.populate_static_details(detail);
        }

        // Update cache
        results
            .iter()
            .filter(|(ip, _)| !is_bogon(ip))
            .for_each(|x| {
                self.cache.put(cache_key(x.0.as_str()), x.1.clone());
            });

        Ok(results)
    }

    async fn batch_request(
        &self,
        client: reqwest::Client,
        ips: &[&str],
    ) -> Result<HashMap<String, IpDetails>, IpError> {
        // Lookup cache misses which are not bogon
        let response = client
            .post(&format!("{}/batch", BASE_URL))
            .headers(Self::construct_headers())
            .bearer_auth(self.token.as_deref().unwrap_or_default())
            .json(&json!(ips))
            .send()
            .await?;

        // Check if we exhausted our request quota
        if let reqwest::StatusCode::TOO_MANY_REQUESTS = response.status() {
            return Err(err!(RateLimitExceededError));
        }

        // Acquire response
        let raw_resp = response.error_for_status()?.text().await?;

        // Parse the response
        let resp: serde_json::Value = serde_json::from_str(&raw_resp)?;

        // Return if an error occurred
        if let Some(e) = resp["error"].as_str() {
            return Err(err!(IpRequestError, e));
        }

        // Parse the results
        let result: HashMap<String, IpDetails> =
            serde_json::from_str(&raw_resp)?;
        Ok(result)
    }

    /// looks up IPDetails for a single IP Address
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ipinfo::IpInfo;
    ///
    ///  #[tokio::main]
    /// async fn main() {
    ///     let mut ipinfo = IpInfo::new(Default::default()).expect("should construct");
    ///     let res = ipinfo.lookup("8.8.8.8").await.expect("should run");
    /// }
    /// ```
    pub async fn lookup(&mut self, ip: &str) -> Result<IpDetails, IpError> {
        self._lookup(ip, BASE_URL).await
    }

    /// looks up IPDetails of your own v4 IP
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ipinfo::IpInfo;
    ///
    ///  #[tokio::main]
    /// async fn main() {
    ///     let mut ipinfo = IpInfo::new(Default::default()).expect("should construct");
    ///     let res = ipinfo.lookup_self_v4().await.expect("should run");
    /// }
    /// ```
    pub async fn lookup_self_v4(&mut self) -> Result<IpDetails, IpError> {
        self._lookup("", BASE_URL).await
    }

    /// looks up IPDetails of your own v6 IP
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ipinfo::IpInfo;
    ///
    ///  #[tokio::main]
    /// async fn main() {
    ///     let mut ipinfo = IpInfo::new(Default::default()).expect("should construct");
    ///     let res = ipinfo.lookup_self_v6().await.expect("should run");
    /// }
    /// ```
    pub async fn lookup_self_v6(&mut self) -> Result<IpDetails, IpError> {
        self._lookup("", BASE_URL_V6).await
    }

    async fn _lookup(
        &mut self,
        ip: &str,
        base_url: &str,
    ) -> Result<IpDetails, IpError> {
        if is_bogon(ip) {
            return Ok(IpDetails {
                ip: ip.to_string(),
                bogon: Some(true),
                ..Default::default() // fill remaining with default values
            });
        }

        // Check for cache hit
        let cached_detail = self.cache.get(&cache_key(ip));

        if let Some(cached_detail) = cached_detail {
            return Ok(cached_detail.clone());
        }

        // lookup in case of a cache miss
        let response = self
            .client
            .get(&format!("{}/{}", base_url, ip))
            .headers(Self::construct_headers())
            .bearer_auth(self.token.as_deref().unwrap_or_default())
            .send()
            .await?;

        // Check if we exhausted our request quota
        if let reqwest::StatusCode::TOO_MANY_REQUESTS = response.status() {
            return Err(err!(RateLimitExceededError));
        }

        // Acquire response
        let raw_resp = response.error_for_status()?.text().await?;

        // Parse the response
        let resp: serde_json::Value = serde_json::from_str(&raw_resp)?;

        // Return if an error occurred
        if let Some(e) = resp["error"].as_str() {
            return Err(err!(IpRequestError, e));
        }

        // Parse the results and add additional country details
        let mut details: IpDetails = serde_json::from_str(&raw_resp)?;
        self.populate_static_details(&mut details);

        // update cache
        self.cache.put(cache_key(ip), details.clone());
        Ok(details)
    }

    /// Get a mapping of a list of IPs on a world map
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ipinfo::IpInfo;
    ///
    ///  #[tokio::main]
    /// async fn main() {
    ///     let ipinfo = IpInfo::new(Default::default()).expect("should construct");
    ///     let map_url = ipinfo.get_map(&["8.8.8.8", "4.2.2.4"]).await.expect("should run");
    /// }
    /// ```
    pub async fn get_map(&self, ips: &[&str]) -> Result<String, IpError> {
        if ips.len() > 500_000 {
            return Err(err!(MapLimitError));
        }

        let map_url = &format!("{}/tools/map?cli=1", BASE_URL);
        let client = self.client.clone();
        let json_ips = serde_json::json!(ips);

        let response = client.post(map_url).json(&json_ips).send().await?;
        if !response.status().is_success() {
            return Err(err!(HTTPClientError));
        }

        let response_json: serde_json::Value = response.json().await?;
        let report_url = response_json["reportUrl"]
            .as_str()
            .ok_or("Report URL not found");
        Ok(report_url.unwrap().to_string())
    }

    // Add country details and EU status to response
    fn populate_static_details(&self, details: &mut IpDetails) {
        if !details.country.is_empty() {
            let country_name: Option<&str> =
                self.localization.country_name(&details.country);
            details.country_name = country_name.map(|x| x.to_string());

            let is_eu = self.localization.is_eu(&details.country);
            details.is_eu = Some(is_eu);

            let flag = self.localization.flag(&details.country);
            details.country_flag = flag.cloned();

            details.country_flag_url =
                Some(format!("{}{}.svg", COUNTRY_FLAG_URL, &details.country));

            let currency = self.localization.currency(&details.country);
            details.country_currency = currency.cloned();

            let continent = self.localization.continent(&details.country);
            details.continent = continent.cloned();
        }
    }

    /// Construct API request headers.
    fn construct_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&format!("IPinfoClient/Rust/{}", VERSION))
                .unwrap(),
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Continent, CountryCurrency, CountryFlag, IpErrorKind};
    use std::env;

    fn get_ipinfo_client() -> IpInfo {
        IpInfo::new(IpInfoConfig {
            token: Some(env::var("IPINFO_TOKEN").unwrap().to_string()),
            timeout: Duration::from_secs(3),
            cache_size: 100,
        })
        .expect("should construct")
    }

    #[test]
    fn ipinfo_config_defaults_reasonable() {
        let ipinfo_config = IpInfoConfig::default();

        assert_eq!(ipinfo_config.timeout, Duration::from_secs(3));
        assert_eq!(ipinfo_config.cache_size, 100);
    }

    #[test]
    fn request_headers_are_canonical() {
        let headers = IpInfo::<StaticTables>::construct_headers();

        assert_eq!(
            headers[USER_AGENT],
            format!("IPinfoClient/Rust/{}", VERSION)
        );
        assert_eq!(headers[CONTENT_TYPE], "application/json");
        assert_eq!(headers[ACCEPT], "application/json");
    }

    #[tokio::test]
    async fn request_single_ip() {
        let mut ipinfo = get_ipinfo_client();

        let details =
            ipinfo.lookup("66.87.125.72").await.expect("should lookup");

        assert_eq!(details.ip, "66.87.125.72");
    }

    #[tokio::test]
    async fn request_no_token() {
        let mut ipinfo =
            IpInfo::new(Default::default()).expect("should construct");

        assert_eq!(
            ipinfo
                .lookup_batch(&["8.8.8.8"], BatchReqOpts::default())
                .await
                .err()
                .unwrap()
                .kind(),
            IpErrorKind::IpRequestError
        );
    }

    #[tokio::test]
    async fn request_multiple_ip() {
        let mut ipinfo = get_ipinfo_client();

        let details = ipinfo
            .lookup_batch(&["8.8.8.8", "4.2.2.4"], BatchReqOpts::default())
            .await
            .expect("should lookup");

        // Assert successful lookup
        assert!(details.contains_key("8.8.8.8"));
        assert!(details.contains_key("4.2.2.4"));

        // Assert 8.8.8.8
        let ip8 = &details["8.8.8.8"];
        assert_eq!(ip8.ip, "8.8.8.8");
        assert_eq!(ip8.hostname, Some("dns.google".to_owned()));
        assert_eq!(ip8.city, "Mountain View");
        assert_eq!(ip8.region, "California");
        assert_eq!(ip8.country, "US");
        assert_eq!(
            ip8.country_flag_url,
            Some(
                "https://cdn.ipinfo.io/static/images/countries-flags/US.svg"
                    .to_owned()
            )
        );
        assert_eq!(
            ip8.country_flag,
            Some(CountryFlag {
                emoji: "🇺🇸".to_owned(),
                unicode: "U+1F1FA U+1F1F8".to_owned()
            })
        );
        assert_eq!(
            ip8.country_currency,
            Some(CountryCurrency {
                code: "USD".to_owned(),
                symbol: "$".to_owned()
            })
        );
        assert_eq!(
            ip8.continent,
            Some(Continent {
                code: "NA".to_owned(),
                name: "North America".to_owned()
            })
        );
        assert_eq!(ip8.loc, "37.4056,-122.0775");
        assert_eq!(ip8.postal, Some("94043".to_owned()));
        assert_eq!(ip8.timezone, Some("America/Los_Angeles".to_owned()));

        // Assert 4.2.2.4
        let ip4 = &details["4.2.2.4"];
        assert_eq!(ip4.ip, "4.2.2.4");
        assert_eq!(ip4.hostname, Some("d.resolvers.level3.net".to_owned()));
        assert_eq!(ip4.city, "Monroe");
        assert_eq!(ip4.region, "Louisiana");
        assert_eq!(ip4.country, "US");
        assert_eq!(ip4.loc, "32.5530,-92.0422");
        assert_eq!(ip4.postal, Some("71203".to_owned()));
        assert_eq!(ip4.timezone, Some("America/Chicago".to_owned()));
    }

    #[tokio::test]
    async fn request_cache_miss_and_hit() {
        let mut ipinfo = get_ipinfo_client();

        // Populate the cache with 8.8.8.8
        let details = ipinfo
            .lookup_batch(&["8.8.8.8"], BatchReqOpts::default())
            .await
            .expect("should lookup");

        // Assert 1 result
        assert!(details.contains_key("8.8.8.8"));
        assert_eq!(details.len(), 1);

        // Should have a cache hit for 8.8.8.8 and query for 4.2.2.4
        let details = ipinfo
            .lookup_batch(&["4.2.2.4", "8.8.8.8"], BatchReqOpts::default())
            .await
            .expect("should lookup");

        // Assert 2 results
        assert!(details.contains_key("8.8.8.8"));
        assert!(details.contains_key("4.2.2.4"));
        assert_eq!(details.len(), 2);
    }
}
