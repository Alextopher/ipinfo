//   Copyright 2023 IPinfo library developers
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

//! Support for custom localization tables, which can be used to override the default tables.
//!
//! # Examples
//!
//! ```
//! use ipinfo::{Localization, BorrowedTables, CURRENCIES, CONTINENTS, FLAGS, COUNTRIES, EU, CountryFlag, CountryCurrency, Continent};
//! use std::{collections::HashMap, sync::Arc};
//!
//! // Example of how to provide custom localization backends.
//! struct ArcedTables {
//!     countries: Arc<HashMap<String, String>>,
//!     eu: Arc<Vec<String>>,
//!     flags: Arc<HashMap<String, CountryFlag>>,
//!     currencies: Arc<HashMap<String, CountryCurrency>>,
//!     continents: Arc<HashMap<String, Continent>>,
//! }
//!
//! impl Localization for ArcedTables {
//!    fn country_name(&self, country_code: &str) -> Option<&str> {
//!        self.countries.get(country_code).map(|s| s.as_str())
//!    }
//!
//!    fn is_eu(&self, country_code: &str) -> bool {
//!        self.eu.contains(&country_code.to_string())
//!    }
//!
//!    fn flag(&self, country_code: &str) -> Option<&CountryFlag> {
//!        self.flags.get(country_code)
//!    }
//!
//!    fn currency(&self, country_code: &str) -> Option<&CountryCurrency> {
//!        self.currencies.get(country_code)
//!    }
//!
//!    fn continent(&self, country_code: &str) -> Option<&Continent> {
//!        self.continents.get(country_code)
//!    }
//! }
//!
//! let tables = ArcedTables {
//!     countries: Arc::new(COUNTRIES.clone()),
//!     eu: Arc::new(EU.clone()),
//!     flags: Arc::new(FLAGS.clone()),
//!     currencies: Arc::new(CURRENCIES.clone()),
//!     continents: Arc::new(CONTINENTS.clone()),
//! };
//! ```

use std::collections::HashMap;

use crate::{Continent, CountryCurrency, CountryFlag};

pub trait Localization {
    fn country_name(&self, country_code: &str) -> Option<&str>;
    fn is_eu(&self, country_code: &str) -> bool;
    fn flag(&self, country_code: &str) -> Option<&CountryFlag>;
    fn currency(&self, country_code: &str) -> Option<&CountryCurrency>;
    fn continent(&self, country_code: &str) -> Option<&Continent>;
}

/// Specialization of `BorrowedLocalization` using 'static tables baked into the binary.
///
/// This is the default localization backend used by `IpInfo`.
pub type StaticTables = BorrowedTables<'static>;

/// Localization backed with borrowed tables.
#[derive(Debug)]
pub struct BorrowedTables<'a> {
    /// Mapping of country codes to country names
    pub countries: &'a HashMap<String, String>,

    /// List of EU countries
    pub eu: &'a [String],

    /// Mapping of country codes to their respective flag emoji and unicode
    pub flags: &'a HashMap<String, CountryFlag>,

    /// Mapping of currencies to their respective currency code and symbol
    pub currencies: &'a HashMap<String, CountryCurrency>,

    /// Mapping of country codes to their respective continent code and name
    pub continents: &'a HashMap<String, Continent>,
}

impl<'a> Default for BorrowedTables<'a> {
    fn default() -> Self {
        Self {
            countries: &crate::COUNTRIES,
            eu: &crate::EU,
            flags: &crate::FLAGS,
            currencies: &crate::CURRENCIES,
            continents: &crate::CONTINENTS,
        }
    }
}

impl<'a> Localization for BorrowedTables<'a> {
    /// Returns the name of the country for the given country code.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{Localization, StaticTables};
    ///
    /// let tables = StaticTables::default();
    /// assert_eq!(tables.country_name("US").unwrap(), "United States");
    /// assert_eq!(tables.country_name("UA").unwrap(), "Ukraine");
    /// ```
    fn country_name(&self, country_code: &str) -> Option<&str> {
        self.countries.get(country_code).map(|s| s.as_str())
    }

    /// Returns true if the given country code is in the EU.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{Localization, StaticTables};
    ///
    /// let tables = StaticTables::default();
    /// assert!(tables.is_eu("DE"));
    /// assert!(!tables.is_eu("UK"));
    /// ```
    fn is_eu(&self, country_code: &str) -> bool {
        self.eu.contains(&country_code.to_string())
    }

    /// Returns the flag emoji and unicode for the given country code.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{Localization, StaticTables};
    ///
    /// let tables = StaticTables::default();
    /// assert_eq!(tables.flag("US").unwrap().emoji, "🇺🇸");
    /// assert_eq!(tables.flag("UA").unwrap().unicode, "U+1F1FA U+1F1E6");
    /// ```
    fn flag(&self, country_code: &str) -> Option<&CountryFlag> {
        self.flags.get(country_code)
    }

    /// Returns the currency code and symbol for the given country code.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{Localization, StaticTables};
    ///
    /// let tables = StaticTables::default();
    /// assert_eq!(tables.currency("US").unwrap().code, "USD");
    /// assert_eq!(tables.currency("UA").unwrap().symbol, "₴");
    /// ```
    fn currency(&self, country_code: &str) -> Option<&CountryCurrency> {
        self.currencies.get(country_code)
    }

    /// Returns the continent code and name for the given country code.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipinfo::{Localization, StaticTables};
    ///
    /// let tables = StaticTables::default();
    /// assert_eq!(tables.continent("US").unwrap().code, "NA");
    /// assert_eq!(tables.continent("UA").unwrap().name, "Europe");
    /// assert_eq!(tables.continent("MG").unwrap().code, "AF");
    /// assert_eq!(tables.continent("MG").unwrap().name, "Africa");
    /// ```
    fn continent(&self, country_code: &str) -> Option<&Continent> {
        self.continents.get(country_code)
    }
}
