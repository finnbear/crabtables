//! JSON (de)serialization of this crate's data types (feature `json`).
//!
//! The format is a direct serde representation of the typed objects
//! (tables, chains, rules with their expressions, sets, ...), which makes
//! it lossless: a [`Ruleset`] written as JSON and read back recreates the
//! exact same kernel objects. For JSON in the schema of `nft -j` (the nft
//! language), see the `lang` module (feature `lang_json`).

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::proto::Ruleset;

fn err(e: serde_json::Error) -> Error {
    Error::InvalidInput(e.to_string().into())
}

/// Serialize to compact JSON.
pub fn to_string<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(err)
}

/// Serialize to indented JSON.
pub fn to_string_pretty<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    serde_json::to_string_pretty(v).map_err(err)
}

/// Deserialize from JSON.
pub fn from_str<T: DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(err)
}

impl Ruleset {
    /// The ruleset as (indented) JSON.
    pub fn to_json(&self) -> Result<String> {
        to_string_pretty(self)
    }

    /// Read a ruleset written by [`Ruleset::to_json`].
    pub fn from_json(s: &str) -> Result<Ruleset> {
        from_str(s)
    }
}
