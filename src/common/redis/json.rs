//! Tiny serde_json wrapper — direct port of `RedisJson.java`.
//!
//! Java uses Jackson with `JavaTimeModule` + ISO-8601 dates and
//! `FAIL_ON_UNKNOWN_PROPERTIES = false`. serde_json already ignores unknown
//! fields by default; for `chrono::NaiveDateTime` we use serde's built-in
//! ISO-8601 representation (matches Jackson's output). The two codecs
//! round-trip cleanly so a snapshot written by either server can be read by
//! the other.

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn stringify<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("redis JSON serialize")
}

pub fn parse<T: DeserializeOwned>(raw: &str) -> Result<T> {
    serde_json::from_str(raw).context("redis JSON deserialize")
}
