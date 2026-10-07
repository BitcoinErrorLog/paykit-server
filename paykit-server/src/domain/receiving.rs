//! Creator-authorized receiving details. These never contain spending keys.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const USDT_CHAIN_ID: &str = "42161";
pub const USDT_TOKEN: &str = "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9";
pub const USDT_ENDPOINT: &str = "usdt-arbitrum-address";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAccount {
    pub xpub: Zeroizing<String>,
    pub account_index: u32,
}

impl fmt::Debug for BitcoinAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BitcoinAccount(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UsdtAddress(String);

impl UsdtAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn endpoint(&self) -> serde_json::Value {
        serde_json::json!({"value": self.0, "chain_id": USDT_CHAIN_ID, "token": USDT_TOKEN})
    }
}

impl TryFrom<String> for UsdtAddress {
    type Error = InvalidUsdtAddress;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 42
            || !value.starts_with("0x")
            || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
            || value[2..].bytes().all(|byte| byte == b'0')
        {
            return Err(InvalidUsdtAddress);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

impl From<UsdtAddress> for String {
    fn from(value: UsdtAddress) -> Self {
        value.0
    }
}

impl fmt::Debug for UsdtAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UsdtAddress(<redacted>)")
    }
}

#[derive(Debug, Error)]
#[error("invalid Arbitrum USDT receiving address")]
pub struct InvalidUsdtAddress;
