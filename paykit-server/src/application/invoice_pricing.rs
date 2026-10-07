//! Fixed invoice rates and exact atomic payment amounts.

use alloy_primitives::U256;
use async_trait::async_trait;
use paykit_lib::ConversionRate;
use serde::Deserialize;
use time::OffsetDateTime;

use super::create_invoice::CreateInvoiceError;
use crate::domain::invoice::CriterionAsset;

const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
const MAX_RATE_AGE_SECONDS: i64 = 600;
const RATES_URL: &str = "https://api1.blocktank.to/api/fx/rates/btc";

#[async_trait]
pub trait ExchangeRates: Send + Sync {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError>;
}

/// The same BTC/USD feed and ten-minute freshness bound used by Bitkit.
pub struct BlocktankRates {
    client: reqwest::Client,
}
impl BlocktankRates {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

#[derive(Deserialize)]
struct Feed {
    tickers: Vec<Ticker>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ticker {
    base: String,
    quote: String,
    last_price: String,
    last_updated_at: i64,
}

impl Feed {
    fn usd_per_btc(self, now: OffsetDateTime) -> Result<String, CreateInvoiceError> {
        let mut rates = self
            .tickers
            .into_iter()
            .filter(|t| t.base == "BTC" && t.quote == "USD");
        let rate = rates.next().ok_or(CreateInvoiceError::Unavailable)?;
        let age = now.unix_timestamp_nanos() / 1_000_000 - i128::from(rate.last_updated_at);
        if rates.next().is_some()
            || age < 0
            || age > i128::from(MAX_RATE_AGE_SECONDS) * 1000
            || rate.last_price.bytes().filter(|b| *b != b'.').count() > 18
            || decimal_units(&rate.last_price, 18).is_err()
        {
            return Err(CreateInvoiceError::Unavailable);
        }
        Ok(rate.last_price)
    }
}

#[async_trait]
impl ExchangeRates for BlocktankRates {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError> {
        let mut response = self
            .client
            .get(RATES_URL)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?
        {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(CreateInvoiceError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<Feed>(&bytes)
            .map_err(|_| CreateInvoiceError::Unavailable)?
            .usd_per_btc(OffsetDateTime::now_utc())
    }
}

/// Rates are payment-asset units per one requested-asset unit.
pub fn conversion_rates(
    requested: CriterionAsset,
    bitcoin: bool,
    usdt: bool,
    usd_per_btc: Option<&str>,
) -> Result<Vec<ConversionRate>, CreateInvoiceError> {
    let mut rates = Vec::new();
    for (asset, enabled) in [(CriterionAsset::Btc, bitcoin), (CriterionAsset::Usdt, usdt)] {
        if !enabled || asset == requested {
            continue;
        }
        let value = if (requested == CriterionAsset::Btc) != (asset == CriterionAsset::Btc) {
            let price = decimal_units(usd_per_btc.ok_or(CreateInvoiceError::Unavailable)?, 18)?;
            let multiplier = if requested == CriterionAsset::Btc {
                price
            } else {
                let numerator = U256::from(RATE_SCALE) * U256::from(RATE_SCALE);
                let quotient = numerator / price;
                let remainder = numerator % price;
                // Both mobile platforms round reciprocal quotes half-even to 18 decimal places.
                quotient
                    + U256::from(
                        remainder * U256::from(2) > price
                            || (remainder * U256::from(2) == price
                                && quotient % U256::from(2) != U256::ZERO),
                    )
            };
            if multiplier == U256::ZERO {
                return Err(CreateInvoiceError::Unavailable);
            }
            format_rate(multiplier)
        } else {
            "1".to_owned()
        };
        rates.push(ConversionRate {
            asset: asset.as_str().to_ascii_lowercase(),
            value,
        });
    }
    Ok(rates)
}

fn format_rate(value: U256) -> String {
    let scale = U256::from(RATE_SCALE);
    let fraction = format!("{:018}", value % scale);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (value / scale).to_string()
    } else {
        format!("{}.{fraction}", value / scale)
    }
}

fn decimal_units(value: &str, decimals: u32) -> Result<U256, CreateInvoiceError> {
    let invalid = CreateInvoiceError::InvalidRequest;
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if value.len() > 80
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > decimals as usize
    {
        return Err(invalid);
    }
    let whole = U256::from_str_radix(whole, 10).map_err(|_| invalid)?;
    let fraction = if fraction.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(fraction, 10).map_err(|_| invalid)?
            * U256::from(10).pow(U256::from(decimals as usize - fraction.len()))
    };
    let units = whole
        .checked_mul(U256::from(10).pow(U256::from(decimals)))
        .and_then(|v| v.checked_add(fraction))
        .ok_or(invalid)?;
    if units == U256::ZERO {
        return Err(invalid);
    }
    Ok(units)
}

/// Computes the payment from the published quote, rounding up to the selected endpoint's unit.
pub fn payment_units(
    amount: &str,
    requested: CriterionAsset,
    payment: CriterionAsset,
    rates: &[ConversionRate],
) -> Result<u64, CreateInvoiceError> {
    let units = decimal_units(amount, requested.decimals())?;
    let multiplier = if requested == payment {
        U256::from(RATE_SCALE)
    } else {
        let rate = rates
            .iter()
            .find(|rate| rate.asset == payment.as_str().to_ascii_lowercase())
            .ok_or(CreateInvoiceError::InvalidRequest)?;
        decimal_units(&rate.value, 18)?
    };
    let numerator = units
        .checked_mul(multiplier)
        .and_then(|v| v.checked_mul(U256::from(10).pow(U256::from(payment.decimals()))))
        .ok_or(CreateInvoiceError::InvalidRequest)?;
    let denominator = U256::from(RATE_SCALE) * U256::from(10).pow(U256::from(requested.decimals()));
    let result = numerator / denominator + U256::from(numerator % denominator != U256::ZERO);
    u64::try_from(result).map_err(|_| CreateInvoiceError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_define_exact_payment_units_for_each_accepted_asset() {
        for (requested, amount, btc, usdt) in [
            (CriterionAsset::Usd, "5.00", 6_173, 5_000_000),
            (CriterionAsset::Usdt, "5.000000", 6_173, 5_000_000),
            (CriterionAsset::Btc, "0.00000001", 1, 810),
        ] {
            let rates = conversion_rates(requested, true, true, Some("81000")).unwrap();
            assert_eq!(
                payment_units(amount, requested, CriterionAsset::Btc, &rates),
                Ok(btc)
            );
            assert_eq!(
                payment_units(amount, requested, CriterionAsset::Usdt, &rates),
                Ok(usdt)
            );
        }
        let rates = conversion_rates(CriterionAsset::Usd, false, true, None).unwrap();
        assert_eq!(rates[0].value, "1");
        assert!(conversion_rates(CriterionAsset::Usd, true, true, None).is_err());
        assert!(
            payment_units(
                "18446744073709551615",
                CriterionAsset::Usd,
                CriterionAsset::Usdt,
                &rates
            )
            .is_err()
        );
    }

    #[test]
    fn feed_requires_one_positive_fresh_btc_usd_rate() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        for (price, age, valid) in [
            ("81000.12", 0, true),
            ("81000", 600_000, true),
            ("81000", 600_001, false),
            ("81000", -1, false),
            ("0", 0, false),
            ("-2", 0, false),
            ("1e5", 0, false),
            ("1234567890123456789", 0, false),
        ] {
            let feed = Feed {
                tickers: vec![Ticker {
                    base: "BTC".into(),
                    quote: "USD".into(),
                    last_price: price.into(),
                    last_updated_at: 1_700_000_000_000 - age,
                }],
            };
            assert_eq!(feed.usd_per_btc(now).is_ok(), valid, "{price}, {age}");
        }
    }
}
