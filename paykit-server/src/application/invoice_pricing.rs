//! Fixed invoice rates and exact atomic payment amounts.

use alloy_primitives::U256;
use async_trait::async_trait;
use paykit_lib::ConversionRate;
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use super::create_invoice::CreateInvoiceError;
use crate::{
    config::{ExchangeRateConfig, ExchangeRateFormat},
    domain::invoice::CriterionAsset,
};

const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
const MAX_RATE_AGE_SECONDS: i64 = 600;
/// A fresh last-trade time can be a moment ahead of a server whose clock runs slightly slow.
const MAX_RATE_FUTURE_SKEW_SECONDS: i64 = 5;
const MAX_RATE_BODY_BYTES: usize = 1024 * 1024;
/// Rate ages are compared in nanoseconds: an `i64` millisecond or second count times
/// these factors cannot overflow `i128`.
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

#[async_trait]
pub trait ExchangeRates: Send + Sync {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError>;
}

/// The configured BTC/USD feed, Bitkit's Blocktank feed by default, with Bitkit's
/// ten-minute freshness bound.
pub struct FeedRates {
    client: reqwest::Client,
    url: Url,
    format: ExchangeRateFormat,
}
impl FeedRates {
    pub fn new(source: &ExchangeRateConfig) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            url: source.url.clone(),
            format: source.format,
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
        if rates.next().is_some() {
            return Err(CreateInvoiceError::Unavailable);
        }
        checked_rate(
            rate.last_price,
            i128::from(rate.last_updated_at) * NANOS_PER_MILLI,
            now,
        )
    }
}

#[derive(Deserialize)]
struct CoinbaseExchangeTicker {
    price: String,
    time: String,
}

impl CoinbaseExchangeTicker {
    fn usd_per_btc(self, now: OffsetDateTime) -> Result<String, CreateInvoiceError> {
        let traded_at = OffsetDateTime::parse(&self.time, &Rfc3339)
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        checked_rate(self.price, traded_at.unix_timestamp_nanos(), now)
    }
}

/// Accepts one positive decimal rate of at most 18 digits, updated no more than ten
/// minutes before `now` and at most [`MAX_RATE_FUTURE_SKEW_SECONDS`] after it.
fn checked_rate(
    price: String,
    updated_at_nanos: i128,
    now: OffsetDateTime,
) -> Result<String, CreateInvoiceError> {
    let age = now.unix_timestamp_nanos() - updated_at_nanos;
    if age < -i128::from(MAX_RATE_FUTURE_SKEW_SECONDS) * NANOS_PER_SECOND
        || age > i128::from(MAX_RATE_AGE_SECONDS) * NANOS_PER_SECOND
        || price.bytes().filter(|b| *b != b'.').count() > 18
        || decimal_units(&price, 18).is_err()
    {
        return Err(CreateInvoiceError::Unavailable);
    }
    Ok(price)
}

fn parse_usd_per_btc(
    format: ExchangeRateFormat,
    bytes: &[u8],
    now: OffsetDateTime,
) -> Result<String, CreateInvoiceError> {
    match format {
        ExchangeRateFormat::Blocktank => serde_json::from_slice::<Feed>(bytes)
            .map_err(|_| CreateInvoiceError::Unavailable)?
            .usd_per_btc(now),
        ExchangeRateFormat::CoinbaseExchange => {
            serde_json::from_slice::<CoinbaseExchangeTicker>(bytes)
                .map_err(|_| CreateInvoiceError::Unavailable)?
                .usd_per_btc(now)
        }
    }
}

#[async_trait]
impl ExchangeRates for FeedRates {
    async fn usd_per_btc(&self) -> Result<String, CreateInvoiceError> {
        let mut response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?;
        // Redirects are not followed, so a 3xx arrives here; its body is not a rate.
        if !response.status().is_success() {
            return Err(CreateInvoiceError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CreateInvoiceError::Unavailable)?
        {
            if bytes.len() + chunk.len() > MAX_RATE_BODY_BYTES {
                return Err(CreateInvoiceError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_usd_per_btc(self.format, &bytes, OffsetDateTime::now_utc())
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
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        extract::{OriginalUri, State},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
    };

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
            ("81000", -5_000, true),
            ("81000", -5_001, false),
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

    #[test]
    fn blocktank_feed_rejects_missing_or_duplicate_btc_usd_tickers() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ticker = |base: &str, quote: &str| {
            format!(
                r#"{{"base":"{base}","quote":"{quote}","lastPrice":"81000","lastUpdatedAt":1700000000000}}"#
            )
        };
        let feed = |tickers: &[String]| format!(r#"{{"tickers":[{}]}}"#, tickers.join(","));
        let parse =
            |body: String| parse_usd_per_btc(ExchangeRateFormat::Blocktank, body.as_bytes(), now);

        assert_eq!(
            parse(feed(&[ticker("BTC", "EUR"), ticker("BTC", "USD")])),
            Ok("81000".to_owned())
        );
        assert!(parse(feed(&[ticker("BTC", "EUR")])).is_err());
        assert!(parse(feed(&[ticker("BTC", "USD"), ticker("BTC", "USD")])).is_err());
    }

    #[test]
    fn coinbase_exchange_ticker_requires_one_positive_fresh_rate() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        for (price, time, valid) in [
            ("81000.12", "2023-11-14T22:13:20Z", true),
            ("81000.12", "2023-11-14T22:13:19.999999999Z", true),
            ("81000", "2023-11-14T22:03:20Z", true),
            ("81000", "2023-11-14T22:03:19.999Z", false),
            ("81000", "2023-11-14T22:13:25Z", true),
            ("81000", "2023-11-14T22:13:25.001Z", false),
            ("81000", "2023-11-14 22:13:20", false),
            ("0", "2023-11-14T22:13:20Z", false),
            ("-2", "2023-11-14T22:13:20Z", false),
            ("1e5", "2023-11-14T22:13:20Z", false),
            ("1234567890123456789", "2023-11-14T22:13:20Z", false),
        ] {
            let body = format!(
                r#"{{"ask":"1","bid":"1","volume":"1","trade_id":1,"price":"{price}","size":"1","time":"{time}"}}"#
            );
            assert_eq!(
                parse_usd_per_btc(ExchangeRateFormat::CoinbaseExchange, body.as_bytes(), now)
                    .is_ok(),
                valid,
                "{price}, {time}"
            );
        }
        for body in [
            r#"{"price":"81000"}"#,
            r#"{"time":"2023-11-14T22:13:20Z"}"#,
            "[]",
        ] {
            assert!(
                parse_usd_per_btc(ExchangeRateFormat::CoinbaseExchange, body.as_bytes(), now)
                    .is_err()
            );
        }
    }

    #[test]
    fn rate_age_bounds_hold_below_one_millisecond() {
        let at = |nanos: i128| OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap();
        let second = 1_000_000_000_i128;
        let now = 1_700_000_000 * second;

        let blocktank = |updated_at_millis: i64, now: i128| {
            Feed {
                tickers: vec![Ticker {
                    base: "BTC".into(),
                    quote: "USD".into(),
                    last_price: "81000".into(),
                    last_updated_at: updated_at_millis,
                }],
            }
            .usd_per_btc(at(now))
            .is_ok()
        };
        for (updated_at_millis, now, valid) in [
            (1_699_999_400_000, now, true),
            (1_699_999_400_000, now + 1, false),
            (1_699_999_400_000, now + 500_000, false),
            (1_699_999_400_001, now + 999_999, true),
            (1_700_000_005_000, now, true),
            (1_700_000_005_000, now - 1, false),
        ] {
            assert_eq!(
                blocktank(updated_at_millis, now),
                valid,
                "{updated_at_millis}, {now}"
            );
        }

        let coinbase = |time: &str, now: i128| {
            let body = format!(r#"{{"price":"81000","time":"{time}"}}"#);
            parse_usd_per_btc(
                ExchangeRateFormat::CoinbaseExchange,
                body.as_bytes(),
                at(now),
            )
            .is_ok()
        };
        for (time, now, valid) in [
            ("2023-11-14T22:13:25Z", now, true),
            ("2023-11-14T22:13:25.000000001Z", now, false),
            ("2023-11-14T22:13:25.000999999Z", now, false),
            ("2023-11-14T22:13:25.000999999Z", now + 999_999, true),
            ("2023-11-14T22:03:20.0009Z", now + 900_000, true),
            ("2023-11-14T22:03:20.0005Z", now + 900_000, false),
            ("2023-11-14T22:03:20.000000001Z", now + 2, false),
        ] {
            assert_eq!(coinbase(time, now), valid, "{time}, {now}");
        }
    }

    #[test]
    fn formats_do_not_accept_each_other() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let blocktank = r#"{"tickers":[{"base":"BTC","quote":"USD","lastPrice":"81000","lastUpdatedAt":1700000000000}]}"#;
        let coinbase = r#"{"price":"81000","time":"2023-11-14T22:13:20Z"}"#;
        assert!(
            parse_usd_per_btc(
                ExchangeRateFormat::CoinbaseExchange,
                blocktank.as_bytes(),
                now
            )
            .is_err()
        );
        assert!(
            parse_usd_per_btc(ExchangeRateFormat::Blocktank, coinbase.as_bytes(), now).is_err()
        );
    }

    #[derive(Clone, Default)]
    struct Requests(Arc<Mutex<Vec<String>>>);

    impl Requests {
        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    fn fresh_coinbase_ticker() -> String {
        let time = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        format!(r#"{{"price":"81000.12","time":"{time}"}}"#)
    }

    fn padded_to(mut body: String, len: usize) -> String {
        body.push_str(&" ".repeat(len - body.len()));
        body
    }

    async fn rate_source(State(requests): State<Requests>, uri: OriginalUri) -> Response {
        requests.0.lock().unwrap().push(uri.path().to_owned());
        match uri.path() {
            "/products/BTC-USD/ticker" => fresh_coinbase_ticker().into_response(),
            "/fx/btc" => format!(
                r#"{{"tickers":[{{"base":"BTC","quote":"USD","lastPrice":"79000","lastUpdatedAt":{}}}]}}"#,
                OffsetDateTime::now_utc().unix_timestamp() * 1000
            )
            .into_response(),
            "/redirect" => (
                StatusCode::FOUND,
                [(header::LOCATION, "/products/BTC-USD/ticker")],
                fresh_coinbase_ticker(),
            )
                .into_response(),
            "/at-cap" => padded_to(fresh_coinbase_ticker(), MAX_RATE_BODY_BYTES).into_response(),
            "/over-cap" => {
                padded_to(fresh_coinbase_ticker(), MAX_RATE_BODY_BYTES + 1).into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    #[tokio::test]
    async fn feed_fetches_the_configured_source_without_redirects_within_the_body_cap() {
        let requests = Requests::default();
        let app = Router::new()
            .fallback(rate_source)
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let rate = |path: &str, format| {
            let feed = FeedRates::new(&ExchangeRateConfig {
                url: Url::parse(&format!("{origin}{path}")).unwrap(),
                format,
            })
            .unwrap();
            async move { feed.usd_per_btc().await }
        };

        assert_eq!(
            rate(
                "/products/BTC-USD/ticker",
                ExchangeRateFormat::CoinbaseExchange
            )
            .await,
            Ok("81000.12".to_owned())
        );
        assert_eq!(requests.take(), ["/products/BTC-USD/ticker"]);
        assert_eq!(
            rate("/fx/btc", ExchangeRateFormat::Blocktank).await,
            Ok("79000".to_owned())
        );
        assert_eq!(requests.take(), ["/fx/btc"]);

        assert_eq!(
            rate("/redirect", ExchangeRateFormat::CoinbaseExchange).await,
            Err(CreateInvoiceError::Unavailable)
        );
        assert_eq!(requests.take(), ["/redirect"]);

        assert_eq!(
            rate("/at-cap", ExchangeRateFormat::CoinbaseExchange).await,
            Ok("81000.12".to_owned())
        );
        assert_eq!(
            rate("/over-cap", ExchangeRateFormat::CoinbaseExchange).await,
            Err(CreateInvoiceError::Unavailable)
        );
        assert_eq!(requests.take(), ["/at-cap", "/over-cap"]);
    }
}
