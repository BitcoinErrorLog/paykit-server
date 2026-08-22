use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    body::to_bytes,
    extract::{FromRequest, Request},
    http::header::HeaderName,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::{config::Config, http::error::ApiError};

const SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-paykit-signature");

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

pub trait AuthProcessingObserver: Send + Sync + 'static {
    fn signature_verification_started(&self);
    fn canonicalization_started(&self);
}

struct NoopAuthProcessingObserver;

impl AuthProcessingObserver for NoopAuthProcessingObserver {
    fn signature_verification_started(&self) {}

    fn canonicalization_started(&self) {}
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub struct SignedLocksAuth {
    /// Every key allowed to sign business requests: the Lock Server's key,
    /// plus the marketplace transaction service's key when configured. A
    /// request is authentic when any trusted key verifies its signature.
    trusted_keys: Vec<VerifyingKey>,
    request_body_bytes: usize,
    limiter: Mutex<TokenBucket>,
    clock: Arc<dyn Clock>,
    observer: Arc<dyn AuthProcessingObserver>,
}

impl fmt::Debug for SignedLocksAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedLocksAuth")
            .field("trusted_keys", &"<redacted>")
            .field("request_body_bytes", &self.request_body_bytes)
            .finish_non_exhaustive()
    }
}

impl SignedLocksAuth {
    pub fn from_config(config: &Config) -> Self {
        Self::with_clock_and_observer(
            config,
            Arc::new(SystemClock),
            Arc::new(NoopAuthProcessingObserver),
        )
    }

    pub fn with_clock(config: &Config, clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_observer(config, clock, Arc::new(NoopAuthProcessingObserver))
    }

    #[doc(hidden)]
    pub fn with_observer(config: &Config, observer: Arc<dyn AuthProcessingObserver>) -> Self {
        Self::with_clock_and_observer(config, Arc::new(SystemClock), observer)
    }

    fn with_clock_and_observer(
        config: &Config,
        clock: Arc<dyn Clock>,
        observer: Arc<dyn AuthProcessingObserver>,
    ) -> Self {
        let now = clock.now();
        let mut trusted_keys = vec![config.locks.trusted_public_key.verifying_key()];
        if let Some(marketplace) = &config.marketplace {
            trusted_keys.push(marketplace.trusted_public_key.verifying_key());
        }
        Self {
            trusted_keys,
            request_body_bytes: usize::try_from(config.limits.request_body_bytes)
                .expect("validated request body limit fits usize"),
            limiter: Mutex::new(TokenBucket::new(
                config.rate_limits.signed_requests_per_second,
                config.rate_limits.signed_burst,
                now,
            )),
            clock,
            observer,
        }
    }

    fn permit(&self) -> bool {
        self.limiter
            .lock()
            .expect("signed request rate limiter mutex is not poisoned")
            .try_take(self.clock.now())
    }
}

struct TokenBucket {
    rate_per_second: u64,
    burst: u64,
    tokens: u64,
    remainder: u128,
    last: Instant,
}

impl TokenBucket {
    fn new(rate_per_second: u64, burst: u64, now: Instant) -> Self {
        Self {
            rate_per_second,
            burst,
            tokens: burst,
            remainder: 0,
            last: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        if self.tokens == self.burst {
            self.remainder = 0;
        } else {
            let elapsed_nanos = elapsed.as_nanos();
            let accrued = elapsed_nanos
                .saturating_mul(u128::from(self.rate_per_second))
                .saturating_add(self.remainder);
            let added = accrued / 1_000_000_000;
            self.remainder = accrued % 1_000_000_000;
            self.tokens = self
                .tokens
                .saturating_add(u64::try_from(added).unwrap_or(u64::MAX))
                .min(self.burst);
            if self.tokens == self.burst {
                self.remainder = 0;
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

pub struct AuthenticatedJson<T>(pub T);

impl<S, T> FromRequest<S> for AuthenticatedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        let auth = request
            .extensions()
            .get::<Arc<SignedLocksAuth>>()
            .cloned()
            .ok_or(ApiError::InvalidSignature)?;
        let (parts, body) = request.into_parts();
        let limit = auth.request_body_bytes;
        let raw_body = to_bytes(body, limit.saturating_add(1))
            .await
            .map_err(|_| ApiError::PayloadTooLarge)?;
        if raw_body.len() > limit {
            return Err(ApiError::PayloadTooLarge);
        }
        auth.observer.signature_verification_started();
        verify_signature(&auth.trusted_keys, &parts.headers, &raw_body)?;

        let value: serde_json::Value =
            serde_json::from_slice(&raw_body).map_err(|_| ApiError::InvalidRequest)?;
        auth.observer.canonicalization_started();
        let canonical =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| ApiError::InvalidRequest)?;
        if canonical != raw_body {
            return Err(ApiError::InvalidRequest);
        }
        let mut ignored_path = None;
        let mut deserializer = serde_json::Deserializer::from_slice(&raw_body);
        let payload = serde_ignored::deserialize(&mut deserializer, |path| {
            ignored_path = Some(path.to_string());
        })
        .map_err(|_| ApiError::InvalidRequest)?;
        if ignored_path.is_some() {
            return Err(ApiError::InvalidRequest);
        }
        if !auth.permit() {
            return Err(ApiError::RateLimited);
        }
        Ok(Self(payload))
    }
}

fn verify_signature(
    trusted_keys: &[VerifyingKey],
    headers: &axum::http::HeaderMap,
    raw_body: &[u8],
) -> Result<(), ApiError> {
    let signatures = headers.get_all(&SIGNATURE_HEADER);
    if signatures.iter().count() != 1 {
        return Err(ApiError::InvalidSignature);
    }
    let encoded = signatures
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidSignature)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| ApiError::InvalidSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ApiError::InvalidSignature)?;
    if URL_SAFE_NO_PAD.encode(signature) != encoded {
        return Err(ApiError::InvalidSignature);
    }
    let signature = Signature::from_bytes(&signature);
    trusted_keys
        .iter()
        .any(|key| key.verify(raw_body, &signature).is_ok())
        .then_some(())
        .ok_or(ApiError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn token_bucket_refills_fractionally_without_exceeding_burst() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(2, 2, start);
        assert!(bucket.try_take(start));
        assert!(bucket.try_take(start));
        assert!(!bucket.try_take(start));
        assert!(bucket.try_take(start + Duration::from_millis(500)));
        assert!(!bucket.try_take(start + Duration::from_millis(500)));
    }

    #[test]
    fn reaching_burst_discards_fractional_refill_time() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(2, 2, start);

        assert!(bucket.try_take(start));
        assert!(bucket.try_take(start + Duration::from_millis(750)));
        assert!(bucket.try_take(start + Duration::from_millis(750)));
        assert!(!bucket.try_take(start + Duration::from_secs(1)));
        assert!(bucket.try_take(start + Duration::from_millis(1250)));
    }
}
