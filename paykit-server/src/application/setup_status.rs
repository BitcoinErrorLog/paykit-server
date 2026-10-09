use std::{sync::Arc, time::Duration};

use crate::{
    application::create_invoice::{
        CreatorReceivingProvider, SessionValidationError, SessionValidator,
    },
    domain::locks::CreatorPubky,
};

const STATUS_TIMEOUT: Duration = Duration::from_secs(15);

/// Coarse Locks-visible result for one Creator's Paykit setup authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStatus {
    Ready,
    SetupRequired,
    Unavailable,
}

impl SetupStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::SetupRequired => "setup_required",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Payment asset a Creator is asked to be able to receive.
///
/// This is not a price denomination: `USD` is a `CriterionAsset` but never an
/// accepted payment asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedAsset {
    Btc,
    Usdt,
}

impl AcceptedAsset {
    pub fn parse(value: &str) -> Result<Self, AcceptedAssetError> {
        match value {
            "BTC" => Ok(Self::Btc),
            "USDT" => Ok(Self::Usdt),
            _ => Err(AcceptedAssetError::Unsupported),
        }
    }
}

/// Error returned when an accepted payment asset is not `BTC` or `USDT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedAssetError {
    Unsupported,
}

/// Validates whether persisted Creator authority is currently usable.
pub struct SetupStatusService {
    sessions: Arc<dyn SessionValidator>,
    receiving: Option<Arc<dyn CreatorReceivingProvider>>,
    usdt_enabled: bool,
    timeout: Duration,
}

impl SetupStatusService {
    pub fn new(sessions: Arc<dyn SessionValidator>) -> Self {
        Self::with_timeout(sessions, STATUS_TIMEOUT)
    }

    #[doc(hidden)]
    pub fn with_timeout(sessions: Arc<dyn SessionValidator>, timeout: Duration) -> Self {
        Self {
            sessions,
            timeout,
            receiving: None,
            usdt_enabled: false,
        }
    }

    pub fn with_receiving(
        mut self,
        receiving: Arc<dyn CreatorReceivingProvider>,
        usdt_enabled: bool,
    ) -> Self {
        self.receiving = Some(receiving);
        self.usdt_enabled = usdt_enabled;
        self
    }

    /// Readiness for a Locks criterion denomination (`asset`).
    ///
    /// A `ready` answer means the Creator has any usable receiving detail, so a
    /// Bitcoin-only Creator is ready for a USDT-denominated criterion that Locks
    /// converts. Use [`Self::status_for_accepted_asset`] to ask whether the
    /// Creator can receive a specific payment asset.
    pub async fn status_for_asset(
        &self,
        creator: &CreatorPubky,
        asset: crate::domain::invoice::CriterionAsset,
    ) -> SetupStatus {
        self.status_for_requirements(creator, Some(asset), None)
            .await
    }

    /// Readiness to receive one payment asset: `BTC` needs an approved Bitcoin
    /// account and `USDT` needs an approved USDT address on a deployment that
    /// has `[usdt]` configured.
    pub async fn status_for_accepted_asset(
        &self,
        creator: &CreatorPubky,
        accepted: AcceptedAsset,
    ) -> SetupStatus {
        self.status_for_requirements(creator, None, Some(accepted))
            .await
    }

    /// Readiness for a criterion denomination and a payment asset together:
    /// `ready` only when both checks pass.
    pub async fn status_for_asset_and_accepted_asset(
        &self,
        creator: &CreatorPubky,
        asset: crate::domain::invoice::CriterionAsset,
        accepted: AcceptedAsset,
    ) -> SetupStatus {
        self.status_for_requirements(creator, Some(asset), Some(accepted))
            .await
    }

    async fn status_for_requirements(
        &self,
        creator: &CreatorPubky,
        asset: Option<crate::domain::invoice::CriterionAsset>,
        accepted: Option<AcceptedAsset>,
    ) -> SetupStatus {
        let status = self.status(creator).await;
        if status != SetupStatus::Ready {
            return status;
        }
        let asks_usdt = asset == Some(crate::domain::invoice::CriterionAsset::Usdt)
            || accepted == Some(AcceptedAsset::Usdt);
        if asks_usdt && !self.usdt_enabled {
            return SetupStatus::SetupRequired;
        }
        let Some(receiving) = &self.receiving else {
            return SetupStatus::SetupRequired;
        };
        match tokio::time::timeout(self.timeout, receiving.receiving(creator)).await {
            Ok(Ok(details))
                if (asset.is_none()
                    || details.bitcoin.is_some()
                    || (self.usdt_enabled && details.usdt.is_some()))
                    && accepted.is_none_or(|accepted| match accepted {
                        AcceptedAsset::Btc => details.bitcoin.is_some(),
                        AcceptedAsset::Usdt => details.usdt.is_some(),
                    }) =>
            {
                SetupStatus::Ready
            }
            Ok(Ok(_)) => SetupStatus::SetupRequired,
            Ok(Err(crate::persistence::PersistenceError::InvalidInput)) => {
                SetupStatus::SetupRequired
            }
            _ => SetupStatus::Unavailable,
        }
    }

    pub async fn status(&self, creator: &CreatorPubky) -> SetupStatus {
        match tokio::time::timeout(self.timeout, self.sessions.validate(creator)).await {
            Ok(Ok(())) => SetupStatus::Ready,
            Ok(Err(SessionValidationError::Invalid)) => SetupStatus::SetupRequired,
            Ok(Err(SessionValidationError::Unavailable)) => {
                crate::diagnostics::failure(
                    "setup_status",
                    "creator_session_validation",
                    "unavailable",
                );
                SetupStatus::Unavailable
            }
            Err(_) => {
                crate::diagnostics::failure(
                    "setup_status",
                    "creator_session_validation",
                    "timeout",
                );
                SetupStatus::Unavailable
            }
        }
    }
}
