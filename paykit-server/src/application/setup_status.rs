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

    pub async fn status_for_asset(
        &self,
        creator: &CreatorPubky,
        asset: crate::domain::invoice::CriterionAsset,
    ) -> SetupStatus {
        let status = self.status(creator).await;
        if status != SetupStatus::Ready {
            return status;
        }
        if asset == crate::domain::invoice::CriterionAsset::Usdt && !self.usdt_enabled {
            return SetupStatus::SetupRequired;
        }
        let Some(receiving) = &self.receiving else {
            return SetupStatus::SetupRequired;
        };
        match tokio::time::timeout(self.timeout, receiving.receiving(creator)).await {
            Ok(Ok(details))
                if details.bitcoin.is_some() || (self.usdt_enabled && details.usdt.is_some()) =>
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
