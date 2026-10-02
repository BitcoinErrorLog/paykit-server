use std::{sync::Arc, time::Duration};

use crate::{
    application::create_invoice::{SessionValidationError, SessionValidator},
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
    timeout: Duration,
}

impl SetupStatusService {
    pub fn new(sessions: Arc<dyn SessionValidator>) -> Self {
        Self::with_timeout(sessions, STATUS_TIMEOUT)
    }

    #[doc(hidden)]
    pub fn with_timeout(sessions: Arc<dyn SessionValidator>, timeout: Duration) -> Self {
        Self { sessions, timeout }
    }

    pub async fn status(&self, creator: &CreatorPubky) -> SetupStatus {
        match tokio::time::timeout(self.timeout, self.sessions.validate(creator)).await {
            Ok(Ok(())) => SetupStatus::Ready,
            Ok(Err(SessionValidationError::Invalid)) => SetupStatus::SetupRequired,
            Ok(Err(SessionValidationError::Unavailable)) | Err(_) => SetupStatus::Unavailable,
        }
    }
}
