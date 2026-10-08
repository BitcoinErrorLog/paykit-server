//! Bounded process-owned tasks, with at most one active task per Creator.

use std::{collections::HashSet, future::Future, sync::Arc};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::runtime::Runtime;

pub(crate) struct CreatorTasks<T> {
    tasks: JoinSet<(Uuid, T)>,
    active: HashSet<Uuid>,
    limit: usize,
    runtime: Arc<Runtime>,
}

impl<T: Send + 'static> CreatorTasks<T> {
    pub(crate) fn new(limit: usize, runtime: Arc<Runtime>) -> Self {
        assert!(limit > 0, "Creator task limit must be nonzero");
        Self {
            tasks: JoinSet::new(),
            active: HashSet::new(),
            limit,
            runtime,
        }
    }

    pub(crate) fn available_slots(&self) -> usize {
        self.limit - self.active.len()
    }

    pub(crate) fn active_creators(&self) -> Vec<Uuid> {
        self.active.iter().copied().collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) fn try_spawn(
        &mut self,
        creator: Uuid,
        work: impl Future<Output = T> + Send + 'static,
    ) -> bool {
        if !self.runtime.may_start_worker_claim()
            || self.available_slots() == 0
            || !self.active.insert(creator)
        {
            return false;
        }
        self.tasks.spawn(async move { (creator, work.await) });
        true
    }

    pub(crate) async fn join_next(&mut self) -> Option<(Uuid, T)> {
        let (creator, result) = self
            .tasks
            .join_next()
            .await?
            .expect("owned Creator task exited unexpectedly");
        self.active.remove(&creator);
        Some((creator, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::DependencyCheck;
    use std::time::Duration;

    struct Available;
    #[async_trait::async_trait]
    impl DependencyCheck for Available {
        async fn postgres_ready(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn slow_creator_does_not_block_other_creator_or_its_next_turn() {
        let runtime = Arc::new(Runtime::new(Arc::new(Available), 1));
        let mut tasks = CreatorTasks::new(2, runtime);
        let slow = Uuid::new_v4();
        let fast = Uuid::new_v4();
        let (release, wait) = tokio::sync::oneshot::channel();
        assert!(tasks.try_spawn(slow, async {
            wait.await.unwrap();
        }));
        assert!(!tasks.try_spawn(slow, async {}));
        assert!(tasks.try_spawn(fast, async {}));
        assert!(!tasks.try_spawn(Uuid::new_v4(), async {}));
        for turn in 0..2 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
                    .await
                    .unwrap(),
                Some((fast, ()))
            );
            assert_eq!(tasks.active_creators(), vec![slow]);
            if turn == 0 {
                assert!(tasks.try_spawn(fast, async {}));
            }
        }
        release.send(()).unwrap();
        assert_eq!(tasks.join_next().await, Some((slow, ())));
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn shutdown_stops_admission_and_drains_owned_work() {
        let runtime = Arc::new(Runtime::new(Arc::new(Available), 1));
        let mut tasks = CreatorTasks::new(2, runtime.clone());
        let creator = Uuid::new_v4();
        let (release, wait) = tokio::sync::oneshot::channel();
        assert!(tasks.try_spawn(creator, async {
            wait.await.unwrap();
        }));
        runtime.begin_shutdown();
        assert!(!tasks.try_spawn(Uuid::new_v4(), async {}));
        assert!(
            tokio::time::timeout(Duration::ZERO, tasks.join_next())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert_eq!(tasks.join_next().await, Some((creator, ())));
        assert!(tasks.is_empty());
    }
}
