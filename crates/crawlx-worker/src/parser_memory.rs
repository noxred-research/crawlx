//! Cancellation-safe transfer of admitted bytes through blocking work.
//!
//! Cancelling a future cannot stop a running blocking parser. The closure keeps
//! both input and reservation until it exits; its result retains ownership until
//! delivery finishes. This does not make an infallible parser allocator fallible.

use crate::runtime::CpuPool;
use crawlx_core::parser_memory::{Budgeted, BytePermit};
use tokio_util::sync::CancellationToken;

/// Blocking admitted work failed before its result could reach a sink.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdmittedTaskError {
    /// Cancellation discards late output, without releasing running ownership early.
    #[error("admitted parser task cancelled")]
    Cancelled,
    /// The blocking closure panicked or runtime stopped.
    #[error("admitted parser task failed: {0}")]
    Join(#[source] tokio::task::JoinError),
}

/// Move input and its permit through the bounded CPU pool into the sink result.
///
/// The reservation must include input still alive, parser peak and output capacity.
/// `work` must grow the permit before any extra allocation. Share only immutable
/// bytes with an `Arc<BytePermit>`; deep copies require new admitted capacity.
/// Cancellation before spawn drops the captured input. Cancellation after spawn
/// leaves ownership in the closure until both input and late output drop.
///
/// # Errors
/// Returns cancellation or a blocking-task failure. Parser errors may be returned
/// as `U = Result<_, _>` so their concrete source chain remains intact.
pub async fn run_admitted<T, U>(
    cpu: &CpuPool,
    input: Budgeted<T>,
    cancel: &CancellationToken,
    work: impl FnOnce(T, &mut BytePermit, &CancellationToken) -> U + Send + 'static,
) -> Result<Budgeted<U>, AdmittedTaskError>
where
    T: Send + 'static,
    U: Send + 'static,
{
    if cancel.is_cancelled() {
        return Err(AdmittedTaskError::Cancelled);
    }
    let task_cancel = cancel.clone();
    let task = cpu.run(move || {
        let (value, mut permit) = input.into_parts();
        if task_cancel.is_cancelled() {
            // Explicit drop order: the reservation must outlive the retained input.
            drop(value);
            return Err(AdmittedTaskError::Cancelled);
        }
        let result = work(value, &mut permit, &task_cancel);
        Ok(Budgeted::new(result, permit))
    });
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(AdmittedTaskError::Cancelled),
        result = task => {
            let output = result.map_err(AdmittedTaskError::Join)??;
            if cancel.is_cancelled() {
                return Err(AdmittedTaskError::Cancelled);
            }
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::parser_memory::ByteBudget;
    use std::num::NonZeroUsize;
    use std::sync::Arc;

    #[tokio::test]
    async fn cancelled_before_spawn_releases_input_without_running() {
        let budget = Arc::new(ByteBudget::new(64));
        let permit = budget.try_reserve(64).unwrap();
        let input = Budgeted::new(vec![0; 64], permit);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = run_admitted(&CpuPool::default(), input, &cancel, |_, _, _| {
            panic!("must not run")
        })
        .await;
        assert!(matches!(result, Err(AdmittedTaskError::Cancelled)));
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn cancelled_running_closure_retains_input_until_real_completion() {
        let budget = Arc::new(ByteBudget::new(64));
        let permit = budget.try_reserve(64).unwrap();
        let input = Budgeted::new(vec![0; 64], permit);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let pool = CpuPool::with_permits(NonZeroUsize::MIN);
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            run_admitted(&task_pool, input, &task_cancel, move |value, _, _| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(value);
                let _ = finished_tx.send(());
            })
            .await
        });
        started_rx.await.unwrap();
        cancel.cancel();
        assert!(matches!(task.await.unwrap(), Err(AdmittedTaskError::Cancelled)));
        let held = budget.used();
        release_tx.send(()).unwrap();
        finished_rx.await.unwrap();
        // A subsequent closure starts only once the first CPU permit has returned.
        pool.run(|| ()).await.unwrap();
        assert_eq!(held, 64);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn sink_stall_retains_full_ownership_and_failure_releases_once() {
        let budget = Arc::new(ByteBudget::new(128));
        let permit = budget.try_reserve(128).unwrap();
        let input = Budgeted::new(vec![0; 64], permit);
        let output = run_admitted(
            &CpuPool::default(),
            input,
            &CancellationToken::new(),
            |value, _, _| value,
        )
        .await
        .unwrap();
        assert_eq!(output.value().len(), 64);
        assert!(budget.try_reserve(1).is_err());
        tokio::task::yield_now().await;
        assert_eq!(budget.used(), 128);
        drop(output);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn cancelling_queued_input_releases_before_cpu_becomes_free() {
        let budget = Arc::new(ByteBudget::new(64));
        let pool = CpuPool::with_permits(NonZeroUsize::MIN);
        let occupied = pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let running = tokio::spawn(async move {
            occupied
                .run(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        let permit = budget.try_reserve(64).unwrap();
        let input = Budgeted::new(vec![0; 64], permit);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let waiting_pool = pool.clone();
        let queued = tokio::spawn(async move {
            run_admitted(&waiting_pool, input, &task_cancel, |_, _, _| {
                panic!("must not run")
            })
            .await
        });
        let was_queued = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while pool.queue_depth() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        cancel.cancel();
        let cancelled = matches!(queued.await.unwrap(), Err(AdmittedTaskError::Cancelled));
        let released = budget.used();
        release_tx.send(()).unwrap();
        running.await.unwrap();
        assert!(was_queued);
        assert!(cancelled);
        assert_eq!(released, 0);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn parser_panic_releases_owned_bytes_without_poisoning_worker() {
        let budget = Arc::new(ByteBudget::new(64));
        let pool = CpuPool::with_permits(NonZeroUsize::MIN);
        let permit = budget.try_reserve(64).unwrap();
        let input = Budgeted::new(vec![0; 64], permit);
        let result = run_admitted(&pool, input, &CancellationToken::new(), |_, _, _| {
            panic!("authored parser failure")
        })
        .await;
        assert!(matches!(result, Err(AdmittedTaskError::Join(_))));
        assert_eq!(budget.used(), 0);
        assert_eq!(pool.run(|| 7).await.unwrap(), 7);
    }
}
