//! Byte admission carried through blocking URL-plane work.
//!
//! A response body is admitted by the transport ([`FetchResponse::body_permit`]). Every blocking job
//! that reads it moves an [`AdmittedBytes`] in, so a cancelled await can never release the
//! reservation while the detached closure still owns the bytes. Derived documents are reserved
//! *before* the parse runs and travel with the closure's result until the row's terminal commit.
//! This is admission, not fallible allocation: the existing parser stays infallible.

use super::*;
use crawlx_core::parser_memory::{ByteAdmissionError, BytePermit};

/// Output-side admission per decoded input byte for the extracted document and its transient
/// sink copies. The parser's own measured peak is charged separately inside the extraction crate
/// and the allocator stays infallible; this is admission accounting, not an allocation bound.
const DERIVED_BYTES_PER_INPUT_BYTE: usize = 4;

/// Shared bytes and the reservation that admitted them. Field order is drop order: the bytes
/// are released before the reservation.
pub(super) struct AdmittedBytes {
    bytes: bytes::Bytes,
    _permit: Option<Arc<BytePermit>>,
}

impl AdmittedBytes {
    /// Share the response body together with its permit.
    pub(super) fn of(response: &FetchResponse) -> Self {
        Self::from_parts(response.body.clone(), response.body_permit.clone())
    }

    fn from_parts(bytes: bytes::Bytes, permit: Option<Arc<BytePermit>>) -> Self {
        Self {
            bytes,
            _permit: permit,
        }
    }

    /// Borrow the admitted bytes.
    pub(super) fn bytes(&self) -> &bytes::Bytes {
        &self.bytes
    }
}

/// Reservation for the document derived from `input_len` decoded bytes, saturating so an
/// overflow is refused by the budget rather than wrapped.
pub(crate) fn derived_bytes(input_len: usize) -> usize {
    input_len.saturating_mul(DERIVED_BYTES_PER_INPUT_BYTE)
}

/// Reserve `bytes` from the shared production budget before allocating a derived value.
///
/// # Errors
/// Returns typed pressure or oversize without reserving anything.
pub(crate) fn reserve_derived(bytes: usize) -> Result<BytePermit, ByteAdmissionError> {
    crawlx_core::parser_memory::global().try_reserve(bytes)
}

/// Attach admission to a response whose bytes did not come from the transport (a retained
/// cache body or a restored 304 baseline) and so carry no permit yet.
///
/// # Errors
/// Returns typed pressure; the caller then drops the response.
pub(super) fn admit_retained(response: &mut FetchResponse) -> Result<(), ByteAdmissionError> {
    if response.body_permit.is_none() && !response.body.is_empty() {
        response.body_permit = Some(Arc::new(reserve_derived(response.body.len())?));
    }
    Ok(())
}

/// Owner a response body clone keeps alive: the bytes first, then the admission that covers them.
struct OwnedAdmitted {
    bytes: bytes::Bytes,
    _permit: Option<Arc<BytePermit>>,
}

impl AsRef<[u8]> for OwnedAdmitted {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A `Bytes` handle whose every clone retains the response's own admission, so it can travel into
/// a detached blocking job without the permit being released before the job drops it.
pub(super) fn owned_bytes(response: &FetchResponse) -> bytes::Bytes {
    bytes::Bytes::from_owner(OwnedAdmitted {
        bytes: response.body.clone(),
        _permit: response.body_permit.clone(),
    })
}

/// Result of an isolated extraction attempt.
pub(crate) enum IsolatedOutcome {
    /// Parsed document with the reservation that still covers it.
    Parsed(Box<crawlx_extract::Document>, BytePermit),
    /// The parser refused the input; the reservation was released with it.
    Failed(crawlx_extract::ExtractError),
    /// The run's cancellation won; nothing is returned.
    Cancelled,
}

/// Largest dynamic-secret snapshot the isolated parser transport can carry: its byte limit
/// plus one `String` header per value.
pub(crate) const DYNAMIC_SECRET_SNAPSHOT_BYTES: usize = crawlx_extract::isolated::MAX_SECRET_BYTES
    + crawlx_extract::isolated::MAX_SECRET_VALUES * std::mem::size_of::<String>();

/// Extract one HTML body through the bounded isolated parser. The input's permit covers the
/// derived document and moves with the bytes into the parser, so it is released only after the
/// parse finished or its detached work dropped the bytes.
pub(crate) async fn extract_isolated(
    cpu: &crate::runtime::CpuPool,
    input: crawlx_core::parser_memory::Budgeted<bytes::Bytes>,
    base: Url,
    options: crawlx_extract::ExtractOptions,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: Option<&crawlx_core::captcha::CaptchaSecrets>,
    cancel: &CancellationToken,
) -> IsolatedOutcome {
    use crate::isolated_parser::{shared, PageRequest};
    let invalid = |reason: String| {
        crawlx_extract::ExtractError::InvalidContentPolicy(crawlx_core::CoreError::Invalid {
            field: "extract.isolated",
            reason,
        })
    };
    let parser = match shared() {
        Ok(parser) => parser,
        Err(error) => return IsolatedOutcome::Failed(invalid(error.to_string())),
    };
    // Bounded, budget-admitted snapshot held until the projection below is built.
    let literals = match captcha {
        Some(captcha) => match captcha.literal_snapshot_admitted(DYNAMIC_SECRET_SNAPSHOT_BYTES) {
            Ok(literals) => Some(literals),
            Err(_) => return IsolatedOutcome::Failed(invalid("dynamic-secret snapshot unavailable".into())),
        },
        None => None,
    };
    let secrets = match crate::isolated_parser::IsolatedSecrets::new(
        controls.secret_values(),
        literals
            .as_ref()
            .into_iter()
            .flat_map(|literals| literals.value().iter().map(String::as_str)),
    ) {
        Ok(secrets) => secrets,
        Err(error) => return IsolatedOutcome::Failed(invalid(error.to_string())),
    };
    let request = PageRequest {
        base,
        options,
        engine: crawlx_extract::isolated::Engine::Pipeline,
        secrets,
    };
    match parser.extract_page(cpu, input, request, cancel).await {
        Ok(page) => {
            let (document, permit) = page.document.into_parts();
            IsolatedOutcome::Parsed(document, permit)
        }
        Err(_) if cancel.is_cancelled() => IsolatedOutcome::Cancelled,
        Err(error) => IsolatedOutcome::Failed(error.into_extract_error()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::runtime::CpuPool;
    use crawlx_core::parser_memory::ByteBudget;
    use std::num::NonZeroUsize;

    #[tokio::test]
    async fn a_cancelled_await_never_releases_the_permit_before_the_blocking_job_ends() {
        let budget = Arc::new(ByteBudget::new(1024));
        let permit = Arc::new(budget.try_reserve(512).unwrap());
        let input = AdmittedBytes::from_parts(bytes::Bytes::from_static(b"body"), Some(permit));
        let pool = CpuPool::with_permits(NonZeroUsize::MIN);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let job_pool = pool.clone();
        let task = tokio::spawn(async move {
            job_pool
                .run(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    input.bytes().len()
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(budget.used(), 512, "the detached closure still owns the bytes");
        release_tx.send(()).unwrap();
        // The next job starts only once the first closure returned and dropped its input.
        pool.run(|| ()).await.unwrap();
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn owned_bytes_clones_keep_the_admission_alive() {
        let budget = Arc::new(ByteBudget::new(64));
        let permit = Arc::new(budget.try_reserve(32).unwrap());
        let owned = bytes::Bytes::from_owner(OwnedAdmitted {
            bytes: bytes::Bytes::from_static(b"abc"),
            _permit: Some(permit),
        });
        let clone = owned.clone();
        drop(owned);
        assert_eq!(budget.used(), 32);
        assert_eq!(&clone[..], b"abc");
        drop(clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn derived_reservations_saturate_and_refusals_reserve_nothing() {
        assert_eq!(derived_bytes(usize::MAX), usize::MAX);
        assert_eq!(derived_bytes(3), 3 * DERIVED_BYTES_PER_INPUT_BYTE);
        let budget = Arc::new(ByteBudget::new(8));
        assert!(budget.try_reserve(derived_bytes(usize::MAX)).is_err());
        assert_eq!(budget.used(), 0);
    }
}
