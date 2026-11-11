//! Charged browser text at the render boundary.
//!
//! The settled DOM arrives as [`AdmittedText`]: immutable, shared, and reserved against the
//! byte budget before it was allocated. A clone shares the allocation and the reservation; the
//! reservation is released only when the last clone drops. A prefix is a new allocation, so it
//! is admitted first and the original stays charged until the copy exists.

use super::RenderError;
use bytes::Bytes;
use crawlx_core::parser_memory::{AdmittedText, ByteBudget};
use crawlx_core::BrowserError;
use std::sync::Arc;

/// Shares an [`AdmittedText`] as the owner of a [`Bytes`] view of the same allocation.
struct Owner(AdmittedText);

impl AsRef<[u8]> for Owner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The DOM as shared [`Bytes`] without copying: the view, and every slice or clone of it,
/// keeps the text allocation and its byte reservation alive until the last of them drops.
pub(super) fn body_bytes(html: &AdmittedText) -> Bytes {
    Bytes::from_owner(Owner(html.clone()))
}

/// Cap `html` at `max` bytes on a character boundary, reserving the prefix before copying it.
///
/// Text within the cap is returned as is, sharing its allocation and reservation. A longer text
/// is replaced by an independently admitted prefix; the original keeps its reservation until
/// the copy exists and then drops with its last clone, so the transient peak is admitted, never
/// hidden. A refused reservation allocates nothing and leaves every existing owner unchanged.
///
/// # Errors
/// [`RenderError::Browser`] carrying the typed byte-admission refusal.
pub(super) fn truncate_admitted(
    html: AdmittedText,
    max: usize,
    budget: &Arc<ByteBudget>,
) -> Result<AdmittedText, RenderError> {
    if html.len() <= max {
        return Ok(html);
    }
    let mut end = max;
    while !html.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let permit = budget
        .try_reserve(end)
        .map_err(|error| super::browser_error(BrowserError::Memory(error)))?;
    let prefix = html[..end].to_owned();
    Ok(AdmittedText::new(prefix, permit))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn admit(budget: &Arc<ByteBudget>, text: &str) -> AdmittedText {
        let permit = budget.try_reserve(text.len()).unwrap();
        AdmittedText::new(text.to_owned(), permit)
    }

    #[test]
    fn short_text_shares_allocation_and_reservation() {
        let budget = Arc::new(ByteBudget::new(64));
        let html = admit(&budget, "<p>ok</p>");
        let same = truncate_admitted(html.clone(), 64, &budget).unwrap();
        assert_eq!(budget.used(), 9);
        assert_eq!(same.as_str().as_ptr(), html.as_str().as_ptr());
        drop(html);
        assert_eq!(budget.used(), 9, "a surviving clone keeps the reservation");
        drop(same);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn prefix_is_admitted_while_the_original_is_charged() {
        let budget = Arc::new(ByteBudget::new(20));
        let html = admit(&budget, "0123456789");
        let prefix = truncate_admitted(html.clone(), 4, &budget).unwrap();
        assert_eq!(prefix.as_str(), "0123");
        assert_eq!(budget.used(), 14);
        drop(html);
        assert_eq!(budget.used(), 4, "the prefix keeps its own reservation");
        drop(prefix);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn prefix_respects_character_boundaries() {
        let budget = Arc::new(ByteBudget::new(64));
        let html = admit(&budget, "aé€z");
        let prefix = truncate_admitted(html, 2, &budget).unwrap();
        assert_eq!(prefix.as_str(), "a");
        assert_eq!(budget.used(), 1, "the consumed original released its seven bytes");
    }

    #[test]
    fn refused_prefix_changes_nothing() {
        let budget = Arc::new(ByteBudget::new(12));
        let html = admit(&budget, "0123456789");
        let error = truncate_admitted(html.clone(), 4, &budget).unwrap_err();
        assert!(matches!(error, RenderError::Browser(_)), "{error:?}");
        assert_eq!(budget.used(), 10, "refusal reserves nothing");
        assert_eq!(html.as_str(), "0123456789");
    }

    #[test]
    fn body_view_and_slices_keep_the_reservation_without_copying() {
        let budget = Arc::new(ByteBudget::new(64));
        let html = admit(&budget, "<p>dom</p>");
        let body = body_bytes(&html);
        assert_eq!(body.as_ptr(), html.as_str().as_ptr(), "no copy");
        assert_eq!(budget.used(), 10);
        let slice = body.slice(3..6);
        drop(html);
        drop(body);
        assert_eq!(&slice[..], b"dom");
        assert_eq!(
            budget.used(),
            10,
            "the slice alone still owns the whole reservation"
        );
        drop(slice);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn detached_work_holds_the_reservation_after_the_caller_is_gone() {
        let budget = Arc::new(ByteBudget::new(64));
        let html = admit(&budget, "<p>dom</p>");
        let body = body_bytes(&html);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            body.len()
        });
        started_rx.recv().unwrap();
        drop(html);
        assert_eq!(
            budget.used(),
            10,
            "caller drop does not release bytes a closure still reads"
        );
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), 10);
        assert_eq!(budget.used(), 0);
    }
}
