//! Trace ids for the span-to-row join.
//!
//! [`TraceIdLayer`] gives every span tree one [`TraceId`]: a span without a parent mints a
//! fresh id, a child inherits its parent's. The id is kept in the span's extensions, so
//! [`current_trace_id`] can read it from any code running inside a span — the journal
//! writers in `crawlx-storage` copy it onto `crawl_runs.trace_id` and `actions.trace_id`
//! without any explicit plumbing through the worker.
//!
//! The lookup follows the shape `tracing-opentelemetry` uses for its span context, minus
//! the `unsafe` downcast hook (`unsafe_code` is forbidden here): when the layer is
//! attached (`Layer::on_layer`) it remembers a lookup function monomorphised for that
//! subscriber type; [`current_trace_id`] finds the layer with `Subscriber::downcast_ref`
//! through any layered stack and calls that function. Without the layer it returns `None`.

use crawlx_core::ids::TraceId;
use std::sync::OnceLock;
use tracing::span::{Attributes, Id};
use tracing::{Dispatch, Span, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

type Lookup = fn(&Dispatch, &Id) -> Option<TraceId>;

/// Assigns a trace id to every span tree and makes it readable from inside the tree.
#[derive(Debug, Default)]
pub struct TraceIdLayer {
    /// Set once by `on_layer`, when the subscriber type the layer sits on is known.
    lookup: OnceLock<Lookup>,
}

impl TraceIdLayer {
    /// A layer with no subscriber attached yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The trace id of span `id` (its own or inherited); `None` when the layer never saw it.
    fn lookup<S>(dispatch: &Dispatch, id: &Id) -> Option<TraceId>
    where
        S: Subscriber + for<'a> LookupSpan<'a> + 'static,
    {
        let subscriber = dispatch.downcast_ref::<S>()?;
        let span = subscriber.span(id)?;
        let found = span.extensions().get::<TraceId>().copied();
        found
    }
}

impl<S> Layer<S> for TraceIdLayer
where
    S: Subscriber + for<'a> LookupSpan<'a> + 'static,
{
    fn on_layer(&mut self, _subscriber: &mut S) {
        // Ignoring the result is correct: a layer is attached once, and a second attach
        // would be to the same `S`.
        let _ = self.lookup.set(Self::lookup::<S>);
    }

    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let inherited = span
            .parent()
            .and_then(|p| p.extensions().get::<TraceId>().copied());
        let trace_id = inherited.unwrap_or_default();
        span.extensions_mut().insert(trace_id);
    }
}

/// Trace id of the current span's tree; `None` outside any span or when the installed
/// subscriber has no [`TraceIdLayer`].
#[must_use]
pub fn current_trace_id() -> Option<TraceId> {
    trace_id_of(&Span::current())
}

/// Trace id of `span`'s tree; `None` for a disabled span or a subscriber without the layer.
#[must_use]
pub fn trace_id_of(span: &Span) -> Option<TraceId> {
    span.with_subscriber(|(id, dispatch)| {
        let layer = dispatch.downcast_ref::<TraceIdLayer>()?;
        let lookup = layer.lookup.get()?;
        lookup(dispatch, id)
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn children_inherit_and_siblings_trees_differ() {
        let subscriber = tracing_subscriber::registry().with(TraceIdLayer::new());
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(current_trace_id(), None, "no span, no trace");
            let crawl = tracing::info_span!("crawl");
            let root = trace_id_of(&crawl).expect("root span has a trace id");
            let inner = crawl.in_scope(|| {
                let run = tracing::info_span!("run");
                let in_run = run.in_scope(current_trace_id).unwrap();
                assert_eq!(trace_id_of(&run), Some(root));
                in_run
            });
            assert_eq!(inner, root, "children inherit the root's trace id");
            let other = tracing::info_span!("crawl");
            assert_ne!(trace_id_of(&other), Some(root), "a new tree gets a new id");
        });
    }

    #[test]
    fn lookup_works_through_a_layered_stack_and_is_none_without_the_layer() {
        let subscriber = tracing_subscriber::registry()
            .with(TraceIdLayer::new())
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("crawl");
            assert!(trace_id_of(&span).is_some());
        });
        let bare = tracing_subscriber::registry();
        tracing::subscriber::with_default(bare, || {
            let span = tracing::info_span!("crawl");
            assert_eq!(trace_id_of(&span), None);
        });
    }

    #[test]
    fn trace_ids_round_trip_through_their_hex_form() {
        let id = TraceId::new();
        let parsed: TraceId = id.to_hex().parse().unwrap();
        assert_eq!(parsed, id);
        assert_eq!(id.to_hex().len(), 32);
        assert!("00000000000000000000000000000000".parse::<TraceId>().is_err());
        assert!("abc".parse::<TraceId>().is_err());
    }
}
