//! `quiescence_event_loop` and `epoch_bump`.
//!
//! The settle loop of a `perform` is driven by browser events: every request, response,
//! finish and mutation record updates the network and observation epochs, and the loop
//! polls in-flight accounting until the page is quiet. These benches isolate that pure
//! bookkeeping from the browser: 10k events through [`NetworkEpochTracker`] with an
//! in-flight check every 100 events and a final summary, and 10k bumps/merges through
//! [`EpochTracker`].
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use chrono::{DateTime, Utc};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::time::Timestamp;
use crawlx_core::traffic::TrafficOrigin;
use crawlx_observe::epoch::{EpochEvent, EpochTracker};
use crawlx_observe::network::{NetworkEpochTracker, RequestEvent, ResponseEvent};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;

const EVENTS: usize = 10_000;
/// In-flight poll cadence of the simulated settle loop.
const POLL_EVERY: usize = 100;

fn t(ms: i64) -> Timestamp {
    DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + ms).unwrap()
}

/// One browser event of the settle loop, in arrival order.
#[derive(Clone)]
enum Event {
    Request(RequestEvent),
    Response(ResponseEvent),
    Finished { request_id: String, at: Timestamp },
    Mutations(u64),
}

/// `n` events: every request is followed by a mutation batch, its response and its finish, so
/// the stream mixes short XHRs, static assets, page-origin and service-worker traffic.
fn events(n: usize) -> Vec<Event> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0_usize;
    while out.len() < n {
        let id = format!("r{i}");
        let at = i64::try_from(i).unwrap() * 3;
        let (method, url, mime) = match i % 5 {
            0 => (
                "POST",
                format!("https://app.test/api/items/{i}"),
                "application/json",
            ),
            1 => (
                "GET",
                format!("https://app.test/api/items/{i}?v={}", i % 7),
                "application/json",
            ),
            2 => (
                "GET",
                format!("https://app.test/static/chunk-{}.js", i % 50),
                "application/javascript",
            ),
            3 => ("GET", format!("https://app.test/items/{i}"), "text/html"),
            _ => ("GET", format!("https://cdn.test/img/{}.png", i % 20), "image/png"),
        };
        let origin = if i.is_multiple_of(11) {
            TrafficOrigin::ServiceWorker
        } else {
            TrafficOrigin::Page
        };
        out.push(Event::Request(RequestEvent {
            request_id: id.clone(),
            method: method.to_owned(),
            url,
            origin,
            at: t(at),
        }));
        out.push(Event::Mutations(1 + u64::try_from(i % 4).unwrap()));
        out.push(Event::Response(ResponseEvent {
            request_id: id.clone(),
            status: Some(if i.is_multiple_of(13) { 404 } else { 200 }),
            mime_type: Some(mime.to_owned()),
            at: t(at + 1),
        }));
        out.push(Event::Finished {
            request_id: id,
            at: t(at + 2),
        });
        i += 1;
    }
    out.truncate(n);
    out
}

/// Feed `events` through both trackers as the settle loop would, polling in-flight every
/// `POLL_EVERY` events; returns what the loop would inspect at the end.
fn settle(events: Vec<Event>) -> (u32, u32, u64, usize) {
    let mut net = NetworkEpochTracker::default();
    let mut epoch = EpochTracker::new();
    net.open_epoch(None, t(0));
    let mut polls_in_flight = 0_u32;
    let mut last_at = t(0);
    for (n, ev) in events.into_iter().enumerate() {
        match ev {
            Event::Request(r) => {
                last_at = r.at;
                black_box(net.on_request(r));
            }
            Event::Response(r) => {
                last_at = r.at;
                black_box(net.on_response(r));
            }
            Event::Finished { request_id, at } => {
                last_at = at;
                black_box(net.on_finished(&request_id, at));
            }
            Event::Mutations(k) => {
                black_box(epoch.apply(EpochEvent::Mutations(k)));
            }
        }
        if n % POLL_EVERY == 0 {
            polls_in_flight = polls_in_flight.saturating_add(net.in_flight());
        }
    }
    let summary = net.close_epoch(last_at);
    (
        polls_in_flight,
        summary.requests,
        epoch.current().mutation_seq,
        summary.operations.len(),
    )
}

fn quiescence_event_loop(c: &mut Criterion) {
    let events = events(EVENTS);
    let mut g = c.benchmark_group("quiescence_event_loop");
    g.bench_with_input(BenchmarkId::new("events", EVENTS), &events, |b, events| {
        b.iter_batched(|| events.clone(), settle, BatchSize::LargeInput);
    });
    g.finish();
}

fn bumps(n: usize) -> Vec<EpochEvent> {
    (0..n)
        .map(|i| match i % 8 {
            0 => EpochEvent::MainFrameNavigated,
            1 => EpochEvent::SameDocumentNavigation { route_changed: true },
            2 => EpochEvent::SameDocumentNavigation { route_changed: false },
            3 => EpochEvent::DocumentReplaced,
            _ => EpochEvent::Mutations(u64::try_from(i % 17).unwrap()),
        })
        .collect()
}

/// 10k `apply` calls plus a backend `merge` every tenth event (the read-back race path).
fn epoch_bump(c: &mut Criterion) {
    let bumps = bumps(EVENTS);
    let mut g = c.benchmark_group("epoch_bump");
    g.bench_with_input(BenchmarkId::new("events", EVENTS), &bumps, |b, bumps| {
        b.iter(|| {
            let mut tracker = EpochTracker::new();
            let mut seen = ObservationEpoch::default();
            for (i, ev) in bumps.iter().enumerate() {
                seen = tracker.apply(black_box(*ev));
                if i % 10 == 0 {
                    let reported = ObservationEpoch {
                        mutation_seq: seen.mutation_seq.saturating_add(1),
                        ..seen
                    };
                    seen = tracker.merge(black_box(reported));
                }
            }
            seen
        });
    });
    g.finish();
}

criterion_group!(benches, quiescence_event_loop, epoch_bump);
criterion_main!(benches);
