//! Which workers may claim a run's sessions and URL batches, evaluated in Rust.
//!
//! PostgreSQL decides this inside the claim statement with `crawlx_worker_data_eligible` and
//! JSON probes over `workers.capacity`. MariaDB and SQLite read the worker row and the run's
//! structural data requirements in the claim transaction and call [`claim_eligible`], so
//! both new engines share one implementation of the same rule. The function is pure: the
//! caller supplies `now` from the database clock.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

/// A live worker must have beaten its heart within this window.
const HEARTBEAT_WINDOW_SECS: i64 = 90;

/// Largest serialized requirement object a claim accepts.
const MAX_REQUIREMENTS_BYTES: usize = 16_384;

/// Longest destination identifier a requirement may name.
const MAX_DESTINATION_LEN: usize = 128;

/// The columns of one `workers` row a claim needs.
#[derive(Clone, Debug)]
pub(crate) struct WorkerFacts {
    /// `workers.capacity`.
    pub capacity: Value,
    /// `workers.draining`.
    pub draining: bool,
    /// `workers.last_heartbeat_at`.
    pub last_heartbeat_at: DateTime<Utc>,
}

/// The claim rule: the run needs nothing from the worker, or the worker is live, accepts
/// queued work (or is the run's own local worker), advertises every required acquisition
/// backend as available, and satisfies the run's data requirements.
pub(crate) fn claim_eligible(
    worker: Option<&WorkerFacts>,
    run: Uuid,
    now: DateTime<Utc>,
    required_backends: &[String],
    data_required: bool,
    requirements: &Value,
) -> bool {
    let backends_ok = (required_backends.is_empty() && !data_required)
        || worker.is_some_and(|w| backends_ready(w, run, now, required_backends));
    backends_ok && data_eligible(worker, now, requirements)
}

fn alive(worker: &WorkerFacts, now: DateTime<Utc>) -> bool {
    !worker.draining
        && worker.last_heartbeat_at <= now
        && worker.last_heartbeat_at >= now - Duration::seconds(HEARTBEAT_WINDOW_SECS)
}

fn backends_ready(worker: &WorkerFacts, run: Uuid, now: DateTime<Utc>, required: &[String]) -> bool {
    if !alive(worker, now) {
        return false;
    }
    let capacity = &worker.capacity;
    let in_scope = capacity.get("acceptsQueued") == Some(&Value::Bool(true))
        || capacity.get("localRun").and_then(Value::as_str) == Some(run.to_string().as_str());
    if !in_scope {
        return false;
    }
    let facts = capacity
        .get("acquisition")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    required.iter().all(|id| {
        facts.iter().any(|fact| {
            fact.get("backendId").and_then(Value::as_str) == Some(id.as_str())
                && fact.get("available") == Some(&Value::Bool(true))
        })
    })
}

fn requirements_empty(requirements: &Value) -> bool {
    let no_bundle = |v: &Value| v.get("languageBundle").is_none_or(Value::is_null);
    requirements.is_null()
        || requirements.as_object().is_some_and(serde_json::Map::is_empty)
        || (requirements.is_object()
            && requirements
                .get("destinations")
                .and_then(Value::as_object)
                .is_some_and(serde_json::Map::is_empty)
            && no_bundle(requirements))
}

fn valid_destination(key: &str) -> bool {
    (1..=MAX_DESTINATION_LEN).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn lower_hex_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Every destination a feed compresses for must be one the worker published compressed-byte
/// support for. Requirements without the field (runs created before it existed) need nothing;
/// a present field that is not an array of strings is never satisfied.
fn compressed_supported(worker: &WorkerFacts, requirements: &Value) -> bool {
    let required = match requirements.get("compressedDestinations") {
        None => return true,
        Some(Value::Array(required)) => required,
        Some(_) => return false,
    };
    let offered = worker
        .capacity
        .get("data")
        .and_then(|data| data.get("compressedDestinations"))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    required.iter().all(|id| id.is_string() && offered.contains(id))
}

fn data_eligible(worker: Option<&WorkerFacts>, now: DateTime<Utc>, requirements: &Value) -> bool {
    if requirements_empty(requirements) {
        return true;
    }
    let Some(worker) = worker else { return false };
    if !alive(worker, now)
        || !requirements.is_object()
        || requirements.to_string().len() > MAX_REQUIREMENTS_BYTES
    {
        return false;
    }
    let empty = serde_json::Map::new();
    let destinations = match requirements.get("destinations") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => return false,
    };
    let offered = worker
        .capacity
        .get("data")
        .and_then(|data| data.get("destinations"))
        .and_then(Value::as_object);
    let destinations_ok = destinations.iter().all(|(key, wanted)| {
        let Some(wanted) = wanted.as_bool() else {
            return false;
        };
        valid_destination(key)
            && offered
                .and_then(|map| map.get(key))
                .is_some_and(|have| !wanted || *have == Value::Bool(true))
    });
    if !destinations_ok || !compressed_supported(worker, requirements) {
        return false;
    }
    match requirements.get("languageBundle") {
        None | Some(Value::Null) => true,
        Some(Value::String(digest)) => {
            lower_hex_digest(digest)
                && worker
                    .capacity
                    .get("data")
                    .and_then(|data| data.get("languageBundles"))
                    .and_then(Value::as_array)
                    .is_some_and(|bundles| bundles.iter().any(|b| b.as_str() == Some(digest.as_str())))
        }
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn worker(capacity: Value, age_secs: i64, draining: bool, now: DateTime<Utc>) -> WorkerFacts {
        WorkerFacts {
            capacity,
            draining,
            last_heartbeat_at: now - Duration::seconds(age_secs),
        }
    }

    #[test]
    fn a_run_without_needs_accepts_any_worker_even_none() {
        let now = Utc::now();
        assert!(claim_eligible(None, Uuid::nil(), now, &[], false, &json!({})));
        assert!(claim_eligible(None, Uuid::nil(), now, &[], false, &Value::Null));
        assert!(claim_eligible(
            None,
            Uuid::nil(),
            now,
            &[],
            false,
            &json!({"destinations": {}, "languageBundle": null})
        ));
    }

    #[test]
    fn required_backends_need_a_live_queue_worker_advertising_them() {
        let now = Utc::now();
        let run = Uuid::now_v7();
        let needs = vec!["native_http".to_owned()];
        let cap =
            json!({"acceptsQueued": true, "acquisition": [{"backendId": "native_http", "available": true}]});
        assert!(claim_eligible(
            Some(&worker(cap.clone(), 1, false, now)),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
        assert!(!claim_eligible(
            Some(&worker(cap.clone(), 1, true, now)),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
        assert!(!claim_eligible(
            Some(&worker(cap.clone(), 91, false, now)),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
        assert!(!claim_eligible(None, run, now, &needs, false, &json!({})));
        let unavailable =
            json!({"acceptsQueued": true, "acquisition": [{"backendId": "native_http", "available": false}]});
        assert!(!claim_eligible(
            Some(&worker(unavailable, 1, false, now)),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
        // a local worker is in scope only for its own run
        let local = json!({"localRun": run.to_string(), "acquisition": [{"backendId": "native_http", "available": true}]});
        assert!(claim_eligible(
            Some(&worker(local.clone(), 1, false, now)),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
        assert!(!claim_eligible(
            Some(&worker(local, 1, false, now)),
            Uuid::now_v7(),
            now,
            &needs,
            false,
            &json!({})
        ));
        // a heartbeat in the future is not live
        let future = WorkerFacts {
            capacity: cap,
            draining: false,
            last_heartbeat_at: now + Duration::seconds(5),
        };
        assert!(!claim_eligible(
            Some(&future),
            run,
            now,
            &needs,
            false,
            &json!({})
        ));
    }

    #[test]
    fn data_requirements_match_destinations_and_bundles() {
        let now = Utc::now();
        let run = Uuid::now_v7();
        let digest = "ab".repeat(32);
        let cap = json!({"acceptsQueued": true, "data": {"destinations": {"sink-a": true, "sink-b": false}, "languageBundles": [digest]}});
        let w = worker(cap, 1, false, now);
        let ok =
            json!({"destinations": {"sink-a": true, "sink-b": false}, "languageBundle": "ab".repeat(32)});
        assert!(claim_eligible(Some(&w), run, now, &[], true, &ok));
        // data requirements still need a worker in scope for queued work (or the run's own local worker)
        let out_of_scope = worker(json!({"data": w.capacity["data"]}), 1, false, now);
        assert!(!claim_eligible(Some(&out_of_scope), run, now, &[], true, &ok));
        // ZDR required on a destination the worker did not approve for ZDR
        assert!(!claim_eligible(
            Some(&w),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {"sink-b": true}})
        ));
        // unknown destination, malformed name, non-boolean value, wrong bundle
        assert!(!claim_eligible(
            Some(&w),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {"sink-c": false}})
        ));
        assert!(!claim_eligible(
            Some(&w),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {"bad name": false}})
        ));
        assert!(!claim_eligible(
            Some(&w),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {"sink-a": "yes"}})
        ));
        assert!(!claim_eligible(
            Some(&w),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {}, "languageBundle": "cd".repeat(32)})
        ));
        assert!(!claim_eligible(None, run, now, &[], true, &ok));
    }

    #[test]
    fn compressed_destinations_need_published_compressed_support() {
        let now = Utc::now();
        let run = Uuid::now_v7();
        let cap = json!({"acceptsQueued": true, "data": {
            "destinations": {"loc": false, "queue": false},
            "compressedDestinations": ["loc"]
        }});
        let w = worker(cap, 1, false, now);
        let eligible = |requirements: Value| claim_eligible(Some(&w), run, now, &[], true, &requirements);
        assert!(eligible(
            json!({"destinations": {"loc": false}, "compressedDestinations": ["loc"]})
        ));
        assert!(!eligible(
            json!({"destinations": {"queue": false}, "compressedDestinations": ["queue"]})
        ));
        assert!(!eligible(
            json!({"destinations": {"loc": false, "queue": false}, "compressedDestinations": ["loc", "queue"]})
        ));
        // uncompressed feeds and requirements written before the field existed keep their meaning
        assert!(eligible(
            json!({"destinations": {"queue": false}, "compressedDestinations": []})
        ));
        assert!(eligible(json!({"destinations": {"queue": false}})));
        // a malformed field is never satisfied
        assert!(!eligible(
            json!({"destinations": {"loc": false}, "compressedDestinations": null})
        ));
        assert!(!eligible(
            json!({"destinations": {"loc": false}, "compressedDestinations": "loc"})
        ));
        assert!(!eligible(
            json!({"destinations": {"loc": false}, "compressedDestinations": [7]})
        ));
        // a worker that published nothing supports no compressed destination
        let legacy = worker(
            json!({"acceptsQueued": true, "data": {"destinations": {"loc": false}}}),
            1,
            false,
            now,
        );
        assert!(!claim_eligible(
            Some(&legacy),
            run,
            now,
            &[],
            true,
            &json!({"destinations": {"loc": false}, "compressedDestinations": ["loc"]})
        ));
    }
}
