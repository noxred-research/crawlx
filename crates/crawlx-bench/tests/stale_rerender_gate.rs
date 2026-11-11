//! G25 `stale-rerender`: `wrong_element_actions = 0`, computed from the gym ledger's server-side
//! effects against the fixture manifest, without a browser.
//!
//! A wrong-element action is a backend effect on a project the actor did not target: after a
//! whole-list rerender a stale locator resolves to the control that moved into its slot. The
//! Chromium test in `browser.rs` asserts the same count after a real stale-locator run; this
//! file holds the pure gate, proves it counts a wrong effect, and proves the fixture's backend
//! produces the effects the gate reads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use std::collections::BTreeMap;

const FIXTURE: &str = "stale-rerender";

/// `(ledger effect, resource)` a control's manifest `effect` produces on the server.
fn expected_effect(manifest_effect: &str) -> Option<(String, String)> {
    let (method, path) = manifest_effect.split_once(' ')?;
    let rest = path.strip_prefix("/stale-rerender/api/projects/")?;
    match (method, rest.split_once('/')) {
        ("POST", Some((id, "star"))) => Some(("star:applied".to_owned(), id.to_owned())),
        ("DELETE", None) => Some(("remove:applied".to_owned(), rest.to_owned())),
        _ => None,
    }
}

/// Effects the actor intended: `targeted` control ids resolved through the manifest.
fn intended_effects(manifest: &FixtureManifest, targeted: &[&str]) -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for id in targeted {
        let control = manifest
            .controls
            .iter()
            .find(|c| c.id == *id)
            .unwrap_or_else(|| panic!("control {id} is not in the {FIXTURE} manifest"));
        let effect = control
            .effect
            .as_deref()
            .and_then(expected_effect)
            .unwrap_or_else(|| panic!("control {id} has no mapped backend effect"));
        *out.entry(effect).or_default() += 1;
    }
    out
}

/// `wrong_element_actions`: server-side effects beyond (or other than) what the targeted
/// controls explain, from ledger effect rows `(principal, effect, resource, resource_context)`.
fn wrong_element_actions(
    effects: &[(String, String, String, String)],
    intended: &BTreeMap<(String, String), usize>,
) -> usize {
    let mut remaining = intended.clone();
    let mut wrong = 0;
    for (_, effect, resource, _) in effects {
        match remaining.get_mut(&(effect.clone(), resource.clone())) {
            Some(n) if *n > 0 => *n -= 1,
            _ => wrong += 1,
        }
    }
    wrong
}

fn effect(name: &str, resource: &str) -> (String, String, String, String) {
    (
        "anonymous".to_owned(),
        name.to_owned(),
        resource.to_owned(),
        "shared".to_owned(),
    )
}

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

#[test]
fn every_effectful_control_maps_to_a_ledger_effect() {
    let manifest = FixtureManifest::embedded(FIXTURE).unwrap();
    let effectful: Vec<_> = manifest.controls.iter().filter(|c| c.effect.is_some()).collect();
    assert_eq!(effectful.len(), 16, "8 stars and 8 removes");
    for control in effectful {
        let (name, id) = expected_effect(control.effect.as_deref().unwrap()).unwrap();
        assert_eq!(control.id.rsplit_once('-').unwrap().1, id, "{}", control.id);
        assert_eq!(
            name,
            if control.id.starts_with("star-") {
                "star:applied"
            } else {
                "remove:applied"
            }
        );
    }
}

#[test]
fn the_intended_effect_alone_is_zero_wrong_element_actions() {
    let manifest = FixtureManifest::embedded(FIXTURE).unwrap();
    let intended = intended_effects(&manifest, &["star-1"]);
    let ledger = [effect("star:applied", "1")];
    assert_eq!(wrong_element_actions(&ledger, &intended), 0);
}

#[test]
fn a_stale_locator_landing_on_another_project_is_counted() {
    let manifest = FixtureManifest::embedded(FIXTURE).unwrap();
    let intended = intended_effects(&manifest, &["star-1"]);
    // The rerender moved project 2's star button into the slot the stale locator named.
    assert_eq!(
        wrong_element_actions(&[effect("star:applied", "2")], &intended),
        1,
        "a star on the wrong project is a wrong-element action"
    );
    assert_eq!(
        wrong_element_actions(
            &[effect("star:applied", "1"), effect("star:applied", "2")],
            &intended
        ),
        1,
        "the intended effect still counts as right, the extra one as wrong"
    );
    // A destructive control that took the place of the intended one.
    assert_eq!(
        wrong_element_actions(&[effect("remove:applied", "1")], &intended),
        1,
        "the right project but the wrong control (remove instead of star) is wrong"
    );
    // The same effect twice: one intended click, one extra application.
    assert_eq!(
        wrong_element_actions(
            &[effect("star:applied", "1"), effect("star:applied", "1")],
            &intended
        ),
        1,
        "an effect applied more often than targeted is wrong"
    );
    // A run that targeted nothing but left an effect.
    assert_eq!(
        wrong_element_actions(&[effect("star:applied", "1")], &BTreeMap::new()),
        1
    );
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fixture_backend_ledger_feeds_the_gate() {
    let manifest = FixtureManifest::embedded(FIXTURE).unwrap();
    let gym = gym().await;
    gym.reset(25);
    let http = reqwest::Client::new();
    let base = format!("{}/{FIXTURE}/api/projects", gym.base_url);
    let intended = intended_effects(&manifest, &["star-1"]);

    // Nothing happened yet: the gate is zero, and the effect list is empty rather than unread.
    assert!(gym.ledger().effects(FIXTURE).is_empty());
    assert_eq!(
        wrong_element_actions(&gym.ledger().effects(FIXTURE), &intended),
        0
    );

    // The intended action reaches the server as exactly the effect the manifest predicts.
    let (_, star_1) = manifest
        .controls
        .iter()
        .find(|c| c.id == "star-1")
        .and_then(|c| c.effect.as_deref())
        .and_then(|e| e.split_once(' '))
        .map(|(m, p)| (m, p.to_owned()))
        .unwrap();
    let response = http
        .post(format!("{}{star_1}", gym.base_url))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let effects = gym.ledger().effects(FIXTURE);
    assert_eq!(effects, [effect("star:applied", "1")]);
    assert_eq!(wrong_element_actions(&effects, &intended), 0);

    // A stale locator that hits project 2 instead shows up in the same ledger as one wrong action.
    http.post(format!("{base}/2/star")).send().await.unwrap();
    let effects = gym.ledger().effects(FIXTURE);
    assert_eq!(effects.len(), 2, "{effects:?}");
    assert_eq!(wrong_element_actions(&effects, &intended), 1, "{effects:?}");

    // And a destructive wrong-element action.
    http.delete(format!("{base}/3")).send().await.unwrap();
    let effects = gym.ledger().effects(FIXTURE);
    assert_eq!(wrong_element_actions(&effects, &intended), 2, "{effects:?}");
    gym.shutdown().await;
}
