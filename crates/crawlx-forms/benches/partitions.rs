//! Criterion benches for the forms plane:
//! `value_partition_derive` (1,000 `(seed, ActionContextKey, partition)` triples through
//! `ValuePartitions::value`) and `form_group_structural` (`FormGrouper::group` over a
//! 200-field page mixing explicit `<form>` ownership, AX landmarks, single-submit
//! proximity and orphans).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use chrono::NaiveDate;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ActionKind, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::ids::{BackendNodeId, FrameId, PrincipalId, StateClusterId, TabId};
use crawlx_core::observation::{ObservedDescriptor, RuntimeLocator};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::url::RouteTemplate;
use crawlx_forms::{
    FormGrouper, Partition, ValueContext, ValuePartitions, ALL_PARTITIONS, GENERATOR_VERSION,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::BTreeMap;
use uuid::Uuid;

const TRIPLES: usize = 1_000;
const FIELDS: usize = 200;

fn key(i: usize) -> ActionContextKey {
    ActionContextKey {
        principal: PrincipalId(format!("user-{}", i % 3)),
        route_template: RouteTemplate(format!("/forms/{}", i % 17)),
        element: ElementIdentityHash(Digest::of("bench/element", &i.to_le_bytes())),
        action_kind: ActionKind::Type,
        input_class: InputClass::none(),
        resource_context: ResourceContext::Own,
        state_cluster: StateClusterId(Uuid::from_u128(u128::try_from(i % 5).unwrap())),
    }
}

fn value_partition_derive(c: &mut Criterion) {
    let ctx = ValueContext::new(NaiveDate::from_ymd_opt(2026, 10, 16).unwrap());
    let triples: Vec<(CrawlSeed, ActionContextKey, Partition)> = (0..TRIPLES)
        .map(|i| {
            let seed = CrawlSeed(0x5eed_0000_0000_0000 + u64::try_from(i % 11).unwrap());
            (seed, key(i), ALL_PARTITIONS[i % ALL_PARTITIONS.len()])
        })
        .collect();
    let mut g = c.benchmark_group("value_partition_derive");
    g.throughput(Throughput::Elements(triples.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("all_partitions", triples.len()),
        &triples,
        |b, triples| {
            b.iter(|| {
                let mut bytes = 0usize;
                for (i, (seed, key, partition)) in triples.iter().enumerate() {
                    let ordinal = u32::try_from(i % 4).unwrap();
                    let v = ValuePartitions::value(
                        *seed,
                        black_box(key),
                        *partition,
                        ordinal,
                        GENERATOR_VERSION,
                        &ctx,
                    );
                    bytes += v.expose().len();
                }
                bytes
            });
        },
    );
    g.finish();
}

fn desc(n: i64, tag: &str, role: &str, attrs: &[(&str, String)], ancestors: &[&str]) -> ObservedDescriptor {
    ObservedDescriptor {
        locator: RuntimeLocator {
            tab: TabId("t".to_owned()),
            frame: FrameId("f".to_owned()),
            backend_node_id: BackendNodeId(n),
            object_id: None,
            ax_node_id: None,
            epoch: ObservationEpoch::default(),
        },
        role: role.to_owned(),
        accessible_name: None,
        description: None,
        tag: Some(tag.to_owned()),
        attributes: attrs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
        text: None,
        href: None,
        bbox: None,
        frame_lineage: Vec::new(),
        ancestor_roles: ancestors.iter().map(|r| (*r).to_owned()).collect(),
        container_text: None,
        focusable: true,
        disabled: false,
        visible: true,
        listeners: Vec::new(),
        cursor: None,
        in_closed_shadow_root: false,
        instance_ordinal: 0,
    }
}

/// One field of mixed kind `i`, with the classifier-relevant attributes a real page carries.
fn field(n: i64, i: usize, owner: &[(&str, String)], ancestors: &[&str]) -> ObservedDescriptor {
    let mut attrs: Vec<(&str, String)> = owner.to_vec();
    let (tag, role) = match i % 10 {
        0 => {
            attrs.extend([
                ("type", "email".to_owned()),
                ("name", "email".to_owned()),
                ("autocomplete", "email".to_owned()),
            ]);
            ("input", "textbox")
        }
        1 => {
            attrs.extend([("type", "password".to_owned()), ("name", "password".to_owned())]);
            ("input", "textbox")
        }
        2 => {
            attrs.extend([
                ("type", "tel".to_owned()),
                ("name", format!("phone_{i}")),
                ("inputmode", "tel".to_owned()),
            ]);
            ("input", "textbox")
        }
        3 => {
            attrs.extend([
                ("type", "date".to_owned()),
                ("name", format!("date_{i}")),
                ("min", "2020-01-01".to_owned()),
            ]);
            ("input", "textbox")
        }
        4 => {
            attrs.extend([
                ("type", "number".to_owned()),
                ("name", format!("qty_{i}")),
                ("min", "1".to_owned()),
                ("max", "99".to_owned()),
            ]);
            ("input", "spinbutton")
        }
        5 => {
            attrs.extend([("type", "checkbox".to_owned()), ("name", format!("opt_{i}"))]);
            ("input", "checkbox")
        }
        6 => {
            attrs.extend([("name", format!("country_{i}"))]);
            ("select", "combobox")
        }
        7 => {
            attrs.extend([("name", format!("notes_{i}")), ("maxlength", "500".to_owned())]);
            ("textarea", "textbox")
        }
        8 => {
            attrs.extend([
                ("type", "hidden".to_owned()),
                ("name", "csrf".to_owned()),
                ("value", "tok".to_owned()),
            ]);
            ("input", "")
        }
        _ => {
            attrs.extend([
                ("type", "text".to_owned()),
                ("name", format!("field_{i}")),
                ("placeholder", "Vorname".to_owned()),
                ("pattern", "[A-Za-z]+".to_owned()),
            ]);
            ("input", "textbox")
        }
    };
    let mut d = desc(n, tag, role, &attrs, ancestors);
    d.accessible_name = Some(format!("Field {i}"));
    d
}

fn submit(n: i64, label: &str, owner: &[(&str, String)], ancestors: &[&str]) -> ObservedDescriptor {
    let mut attrs: Vec<(&str, String)> = owner.to_vec();
    attrs.push(("type", "submit".to_owned()));
    let mut d = desc(n, "button", "button", &attrs, ancestors);
    d.accessible_name = Some(label.to_owned());
    d
}

/// 200 fields in five blocks of 40: two explicit `<form>`s (one owned through `crawlx:form`,
/// one through HTML `form=`), one AX `form` landmark, one proximity group with a single
/// submit, and 40 orphans scattered under generic containers.
fn page(fields: usize) -> Vec<ObservedDescriptor> {
    let per_block = fields / 5;
    let mut out: Vec<ObservedDescriptor> = Vec::with_capacity(fields + 8);
    let mut n: i64 = 1;
    let mut next = || {
        let id = n;
        n += 1;
        id
    };
    let main = ["main"];
    let decl_attrs = |id: &str, action: &str| -> Vec<(&'static str, String)> {
        vec![
            ("id", id.to_owned()),
            ("crawlx:form", id.to_owned()),
            ("method", "post".to_owned()),
            ("action", action.to_owned()),
        ]
    };

    out.push(desc(
        next(),
        "form",
        "form",
        &decl_attrs("signup", "/signup"),
        &main,
    ));
    let own = [("crawlx:form", "signup".to_owned())];
    for i in 0..per_block {
        out.push(field(next(), i, &own, &["main", "form"]));
    }
    out.push(submit(next(), "Create account", &own, &["main", "form"]));

    out.push(desc(
        next(),
        "form",
        "form",
        &decl_attrs("checkout", "/checkout"),
        &main,
    ));
    let own = [("form", "checkout".to_owned())];
    for i in 0..per_block {
        out.push(field(next(), i + 1, &own, &["main", "region"]));
    }
    out.push(submit(next(), "Pay now", &own, &["main", "region"]));

    for i in 0..per_block {
        out.push(field(next(), i + 2, &[], &["main", "region", "form", "group"]));
    }
    out.push(submit(
        next(),
        "Save settings",
        &[],
        &["main", "region", "form", "group"],
    ));

    for i in 0..per_block {
        out.push(field(next(), i + 3, &[], &["main", "region", "contentinfo"]));
    }
    out.push(submit(
        next(),
        "Subscribe",
        &[],
        &["main", "region", "contentinfo"],
    ));

    for i in 0..per_block {
        let anc: &[&str] = if i % 2 == 0 { &["main", "generic"] } else { &[] };
        out.push(field(next(), i + 4, &[], anc));
    }
    out
}

fn form_group_structural(c: &mut Criterion) {
    let candidates = page(FIELDS);
    let grouper = FormGrouper::new();
    let groups = grouper.group(&candidates);
    assert_eq!(groups.len(), 5, "explicit ×2, landmark, proximity, orphans");
    let total: usize = groups.iter().map(|g| g.inputs.len()).sum();
    assert!(
        total >= FIELDS - FIELDS / 10,
        "{total} inputs grouped (hidden fields may be folded)"
    );
    let mut g = c.benchmark_group("form_group_structural");
    g.throughput(Throughput::Elements(FIELDS as u64));
    g.bench_with_input(
        BenchmarkId::new("fields", FIELDS),
        &candidates,
        |b, candidates| {
            b.iter(|| grouper.group(black_box(candidates)).len());
        },
    );
    g.finish();
}

criterion_group!(benches, value_partition_derive, form_group_structural);
criterion_main!(benches);
