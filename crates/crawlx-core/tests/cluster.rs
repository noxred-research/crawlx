//! Authored contracts of the embedding-cluster extraction arithmetic: determinism under seed and
//! input order, hard caps, bounds and envelope validation. Vectors are supplied directly; the
//! model call is exercised in `crawlx-model`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::extraction::{
    ClusterEnvelopeV1, ClusterErrorV1, ClusterPolicyV1, SourceRangeV1, MAX_CLUSTER_VECTORS,
};
use crawlx_core::seed::CrawlSeed;

/// Three well-separated groups of two-dimensional unit-ish vectors, one line of text each.
fn fixture() -> (String, Vec<SourceRangeV1>, Vec<Vec<f32>>) {
    let lines = [
        ("rivers flow", [1.0, 0.0, 0.0]),
        ("lakes and rivers", [0.9, 0.1, 0.0]),
        ("market prices", [0.0, 1.0, 0.0]),
        ("stock market", [0.1, 0.9, 0.0]),
        ("mountain trails", [0.0, 0.0, 1.0]),
        ("hiking trails", [0.0, 0.1, 0.9]),
    ];
    let mut text = String::new();
    let mut ranges = Vec::new();
    let mut vectors = Vec::new();
    for (line, vector) in lines {
        let start = text.len();
        text.push_str(line);
        ranges.push(SourceRangeV1::new(start, text.len()));
        text.push('\n');
        vectors.push(vector.to_vec());
    }
    (text, ranges, vectors)
}

fn policy(clusters: usize) -> ClusterPolicyV1 {
    let mut policy = ClusterPolicyV1::default();
    policy.clusters = clusters;
    policy
}

fn groups(envelope: &ClusterEnvelopeV1) -> Vec<Vec<(usize, usize)>> {
    envelope
        .clusters
        .iter()
        .map(|c| c.members.iter().map(|r| (r.start, r.end)).collect())
        .collect()
}

#[test]
fn separated_groups_cluster_together_and_are_ordered_by_first_member() {
    let (text, ranges, vectors) = fixture();
    let envelope =
        ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", policy(3), CrawlSeed(7)).unwrap();
    let expected: Vec<Vec<(usize, usize)>> = [[0, 1], [2, 3], [4, 5]]
        .iter()
        .map(|pair| pair.iter().map(|&i| (ranges[i].start, ranges[i].end)).collect())
        .collect();
    assert_eq!(groups(&envelope), expected);
    assert!(envelope.converged);
    assert!(envelope.clusters.iter().all(|c| c.cohesion_millis >= 990));
    envelope.validate(&text, &policy(3)).unwrap();
}

#[test]
fn output_is_identical_for_the_same_seed_and_for_any_input_order() {
    let (text, ranges, vectors) = fixture();
    let reference =
        ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", policy(3), CrawlSeed(11)).unwrap();
    assert_eq!(
        reference,
        ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", policy(3), CrawlSeed(11)).unwrap()
    );
    // Every rotation and the reversal of the (range, vector) pairs yields the same envelope.
    for shift in 0..ranges.len() {
        let mut r = ranges.clone();
        let mut v = vectors.clone();
        r.rotate_left(shift);
        v.rotate_left(shift);
        assert_eq!(
            reference,
            ClusterEnvelopeV1::build(&text, &r, &v, "mock", policy(3), CrawlSeed(11)).unwrap(),
            "rotation {shift}"
        );
    }
    let mut r = ranges.clone();
    let mut v = vectors.clone();
    r.reverse();
    v.reverse();
    assert_eq!(
        reference,
        ClusterEnvelopeV1::build(&text, &r, &v, "mock", policy(3), CrawlSeed(11)).unwrap()
    );
    // Separated data clusters the same way under other seeds; each result is self-consistent.
    for seed in [0, 1, 2, 99, u64::MAX] {
        let other =
            ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", policy(3), CrawlSeed(seed)).unwrap();
        assert_eq!(groups(&other), groups(&reference), "seed {seed}");
        other.validate(&text, &policy(3)).unwrap();
    }
}

#[test]
fn fewer_ranges_than_clusters_and_single_cluster_requests_are_valid() {
    let (text, ranges, vectors) = fixture();
    let two = ClusterEnvelopeV1::build(
        &text,
        &ranges[..2],
        &vectors[..2],
        "mock",
        policy(10),
        CrawlSeed(1),
    )
    .unwrap();
    assert_eq!(two.clusters.len(), 2);
    let all = ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", policy(1), CrawlSeed(1)).unwrap();
    assert_eq!(all.clusters.len(), 1);
    assert_eq!(all.clusters[0].members.len(), 6);
    // Zero vectors are legal; they join the lowest-index centroid and never produce NaN.
    let zero = vec![vec![0.0_f32; 3]; 3];
    let envelope =
        ClusterEnvelopeV1::build(&text, &ranges[..3], &zero, "mock", policy(2), CrawlSeed(3)).unwrap();
    envelope.validate(&text, &policy(2)).unwrap();
}

#[test]
fn the_vector_cap_is_inclusive_and_fails_closed_one_over() {
    let text = "x".repeat(MAX_CLUSTER_VECTORS + 2);
    let make = |n: usize| -> (Vec<SourceRangeV1>, Vec<Vec<f32>>) {
        (
            (0..n).map(|i| SourceRangeV1::new(i, i + 1)).collect(),
            (0..n)
                .map(|i| vec![1.0, f32::from(u16::try_from(i % 7).unwrap())])
                .collect(),
        )
    };
    let mut capped = policy(4);
    capped.max_vectors = 10;
    let (r, v) = make(10);
    assert!(ClusterEnvelopeV1::build(&text, &r, &v, "mock", capped, CrawlSeed(5)).is_ok());
    let (r, v) = make(11);
    assert_eq!(
        ClusterEnvelopeV1::build(&text, &r, &v, "mock", capped, CrawlSeed(5)),
        Err(ClusterErrorV1::TooManyVectors { count: 11, max: 10 })
    );
    assert_eq!(
        capped.check_count(11),
        Err(ClusterErrorV1::TooManyVectors { count: 11, max: 10 })
    );
    let mut hard = policy(4);
    hard.max_vectors = MAX_CLUSTER_VECTORS + 1;
    assert_eq!(hard.validate(), Err(ClusterErrorV1::InvalidPolicy));
    let mut full = policy(4);
    full.max_vectors = MAX_CLUSTER_VECTORS;
    let (r, v) = make(MAX_CLUSTER_VECTORS);
    assert!(ClusterEnvelopeV1::build(&text, &r, &v, "mock", full, CrawlSeed(5)).is_ok());
}

#[test]
fn malformed_policies_ranges_and_vectors_are_refused() {
    let (text, ranges, vectors) = fixture();
    let build = |text: &str, r: &[SourceRangeV1], v: &[Vec<f32>], p: ClusterPolicyV1| {
        ClusterEnvelopeV1::build(text, r, v, "mock", p, CrawlSeed(1))
    };
    for bad in [
        {
            let mut p = policy(3);
            p.version = 2;
            p
        },
        policy(0),
        policy(65),
        {
            let mut p = policy(3);
            p.max_iterations = 0;
            p
        },
    ] {
        assert_eq!(
            build(&text, &ranges, &vectors, bad),
            Err(ClusterErrorV1::InvalidPolicy)
        );
    }
    assert!(matches!(
        build(&text, &ranges, &vectors[..5], policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    assert!(matches!(
        build(&text, &[], &[], policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut ragged = vectors.clone();
    ragged[2].pop();
    assert!(matches!(
        build(&text, &ranges, &ragged, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut nan = vectors.clone();
    nan[0][0] = f32::NAN;
    assert!(matches!(
        build(&text, &ranges, &nan, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut inf = vectors.clone();
    inf[1][1] = f32::INFINITY;
    assert!(matches!(
        build(&text, &ranges, &inf, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut past = ranges.clone();
    past[0] = SourceRangeV1::new(0, text.len() + 1);
    assert!(matches!(
        build(&text, &past, &vectors, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut empty = ranges.clone();
    empty[0] = SourceRangeV1::new(3, 3);
    assert!(matches!(
        build(&text, &empty, &vectors, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    let mut dup = ranges.clone();
    dup[1] = dup[0];
    assert!(matches!(
        build(&text, &dup, &vectors, policy(3)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
    // A range that splits a multi-byte scalar is refused.
    let wide = "日本語";
    let split = [SourceRangeV1::new(1, 3)];
    assert!(matches!(
        build(wide, &split, &[vec![1.0]], policy(1)),
        Err(ClusterErrorV1::InvalidInput(_))
    ));
}

#[test]
fn envelope_validation_detects_stale_text_policy_and_edits() {
    let (text, ranges, vectors) = fixture();
    let p = policy(3);
    let good = ClusterEnvelopeV1::build(&text, &ranges, &vectors, "mock", p, CrawlSeed(2)).unwrap();
    good.validate(&text, &p).unwrap();
    assert_eq!(
        good.validate("different", &p),
        Err(ClusterErrorV1::InvalidEnvelope)
    );
    assert_eq!(
        good.validate(&text, &policy(2)),
        Err(ClusterErrorV1::InvalidEnvelope)
    );
    let mut moved = good.clone();
    moved.clusters[0].members[0] = SourceRangeV1::new(0, text.len() + 5);
    assert_eq!(moved.validate(&text, &p), Err(ClusterErrorV1::InvalidEnvelope));
    let mut twice = good.clone();
    let dup = twice.clusters[0].members[0];
    twice.clusters[1].members.push(dup);
    assert_eq!(twice.validate(&text, &p), Err(ClusterErrorV1::InvalidEnvelope));
    let mut swapped = good.clone();
    swapped.clusters.swap(0, 1);
    assert_eq!(swapped.validate(&text, &p), Err(ClusterErrorV1::InvalidEnvelope));
    let wire = serde_json::to_string(&good).unwrap();
    assert_eq!(serde_json::from_str::<ClusterEnvelopeV1>(&wire).unwrap(), good);
}
