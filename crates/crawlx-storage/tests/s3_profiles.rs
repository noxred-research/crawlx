//! S3 profiles: parsing, per-profile defaults and overrides, every capability refusal,
//! checksum and addressing behavior observed on the in-process fake S3 (always runs), and
//! an env-gated conformance run per profile against a real endpoint
//! (`CRAWLX_TEST_S3_ENDPOINT`, `CRAWLX_TEST_S3_PROFILE`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::StoreError;
use crawlx_storage::artifacts::ArtifactBlobs;
use crawlx_storage::s3::{
    ChecksumMode, PlainHttp, S3Blobs, S3Config, S3ConfigError, S3Profile, Sse, SINGLE_PUT_MAX_BYTES,
};
use crawlx_storage::testkit::fake_s3::{FakeS3, RequestRecord};
use std::collections::BTreeMap;
use std::time::Duration;

fn env(vars: &[(&str, &str)]) -> BTreeMap<String, String> {
    vars.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn config(vars: &[(&str, &str)]) -> Result<S3Config, S3ConfigError> {
    let vars = env(vars);
    S3Config::from_lookup(&|name| vars.get(name).cloned())
}

/// The error of an environment that must be refused.
fn refused(vars: &[(&str, &str)]) -> S3ConfigError {
    config(vars).expect_err("configuration must be refused")
}

const EDGE_ENDPOINT: &str = "https://acct.edge.example.test";
const COMPAT_ENDPOINT: &str = "https://objects.example.test";
const LAN_ENDPOINT: &str = "http://192.168.1.5:9000";

// ---- parsing, defaults, overrides ------------------------------------------------

#[test]
fn profile_labels_round_trip_and_the_default_is_standard() {
    for profile in S3Profile::ALL {
        assert_eq!(S3Profile::parse(profile.as_str()).unwrap(), profile);
        assert_eq!(profile.to_string(), profile.as_str());
    }
    assert_eq!(S3Profile::parse(" Self_Hosted ").unwrap(), S3Profile::SelfHosted);
    assert_eq!(S3Profile::parse("EDGE").unwrap(), S3Profile::Edge);
    assert_eq!(S3Profile::default(), S3Profile::Standard);
    assert_eq!(
        S3Profile::parse("object-store"),
        Err(S3ConfigError::UnknownProfile("object-store".to_owned()))
    );
    assert_eq!(
        S3Profile::parse(""),
        Err(S3ConfigError::UnknownProfile(String::new()))
    );
    assert_eq!(
        ChecksumMode::parse("Required").unwrap(),
        ChecksumMode::WhenRequired
    );
    assert_eq!(
        ChecksumMode::parse("when_supported").unwrap(),
        ChecksumMode::WhenSupported
    );
    assert!(matches!(
        ChecksumMode::parse("always"),
        Err(S3ConfigError::InvalidValue {
            var: "CRAWLX_S3_CHECKSUM",
            ..
        })
    ));
}

#[test]
fn capabilities_table_matches_the_documented_profiles() {
    let standard = S3Profile::Standard.capabilities();
    assert!(!standard.endpoint_required && standard.object_lock && standard.extended_checksums);
    assert!(standard.sse_aes256 && standard.sse_kms && !standard.kms_needs_opt_in);
    assert_eq!(
        (standard.default_region, standard.default_path_style),
        ("us-east-1", false)
    );
    assert_eq!(standard.plain_http, PlainHttp::Unrestricted);

    let compatible = S3Profile::Compatible.capabilities();
    assert!(compatible.endpoint_required && compatible.default_path_style);
    assert!(compatible.sse_kms && compatible.kms_needs_opt_in && !compatible.extended_checksums);
    assert_eq!(compatible.plain_http, PlainHttp::PrivateHostsOnly);

    let edge = S3Profile::Edge.capabilities();
    assert!(edge.endpoint_required && edge.default_path_style);
    assert_eq!(edge.default_region, "auto");
    assert!(!edge.sse_aes256 && !edge.sse_kms && !edge.object_lock && !edge.extended_checksums);
    assert_eq!(edge.plain_http, PlainHttp::Refused);

    let self_hosted = S3Profile::SelfHosted.capabilities();
    assert!(self_hosted.endpoint_required && self_hosted.default_path_style);
    assert!(self_hosted.sse_aes256 && self_hosted.sse_kms && !self_hosted.kms_needs_opt_in);
    assert!(self_hosted.object_lock && !self_hosted.extended_checksums);
    assert_eq!(self_hosted.plain_http, PlainHttp::PrivateHostsOnly);

    for profile in S3Profile::ALL {
        assert_eq!(profile.capabilities().single_put_max_bytes, SINGLE_PUT_MAX_BYTES);
    }
}

#[test]
fn unset_profile_keeps_the_historical_standard_behavior() {
    let cfg = config(&[("CRAWLX_S3_BUCKET", "b")]).unwrap();
    assert_eq!(cfg.profile, S3Profile::Standard);
    assert_eq!(cfg.bucket, "b");
    assert_eq!(cfg.region, "us-east-1");
    assert_eq!(cfg.endpoint, None);
    assert!(!cfg.path_style);
    assert_eq!(cfg.sse, None);
    assert_eq!(cfg.checksum, ChecksumMode::WhenRequired);
    assert!(!cfg.object_lock && !cfg.allow_http && !cfg.allow_kms);
    assert_eq!(cfg, S3Config::new("b", "us-east-1"));

    // the previous recipe for a local server: endpoint + path style, plain http, any host
    let legacy = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_ENDPOINT", "http://objects.example.test:9000"),
        ("CRAWLX_S3_PATH_STYLE", "true"),
        ("CRAWLX_S3_SSE", "aes256"),
    ])
    .unwrap();
    assert_eq!(legacy.profile, S3Profile::Standard);
    assert!(legacy.path_style);
    assert_eq!(legacy.sse, Some(Sse::Aes256));
}

#[test]
fn profile_defaults_fill_region_and_addressing() {
    let compatible = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "compatible"),
        ("CRAWLX_S3_ENDPOINT", COMPAT_ENDPOINT),
    ])
    .unwrap();
    assert_eq!(compatible.profile, S3Profile::Compatible);
    assert_eq!(compatible.region, "us-east-1");
    assert!(compatible.path_style);
    assert_eq!(compatible.checksum, ChecksumMode::WhenRequired);
    assert_eq!(compatible.endpoint.as_deref(), Some(COMPAT_ENDPOINT));

    let edge = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "edge"),
        ("CRAWLX_S3_ENDPOINT", EDGE_ENDPOINT),
    ])
    .unwrap();
    assert_eq!(edge.profile, S3Profile::Edge);
    assert_eq!(edge.region, "auto");
    assert!(edge.path_style);
    assert_eq!(edge.checksum, ChecksumMode::WhenRequired);
    assert_eq!(edge.sse, None);
    assert!(!edge.object_lock);

    let self_hosted = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "self-hosted"),
        ("CRAWLX_S3_ENDPOINT", LAN_ENDPOINT),
    ])
    .unwrap();
    assert_eq!(self_hosted.profile, S3Profile::SelfHosted);
    assert_eq!(self_hosted.region, "us-east-1");
    assert!(self_hosted.path_style);
    assert!(!self_hosted.allow_http, "private hosts need no opt-in");
}

#[test]
fn explicit_environment_overrides_profile_defaults() {
    let compatible = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "Compatible"),
        ("CRAWLX_S3_ENDPOINT", COMPAT_ENDPOINT),
        ("CRAWLX_S3_REGION", "eu-west-1"),
        ("CRAWLX_S3_PATH_STYLE", "off"),
        ("CRAWLX_S3_SSE", "kms"),
        ("CRAWLX_S3_KMS_KEY_ID", "key-1"),
        ("CRAWLX_S3_ALLOW_KMS", "1"),
        ("CRAWLX_S3_OBJECT_LOCK", "yes"),
    ])
    .unwrap();
    assert_eq!(compatible.region, "eu-west-1");
    assert!(!compatible.path_style);
    assert_eq!(
        compatible.sse,
        Some(Sse::CloudKms {
            key_id: Some("key-1".to_owned())
        })
    );
    assert!(compatible.allow_kms && compatible.object_lock);

    let edge = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "edge"),
        ("CRAWLX_S3_ENDPOINT", EDGE_ENDPOINT),
        ("CRAWLX_S3_REGION", "us-east-1"),
        ("CRAWLX_S3_PATH_STYLE", "0"),
        ("CRAWLX_S3_CHECKSUM", "when_required"),
        ("CRAWLX_S3_OBJECT_LOCK", "false"),
    ])
    .unwrap();
    assert_eq!(edge.region, "us-east-1");
    assert!(!edge.path_style);

    let standard = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_CHECKSUM", "when_supported"),
        ("CRAWLX_S3_OBJECT_LOCK", "1"),
        ("CRAWLX_S3_SSE", "kms"),
    ])
    .unwrap();
    assert_eq!(standard.checksum, ChecksumMode::WhenSupported);
    assert!(standard.object_lock);
    assert_eq!(standard.sse, Some(Sse::CloudKms { key_id: None }));

    // blank values count as unset, so they fall back to the profile default
    let blank = config(&[
        ("CRAWLX_S3_BUCKET", "b"),
        ("CRAWLX_S3_PROFILE", "  "),
        ("CRAWLX_S3_REGION", " "),
        ("CRAWLX_S3_ENDPOINT", ""),
    ])
    .unwrap();
    assert_eq!(blank, S3Config::new("b", "us-east-1"));

    let explicit_bucket = {
        let vars = env(&[("CRAWLX_S3_BUCKET", "ignored"), ("CRAWLX_S3_PROFILE", "edge")]);
        S3Config::from_lookup_for_bucket("given", &|name| vars.get(name).cloned())
    };
    assert_eq!(
        explicit_bucket,
        Err(S3ConfigError::EndpointRequired {
            profile: S3Profile::Edge
        })
    );
}

// ---- refusals --------------------------------------------------------------------

#[test]
fn missing_bucket_unknown_values_and_malformed_endpoints_are_refused() {
    assert_eq!(config(&[]), Err(S3ConfigError::BucketMissing));
    assert_eq!(
        config(&[("CRAWLX_S3_BUCKET", "  ")]),
        Err(S3ConfigError::BucketMissing)
    );
    assert_eq!(
        S3Config::from_lookup_for_bucket(" ", &|_| None),
        Err(S3ConfigError::BucketMissing)
    );
    assert_eq!(
        refused(&[("CRAWLX_S3_BUCKET", "b"), ("CRAWLX_S3_PROFILE", "premium")]),
        S3ConfigError::UnknownProfile("premium".to_owned())
    );
    for (var, value, expected) in [
        (
            "CRAWLX_S3_PATH_STYLE",
            "maybe",
            "1, true, yes, on, 0, false, no or off",
        ),
        (
            "CRAWLX_S3_OBJECT_LOCK",
            "2",
            "1, true, yes, on, 0, false, no or off",
        ),
        (
            "CRAWLX_S3_ALLOW_HTTP",
            "y",
            "1, true, yes, on, 0, false, no or off",
        ),
        ("CRAWLX_S3_ALLOW_KMS", "", "unused"),
        ("CRAWLX_S3_CHECKSUM", "crc32", "when_required or when_supported"),
        ("CRAWLX_S3_SSE", "rot13", "aes256 or kms"),
    ] {
        if value.is_empty() {
            continue; // blank is "unset", not invalid
        }
        match refused(&[("CRAWLX_S3_BUCKET", "b"), (var, value)]) {
            S3ConfigError::InvalidValue {
                var: v,
                value: got,
                expected: want,
            } => {
                assert_eq!((v, got.as_str(), want), (var, value, expected));
            }
            other => panic!("{var}: {other:?}"),
        }
    }
    for endpoint in [
        "objects.example.test",
        "ftp://objects.example.test",
        "https://user:secret@objects.example.test",
        "https://objects.example.test/?x=1",
        "https://objects.example.test/#frag",
    ] {
        match refused(&[
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", "compatible"),
            ("CRAWLX_S3_ENDPOINT", endpoint),
        ]) {
            S3ConfigError::EndpointInvalid(why) => {
                assert!(!why.contains("secret"), "no credentials in errors: {why}");
            }
            other => panic!("{endpoint}: {other:?}"),
        }
    }
    let mut cfg = S3Config::new("b", "us-east-1");
    cfg.region = "  ".to_owned();
    assert_eq!(cfg.validate(), Err(S3ConfigError::RegionEmpty));
}

#[test]
fn profiles_without_a_default_endpoint_require_one() {
    for profile in ["compatible", "edge", "self-hosted"] {
        let parsed = S3Profile::parse(profile).unwrap();
        assert_eq!(
            refused(&[("CRAWLX_S3_BUCKET", "b"), ("CRAWLX_S3_PROFILE", profile)]),
            S3ConfigError::EndpointRequired { profile: parsed },
            "{profile}"
        );
    }
    assert!(config(&[("CRAWLX_S3_BUCKET", "b"), ("CRAWLX_S3_PROFILE", "standard")]).is_ok());
}

#[test]
fn plain_http_follows_the_profile_policy() {
    // edge: never without the opt-in, even on loopback
    for endpoint in ["http://acct.edge.example.test", "http://127.0.0.1:9000"] {
        let vars = [
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", "edge"),
            ("CRAWLX_S3_ENDPOINT", endpoint),
        ];
        assert!(matches!(
            refused(&vars),
            S3ConfigError::PlainHttpRefused {
                profile: S3Profile::Edge,
                ..
            }
        ));
        let mut opted_in = vars.to_vec();
        opted_in.push(("CRAWLX_S3_ALLOW_HTTP", "1"));
        assert!(config(&opted_in).unwrap().allow_http);
    }
    // compatible and self-hosted: private hosts yes, public hosts only with the opt-in
    for profile in ["compatible", "self-hosted"] {
        for private in [
            LAN_ENDPOINT,
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
            "http://store.lan:9000",
            "http://store:9000",
        ] {
            config(&[
                ("CRAWLX_S3_BUCKET", "b"),
                ("CRAWLX_S3_PROFILE", profile),
                ("CRAWLX_S3_ENDPOINT", private),
            ])
            .unwrap_or_else(|e| panic!("{profile} {private}: {e}"));
        }
        let public = [
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", profile),
            ("CRAWLX_S3_ENDPOINT", "http://objects.example.test:9000"),
        ];
        let err = refused(&public);
        assert_eq!(
            err,
            S3ConfigError::PlainHttpRefused {
                profile: S3Profile::parse(profile).unwrap(),
                host: "objects.example.test".to_owned(),
            }
        );
        assert!(err.to_string().contains("CRAWLX_S3_ALLOW_HTTP=1"), "{err}");
        let mut opted_in = public.to_vec();
        opted_in.push(("CRAWLX_S3_ALLOW_HTTP", "true"));
        assert!(config(&opted_in).is_ok());
        // https is always fine
        config(&[
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", profile),
            ("CRAWLX_S3_ENDPOINT", COMPAT_ENDPOINT),
        ])
        .unwrap();
    }
}

#[test]
fn encryption_follows_the_profile_capabilities() {
    let base = |profile: &'static str, endpoint: &'static str, sse: &'static str| {
        vec![
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", profile),
            ("CRAWLX_S3_ENDPOINT", endpoint),
            ("CRAWLX_S3_SSE", sse),
        ]
    };
    // edge: no server-side encryption of any kind
    assert_eq!(
        refused(&base("edge", EDGE_ENDPOINT, "aes256")),
        S3ConfigError::SseRefused {
            profile: S3Profile::Edge,
            sse: "aes256"
        }
    );
    assert_eq!(
        refused(&base("edge", EDGE_ENDPOINT, "kms")),
        S3ConfigError::SseRefused {
            profile: S3Profile::Edge,
            sse: "kms"
        }
    );
    // compatible: kms only when opted in, aes256 always
    assert_eq!(
        refused(&base("compatible", COMPAT_ENDPOINT, "kms")),
        S3ConfigError::KmsNotAllowed {
            profile: S3Profile::Compatible
        }
    );
    let mut allowed = base("compatible", COMPAT_ENDPOINT, "kms");
    allowed.push(("CRAWLX_S3_ALLOW_KMS", "1"));
    assert!(config(&allowed).is_ok());
    assert_eq!(
        config(&base("compatible", COMPAT_ENDPOINT, "aes256"))
            .unwrap()
            .sse,
        Some(Sse::Aes256)
    );
    // self-hosted and standard: both modes, no opt-in
    for sse in ["aes256", "kms"] {
        assert!(config(&base("self-hosted", LAN_ENDPOINT, sse)).is_ok());
        assert!(config(&[("CRAWLX_S3_BUCKET", "b"), ("CRAWLX_S3_SSE", sse)]).is_ok());
    }
    // a key id without kms would silently drop the key: refused
    for vars in [
        vec![("CRAWLX_S3_BUCKET", "b"), ("CRAWLX_S3_KMS_KEY_ID", "k")],
        vec![
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_SSE", "aes256"),
            ("CRAWLX_S3_KMS_KEY_ID", "k"),
        ],
    ] {
        assert_eq!(refused(&vars), S3ConfigError::KmsKeyWithoutKms);
    }
}

#[test]
fn object_lock_and_checksum_modes_follow_the_profile_capabilities() {
    assert_eq!(
        refused(&[
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", "edge"),
            ("CRAWLX_S3_ENDPOINT", EDGE_ENDPOINT),
            ("CRAWLX_S3_OBJECT_LOCK", "1"),
        ]),
        S3ConfigError::ObjectLockRefused {
            profile: S3Profile::Edge
        }
    );
    let message = S3ConfigError::ObjectLockRefused {
        profile: S3Profile::Edge,
    }
    .to_string();
    assert!(
        message.contains("edge") && message.contains("object lock"),
        "{message}"
    );
    for (profile, endpoint) in [
        ("standard", ""),
        ("compatible", COMPAT_ENDPOINT),
        ("self-hosted", LAN_ENDPOINT),
    ] {
        let mut vars = vec![
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PROFILE", profile),
            ("CRAWLX_S3_OBJECT_LOCK", "1"),
        ];
        if !endpoint.is_empty() {
            vars.push(("CRAWLX_S3_ENDPOINT", endpoint));
        }
        assert!(config(&vars).unwrap().object_lock, "{profile}");
    }
    for (profile, endpoint) in [
        ("compatible", COMPAT_ENDPOINT),
        ("edge", EDGE_ENDPOINT),
        ("self-hosted", LAN_ENDPOINT),
    ] {
        assert_eq!(
            refused(&[
                ("CRAWLX_S3_BUCKET", "b"),
                ("CRAWLX_S3_PROFILE", profile),
                ("CRAWLX_S3_ENDPOINT", endpoint),
                ("CRAWLX_S3_CHECKSUM", "when_supported"),
            ]),
            S3ConfigError::ChecksumRefused {
                profile: S3Profile::parse(profile).unwrap(),
                mode: ChecksumMode::WhenSupported
            },
            "{profile}"
        );
    }
}

#[test]
fn error_messages_are_lowercase_and_convert_to_store_conflicts() {
    for error in [
        S3ConfigError::BucketMissing,
        S3ConfigError::EndpointRequired {
            profile: S3Profile::Edge,
        },
        S3ConfigError::SseRefused {
            profile: S3Profile::Edge,
            sse: "kms",
        },
        S3ConfigError::ChecksumRefused {
            profile: S3Profile::Compatible,
            mode: ChecksumMode::WhenSupported,
        },
    ] {
        let text = error.to_string();
        assert!(
            text.starts_with("CRAWLX_") || !text.starts_with(|c: char| c.is_uppercase()),
            "{text}"
        );
        assert!(matches!(StoreError::from(error), StoreError::Conflict(msg) if msg == text));
    }
}

#[tokio::test]
async fn the_backend_refuses_a_hand_built_configuration_that_the_profile_cannot_serve() {
    let credentials = FakeS3::credentials;
    let mut edge = S3Config::for_profile(S3Profile::Edge, "b").with_endpoint(EDGE_ENDPOINT);
    assert!(S3Blobs::with_credentials(&edge, credentials()).is_ok());
    edge.sse = Some(Sse::Aes256);
    assert!(matches!(
        S3Blobs::with_credentials(&edge, credentials()),
        Err(S3ConfigError::SseRefused { .. })
    ));
    edge.sse = None;
    edge.object_lock = true;
    assert!(matches!(
        S3Blobs::with_credentials(&edge, credentials()),
        Err(S3ConfigError::ObjectLockRefused { .. })
    ));
    edge.object_lock = false;
    edge.endpoint = None;
    assert!(matches!(
        S3Blobs::with_credentials(&edge, credentials()),
        Err(S3ConfigError::EndpointRequired { .. })
    ));
    let mut compat = S3Config::for_profile(S3Profile::Compatible, "b").with_endpoint(COMPAT_ENDPOINT);
    compat.checksum = ChecksumMode::WhenSupported;
    assert!(matches!(
        S3Blobs::new(&compat),
        Err(S3ConfigError::ChecksumRefused { .. })
    ));
    assert_eq!(
        S3Blobs::with_credentials(&S3Config::new("b", "us-east-1"), credentials())
            .unwrap()
            .profile(),
        S3Profile::Standard
    );
}

// ---- wire behavior on the fake server --------------------------------------------

async fn fake() -> FakeS3 {
    FakeS3::start().await.unwrap()
}

fn is_checksum_header(name: &str) -> bool {
    name.starts_with("x-amz-checksum-") || name == "x-amz-sdk-checksum-algorithm" || name == "x-amz-trailer"
}

fn checksum_headers(record: &RequestRecord) -> Vec<&str> {
    record
        .headers
        .keys()
        .map(String::as_str)
        .filter(|name| is_checksum_header(name))
        .collect()
}

fn puts(fake: &FakeS3) -> Vec<RequestRecord> {
    fake.requests()
        .into_iter()
        .filter(|r| r.method == "PUT")
        .collect()
}

/// put, get, head, list and delete against the fake.
async fn exercise(blobs: &S3Blobs) {
    blobs.put("content/a", b"alpha").await.unwrap();
    blobs.put("content/b", b"beta").await.unwrap();
    blobs.put("content/c", b"gamma").await.unwrap();
    assert_eq!(
        blobs.get("content/a").await.unwrap().as_deref(),
        Some(&b"alpha"[..])
    );
    assert!(blobs.exists("content/b").await.unwrap());
    let keys: Vec<String> = blobs
        .list("content/")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(
        keys,
        ["content/a", "content/b", "content/c"],
        "pagination follows continuation tokens"
    );
    blobs.delete("content/a").await.unwrap();
    assert_eq!(blobs.get("content/a").await.unwrap(), None);
}

#[tokio::test]
async fn every_profile_serves_the_operations_with_its_signing_region_and_path_style_shape() {
    for profile in S3Profile::ALL {
        let fake = fake().await;
        let mut cfg = fake.config(profile);
        cfg.path_style = true; // the fake is addressed by IP, which the SDK serves path-style
        let blobs = fake.blobs_with(&cfg).unwrap();
        assert_eq!(blobs.profile(), profile);
        exercise(&blobs).await;

        let requests = fake.requests();
        assert!(requests.len() >= 8, "{profile}: {requests:?}");
        let region = profile.capabilities().default_region;
        for request in &requests {
            assert!(
                request.path == "/artifacts" || request.path.starts_with("/artifacts/"),
                "{profile}: path-style bucket in the path: {}",
                request.path
            );
            assert_eq!(
                request.header("host"),
                Some(fake.endpoint().trim_start_matches("http://")),
                "{profile}: path-style keeps the endpoint host"
            );
            let scope = request.header("signing-scope").unwrap();
            assert!(
                scope.ends_with(&format!("/{region}/s3/aws4_request")),
                "{profile}: {scope}"
            );
        }
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.method == "GET" && r.query.as_deref().is_some_and(|q| q.contains("list-type=2")))
                .count(),
            2,
            "{profile}: one list request per page of two keys"
        );
    }
}

#[tokio::test]
async fn checksums_stay_off_the_wire_unless_the_profile_allows_and_the_operator_asks() {
    // when_required (the default of every profile): no checksum header or trailer on uploads
    for profile in S3Profile::ALL {
        let fake = fake().await;
        let cfg = fake.config(profile);
        assert_eq!(cfg.checksum, ChecksumMode::WhenRequired);
        let blobs = fake.blobs_with(&cfg).unwrap();
        exercise(&blobs).await;
        let uploads = puts(&fake);
        assert_eq!(uploads.len(), 3, "{profile}");
        for upload in &uploads {
            assert!(
                checksum_headers(upload).is_empty(),
                "{profile}: {:?}",
                upload.headers
            );
            assert_ne!(
                upload.header("content-encoding"),
                Some("aws-chunked"),
                "{profile}: no trailer encoding"
            );
        }
        assert_eq!(fake.objects().get("content/b").unwrap(), b"beta", "{profile}");
    }

    // when_supported, accepted on the standard profile only: uploads carry a CRC32
    let fake = fake().await;
    let mut cfg = fake.config(S3Profile::Standard);
    cfg.checksum = ChecksumMode::WhenSupported;
    cfg.path_style = true;
    let blobs = fake.blobs_with(&cfg).unwrap();
    blobs.put("content/crc", b"payload").await.unwrap();
    let uploads = puts(&fake);
    assert_eq!(uploads.len(), 1);
    assert!(
        !checksum_headers(&uploads[0]).is_empty(),
        "{:?}",
        uploads[0].headers
    );
    assert_eq!(
        fake.objects().get("content/crc").unwrap(),
        b"payload",
        "the fake stores the decoded body"
    );
}

#[tokio::test]
async fn object_lock_buckets_receive_a_checksum_on_every_upload_and_archives_too() {
    for profile in [S3Profile::Standard, S3Profile::Compatible, S3Profile::SelfHosted] {
        let fake = fake().await;
        let mut cfg = fake.config(profile);
        cfg.path_style = true;
        cfg.object_lock = true;
        cfg.allow_kms = true;
        let blobs = fake.blobs_with(&cfg).unwrap();
        blobs.put("audit/x", b"first").await.unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"archived").unwrap();
        blobs.put_file("audit/y", file.path(), 8).await.unwrap();
        let uploads = puts(&fake);
        assert_eq!(uploads.len(), 2, "{profile}");
        for upload in &uploads {
            assert!(
                upload
                    .header("x-amz-sdk-checksum-algorithm")
                    .is_some_and(|a| a.eq_ignore_ascii_case("crc32")),
                "{profile}: {:?}",
                upload.headers
            );
        }
        assert_eq!(fake.objects().get("audit/x").unwrap(), b"first", "{profile}");
        assert_eq!(fake.objects().get("audit/y").unwrap(), b"archived", "{profile}");
    }
}

#[tokio::test]
async fn encryption_headers_are_sent_where_the_profile_allows_them() {
    let fake = fake().await;
    let mut self_hosted = fake.config(S3Profile::SelfHosted);
    self_hosted.sse = Some(Sse::Aes256);
    fake.blobs_with(&self_hosted)
        .unwrap()
        .put("k/aes", b"x")
        .await
        .unwrap();

    let mut compatible = fake.config(S3Profile::Compatible);
    compatible.sse = Some(Sse::CloudKms {
        key_id: Some("key-7".to_owned()),
    });
    assert!(matches!(
        fake.blobs_with(&compatible),
        Err(S3ConfigError::KmsNotAllowed { .. })
    ));
    compatible.allow_kms = true;
    fake.blobs_with(&compatible)
        .unwrap()
        .put("k/kms", b"x")
        .await
        .unwrap();

    // edge has no encryption mode: nothing is requested, and nothing can be configured
    let edge = fake.config(S3Profile::Edge);
    fake.blobs_with(&edge).unwrap().put("k/none", b"x").await.unwrap();

    let log = fake.log();
    let sent = |key: &str| {
        log.iter()
            .find(|(m, k, ..)| m == "PUT" && k == key)
            .map(|(_, _, sse, kms)| (sse.clone(), kms.clone()))
            .unwrap()
    };
    assert_eq!(sent("k/aes"), (Some("AES256".to_owned()), None));
    assert_eq!(
        sent("k/kms"),
        (Some("aws:kms".to_owned()), Some("key-7".to_owned())) // wire-compat: S3 SSE algorithm label
    );
    assert_eq!(sent("k/none"), (None, None));
}

#[tokio::test]
async fn archives_work_on_every_profile_and_oversized_objects_are_refused_before_any_request() {
    for profile in S3Profile::ALL {
        let fake = fake().await;
        let mut cfg = fake.config(profile);
        cfg.path_style = true;
        let blobs = fake.blobs_with(&cfg).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"0123456789").unwrap();
        blobs.put_file("archive/ok", file.path(), 10).await.unwrap();
        assert_eq!(
            fake.objects().get("archive/ok").unwrap(),
            b"0123456789",
            "{profile}"
        );
        fake.clear_log();
        match blobs
            .put_file("archive/big", file.path(), SINGLE_PUT_MAX_BYTES + 1)
            .await
        {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.contains("single-put limit") && msg.contains(profile.as_str()),
                    "{msg}"
                );
            }
            other => panic!("{profile}: expected Conflict, got {other:?}"),
        }
        assert!(
            fake.requests().is_empty(),
            "{profile}: refused before any request"
        );
        assert!(!fake.keys().contains(&"archive/big".to_owned()));
    }
}

// ---- presigned URLs (no network) -------------------------------------------------

fn presign_blobs(cfg: &S3Config) -> S3Blobs {
    S3Blobs::with_credentials(cfg, FakeS3::credentials()).unwrap()
}

async fn presigned(cfg: &S3Config) -> url::Url {
    presign_blobs(cfg)
        .presign("content/key", Duration::from_secs(60))
        .await
        .unwrap()
        .expect("every profile presigns")
}

fn query(url: &url::Url) -> BTreeMap<String, String> {
    url.query_pairs().into_owned().collect()
}

#[tokio::test]
async fn presigned_urls_follow_each_profiles_addressing_and_region() {
    // standard: virtual-hosted, regional signing, no endpoint configured
    let standard = presigned(&S3Config::new("artifacts", "us-east-1")).await;
    assert_eq!(standard.scheme(), "https");
    assert!(
        standard
            .host_str()
            .unwrap()
            .starts_with("artifacts.s3.us-east-1."),
        "bucket in the host: {standard}"
    );
    assert_eq!(standard.path(), "/content/key");
    assert!(query(&standard)["X-Amz-Credential"].contains("/us-east-1/s3/aws4_request"));

    // compatible: path-style by default, virtual-hosted on request
    let mut compatible =
        S3Config::for_profile(S3Profile::Compatible, "artifacts").with_endpoint(COMPAT_ENDPOINT);
    let path_style = presigned(&compatible).await;
    assert_eq!(path_style.host_str(), Some("objects.example.test"));
    assert_eq!(path_style.path(), "/artifacts/content/key");
    compatible.path_style = false;
    let virtual_host = presigned(&compatible).await;
    assert_eq!(virtual_host.host_str(), Some("artifacts.objects.example.test"));
    assert_eq!(virtual_host.path(), "/content/key");

    // edge: account-scoped https endpoint, region auto
    let edge =
        presigned(&S3Config::for_profile(S3Profile::Edge, "artifacts").with_endpoint(EDGE_ENDPOINT)).await;
    assert_eq!(edge.host_str(), Some("acct.edge.example.test"));
    assert_eq!(edge.path(), "/artifacts/content/key");
    assert!(
        query(&edge)["X-Amz-Credential"].contains("/auto/s3/aws4_request"),
        "{edge}"
    );

    // self-hosted: plain http on a private host, path-style
    let lan =
        presigned(&S3Config::for_profile(S3Profile::SelfHosted, "artifacts").with_endpoint(LAN_ENDPOINT))
            .await;
    assert_eq!(
        (lan.scheme(), lan.host_str(), lan.port()),
        ("http", Some("192.168.1.5"), Some(9000))
    );
    assert_eq!(lan.path(), "/artifacts/content/key");

    for url in [&standard, &path_style, &virtual_host, &edge, &lan] {
        let q = query(url);
        assert_eq!(q["X-Amz-Expires"], "60", "{url}");
        assert!(q.contains_key("X-Amz-Signature"), "{url}");
        assert!(
            !q.keys().any(|k| k.to_ascii_lowercase().contains("checksum")),
            "a presigned GET carries no checksum parameter: {url}"
        );
        assert!(!url.as_str().contains("test-secret-key"), "{url}");
    }
}

#[tokio::test]
async fn presign_ttl_beyond_the_signature_limit_is_a_typed_error_not_a_clamp() {
    let blobs = presign_blobs(&S3Config::new("artifacts", "us-east-1"));
    match blobs
        .presign("content/key", Duration::from_secs(8 * 24 * 3600))
        .await
    {
        Err(StoreError::Conflict(msg)) => assert!(msg.starts_with("s3 presign content/key"), "{msg}"),
        other => panic!("expected Conflict, got {other:?}"),
    }
}

// ---- real endpoints (env-gated) --------------------------------------------------

/// Plain HTTP/1.1 `GET` of an `http` URL; returns `(status, body)`.
async fn http_get(url: &url::Url) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let host = url.host_str().unwrap();
    let port = url.port_or_known_default().unwrap();
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.unwrap();
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    stream
        .write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

/// The configuration of the live endpoint for `expected`, or `None` (with a skip note) when
/// `CRAWLX_TEST_S3_ENDPOINT` is unset or `CRAWLX_TEST_S3_PROFILE` (default `self-hosted`)
/// names another profile. Every `CRAWLX_S3_*` option is read from its `CRAWLX_TEST_S3_*`
/// twin (region, path style, plain-http opt-in, ...); the bucket is `CRAWLX_TEST_S3_BUCKET`
/// (default `crawlx-artifacts`).
fn live_config(expected: S3Profile) -> Option<S3Config> {
    let Ok(endpoint) = std::env::var("CRAWLX_TEST_S3_ENDPOINT") else {
        eprintln!("skipped: CRAWLX_TEST_S3_ENDPOINT is not set");
        return None;
    };
    let selected = std::env::var("CRAWLX_TEST_S3_PROFILE").unwrap_or_else(|_| "self-hosted".to_owned());
    let selected = S3Profile::parse(&selected).expect("CRAWLX_TEST_S3_PROFILE");
    if selected != expected {
        eprintln!("skipped: CRAWLX_TEST_S3_PROFILE is {selected}, not {expected}");
        return None;
    }
    let bucket = std::env::var("CRAWLX_TEST_S3_BUCKET").unwrap_or_else(|_| "crawlx-artifacts".to_owned());
    let lookup = |name: &str| match name {
        "CRAWLX_S3_PROFILE" => Some(expected.as_str().to_owned()),
        "CRAWLX_S3_ENDPOINT" => Some(endpoint.clone()),
        other => std::env::var(other.replacen("CRAWLX_S3_", "CRAWLX_TEST_S3_", 1)).ok(),
    };
    Some(S3Config::from_lookup_for_bucket(&bucket, &lookup).expect("live endpoint configuration"))
}

/// put, get, head, list, delete and presign against a real endpoint.
async fn live_conformance(profile: S3Profile) {
    let Some(mut cfg) = live_config(profile) else {
        return;
    };
    cfg.max_attempts = 3;
    let access = std::env::var("CRAWLX_TEST_S3_ACCESS_KEY").unwrap_or_else(|_| "crawlx".to_owned());
    let secret = std::env::var("CRAWLX_TEST_S3_SECRET_KEY").unwrap_or_else(|_| "crawlx-secret".to_owned());
    let blobs = S3Blobs::with_credentials(
        &cfg,
        aws_sdk_s3::config::Credentials::new(access, secret, None, None, "test"),
    )
    .unwrap();
    // readiness: the bucket exists once the server answers
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        match blobs.client().create_bucket().bucket(&cfg.bucket).send().await {
            Ok(_) => break,
            Err(e)
                if e.as_service_error()
                    .is_some_and(|s| s.is_bucket_already_owned_by_you() || s.is_bucket_already_exists()) =>
            {
                break;
            }
            Err(e) if tokio::time::Instant::now() < deadline => {
                eprintln!("endpoint not ready: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("endpoint did not become ready: {e}"),
        }
    }
    let prefix = format!("conformance-{}/", crawlx_core::TenantId::new());
    let key = |name: &str| format!("{prefix}{name}");
    assert!(!blobs.exists(&key("a")).await.unwrap());
    assert_eq!(blobs.get(&key("a")).await.unwrap(), None);
    blobs.put(&key("a"), b"alpha").await.unwrap();
    blobs.put(&key("b"), b"beta").await.unwrap();
    blobs.put(&key("c"), b"gamma").await.unwrap();
    assert!(blobs.exists(&key("a")).await.unwrap());
    assert_eq!(
        blobs.get(&key("a")).await.unwrap().as_deref(),
        Some(&b"alpha"[..])
    );
    blobs.put(&key("a"), b"alpha again").await.unwrap();
    assert_eq!(
        blobs.get(&key("a")).await.unwrap().as_deref(),
        Some(&b"alpha again"[..])
    );
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"archived").unwrap();
    blobs.put_file(&key("archive"), file.path(), 8).await.unwrap();
    let listed: Vec<String> = blobs
        .list(&prefix)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(listed, [key("a"), key("archive"), key("b"), key("c")]);
    let url = blobs
        .presign(&key("b"), Duration::from_secs(60))
        .await
        .unwrap()
        .expect("presigned url");
    assert!(query(&url).contains_key("X-Amz-Signature"), "{url}");
    if url.scheme() == "http" {
        let (status, body) = http_get(&url).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"beta");
    }
    for name in ["a", "archive", "b", "c"] {
        blobs.delete(&key(name)).await.unwrap();
    }
    blobs.delete(&key("a")).await.unwrap(); // a missing key is not an error
    assert!(!blobs.exists(&key("a")).await.unwrap());
    assert!(blobs.list(&prefix).await.unwrap().is_empty());
}

#[tokio::test]
async fn live_standard_profile_conformance() {
    live_conformance(S3Profile::Standard).await;
}

#[tokio::test]
async fn live_compatible_profile_conformance() {
    live_conformance(S3Profile::Compatible).await;
}

#[tokio::test]
async fn live_edge_profile_conformance() {
    live_conformance(S3Profile::Edge).await;
}

#[tokio::test]
async fn live_self_hosted_profile_conformance() {
    live_conformance(S3Profile::SelfHosted).await;
}
