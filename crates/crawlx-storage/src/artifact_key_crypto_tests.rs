#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::{artifact_crypto::ArtifactDecryption, testkit::fake_kms::LoopbackKms};
use aws_sdk_kms::config::{retry::RetryConfig, Credentials, Region};
use crawlx_core::{ArtifactId, CrawlRunId, TenantId};
use uuid::Uuid;

fn context() -> ArtifactContext {
    ArtifactContext::new(
        TenantId(Uuid::from_u128(1)),
        CrawlRunId(Uuid::from_u128(2)),
        ArtifactId(Uuid::from_u128(3)),
    )
}

fn memory() -> MemoryArtifactKeys {
    MemoryArtifactKeys {
        root: Arc::new(Zeroizing::new([0x29; 32])),
        key_id: "memory-artifact-only:deterministic-fixture".into(),
    }
}

fn kms(fixture: &LoopbackKms) -> KmsArtifactKeys {
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
        .build_https();
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            "fixture-access",
            "fixture-secret",
            None,
            None,
            "fixture",
        ))
        .http_client(http)
        .retry_config(RetryConfig::disabled())
        .endpoint_url(fixture.endpoint())
        .build();
    KmsArtifactKeys {
        client: Client::from_conf(config),
        key_id: fixture.key_id().to_owned(),
    }
}

async fn roundtrip(provider: &dyn ArtifactKeys) -> (ArtifactKeyEnvelope, Vec<u8>) {
    let scope = context();
    let plaintext = b"artifact-private-marker".repeat(5000);
    let length = u64::try_from(plaintext.len()).unwrap();
    let prepared = provider.prepare(&scope, length, length).await.unwrap();
    let mut ciphertext = Vec::new();
    let sealed = prepared
        .encryption
        .seal(plaintext.as_slice(), &mut ciphertext)
        .await
        .unwrap();
    let recovered_key = provider.open(&scope, &prepared.envelope).await.unwrap();
    assert_eq!(sealed.data_key.as_bytes(), recovered_key.as_bytes());
    assert!(!ciphertext
        .windows(32)
        .any(|window| window == recovered_key.as_bytes()));
    assert!(!ciphertext
        .windows(prepared.envelope.wrapped_key.len())
        .any(|window| window == prepared.envelope.wrapped_key));
    let mut consumer = ArtifactDecryption::new(ciphertext.as_slice(), scope, recovered_key, length)
        .await
        .unwrap();
    let mut recovered = Vec::new();
    while let Some(chunk) = consumer.next_chunk().await.unwrap() {
        recovered.extend_from_slice(&chunk);
    }
    assert_eq!(recovered, plaintext);
    assert_eq!(consumer.authenticated_len(), Some(length));
    (prepared.envelope, ciphertext)
}

#[tokio::test]
async fn memory_custody_is_explicit_ephemeral_and_production_envelope_incompatible() {
    let provider = memory();
    assert!(provider.is_available());
    assert!(!provider.is_durable());
    let (envelope, _) = roundtrip(&provider).await;
    assert_eq!(envelope.format_version, 0);
    let mut wrong_root = memory();
    wrong_root.root = Arc::new(Zeroizing::new([0x30; 32]));
    assert!(matches!(
        wrong_root.open(&context(), &envelope).await,
        Err(ArtifactKeyError::Authentication)
    ));
    let mut production_version = envelope.clone();
    production_version.format_version = 1;
    assert!(matches!(
        provider.open(&context(), &production_version).await,
        Err(ArtifactKeyError::InvalidEnvelope)
    ));
    for index in 0..envelope.wrapped_key.len() {
        let mut altered = envelope.clone();
        altered.wrapped_key[index] ^= 1;
        assert!(provider.open(&context(), &altered).await.is_err());
    }
}

fn key_file(contents: &str, mode: u32) -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.key");
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    let path = path.to_string_lossy().into_owned();
    (dir, path)
}

fn load(path: &str) -> Result<Option<FileArtifactKeys>, ArtifactKeyFileError> {
    FileArtifactKeys::from_lookup(&|name| (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| path.to_owned()))
}

#[tokio::test]
async fn file_custody_is_durable_version_one_and_bound_to_its_root_key() {
    assert!(FileArtifactKeys::from_lookup(&|_| None).unwrap().is_none());
    let hex = "3c".repeat(32);
    for suffix in ["", "\n"] {
        let (_dir, path) = key_file(&format!("{hex}{suffix}"), 0o600);
        let provider = load(&path).unwrap().unwrap();
        assert!(provider.is_available());
        assert!(provider.is_durable());
        assert!(!format!("{provider:?}").contains(&hex));
        let (envelope, _) = roundtrip(&provider).await;
        assert_eq!(envelope.format_version, 1);
        assert!(envelope.kms_key_id.starts_with("file-artifact-key:"));
        // A restarted process loading the same file unwraps existing envelopes.
        let restarted = load(&path).unwrap().unwrap();
        assert!(restarted.open(&context(), &envelope).await.is_ok());
        // Another root key, a foreign ownership context and tampered wrapped keys all fail closed.
        let (_other_dir, other_path) = key_file(&"4d".repeat(32), 0o600);
        let other = load(&other_path).unwrap().unwrap();
        assert!(other.open(&context(), &envelope).await.is_err());
        let foreign = ArtifactContext::new(
            TenantId(Uuid::from_u128(9)),
            CrawlRunId(Uuid::from_u128(2)),
            ArtifactId(Uuid::from_u128(3)),
        );
        assert!(restarted.open(&foreign, &envelope).await.is_err());
        for index in 0..envelope.wrapped_key.len() {
            let mut altered = envelope.clone();
            altered.wrapped_key[index] ^= 1;
            assert!(restarted.open(&context(), &altered).await.is_err());
        }
        // Memory custody cannot open production envelopes and vice versa.
        assert!(memory().open(&context(), &envelope).await.is_err());
    }
}

#[test]
fn file_custody_rejects_unsafe_or_malformed_key_files_without_echoing_contents() {
    let canary = "invalid-key-canary".repeat(8);
    for contents in [
        "".to_owned(),
        "ab".repeat(33),
        "zz".repeat(32),
        format!("{}\n\n", "11".repeat(32)),
        canary.clone(),
    ] {
        let (_dir, path) = key_file(&contents, 0o600);
        let error = load(&path).expect_err("malformed key must be refused");
        assert!(matches!(error, ArtifactKeyFileError::Invalid), "{error:?}");
        assert!(!format!("{error:?} {error}").contains(&canary));
    }
    for mode in [0o620, 0o602, 0o666] {
        let (_dir, path) = key_file(&"11".repeat(32), mode);
        assert!(matches!(load(&path), Err(ArtifactKeyFileError::UnsafeFile)));
    }
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        load(&dir.path().to_string_lossy()),
        Err(ArtifactKeyFileError::UnsafeFile | ArtifactKeyFileError::File(_))
    ));
    assert!(matches!(
        load(&dir.path().join("missing").to_string_lossy()),
        Err(ArtifactKeyFileError::File(_))
    ));
}

#[tokio::test]
async fn actual_kms_sdk_custody_recovers_under_new_provider_without_exposing_keys_in_stage() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    assert!(provider.is_available());
    assert!(provider.is_durable());
    let (envelope, stage) = roundtrip(&provider).await;
    assert_eq!(envelope.format_version, 1);
    assert_eq!(envelope.encryption_context, ownership(&context()));
    assert_eq!(fixture.counts(), (1, 1));
    assert_eq!(
        fixture.contexts(),
        vec![ownership(&context()), ownership(&context())]
    );
    assert!(!fixture.contains_key_material(&stage));
    let reopened = kms(&fixture).open(&context(), &envelope).await.unwrap();
    let mut reader = ArtifactDecryption::new(stage.as_slice(), context(), reopened, 200_000)
        .await
        .unwrap();
    while reader.next_chunk().await.unwrap().is_some() {}
    assert!(reader.authenticated_len().is_some());
    assert_eq!(fixture.counts(), (1, 2));
}

#[tokio::test]
async fn kms_rejects_scope_metadata_configured_root_and_wrapped_key_tampering() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    let scope = context();
    let envelope = provider.prepare(&scope, 0, 0).await.unwrap().envelope;
    for other in [
        ArtifactContext::new(TenantId(Uuid::from_u128(9)), scope.run(), scope.artifact()),
        ArtifactContext::new(scope.tenant(), CrawlRunId(Uuid::from_u128(9)), scope.artifact()),
        ArtifactContext::new(scope.tenant(), scope.run(), ArtifactId(Uuid::from_u128(9))),
    ] {
        assert!(matches!(
            provider.open(&other, &envelope).await,
            Err(ArtifactKeyError::InvalidEnvelope)
        ));
    }
    for mode in 0..5 {
        let mut altered = envelope.clone();
        match mode {
            0 => {
                altered.kms_key_id.push('x');
            }
            1 => {
                altered.format_version = 0;
            }
            2 => {
                altered.encryption_context.insert("extra".into(), "wrong".into());
            }
            3 => {
                altered.wrapped_key.clear();
            }
            _ => {
                altered.wrapped_key.resize(MAX_WRAPPED_KEY + 1, 0);
            }
        }
        assert!(matches!(
            provider.open(&scope, &altered).await,
            Err(ArtifactKeyError::InvalidEnvelope)
        ));
    }
    assert_eq!(fixture.counts(), (1, 0));
    let mut altered = envelope.clone();
    altered.wrapped_key[0] ^= 1;
    assert!(matches!(
        provider.open(&scope, &altered).await,
        Err(ArtifactKeyError::Kms(_))
    ));
    let another_root = LoopbackKms::start().await.unwrap();
    assert!(matches!(
        kms(&another_root).open(&scope, &envelope).await,
        Err(ArtifactKeyError::Kms(_))
    ));
    let wrong_key = KmsArtifactKeys {
        client: provider.client.clone(),
        key_id: "wrong-key-id".into(),
    };
    assert!(matches!(
        wrong_key.open(&scope, &envelope).await,
        Err(ArtifactKeyError::InvalidEnvelope)
    ));
}

#[tokio::test]
async fn missing_or_failed_remote_custody_never_downgrades_and_size_refusal_precedes_sdk() {
    let absent = UnavailableArtifactKeys;
    assert!(!absent.is_available());
    assert!(!absent.is_durable());
    assert!(matches!(
        absent.prepare(&context(), 0, 0).await,
        Err(ArtifactKeyError::Unavailable)
    ));
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    assert!(matches!(
        provider.prepare(&context(), 2, 1).await,
        Err(ArtifactKeyError::Crypto(ArtifactCryptoError::LimitExceeded))
    ));
    assert_eq!(fixture.counts(), (0, 0));
    let envelope = provider.prepare(&context(), 0, 0).await.unwrap().envelope;
    assert!(matches!(
        absent.open(&context(), &envelope).await,
        Err(ArtifactKeyError::Unavailable)
    ));
    drop(fixture);
    assert!(matches!(
        provider.prepare(&context(), 0, 0).await,
        Err(ArtifactKeyError::Kms(_))
    ));
    assert!(matches!(
        provider.open(&context(), &envelope).await,
        Err(ArtifactKeyError::Kms(_))
    ));
}

#[tokio::test]
async fn invalid_kms_configuration_fails_before_sdk_configuration_loading() {
    for id in [
        "".to_owned(),
        "   ".to_owned(),
        "x".repeat(2049),
        "memory-artifact-only:forbidden".to_owned(),
    ] {
        assert!(matches!(
            KmsArtifactKeys::from_environment(id).await,
            Err(ArtifactKeyError::InvalidConfiguration)
        ));
    }
}

#[test]
fn kms_error_chain_keeps_causes_but_never_formats_remote_details() {
    let error = ArtifactKeyError::Kms(ArtifactKeySource::new(std::io::Error::other(
        "SECRET-REMOTE-DETAIL",
    )));
    let mut current: Option<&dyn Error> = Some(&error);
    let mut count = 0;
    while let Some(node) = current {
        assert!(!format!("{node} {node:?}").contains("SECRET-REMOTE-DETAIL"));
        count += 1;
        current = node.source();
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn loopback_fixture_rejects_every_unapproved_ownership_context_shape() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    let approved = ownership(&context());
    let mut invalid = Vec::new();
    for key in ["domain", "tenant", "run", "artifact"] {
        let mut missing = approved.clone();
        missing.remove(key);
        invalid.push(missing);
        let mut empty = approved.clone();
        empty.insert(key.into(), String::new());
        invalid.push(empty);
    }
    let mut extra = approved.clone();
    extra.insert("session".into(), Uuid::from_u128(7).to_string());
    invalid.push(extra);
    let mut checkpoint_domain_without_checkpoint_ids = approved;
    checkpoint_domain_without_checkpoint_ids.insert("domain".into(), "crawlx/checkpoint/v1".into());
    invalid.push(checkpoint_domain_without_checkpoint_ids);
    for context in invalid {
        let mut request = provider
            .client
            .generate_data_key()
            .key_id(&provider.key_id)
            .key_spec(DataKeySpec::Aes256);
        for (key, value) in context {
            request = request.encryption_context(key, value);
        }
        assert!(request.send().await.is_err());
    }
    assert_eq!(fixture.counts(), (0, 0));
}

#[test]
fn durable_key_identity_rejects_aliases_bare_ids_and_malformed_arns() {
    for key_id in [
        "alias/crawlx",
        "12345678-1234-1234-1234-123456789abc",
        "arn:aws:kms:us-east-1:111122223333:alias/crawlx", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1:111122223333:key/alias/crawlx", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1.attacker.invalid:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1@attacker.invalid:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws:kms:cn-north-1:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws-cn:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws-us-gov:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws-iso:kms:us-iso-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1:account:key/12345678-1234-1234-1234-123456789abc", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc:extra", // wire-compat: key ARN shape
        "arn:aws:kms:us-east-1:111122223333:key/mrk-not-a-key", // wire-compat: key ARN shape
    ] {
        assert!(
            matches!(
                trusted_endpoint(key_id),
                Err(ArtifactKeyError::InvalidConfiguration)
            ),
            "{key_id}"
        );
    }
}

#[tokio::test]
async fn trusted_resolver_pins_partition_region_and_https_ignoring_endpoint_parameters() {
    let id = "12345678-1234-1234-1234-123456789abc";
    for (partition, region, suffix) in [
        ("aws", "us-east-1", "amazonaws.com"), // wire-compat: ARN partition, KMS endpoint host suffix
        ("aws-cn", "cn-north-1", "amazonaws.com.cn"), // wire-compat: ARN partition, KMS endpoint host suffix
        ("aws-us-gov", "us-gov-west-1", "amazonaws.com"), // wire-compat: ARN partition, KMS endpoint host suffix
    ] {
        let trusted =
            trusted_endpoint(&format!("arn:{partition}:kms:{region}:111122223333:key/{id}")).unwrap();
        assert_eq!(trusted.region, region);
        let params = Params::builder()
            .region("attacker-region")
            .endpoint("http://127.0.0.1:9/attacker")
            .use_fips(true)
            .use_dual_stack(true)
            .build()
            .unwrap();
        let resolved = trusted.resolve_endpoint(&params).await.unwrap();
        assert_eq!(resolved.url(), format!("https://kms.{region}.{suffix}"));
    }
    assert!(
        trusted_endpoint("arn:aws:kms:us-east-1:111122223333:key/mrk-12345678123412341234123456789abc") // wire-compat: key ARN shape
            .is_ok()
    );
}

#[tokio::test]
async fn production_constructor_pins_cloud_https_despite_environment_and_profile_endpoints() {
    const CHILD: &str = "CRAWLX_ARTIFACT_KMS_ENDPOINT_TEST_CHILD";
    const KEY: &str = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789abc"; // wire-compat: key ARN shape
    if std::env::var_os(CHILD).is_some() {
        let provider = KmsArtifactKeys::from_environment(KEY.to_owned()).await.unwrap();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Arc::clone(&observed);
        // Abort before signing/transmission, after actual SDK endpoint resolution.
        // No external KMS endpoint is contacted by this behavioral regression.
        let result = provider
            .client
            .generate_data_key()
            .key_id(KEY)
            .key_spec(DataKeySpec::Aes256)
            .customize()
            .map_request(move |request| {
                capture.lock().unwrap().push(request.uri().to_string());
                Err::<_, std::io::Error>(std::io::Error::other("stop before external dispatch"))
            })
            .send()
            .await;
        assert!(result.is_err());
        let observed = observed.lock().unwrap();
        assert!(!observed.is_empty());
        assert!(observed
            .iter()
            .all(|url| url == "https://kms.us-east-1.amazonaws.com/")); // wire-compat: KMS endpoint host
        return;
    }
    // A child process isolates SDK environment/profile injection without unsafe
    // process-global environment mutation or races with other unit tests.
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("sdk-config");
    std::fs::write(
        &profile,
        concat!(
            "[profile artifact-custody-test]\n",
            "region = us-west-2\n",
            "endpoint_url = http://127.0.0.1:9/profile-global\n",
            "services = redirected-services\n",
            "[services redirected-services]\n",
            "kms =\n",
            "  endpoint_url = http://127.0.0.1:9/profile-service\n",
        ),
    )
    .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("artifact_key_crypto::tests::production_constructor_pins_cloud_https_despite_environment_and_profile_endpoints")
        .arg("--nocapture")
        .env(CHILD, "1")
        .env("AWS_CONFIG_FILE", profile)  // wire-compat: SDK environment variable
        .env("AWS_PROFILE", "artifact-custody-test")  // wire-compat: SDK environment variable
        .env("AWS_ACCESS_KEY_ID", "fixture-access")  // wire-compat: SDK environment variable
        .env("AWS_SECRET_ACCESS_KEY", "fixture-secret")  // wire-compat: SDK environment variable
        .env("AWS_EC2_METADATA_DISABLED", "true")  // wire-compat: SDK environment variable
        .env("AWS_REGION", "us-west-2")  // wire-compat: SDK environment variable
        .env("AWS_ENDPOINT_URL", "http://127.0.0.1:9/environment-global")  // wire-compat: SDK environment variable
        .env("AWS_ENDPOINT_URL_KMS", "http://127.0.0.1:9/environment-service")  // wire-compat: SDK environment variable
        .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")  // wire-compat: SDK environment variable
        .env("AWS_USE_FIPS_ENDPOINT", "true")  // wire-compat: SDK environment variable
        .env("AWS_USE_DUALSTACK_ENDPOINT", "true")  // wire-compat: SDK environment variable
        .status()
        .unwrap();
    assert!(status.success());
}
