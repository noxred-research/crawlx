//! Native and real SDK loopback protocol regressions; no external cloud or network dependency.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::testkit::fake_kms::LoopbackKms;
use aws_sdk_kms::config::{retry::RetryConfig, Credentials, Region};
use uuid::Uuid;

const SECRET: &[u8] = b"checkpoint-cookie=AUTHENTICATED-SECRET; localStorage=session-private-value";

fn context() -> CheckpointContext {
    CheckpointContext::new(
        TenantId(Uuid::from_u128(1)),
        CrawlRunId(Uuid::from_u128(2)),
        SessionId(Uuid::from_u128(3)),
        CheckpointId(Uuid::from_u128(4)),
    )
}

fn other_contexts(context: CheckpointContext) -> [CheckpointContext; 4] {
    [
        CheckpointContext {
            tenant: TenantId(Uuid::from_u128(11)),
            ..context
        },
        CheckpointContext {
            run: CrawlRunId(Uuid::from_u128(12)),
            ..context
        },
        CheckpointContext {
            session: SessionId(Uuid::from_u128(13)),
            ..context
        },
        CheckpointContext {
            checkpoint: CheckpointId(Uuid::from_u128(14)),
            ..context
        },
    ]
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture constructs only the reviewed checkpoint-custody SDK adapter"
)]
fn kms(fixture: &LoopbackKms) -> KmsCheckpointKeys {
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
    KmsCheckpointKeys {
        client: Client::from_conf(config),
        key_id: fixture.key_id().to_owned(),
    }
}

fn assert_redacted(error: &CheckpointCryptoError) {
    let mut current: Option<&dyn Error> = Some(error);
    let mut count = 0;
    while let Some(cause) = current {
        let text = format!("{cause} {cause:?}");
        for forbidden in [
            "fixture-secret-response-body",
            "sensitive-endpoint",
            "fixture-secret",
            "127.0.0.1",
            "InvalidCiphertextException",
        ] {
            assert!(!text.contains(forbidden), "source leaked {forbidden}: {text}");
        }
        count += 1;
        assert!(count < 20);
        current = cause.source();
    }
    assert!(count >= 2, "provider source must remain attached");
}

#[tokio::test]
async fn memory_roundtrip_binds_every_id_and_never_serializes_plaintext_or_key() {
    let provider = MemoryCheckpointKeys::new().unwrap();
    let scope = context();
    let first = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let second = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    assert_ne!(first, second, "every seal needs fresh random nonce");
    let _: &dyn crawlx_core::secret::SecretFree = &first;
    let first = first.as_ref().to_vec();
    assert_eq!(&*provider.open(&scope, first.clone()).await.unwrap(), SECRET);
    assert!(!contains(&first, SECRET));
    assert!(!contains(&first, provider.key.as_ref().as_ref()));
    assert_eq!(parse_envelope(&first, MEMORY).unwrap().wrapped, b"");
    for other in other_contexts(scope) {
        assert!(matches!(
            provider.open(&other, first.clone()).await,
            Err(CheckpointCryptoError::Authentication)
        ));
    }
    let wrong = MemoryCheckpointKeys::new().unwrap();
    assert!(matches!(
        wrong.open(&scope, first).await,
        Err(CheckpointCryptoError::Authentication)
    ));
    let empty = provider.seal(&scope, Zeroizing::new(Vec::new())).await.unwrap();
    assert!(provider
        .open(&scope, empty.as_ref().to_vec())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn native_rejects_plaintext_versions_provider_lengths_and_all_tampering() {
    let provider = MemoryCheckpointKeys::new().unwrap();
    let scope = context();
    let envelope = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let envelope = envelope.as_ref().to_vec();
    for index in [0, 4, 5, 6, 10, HEADER_BYTES, envelope.len() - 1] {
        let mut tampered = envelope.clone();
        tampered[index] ^= 0x80;
        assert!(
            provider.open(&scope, tampered).await.is_err(),
            "accepted changed byte {index}"
        );
    }
    for length in 0..HEADER_BYTES + TAG_BYTES {
        assert!(provider.open(&scope, envelope[..length].to_vec()).await.is_err());
    }
    assert!(provider.open(&scope, SECRET.to_vec()).await.is_err());
    assert!(provider
        .open(&scope, br#"{"cookie":"plaintext"}"#.to_vec())
        .await
        .is_err());
    let oversized = vec![0; MAX_PLAINTEXT + 1];
    assert!(matches!(
        provider.seal(&scope, Zeroizing::new(oversized)).await,
        Err(CheckpointCryptoError::LimitExceeded)
    ));
    let oversized_envelope = vec![0; MAX_ENVELOPE + 1];
    assert!(matches!(
        provider.open(&scope, oversized_envelope).await,
        Err(CheckpointCryptoError::LimitExceeded)
    ));
}

#[tokio::test]
async fn maximum_native_payload_roundtrips() {
    let provider = MemoryCheckpointKeys::new().unwrap();
    let payload = Zeroizing::new(vec![0x93; MAX_PLAINTEXT]);
    let envelope = provider.seal(&context(), payload).await.unwrap();
    let envelope = envelope.as_ref().to_vec();
    assert_eq!(envelope.len(), HEADER_BYTES + MAX_PLAINTEXT + TAG_BYTES);
    let plaintext = provider.open(&context(), envelope).await.unwrap();
    assert_eq!(plaintext.as_slice(), vec![0x93; MAX_PLAINTEXT]);
}

#[tokio::test]
async fn unavailable_provider_is_explicit_and_fail_closed() {
    let provider: Arc<dyn CheckpointKeys> = Arc::new(UnavailableCheckpointKeys);
    assert!(!provider.is_available());
    assert!(matches!(
        provider.seal(&context(), Zeroizing::new(SECRET.to_vec())).await,
        Err(CheckpointCryptoError::Unavailable)
    ));
    assert!(matches!(
        provider.open(&context(), SECRET.to_vec()).await,
        Err(CheckpointCryptoError::Unavailable)
    ));
    assert!(MemoryCheckpointKeys::new().unwrap().is_available());
    for key in [String::new(), "  ".to_owned(), "k".repeat(2049)] {
        assert!(matches!(
            KmsCheckpointKeys::from_environment(key).await,
            Err(CheckpointCryptoError::InvalidConfiguration)
        ));
    }
}

#[tokio::test]
async fn kms_sdk_generate_and_decrypt_use_wrapped_keys_and_exact_ownership_context() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    let scope = context();
    let envelope = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let envelope = envelope.as_ref().to_vec();
    assert_eq!(fixture.counts(), (1, 0));
    let parsed = parse_envelope(&envelope, KMS).unwrap();
    assert_eq!(
        parsed.wrapped.len(),
        60,
        "fixture returns authenticated wrapped data key, not plaintext"
    );
    assert!(!contains(&envelope, SECRET));
    assert!(!fixture.contains_key_material(&envelope));
    assert_eq!(&*provider.open(&scope, envelope.clone()).await.unwrap(), SECRET);
    assert_eq!(fixture.counts(), (1, 1));
    assert_eq!(fixture.contexts(), vec![scope.kms_context(), scope.kms_context()]);
    // A new SDK client with the same actual fixture custody can resume checkpoints.
    assert_eq!(
        &*kms(&fixture).open(&scope, envelope.clone()).await.unwrap(),
        SECRET
    );
    let second = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let second = second.as_ref().to_vec();
    assert_ne!(envelope, second);
    assert_ne!(
        parse_envelope(&envelope, KMS).unwrap().wrapped,
        parse_envelope(&second, KMS).unwrap().wrapped
    );
}

#[tokio::test]
async fn kms_rejects_cross_owner_wrapped_nonce_ciphertext_root_and_configured_key_tampering() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    let scope = context();
    let envelope = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let envelope = envelope.as_ref().to_vec();
    for other in other_contexts(scope) {
        let error = provider.open(&other, envelope.clone()).await.unwrap_err();
        assert!(matches!(error, CheckpointCryptoError::Kms { .. }));
        assert_redacted(&error);
    }
    for index in [10, HEADER_BYTES, HEADER_BYTES + 60, envelope.len() - 1] {
        let mut tampered = envelope.clone();
        tampered[index] ^= 1;
        assert!(
            provider.open(&scope, tampered).await.is_err(),
            "accepted changed byte {index}"
        );
    }
    let different_custody = LoopbackKms::start().await.unwrap();
    assert!(kms(&different_custody)
        .open(&scope, envelope.clone())
        .await
        .is_err());
    let wrong_key = KmsCheckpointKeys {
        client: provider.client.clone(),
        key_id: "wrong-key-id".to_owned(),
    };
    assert_redacted(&wrong_key.open(&scope, envelope.clone()).await.unwrap_err());
    assert!(MemoryCheckpointKeys::new()
        .unwrap()
        .open(&scope, envelope)
        .await
        .is_err());
    assert_eq!(
        fixture.counts(),
        (1, 3),
        "only nonce/payload/tag tampering reaches a successful KMS unwrap"
    );
}

#[tokio::test]
async fn kms_rejects_malformed_and_oversized_envelopes_before_sdk_traffic() {
    let fixture = LoopbackKms::start().await.unwrap();
    let provider = kms(&fixture);
    let scope = context();
    let valid = provider
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let valid = valid.as_ref().to_vec();
    for index in [0, 4, 5] {
        let mut malformed = valid.clone();
        malformed[index] ^= 0x80;
        assert!(provider.open(&scope, malformed).await.is_err());
    }
    for length in 0..HEADER_BYTES + TAG_BYTES {
        assert!(provider.open(&scope, valid[..length].to_vec()).await.is_err());
    }
    for wrapped_len in [0, 65537, u32::MAX] {
        let mut malformed = valid.clone();
        malformed[6..10].copy_from_slice(&wrapped_len.to_be_bytes());
        assert!(provider.open(&scope, malformed).await.is_err());
    }
    // A maximum-length declaration with insufficient bytes must not allocate or call KMS.
    let mut truncated = valid.clone();
    truncated[6..10].copy_from_slice(&65536_u32.to_be_bytes());
    assert!(provider.open(&scope, truncated).await.is_err());
    let native = MemoryCheckpointKeys::new()
        .unwrap()
        .seal(&scope, Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    assert!(provider.open(&scope, native.as_ref().to_vec()).await.is_err());
    assert!(provider.open(&scope, SECRET.to_vec()).await.is_err());
    let oversized = vec![0; MAX_PLAINTEXT + 1];
    assert!(matches!(
        provider.seal(&scope, Zeroizing::new(oversized)).await,
        Err(CheckpointCryptoError::LimitExceeded)
    ));
    let oversized_envelope = vec![0; MAX_ENVELOPE + 1];
    assert!(matches!(
        provider.open(&scope, oversized_envelope).await,
        Err(CheckpointCryptoError::LimitExceeded)
    ));
    assert_eq!(fixture.counts(), (1, 0));
}

#[test]
fn redacted_source_chain_preserves_shape_without_disclosing_original_errors() {
    #[derive(Debug, thiserror::Error)]
    #[error("fixture-secret-response-body https://sensitive-endpoint.invalid")]
    struct Sensitive {
        #[source]
        source: std::io::Error,
    }
    let error = CheckpointCryptoError::Kms {
        source: CheckpointCryptoSource::new(Sensitive {
            source: std::io::Error::other("fixture-secret nested cause"),
        }),
    };
    assert_redacted(&error);
    assert!(error.source().unwrap().source().is_some());
    let entropy = CheckpointCryptoError::Entropy {
        source: CheckpointCryptoSource::new(ring::error::Unspecified),
    };
    assert!(entropy.source().is_some());
}

#[tokio::test]
async fn memory_store_custody_survives_reopened_wrappers_but_not_a_distinct_store() {
    let store = Arc::new(crate::MemoryStore::new());
    let producer = store.checkpoint_keys().unwrap();
    let envelope = producer
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let envelope = envelope.as_ref().to_vec();
    let reopened_store = Arc::clone(&store);
    let reopened = reopened_store.checkpoint_keys().unwrap();
    assert!(Arc::ptr_eq(&producer, &reopened));
    drop(producer);
    assert_eq!(
        &*reopened.open(&context(), envelope.clone()).await.unwrap(),
        SECRET
    );
    let distinct = crate::MemoryStore::new().checkpoint_keys().unwrap();
    assert!(matches!(
        distinct.open(&context(), envelope).await,
        Err(CheckpointCryptoError::Authentication)
    ));
}

const KEK_OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEK_NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const KEK_OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// A file provider over `body`, written owner-only into a fresh directory.
fn kek_provider(body: &str) -> (tempfile::TempDir, FileCheckpointKeys) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kek");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let provider = FileCheckpointKeys::from_file(&path).unwrap();
    (dir, provider)
}

/// The key id a file-wrapped envelope names.
fn wrapped_key_id(envelope: &[u8]) -> String {
    let len = usize::from(envelope[HEADER_BYTES]);
    String::from_utf8(envelope[HEADER_BYTES + 1..HEADER_BYTES + 1 + len].to_vec()).unwrap()
}

#[tokio::test]
async fn kek_file_round_trip_binds_ownership_and_hides_plaintext() {
    let (_dir, provider) = kek_provider(&format!("k1:{KEK_OLD}\n"));
    assert!(provider.is_available());
    assert_eq!(format!("{provider:?}"), "FileCheckpointKeys([REDACTED])");
    let sealed = provider
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    let bytes = sealed.as_ref().to_vec();
    assert_eq!(&bytes[..4], MAGIC);
    assert_eq!(&bytes[4..6], &[VERSION, FILE]);
    assert!(!contains(&bytes, SECRET));
    assert!(!contains(&bytes, KEK_OLD.as_bytes()));
    assert_eq!(wrapped_key_id(&bytes), "k1");
    assert_eq!(&*provider.open(&context(), bytes.clone()).await.unwrap(), SECRET);
    for other in other_contexts(context()) {
        assert!(matches!(
            provider.open(&other, bytes.clone()).await,
            Err(CheckpointCryptoError::Authentication)
        ));
    }
    // each seal draws a fresh data key and nonce
    let again = provider
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap();
    assert_ne!(again.as_ref(), bytes.as_slice());
}

#[tokio::test]
async fn kek_rotation_wraps_with_the_primary_and_old_ids_still_unwrap() {
    let (_old_dir, old_only) = kek_provider(&format!("k1:{KEK_OLD}\n"));
    let before = old_only
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap()
        .as_ref()
        .to_vec();
    assert_eq!(wrapped_key_id(&before), "k1");

    // rotate: the new key goes on top, the old one stays listed
    let (_both_dir, both) = kek_provider(&format!("k2:{KEK_NEW}\nk1:{KEK_OLD}\n"));
    assert_eq!(both.key_ids().collect::<Vec<_>>(), ["k2", "k1"]);
    assert_eq!(&*both.open(&context(), before.clone()).await.unwrap(), SECRET);
    let after = both
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap()
        .as_ref()
        .to_vec();
    assert_eq!(wrapped_key_id(&after), "k2");
    assert_eq!(&*both.open(&context(), after.clone()).await.unwrap(), SECRET);

    // retire the old key: what it wrapped fails closed, what the new key wrapped still opens
    let (_new_dir, new_only) = kek_provider(&format!("k2:{KEK_NEW}\n"));
    assert!(matches!(
        new_only.open(&context(), before).await,
        Err(CheckpointCryptoError::UnknownKey)
    ));
    assert_eq!(&*new_only.open(&context(), after).await.unwrap(), SECRET);
}

#[tokio::test]
async fn kek_wrong_key_tamper_and_foreign_envelopes_fail_closed() {
    let (_dir, provider) = kek_provider(&format!("k1:{KEK_OLD}\n"));
    let sealed = provider
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap()
        .as_ref()
        .to_vec();

    // same id, different key material
    let (_wrong_dir, wrong) = kek_provider(&format!("k1:{KEK_OTHER}\n"));
    assert!(matches!(
        wrong.open(&context(), sealed.clone()).await,
        Err(CheckpointCryptoError::Authentication)
    ));

    // every byte of the envelope is authenticated or validated
    for index in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        let result = provider.open(&context(), tampered).await;
        assert!(result.is_err(), "flipping byte {index} was accepted");
    }
    assert!(provider
        .open(&context(), sealed[..sealed.len() - 1].to_vec())
        .await
        .is_err());
    assert!(provider.open(&context(), Vec::new()).await.is_err());

    // other providers' envelopes are not accepted by this one, and vice versa
    let memory = MemoryCheckpointKeys::new().unwrap();
    let foreign = memory
        .seal(&context(), Zeroizing::new(SECRET.to_vec()))
        .await
        .unwrap()
        .as_ref()
        .to_vec();
    assert!(matches!(
        provider.open(&context(), foreign).await,
        Err(CheckpointCryptoError::InvalidEnvelope)
    ));
    assert!(matches!(
        memory.open(&context(), sealed).await,
        Err(CheckpointCryptoError::InvalidEnvelope)
    ));
}

#[tokio::test]
async fn kek_file_must_be_owner_only_and_valid_to_load() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kek");
    std::fs::write(&path, format!("k1:{KEK_OLD}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        FileCheckpointKeys::from_file(&path),
        Err(KekFileError::UnsafeFile)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(FileCheckpointKeys::from_file(&path).is_ok());
    assert!(matches!(
        FileCheckpointKeys::from_file(&dir.path().join("absent")),
        Err(KekFileError::File(_))
    ));
}
