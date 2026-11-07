#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use std::{future::Future as _, task::Poll};
use uuid::Uuid;

fn context() -> ArtifactContext {
    ArtifactContext::new(
        TenantId(Uuid::from_u128(1)),
        CrawlRunId(Uuid::from_u128(2)),
        ArtifactId(Uuid::from_u128(3)),
    )
}

fn key() -> ArtifactDataKey {
    ArtifactDataKey::from_bytes(Zeroizing::new([0x47; 32]))
}

// Fixed keys/nonces exist only inside these private deterministic fixtures.
fn plan(length: u64) -> ArtifactEncryption {
    let mut header = make_header(length);
    header[17..].copy_from_slice(&[1, 2, 3, 4]);
    ArtifactEncryption {
        context: context(),
        key: key(),
        header,
        plaintext_len: length,
        ciphertext_len: checked_lengths(length, length).unwrap(),
    }
}

async fn encrypted(plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    let sealed = plan(u64::try_from(plaintext.len()).unwrap())
        .seal(plaintext, &mut ciphertext)
        .await
        .unwrap();
    assert_eq!(sealed.ciphertext_len, u64::try_from(ciphertext.len()).unwrap());
    assert_eq!(sealed.plaintext_len, u64::try_from(plaintext.len()).unwrap());
    ciphertext
}

async fn decrypt(
    ciphertext: &[u8],
    scope: ArtifactContext,
    data_key: ArtifactDataKey,
) -> Result<Vec<u8>, ArtifactCryptoError> {
    let mut reader = ArtifactDecryption::new(ciphertext, scope, data_key, 4 * CHUNK_U64).await?;
    assert_eq!(reader.authenticated_len(), None);
    let mut plaintext = Vec::new();
    while let Some(chunk) = reader.next_chunk().await? {
        assert!(chunk.len() <= ARTIFACT_CHUNK_BYTES);
        plaintext.extend_from_slice(&chunk);
    }
    assert_eq!(
        reader.authenticated_len(),
        Some(u64::try_from(plaintext.len()).unwrap())
    );
    assert!(reader.next_chunk().await?.is_none());
    Ok(plaintext)
}

#[tokio::test]
async fn actual_file_stage_contains_only_ciphertext_and_roundtrips_bounded_chunks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("encrypted-stage");
    let plaintext = b"secret-artifact-marker".repeat(9000);
    let length = u64::try_from(plaintext.len()).unwrap();
    let mut stage = tokio::fs::File::create(&path).await.unwrap();
    let sealed = plan(length).seal(plaintext.as_slice(), &mut stage).await.unwrap();
    stage.sync_all().await.unwrap();
    drop(stage);
    let bytes = tokio::fs::read(&path).await.unwrap();
    assert!(!bytes
        .windows(22)
        .any(|window| window == b"secret-artifact-marker"));
    assert!(!bytes
        .windows(32)
        .any(|window| window == sealed.data_key.as_bytes()));
    assert_eq!(u64::try_from(bytes.len()).unwrap(), sealed.ciphertext_len);
    let input = tokio::fs::File::open(path).await.unwrap();
    let mut reader = ArtifactDecryption::new(input, context(), sealed.data_key, length)
        .await
        .unwrap();
    let mut recovered = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = reader.next_chunk().await.unwrap() {
        assert!(!chunk.is_empty());
        assert!(chunk.len() <= ARTIFACT_CHUNK_BYTES);
        recovered.extend_from_slice(&chunk);
        chunks += 1;
    }
    assert!(chunks > 1);
    assert_eq!(recovered, plaintext);
    assert_eq!(reader.authenticated_len(), Some(length));
}

#[tokio::test]
async fn empty_partial_exact_and_multichunk_inputs_use_authenticated_terminal() {
    for length in [
        0,
        1,
        ARTIFACT_CHUNK_BYTES - 1,
        ARTIFACT_CHUNK_BYTES,
        ARTIFACT_CHUNK_BYTES + 1,
        2 * ARTIFACT_CHUNK_BYTES,
    ] {
        let plaintext = vec![0x35; length];
        let ciphertext = encrypted(&plaintext).await;
        assert_eq!(decrypt(&ciphertext, context(), key()).await.unwrap(), plaintext);
    }
}

#[tokio::test]
async fn actual_duplex_reader_and_writer_preserve_framing_under_fragmentation_and_backpressure() {
    let plaintext = vec![0x29; ARTIFACT_CHUNK_BYTES + 17];
    let ciphertext = encrypted(&plaintext).await;
    let (mut sender, receiver) = tokio::io::duplex(13);
    let producer = async {
        for chunk in ciphertext.chunks(7) {
            sender.write_all(chunk).await.unwrap();
        }
        sender.shutdown().await.unwrap();
    };
    let consumer = async {
        let mut reader = ArtifactDecryption::new(receiver, context(), key(), 2 * CHUNK_U64)
            .await
            .unwrap();
        let mut recovered = Vec::new();
        while let Some(chunk) = reader.next_chunk().await.unwrap() {
            recovered.extend_from_slice(&chunk);
        }
        assert_eq!(recovered, plaintext);
    };
    tokio::join!(producer, consumer);

    let (writer, mut reader) = tokio::io::duplex(11);
    let producer = async {
        plan(u64::try_from(plaintext.len()).unwrap())
            .seal(plaintext.as_slice(), writer)
            .await
            .unwrap()
    };
    let consumer = async {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        bytes
    };
    let (sealed, streamed) = tokio::join!(producer, consumer);
    assert_eq!(streamed, ciphertext);
    assert_eq!(sealed.ciphertext_len, u64::try_from(streamed.len()).unwrap());
}

#[tokio::test]
async fn each_ownership_component_and_wrong_key_fail_before_plaintext() {
    let ciphertext = encrypted(b"classified object").await;
    let scope = context();
    for other in [
        ArtifactContext::new(TenantId(Uuid::from_u128(9)), scope.run, scope.artifact),
        ArtifactContext::new(scope.tenant, CrawlRunId(Uuid::from_u128(9)), scope.artifact),
        ArtifactContext::new(scope.tenant, scope.run, ArtifactId(Uuid::from_u128(9))),
    ] {
        assert!(matches!(
            decrypt(&ciphertext, other, key()).await,
            Err(ArtifactCryptoError::Authentication)
        ));
    }
    let wrong = ArtifactDataKey::from_bytes(Zeroizing::new([0x48; 32]));
    assert!(matches!(
        decrypt(&ciphertext, scope, wrong).await,
        Err(ArtifactCryptoError::Authentication)
    ));
}

#[tokio::test]
async fn every_header_ciphertext_and_tag_byte_is_authenticated_or_rejected() {
    let ciphertext = encrypted(b"small deterministic object").await;
    for index in 0..ciphertext.len() {
        let mut corrupt = ciphertext.clone();
        corrupt[index] ^= 1;
        assert!(
            decrypt(&corrupt, context(), key()).await.is_err(),
            "tamper at {index}"
        );
    }
    let empty = encrypted(b"").await;
    for index in 0..empty.len() {
        let mut corrupt = empty.clone();
        corrupt[index] ^= 1;
        assert!(
            decrypt(&corrupt, context(), key()).await.is_err(),
            "empty tamper at {index}"
        );
    }
}

#[tokio::test]
async fn every_truncated_prefix_and_appended_byte_is_rejected() {
    let ciphertext = encrypted(b"small deterministic object").await;
    for end in 0..ciphertext.len() {
        assert!(
            decrypt(&ciphertext[..end], context(), key()).await.is_err(),
            "prefix {end}"
        );
    }
    let mut appended = ciphertext;
    appended.push(0);
    assert!(matches!(
        decrypt(&appended, context(), key()).await,
        Err(ArtifactCryptoError::InvalidEnvelope)
    ));
}

#[tokio::test]
async fn final_plaintext_never_escapes_before_terminal_tag_and_eof() {
    let plaintext = vec![0x63; ARTIFACT_CHUNK_BYTES + 17];
    let ciphertext = encrypted(&plaintext).await;
    for mode in 0..3 {
        let mut corrupt = ciphertext.clone();
        match mode {
            0 => {
                corrupt.pop();
            }
            1 => {
                *corrupt.last_mut().unwrap() ^= 1;
            }
            _ => {
                corrupt.push(1);
            }
        }
        let mut reader = ArtifactDecryption::new(corrupt.as_slice(), context(), key(), 2 * CHUNK_U64)
            .await
            .unwrap();
        assert_eq!(
            reader.next_chunk().await.unwrap().unwrap().len(),
            ARTIFACT_CHUNK_BYTES
        );
        assert_eq!(reader.authenticated_len(), None);
        assert!(reader.next_chunk().await.is_err());
        assert_eq!(reader.authenticated_len(), None);
        assert!(matches!(
            reader.next_chunk().await,
            Err(ArtifactCryptoError::Aborted)
        ));
    }
    for length in [1, ARTIFACT_CHUNK_BYTES] {
        let mut ciphertext = encrypted(&vec![0x63; length]).await;
        ciphertext.pop();
        let mut reader = ArtifactDecryption::new(ciphertext.as_slice(), context(), key(), CHUNK_U64)
            .await
            .unwrap();
        assert!(reader.next_chunk().await.is_err());
        assert_eq!(reader.authenticated_len(), None);
    }
}

#[tokio::test]
async fn reordered_duplicated_and_removed_chunks_fail_authentication() {
    let mut plaintext = vec![0x11; ARTIFACT_CHUNK_BYTES];
    plaintext.extend(vec![0x22; ARTIFACT_CHUNK_BYTES]);
    plaintext.extend_from_slice(b"last chunk");
    let ciphertext = encrypted(&plaintext).await;
    let frame = ARTIFACT_CHUNK_BYTES + TAG_BYTES;
    let first = HEADER_BYTES;
    let second = first + frame;
    let third = second + frame;
    let mut reordered = ciphertext.clone();
    reordered[first..second].copy_from_slice(&ciphertext[second..third]);
    reordered[second..third].copy_from_slice(&ciphertext[first..second]);
    assert!(matches!(
        decrypt(&reordered, context(), key()).await,
        Err(ArtifactCryptoError::Authentication)
    ));
    let mut duplicated = ciphertext.clone();
    duplicated[second..third].copy_from_slice(&ciphertext[first..second]);
    assert!(matches!(
        decrypt(&duplicated, context(), key()).await,
        Err(ArtifactCryptoError::Authentication)
    ));
    let mut removed = ciphertext;
    removed.drain(first..second);
    assert!(decrypt(&removed, context(), key()).await.is_err());
}

#[tokio::test]
async fn limits_and_declared_final_length_never_expand_consumer_budget() {
    assert!(matches!(
        ArtifactEncryption::new(context(), 2, 1),
        Err(ArtifactCryptoError::LimitExceeded)
    ));
    assert!(matches!(
        ArtifactEncryption::new(context(), u64::MAX, u64::MAX),
        Err(ArtifactCryptoError::LimitExceeded)
    ));
    let oversized = make_header(CHUNK_U64 + 1);
    // No body or EOF is available: rejection must depend only on the bounded header.
    let (mut writer, input) = tokio::io::duplex(HEADER_BYTES);
    writer.write_all(&oversized).await.unwrap();
    assert!(matches!(
        ArtifactDecryption::new(input, context(), key(), CHUNK_U64).await,
        Err(ArtifactCryptoError::LimitExceeded)
    ));
    for (declared, actual) in [
        (4, b"abc".as_slice()),
        (2, b"abc".as_slice()),
        (0, b"a".as_slice()),
    ] {
        let mut destination = Vec::new();
        assert!(matches!(
            plan(declared).seal(actual, &mut destination).await,
            Err(ArtifactCryptoError::LengthMismatch)
        ));
        assert!(decrypt(&destination, context(), key()).await.is_err());
    }
}

#[tokio::test]
async fn cancelling_partial_frame_poison_reader_instead_of_resuming_lost_io_state() {
    let (mut writer, input) = tokio::io::duplex(HEADER_BYTES + 1);
    writer.write_all(&make_header(10)).await.unwrap();
    writer.write_all(&[0]).await.unwrap();
    let mut reader = ArtifactDecryption::new(input, context(), key(), 10)
        .await
        .unwrap();
    {
        let pending = reader.next_chunk();
        tokio::pin!(pending);
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(matches!(
        reader.next_chunk().await,
        Err(ArtifactCryptoError::Aborted)
    ));
    assert_eq!(reader.authenticated_len(), None);
}

#[test]
fn key_formatting_never_discloses_key_bytes() {
    assert_eq!(format!("{:?}", key()), "ArtifactDataKey([REDACTED])");
}
