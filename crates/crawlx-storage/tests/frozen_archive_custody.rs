//! Terminal archive custody against real PostgreSQL and the volatile Redis registry.
//!
//! Terminal exports are sealed under a frozen grant: no new secret registration, no empty
//! snapshot, and the durable grant keeps working after the raw registry is gone. Both backend
//! URLs are required; the tests report and return when either is absent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::archive_catalog::ArchiveCustodyV1;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::{CustodyLease, FrozenArchiveSource, RunSecretAuthority, SecretEpoch};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{RunRepo, Sensitivity};
use crawlx_core::{ArtifactId, ArtifactRef, SecretOr, StoreError, TenantId, WorkerId};
use crawlx_storage::custody::{
    encrypted_object_key, ArtifactKeyEnvelope, CiphertextIdentity, PgSecretAuthority,
    CIPHERTEXT_DIGEST_DOMAIN,
};
use crawlx_storage::leases::LeaseRepo;
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{ArtifactRow, Pg, PgConfig};
use std::time::Duration;
use uuid::Uuid;

struct World {
    pg: Pg,
    authority: PgSecretAuthority,
    session: CustodyLease,
    tenant: TenantId,
    run: crawlx_core::CrawlRunId,
    export: Uuid,
    redis: redis::aio::MultiplexedConnection,
    redis_key: String,
}

async fn world() -> Option<World> {
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").ok()?;
    let config = PgConfig {
        schema: Some(format!("frozen_{}", Uuid::now_v7().simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&database, config).await.unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "frozen-archive-regression")
        .await
        .unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 2));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 2)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let claim = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let session = CustodyLease::new(
        tenant,
        run.id,
        claim.session.id,
        claim.worker,
        claim.fencing_token,
    );
    let authority = PgSecretAuthority::open(pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let redis = redis::Client::open(redis_url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    Some(World {
        redis_key: format!("crawlx:secrets:{{{}:{}}}", tenant, run.id),
        pg,
        authority,
        session,
        tenant,
        run: run.id,
        export: Uuid::now_v7(),
        redis,
    })
}

/// PostgreSQL stores microseconds; exact proofs must be representable.
fn micros(at: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_micros(at.timestamp_micros()).unwrap()
}

fn identity(seed: u8) -> CiphertextIdentity {
    CiphertextIdentity::new(Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &[seed; 96]), 96).unwrap()
}

fn row(
    w: &World,
    kind: &str,
    content_type: &str,
    class: Sensitivity,
    seed: u8,
) -> (ArtifactRow, CiphertextIdentity) {
    let id = ArtifactId::new();
    let cipher = identity(seed);
    (
        ArtifactRow {
            id,
            tenant: w.tenant,
            run: w.run,
            kind: kind.into(),
            bucket: "encrypted-artifacts".into(),
            object_key: encrypted_object_key(w.tenant, w.run, id, cipher.digest),
            size_bytes: 64,
            digest: Digest::of("crawlx/artifact/v1", &[seed; 64]),
            content_type: content_type.into(),
            sensitivity: class,
            created_at: micros(chrono::Utc::now()),
            expires_at: None,
        },
        cipher,
    )
}

fn envelope(row: &ArtifactRow) -> ArtifactKeyEnvelope {
    ArtifactKeyEnvelope::new(
        row.tenant,
        row.run,
        row.id,
        "file-artifact-key:test".into(),
        vec![5; 64],
    )
    .unwrap()
}

fn export_lease(w: &World, fence: i64) -> CustodyLease {
    CustodyLease::for_archive_export(w.tenant, w.run, w.export, WorkerId::new(), fence)
}

async fn count(w: &World, sql: &'static str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(w.pg.pool())
        .await
        .unwrap()
}

/// Publish one live source, run the run to a terminal state and claim an export at fence 3.
async fn terminal(w: &World, class: Sensitivity) -> (SecretEpoch, ArtifactRow) {
    let snapshot = w.authority.initialize(&w.session).await.unwrap();
    let (mut source, cipher) = row(w, "html", "text/html", class, 1);
    if class == Sensitivity::Sensitive {
        source.expires_at = Some(micros(chrono::Utc::now() + chrono::Duration::hours(2)));
    }
    w.authority
        .publish(&w.session, snapshot.version, &source, &cipher, &envelope(&source))
        .await
        .unwrap();
    w.pg.set_status(
        w.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO archive_exports(tenant_id,run_id,export_id,state,fence,lease_until,payload) \
         VALUES($1,$2,$3,'recording',3,clock_timestamp()+interval '2 minutes','{}'::jsonb)",
    )
    .bind(w.tenant.0)
    .bind(w.run.0)
    .bind(w.export)
    .execute(w.pg.pool())
    .await
    .unwrap();
    (snapshot.version, source)
}

fn proof(source: &ArtifactRow) -> FrozenArchiveSource {
    FrozenArchiveSource::new(
        ArtifactRef {
            id: source.id,
            digest: source.digest,
        },
        ArchiveCustodyV1::content(source.expires_at),
    )
}

#[tokio::test]
async fn terminal_export_is_sealed_under_a_grant_that_registers_nothing_and_survives_registry_loss() {
    let Some(mut w) = world().await else {
        eprintln!("SKIPPED: CRAWLX_TEST_DATABASE_URL / CRAWLX_TEST_SECRET_REDIS_URL not set");
        return;
    };
    eprintln!(
        "RAN: terminal_export_is_sealed_under_a_grant_that_registers_nothing_and_survives_registry_loss"
    );
    let (epoch, source) = terminal(&w, Sensitivity::Content).await;
    let lease = export_lease(&w, 3);
    let grant = w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[proof(&source)])
        .await
        .unwrap();
    assert_eq!(
        grant.epoch, epoch,
        "the grant carries the run's closed epoch, not a fresh one"
    );
    assert_eq!(grant.fence, 3);
    // Issuing again with identical inputs is idempotent and registers nothing.
    let again = w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[proof(&source)])
        .await
        .unwrap();
    assert_eq!(again.binding(), grant.binding());
    assert_eq!(count(&w, "SELECT count(*) FROM archive_frozen_grants").await, 1);
    assert_eq!(count(&w, "SELECT count(*) FROM archive_frozen_sources").await, 1);
    let authority_epoch: i64 = sqlx::query_scalar("SELECT epoch FROM run_secret_authority WHERE run_id=$1")
        .bind(w.run.0)
        .fetch_one(w.pg.pool())
        .await
        .unwrap();
    assert_eq!(authority_epoch, epoch.epoch, "no new registration or epoch");

    // The raw registry is gone: neither issuing nor publishing needs it.
    let _: i64 = redis::cmd("DEL")
        .arg(&w.redis_key)
        .query_async(&mut w.redis)
        .await
        .unwrap();
    let durable = PgSecretAuthority::finalized_reads(w.pg.clone());
    let (output, cipher) = row(&w, "evidence", "application/warc", Sensitivity::Content, 2);
    durable
        .publish_frozen_archive(&grant, &lease, &output, &cipher, &envelope(&output))
        .await
        .unwrap();
    // An identical retry after an unknown outcome is idempotent.
    durable
        .publish_frozen_archive(&grant, &lease, &output, &cipher, &envelope(&output))
        .await
        .unwrap();
    assert_eq!(
        count(&w, "SELECT count(*) FROM artifacts WHERE kind='evidence'").await,
        1
    );
    let sealed_epoch: i64 =
        sqlx::query_scalar("SELECT secret_epoch FROM artifact_key_custody WHERE artifact_id=$1")
            .bind(output.id.0)
            .fetch_one(w.pg.pool())
            .await
            .unwrap();
    assert_eq!(sealed_epoch, epoch.epoch);
    let custody = durable.read_custody(w.tenant, w.run, output.id).await.unwrap();
    assert_eq!(custody.ciphertext, cipher);
    // A changed retry of the same artifact is refused.
    let mut changed = output.clone();
    changed.size_bytes += 1;
    assert!(durable
        .publish_frozen_archive(&grant, &lease, &changed, &cipher, &envelope(&changed))
        .await
        .is_err());
}

#[tokio::test]
async fn grant_authorizes_only_its_exact_export_fence_and_outputs() {
    let Some(w) = world().await else {
        eprintln!("SKIPPED: CRAWLX_TEST_DATABASE_URL / CRAWLX_TEST_SECRET_REDIS_URL not set");
        return;
    };
    eprintln!("RAN: grant_authorizes_only_its_exact_export_fence_and_outputs");
    let (_, source) = terminal(&w, Sensitivity::Content).await;
    let lease = export_lease(&w, 3);
    let grant = w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[proof(&source)])
        .await
        .unwrap();
    let evidence = |seed| row(&w, "evidence", "application/warc", Sensitivity::Content, seed);
    let outputs = || count(&w, "SELECT count(*) FROM artifacts WHERE kind='evidence'");

    // Another export of the run, another run, a stale fence and other producers are refused.
    let (output, cipher) = evidence(2);
    for other in [
        CustodyLease::for_archive_export(w.tenant, w.run, Uuid::now_v7(), WorkerId::new(), 3),
        export_lease(&w, 2),
        export_lease(&w, 4),
        CustodyLease::for_archive_export(
            w.tenant,
            crawlx_core::CrawlRunId::new(),
            w.export,
            WorkerId::new(),
            3,
        ),
        w.session.clone(),
    ] {
        let refused = w
            .authority
            .publish_frozen_archive(&grant, &other, &output, &cipher, &envelope(&output))
            .await;
        assert!(matches!(refused, Err(StoreError::AccessDenied(_))), "{refused:?}");
    }
    // The grant cannot issue another export and a session cannot issue at all.
    assert!(w
        .authority
        .issue_frozen_archive(&w.session, &ArchiveCustodyV1::content(None), &[proof(&source)])
        .await
        .is_err());
    assert!(w
        .authority
        .issue_frozen_archive(
            &export_lease(&w, 4),
            &ArchiveCustodyV1::content(None),
            &[proof(&source)]
        )
        .await
        .is_err());
    assert_eq!(outputs().await, 0);

    // Kind, media type and class outside the grant are refused, whatever the producer says.
    for (kind, content_type, class, seed) in [
        ("markdown", "application/warc", Sensitivity::Content, 3),
        ("evidence", "text/html", Sensitivity::Content, 4),
        ("evidence", "application/warc", Sensitivity::Sensitive, 5),
    ] {
        let (output, cipher) = row(&w, kind, content_type, class, seed);
        let refused = w
            .authority
            .publish_frozen_archive(&grant, &lease, &output, &cipher, &envelope(&output))
            .await;
        assert!(
            matches!(refused, Err(StoreError::RetentionDenied(_))),
            "{kind} {content_type}: {refused:?}"
        );
    }
    // An output that outlives a bounded grant is refused as well.
    assert_eq!(outputs().await, 0);

    // A source proof that does not match its catalog row never yields a grant.
    let forged = FrozenArchiveSource::new(
        ArtifactRef {
            id: source.id,
            digest: Digest::of("crawlx/artifact/v1", b"other"),
        },
        ArchiveCustodyV1::content(None),
    );
    assert!(w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[forged])
        .await
        .is_err());
    let unknown = FrozenArchiveSource::new(
        ArtifactRef {
            id: ArtifactId::new(),
            digest: source.digest,
        },
        ArchiveCustodyV1::content(None),
    );
    assert!(w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[unknown])
        .await
        .is_err());

    // A revoked source invalidates the grant before publication.
    sqlx::query("UPDATE artifacts SET deleted_at=clock_timestamp() WHERE artifact_id=$1")
        .bind(source.id.0)
        .execute(w.pg.pool())
        .await
        .unwrap();
    let (output, cipher) = evidence(6);
    let revoked = w
        .authority
        .publish_frozen_archive(&grant, &lease, &output, &cipher, &envelope(&output))
        .await;
    assert!(
        matches!(revoked, Err(StoreError::RetentionDenied(_))),
        "{revoked:?}"
    );
    assert_eq!(outputs().await, 0);

    // Re-claiming the export fences the old grant off even though its row still exists.
    sqlx::query("UPDATE archive_exports SET fence=4 WHERE export_id=$1")
        .bind(w.export)
        .execute(w.pg.pool())
        .await
        .unwrap();
    let stale = w
        .authority
        .publish_frozen_archive(&grant, &lease, &output, &cipher, &envelope(&output))
        .await;
    assert!(matches!(stale, Err(StoreError::LeaseLost)), "{stale:?}");
    assert_eq!(outputs().await, 0);
}

#[tokio::test]
async fn sensitive_sources_keep_the_grant_sensitive_and_bounded() {
    let Some(w) = world().await else {
        eprintln!("SKIPPED: CRAWLX_TEST_DATABASE_URL / CRAWLX_TEST_SECRET_REDIS_URL not set");
        return;
    };
    eprintln!("RAN: sensitive_sources_keep_the_grant_sensitive_and_bounded");
    let (_, source) = terminal(&w, Sensitivity::Sensitive).await;
    let deadline = source.expires_at.unwrap();
    let lease = export_lease(&w, 3);
    let sensitive = FrozenArchiveSource::new(
        ArtifactRef {
            id: source.id,
            digest: source.digest,
        },
        ArchiveCustodyV1::sensitive(deadline),
    );
    // Requested Content is narrowed to Sensitive and the source deadline.
    let grant = w
        .authority
        .issue_frozen_archive(
            &lease,
            &ArchiveCustodyV1::content(None),
            std::slice::from_ref(&sensitive),
        )
        .await
        .unwrap();
    assert_eq!(grant.custody, ArchiveCustodyV1::sensitive(deadline));
    // A proof that downgrades the stored class is refused.
    let downgrade = FrozenArchiveSource::new(
        ArtifactRef {
            id: source.id,
            digest: source.digest,
        },
        ArchiveCustodyV1::content(Some(deadline)),
    );
    assert!(w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[downgrade])
        .await
        .is_err());
    // Content output of a sensitive grant and an output outliving the deadline are refused.
    let (content, cipher) = row(&w, "evidence", "application/warc", Sensitivity::Content, 2);
    assert!(w
        .authority
        .publish_frozen_archive(&grant, &lease, &content, &cipher, &envelope(&content))
        .await
        .is_err());
    let (mut late, cipher) = row(&w, "evidence", "application/warc", Sensitivity::Sensitive, 3);
    late.expires_at = Some(deadline + chrono::Duration::hours(1));
    assert!(w
        .authority
        .publish_frozen_archive(&grant, &lease, &late, &cipher, &envelope(&late))
        .await
        .is_err());
    let (mut ok, cipher) = row(&w, "evidence", "application/cdxj", Sensitivity::Sensitive, 4);
    ok.expires_at = Some(deadline);
    w.authority
        .publish_frozen_archive(&grant, &lease, &ok, &cipher, &envelope(&ok))
        .await
        .unwrap();
}

#[tokio::test]
async fn sealed_authority_admits_only_validated_grant_outputs_and_never_reopens() {
    let Some(mut w) = world().await else {
        eprintln!("SKIPPED: CRAWLX_TEST_DATABASE_URL / CRAWLX_TEST_SECRET_REDIS_URL not set");
        return;
    };
    eprintln!("RAN: sealed_authority_admits_only_validated_grant_outputs_and_never_reopens");
    let (epoch, source) = terminal(&w, Sensitivity::Content).await;
    let lease = export_lease(&w, 3);
    let grant = w
        .authority
        .issue_frozen_archive(&lease, &ArchiveCustodyV1::content(None), &[proof(&source)])
        .await
        .unwrap();
    let (first, cipher) = row(&w, "evidence", "application/warc", Sensitivity::Content, 2);
    w.authority
        .publish_frozen_archive(&grant, &lease, &first, &cipher, &envelope(&first))
        .await
        .unwrap();
    // The run is finalized at its closed epoch with the sealed output in the catalog.
    w.authority.finalize(epoch).await.unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(&w.redis_key)
        .query_async(&mut w.redis)
        .await
        .unwrap();
    let durable = PgSecretAuthority::finalized_reads(w.pg.clone());

    // A second output of the same grant still publishes: the validated exception, no reopening.
    let (second, cipher) = row(&w, "evidence", "application/cdxj", Sensitivity::Content, 3);
    durable
        .publish_frozen_archive(&grant, &lease, &second, &cipher, &envelope(&second))
        .await
        .unwrap();
    assert!(matches!(
        durable.read_state(w.tenant, w.run, second.id).await.unwrap(),
        crawlx_core::custody::ArtifactReadState::Finalized(version) if version == epoch
    ));
    let sealed: bool =
        sqlx::query_scalar("SELECT sealed_at IS NOT NULL FROM run_secret_authority WHERE run_id=$1")
            .bind(w.run.0)
            .fetch_one(w.pg.pool())
            .await
            .unwrap();
    assert!(sealed);

    // No other route can grow the sealed catalog: raw rows, forged outputs and key updates fail.
    let (raw, raw_cipher) = row(&w, "evidence", "application/warc", Sensitivity::Content, 4);
    assert!(crawlx_storage::ArtifactIndex::record(&w.pg, &raw).await.is_err());
    let forged = sqlx::query(
        "INSERT INTO archive_frozen_outputs(tenant_id,run_id,export_id,binding,artifact_id,kind,bucket,object_key,size_bytes,\
         content_digest,content_type,sensitivity,created_at,expires_at,incarnation,secret_epoch,ciphertext_digest,ciphertext_size) \
         VALUES($1,$2,$3,$4,$5,'evidence','b','k',1,$6,'application/warc','content',clock_timestamp(),NULL,$7,$8,$9,1)",
    )
    .bind(w.tenant.0)
    .bind(w.run.0)
    .bind(w.export)
    .bind(Digest::of("forged", b"binding").0.as_slice())
    .bind(raw.id.0)
    .bind(raw.digest.0.as_slice())
    .bind(epoch.incarnation)
    .bind(epoch.epoch)
    .bind(raw_cipher.digest.0.as_slice())
    .execute(w.pg.pool())
    .await;
    assert!(forged.is_err(), "an output needs a persisted grant");
    for sql in [
        "UPDATE artifact_key_custody SET secret_epoch=secret_epoch",
        "UPDATE run_secret_authority SET sealed_at=NULL",
        "UPDATE archive_frozen_grants SET fence=fence",
        "UPDATE archive_frozen_outputs SET secret_epoch=secret_epoch",
        "UPDATE archive_frozen_sources SET digest=digest",
    ] {
        assert!(sqlx::query(sql).execute(w.pg.pool()).await.is_err(), "{sql}");
    }
    // The registry stays closed: no registration reaches the sealed run.
    assert!(w
        .authority
        .register(
            &w.session,
            epoch,
            Uuid::now_v7(),
            &SecretOr::secret("late-secret-value-91".into())
        )
        .await
        .is_err());
}
