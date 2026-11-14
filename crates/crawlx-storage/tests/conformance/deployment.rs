//! The deployment id: one random id per database, created on first use, read back identically
//! by every handle and every concurrent first user, on every engine.

use crate::rig::Rig;
use crawlx_storage::deployment::{deployment_id_of, DeploymentIdentity};
use futures::future::join_all;

/// Run `$body` with `$store` bound to the `Store` of the rig's database engine.
macro_rules! on_db {
    ($rig:expr, |$store:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Sqlite => {
                let $store = $rig.database().sqlite_store().expect("a sqlite rig has a store");
                $body
            }
            Engine::MariaDb => {
                let $store = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store");
                $body
            }
            Engine::Postgres => {
                let $store = $rig.database().postgres().expect("a postgres rig has a store");
                $body
            }
            _ => panic!("this case needs a database engine"),
        }
    }};
}

async fn deployment_id_is_created_once_and_shared_by_every_user(rig: &Rig) {
    rig.migrate().await;
    on_db!(rig, |store| {
        // concurrent first users all end up with the one id that won the insert
        let first_users = join_all((0..8).map(|_| deployment_id_of(store))).await;
        let ids: Vec<String> = first_users.into_iter().map(|id| id.unwrap()).collect();
        assert!(ids.iter().all(|id| id == &ids[0]), "{ids:?}");
        uuid::Uuid::parse_str(&ids[0]).expect("the id is a uuid");
        // later reads, through the trait and through a clone of the store, see the same value
        assert_eq!(store.deployment_id().await.unwrap(), ids[0]);
        assert_eq!(store.clone().deployment_id().await.unwrap(), ids[0]);
    });
}

/// `sweep-retention` with an orphan grace of zero: a worker of the same deployment (the same
/// database) has claimed the prefix and the sweep still collects orphans; another deployment's
/// sweep over that prefix is refused and deletes nothing.
async fn orphan_sweep_is_refused_for_another_deployment_but_runs_for_the_owner(rig: &Rig) {
    use crawlx_core::SystemClock;
    use crawlx_storage::artifacts::{ArtifactBlobs, ObjectArtifactStore};
    use crawlx_storage::retention::RetentionSweeper;
    use crawlx_storage::testkit::fake_s3::FakeS3;
    use crawlx_storage::{S3Blobs, S3Config};
    use std::sync::Arc;

    rig.migrate().await;
    let fake = FakeS3::start().await.unwrap();
    let blobs = |identity: Arc<dyn DeploymentIdentity>| {
        let mut cfg = S3Config::new("artifacts", "us-east-1")
            .with_endpoint(fake.endpoint())
            .with_prefix("shared")
            .unwrap();
        cfg.max_attempts = 2;
        S3Blobs::with_credentials(&cfg, FakeS3::credentials())
            .unwrap()
            .with_deployment(identity)
    };
    on_db!(rig, |store| {
        let runs: Arc<dyn crawlx_core::repo::RunRepo> = Arc::new(store.clone());
        let clock = Arc::new(SystemClock);
        // a worker of this deployment claims the prefix and leaves an orphan behind
        let worker = blobs(Arc::new(store.clone()));
        worker.put("content/t/r/orphan", b"orphan").await.unwrap();
        let orphan = "shared/content/t/r/orphan".to_owned();
        assert!(fake.keys().contains(&orphan));

        let sweep = |identity: Arc<dyn DeploymentIdentity>| {
            let reaper = ObjectArtifactStore::new(blobs(identity), runs.clone(), clock.clone())
                .with_index(Arc::new(store.clone()));
            RetentionSweeper::new(store.clone())
                .with_artifacts(Arc::new(reaper))
                .with_orphan_grace(chrono::Duration::zero())
        };
        let now = chrono::Utc::now() + chrono::Duration::seconds(5);
        // the other deployment's sweep is refused and removes nothing
        let error = sweep(Arc::new("another-deployment".to_owned()))
            .sweep(now)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("claimed by another crawlx deployment"),
            "{error}"
        );
        assert!(fake.keys().contains(&orphan));
        // this deployment's sweep (a different process, same database) collects the orphan
        let report = sweep(Arc::new(store.clone())).sweep(now).await.unwrap();
        assert_eq!(report.orphans_collected, 1);
        assert!(!fake.keys().contains(&orphan));
        assert!(fake.keys().contains(&"shared/.crawlx-deployment".to_owned()));
    });
}

conformance! { databases:
    deployment_id_is_created_once_and_shared_by_every_user,
    orphan_sweep_is_refused_for_another_deployment_but_runs_for_the_owner,
}
