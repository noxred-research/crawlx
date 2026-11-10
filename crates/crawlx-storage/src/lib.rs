//! crawlx-storage: PostgreSQL repositories, migrations, the artifact store and
//! retention.
//!
//! # What lives here
//!
//! * [`Pg`] – pooled PostgreSQL handle. It implements every repository trait of
//!   `crawlx_core::repo` (`RunRepo`, `FrontierRepo`, `PageRepo`, `ActionJournal`,
//!   `StateRepo`, `EdgeStore`, `LedgerRepo`, `SafetyAudit`, `EventRepo`) plus
//!   [`leases::LeaseRepo`].
//! * [`artifacts`] – content-addressed [`artifacts::FsArtifactStore`],
//!   [`artifacts::MemoryArtifactStore`] and [`s3::S3ArtifactStore`] implementing
//!   `crawlx_core::repo::ArtifactStore`, with the ZDR write gate from [`retention`].
//!   Backends implement [`artifacts::ArtifactBlobs`]; [`s3`] is the S3-compatible one
//!   and the only one that presigns `content` URLs.
//! * [`checkpoint_crypto`] – ownership-bound checkpoint encryption with process-local
//!   memory custody or explicit cloud KMS envelope keys; no plaintext fallback.
//! * [`zdr`] – [`zdr::DeliveryBuffer`], bounded shared volatile delivery over Redis or an
//!   explicitly configured tmpfs; process memory is an explicit local/test backend only.
//!   ZDR content disappears on webhook acknowledgement or fixed 1 h expiry.
//! * [`trusted`] – [`trusted::TrustedCorpus`], the lane-aware read path for coverage and
//!   traffic consumers; the `/traffic` and `/coverage` endpoints go through it.
//! * [`InspectRepo`] – typed reads of `network_epochs`, navigation events and
//!   `transitions` for `crawlx inspect`/`crawlx replay`, so the CLI holds no SQL.
//! * [`retention`] – the sweeper (expired artifacts, pages, whole-run purge with an
//!   audit-chain row), the ZDR gate and monthly `traffic_events` partitions.
//! * [`audit`] – the daily Merkle export of the `audit_events` chain
//!   ([`audit::MerkleExport`]).
//! * [`leases`] – session leases with fencing tokens and the round-robin turn
//!   barrier, plus the stale-lease reaper primitives.
//! * [`intel`] – [`IntelRepo`], the persistence of the compatibility API's LLM products:
//!   `extract`/`agent` jobs with trace, snapshots and threads, scheduled monitors with
//!   checks and baselines, the usage ledger behind `/team/*` and tenant settings.
//!   [`MemoryIntel`] is the in-memory implementation; `Pg` implements it over migration 0016.
//! * [`testkit`] – deterministic fixtures for this crate's and downstream tests.
//! * [`memory`] – in-memory implementations of every trait (`MemoryStore`,
//!   `InMemoryJournal`) for worker, strategy and scheduler tests.
//!
//! # SQL numeric and error boundaries
//!
//! Numeric counters and versions use checked conversions and return
//! [`crawlx_core::StoreError::Serialization`] when a column cannot represent them.
//! Seeds and perceptual hashes instead encode all 64 bits into signed `BIGINT`
//! slots; this representation preserves existing negative slots without wrapping
//! numeric casts. Unclassified driver failures retain their original error chain
//! in [`crawlx_core::StoreError::Database`], whose display omits driver details.
//!
//! # Deliberate design choices
//!
//! * **Runtime-checked queries.** Every statement uses `sqlx::query` /
//!   `query_as`; there are no `query!` macros and no `.sqlx` offline data, so the
//!   crate builds without a database. `sqlx::migrate!` embeds `migrations/`.
//!   Consequently the CI `cargo sqlx prepare --check` step has nothing to check
//!   for this crate.
//! * **Schema adaptations** (all in `migrations/`): enum labels follow the
//!   `as_str()` of the `crawlx-core` types (`risk_class`, `action_fidelity`,
//!   `terminal_reason`, `traffic_events.origin`, `url_frontier.status`); extra
//!   columns carry what the core record types need to round-trip
//!   (`action_contexts.context_hash`, `actions.before_state_id`,
//!   `states.observed_url`, `pages.url_meta`, ...); the foreign keys on
//!   `action_contexts.state_cluster_id`, `enablement_edges.context_cluster_id` and
//!   `actions.model_decision_id` are dropped because clusters and model decisions
//!   are written by other components on their own schedule.
//! * `FrontierRepo::lease_batch` claims across origins. The shared HTTP/browser
//!   governor uses [`origin::PgOriginAdmission`] and `origin_leases` for run-local
//!   admission, plus `origin_admission` for deployment-wide cross-tenant limits.
//!   Permits hold transaction-scoped advisory locks until drop; no expiring TTL
//!   can free capacity while a paused worker still performs an effect.
//! * ZDR: the artifact gate, header/URL redaction on `traffic_events` and value-free
//!   `actions.params` are implemented; NULLing `canonical_url` is not, because the
//!   frontier needs the URL while the run is live.

pub mod admin;
pub mod archive;
pub mod archive_catalog;
pub mod artifact_crypto;
pub mod artifact_custody;
pub mod artifact_key_crypto;
pub mod artifacts;
pub mod audit;
pub mod ax_artifact;
pub mod chaos;
pub mod checkpoint_crypto;
mod codec;
pub mod custody;
pub mod dataset;
mod error;
pub mod intel;
mod intel_memory;
pub mod leases;
pub mod memory;
pub mod origin;
mod pg;
pub mod profiles;
mod repos;
pub mod retention;
pub mod s3;
pub mod safety_auditor;
pub mod session_binding;
pub mod spool;
pub mod tenant;
pub mod testkit;
pub mod trail;
pub mod trusted;
pub mod zdr;

pub use admin::{
    AdminOps, AdmissionMode, ArtifactDefect, ArtifactVerification, DurabilityAudit, OpenAction, RunSelector,
    TenantEngine, WorkerRegistry, WorkerRow,
};
pub use artifact_custody::{
    ArtifactCustody, CustodyWrites, LeasedSecretRegistrar, LocalArtifactCustody, PgArtifactCustody,
};
pub use artifacts::{
    ArtifactBlobs, ArtifactIndex, ArtifactReaper, ArtifactRow, BlobEntry, FsArtifactStore, FsBlobs,
    LiveArtifacts, MemBlobs, MemoryArtifactStore, ObjectArtifactStore, PRESIGN_MAX_TTL,
};
pub use audit::{AuditDayExport, MerkleExport};
pub use intel::{
    Baseline, CheckPage, CheckRecord, CheckState, IntelRepo, IntelResult, JobCount, JobKind, JobPatch,
    JobRecord, JobStatus, MemoryIntel, MonitorRecord, MonitorStatus, PurgeReport, Snapshot, ThreadRecord,
    TraceEvent, UsageDay, UsageEvent, UsageTotals,
};
pub use leases::{
    ActiveRun, LeaseRepo, ReapReport, SessionLease, DEFAULT_SESSION_TTL, DEFAULT_URL_BATCH_TTL,
};
pub use memory::adaptive_selectors;
pub use memory::{InMemoryJournal, MemoryStore};
pub use origin::PgOriginAdmission;
pub use pg::{AuthorizationRow, Pg, PgConfig};
pub use repos::api::{
    ActionSummary, ApiKeyRow, ApprovalDecision, ApprovalRecord, DecideOutcome, DeliveryResult,
    DeliveryStatus, IdemClaim, IdemResponse, PgApiRepo, TransitionFilter, TransitionRecord, WebhookDelivery,
};
pub use repos::authorization::{AuthorizationInsert, NewAuthorization, Revoked, StoredAuthorization};
pub use repos::inspect::{EpochRow, InspectRepo, NavigationEvent, TransitionRow};
pub use retention::{RetentionSweeper, SweepReport};
pub use s3::{S3ArtifactStore, S3Blobs, S3Config};
pub use safety_auditor::{SafetyAuditReport, SafetyAuditor, SafetyViolation};
pub use spool::{UploadSpool, UploadSpoolConfig};
pub use trail::{TrafficAttributionRow, TrailReads};
pub use trusted::{CorpusTrafficEvent, CoverageRow, LaneFilter, TrafficQuery, TrustedCorpus};
pub use zdr::{BufferLimits, BufferedBlob, BufferedPage, DeliveryBuffer};
