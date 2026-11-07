//! crawlx-forms: input classification, deterministic value partitions, form
//! grouping.
//!
//! * [`classify`]: `InputClassifier::classify(&ObservedDescriptor) -> InputClass2`
//!   from `type`, `autocomplete`, `inputmode`, ARIA role, multilingual
//!   (en/de/fr/es/tr) label keywords and `pattern`; [`FormSemantics`] with the
//!   `form_hint()` vocabulary `crawlx-safety` matches on.
//! * [`group`]: `FormGrouper::group` by `form` ownership, AX landmark, or
//!   single-submit proximity; orphans form one group.
//! * [`partition`]: the base partition table, profile-dependent sets and the
//!   validators generated values must satisfy.
//! * [`seed`]: `ValuePartitions::value`, seed-derived and wall-clock free.
//! * [`fixtures`]: fixture files for `file:*` partitions.
//! * [`sinks`]: test-sink requirements (mirrors `crawlx_safety::sinks::SinkKind`
//!   without depending on that crate).
//! * [`login`]: the declarative `builtin:form` login plan and `login::recorded`, the
//!   Chrome DevTools Recorder / explicit-step flows.
//! * [`cache`]: model-advisory cache keyed `(element identity, principal, locale)`.
//!
//! Nothing here reads wall time or global randomness; hashing paths iterate
//! ordered collections only.

pub mod cache;
pub mod classify;
pub mod fixtures;
pub mod group;
pub mod login;
pub mod partition;
pub mod seed;
pub mod sinks;
mod text;

pub use cache::{CachedFormClassification, FormCacheKey, FormClassificationCache, ModelStamp};
pub use classify::{
    DateFlavor, FieldRole, FormSemantics, InputClass2, InputClassifier, InputConstraints, InputKind,
    REFINE_BELOW,
};
pub use fixtures::{FixtureContent, FixtureFile, FixtureFiles};
pub use group::{FormGroup, FormGroupId, FormGrouper, FormInput, FormMethod, GroupOrigin};
pub use login::recorded::{
    is_logout_path, FillValue, PressKey, RecordedFlow, RecordedFlowError, Selector, SelectorKind,
    LOGOUT_PATHS,
};
pub use login::{
    detect_login_form, CredentialPart, LoggedInIndicator, LoginError, LoginExpectation, LoginField,
    LoginPlan, LoginPlanSource, LoginStep, LoginTarget, LoginTargets, SubmitMethod,
};
pub use partition::{
    ofat_combinations, partitions_for, partitions_for_set, validate, ParsePartitionError, Partition,
    PartitionFamily, PartitionSet, ALL_PARTITIONS,
};
pub use seed::{ConfiguredValues, ValueContext, ValuePartitions, FALLBACK_EMAIL_DOMAIN, GENERATOR_VERSION};
pub use sinks::{requires_sink, sink_domain, SinkKind, TestSinksLike};
