//! `-fc` form-config values in the browser plane (the `-form-config` compatibility flag):
//! when `extract.formFill` is enabled and configures a value for a field's class, the browser
//! plane types it into the matching `Type` partition (valid email, phone, password, text);
//! without the config, and for fields no class matches, the seeded partition values apply.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, FormFill, SafetyProfile};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::sync::Arc;

fn script() -> FakeScript {
    FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Sign up")
            .node(FakeAxSpec::textbox("email", "Email").attr("type", "email"))
            .node(FakeAxSpec::textbox("nick", "Nickname").attr("type", "text"))
            .node(FakeAxSpec::textbox("qty", "Quantity").attr("type", "number")),
    )
}

/// What the browser plane typed, by node key.
async fn typed(form_fill: Option<FormFill>) -> BTreeMap<String, String> {
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_028);
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.limits.interactions = 30;
    crawl.limits.states = 50;
    if let Some(f) = form_fill {
        crawl.extract.form_fill = f;
    }
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(script()));
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    backend
        .context_handles()
        .iter()
        .flat_map(|h| h.typed_inputs())
        .filter_map(|t| t.text.map(|text| (t.key, text)))
        .collect()
}

fn configured() -> FormFill {
    FormFill {
        enabled: true,
        email: Some("fc@example.org".to_owned()),
        placeholder: Some("Alice".to_owned()),
        ..FormFill::default()
    }
}

#[tokio::test]
async fn configured_values_reach_the_matching_fields_of_the_browser_plane() {
    let seeded = typed(None).await;
    assert!(
        seeded.contains_key("email") && seeded.contains_key("nick"),
        "the browser plane typed into the fields: {seeded:?}"
    );
    assert_ne!(seeded["email"], "fc@example.org");
    assert_ne!(seeded["nick"], "Alice");

    let with_config = typed(Some(configured())).await;
    assert_eq!(with_config["email"], "fc@example.org", "{with_config:?}");
    assert_eq!(with_config["nick"], "Alice", "{with_config:?}");
    if let Some(quantity) = with_config.get("qty") {
        assert_eq!(
            Some(quantity),
            seeded.get("qty"),
            "a number has no configured class"
        );
    }
}

#[tokio::test]
async fn a_form_config_without_automatic_form_fill_changes_nothing() {
    let off = FormFill {
        enabled: false,
        ..configured()
    };
    assert_eq!(typed(Some(off)).await, typed(None).await);
}
