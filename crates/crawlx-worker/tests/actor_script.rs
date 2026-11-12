//! Bounded actor scripts reach the worker only as the flat, operator-approved action list:
//! refused scripts never compile, and a compiled script gains no authority.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{
    archive_behaviors::{RecipeReferenceV1, RecipeV1},
    extension_recipes::{ActorActionV1, ExtensionRecipeError, ExtensionRecipeV1, ScriptError},
    scrape::{ScrapeAction, ScrollDirection},
    CreateCrawl, TenantId,
};
use crawlx_worker::archive_behaviors::{sign_registry_bytes, RecipeRegistry};
use crawlx_worker::extension_recipes::{CompiledExtensionRecipe, RecipeExecutionError};
use crawlx_worker::WorkerConfig;
use std::sync::Arc;

const KEY: [u8; 32] = [7; 32];

fn scripted(source: &str) -> ExtensionRecipeV1 {
    let mut spec = ExtensionRecipeV1::new("scripted".into(), 1);
    spec.actor_script = Some(source.into());
    spec
}

fn crawl(spec: ExtensionRecipeV1) -> CreateCrawl {
    let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
    crawl.mode = crawlx_core::config::CrawlMode::Hybrid;
    crawl.dynamic.enabled = true;
    crawl.extension_recipe = Some(spec);
    crawl
}

fn registry_of(recipe: &RecipeV1, tenant: TenantId) -> Arc<RecipeRegistry> {
    let reference = RecipeReferenceV1::for_recipe(recipe).unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion": 1, "recipes": [{
        "recipe": recipe, "digest": reference.digest, "approvedTenants": [tenant],
        "approvalId": "fixture-approval", "legalReviewApproved": true
    }]}))
    .unwrap();
    RecipeRegistry::from_bytes(&sign_registry_bytes(&bytes, &KEY).unwrap(), &KEY).unwrap()
}

#[test]
fn a_script_compiles_to_the_flat_actor_recipe_with_checked_selectors_and_keys() {
    let compiled = CompiledExtensionRecipe::new(scripted(
        "REPEAT 3 AS page\nCLICK `a.page-${page}`\nWAIT 100\nEND\nPRESS Enter",
    ))
    .unwrap();
    let steps = &compiled.actor().steps;
    assert_eq!(steps.len(), 7);
    assert!(matches!(
        &steps[0].action,
        ScrapeAction::Click { selector, all: false } if selector == "a.page-1"
    ));
    assert!(matches!(
        &steps[4].action,
        ScrapeAction::Click { selector, .. } if selector == "a.page-3"
    ));
    assert!(steps.windows(2).all(|p| p[0].source_index < p[1].source_index));
    assert_eq!(
        compiled.pin(),
        &scripted_pin("REPEAT 3 AS page\nCLICK `a.page-${page}`\nWAIT 100\nEND\nPRESS Enter")
    );
    // the unrolled selector and key still pass the worker's own static checks
    assert!(CompiledExtensionRecipe::new(scripted("REPEAT 2\nCLICK `[`\nEND")).is_err());
    assert!(CompiledExtensionRecipe::new(scripted("PRESS not-a-native-key")).is_err());
}

fn scripted_pin(source: &str) -> crawlx_core::extension_recipes::ExtensionRecipePinV1 {
    scripted(source).pin().unwrap()
}

#[test]
fn refused_scripts_fail_before_any_recipe_exists() {
    for (source, check) in [
        (
            "CLICK `a`\nEVAL `window.close()`",
            (|e: &ScriptError| matches!(e, ScriptError::Eval { line: 2 })) as fn(&ScriptError) -> bool,
        ),
        ("REPEAT 21\nCLICK `a`\nEND", |e| {
            matches!(e, ScriptError::RepeatRange { line: 1 })
        }),
        ("REPEAT 20\nREPEAT 20\nCLICK `a`\nEND\nEND", |e| {
            matches!(e, ScriptError::Limit)
        }),
        ("SET `input` \"value\"", |e| {
            matches!(e, ScriptError::NonNativeInteraction { .. })
        }),
        ("IF EXISTS `#gate`\nCLICK `#gate`\nEND", |e| {
            matches!(e, ScriptError::RuntimeCondition { .. })
        }),
    ] {
        match CompiledExtensionRecipe::new(scripted(source)) {
            Err(RecipeExecutionError::Recipe(ExtensionRecipeError::Script(error))) => {
                assert!(check(&error), "{source}: {error}");
            }
            other => panic!("{source}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_compiled_script_gains_no_authority_beyond_the_operator_registry() {
    let tenant = TenantId::new();
    let source = "FILL `input[name=q]` \"query\"\nPRESS Enter\nREPEAT 2\nSCROLL down\nEND";
    let spec = scripted(source);
    let approved = spec.compile_actor().unwrap();

    // the unrolled script is exactly the recipe a hand-written list of the same actions gives, so
    // the runner, kernel denial and first-failure-stops semantics of that path apply unchanged
    let mut by_hand = ExtensionRecipeV1::new("scripted".into(), 1);
    by_hand.actor_actions = vec![
        ActorActionV1::Fill {
            selector: "input[name=q]".into(),
            text: "query".into(),
        },
        ActorActionV1::Press { key: "Enter".into() },
        ActorActionV1::Scroll {
            direction: ScrollDirection::Down,
            selector: None,
        },
        ActorActionV1::Scroll {
            direction: ScrollDirection::Down,
            selector: None,
        },
    ];
    assert_eq!(by_hand.compile_actor().unwrap(), approved);
    assert_eq!(
        RecipeReferenceV1::for_recipe(&by_hand.compile_actor().unwrap()).unwrap(),
        RecipeReferenceV1::for_recipe(&approved).unwrap(),
        "one operator approval covers both spellings and nothing else"
    );

    // no registry: the script cannot run at all
    let bare = WorkerConfig::default();
    assert!(bare
        .resolve_extension_actor_recipe(&crawl(spec.clone()), tenant)
        .await
        .is_err());

    // the exact compiled recipe is approved for the tenant
    let config = WorkerConfig {
        archive_behaviors: Some(registry_of(&approved, tenant)),
        ..WorkerConfig::default()
    };
    let resolved = config
        .resolve_extension_actor_recipe(&crawl(spec.clone()), tenant)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*resolved, approved);

    // another tenant, an edited script and an extra loop iteration are all unapproved
    assert!(config
        .resolve_extension_actor_recipe(&crawl(spec), TenantId::new())
        .await
        .is_err());
    for edited in [
        source.replace("query", "other"),
        source.replace("REPEAT 2", "REPEAT 3"),
        format!("{source}\nWAIT 1"),
    ] {
        assert!(
            config
                .resolve_extension_actor_recipe(&crawl(scripted(&edited)), tenant)
                .await
                .is_err(),
            "{edited}"
        );
    }
}
