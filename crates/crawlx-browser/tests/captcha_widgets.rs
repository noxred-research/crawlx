//! Controlled widgets exercise real CDP and real loopback provider HTTP, never a live provider.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_support;

use crawlx_core::browser::{BrowserContext as _, BrowserError};
use crawlx_core::captcha::{CaptchaConfig, CaptchaCredentials, CaptchaError, CaptchaProvider};
use crawlx_core::observation::ObservationSpec;
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::secret::{CredentialRef, SecretOr};
use crawlx_core::BrowserAction;
use std::collections::BTreeMap;
use surface_support::{canonical, context_config, launch, serve};

const TOKEN: &str = "fixture-secret-captcha-token";

async fn provider() -> surface_support::Server {
    serve(BTreeMap::from([
        ("127.0.0.1/createTask".to_owned(), ("application/json", r#"{"errorId":0,"taskId":"local-task"}"#.to_owned())),
        ("127.0.0.1/getTaskResult".to_owned(), ("application/json", format!(r#"{{"errorId":0,"status":"ready","solution":{{"gRecaptchaResponse":"{TOKEN}","token":"{TOKEN}"}}}}"#))), // wire-compat: provider solution field
    ]), false).await
}

fn configured(port: u16) -> crawlx_core::ContextConfig {
    let mut cfg = context_config();
    let mut solver = CaptchaConfig::new(
        CaptchaProvider::TaskApi,
        CredentialRef("env://UNUSED_TEST_KEY".to_owned()),
    );
    solver.endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    solver.poll_interval_ms = 1;
    cfg.captcha = Some(CaptchaCredentials::new(
        solver,
        SecretOr::secret("local-key".to_owned()),
    ));
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn widget_fields_and_callbacks_use_real_provider_tokens_without_persisting_them() {
    let provider = provider().await;
    // wire-compat: the page fixtures below reproduce third-party widget markup and global APIs
    let page = r#"<!doctype html><html><body>
<form id="danger" method="post" action="/destroy"><div class="g-recaptcha" data-sitekey="site-key" data-callback="accepted"></div></form><!-- wire-compat: widget markup -->
<h1 id="result">waiting</h1>
<script>function accepted(token) {
 document.getElementById('result').textContent = token;
 document.body.dataset.accepted = String(document.querySelector('[name=g-recaptcha-response]').value === token); // wire-compat: widget field name
 try {document.getElementById('danger').submit();} catch (_) {document.body.dataset.submitBlocked = 'yes';}
 console.log(token);
}</script></body></html>"#.to_owned();
    let site = serve(
        BTreeMap::from([("app.test/".to_owned(), ("text/html", page))]),
        true,
    )
    .await;
    let Some(backend) = launch(Some(site.port), |_| {}).await else {
        return;
    };
    let mut ctx = backend.new_cdp_context(configured(provider.port)).await.unwrap();
    ctx.navigate(&canonical("http://app.test/")).await.unwrap();
    assert!(ctx.captcha_pending().await.unwrap());
    ctx.perform(BrowserAction::SolveCaptcha).await.unwrap();
    assert!(!ctx.captcha_pending().await.unwrap());
    assert_eq!(
        ctx.evaluate_isolated("document.body.dataset.accepted")
            .await
            .unwrap(),
        "true"
    );
    assert_eq!(
        ctx.evaluate_isolated("document.body.dataset.submitBlocked")
            .await
            .unwrap(),
        "yes"
    );
    assert_eq!(site.hits.count("app.test/destroy"), 0);
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert!(!format!("{bundle:?}").contains(TOKEN));
    assert!(!format!("{:?}", ctx.console_messages()).contains(TOKEN));
    assert!(!format!("{:?}", ctx.drain_traffic()).contains(TOKEN));
    match ctx.page_op(PageOp::Html).await.unwrap() {
        PageOpResult::Html { html, .. } => assert!(!html.contains(TOKEN)),
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(provider.hits.count("127.0.0.1/createTask"), 1);
    // Repeating an already solved action cannot create another billed task.
    assert!(matches!(
        ctx.perform(BrowserAction::SolveCaptcha).await,
        Err(BrowserError::Captcha(CaptchaError::UnsupportedChallenge))
    ));
    assert_eq!(provider.hits.count("127.0.0.1/createTask"), 1);
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_render_callbacks_and_v3_promises_receive_their_widget_token() {
    let provider = provider().await;
    let page = r#"<!doctype html><html><body><div id="widget-t"></div><div class="h-captcha" data-sitekey="hkey" data-callback="hSolved"></div><!-- wire-compat: widget markup -->
<div class="g-recaptcha" data-sitekey="ent-v2-key" data-s="enterprise-s" data-callback="entV2Solved"></div><script src="/recaptcha/enterprise.js"></script><!-- wire-compat: widget markup -->
<script>
 window.turnstile = {render: () => 'widget-0', getResponse: () => ''}; // wire-compat: widget global API
 turnstile.render(document.getElementById('widget-t'), {sitekey:'tkey', callback: token => {document.body.dataset.widgetT = token; document.body.dataset.widgetApi = String(turnstile.getResponse('widget-0') === token);}}); // wire-compat: widget global API
 function hSolved(token) {document.body.dataset.widgetH = token;}
 function entV2Solved(token) {document.body.dataset.entv2 = token;}
 window.grecaptcha = {}; // wire-compat: widget global API
 grecaptcha.execute = () => Promise.reject(new Error('must use solver')); // wire-compat: widget global API
 grecaptcha.enterprise = {}; // wire-compat: widget global API
 grecaptcha.enterprise.execute = () => Promise.reject(new Error('must use solver')); // wire-compat: widget global API
 grecaptcha.execute('v3key', {action:'login'}).then(token => {document.body.dataset.v3 = token;}); // wire-compat: widget global API
 grecaptcha.enterprise.execute('entkey', {action:'verify'}).then(token => {document.body.dataset.enterprise = token;}); // wire-compat: widget global API
 grecaptcha.execute('noactionkey').then(token => {document.body.dataset.v3WithoutAction = token;}); // wire-compat: widget global API
</script></body></html>"#;
    let site = serve(
        BTreeMap::from([("app.test/".to_owned(), ("text/html", page.to_owned()))]),
        true,
    )
    .await;
    let Some(backend) = launch(Some(site.port), |_| {}).await else {
        return;
    };
    let mut ctx = backend.new_cdp_context(configured(provider.port)).await.unwrap();
    ctx.navigate(&canonical("http://app.test/")).await.unwrap();
    ctx.perform(BrowserAction::SolveCaptcha).await.unwrap();
    for name in [
        "widgetT",
        "widgetH",
        "v3",
        "enterprise",
        "entv2",
        "v3WithoutAction",
    ] {
        assert_eq!(
            ctx.evaluate_isolated(&format!("document.body.dataset.{name}"))
                .await
                .unwrap(),
            TOKEN
        );
    }
    assert_eq!(
        ctx.evaluate_isolated("document.body.dataset.widgetApi")
            .await
            .unwrap(),
        "true"
    );
    assert_eq!(provider.hits.count("127.0.0.1/createTask"), 6);
    assert!(!format!("{:?}", ctx.observe(ObservationSpec::default()).await.unwrap()).contains(TOKEN));
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambiguous_provider_failure_cannot_bill_the_same_widget_twice() {
    let provider = serve(
        BTreeMap::from([(
            "127.0.0.1/createTask".to_owned(),
            ("application/json", "not-json".to_owned()),
        )]),
        false,
    )
    .await;
    let site = serve(
        BTreeMap::from([(
            "app.test/".to_owned(),
            (
                "text/html",
                "<div class=cf-turnstile data-sitekey=key></div>".to_owned(), // wire-compat: widget markup
            ),
        )]),
        true,
    )
    .await;
    let Some(backend) = launch(Some(site.port), |_| {}).await else {
        return;
    };
    let mut ctx = backend.new_cdp_context(configured(provider.port)).await.unwrap();
    ctx.navigate(&canonical("http://app.test/")).await.unwrap();
    assert!(matches!(
        ctx.perform(BrowserAction::SolveCaptcha).await,
        Err(BrowserError::Captcha(CaptchaError::InvalidResponse))
    ));
    assert!(matches!(
        ctx.perform(BrowserAction::SolveCaptcha).await,
        Err(BrowserError::Captcha(CaptchaError::Delivery))
    ));
    assert_eq!(provider.hits.count("127.0.0.1/createTask"), 1);
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_off_never_contacts_provider_and_unknown_widgets_fail_explicitly() {
    let site = serve(
        BTreeMap::from([(
            "app.test/".to_owned(),
            ("text/html", "<div class=g-recaptcha></div>".to_owned()), // wire-compat: widget markup
        )]),
        true,
    )
    .await;
    let Some(backend) = launch(Some(site.port), |_| {}).await else {
        return;
    };
    let mut off = backend.new_cdp_context(context_config()).await.unwrap();
    off.navigate(&canonical("http://app.test/")).await.unwrap();
    assert!(!off.captcha_pending().await.unwrap());
    assert!(matches!(
        off.perform(BrowserAction::SolveCaptcha).await,
        Err(BrowserError::Captcha(CaptchaError::Configuration))
    ));
    let provider = provider().await;
    let mut enabled = backend.new_cdp_context(configured(provider.port)).await.unwrap();
    enabled.navigate(&canonical("http://app.test/")).await.unwrap();
    assert!(matches!(
        enabled.captcha_pending().await,
        Err(BrowserError::Captcha(CaptchaError::UnsupportedChallenge))
    ));
    assert_eq!(provider.hits.count("127.0.0.1/createTask"), 0);
    backend.close().await.unwrap();
}
