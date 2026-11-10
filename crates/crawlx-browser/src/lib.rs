//! crawlx-browser: Chromium lifecycle and the CDP adapter behind `BrowserBackend`.
//!
//! * [`backend`]: [`ChromiumBackend`], launch + pin verification + context factory.
//! * [`context`]: [`CdpContext`], the `BrowserContext` over CDP (observe, revalidate,
//!   perform, settle, epochs, traffic, storage).
//! * [`cdp`]: the only module that touches `chromiumoxide` (WebSocket connection and
//!   message types); typed helpers return crawlx-owned structs.
//! * [`launch`], [`profile`], [`egress`], [`pin`]: flags, launch profiles, proxy flags and
//!   traffic redaction, `chromium-pin.toml`; `LaunchConfig::cdp_ws_url` attaches to a
//!   running browser instead.
//! * [`options`], [`health`], [`consent`]: validated operator launch options (compatibility flags `-sc`, `-scp`,
//!   `-sb`, `-ho`, `-nos`, `-cdd`), the `-health-check` probe, and the cookie-consent banner
//!   blocklist (`dynamic.blockConsentBanners`).
//! * [`hooks`]: the opt-in page-hooks discovery sink (`dynamic.pageHooks`) and the
//!   opt-in behaviour script (`dynamic.pageHookOptions`); [`stealth`]: the opt-in stealth patches
//!   (`dynamic.stealthPatches`).
//! * [`install`], [`profiles`]: Chromium auto-download with a pinned hash and the named
//!   persistent browser profiles (`dynamic.browserProfile`).
//! * [`input`], [`snapshot`], [`target`]: native input, AX/DOMSnapshot conversion, tab graph.
//! * [`fake`]: `FakeBackend`, the scripted backend downstream tests use.
//! * [`NavigationGuard`]: the hook a context consults before it loads a document
//!   (`ContextConfig::navigation_guard`): `robots.txt` obedience for the browser plane. The real
//!   context pauses main-frame document requests with `Fetch.requestPaused`; `FakeBackend`
//!   models the same refusals.
//!
//! `chromiumoxide::Browser::launch` is deliberately not used: its `Handler` sends
//! `Runtime.enable` for every target, which the `Stealth` profile must never do,
//! and the browser must lead its own process group.

pub mod backend;
pub mod captcha;
pub mod cdp;
pub mod consent;
pub mod context;
pub mod egress;
pub mod fake;
pub mod health;
pub mod hooks;
pub mod input;
pub mod install;
pub mod launch;
pub mod options;
pub mod pin;
pub mod profile;
pub mod profiles;
pub mod snapshot;
pub mod stealth;
pub mod target;

pub use backend::ChromiumBackend;
pub use context::CdpContext;
pub use crawlx_core::browser::{BlockedNavigation, NavigationGuard, NavigationVerdict};
pub use fake::{FakeBackend, FakeContext};
pub use hooks::{DiscoverySink, NavigatedUrl, RecordedListener, PAGE_HOOKS_SCRIPT};
pub use launch::LaunchConfig;
pub use options::LaunchOptionError;
pub use pin::ChromiumPin;
