//! PostgreSQL implementations of the `crawlx_core::repo` traits on [`crate::Pg`].

pub mod api;
pub mod authorization;
mod checkpoint;
mod edge;
mod event;
mod frontier;
mod identity_alias;
pub mod inspect;
mod intel;
mod journal;
mod ledger;
mod model_decision;
mod page;
mod privacy;
mod run;
mod safety;
mod state;

pub(crate) use journal::{flip_intended_to_unknown, traffic_attribution};
pub(crate) use ledger::{key_from_row, KEY_COLS};
pub(crate) use state::{pick_successor, split_event};

use crate::codec::{conv, get, parse_label};
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::CrawlSession;
use crawlx_core::{CrawlRunId, PrincipalId, SessionId, StoreError};
use sqlx::postgres::PgRow;

/// Column list for `crawl_sessions` rows read by [`session_from_row`] (alias `s`).
pub(crate) const SESSION_COLS: &str = "s.session_id, s.run_id, s.role, s.run_index, s.schedule_slot, s.status, \
    s.browser_build, s.cdp_revision, s.browser_user_agent, s.browser_pinned, s.launch_profile, s.console_capture, s.action_seq";

pub(crate) fn session_from_row(r: &PgRow) -> Result<CrawlSession, StoreError> {
    let browser = match get::<Option<String>>(r, "browser_build")? {
        Some(chromium_version) => Some(BrowserBuildInfo {
            chromium_version,
            cdp_revision: get::<Option<String>>(r, "cdp_revision")?.unwrap_or_default(),
            user_agent: get::<Option<String>>(r, "browser_user_agent")?.unwrap_or_default(),
            pinned: get::<Option<bool>>(r, "browser_pinned")?.unwrap_or(false),
            launch_profile: parse_label(&get::<String>(r, "launch_profile")?)?,
            console_capture: get(r, "console_capture")?,
            // not persisted (no column yet); attached sessions are
            // worker-local and never pinned
            attached: false,
        }),
        None => None,
    };
    Ok(CrawlSession {
        id: SessionId(get(r, "session_id")?),
        run: CrawlRunId(get(r, "run_id")?),
        role: PrincipalId(get(r, "role")?),
        run_index: conv(get::<i32>(r, "run_index")?, "run_index")?,
        schedule_slot: conv(get::<i32>(r, "schedule_slot")?, "schedule_slot")?,
        status: parse_label(&get::<String>(r, "status")?)?,
        browser,
        action_seq: conv(get::<i64>(r, "action_seq")?, "action_seq")?,
    })
}
