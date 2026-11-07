//! Usage accounting: every unit of billable work writes one row of the usage ledger
//! ([`crawlx_storage::UsageEvent`]) that `/team/*` aggregates. Recording is best-effort: a
//! failing ledger write is logged and never fails the request that caused it.

use crate::state::AppState;
use crawlx_core::TenantId;
use crawlx_model::llm::TokenUsage;
use crawlx_storage::UsageEvent;
use uuid::Uuid;

/// What a request cost.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Cost {
    /// Credits (crawlx counts one per scraped page, one per search, one per parsed document).
    pub credits: u64,
    /// LLM tokens.
    pub tokens: TokenUsage,
}

impl Cost {
    /// A cost of `credits` and no tokens.
    #[must_use]
    pub const fn credits(credits: u64) -> Self {
        Self {
            credits,
            tokens: TokenUsage {
                prompt_tokens: 0,
                completion_tokens: 0,
            },
        }
    }

    /// Add `other` (saturating).
    pub const fn add(&mut self, other: Self) {
        self.credits = self.credits.saturating_add(other.credits);
        self.tokens.add(other.tokens);
    }
}

/// Append one ledger row for `endpoint` (`search`, `extract`, `agent`, `parse`, `monitor`,
/// `scrape`, ...) with the job or monitor it belongs to and its terminal `status`.
pub async fn record(
    state: &AppState,
    tenant: TenantId,
    endpoint: &str,
    ref_id: Option<Uuid>,
    status: &str,
    cost: Cost,
) {
    let event = UsageEvent {
        tenant,
        at: state.clock.now(),
        endpoint: endpoint.to_owned(),
        ref_id,
        status: status.to_owned(),
        credits: cost.credits,
        prompt_tokens: cost.tokens.prompt_tokens,
        completion_tokens: cost.tokens.completion_tokens,
    };
    if let Err(e) = state.repos.intel.usage_record(&event).await {
        tracing::warn!(error = %e, endpoint, "usage ledger write failed");
    }
}
