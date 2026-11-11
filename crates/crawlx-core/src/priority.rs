//! The native `priority` frontier strategy, derived from an MIT-licensed upstream
//! implementation; see THIRD_PARTY_NOTICES.md. Every
//! URL gets a *surface score* and is ordered by `depth - score`, so one score point is worth
//! one level of depth and a promising link a level deeper still goes ahead of a plain one.
//!
//! Pure and deterministic: the score depends only on the URL and the request method.

use url::Url;

/// Path segments that usually lead to more attack surface than an average page.
const SURFACE_WORDS: [&str; 35] = [
    "admin",
    "administrator",
    "api",
    "graphql",
    "rest",
    "upload",
    "uploads",
    "file",
    "files",
    "download",
    "import",
    "export",
    "backup",
    "auth",
    "login",
    "signin",
    "signup",
    "register",
    "oauth",
    "sso",
    "token",
    "password",
    "reset",
    "account",
    "user",
    "users",
    "profile",
    "dashboard",
    "manage",
    "console",
    "config",
    "settings",
    "debug",
    "internal",
    "swagger",
];

/// Highest score [`surface_score`] returns (word 2, query 1, non-GET 1).
pub const MAX_SCORE: u32 = 4;

/// Surface score of a request: 2 for the first attack-surface word in the path, 1 for a
/// query string, 1 for a method other than `GET`.
#[must_use]
pub fn surface_score(url: &Url, is_get: bool) -> u32 {
    let mut score = 0;
    if url
        .path()
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| SURFACE_WORDS.iter().any(|s| s.eq_ignore_ascii_case(w)))
    {
        score += 2;
    }
    if url.query().is_some_and(|q| !q.is_empty()) {
        score += 1;
    }
    if !is_get {
        score += 1;
    }
    score
}

/// Queue key of a URL at `depth` under the priority strategy: `depth - score` shifted by
/// [`MAX_SCORE`] so it stays unsigned. Lower is visited first.
#[must_use]
pub fn priority_depth(url: &Url, depth: u32, is_get: bool) -> u32 {
    depth
        .saturating_add(MAX_SCORE)
        .saturating_sub(surface_score(url, is_get))
}

/// Deterministic strategy key within one explicit request-priority tier.
///
/// Breadth-first uses depth and discovery order. Depth-first uses descending depth
/// and reverse discovery order. Priority uses the surface-adjusted depth, then
/// breadth-first tie-breaks. Callers must compare explicit request priorities first.
#[must_use]
pub fn strategy_order(
    strategy: crate::config::CrawlStrategy,
    depth: u16,
    scored_depth: u32,
    id: i64,
) -> (i64, i64, i64) {
    match strategy {
        crate::config::CrawlStrategy::BreadthFirst => (i64::from(depth), 0, id),
        crate::config::CrawlStrategy::DepthFirst => (-i64::from(depth), 0, !id),
        crate::config::CrawlStrategy::Priority => (i64::from(scored_depth), i64::from(depth), id),
    }
}

/// Versioned typed eligibility/ranking expression, separate from URL surface priority.
/// Integer coefficients avoid platform-dependent floating-point ordering.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct EligibilityRankingV1 {
    /// Exactly one.
    pub version: u16,
    /// Inclusive measured HTTP status bounds; absent status never matches these bounds.
    pub status_range: Option<(u16, u16)>,
    /// Minimum measured change frequency, in thousandths.
    pub min_change_rate_permille: u16,
    /// Explicit priority coefficient.
    pub priority_weight: i16,
    /// Measured change-frequency coefficient.
    pub change_weight: i16,
    /// Nonnegative penalty per consecutive acquisition error.
    pub error_penalty: u16,
}

impl Default for EligibilityRankingV1 {
    fn default() -> Self {
        Self {
            version: 1,
            status_range: None,
            min_change_rate_permille: 0,
            priority_weight: 1,
            change_weight: 0,
            error_penalty: 1,
        }
    }
}

impl EligibilityRankingV1 {
    /// Validate the version and finite expression bounds before admitting configuration.
    ///
    /// # Errors
    /// Rejects unsupported versions, malformed status ranges, or change rates over one thousand.
    pub fn validate(&self) -> Result<(), crate::StoreError> {
        if self.version != 1
            || self.min_change_rate_permille > 1000
            || self
                .status_range
                .is_some_and(|(low, high)| !(100..=599).contains(&low) || high < low || high > 599)
        {
            return Err(crate::StoreError::Conflict(
                "invalid eligibility ranking policy".into(),
            ));
        }
        Ok(())
    }

    /// Evaluate eligibility and produce an ascending deterministic rank key.
    /// Hard admission, authorization and robots checks remain independent.
    ///
    /// # Errors
    /// Rejects unsupported versions, invalid status/rate bounds, or unbounded priorities.
    #[allow(clippy::too_many_arguments)]
    pub fn key(
        &self,
        now: crate::Timestamp,
        not_before: Option<crate::Timestamp>,
        status: Option<u16>,
        priority: i32,
        change_rate_permille: u16,
        consecutive_errors: u32,
        stable_id: i64,
    ) -> Result<Option<(i64, i64)>, crate::StoreError> {
        self.validate()?;
        if change_rate_permille > 1000 || i16::try_from(priority).is_err() {
            return Err(crate::StoreError::Conflict(
                "invalid eligibility ranking policy".into(),
            ));
        }
        if not_before.is_some_and(|at| at > now)
            || change_rate_permille < self.min_change_rate_permille
            || self
                .status_range
                .is_some_and(|(low, high)| status.is_none_or(|value| !(low..=high).contains(&value)))
        {
            return Ok(None);
        }
        // These bounded products fit i64 even at u32::MAX consecutive errors.
        let score = i64::from(priority) * i64::from(self.priority_weight)
            + i64::from(change_rate_permille) * i64::from(self.change_weight)
            - i64::from(consecutive_errors) * i64::from(self.error_penalty);
        Ok(Some((-score, stable_id)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn words_query_and_method_add_up() {
        assert_eq!(surface_score(&u("https://a.test/blog/post"), true), 0);
        assert_eq!(surface_score(&u("https://a.test/admin/panel"), true), 2);
        assert_eq!(surface_score(&u("https://a.test/blog?id=1"), true), 1);
        assert_eq!(surface_score(&u("https://a.test/blog"), false), 1);
        assert_eq!(
            surface_score(&u("https://a.test/api/v1/users?x=1"), false),
            MAX_SCORE
        );
    }

    #[test]
    fn only_whole_words_count_and_only_once() {
        assert_eq!(surface_score(&u("https://a.test/administrators-guide"), true), 0);
        assert_eq!(surface_score(&u("https://a.test/Admin/API/login"), true), 2);
        assert_eq!(surface_score(&u("https://a.test/user-profile"), true), 2);
    }

    #[test]
    fn a_surface_link_one_level_deeper_beats_a_plain_one() {
        let plain = priority_depth(&u("https://a.test/blog/a"), 1, true);
        let surface = priority_depth(&u("https://a.test/admin/a"), 2, true);
        assert!(surface < plain, "{surface} < {plain}");
        assert_eq!(priority_depth(&u("https://a.test/api/x?q=1"), 0, true), 1);
    }

    #[test]
    fn typed_eligibility_and_rank_have_stable_hand_computed_ties() {
        let now: crate::Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let policy = EligibilityRankingV1 {
            status_range: Some((200, 299)),
            min_change_rate_permille: 100,
            priority_weight: 2,
            change_weight: 3,
            error_penalty: 5,
            ..EligibilityRankingV1::default()
        };
        assert_eq!(
            policy.key(now, None, Some(200), 7, 500, 2, 9).unwrap(),
            Some((-1504, 9))
        );
        assert_eq!(
            policy.key(now, None, Some(200), 7, 500, 2, 8).unwrap(),
            Some((-1504, 8))
        );
        assert!(policy.key(now, None, None, 7, 500, 2, 9).unwrap().is_none());
        assert!(policy.key(now, None, Some(503), 7, 500, 2, 9).unwrap().is_none());
        assert!(policy
            .key(
                now,
                Some(now + chrono::Duration::seconds(1)),
                Some(200),
                7,
                500,
                2,
                9
            )
            .unwrap()
            .is_none());
        assert!(policy.key(now, None, Some(200), 7, 99, 2, 9).unwrap().is_none());
        assert!(policy.key(now, None, Some(200), 7, 1001, 2, 9).is_err());
    }
}
