//! Queue cost policy: the bounded, deterministic cost a newly discovered URL is queued under.
//!
//! The cost is assigned once, at discovery, from facts the crawl already holds: the typed hop
//! path that led to the URL, whether its path or query looks like a calendar, how often one path
//! segment repeats, and how many pages the URL's host has already yielded. It becomes the
//! request's explicit priority (`base - cost`), which the durable queue already applies before the
//! configured strategy, so no second ordering exists and a restart cannot change it.
//!
//! The cost is advisory ordering only. It never admits a URL: scope, robots, authorization and the
//! origin governor decide that independently, and the hop limits that stop calendar-style traps
//! outright live in [`crate::request::hops::HopPolicyV1`].

use crate::request::hops::{repeated_segments, HopKindV1, HopPathV1};
use serde::{Deserialize, Serialize};
use url::Url;

/// Largest `maxCost` a policy may configure; keeps `base - cost` inside the `i16` request
/// priority range.
pub const MAX_QUEUE_COST: u32 = 32_000;

/// Month names (short and long) that make a path segment look like part of a date.
const MONTHS: [&str; 24] = [
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "sept",
    "october",
    "november",
    "december",
];

/// Query parameter names that carry a date or calendar position.
const CALENDAR_KEYS: [&str; 13] = [
    "date",
    "day",
    "month",
    "year",
    "week",
    "cal",
    "calendar",
    "ym",
    "ymd",
    "startdate",
    "enddate",
    "start_date",
    "end_date",
];

fn is_year(segment: &str) -> bool {
    segment.len() == 4
        && segment.bytes().all(|b| b.is_ascii_digit())
        && segment
            .parse::<u16>()
            .is_ok_and(|year| (1900..=2099).contains(&year))
}

fn is_iso_date(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
    };
    (bytes.len() == 7 && digits(0..4) && bytes[4] == b'-' && digits(5..7))
        || (bytes.len() == 10
            && digits(0..4)
            && bytes[4] == b'-'
            && digits(5..7)
            && bytes[7] == b'-'
            && digits(8..10))
}

fn is_day_or_month_number(segment: &str) -> bool {
    segment.len() <= 2
        && segment.bytes().all(|b| b.is_ascii_digit())
        && segment.parse::<u8>().is_ok_and(|n| (1..=31).contains(&n))
}

/// Date-like tokens in `url`: calendar words, years, month names, ISO dates, and a one or two
/// digit number right after another date token (`/2024/05/12` counts three), plus query
/// parameters named like a date. A calendar trap is a family of URLs that differ only in these.
#[must_use]
pub fn calendar_tokens(url: &Url) -> usize {
    let mut tokens = 0usize;
    let mut previous_was_date = false;
    for segment in url.path().split('/').filter(|segment| !segment.is_empty()) {
        let lower = segment.to_ascii_lowercase();
        let date_like = lower == "calendar"
            || lower == "cal"
            || is_year(&lower)
            || is_iso_date(&lower)
            || MONTHS.contains(&lower.as_str());
        let follows = previous_was_date && is_day_or_month_number(&lower);
        if date_like || follows {
            tokens = tokens.saturating_add(1);
        }
        previous_was_date = date_like || follows;
    }
    for (key, _) in url.query_pairs() {
        if CALENDAR_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            tokens = tokens.saturating_add(1);
        }
    }
    tokens
}

/// `scope.queueCost`: how discovery cost orders the queue. Lower cost is dequeued first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct QueueCostPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Cost of each followed link in the hop path (default 1).
    pub link_cost: u16,
    /// Cost of each embedded resource (default 0: embeds ride with their page).
    pub embed_cost: u16,
    /// Cost of each prerequisite (default 0: a page's prerequisites are not pushed behind it).
    pub prerequisite_cost: u16,
    /// Cost of each redirect (default 0).
    pub redirect_cost: u16,
    /// Cost per date-like token in the URL (default 4; `0` turns the anti-calendar rule off).
    pub calendar_penalty: u16,
    /// Cost per repetition of one path segment beyond the first (default 2).
    pub repeat_penalty: u16,
    /// Pages a host yields per success step; `0` turns the success rule off (default 0).
    pub success_step: u32,
    /// Cost added per completed success step of the URL's host (default 1).
    pub success_penalty: u16,
    /// Ceiling of the total cost, at most [`MAX_QUEUE_COST`] (default 1000).
    pub max_cost: u32,
}

impl Default for QueueCostPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            link_cost: 1,
            embed_cost: 0,
            prerequisite_cost: 0,
            redirect_cost: 0,
            calendar_penalty: 4,
            repeat_penalty: 2,
            success_step: 0,
            success_penalty: 1,
            max_cost: 1000,
        }
    }
}

impl QueueCostPolicyV1 {
    /// Check the version and ceiling.
    ///
    /// # Errors
    /// An unsupported version or a ceiling of zero or above [`MAX_QUEUE_COST`].
    pub fn validate(&self) -> Result<(), crate::StoreError> {
        if self.version != 1 || self.max_cost == 0 || self.max_cost > MAX_QUEUE_COST {
            return Err(crate::StoreError::Conflict("invalid queue cost policy".into()));
        }
        Ok(())
    }

    /// Total cost of a URL reached by `path`, whose host has yielded `host_successes` pages.
    /// Integer arithmetic throughout; the same inputs give the same cost on every platform.
    #[must_use]
    pub fn cost(&self, url: &Url, path: &HopPathV1, host_successes: u32) -> u32 {
        let hops = [
            (HopKindV1::Link, self.link_cost),
            (HopKindV1::Embed, self.embed_cost),
            (HopKindV1::Prerequisite, self.prerequisite_cost),
            (HopKindV1::Redirect, self.redirect_cost),
        ]
        .into_iter()
        .map(|(kind, weight)| {
            u64::try_from(path.count(kind))
                .unwrap_or(u64::MAX)
                .saturating_mul(u64::from(weight))
        })
        .fold(0u64, u64::saturating_add);
        let calendar = u64::try_from(calendar_tokens(url))
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(self.calendar_penalty));
        let repeats = u64::try_from(repeated_segments(url).saturating_sub(1))
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(self.repeat_penalty));
        let success = u64::from(host_successes.checked_div(self.success_step).unwrap_or(0))
            .saturating_mul(u64::from(self.success_penalty));
        let total = hops
            .saturating_add(calendar)
            .saturating_add(repeats)
            .saturating_add(success)
            .min(u64::from(self.max_cost));
        u32::try_from(total).unwrap_or(self.max_cost)
    }

    /// The explicit request priority for `cost`: `base - cost`, inside the `i16` range the
    /// request envelope accepts. Higher dispatches first.
    #[must_use]
    pub fn priority(&self, base: i32, cost: u32) -> i32 {
        let value = i64::from(base)
            .saturating_sub(i64::from(cost))
            .clamp(i64::from(i16::MIN), i64::from(i16::MAX));
        i32::try_from(value).unwrap_or(0)
    }

    /// Ascending queue key `(−priority, stable id)`: dequeue the smallest first. Equal costs
    /// fall back to the stable id, so the order is total and replays identically.
    #[must_use]
    pub fn rank_key(&self, base: i32, cost: u32, stable_id: i64) -> (i64, i64) {
        (-i64::from(self.priority(base, cost)), stable_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn path(text: &str) -> HopPathV1 {
        HopPathV1::try_from(text.to_owned()).unwrap()
    }

    #[test]
    fn calendar_tokens_count_dates_not_ordinary_numbers() {
        assert_eq!(calendar_tokens(&url("https://t.test/blog/post-1")), 0);
        assert_eq!(calendar_tokens(&url("https://t.test/items/42")), 0);
        assert_eq!(calendar_tokens(&url("https://t.test/calendar/2024/05")), 3);
        assert_eq!(calendar_tokens(&url("https://t.test/calendar/2024/05/12")), 4);
        assert_eq!(calendar_tokens(&url("https://t.test/archive/2024-05-12")), 1);
        assert_eq!(calendar_tokens(&url("https://t.test/events/March/7")), 2);
        assert_eq!(
            calendar_tokens(&url("https://t.test/list?month=5&page=2&Year=2024")),
            2
        );
        assert_eq!(calendar_tokens(&url("https://t.test/1999")), 1);
        assert_eq!(calendar_tokens(&url("https://t.test/3000")), 0);
    }

    /// Hand-computed with the default weights: link 1, calendar token 4, repeated segment 2.
    #[test]
    fn calendar_trap_graph_has_a_stable_hand_computed_queue_order() {
        let policy = QueueCostPolicyV1::default();
        // (id, url, hop path, expected cost)
        let graph = [
            (11, "https://t.test/calendar/2024/05/12", "LLLL", 4 + 4 * 4),
            (12, "https://t.test/about", "L", 1),
            (13, "https://t.test/calendar/2024/05", "LL", 2 + 3 * 4),
            (14, "https://t.test/blog/post-1", "LL", 2),
            (15, "https://t.test/logo.png", "LE", 1),
            (16, "https://t.test/app.js", "LP", 1),
            (17, "https://t.test/a/b/a/b/a/b", "LL", 2 + 2 * 2),
            (18, "https://t.test/calendar/2024/06", "LL", 2 + 3 * 4),
            (19, "https://t.test/a/redirected", "LR", 1),
        ];
        let mut ranked: Vec<(i64, i64, u32)> = graph
            .iter()
            .map(|(id, text, hops, expected)| {
                let cost = policy.cost(&url(text), &path(hops), 0);
                assert_eq!(cost, *expected, "cost of {text}");
                let key = policy.rank_key(0, cost, *id);
                (key.0, key.1, cost)
            })
            .collect();
        ranked.sort_unstable();
        let order: Vec<i64> = ranked.iter().map(|(_, id, _)| *id).collect();
        // cost 1: 12, 15, 16, 19; cost 2: 14; cost 6: 17; cost 14: 13, 18; cost 20: 11
        assert_eq!(order, vec![12, 15, 16, 19, 14, 17, 13, 18, 11]);
        // the order does not depend on discovery order
        let mut reversed: Vec<(i64, i64)> = graph
            .iter()
            .rev()
            .map(|(id, text, hops, _)| policy.rank_key(0, policy.cost(&url(text), &path(hops), 0), *id))
            .collect();
        reversed.sort_unstable();
        assert_eq!(reversed.iter().map(|(_, id)| *id).collect::<Vec<_>>(), order);
    }

    #[test]
    fn success_counts_demote_a_host_and_the_cost_is_capped() {
        let policy = QueueCostPolicyV1 {
            success_step: 3,
            success_penalty: 2,
            max_cost: 10,
            ..QueueCostPolicyV1::default()
        };
        let page = url("https://t.test/x");
        assert_eq!(policy.cost(&page, &path("L"), 2), 1);
        assert_eq!(policy.cost(&page, &path("L"), 7), 1 + 2 * 2);
        assert_eq!(policy.cost(&page, &path("L"), 300), 10, "capped");
        assert_eq!(policy.priority(0, 10), -10);
        assert_eq!(policy.priority(5, 7), -2);
        assert_eq!(
            QueueCostPolicyV1 {
                max_cost: MAX_QUEUE_COST,
                ..policy.clone()
            }
            .priority(0, MAX_QUEUE_COST),
            -32_000
        );
        assert_eq!(policy.priority(i32::MIN, 10), i32::from(i16::MIN));
        assert!(QueueCostPolicyV1 {
            max_cost: 0,
            ..policy.clone()
        }
        .validate()
        .is_err());
        assert!(QueueCostPolicyV1 {
            max_cost: MAX_QUEUE_COST + 1,
            ..policy
        }
        .validate()
        .is_err());
    }

    #[test]
    fn calendar_rule_can_be_turned_off() {
        let policy = QueueCostPolicyV1 {
            calendar_penalty: 0,
            ..QueueCostPolicyV1::default()
        };
        assert_eq!(
            policy.cost(&url("https://t.test/calendar/2024/05"), &path("LL"), 0),
            2
        );
    }
}
