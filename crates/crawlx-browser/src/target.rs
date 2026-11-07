//! Bounded tab graph: popups open as targets in the session's browser
//! context; the graph decides which are attached and which are closed immediately.

use crawlx_core::ids::TabId;
use crawlx_core::observation::TabInfo;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// More than this many targets created within [`STORM_WINDOW`] is a popup storm.
pub const STORM_LIMIT: usize = 5;
/// Width of the sliding window the popup-storm limit is counted over.
pub const STORM_WINDOW: Duration = Duration::from_secs(2);
/// Maximum wait for a popup's first navigation before applying scope policy.
pub const FIRST_NAVIGATION_WAIT: Duration = Duration::from_secs(2);

/// Why a new target is not admitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejectReason {
    /// Too many targets created in a short window.
    Storm,
}

/// Outcome of [`TabGraph::on_target_created`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TabDecision {
    /// Attach to the target and use it as a tab.
    Attach,
    /// Keep the target pending until the worker journals an eviction or rejection.
    Pending,
    /// Close the target.
    Reject(RejectReason),
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct TabNode {
    opener: Option<String>,
    url: String,
    pending: bool,
    download: bool,
    closed: bool,
    created: Option<Instant>,
}

/// The open tabs of one browser context.
#[derive(Debug)]
pub struct TabGraph {
    max_tabs: usize,
    tabs: BTreeMap<String, TabNode>,
    created: VecDeque<Instant>,
    /// Popups rejected so far (counted as `out_of_scope_popup` by callers).
    rejected: u64,
}

impl TabGraph {
    /// A graph admitting at most `max_tabs` tabs (a value of 0 is raised to 1).
    #[must_use]
    pub fn new(max_tabs: u8) -> Self {
        Self {
            max_tabs: usize::from(max_tabs.max(1)),
            tabs: BTreeMap::new(),
            created: VecDeque::new(),
            rejected: 0,
        }
    }

    /// Register the tab the context was created with; it always counts and is never evicted.
    pub fn add_home(&mut self, id: &str, url: &str) {
        self.tabs.insert(
            id.to_owned(),
            TabNode {
                opener: None,
                url: url.to_owned(),
                pending: false,
                download: false,
                closed: false,
                created: None,
            },
        );
    }

    /// Decide whether a newly created target joins the graph.
    pub fn on_target_created(
        &mut self,
        id: &str,
        opener: Option<&str>,
        url: &str,
        now: Instant,
    ) -> TabDecision {
        self.created.push_back(now);
        while self
            .created
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > STORM_WINDOW)
        {
            self.created.pop_front();
        }
        if self.created.len() > STORM_LIMIT {
            self.rejected += 1;
            return TabDecision::Reject(RejectReason::Storm);
        }
        let pending = self.attached_len() >= self.max_tabs;
        self.tabs.insert(
            id.to_owned(),
            TabNode {
                opener: opener.map(str::to_owned),
                url: url.to_owned(),
                pending,
                download: false,
                closed: false,
                created: Some(now),
            },
        );
        if pending {
            TabDecision::Pending
        } else {
            TabDecision::Attach
        }
    }

    /// Number of admitted tabs, excluding targets awaiting worker policy.
    #[must_use]
    pub fn attached_len(&self) -> usize {
        self.tabs.values().filter(|t| !t.pending).count()
    }

    /// Admit a pending target after the worker has journaled and closed an eviction victim.
    pub fn admit(&mut self, id: &str) -> bool {
        if self.attached_len() >= self.max_tabs {
            return false;
        }
        self.tabs.get_mut(id).is_some_and(|t| {
            t.pending = false;
            true
        })
    }

    /// Whether a known target is waiting for an admission slot.
    #[must_use]
    pub fn pending(&self, id: &str) -> Option<bool> {
        self.tabs.get(id).map(|t| t.pending)
    }

    /// Record a download for its owning target, never another window with the same URL.
    pub fn record_download(&mut self, target: &str, url: &str) {
        if let Some(tab) = self.tabs.get_mut(target).filter(|tab| tab.opener.is_some()) {
            tab.download = true;
            url.clone_into(&mut tab.url);
        }
    }

    /// Retain a browser-closed download until its diagnostic close is journaled.
    pub fn record_closed_download(&mut self, id: &str) -> bool {
        self.tabs.get_mut(id).is_some_and(|tab| {
            if !tab.download {
                return false;
            }
            tab.closed = true;
            true
        })
    }

    /// The browser already closed this recorded download window.
    #[must_use]
    pub fn closed_download(&self, id: &str) -> bool {
        self.tabs.get(id).is_some_and(|tab| tab.download && tab.closed)
    }

    /// Earliest first-navigation deadline of a still-blank popup.
    #[must_use]
    pub fn blank_deadline(&self, now: Instant) -> Option<Instant> {
        self.tabs
            .values()
            .filter_map(|t| {
                let deadline = t.created? + FIRST_NAVIGATION_WAIT;
                ((t.url.is_empty() || t.url == "about:blank") && !t.download && now < deadline)
                    .then_some(deadline)
            })
            .min()
    }

    /// Is a storm in progress at `now`?
    #[must_use]
    pub fn storm_active(&self, now: Instant) -> bool {
        self.created
            .iter()
            .filter(|t| now.saturating_duration_since(**t) <= STORM_WINDOW)
            .count()
            > STORM_LIMIT
    }

    /// Update a tab's last known URL.
    pub fn set_url(&mut self, id: &str, url: &str) {
        if let Some(t) = self.tabs.get_mut(id) {
            if !t.download {
                url.clone_into(&mut t.url);
            }
        }
    }

    /// Remove a tab and reparent its descendants to its opener for later fallback.
    pub fn remove(&mut self, id: &str) -> Option<String> {
        let opener = self.tabs.remove(id).and_then(|t| t.opener);
        for tab in self.tabs.values_mut() {
            if tab.opener.as_deref() == Some(id) {
                tab.opener.clone_from(&opener);
            }
        }
        opener
    }

    /// Is `id` an open tab?
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.tabs.contains_key(id)
    }

    /// Number of open tabs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tabs.len()
    }

    /// No tab is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }

    /// Targets rejected so far (tab limit or storm).
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Opener of tab `id`; `None` for the home tab, unknown tabs and tabs with no known opener.
    #[must_use]
    pub fn opener_of(&self, id: &str) -> Option<&str> {
        self.tabs.get(id).and_then(|t| t.opener.as_deref())
    }

    /// Ids of all tabs.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.tabs.keys().cloned().collect()
    }

    /// `TabInfo` list in creation order, `active` marking the focused tab.
    #[must_use]
    pub fn infos(&self, active: &str) -> Vec<TabInfo> {
        let mut infos: Vec<_> = self
            .tabs
            .iter()
            .map(|(id, t)| TabInfo {
                id: TabId(id.clone()),
                url: t.url.clone(),
                opener: t.opener.clone().map(TabId),
                active: id == active,
                pending: t.pending,
                download: t.download,
            })
            .collect();
        infos.sort_by_key(|tab| self.tabs.get(&tab.id.0).and_then(|t| t.created));
        infos
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn excess_popups_wait_for_a_journaled_eviction() {
        let t0 = Instant::now();
        let mut g = TabGraph::new(3);
        g.add_home("home", "about:blank");
        assert_eq!(
            g.on_target_created("p1", Some("home"), "http://a/", t0),
            TabDecision::Attach
        );
        assert_eq!(
            g.on_target_created("p2", Some("home"), "http://b/", t0),
            TabDecision::Attach
        );
        assert_eq!(
            g.on_target_created("p3", Some("home"), "http://c/", t0),
            TabDecision::Pending
        );
        assert_eq!(g.attached_len(), 3);
        assert_eq!(g.len(), 4);
        assert_eq!(g.rejected(), 0);
        assert!(!g.admit("p3"));
        assert_eq!(g.remove("p1").as_deref(), Some("home"));
        assert!(g.admit("p3"));
        assert_eq!(g.attached_len(), 3);
        assert!(g.contains("home"));
    }

    #[test]
    fn blank_navigation_wait_is_anchored_and_bounded() {
        let now = Instant::now();
        let mut graph = TabGraph::new(3);
        graph.add_home("home", "http://h/");
        graph.on_target_created("blank", Some("home"), "about:blank", now);
        assert_eq!(graph.blank_deadline(now), Some(now + FIRST_NAVIGATION_WAIT));
        assert_eq!(
            graph.blank_deadline(now + Duration::from_millis(1999)),
            Some(now + FIRST_NAVIGATION_WAIT)
        );
        assert_eq!(graph.blank_deadline(now + FIRST_NAVIGATION_WAIT), None);
        graph.set_url("blank", "http://h/next");
        assert_eq!(graph.blank_deadline(now + Duration::from_millis(500)), None);
    }

    #[test]
    fn download_records_url_without_waiting_for_blank_navigation() {
        let now = Instant::now();
        let mut graph = TabGraph::new(3);
        graph.add_home("home", "http://h/");
        graph.on_target_created("download", Some("home"), "about:blank", now);
        graph.record_download("download", "http://h/report.csv");
        assert_eq!(graph.blank_deadline(now), None);
        let tabs = graph.infos("home");
        let download = tabs.iter().find(|t| t.id.0 == "download").unwrap();
        assert!(download.download);
        assert_eq!(download.url, "http://h/report.csv");
    }

    #[test]
    fn eviction_reparents_descendants_and_downloads_are_target_scoped() {
        let now = Instant::now();
        let mut graph = TabGraph::new(3);
        graph.add_home("home", "http://h/");
        graph.on_target_created("parent", Some("home"), "http://h/file", now);
        graph.on_target_created("child", Some("parent"), "http://h/file", now);
        graph.record_download("foreign", "http://h/file");
        assert!(graph.infos("home").iter().all(|t| !t.download));
        graph.remove("parent");
        assert_eq!(graph.opener_of("child"), Some("home"));
    }

    #[test]
    fn storm_is_detected_within_window_and_expires() {
        let t0 = Instant::now();
        let mut g = TabGraph::new(8);
        g.add_home("home", "about:blank");
        for i in 0..STORM_LIMIT {
            assert_eq!(
                g.on_target_created(&format!("t{i}"), Some("home"), "http://a/", t0),
                TabDecision::Attach
            );
        }
        assert_eq!(
            g.on_target_created("storm", Some("home"), "http://a/", t0),
            TabDecision::Reject(RejectReason::Storm)
        );
        assert!(g.storm_active(t0));
        let later = t0 + STORM_WINDOW + Duration::from_millis(1);
        assert!(!g.storm_active(later));
    }

    #[test]
    fn infos_mark_active_and_opener() {
        let mut g = TabGraph::new(3);
        g.add_home("home", "http://h/");
        g.on_target_created("p", Some("home"), "http://p/", Instant::now());
        g.set_url("p", "http://p2/");
        let infos = g.infos("p");
        assert_eq!(infos.len(), 2);
        let p = infos.iter().find(|i| i.id.0 == "p").unwrap();
        assert!(p.active);
        assert_eq!(p.url, "http://p2/");
        assert_eq!(p.opener, Some(TabId("home".to_owned())));
        assert_eq!(g.opener_of("p"), Some("home"));
    }
}
