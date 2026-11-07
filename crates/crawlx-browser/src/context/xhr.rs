//! XHR and `fetch()` requests of a tab (`extract.xhr`, katana `-xhr-extraction`).
//!
//! The CDP event handler feeds the three request lifecycle events of requests whose resource
//! type is `XHR` or `Fetch` into an [`XhrTracker`]; finished requests wait there until
//! [`BrowserContext::drain_xhr`](crawlx_core::BrowserContext::drain_xhr) takes them. Each record
//! names the page (main document URL) that issued the request, so the worker can attach it to the
//! right page however many pages the session visited between two drains.

use crawlx_core::dom_ops::XhrRecord;
use std::collections::BTreeMap;

/// Finished records kept per tab; the oldest are dropped beyond this bound.
pub(crate) const MAX_FINISHED: usize = 2_000;

/// Lifecycle tracking of one tab's XHR/fetch requests.
#[derive(Debug, Default)]
pub(crate) struct XhrTracker {
    /// Requests that started and have not finished yet, by CDP request id.
    started: BTreeMap<String, XhrRecord>,
    finished: Vec<XhrRecord>,
}

/// `xhr` or `fetch` for a CDP resource type; `None` for every other type.
fn kind_of(resource_type: &str) -> Option<&'static str> {
    match resource_type {
        "XHR" => Some("xhr"),
        "Fetch" => Some("fetch"),
        _ => None,
    }
}

impl XhrTracker {
    /// `Network.requestWillBeSent`. `url` is the already redacted request URL, `page_url` the
    /// main document of the tab. Requests of other resource types are ignored.
    pub(crate) fn request_started(
        &mut self,
        request_id: &str,
        resource_type: &str,
        method: &str,
        url: &str,
        page_url: &str,
    ) {
        let Some(kind) = kind_of(resource_type) else {
            return;
        };
        self.started.insert(
            request_id.to_owned(),
            XhrRecord {
                page_url: page_url.to_owned(),
                method: method.to_ascii_uppercase(),
                url: url.to_owned(),
                status: None,
                resource_type: kind.to_owned(),
                content_type: None,
            },
        );
    }

    /// `Network.responseReceived` (or the `redirectResponse` of a redirected hop). A request
    /// with a response is complete for the listing: Chromium reports `loadingFinished` of a
    /// `fetch()` only once the page consumed the body, which many pages never do.
    pub(crate) fn response_received(
        &mut self,
        request_id: &str,
        status: Option<u16>,
        content_type: Option<&str>,
    ) {
        let Some(mut done) = self.started.remove(request_id) else {
            return;
        };
        done.status = status;
        done.content_type = content_type.filter(|c| !c.is_empty()).map(str::to_owned);
        self.push_finished(done);
    }

    /// `Network.loadingFinished` / `Network.loadingFailed` of a request that never got a
    /// response (failed, blocked, aborted): it is listed without a status.
    pub(crate) fn request_finished(&mut self, request_id: &str) {
        if let Some(done) = self.started.remove(request_id) {
            self.push_finished(done);
        }
    }

    fn push_finished(&mut self, record: XhrRecord) {
        self.finished.push(record);
        if self.finished.len() > MAX_FINISHED {
            let excess = self.finished.len() - MAX_FINISHED;
            self.finished.drain(..excess);
        }
    }

    /// Take the finished records, oldest first.
    pub(crate) fn take(&mut self) -> Vec<XhrRecord> {
        std::mem::take(&mut self.finished)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn only_xhr_and_fetch_finish_into_records_with_their_response_facts() {
        let mut t = XhrTracker::default();
        t.request_started("1", "XHR", "post", "http://a.test/api/save", "http://a.test/");
        t.request_started("2", "Fetch", "GET", "http://a.test/api/list", "http://a.test/");
        t.request_started("3", "Script", "GET", "http://a.test/app.js", "http://a.test/");
        t.request_started("4", "Document", "GET", "http://a.test/", "http://a.test/");
        t.response_received("1", Some(201), Some("application/json"));
        t.request_finished("1");
        t.request_finished("3");
        t.request_finished("4");
        assert_eq!(t.take().len(), 1, "request 2 is still in flight");
        t.request_finished("2");
        let rest = t.take();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].resource_type, "fetch");
        assert_eq!(rest[0].status, None, "no response arrived");
        assert!(t.take().is_empty(), "take drains");
    }

    #[test]
    fn records_carry_page_method_status_and_content_type() {
        let mut t = XhrTracker::default();
        t.request_started("1", "XHR", "post", "http://a.test/api/save", "http://a.test/page");
        t.response_received("1", Some(201), Some("application/json"));
        t.request_finished("1");
        assert_eq!(
            t.take(),
            [XhrRecord {
                page_url: "http://a.test/page".to_owned(),
                method: "POST".to_owned(),
                url: "http://a.test/api/save".to_owned(),
                status: Some(201),
                resource_type: "xhr".to_owned(),
                content_type: Some("application/json".to_owned()),
            }]
        );
    }

    #[test]
    fn finished_records_are_bounded() {
        let mut t = XhrTracker::default();
        for i in 0..MAX_FINISHED + 10 {
            let id = i.to_string();
            t.request_started(&id, "XHR", "GET", &format!("http://a.test/{i}"), "http://a.test/");
            t.request_finished(&id);
        }
        let kept = t.take();
        assert_eq!(kept.len(), MAX_FINISHED);
        assert_eq!(kept[0].url, "http://a.test/10", "the oldest were dropped");
    }
}
