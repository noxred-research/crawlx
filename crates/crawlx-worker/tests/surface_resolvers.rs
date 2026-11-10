//! The `-resolvers` compatibility flag (`fetch.resolvers`): the fetch plane resolves hosts with the servers the
//! request lists, and the egress policy still judges what they answer. The DNS server is an
//! in-process UDP stub.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_common;

use axum::routing::get;
use axum::Router;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use surface_common::{crawl_with, page, Site};

/// A UDP DNS server answering `A` queries from a table and everything else with no data.
struct DnsStub {
    addr: SocketAddr,
    queries: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DnsStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `(name, qtype, end offset of the question)` of a DNS query packet.
fn parse_question(packet: &[u8]) -> Option<(String, u16, usize)> {
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*packet.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(packet.get(at..at + len)?).to_ascii_lowercase());
        at += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    Some((labels.join("."), qtype, at + 4))
}

impl DnsStub {
    async fn start(table: &[(&str, Ipv4Addr)]) -> Self {
        let table: BTreeMap<String, Ipv4Addr> = table.iter().map(|(n, ip)| ((*n).to_owned(), *ip)).collect();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let packet = &buf[..n];
                let Some((name, qtype, end)) = parse_question(packet) else {
                    continue;
                };
                seen.lock().unwrap().push(format!("{name}/{qtype}"));
                let answer = table.get(&name).filter(|_| qtype == 1);
                let rcode = if table.contains_key(&name) { 0x00 } else { 0x03 };
                let mut reply = Vec::with_capacity(end + 16);
                reply.extend_from_slice(&packet[..2]); // id
                reply.extend_from_slice(&[0x81, 0x80 | rcode]); // response, recursion available
                reply.extend_from_slice(&[0, 1, 0, u8::from(answer.is_some()), 0, 0, 0, 0]);
                reply.extend_from_slice(&packet[12..end]);
                if let Some(ip) = answer {
                    reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    reply.extend_from_slice(&ip.octets());
                }
                let _ = socket.send_to(&reply, from).await;
            }
        });
        Self { addr, queries, task }
    }

    fn asked(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

async fn site() -> Site {
    Site::start(|_| Router::new().route("/", get(|| async { page("Home", "") }))).await
}

#[tokio::test]
async fn the_listed_resolver_resolves_the_crawled_host() {
    let site = site().await;
    let dns = DnsStub::start(&[("crawl-target.test", Ipv4Addr::LOCALHOST)]).await;
    let base = format!("http://crawl-target.test:{}", site.addr.port());
    let resolvers = vec![dns.addr.to_string()];
    let run = crawl_with(
        &base,
        move |c| c.fetch.resolvers = resolvers,
        |cfg| cfg.egress.resolver = None,
        |run| run,
    )
    .await;
    assert_eq!(
        site.gets(),
        ["/"],
        "the stub's answer led the fetcher to the site"
    );
    assert_eq!(run.report.pages.len(), 1);
    assert!(run.report.failures.is_empty(), "{:?}", run.report.failures);
    let asked = dns.asked();
    assert!(
        asked.iter().any(|q| q == "crawl-target.test/1"),
        "the A query went to the configured server: {asked:?}"
    );
}

#[tokio::test]
async fn a_malformed_resolver_entry_is_a_configuration_error() {
    let site = site().await;
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = surface_common::static_crawl(&site.base);
    crawl.fetch.resolvers = vec!["not-an-ip".to_owned()];
    let mut cfg = surface_common::config(dir.path());
    cfg.egress.resolver = None;
    let err = crawlx_worker::run_local(crawl, cfg).await.unwrap_err();
    assert!(err.to_string().contains("fetch.resolvers"), "{err}");
    assert!(site.gets().is_empty());
}

#[tokio::test]
async fn the_egress_policy_still_judges_what_the_resolver_answers() {
    let site = site().await;
    // the stub points the name at an address the operator denies
    let dns = DnsStub::start(&[("denied-target.test", Ipv4Addr::new(127, 0, 0, 2))]).await;
    let base = format!("http://denied-target.test:{}", site.addr.port());
    let resolvers = vec![dns.addr.to_string()];
    let run = crawl_with(
        &base,
        move |c| {
            c.fetch.resolvers = resolvers;
            c.safety.respect_robots_txt = false; // the robots fetch would be refused first
        },
        |cfg| {
            cfg.egress.resolver = None;
            cfg.egress.extra_deny = vec!["127.0.0.2/32".parse().unwrap()];
        },
        |run| run,
    )
    .await;
    assert!(dns.asked().iter().any(|q| q == "denied-target.test/1"));
    assert!(
        site.gets().is_empty(),
        "nothing was fetched: {:?}",
        site.requests()
    );
    assert!(run.report.pages.is_empty());
    assert_eq!(run.report.failures.len(), 1);
    assert_eq!(run.report.failures[0].reason, "egress_denied");
    assert_eq!(
        run.report.failures[0].status, None,
        "a refused fetch has no HTTP status"
    );
}
