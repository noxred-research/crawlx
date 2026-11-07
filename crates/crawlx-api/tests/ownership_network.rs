#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The network side of the ownership challenge (`NetworkProbe`): TXT lookups through a real
//! resolver against an in-process DNS server, and the well-known file fetch under the public-only
//! egress policy. No test reaches the internet.

use crawlx_api::ownership::{verify_ownership, NetworkProbe, OwnershipOutcome, OwnershipProbe, ProbeError};
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_fetch::HickoryResolver;
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::authorization::OwnershipProof;
use crawlx_policy::testkit::sample_record;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

/// What the in-process DNS server answers for one name.
#[derive(Clone)]
enum Answer {
    /// TXT records; each record is a list of character-strings.
    Txt(Vec<Vec<Vec<u8>>>),
    /// An A record.
    A(Ipv4Addr),
    /// SERVFAIL.
    ServFail,
}

/// A DNS server on a loopback UDP port. Names not in `table` answer NXDOMAIN.
async fn dns_server(table: BTreeMap<String, Answer>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if let Some(reply) = respond(&table, &buf[..n]) {
                let _ = socket.send_to(&reply, peer).await;
            }
        }
    });
    addr
}

fn respond(table: &BTreeMap<String, Answer>, query: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 12;
    let mut labels = Vec::new();
    while *query.get(pos)? != 0 {
        let len = usize::from(query[pos]);
        labels.push(String::from_utf8_lossy(query.get(pos + 1..pos + 1 + len)?).to_ascii_lowercase());
        pos += len + 1;
    }
    let question_end = pos + 5;
    let qtype = u16::from_be_bytes([*query.get(pos + 1)?, *query.get(pos + 2)?]);
    let name = labels.join(".");
    let (rcode, records): (u8, Vec<Vec<u8>>) = match table.get(&name) {
        None => (3, Vec::new()),
        Some(Answer::ServFail) => (2, Vec::new()),
        Some(Answer::Txt(set)) if qtype == 16 => (
            0,
            set.iter()
                .map(|strings| {
                    strings
                        .iter()
                        .flat_map(|s| [vec![u8::try_from(s.len()).unwrap()], s.clone()].concat())
                        .collect()
                })
                .collect(),
        ),
        Some(Answer::A(ip)) if qtype == 1 => (0, vec![ip.octets().to_vec()]),
        Some(_) => (0, Vec::new()),
    };
    let rtype: u16 = if qtype == 16 { 16 } else { 1 };
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x81, 0x80 | rcode]);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(query.get(12..question_end)?);
    for rdata in records {
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

fn probe_for(server: SocketAddr) -> NetworkProbe {
    NetworkProbe::with_resolver(HickoryResolver::from_servers(&[server]).unwrap()).unwrap()
}

#[tokio::test]
async fn txt_lookups_join_character_strings_and_nxdomain_is_no_record_not_an_error() {
    let mut table = BTreeMap::new();
    table.insert(
        "_crawlx-authz.a.example.test".to_owned(),
        Answer::Txt(vec![
            vec![b"unrelated".to_vec()],
            // one record split into two character-strings, as long TXT values are
            vec![b"0198a0e2-7c1d-7a41-".to_vec(), b"8f3e-5b1c9d2e4f60".to_vec()],
        ]),
    );
    table.insert("_crawlx-authz.broken.example.test".to_owned(), Answer::ServFail);
    let probe = probe_for(dns_server(table).await);

    assert_eq!(
        probe.txt("_crawlx-authz.a.example.test").await.unwrap(),
        ["unrelated", "0198a0e2-7c1d-7a41-8f3e-5b1c9d2e4f60"]
    );
    assert_eq!(
        probe.txt("_crawlx-authz.nothing.example.test").await.unwrap(),
        Vec::<String>::new(),
        "NXDOMAIN: the name publishes nothing"
    );
    let failed = probe.txt("_crawlx-authz.broken.example.test").await;
    assert!(
        matches!(failed, Err(ProbeError::Lookup { .. })),
        "SERVFAIL is a failed lookup, not an absent record: {failed:?}"
    );
}

#[tokio::test]
async fn a_dns_proof_verifies_against_a_real_resolver() {
    let now = SystemClock.now();
    let mut record = sample_record(
        TenantId::new(),
        now,
        &["https://a.example.test", "https://b.example.test"],
    );
    record.ownership = Some(OwnershipProof::DnsTxt {});
    let id = record.id.to_string();
    let (head, tail) = id.split_at(18);

    let mut table = BTreeMap::new();
    table.insert(
        "_crawlx-authz.a.example.test".to_owned(),
        Answer::Txt(vec![vec![head.as_bytes().to_vec(), tail.as_bytes().to_vec()]]),
    );
    let probe = probe_for(dns_server(table.clone()).await);
    let OwnershipOutcome::Unverified { failures } =
        verify_ownership(&record, &OperatorKeys::new(), &probe, now).await
    else {
        panic!("b.example.test publishes nothing");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].subject, "b.example.test");

    table.insert(
        "_crawlx-authz.b.example.test".to_owned(),
        Answer::Txt(vec![vec![format!("  {id}  ").into_bytes()]]),
    );
    let probe = probe_for(dns_server(table).await);
    let outcome = verify_ownership(&record, &OperatorKeys::new(), &probe, now).await;
    assert!(
        matches!(outcome, OwnershipOutcome::Verified { .. }),
        "{outcome:?}"
    );
}

/// A loopback TCP listener that counts the connections it receives.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn the_well_known_probe_never_connects_to_private_loopback_or_metadata_addresses() {
    let (port, accepted) = counting_listener().await;
    let mut table = BTreeMap::new();
    table.insert("evil.example.test".to_owned(), Answer::A(Ipv4Addr::LOCALHOST));
    let probe = probe_for(dns_server(table).await);

    for origin in [
        // a loopback literal that really is listening
        format!("http://127.0.0.1:{port}"),
        // a public-looking name that resolves to loopback
        format!("http://evil.example.test:{port}"),
        "http://evil.example.test".to_owned(),
        "http://169.254.169.254".to_owned(),
        "http://10.0.0.5".to_owned(),
        "http://[::1]".to_owned(),
        format!("http://localhost:{port}"),
    ] {
        let result = probe.well_known(&origin).await;
        assert!(
            matches!(result, Err(ProbeError::Fetch { .. })),
            "{origin} must be refused, got {result:?}"
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no connection reached the listener"
    );
}

#[tokio::test]
async fn the_well_known_probe_refuses_other_schemes_and_malformed_origins() {
    let probe = probe_for("127.0.0.1:9".parse().unwrap());
    for origin in ["ftp://example.test", "file:///etc/passwd", "not a url", ""] {
        let result = probe.well_known(origin).await;
        assert!(
            matches!(result, Err(ProbeError::Fetch { .. })),
            "{origin:?}: {result:?}"
        );
    }
}
