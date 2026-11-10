//! `crawlx crawl --health-check` (compatibility `-health-check`): what would stop a crawl from
//! working on this machine, as a table.
//!
//! Checks: the crawlx build, the request the flags produce (admission), the browser
//! (`crawlx_browser::health::probe`), every custom resolver (a real DNS query over UDP) and
//! the path to every seed (system DNS + a TCP connect). Nothing leaves the machine except
//! the queries to resolvers and seeds the user named.

use crate::style::Style;
use crawlx_core::CreateCrawl;
use crawlx_worker::WorkerConfig;
use std::io::Write;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::time::timeout;
use url::Url;

/// How long one network check may take.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Seeds probed at most, so a long list does not stall the report.
const MAX_SEEDS: usize = 10;

/// One line of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    /// What was checked.
    pub name: String,
    /// Whether it works.
    pub ok: bool,
    /// What was found.
    pub detail: String,
}

impl Row {
    fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            detail: detail.into(),
        }
    }

    fn failed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            detail: detail.into(),
        }
    }

    fn from_result(name: impl Into<String>, result: Result<String, String>) -> Self {
        match result {
            Ok(detail) => Self::ok(name, detail),
            Err(detail) => Self::failed(name, detail),
        }
    }
}

/// What the checks look at.
pub(crate) struct Subject<'a> {
    /// The worker configuration the crawl would run with (launch options applied).
    pub cfg: &'a WorkerConfig,
    /// The request the flags build, `None` without a seed.
    pub crawl: Option<&'a CreateCrawl>,
    /// The seeds.
    pub seeds: &'a [Url],
    /// Admission of the request: `Ok` or the reasons it is refused.
    pub admission: Result<(), String>,
    /// A launch flag that was refused, if any.
    pub launch_error: Option<String>,
    /// Whether the browser plane is needed (anything but `--mode static`).
    pub needs_browser: bool,
}

/// Run every check.
pub(crate) async fn checks(subject: &Subject<'_>) -> Vec<Row> {
    let mut rows = vec![Row::ok(
        "version",
        format!(
            "crawlx {} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    )];
    rows.push(Row::from_result(
        "request",
        subject.admission.clone().map(|()| {
            if subject.crawl.is_some() {
                "admitted".to_owned()
            } else {
                "no seed given: not checked".to_owned()
            }
        }),
    ));
    if let Some(e) = &subject.launch_error {
        rows.push(Row::failed("launch options", e.clone()));
    }
    if subject.needs_browser {
        let report = crawlx_browser::health::probe(&subject.cfg.launch).await;
        rows.extend(report.checks.into_iter().map(|c| Row {
            name: format!("browser {}", c.name),
            ok: c.ok,
            detail: c.detail,
        }));
    }
    if let Some(crawl) = subject.crawl {
        rows.push(match subject.cfg.egress.resolver_for(crawl) {
            Ok(_) if crawl.fetch.resolvers.is_empty() => Row::ok("resolver", "system resolver"),
            Ok(_) => Row::ok(
                "resolver",
                format!("{} custom server(s) configured", crawl.fetch.resolvers.len()),
            ),
            Err(e) => Row::failed("resolver", e.to_string()),
        });
        let probe_name = subject
            .seeds
            .first()
            .and_then(|u| u.host_str())
            .unwrap_or("localhost")
            .to_owned();
        for server in &crawl.fetch.resolvers {
            let result = match parse_server(server) {
                Ok(addr) => dns_probe(addr, &probe_name).await,
                Err(e) => Err(e),
            };
            rows.push(Row::from_result(format!("dns {server}"), result));
        }
    }
    for seed in subject.seeds.iter().take(MAX_SEEDS) {
        rows.push(Row::from_result(
            format!("network {}", target(seed)),
            reach(seed).await,
        ));
    }
    rows
}

fn target(url: &Url) -> String {
    match (url.host_str(), url.port_or_known_default()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        _ => url.as_str().to_owned(),
    }
}

/// System DNS and a TCP connect to the seed's host and port.
async fn reach(url: &Url) -> Result<String, String> {
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return Err("the URL has no host or port".to_owned());
    };
    let started = Instant::now();
    let mut addrs = timeout(CHECK_TIMEOUT, lookup_host((host.to_owned(), port)))
        .await
        .map_err(|_| format!("resolving {host} timed out after {CHECK_TIMEOUT:?}"))?
        .map_err(|e| format!("resolving {host}: {e}"))?;
    let addr = addrs.next().ok_or_else(|| format!("{host} has no address"))?;
    timeout(CHECK_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connecting to {addr} timed out after {CHECK_TIMEOUT:?}"))?
        .map_err(|e| format!("connecting to {addr}: {e}"))?;
    Ok(format!(
        "connected to {addr} in {}ms",
        started.elapsed().as_millis()
    ))
}

/// `ip` (port 53) or `ip:port`.
fn parse_server(entry: &str) -> Result<SocketAddr, String> {
    let entry = entry.trim();
    entry
        .parse::<SocketAddr>()
        .or_else(|_| {
            entry
                .parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .map_err(|_| format!("{entry:?} is not an IP address or ip:port"))
}

/// A DNS `A` query for `name` over UDP; any well-formed answer to it counts as alive.
async fn dns_probe(server: SocketAddr, name: &str) -> Result<String, String> {
    const ID: u16 = 0x6358;
    let mut query = Vec::with_capacity(32);
    query.extend_from_slice(&ID.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len()).map_err(|_| format!("label {label:?} is too long"))?;
        if len == 0 || len > 63 {
            return Err(format!("{name:?} is not a DNS name"));
        }
        query.push(len);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let bind: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("binding a UDP socket: {e}"))?;
    let started = Instant::now();
    socket
        .send_to(&query, server)
        .await
        .map_err(|e| format!("sending to {server}: {e}"))?;
    let mut answer = [0u8; 512];
    let (len, from) = timeout(CHECK_TIMEOUT, socket.recv_from(&mut answer))
        .await
        .map_err(|_| format!("{server} did not answer within {CHECK_TIMEOUT:?}"))?
        .map_err(|e| format!("reading from {server}: {e}"))?;
    let well_formed = len >= 12 && answer[..2] == ID.to_be_bytes() && answer[2] & 0x80 != 0;
    if from.ip() != server.ip() || !well_formed {
        return Err(format!("{server} answered something that is not a DNS response"));
    }
    Ok(format!(
        "{server} answered {name} in {}ms",
        started.elapsed().as_millis()
    ))
}

/// Print `rows` as a table; `true` when every check passed.
///
/// # Errors
/// Writing to `out` failed.
pub(crate) fn print(rows: &[Row], out: &mut dyn Write, style: Style) -> std::io::Result<bool> {
    let width = rows.iter().map(|r| r.name.len()).max().unwrap_or(5).max(5);
    writeln!(out, "{:<width$}  status  detail", "check")?;
    for row in rows {
        let status = if row.ok {
            style.good("ok  ")
        } else {
            style.bad("FAIL")
        };
        writeln!(out, "{:<width$}  {status}    {}", row.name, row.detail)?;
    }
    let failed = rows.iter().filter(|r| !r.ok).count();
    if failed == 0 {
        writeln!(out, "health check passed ({} checks)", rows.len())?;
    } else {
        writeln!(out, "health check failed: {failed} of {} checks", rows.len())?;
    }
    Ok(failed == 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn a_dns_server_that_answers_passes_and_a_silent_one_fails() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            server.send_to(&reply, peer).await.unwrap();
        });
        let ok = dns_probe(addr, "example.test").await.unwrap();
        assert!(ok.contains("answered example.test"), "{ok}");
        assert!(dns_probe(addr, "bad..name").await.is_err());
        assert_eq!(parse_server("127.0.0.1").unwrap().port(), 53);
        assert!(parse_server("not-an-ip").is_err());
    }

    #[tokio::test]
    async fn reachability_names_the_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        assert!(reach(&up).await.unwrap().contains("connected to 127.0.0.1"));
        drop(listener);
        let down = reach(&up).await.unwrap_err();
        assert!(down.contains("connecting to 127.0.0.1"), "{down}");
    }

    #[test]
    fn the_table_marks_failures_and_counts_them() {
        let rows = vec![Row::ok("a", "fine"), Row::failed("longer-name", "broken")];
        let mut out = Vec::new();
        let style = Style::detect(true, &|_| None);
        assert!(!print(&rows, &mut out, style).unwrap());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("a            ok      fine"), "{text}");
        assert!(text.contains("longer-name  FAIL    broken"), "{text}");
        assert!(text.contains("health check failed: 1 of 2 checks"), "{text}");
    }
}
