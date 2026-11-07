//! `crawlx healthcheck`: the probe behind the `healthcheck:` entries of `docker/docker-compose.yml`.
//!
//! The API image is distroless (no shell, no `curl`), so the container's own health probe has to
//! be a subcommand of the one binary it ships. The command issues one `GET`, follows no redirect,
//! ignores proxy environment variables and exits `0` for a `2xx` answer and `1` for anything else
//! (Docker reads exit code `1` as "unhealthy"). It never initialises logging and never prints the
//! query string or credentials of the URL.

use crate::duration::parse_duration;
use anyhow::Context as _;
use clap::Args;
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

/// Arguments of `crawlx healthcheck`.
#[derive(Args, Debug)]
pub struct HealthcheckArgs {
    /// `http`/`https` URL to `GET`; a `2xx` answer is healthy. `http://127.0.0.1:8080/v0/health/readiness`
    /// probes the API (storage answers), `http://127.0.0.1:9464/metrics` a worker's metrics listener.
    #[arg(long, value_name = "URL", value_parser = parse_probe_url)]
    pub url: url::Url,
    /// Give up after this long (`3s`, `500ms`, bare seconds).
    #[arg(long, default_value = "3s", value_parser = parse_duration, value_name = "DURATION")]
    pub timeout: Duration,
}

fn parse_probe_url(text: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(text).map_err(|e| format!("{e}"))?;
    match url.scheme() {
        "http" | "https" if url.host_str().is_some() => Ok(url),
        _ => Err("expected an absolute http(s) URL with a host".to_owned()),
    }
}

/// The URL as printed: no credentials, no query, no fragment.
fn shown(url: &url::Url) -> String {
    let mut plain = url.clone();
    let _ = plain.set_username("");
    let _ = plain.set_password(None);
    plain.set_query(None);
    plain.set_fragment(None);
    plain.to_string()
}

pub(crate) async fn run(args: HealthcheckArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let client = reqwest::Client::builder()
        .timeout(args.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("building the HTTP client")?;
    let target = shown(&args.url);
    match client.get(args.url).send().await {
        Ok(response) if response.status().is_success() => {
            writeln!(out, "healthy: {} {target}", response.status())?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(response) => {
            writeln!(out, "unhealthy: {} {target}", response.status())?;
            Ok(ExitCode::FAILURE)
        }
        Err(e) if e.is_timeout() => {
            writeln!(
                out,
                "unhealthy: no answer from {target} within {:?}",
                args.timeout
            )?;
            Ok(ExitCode::FAILURE)
        }
        Err(e) if e.is_connect() => {
            writeln!(out, "unhealthy: cannot connect to {target}")?;
            Ok(ExitCode::FAILURE)
        }
        Err(e) => {
            // `without_url`: the error text must not echo the query string
            writeln!(out, "unhealthy: {target}: {}", e.without_url())?;
            Ok(ExitCode::FAILURE)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// A loopback server that answers every request with `status_line` (or never answers when
    /// `None`), and the base URL it listens on.
    async fn server(status_line: Option<&'static str>) -> url::Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    match status_line {
                        Some(line) => {
                            let reply =
                                format!("HTTP/1.1 {line}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                            let _ = stream.write_all(reply.as_bytes()).await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        url::Url::parse(&format!("http://{addr}/v0/health/readiness?token=secret")).unwrap()
    }

    async fn probe(url: url::Url, timeout: Duration) -> (ExitCode, String) {
        let mut out = Vec::new();
        let code = run(HealthcheckArgs { url, timeout }, &mut out).await.unwrap();
        (code, String::from_utf8(out).unwrap())
    }

    #[tokio::test]
    async fn a_2xx_answer_is_healthy() {
        let (code, text) = probe(server(Some("200 OK")).await, Duration::from_secs(2)).await;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(text.starts_with("healthy: 200 OK http://127.0.0.1:"), "{text}");
        assert!(
            !text.contains("secret"),
            "the query string must not be printed: {text}"
        );
    }

    #[tokio::test]
    async fn a_5xx_answer_is_unhealthy() {
        let (code, text) = probe(
            server(Some("503 Service Unavailable")).await,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(text.starts_with("unhealthy: 503 Service Unavailable"), "{text}");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_and_is_unhealthy() {
        let (code, text) = probe(server(Some("302 Found")).await, Duration::from_secs(2)).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(text.starts_with("unhealthy: 302 Found"), "{text}");
    }

    #[tokio::test]
    async fn a_closed_port_is_unhealthy() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let (code, text) = probe(url, Duration::from_secs(2)).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(
            text.starts_with("unhealthy: cannot connect to http://127.0.0.1:"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let (code, text) = probe(server(None).await, Duration::from_millis(200)).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(text.contains("no answer from http://127.0.0.1:"), "{text}");
    }

    #[test]
    fn only_http_urls_with_a_host_are_accepted() {
        assert!(parse_probe_url("http://127.0.0.1:8080/v0/health/readiness").is_ok());
        assert!(parse_probe_url("https://example.test/").is_ok());
        assert!(parse_probe_url("file:///etc/passwd").is_err());
        assert!(parse_probe_url("not a url").is_err());
    }
}
