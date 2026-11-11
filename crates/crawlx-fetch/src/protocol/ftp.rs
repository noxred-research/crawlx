//! Explicitly approved anonymous FTP file reads. No active mode, recursion, or credential forwarding.

use super::{ProtocolError, ProtocolResource};
use crate::{governor::Origin, OriginGovernor, Resolver};
use bytes::Bytes;
use crawlx_policy::egress::EgressPolicy;
use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Operator-only authority for anonymous, nonrecursive file acquisition.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FtpRegistry {
    /// Exact canonical FTP origins; paths never grant authority to another origin.
    pub origins: BTreeSet<String>,
    /// Explicit approved run-policy revisions.
    pub policy_digests: BTreeSet<String>,
}

impl FtpRegistry {
    /// Validate the bounded operator registration without opening sockets.
    ///
    /// # Errors
    /// Refuses empty, oversized, noncanonical or non-FTP origin registrations.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.origins.is_empty()
            || self.origins.len() > 64
            || self.policy_digests.is_empty()
            || self.policy_digests.len() > 64
            || self
                .policy_digests
                .iter()
                .any(|id| id.is_empty() || id.len() > 128)
            || self.origins.iter().any(|origin| {
                origin.len() > 512
                    || Url::parse(origin).ok().is_none_or(|url| {
                        url.scheme() != "ftp"
                            || !url.username().is_empty()
                            || url.password().is_some()
                            || crawlx_core::protocol::protocol_origin(&url).as_ref() != Some(origin)
                    })
            })
        {
            return Err(ProtocolError::Refused("FTP registry bounds or origin"));
        }
        Ok(())
    }

    /// Admit an exact approved file target and policy before DNS or connection work.
    ///
    /// # Errors
    /// Refuses URL credentials, command injection, directories, traversal and unknown authority.
    pub fn admit(&self, url: &Url, policy_digest: &str) -> Result<(), ProtocolError> {
        self.admitted_path(url, policy_digest).map(|_| ())
    }

    fn admitted_path<'a>(
        &self,
        url: &'a Url,
        policy_digest: &str,
    ) -> Result<std::borrow::Cow<'a, str>, ProtocolError> {
        let origin = crawlx_core::protocol::protocol_origin(url);
        if url.scheme() != "ftp"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !origin
                .as_ref()
                .is_some_and(|origin| self.origins.contains(origin))
            || !self.policy_digests.contains(policy_digest)
        {
            return Err(ProtocolError::CapabilityUnavailable(
                "approved anonymous FTP origin and policy",
            ));
        }
        let path = percent_encoding::percent_decode_str(url.path())
            .decode_utf8()
            .map_err(|_| ProtocolError::Refused("FTP path encoding"))?;
        if path.len() > 4096
            || path.ends_with('/')
            || path.bytes().any(|byte| byte.is_ascii_control() || byte == b'\\')
            || path.split('/').any(|part| matches!(part, "." | ".."))
            || path.contains(';')
        {
            return Err(ProtocolError::Refused("FTP file path"));
        }
        Ok(path)
    }

    /// Read one complete binary-mode file with separately checked control and passive data sockets.
    ///
    /// Cancellation drops both owned sockets and the origin permit. Failed or partial transfers
    /// return errors, never a complete resource. No filesystem spool or helper task is created.
    ///
    /// # Errors
    /// Refuses missing authority, passive bounce, disallowed peers/ports, malformed replies,
    /// incomplete transfer, byte/deadline exhaustion and cancellation.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire(
        &self,
        url: &Url,
        policy_digest: &str,
        max_bytes: u32,
        deadline: Duration,
        cancel: &CancellationToken,
        policy: &EgressPolicy,
        resolver: &dyn Resolver,
        governor: &Arc<OriginGovernor>,
    ) -> Result<ProtocolResource, ProtocolError> {
        // Decode once: the authorized effective path is exactly the path sent to RETR.
        let path = self.admitted_path(url, policy_digest)?;
        if max_bytes == 0
            || max_bytes > 67_108_864
            || deadline.is_zero()
            || deadline > Duration::from_secs(90)
        {
            return Err(ProtocolError::Limit);
        }
        let operation = async {
            if let Some(scope) = &policy.record_scope {
                scope
                    .check_request(url)
                    .map_err(|_| ProtocolError::Refused("FTP authorization"))?;
                if path.as_ref() != url.path() {
                    let mut effective = url.clone();
                    effective.set_path(&path);
                    // Check both forms so decoding cannot weaken an existing URL exclusion.
                    scope
                        .check_request(&effective)
                        .map_err(|_| ProtocolError::Refused("FTP authorization"))?;
                }
            }
            let host = url.host_str().ok_or(ProtocolError::Refused("FTP host"))?;
            let port = url
                .port_or_known_default()
                .ok_or(ProtocolError::Refused("FTP port"))?;
            policy
                .check_host(host)
                .and_then(|()| policy.check_port(port))
                .map_err(|_| ProtocolError::Refused("FTP control policy"))?;
            let addresses = resolver.resolve(host).await?;
            policy
                .check_all(host, &addresses)
                .map_err(|_| ProtocolError::Refused("FTP DNS policy"))?;
            let ip = addresses.first().ok_or(ProtocolError::Refused("FTP empty DNS"))?;
            let origin =
                crawlx_core::protocol::protocol_origin(url).ok_or(ProtocolError::Refused("FTP origin"))?;
            let _permit = governor
                .acquire(&Origin::new(&origin))
                .await
                .map_err(|_| ProtocolError::Refused("origin admission unavailable"))?;
            let control_socket = SocketAddr::new(*ip, port);
            let control = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(control_socket))
                .await
                .map_err(|_| ProtocolError::Deadline)??;
            if control.peer_addr()? != control_socket {
                return Err(ProtocolError::Refused("FTP control peer"));
            }
            let mut control = BufReader::new(control);
            expect(&mut control, &[220]).await?;
            let (code, _) = command(&mut control, "USER anonymous").await?;
            match code {
                230 => {}
                331 => {
                    expect_command(&mut control, "PASS anonymous@", &[230]).await?;
                }
                _ => return Err(ProtocolError::Refused("FTP anonymous login")),
            }
            expect_command(&mut control, "TYPE I", &[200]).await?;
            let (code, line) = command(&mut control, "EPSV").await?;
            let data_socket = match code {
                229 => SocketAddr::new(*ip, epsv_port(&line)?),
                500 | 501 | 502 | 504 | 522 if ip.is_ipv4() => {
                    let (_, line) = expect_command(&mut control, "PASV", &[227]).await?;
                    let socket = pasv_socket(&line)?;
                    if socket.ip() != *ip {
                        return Err(ProtocolError::Refused("FTP passive bounce"));
                    }
                    socket
                }
                _ => return Err(ProtocolError::Refused("FTP passive negotiation")),
            };
            policy
                .check_ip(data_socket.ip())
                .and_then(|()| policy.check_port(data_socket.port()))
                .map_err(|_| ProtocolError::Refused("FTP data policy"))?;
            let mut data = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(data_socket))
                .await
                .map_err(|_| ProtocolError::Deadline)??;
            if data.peer_addr()? != data_socket {
                return Err(ProtocolError::Refused("FTP data peer"));
            }
            expect_command(&mut control, &format!("RETR {path}"), &[125, 150]).await?;
            let mut body = Vec::new();
            let mut chunk = [0_u8; 8192];
            loop {
                let count = data.read(&mut chunk).await?;
                if count == 0 {
                    break;
                }
                if body.len().saturating_add(count)
                    > usize::try_from(max_bytes).map_err(|_| ProtocolError::Limit)?
                {
                    return Err(ProtocolError::Limit);
                }
                body.extend_from_slice(&chunk[..count]);
            }
            drop(data);
            expect(&mut control, &[226, 250]).await?;
            Ok(ProtocolResource {
                final_url: Some(url.clone()),
                target_status: None,
                gateway_status: None,
                media_type: None,
                decoded_bytes: body.len(),
                body: Bytes::from(body),
                children: Vec::new(),
                denied_children: Vec::new(),
                network_requests: 1,
                build_digest: "native-ftp-v1".to_owned(),
                redirects: Vec::new(),
            })
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            result = tokio::time::timeout(deadline, operation) => result.map_err(|_| ProtocolError::Deadline)?,
        }
    }
}

async fn command(control: &mut BufReader<TcpStream>, value: &str) -> Result<(u16, Vec<u8>), ProtocolError> {
    control.get_mut().write_all(value.as_bytes()).await?;
    control.get_mut().write_all(b"\r\n").await?;
    reply(control).await
}

async fn expect_command(
    control: &mut BufReader<TcpStream>,
    value: &str,
    codes: &[u16],
) -> Result<(u16, Vec<u8>), ProtocolError> {
    let result = command(control, value).await?;
    if !codes.contains(&result.0) {
        return Err(ProtocolError::Refused("FTP command rejected"));
    }
    Ok(result)
}

async fn expect(control: &mut BufReader<TcpStream>, codes: &[u16]) -> Result<(), ProtocolError> {
    if !codes.contains(&reply(control).await?.0) {
        return Err(ProtocolError::Refused("FTP transfer reply"));
    }
    Ok(())
}

// RFC 959 framing: finite aggregate bytes and lines, including multiline greetings.
async fn reply(control: &mut BufReader<TcpStream>) -> Result<(u16, Vec<u8>), ProtocolError> {
    let mut prefix: Option<[u8; 3]> = None;
    let mut total = 0_usize;
    for _ in 0..64 {
        let mut line = Vec::new();
        let count = (&mut *control).take(4097).read_until(b'\n', &mut line).await?;
        total = total.saturating_add(count);
        if count == 0 || count > 4096 || total > 16_384 || !line.ends_with(b"\r\n") {
            return Err(ProtocolError::Refused("FTP reply framing"));
        }
        if let Some(expected) = prefix {
            if line.get(..3) != Some(expected.as_slice()) || line.get(3) != Some(&b' ') {
                continue;
            }
        } else {
            if line.len() < 6 || !line[..3].iter().all(u8::is_ascii_digit) || !matches!(line[3], b' ' | b'-')
            {
                return Err(ProtocolError::Refused("FTP reply code"));
            }
            if line[3] == b'-' {
                prefix = Some([line[0], line[1], line[2]]);
                continue;
            }
        }
        let code =
            u16::from(line[0] - b'0') * 100 + u16::from(line[1] - b'0') * 10 + u16::from(line[2] - b'0');
        return Ok((code, line));
    }
    Err(ProtocolError::Limit)
}

fn passive_tuple(line: &[u8]) -> Result<&str, ProtocolError> {
    let text = std::str::from_utf8(line).map_err(|_| ProtocolError::Refused("FTP passive encoding"))?;
    let (_, suffix) = text
        .split_once('(')
        .ok_or(ProtocolError::Refused("FTP passive tuple"))?;
    let (tuple, _) = suffix
        .split_once(')')
        .ok_or(ProtocolError::Refused("FTP passive tuple"))?;
    Ok(tuple)
}

fn epsv_port(line: &[u8]) -> Result<u16, ProtocolError> {
    let tuple = passive_tuple(line)?.as_bytes();
    let delimiter = *tuple.first().ok_or(ProtocolError::Refused("FTP EPSV tuple"))?;
    if !(33..=126).contains(&delimiter)
        || tuple.len() < 5
        || tuple[1..3] != [delimiter; 2]
        || tuple.last() != Some(&delimiter)
    {
        return Err(ProtocolError::Refused("FTP EPSV tuple"));
    }
    let port = std::str::from_utf8(&tuple[3..tuple.len() - 1])
        .ok()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ProtocolError::Refused("FTP passive port"))?;
    Ok(port)
}

fn pasv_socket(line: &[u8]) -> Result<SocketAddr, ProtocolError> {
    let mut values = [0_u8; 6];
    let mut parts = passive_tuple(line)?.split(',');
    for value in &mut values {
        *value = parts
            .next()
            .filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|part| part.parse().ok())
            .ok_or(ProtocolError::Refused("FTP PASV tuple"))?;
    }
    let port = u16::from(values[4]) * 256 + u16::from(values[5]);
    if parts.next().is_some() || port == 0 {
        return Err(ProtocolError::Refused("FTP PASV tuple"));
    }
    Ok(SocketAddr::new(
        std::net::Ipv4Addr::new(values[0], values[1], values[2], values[3]).into(),
        port,
    ))
}

#[cfg(test)]
#[path = "ftp_tests.rs"]
mod tests;
