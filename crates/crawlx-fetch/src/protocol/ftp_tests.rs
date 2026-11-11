#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{resolver::StaticResolver, GovernorConfig};
use tokio::net::TcpListener;

#[derive(Clone, Copy)]
enum Case {
    Epsv,
    Pasv,
    Bounce,
    DeniedPort,
    Partial,
    Oversize,
    Hang,
    Malformed,
    Encoded,
}

async fn line(control: &mut BufReader<TcpStream>) -> String {
    let mut value = String::new();
    control.read_line(&mut value).await.unwrap();
    assert!(value.len() < 8192);
    value
}

async fn fixture(
    case: Case,
) -> (
    Url,
    EgressPolicy,
    tokio::sync::oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data = TcpListener::bind(if matches!(case, Case::Bounce) {
        "127.0.0.2:0"
    } else {
        "127.0.0.1:0"
    })
    .await
    .unwrap();
    let port = listener.local_addr().unwrap().port();
    let data_port = data.local_addr().unwrap().port();
    let path = if matches!(case, Case::Encoded) {
        "/%6fwned%20file.txt"
    } else {
        "/owned.txt"
    };
    let target = Url::parse(&format!("ftp://fixture.test:{port}{path}")).unwrap();
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow.push("127.0.0.0/8".parse().unwrap());
    policy.extra_ports.push(port);
    if !matches!(case, Case::DeniedPort) {
        policy.extra_ports.push(data_port);
    }
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut control = BufReader::new(socket);
            if matches!(case, Case::Malformed) {
                control.get_mut().write_all(b"220 not framed\n").await.unwrap();
                return;
            }
            control
                .get_mut()
                .write_all(b"220-fixture\r\nbounded multiline greeting\r\n220 ready\r\n")
                .await
                .unwrap();
            assert_eq!(line(&mut control).await, "USER anonymous\r\n");
            control.get_mut().write_all(b"331 password\r\n").await.unwrap();
            assert_eq!(line(&mut control).await, "PASS anonymous@\r\n");
            control.get_mut().write_all(b"230 logged in\r\n").await.unwrap();
            assert_eq!(line(&mut control).await, "TYPE I\r\n");
            control.get_mut().write_all(b"200 binary\r\n").await.unwrap();
            assert_eq!(line(&mut control).await, "EPSV\r\n");
            if matches!(case, Case::Pasv | Case::Bounce) {
                control.get_mut().write_all(b"502 unsupported\r\n").await.unwrap();
                assert_eq!(line(&mut control).await, "PASV\r\n");
                let last = if matches!(case, Case::Bounce) { 2 } else { 1 };
                control
                    .get_mut()
                    .write_all(
                        format!(
                            "227 passive (127,0,0,{last},{},{})\r\n",
                            data_port / 256,
                            data_port % 256
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else {
                control
                    .get_mut()
                    .write_all(format!("229 passive (|||{data_port}|)\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            if matches!(case, Case::Bounce | Case::DeniedPort) {
                assert!(tokio::time::timeout(Duration::from_millis(50), data.accept())
                    .await
                    .is_err());
                return;
            }
            let (mut data, _) = data.accept().await.unwrap();
            let expected = if matches!(case, Case::Encoded) {
                "RETR /owned file.txt\r\n"
            } else {
                "RETR /owned.txt\r\n"
            };
            assert_eq!(line(&mut control).await, expected);
            control
                .get_mut()
                .write_all(b"150 opening data\r\n")
                .await
                .unwrap();
            let _ = ready.send(());
            if matches!(case, Case::Hang) {
                let mut byte = [0];
                for result in [data.read(&mut byte).await, control.read(&mut byte).await] {
                    match result {
                        Ok(0) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                        other => panic!("expected a closed socket, got {other:?}"),
                    }
                }
                return;
            }
            let body: &[u8] = if matches!(case, Case::Oversize) {
                &[b'x'; 128]
            } else {
                b"owned FTP bytes"
            };
            data.write_all(body).await.unwrap();
            data.shutdown().await.unwrap();
            let reply = if matches!(case, Case::Partial) {
                b"426 transfer interrupted\r\n".as_slice()
            } else {
                b"226 complete\r\n".as_slice()
            };
            // Over-limit clients may already have closed the control socket.
            if !matches!(case, Case::Oversize) {
                control.get_mut().write_all(reply).await.unwrap();
            }
        })
        .await
        .unwrap();
    });
    (target, policy, received, task)
}

fn registry(target: &Url) -> FtpRegistry {
    FtpRegistry {
        origins: BTreeSet::from([crawlx_core::protocol::protocol_origin(target).unwrap()]),
        policy_digests: BTreeSet::from(["fixture-policy".to_owned()]),
    }
}

async fn acquire(
    target: &Url,
    policy: &EgressPolicy,
    max_bytes: u32,
    token: &CancellationToken,
    deadline: Duration,
) -> Result<ProtocolResource, ProtocolError> {
    registry(target)
        .acquire(
            target,
            "fixture-policy",
            max_bytes,
            deadline,
            token,
            policy,
            &StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()]),
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
        )
        .await
}

#[tokio::test]
async fn passive_epsv_and_pasv_return_real_complete_file_without_http_status() {
    for case in [Case::Epsv, Case::Pasv] {
        let (url, policy, _, task) = fixture(case).await;
        let resource = acquire(
            &url,
            &policy,
            4096,
            &CancellationToken::new(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(resource.body.as_ref(), b"owned FTP bytes");
        assert_eq!(resource.target_status, None);
        assert_eq!(resource.gateway_status, None);
        assert_eq!(resource.network_requests, 1);
        assert_eq!(resource.final_url.as_ref(), Some(&url));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn passive_bounce_and_unapproved_data_port_open_no_data_socket() {
    for (case, reason) in [
        (Case::Bounce, "FTP passive bounce"),
        (Case::DeniedPort, "FTP data policy"),
    ] {
        let (url, policy, _, task) = fixture(case).await;
        assert!(
            matches!(acquire(&url, &policy, 4096, &CancellationToken::new(), Duration::from_secs(1)).await,
            Err(ProtocolError::Refused(message)) if message == reason)
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn partial_oversized_and_malformed_transfers_never_become_resources() {
    for case in [Case::Partial, Case::Oversize, Case::Malformed] {
        let (url, policy, _, task) = fixture(case).await;
        let result = acquire(
            &url,
            &policy,
            32,
            &CancellationToken::new(),
            Duration::from_secs(1),
        )
        .await;
        match case {
            Case::Oversize => assert!(matches!(result, Err(ProtocolError::Limit))),
            Case::Partial => assert!(matches!(
                result,
                Err(ProtocolError::Refused("FTP transfer reply"))
            )),
            _ => assert!(matches!(result, Err(ProtocolError::Refused("FTP reply framing")))),
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn cancellation_and_deadline_close_both_sockets_and_release_origin_permit() {
    for cancel in [true, false] {
        let (url, policy, ready, task) = fixture(Case::Hang).await;
        let token = CancellationToken::new();
        let signal = token.clone();
        let cancel_task = tokio::spawn(async move {
            ready.await.unwrap();
            if cancel {
                signal.cancel();
            }
        });
        let governor = Arc::new(OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            ..GovernorConfig::default()
        }));
        let result = registry(&url)
            .acquire(
                &url,
                "fixture-policy",
                4096,
                Duration::from_secs(1),
                &token,
                &policy,
                &StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()]),
                &governor,
            )
            .await;
        if cancel {
            assert!(matches!(result, Err(ProtocolError::Cancelled)));
        } else {
            assert!(matches!(result, Err(ProtocolError::Deadline)));
        }
        cancel_task.await.unwrap();
        let origin = Origin::new(&crawlx_core::protocol::protocol_origin(&url).unwrap());
        let permit = tokio::time::timeout(Duration::from_millis(100), governor.acquire(&origin))
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn private_dns_and_invalid_authority_fail_before_control_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Url::parse(&format!(
        "ftp://fixture.test:{}/owned.txt",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    let registry = registry(&target);
    registry.validate().unwrap();
    let mut policy = EgressPolicy::new(false);
    policy.extra_ports.push(listener.local_addr().unwrap().port());
    let result = registry
        .acquire(
            &target,
            "fixture-policy",
            4096,
            Duration::from_secs(1),
            &CancellationToken::new(),
            &policy,
            &StaticResolver::new().with("fixture.test", ["169.254.169.254".parse().unwrap()]),
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
        )
        .await;
    assert!(matches!(result, Err(ProtocolError::Refused("FTP DNS policy"))));
    for path in [
        "/directory/",
        "/a%0d%0aPORT%20x",
        "/a%5cb",
        "/%2e%2e%2fsecret",
        "/file;type=a",
    ] {
        let mut invalid = target.clone();
        invalid.set_path(path);
        assert!(registry.admit(&invalid, "fixture-policy").is_err());
    }
    assert!(registry.admit(&target, "unapproved-policy").is_err());
    let mut invalid = target.clone();
    invalid.set_username("secret").unwrap();
    assert!(registry.admit(&invalid, "fixture-policy").is_err());
    assert!(tokio::time::timeout(Duration::from_millis(25), listener.accept())
        .await
        .is_err());
}

#[test]
fn passive_reply_parsers_reject_malformed_and_zero_ports() {
    assert_eq!(epsv_port(b"229 (!!!1234!)\r\n").unwrap(), 1234);
    for line in [
        b"229 (|||0|)\r\n".as_slice(),
        b"229 (|||65536|)\r\n",
        b"229 (||123|)\r\n",
        b"229 (|||+21|)\r\n",
    ] {
        assert!(epsv_port(line).is_err());
    }
    for line in [
        b"227 (127,0,0,1,0,0)\r\n".as_slice(),
        b"227 (127,0,0,1,1,256)\r\n",
        b"227 (127,0,0,1,1,2,3)\r\n",
    ] {
        assert!(pasv_socket(line).is_err());
    }
}

fn with_path_exclusions(mut policy: EgressPolicy, target: &Url) -> EgressPolicy {
    let origin = crawlx_core::protocol::protocol_origin(target).unwrap();
    let mut record = crawlx_policy::testkit::sample_record(
        crawlx_core::TenantId::new(),
        "2026-11-01T00:00:00Z".parse().unwrap(),
        &[&origin],
    );
    record.excluded_paths = vec!["/private/*".to_owned()];
    policy.record_scope = Some(Arc::new(record.scope()));
    policy
}

#[tokio::test]
async fn encoded_excluded_ftp_path_is_denied_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.push(port);
    let base = Url::parse(&format!("ftp://fixture.test:{port}/owned.txt")).unwrap();
    let policy = with_path_exclusions(policy, &base);
    for path in ["/%70rivate/secret", "/private%2fsecret", "/%70%72ivate/secret"] {
        let target = Url::parse(&format!("ftp://fixture.test:{port}{path}")).unwrap();
        assert!(policy
            .record_scope
            .as_ref()
            .unwrap()
            .check_request(&target)
            .is_ok());
        let result = acquire(
            &target,
            &policy,
            4096,
            &CancellationToken::new(),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(ProtocolError::Refused("FTP authorization"))));
    }
    assert!(tokio::time::timeout(Duration::from_millis(25), listener.accept())
        .await
        .is_err());
}

#[tokio::test]
async fn encoded_safe_ftp_path_uses_the_authorized_decoded_retr_command() {
    let (target, policy, _, task) = fixture(Case::Encoded).await;
    let policy = with_path_exclusions(policy, &target);
    let resource = acquire(
        &target,
        &policy,
        4096,
        &CancellationToken::new(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(resource.body.as_ref(), b"owned FTP bytes");
    assert_eq!(resource.final_url.as_ref(), Some(&target));
    task.await.unwrap();
}
