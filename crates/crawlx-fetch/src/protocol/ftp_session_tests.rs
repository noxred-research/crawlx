#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Credential login, bounded directory discovery and data-peer pinning against a scripted
//! in-process FTP server.

use super::*;
use crate::{resolver::StaticResolver, GovernorConfig};
use crawlx_core::error::CoreError;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use tokio::net::TcpListener;

const POLICY: &str = "fixture-policy";
const USER: &str = "alice-account";
const PASSWORD: &str = "p4ssw0rd-canary";

#[derive(Clone, Default)]
struct Script {
    login: Option<(&'static str, &'static str)>,
    dirs: BTreeMap<&'static str, Vec<&'static str>>,
    files: BTreeMap<&'static str, &'static [u8]>,
    /// PASV advertises this host while the real data listener stays on the control peer.
    pasv_host: Option<&'static str>,
    /// Refuse EPSV so the client falls back to PASV.
    no_epsv: bool,
    /// Refusal texts repeat the offered account and password, as careless servers do.
    echo_secrets: bool,
    /// Raw bytes sent for every MLSD instead of the scripted lines.
    raw_listing: Option<&'static [u8]>,
}

struct Server {
    base: String,
    policy: EgressPolicy,
    commands: Arc<Mutex<Vec<String>>>,
    stray: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

struct Observed {
    commands: Vec<String>,
    stray_data: bool,
}

async fn say(control: &mut BufReader<TcpStream>, text: &str) {
    let _ = control
        .get_mut()
        .write_all(format!("{text}\r\n").as_bytes())
        .await;
}

async fn serve(
    listener: TcpListener,
    data: Vec<TcpListener>,
    connections: usize,
    script: Script,
    commands: Arc<Mutex<Vec<String>>>,
    stray: Arc<AtomicBool>,
) {
    let mut data = data.into_iter();
    for _ in 0..connections {
        let (socket, _) = listener.accept().await.unwrap();
        session(socket, &mut data, &script, &commands, &stray).await;
    }
}

async fn session(
    socket: TcpStream,
    data: &mut std::vec::IntoIter<TcpListener>,
    script: &Script,
    commands: &Mutex<Vec<String>>,
    stray: &AtomicBool,
) {
    let mut control = BufReader::new(socket);
    say(&mut control, "220 ready").await;
    let mut pending: Option<TcpListener> = None;
    loop {
        let mut line = String::new();
        if !matches!(control.read_line(&mut line).await, Ok(count) if count > 0) {
            break;
        }
        let line = line.trim_end().to_owned();
        commands.lock().unwrap().push(line.clone());
        let (verb, argument) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match verb {
            "USER" => match script.login {
                None => say(&mut control, "230 anonymous ok").await,
                Some((user, _)) if user == argument => say(&mut control, "331 password please").await,
                Some(_) if script.echo_secrets => {
                    say(&mut control, &format!("530 unknown account {argument}")).await
                }
                Some(_) => say(&mut control, "530 unknown account").await,
            },
            "PASS" => match script.login {
                Some((_, password)) if password == argument => say(&mut control, "230 welcome").await,
                _ if script.echo_secrets => {
                    say(&mut control, &format!("530 wrong password {argument}")).await
                }
                _ => say(&mut control, "530 wrong password").await,
            },
            "TYPE" => say(&mut control, "200 binary").await,
            "EPSV" if script.no_epsv => say(&mut control, "502 not implemented").await,
            "EPSV" | "PASV" => {
                let listener = data.next().unwrap();
                let port = listener.local_addr().unwrap().port();
                if verb == "EPSV" {
                    say(&mut control, &format!("229 passive (|||{port}|)")).await;
                } else {
                    let host = script.pasv_host.unwrap_or("127.0.0.1").replace('.', ",");
                    say(
                        &mut control,
                        &format!("227 passive ({host},{},{})", port / 256, port % 256),
                    )
                    .await;
                }
                pending = Some(listener);
            }
            "MLSD" | "RETR" => {
                let payload: Option<Vec<u8>> = if verb == "MLSD" {
                    script.raw_listing.map(<[u8]>::to_vec).or_else(|| {
                        script.dirs.get(argument).map(|lines| {
                            let mut text = lines.join("\r\n");
                            text.push_str("\r\n");
                            text.into_bytes()
                        })
                    })
                } else {
                    script.files.get(argument).map(|body| body.to_vec())
                };
                let (Some(listener), Some(payload)) = (pending.take(), payload) else {
                    say(&mut control, "550 unavailable").await;
                    continue;
                };
                let Ok(Ok((mut socket, _))) =
                    tokio::time::timeout(Duration::from_secs(1), listener.accept()).await
                else {
                    break;
                };
                say(&mut control, "150 opening data").await;
                socket.write_all(&payload).await.unwrap();
                socket.shutdown().await.unwrap();
                say(&mut control, "226 complete").await;
            }
            _ => say(&mut control, "500 unknown").await,
        }
    }
    if let Some(listener) = pending {
        // A client that honored the pin never connected to the data listener.
        let connected = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
        if connected.is_ok() {
            stray.store(true, Ordering::SeqCst);
        }
    }
}

impl Server {
    async fn start(script: Script) -> Self {
        Self::start_n(script, 1).await
    }

    /// Serve `connections` sequential control connections, then finish.
    async fn start_n(script: Script, connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut policy = EgressPolicy::new(true);
        policy.extra_allow.push("127.0.0.0/8".parse().unwrap());
        policy.extra_ports.push(port);
        let mut data = Vec::new();
        for _ in 0..8 {
            let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
            policy.extra_ports.push(socket.local_addr().unwrap().port());
            data.push(socket);
        }
        let commands = Arc::new(Mutex::new(Vec::new()));
        let stray = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let (commands, stray) = (Arc::clone(&commands), Arc::clone(&stray));
            async move {
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    serve(listener, data, connections, script, commands, stray),
                )
                .await;
            }
        });
        Self {
            base: format!("ftp://fixture.test:{port}"),
            policy,
            commands,
            stray,
            task,
        }
    }

    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{path}", self.base)).unwrap()
    }

    fn registry(&self) -> FtpRegistry {
        FtpRegistry::new(
            BTreeSet::from([crawlx_core::protocol::protocol_origin(&self.url("/")).unwrap()]),
            BTreeSet::from([POLICY.to_owned()]),
        )
    }

    async fn run(
        &self,
        registry: &FtpRegistry,
        path: &str,
        max_bytes: u32,
        max_requests: u32,
    ) -> Result<ProtocolResource, ProtocolError> {
        let url = self.url(path);
        let resolver = StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()]);
        let governor = Arc::new(OriginGovernor::new(GovernorConfig::default()));
        registry
            .acquire(
                &FtpRequest::new(&url, POLICY, max_bytes, Duration::from_secs(5))
                    .with_max_requests(max_requests),
                &FtpNetwork::new(&self.policy, &resolver, &governor),
                &CancellationToken::new(),
            )
            .await
    }

    async fn finish(self) -> Observed {
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap();
        Observed {
            commands: self.commands.lock().unwrap().clone(),
            stray_data: self.stray.load(Ordering::SeqCst),
        }
    }

    /// For tests that must never reach the control socket.
    async fn untouched(self) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(self.commands.lock().unwrap().is_empty());
        self.task.abort();
    }
}

struct Secrets;

#[async_trait::async_trait]
impl SecretResolver for Secrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        match reference.0.as_str() {
            "env://FTP_USER" => Ok(SecretOr::secret(USER.to_owned())),
            "env://FTP_PASSWORD" => Ok(SecretOr::secret(PASSWORD.to_owned())),
            "env://FTP_WRONG" => Ok(SecretOr::secret("wrong-canary".to_owned())),
            "env://FTP_INJECTED" => Ok(SecretOr::secret("x\r\nDELE /".to_owned())),
            "env://FTP_EMPTY" => Ok(SecretOr::secret(String::new())),
            _ => Err(CoreError::Invalid {
                field: "credential",
                reason: "unavailable".to_owned(),
            }),
        }
    }
}

async fn credentialed(server: &Server, password_ref: &str) -> FtpRegistry {
    let origin = crawlx_core::protocol::protocol_origin(&server.url("/")).unwrap();
    let mut registry = server
        .registry()
        .with_recursion(FtpRecursion::new(2, 64))
        .with_credential_ref(origin, FtpCredentialRef::new("env://FTP_USER", password_ref));
    registry.validate().unwrap();
    registry.resolve_credentials(&Secrets).await.unwrap();
    registry
}

fn tree() -> Script {
    Script {
        dirs: BTreeMap::from([
            (
                "/",
                vec![
                    "type=cdir;modify=20260101000000; .",
                    "type=pdir; ..",
                    "type=file;size=1; z.txt",
                    "type=dir; docs",
                    "type=file;size=1; a.txt",
                ],
            ),
            (
                "/docs",
                vec![
                    "type=cdir; .",
                    "type=pdir; ..",
                    "type=file; b.txt",
                    "type=dir; deep",
                ],
            ),
            ("/docs/deep", vec!["type=file; c.txt"]),
        ]),
        files: BTreeMap::from([("/a.txt", b"alpha".as_slice())]),
        ..Script::default()
    }
}

fn urls(urls: &[Url]) -> Vec<String> {
    urls.iter().map(|url| url.path().to_owned()).collect()
}

#[tokio::test]
async fn recursion_lists_breadth_first_to_the_depth_cap_and_reports_the_boundary() {
    let server = Server::start_n(tree(), 2).await;
    let shallow = server.registry().with_recursion(FtpRecursion::new(1, 64));
    let resource = server.run(&shallow, "/", 4096, 8).await.unwrap();
    assert_eq!(
        urls(&resource.children),
        ["/a.txt", "/docs/b.txt", "/docs/deep/", "/z.txt"]
    );
    assert!(resource.denied_children.is_empty());
    assert!(resource.body.is_empty());
    assert_eq!((resource.target_status, resource.gateway_status), (None, None));
    assert_eq!(resource.network_requests, 2);
    assert_eq!(resource.final_url, Some(server.url("/")));
    assert!(resource.decoded_bytes > 0);

    let deep = server.registry().with_recursion(FtpRecursion::new(2, 64));
    let resource = server.run(&deep, "/docs/", 4096, 8).await.unwrap();
    assert_eq!(urls(&resource.children), ["/docs/b.txt", "/docs/deep/c.txt"]);
    let observed = server.finish().await;
    assert_eq!(
        observed
            .commands
            .iter()
            .filter(|c| c.starts_with("MLSD"))
            .collect::<Vec<_>>(),
        ["MLSD /", "MLSD /docs", "MLSD /docs", "MLSD /docs/deep"]
    );
    assert!(!observed.commands.iter().any(|c| c.starts_with("RETR")));
}

#[tokio::test]
async fn entry_byte_and_request_caps_fail_the_whole_discovery() {
    // Three root entries, two below `docs` and one below `deep`; `.` and `..` do not count.
    let exact = Server::start(tree()).await;
    let registry = exact.registry().with_recursion(FtpRecursion::new(2, 6));
    assert_eq!(
        exact.run(&registry, "/", 4096, 8).await.unwrap().children.len(),
        4,
        "z.txt, a.txt, b.txt, c.txt"
    );
    exact.finish().await;

    let entries = Server::start(tree()).await;
    let registry = entries.registry().with_recursion(FtpRecursion::new(2, 5));
    assert!(matches!(
        entries.run(&registry, "/", 4096, 8).await,
        Err(ProtocolError::Limit)
    ));
    entries.finish().await;

    let bytes = Server::start(tree()).await;
    let registry = bytes.registry().with_recursion(FtpRecursion::new(2, 64));
    assert!(matches!(
        bytes.run(&registry, "/", 40, 8).await,
        Err(ProtocolError::Limit)
    ));
    bytes.finish().await;

    let requests = Server::start(tree()).await;
    let registry = requests.registry().with_recursion(FtpRecursion::new(2, 64));
    assert!(matches!(
        requests.run(&registry, "/", 4096, 1).await,
        Err(ProtocolError::Limit)
    ));
    let observed = requests.finish().await;
    assert_eq!(
        observed.commands.iter().filter(|c| c.starts_with("MLSD")).count(),
        1
    );
}

#[tokio::test]
async fn out_of_scope_special_and_unsafe_entries_are_denied_and_never_listed() {
    let mut script = tree();
    script.dirs.insert(
        "/",
        vec![
            "type=dir; private",
            "type=dir; open",
            "type=OS.unix=slink:/etc; link",
            "type=sock; socket",
            "size=1; untyped",
            "type=file; back\\slash",
            "type=file; semi;colon",
            "type=file; bell\u{7}",
            "type=file; fine.txt",
        ],
    );
    script.dirs.insert("/open", vec!["type=file; inside.txt"]);
    let server = Server::start(script).await;
    let origin = crawlx_core::protocol::protocol_origin(&server.url("/")).unwrap();
    let mut record = crawlx_policy::testkit::sample_record(
        crawlx_core::TenantId::new(),
        "2026-11-01T00:00:00Z".parse().unwrap(),
        &[&origin],
    );
    record.excluded_paths = vec!["/private*".to_owned()];
    let mut policy = server.policy.clone();
    policy.record_scope = Some(Arc::new(record.scope()));
    let registry = server.registry().with_recursion(FtpRecursion::new(3, 64));
    let url = server.url("/");
    let resolver = StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()]);
    let governor = Arc::new(OriginGovernor::new(GovernorConfig::default()));
    let resource = registry
        .acquire(
            &FtpRequest::new(&url, POLICY, 4096, Duration::from_secs(5)),
            &FtpNetwork::new(&policy, &resolver, &governor),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(urls(&resource.children), ["/fine.txt", "/open/inside.txt"]);
    assert_eq!(
        urls(&resource.denied_children),
        [
            "/back%5Cslash",
            "/bell%07",
            "/link",
            "/private/",
            "/semi;colon",
            "/socket",
            "/untyped"
        ]
    );
    let observed = server.finish().await;
    assert_eq!(
        observed.commands.iter().filter(|c| c.starts_with("MLSD")).count(),
        2
    );
    assert!(!observed.commands.iter().any(|c| c.contains("private")));
}

#[tokio::test]
async fn traversal_names_and_malformed_listings_never_become_resources() {
    for (listing, reason) in [
        (b"type=file; ..\r\n".as_slice(), "FTP listing name"),
        (b"type=file; .\r\n", "FTP listing name"),
        (b"type=file; ../escape\r\n", "FTP listing name"),
        (b"type=dir; a/b\r\n", "FTP listing name"),
        (b"type=file; truncated", "FTP listing framing"),
        (b"no-space-line\r\n", "FTP listing line"),
        (b"type=file; \r\n", "FTP listing line"),
        (
            &[b't', b'=', 0xff, b' ', b'x', b'\r', b'\n'],
            "FTP listing encoding",
        ),
    ] {
        let server = Server::start(Script {
            raw_listing: Some(listing),
            ..Script::default()
        })
        .await;
        let registry = server.registry().with_recursion(FtpRecursion::new(2, 64));
        assert!(
            matches!(server.run(&registry, "/", 4096, 8).await, Err(ProtocolError::Refused(message)) if message == reason),
            "{reason}"
        );
        server.finish().await;
    }
}

#[tokio::test]
async fn directory_targets_need_approved_recursion_and_file_reads_are_unchanged() {
    let server = Server::start(tree()).await;
    let plain = server.registry();
    assert!(matches!(
        server.run(&plain, "/docs/", 4096, 8).await,
        Err(ProtocolError::Refused("FTP file path"))
    ));
    assert!(plain.admit(&server.url("/docs/"), POLICY).is_err());
    let approved = plain.clone().with_recursion(FtpRecursion::new(1, 8));
    assert!(approved.admit(&server.url("/docs/"), POLICY).is_ok());
    assert!(approved.admit(&server.url("/a%2f..%2f"), POLICY).is_err());
    // Credentials and a directory never ride the URL.
    let mut with_user = server.url("/docs/");
    with_user.set_username("alice").unwrap();
    assert!(approved.admit(&with_user, POLICY).is_err());
    let file = server.run(&approved, "/a.txt", 4096, 8).await.unwrap();
    assert_eq!(file.body.as_ref(), b"alpha");
    assert!(file.children.is_empty() && file.denied_children.is_empty());
    assert_eq!(file.build_digest, "native-ftp-v1");
    let observed = server.finish().await;
    assert_eq!(observed.commands.last().map(String::as_str), Some("RETR /a.txt"));
}

#[tokio::test]
async fn credential_login_reads_files_and_trees_and_no_output_carries_the_secrets() {
    let mut script = tree();
    script.login = Some((USER, PASSWORD));
    let server = Server::start(script).await;
    let registry = credentialed(&server, "env://FTP_PASSWORD").await;
    let file = server.run(&registry, "/a.txt", 4096, 8).await.unwrap();
    assert_eq!(file.body.as_ref(), b"alpha");
    assert_eq!(file.build_digest, "native-ftp-credential-v1");
    let observed = server.finish().await;
    assert_eq!(
        observed.commands,
        [
            format!("USER {USER}"),
            format!("PASS {PASSWORD}"),
            "TYPE I".into(),
            "EPSV".into(),
            "RETR /a.txt".into()
        ]
    );
    for output in [
        format!("{file:?}"),
        format!("{:?}", file.final_url),
        format!("{registry:?}"),
    ] {
        assert!(!output.contains(PASSWORD) && !output.contains(USER), "{output}");
    }

    let mut script = tree();
    script.login = Some((USER, PASSWORD));
    let server = Server::start(script).await;
    let registry = credentialed(&server, "env://FTP_PASSWORD").await;
    let resource = server.run(&registry, "/", 4096, 8).await.unwrap();
    assert_eq!(resource.children.len(), 4);
    assert_eq!(resource.build_digest, "native-ftp-credential-v1");
    let rendered = format!(
        "{resource:?} {:?} {:?}",
        resource.children, resource.denied_children
    );
    assert!(!rendered.contains(PASSWORD) && !rendered.contains(USER));
    server.finish().await;
}

#[tokio::test]
async fn rejected_login_never_surfaces_or_continues_with_the_echoed_secret() {
    let mut script = tree();
    script.login = Some((USER, PASSWORD));
    script.echo_secrets = true;
    let server = Server::start(script).await;
    let registry = credentialed(&server, "env://FTP_WRONG").await;
    let error = server.run(&registry, "/a.txt", 4096, 8).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Refused("FTP login rejected")));
    let rendered = format!("{error} {error:?}");
    for secret in [USER, PASSWORD, "wrong-canary"] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
    let observed = server.finish().await;
    assert_eq!(observed.commands.len(), 2, "no command follows a refused login");

    // An unknown account is refused at USER, with the account echoed by the server.
    let mut script = tree();
    script.login = Some(("someone-else", PASSWORD));
    script.echo_secrets = true;
    let server = Server::start(script).await;
    let registry = credentialed(&server, "env://FTP_PASSWORD").await;
    let error = server.run(&registry, "/a.txt", 4096, 8).await.unwrap_err();
    assert!(matches!(error, ProtocolError::Refused("FTP login rejected")));
    assert!(!format!("{error} {error:?}").contains(USER));
    let observed = server.finish().await;
    assert_eq!(
        observed.commands.len(),
        1,
        "the password is never sent to an unknown account"
    );
}

#[tokio::test]
async fn credentialed_origin_without_resolved_secrets_never_degrades_to_anonymous() {
    let server = Server::start(tree()).await;
    let origin = crawlx_core::protocol::protocol_origin(&server.url("/")).unwrap();
    let registry = server.registry().with_credential_ref(
        origin,
        FtpCredentialRef::new("env://FTP_USER", "env://FTP_PASSWORD"),
    );
    assert!(registry.has_credentials() && registry.uses_credentials(&server.url("/a.txt")));
    assert!(matches!(
        server.run(&registry, "/a.txt", 4096, 8).await,
        Err(ProtocolError::CapabilityUnavailable("FTP credential unresolved"))
    ));
    server.untouched().await;
}

#[tokio::test]
async fn credential_registration_and_resolution_fail_closed_without_naming_secrets() {
    let origin = "ftp://registered.test".to_owned();
    let base = FtpRegistry::new(
        BTreeSet::from([origin.clone()]),
        BTreeSet::from([POLICY.to_owned()]),
    );
    let refs = |user: &str, password: &str| FtpCredentialRef::new(user, password);
    for (registry, label) in [
        (
            base.clone()
                .with_credential_ref("ftp://other.test", refs("env://FTP_USER", "env://FTP_PASSWORD")),
            "unregistered origin",
        ),
        (
            base.clone()
                .with_credential_ref(origin.clone(), refs("plain-user", "env://FTP_PASSWORD")),
            "bare reference",
        ),
        (
            base.clone()
                .with_credential_ref(origin.clone(), refs("env://FTP_USER", "")),
            "empty reference",
        ),
        (base.clone().with_recursion(FtpRecursion::new(0, 8)), "zero depth"),
        (base.clone().with_recursion(FtpRecursion::new(9, 8)), "deep"),
        (base.clone().with_recursion(FtpRecursion::new(2, 0)), "no entries"),
        (
            base.clone().with_recursion(FtpRecursion::new(2, 4097)),
            "many entries",
        ),
    ] {
        assert!(registry.validate().is_err(), "{label}");
    }
    base.clone()
        .with_credential_ref(origin.clone(), refs("env://FTP_USER", "env://FTP_PASSWORD"))
        .with_recursion(FtpRecursion::new(8, 4096))
        .validate()
        .unwrap();

    for (password_ref, reason) in [
        ("env://FTP_MISSING", "FTP credential unavailable"),
        ("env://FTP_INJECTED", "FTP credential value"),
        ("env://FTP_EMPTY", "FTP credential value"),
    ] {
        let mut registry = base
            .clone()
            .with_credential_ref(origin.clone(), refs("env://FTP_USER", password_ref));
        let error = registry.resolve_credentials(&Secrets).await.unwrap_err();
        assert!(matches!(error, ProtocolError::Refused(message) if message == reason));
        let rendered = format!("{error} {error:?}");
        for hidden in [password_ref, "DELE", USER] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}

#[tokio::test]
async fn data_peer_other_than_the_control_peer_is_refused_for_every_transfer_kind() {
    for host in ["0.0.0.0", "10.0.0.5", "127.0.0.2", "169.254.169.254"] {
        for (credentials, path) in [(false, "/a.txt"), (true, "/a.txt"), (false, "/"), (true, "/")] {
            let mut script = tree();
            script.no_epsv = true;
            script.pasv_host = Some(host);
            if credentials {
                script.login = Some((USER, PASSWORD));
            }
            let server = Server::start(script).await;
            let registry = if credentials {
                credentialed(&server, "env://FTP_PASSWORD").await
            } else {
                server.registry().with_recursion(FtpRecursion::new(2, 64))
            };
            let error = server.run(&registry, path, 4096, 8).await.unwrap_err();
            assert!(
                matches!(error, ProtocolError::Refused("FTP passive bounce")),
                "{host} {path}: {error}"
            );
            assert!(!format!("{error:?}").contains(PASSWORD));
            let observed = server.finish().await;
            assert!(
                !observed.stray_data,
                "{host}: a data socket reached the control peer"
            );
            assert!(
                !observed
                    .commands
                    .iter()
                    .any(|c| c.starts_with("RETR") || c.starts_with("MLSD")),
                "{host}: no transfer command follows a refused peer"
            );
        }
    }
}

#[tokio::test]
async fn pasv_fallback_lists_through_the_control_peer() {
    let server = Server::start(Script {
        no_epsv: true,
        ..tree()
    })
    .await;
    let registry = server.registry().with_recursion(FtpRecursion::new(2, 64));
    // PASV is the fallback only after an EPSV refusal; a working PASV to the control peer lists normally.
    let resource = server.run(&registry, "/docs/", 4096, 8).await.unwrap();
    assert_eq!(urls(&resource.children), ["/docs/b.txt", "/docs/deep/c.txt"]);
    let observed = server.finish().await;
    assert_eq!(
        observed.commands.iter().filter(|c| c.as_str() == "PASV").count(),
        2
    );
}
