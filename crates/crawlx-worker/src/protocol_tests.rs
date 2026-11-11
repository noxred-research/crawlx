#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_fetch::{resolver::StaticResolver, GovernorConfig};
use serde_json::json;
use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn route() -> ProtocolRouteV1 {
    serde_json::from_value(json!({
        "id":"owned-file", "schemes":["ftp"], "origin":null, "pathPattern":null,
        "schedulerMetadata":{}, "backend":"delegate", "delegateId":"native_ftp",
        "requiredCapabilities":["ftp_anonymous_file","ftp_passive_pinned"],
        "maxBodyBytes":4096, "maxElapsedMs":2000, "policyRevision":"fixture-policy"
    }))
    .unwrap()
}

async fn registry(root: &std::path::Path, origin: &str, tenant: TenantId) -> Arc<ProtocolRegistry> {
    let path = root.join("registry.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schemaVersion":1, "approvedTenants":[tenant.to_string()], "services":{},
            "ftp":{"origins":[origin],"policyDigests":["fixture-policy"]}
        }))
        .unwrap(),
    )
    .unwrap();
    ProtocolRegistry::from_file(&path, &crate::secrets::ChainResolver::new())
        .await
        .unwrap()
}

#[tokio::test]
async fn registered_ftp_dispatch_preserves_diagnostic_facts_and_request_budget() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let data_port = data.local_addr().unwrap().port();
    let url = Url::parse(&format!("ftp://fixture.test:{port}/owned.txt")).unwrap();
    let origin = crawlx_core::protocol::protocol_origin(&url).unwrap();
    let root = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.extend([port, data_port]);
    let runtime = ProtocolRuntime {
        registry: registry(root.path(), &origin, tenant).await,
        policy: Arc::new(policy),
        resolver: Arc::new(StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()])),
        governor: Arc::new(OriginGovernor::new(GovernorConfig::default())),
    };
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut control = BufReader::new(socket);
            control.get_mut().write_all(b"220 ready\r\n").await.unwrap();
            for (expected, response) in [
                ("USER anonymous\r\n", "230 ready\r\n".to_owned()),
                ("TYPE I\r\n", "200 binary\r\n".to_owned()),
                ("EPSV\r\n", format!("229 passive (|||{data_port}|)\r\n")),
            ] {
                let mut line = String::new();
                control.read_line(&mut line).await.unwrap();
                assert_eq!(line, expected);
                control.get_mut().write_all(response.as_bytes()).await.unwrap();
            }
            let (mut data, _) = data.accept().await.unwrap();
            let mut line = String::new();
            control.read_line(&mut line).await.unwrap();
            assert_eq!(line, "RETR /owned.txt\r\n");
            control.get_mut().write_all(b"150 start\r\n").await.unwrap();
            data.write_all(b"owned worker fixture").await.unwrap();
            data.shutdown().await.unwrap();
            control.get_mut().write_all(b"226 complete\r\n").await.unwrap();
        })
        .await
        .unwrap();
    });
    let route = route();
    runtime
        .admit(std::slice::from_ref(&route), run, tenant, &url, true)
        .unwrap();
    assert!(runtime
        .admit(std::slice::from_ref(&route), run, TenantId::new(), &url, true)
        .is_err());
    let mut wrong = route.clone();
    wrong
        .required_capabilities
        .insert("directory_recursion".to_owned());
    assert!(runtime.admit(&[wrong], run, tenant, &url, true).is_err());
    let requests = Arc::new(AtomicU32::new(1));
    let resource = runtime
        .acquire(
            &route,
            &url,
            run,
            tenant,
            "attempt",
            true,
            &requests,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(resource.body.as_ref(), b"owned worker fixture");
    assert_eq!(requests.load(Ordering::Acquire), 0);
    let metadata = resource_metadata(&resource, &route, &url, run, tenant);
    assert_eq!(metadata.target_status, None);
    assert_eq!(metadata.gateway_status, None);
    assert_eq!(metadata.network_requests, 1);
    assert!(metadata
        .backend
        .limitations
        .iter()
        .any(|item| item == "diagnostic_only"));
    assert!(matches!(
        runtime
            .acquire(
                &route,
                &url,
                run,
                tenant,
                "next",
                true,
                &requests,
                &CancellationToken::new()
            )
            .await,
        Err(ProtocolError::Limit)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn registry_probe_has_no_default_delegate_and_no_live_attestation() {
    let absent = capability_report(None);
    assert!(!absent.registry_present);
    assert!(!absent.network_probed);
    assert!(absent.delegates.is_empty());
    let root = tempfile::tempdir().unwrap();
    let registry = registry(root.path(), "ftp://fixture.test", TenantId::new()).await;
    let report = capability_report(Some(&registry));
    assert!(report.registry_present);
    assert!(!report.network_probed);
    assert_eq!(report.delegates.len(), 1);
    assert_eq!(report.delegates[0].id, "native_ftp");
    assert!(report.delegates[0].operator_configured);
    assert!(!report.delegates[0].live_attested);
    assert!(!serde_json::to_string(&report).unwrap().contains("fixture.test"));
}

#[tokio::test]
async fn registry_special_files_and_symlinks_fail_without_blocking() {
    let root = tempfile::tempdir().unwrap();
    let directory = rustix::fs::open(
        root.path(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::mkfifoat(
        &directory,
        "pipe",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    std::fs::write(root.path().join("regular"), b"{}").unwrap();
    std::os::unix::fs::symlink(root.path().join("regular"), root.path().join("link")).unwrap();
    for name in ["pipe", "link"] {
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            ProtocolRegistry::from_file(&root.path().join(name), &crate::secrets::ChainResolver::new())
        )
        .await
        .unwrap()
        .is_err());
    }
}
