#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Deployment artifacts as code (deployment checks): the alert rules and the
//! dashboard reference only catalogued metric names, the Prometheus rule file has the shape
//! `promtool check rules` accepts, the seccomp profile allows the Chromium sandbox and nothing
//! wider, the Kubernetes manifests carry the hardened security context, the Dockerfiles never
//! pass `--no-sandbox` and verify the Chromium pin, and the Helm configuration is parsed and
//! validated by `crawlx config check`. The production
//! Compose stack (`docker/docker-compose.yml`) is held to the same documents: its images, build
//! wiring, environment, ports, posture, health checks and start-up order.

use clap::Parser as _;
use crawlx_cli::config_check::{load_from, validate};
use crawlx_cli::{Cli, Command};
use crawlx_telemetry::metrics::catalog;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Every Prometheus family name the catalog exports (`crawlx_…`), plus `_bucket/_count/_sum`.
fn exported_names() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for def in catalog::all() {
        let base = def.prometheus_name();
        if def.kind == catalog::MetricKind::Histogram {
            out.insert(format!("{base}_bucket"));
            out.insert(format!("{base}_count"));
            out.insert(format!("{base}_sum"));
        }
        out.insert(base);
    }
    out
}

/// `crawlx_*` identifiers in a PromQL expression.
fn crawlx_metrics(expr: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while let Some(pos) = expr[i..].find("crawlx_") {
        let start = i + pos;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        out.insert(expr[start..end].to_owned());
        i = end;
    }
    out
}

#[test]
fn alert_rules_parse_and_reference_only_catalogued_metrics() {
    let doc: Value = serde_yaml_ng::from_str(&read("deploy/alerts/crawlx-rules.yaml")).unwrap();
    let groups = doc["groups"].as_array().expect("groups");
    assert!(groups.len() >= 7, "one group per SLO plus supporting alerts");
    let known = exported_names();
    let mut names = BTreeSet::new();
    let mut slos = BTreeSet::new();
    for g in groups {
        assert!(g["name"].as_str().unwrap().starts_with("crawlx-"));
        for r in g["rules"].as_array().unwrap() {
            let alert = r["alert"].as_str().expect("alert name");
            assert!(names.insert(alert.to_owned()), "duplicate alert {alert}");
            assert!(alert.starts_with("Crawlx"), "{alert}");
            let expr = r["expr"].as_str().expect("expr");
            assert!(r["for"].is_string(), "{alert}: `for` must be a duration string");
            let labels = r["labels"].as_object().expect("labels");
            assert!(
                matches!(labels["severity"].as_str(), Some("page" | "ticket")),
                "{alert}: severity must be page or ticket"
            );
            if let Some(slo) = labels.get("slo").and_then(Value::as_str) {
                slos.insert(slo.to_owned());
            }
            assert!(r["annotations"]["summary"].is_string(), "{alert}: summary");
            for m in crawlx_metrics(expr) {
                assert!(
                    known.contains(&m),
                    "{alert}: `{m}` is not a catalogued metric family"
                );
            }
        }
    }
    // six SLOs
    for slo in [
        "api_availability",
        "job_durability",
        "webhook_delivery",
        "stale_lease_reconciliation",
        "safety_hard_deny",
        "zdr_retention",
    ] {
        assert!(slos.contains(slo), "SLO {slo} has no alert");
    }
    // the exact thresholds
    let text = read("deploy/alerts/crawlx-rules.yaml");
    for needle in [
        "> 14.4 * 0.001",
        "> 6 * 0.001",
        "> 1 * 0.001",
        "crawlx_webhook_oldest_pending_age_seconds) > 900",
        "> 0.05",
        "< 0.5)",
        "< 0.999",
        "histogram_quantile(0.999",
        "* 60 > 10",
        "> 0.150",
        "> 0.005",
        "for: 24h",
    ] {
        assert!(text.contains(needle), "threshold {needle:?} missing");
    }
}

#[test]
fn dashboard_covers_every_plan_dashboard_with_catalogued_metrics() {
    let doc: Value = serde_json::from_str(&read("deploy/dashboards/crawlx.json")).unwrap();
    let known = exported_names();
    let panels = doc["panels"].as_array().unwrap();
    let rows: BTreeSet<&str> = panels
        .iter()
        .filter(|p| p["type"] == "row")
        .map(|p| p["title"].as_str().unwrap())
        .collect();
    for want in [
        "SLO overview",
        "Crawl health",
        "Sessions and browsers",
        "Journal and safety",
        "Scheduler and leases",
        "Storage",
        "Models",
        "Fetch and politeness",
        "Retention and webhooks",
        "Capacity",
    ] {
        assert!(
            rows.iter().any(|r| r.starts_with(want)),
            "dashboard row {want:?} missing in {rows:?}"
        );
    }
    let mut ids = BTreeSet::new();
    for p in panels {
        assert!(ids.insert(p["id"].as_u64().unwrap()), "duplicate panel id");
        for t in p["targets"].as_array().map(Vec::as_slice).unwrap_or_default() {
            for m in crawlx_metrics(t["expr"].as_str().unwrap()) {
                assert!(known.contains(&m), "{}: `{m}` is not catalogued", p["title"]);
            }
        }
    }
}

#[test]
fn seccomp_profile_allows_user_namespaces_and_nothing_wider() {
    let p: Value = serde_json::from_str(&read("docker/seccomp/crawlx-chromium.json")).unwrap();
    assert_eq!(p["defaultAction"], "SCMP_ACT_ERRNO");
    let mut allowed = BTreeSet::new();
    for rule in p["syscalls"].as_array().unwrap() {
        let unconditional = rule["action"] == "SCMP_ACT_ALLOW"
            && rule["includes"].as_object().is_none_or(serde_json::Map::is_empty)
            && rule["args"].as_array().is_none_or(Vec::is_empty);
        if unconditional {
            for n in rule["names"].as_array().unwrap() {
                allowed.insert(n.as_str().unwrap().to_owned());
            }
        }
    }
    for needed in [
        "clone",
        "clone3",
        "unshare",
        "chroot",
        "seccomp",
        "prctl",
        "execve",
        "futex",
        "epoll_wait",
    ] {
        assert!(
            allowed.contains(needed),
            "{needed} must be allowed for the Chromium sandbox"
        );
    }
    for denied in [
        "setns",
        "mount",
        "umount2",
        "pivot_root",
        "bpf",
        "kexec_load",
        "init_module",
        "reboot",
        "ptrace",
    ] {
        assert!(
            !allowed.contains(denied),
            "{denied} must not be allowed unconditionally"
        );
    }
}

#[test]
fn kubernetes_manifests_carry_the_plan_security_posture() {
    let worker = read("deploy/k8s/worker-deployment.yaml");
    for needle in [
        "runAsNonRoot: true",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        "localhostProfile: crawlx-chromium.json",
        "drop: [\"ALL\"]",
        "emptyDir: { medium: Memory, sizeLimit: 512Mi }",
        "emptyDir: { medium: Memory, sizeLimit: 1Gi }",
        "requests: { cpu: \"4\", memory: 8Gi }",
        "limits: { memory: 12Gi }",
    ] {
        assert!(worker.contains(needle), "worker deployment lacks {needle:?}");
    }
    assert!(!worker.contains("--no-sandbox"));
    assert!(!worker.contains("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI"));
    assert!(!worker.contains("CRAWLX_ALLOW_UNPINNED"));
    let np = read("deploy/k8s/networkpolicy.yaml");
    for cidr in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "fd00:ec2::254",
    ] {
        assert!(np.contains(cidr), "network policy does not deny {cidr}");
    }
    assert!(np.contains("app: crawlx-postgres") && np.contains("app: crawlx-model"));
    assert!(
        np.contains("crawlx-worker-deny-all-egress"),
        "RB-11 level 3 policy"
    );
    for f in [
        "deploy/k8s/api-deployment.yaml",
        "deploy/k8s/namespace.yaml",
        "deploy/k8s/networkpolicy.yaml",
        "deploy/k8s/worker-deployment.yaml",
    ] {
        for doc in read(f).split("\n---\n") {
            let v: Value = serde_yaml_ng::from_str(doc).unwrap_or_else(|e| panic!("{f}: {e}"));
            assert!(v["kind"].is_string(), "{f}: every document has a kind");
        }
    }
}

#[test]
fn dockerfiles_verify_the_pin_and_never_disable_the_sandbox() {
    let worker = read("docker/Dockerfile.worker");
    assert!(
        worker.contains("sha256sum -c"),
        "the archive is verified against the pin"
    );
    assert!(worker.contains("chromium-pin.toml"));
    assert!(worker.contains("USER 10001:10001"));
    assert!(!worker.contains("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI="));
    assert!(
        worker.contains("rm -rf") && worker.contains("/usr/bin/apt-get"),
        "no package manager in the runtime layer"
    );
    let api = read("docker/Dockerfile.api");
    assert!(api.contains("distroless/cc"));
    assert!(api.contains("USER 65532:65532"));
    assert!(api.contains("--locked"));
    let pin = read("chromium-pin.toml");
    let version = pin
        .lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')))
        .unwrap();
    assert!(
        read("deploy/k8s/worker-deployment.yaml").contains(&format!("chromium{version}")),
        "worker image tag carries the pinned Chromium version"
    );
    assert!(read("deploy/helm/crawlx/values.yaml").contains(&format!("chromiumVersion: \"{version}\"")));
}

#[test]
fn helm_configuration_passes_the_real_config_parser_and_validation() {
    let rendered = match std::process::Command::new("helm")
        .args(["template", "config-regression"])
        .arg(root().join("deploy/helm/crawlx"))
        .args(["--set", HELM_KEY_FILE, "--set", HELM_SECRET_REDIS])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: helm is not available");
            return;
        }
        Err(error) => panic!("cannot render chart: {error}"),
    };
    assert!(
        rendered.status.success(),
        "{}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let toml_text = serde_yaml_ng::Deserializer::from_slice(&rendered.stdout)
        .map(|document| <Value as serde::Deserialize>::deserialize(document).unwrap())
        .find_map(|document| document["data"]["crawlx.toml"].as_str().map(str::to_owned))
        .expect("rendered configuration");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("crawlx.toml");
    std::fs::write(&file, &toml_text).unwrap();
    let loaded = load_from(Some(&file), &[]).unwrap();
    // in the chart the secrets are files (missing on this host): errors are exactly those
    let (findings, _) = validate(&loaded);
    for f in findings.iter().filter(|f| f.error) {
        assert!(
            f.key.ends_with("_file"),
            "unexpected error from the chart's defaults: {f:?}"
        );
    }
}

/// Required custody values of the chart: it refuses to render without them.
const HELM_KEY_FILE: &str = "artifactCustody.keyFileSecret=crawlx-artifact-key";
const HELM_SECRET_REDIS: &str = "artifactCustody.secretRedis.existingSecret=crawlx-secret-registry";
const HELM_KMS: &str = "artifactCustody.kmsKeyId=arn:aws:kms:us-east-1:123456789012:key/operator-canary"; // wire-compat: key ARN shape

/// `helm template custody deploy/helm/crawlx --set …`; `None` when helm is not installed.
fn helm_template(sets: &[&str]) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new("helm");
    cmd.args(["template", "custody"])
        .arg(root().join("deploy/helm/crawlx"));
    for set in sets {
        cmd.arg("--set").arg(set);
    }
    match cmd.output() {
        Ok(output) => Some(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: helm is not available");
            None
        }
        Err(error) => panic!("cannot render chart: {error}"),
    }
}

fn rendered_documents(output: &std::process::Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_yaml_ng::Deserializer::from_slice(&output.stdout)
        .map(|document| <Value as serde::Deserialize>::deserialize(document).unwrap())
        .filter(|document| !document.is_null())
        .collect()
}

fn named<'a>(documents: &'a [Value], kind: &str, name: &str) -> Option<&'a Value> {
    documents
        .iter()
        .find(|d| d["kind"] == kind && d["metadata"]["name"] == name)
}

/// The literal environment (`name`/`value`) of the first container of a Deployment or Job.
fn container_env(workload: &Value) -> BTreeMap<String, String> {
    workload["spec"]["template"]["spec"]["containers"][0]["env"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| Some((e["name"].as_str()?.to_owned(), e["value"].as_str()?.to_owned())))
        .collect()
}

/// `(Secret name, projected file)` pairs of the workload's `secrets` volume.
fn projected_secrets(workload: &Value) -> BTreeSet<(String, String)> {
    workload["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "secrets")
        .unwrap()["projected"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| {
            let secret = &s["secret"];
            Some((
                secret["name"].as_str()?.to_owned(),
                secret["items"][0]["path"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

#[test]
fn helm_chart_refuses_to_render_without_complete_artifact_custody() {
    let no_ttl = "artifactCustody.secretRedis.ttlSeconds";
    let ttl_zero = format!("{no_ttl}=0");
    let ttl_over = format!("{no_ttl}=86401");
    for (sets, message) in [
        (&[][..], "requires an artifact key provider"),
        (&[HELM_SECRET_REDIS][..], "requires an artifact key provider"),
        (&[HELM_KEY_FILE][..], "secretRedis.existingSecret is required"),
        (&[HELM_KMS][..], "secretRedis.existingSecret is required"),
        (&[HELM_KEY_FILE, HELM_KMS, HELM_SECRET_REDIS][..], "mutually exclusive"),
        (&[HELM_KEY_FILE, HELM_SECRET_REDIS, ttl_zero.as_str()][..], "ttlSeconds must be 1..86400"),
        (&[HELM_KEY_FILE, HELM_SECRET_REDIS, ttl_over.as_str()][..], "ttlSeconds must be 1..86400"),
        (
            &[HELM_KEY_FILE, HELM_SECRET_REDIS, "capabilities.retainedProfiles.enabled=true"][..],
            "profile_unavailable: retained browser profiles are unavailable while encrypted artifact custody is enabled",
        ),
    ] {
        let Some(output) = helm_template(sets) else {
            return;
        };
        assert!(
            !output.status.success(),
            "{sets:?} must not render: custody is required"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "{sets:?}: {stderr}");
    }
}

#[test]
fn helm_chart_wires_artifact_custody_into_api_worker_and_config_check() {
    let Some(output) = helm_template(&[HELM_KEY_FILE, HELM_SECRET_REDIS]) else {
        return;
    };
    let documents = rendered_documents(&output);
    let api = named(&documents, "Deployment", "custody-api").expect("api deployment");
    let worker = named(&documents, "Deployment", "custody-worker").expect("worker deployment");
    let check = named(&documents, "Job", "custody-config-check").expect("config-check job");
    let key_file = ("crawlx-artifact-key".to_owned(), "artifact_key".to_owned());
    let registry = ("crawlx-secret-registry".to_owned(), "secret_redis_url".to_owned());
    // the API needs only the key provider: it decrypts for reads, never writes, and has no Redis URL
    let env = container_env(api);
    assert_eq!(
        env["CRAWLX_ARTIFACT_KEY_FILE"],
        "/run/secrets/crawlx/artifact_key"
    );
    for absent in [
        "CRAWLX_ARTIFACT_KMS_KEY_ID",
        "CRAWLX_SECRET_REDIS_URL",
        "CRAWLX_SECRET_REDIS_URL_FILE",
        "CRAWLX_SECRET_AUTHORITY_TTL_SECS",
    ] {
        assert!(!env.contains_key(absent), "api carries {absent}");
    }
    let secrets = projected_secrets(api);
    assert!(secrets.contains(&key_file) && !secrets.contains(&registry));
    // workers and the pre-roll config check carry the key provider, the registry URL and the lifetime
    for workload in [worker, check] {
        let env = container_env(workload);
        assert_eq!(
            env["CRAWLX_ARTIFACT_KEY_FILE"],
            "/run/secrets/crawlx/artifact_key"
        );
        assert_eq!(
            env["CRAWLX_SECRET_REDIS_URL_FILE"],
            "/run/secrets/crawlx/secret_redis_url"
        );
        assert_eq!(env["CRAWLX_SECRET_AUTHORITY_TTL_SECS"], "86400");
        assert!(!env.contains_key("CRAWLX_ARTIFACT_KMS_KEY_ID"));
        assert!(
            !env.contains_key("CRAWLX_SECRET_REDIS_URL"),
            "the URL is a file, never an env value"
        );
        let secrets = projected_secrets(workload);
        assert!(secrets.contains(&key_file) && secrets.contains(&registry));
    }
    // the chart runs no registry unless asked: the operator supplies the Redis by default
    assert!(named(&documents, "Deployment", "custody-secret-registry").is_none());
    // the KMS provider replaces the key file entirely; the lifetime is configurable
    let Some(output) = helm_template(&[
        HELM_KMS,
        HELM_SECRET_REDIS,
        "artifactCustody.secretRedis.ttlSeconds=3600",
    ]) else {
        return;
    };
    let documents = rendered_documents(&output);
    for (kind, name) in [
        ("Deployment", "custody-api"),
        ("Deployment", "custody-worker"),
        ("Job", "custody-config-check"),
    ] {
        let workload = named(&documents, kind, name).unwrap();
        let env = container_env(workload);
        assert_eq!(
            env["CRAWLX_ARTIFACT_KMS_KEY_ID"],
            "arn:aws:kms:us-east-1:123456789012:key/operator-canary", // wire-compat: key ARN shape
            "{name}"
        );
        assert!(!env.contains_key("CRAWLX_ARTIFACT_KEY_FILE"), "{name}");
        assert!(!projected_secrets(workload).contains(&key_file), "{name}");
        if name != "custody-api" {
            assert_eq!(env["CRAWLX_SECRET_AUTHORITY_TTL_SECS"], "3600", "{name}");
        }
    }
}

#[test]
fn helm_managed_secret_registry_is_volatile_noeviction_and_reachable_only_by_workers() {
    let Some(output) = helm_template(&[
        HELM_KEY_FILE,
        HELM_SECRET_REDIS,
        "artifactCustody.secretRedis.managed.enabled=true",
    ]) else {
        return;
    };
    let documents = rendered_documents(&output);
    let registry = named(&documents, "Deployment", "custody-secret-registry").expect("registry deployment");
    let container = &registry["spec"]["template"]["spec"]["containers"][0];
    let args: Vec<&str> = container["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    for pair in [
        ["--save", ""],
        ["--appendonly", "no"],
        ["--maxmemory-policy", "noeviction"],
        ["--protected-mode", "yes"],
    ] {
        assert!(args.windows(2).any(|w| w == pair), "{pair:?} missing in {args:?}");
    }
    assert!(args.contains(&"--aclfile") && args.contains(&"--maxmemory"));
    assert_eq!(registry["spec"]["strategy"]["type"], "Recreate");
    assert!(
        registry["spec"]["template"]["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v.get("persistentVolumeClaim").is_none()),
        "the registry has no persistent volume"
    );
    assert!(named(&documents, "Service", "custody-secret-registry").is_some());
    let policy = named(&documents, "NetworkPolicy", "custody-secret-registry").expect("registry policy");
    let from = policy["spec"]["ingress"][0]["from"].as_array().unwrap();
    assert_eq!(from.len(), 1, "only workers may connect");
    assert_eq!(from[0]["podSelector"]["matchLabels"]["app"], "crawlx-worker");
    assert_eq!(policy["spec"]["egress"], serde_json::json!([]));
    // the managed registry still needs its Secret (keys url and users.acl): no silent default
    let Some(refused) = helm_template(&[HELM_KEY_FILE, "artifactCustody.secretRedis.managed.enabled=true"])
    else {
        return;
    };
    assert!(!refused.status.success());
}

#[test]
fn ci_images_job_builds_tests_scans_and_pins_actions() {
    let ci = read(".github/workflows/ci.yml");
    let job = ci.split("\n  images:\n").nth(1).expect("images job");
    for needle in [
        "docker/Dockerfile.api",
        "docker/Dockerfile.worker",
        "ci/container-policy-test.sh",
        "anchore/syft",
        "aquasec/trivy",
        "--severity CRITICAL --exit-code 1",
        "promtool",
    ] {
        assert!(job.contains(needle), "images job lacks {needle:?}");
    }
    for line in ci.lines().filter(|l| l.trim_start().starts_with("- uses:")) {
        let sha = line.split('@').nth(1).unwrap().split_whitespace().next().unwrap();
        assert!(
            sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "unpinned action: {line}"
        );
    }
}

// ---- docker/docker-compose.yml ------------------------------------------

const COMPOSE: &str = "docker/docker-compose.yml";

fn compose() -> Value {
    serde_yaml_ng::from_str(&read(COMPOSE)).unwrap()
}

fn service<'a>(stack: &'a Value, name: &str) -> &'a Value {
    let svc = &stack["services"][name];
    assert!(svc.is_object(), "docker-compose.yml has no service {name:?}");
    svc
}

/// `${NAME:-default}` as Compose interpolates it when the variable is unset. Any other form
/// (`${NAME}`, `${NAME:?...}`) is refused: the stack must validate and start with defaults only.
fn expand(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(rest.get(..start).unwrap());
        let after = rest.get(start + 2..).unwrap();
        let end = after
            .find('}')
            .unwrap_or_else(|| panic!("unterminated `${{` in {text:?}"));
        let (_, default) = after
            .get(..end)
            .unwrap()
            .split_once(":-")
            .unwrap_or_else(|| panic!("{text:?}: only `${{NAME:-default}}` interpolation is allowed"));
        out.push_str(default);
        rest = after.get(end + 1..).unwrap();
    }
    out.push_str(rest);
    out
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| expand(s.as_str().unwrap())).collect())
        .unwrap_or_default()
}

/// The `environment:` of a service as written (interpolation not yet expanded).
fn raw_env(svc: &Value) -> BTreeMap<String, String> {
    match &svc["environment"] {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_owned)))
            .collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(|e| {
                let (k, v) = e.split_once('=').unwrap_or((e, ""));
                (k.to_owned(), v.to_owned())
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn image_of(stack: &Value, name: &str) -> String {
    expand(service(stack, name)["image"].as_str().unwrap())
}

fn tag_of(image: &str) -> Option<&str> {
    image
        .rsplit_once(':')
        .map(|(_, tag)| tag)
        .filter(|t| !t.contains('/'))
}

/// `crawlx <args>` parsed by the real command-line definition.
fn parse_cli(args: &[String]) -> Cli {
    Cli::try_parse_from(std::iter::once("crawlx".to_owned()).chain(args.iter().cloned()))
        .unwrap_or_else(|e| panic!("{args:?} is not a valid crawlx command line: {e}"))
}

/// The command line of a crawlx service, parsed: the subcommand and flags of `command:`, after
/// the arguments an `entrypoint: [crawlx, admin]` fixes (the binary path itself is skipped).
fn cli_of(stack: &Value, name: &str) -> Cli {
    let svc = service(stack, name);
    let mut args: Vec<String> = strings(&svc["entrypoint"]).into_iter().skip(1).collect();
    args.extend(strings(&svc["command"]));
    parse_cli(&args)
}

#[test]
fn compose_stack_has_the_services_and_builds_from_the_repository_dockerfiles() {
    let stack = compose();
    for name in [
        "postgres",
        "migrate",
        "api",
        "worker",
        "minio",
        "minio-init",
        "gym",
        "admin",
        "secret-custody",
    ] {
        service(&stack, name);
    }
    let repo = root().canonicalize().unwrap();
    let compose_dir = root().join("docker");
    let wiring = [
        ("migrate", "docker/Dockerfile.api"),
        ("api", "docker/Dockerfile.api"),
        ("admin", "docker/Dockerfile.api"),
        ("worker", "docker/Dockerfile.worker"),
        ("artifacts-init", "docker/Dockerfile.worker"),
        ("gym", "docker/Dockerfile.gym"),
    ];
    for (name, dockerfile) in wiring {
        let build = &service(&stack, name)["build"];
        assert_eq!(build["dockerfile"], dockerfile, "{name}");
        let context = compose_dir
            .join(build["context"].as_str().unwrap())
            .canonicalize()
            .unwrap();
        assert_eq!(context, repo, "{name}: the build context is the repository root");
        assert!(context.join(dockerfile).is_file(), "{name}: {dockerfile} exists");
        for arg in build["args"].as_object().into_iter().flat_map(|a| a.keys()) {
            assert!(
                read(dockerfile).contains(&format!("ARG {arg}")),
                "{name}: build arg {arg} is not an ARG of {dockerfile}"
            );
        }
    }
    // every build in the file is one of the wired ones (no stray Dockerfile reference)
    let built: BTreeSet<_> = stack["services"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, s)| s.get("build").is_some())
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(built, wiring.iter().map(|(n, _)| *n).collect::<BTreeSet<_>>());
    // services that share a Dockerfile share its image, so one `build` serves them all
    assert_eq!(image_of(&stack, "api"), image_of(&stack, "migrate"));
    assert_eq!(image_of(&stack, "api"), image_of(&stack, "admin"));
    assert_eq!(image_of(&stack, "worker"), image_of(&stack, "artifacts-init"));
    // the fixture server is staging/CI only: behind a profile, and no other service needs it
    assert_eq!(service(&stack, "gym")["profiles"], serde_json::json!(["smoke"]));
    assert_eq!(service(&stack, "admin")["profiles"], serde_json::json!(["ops"]));
    for (name, svc) in stack["services"].as_object().unwrap() {
        assert!(
            svc["depends_on"].get("gym").is_none(),
            "{name} depends on the smoke-only gym service"
        );
    }
}

#[test]
fn compose_images_are_pinned_and_match_the_chart_and_the_chromium_pin() {
    let stack = compose();
    for (name, svc) in stack["services"].as_object().unwrap() {
        let image = expand(svc["image"].as_str().unwrap());
        let tag = tag_of(&image).unwrap_or_else(|| panic!("{name}: image {image:?} has no tag"));
        assert!(
            !tag.is_empty() && !tag.contains("latest"),
            "{name}: {image:?} is not pinned"
        );
        for base in svc["build"]["args"]
            .as_object()
            .into_iter()
            .flat_map(|a| a.values())
        {
            let base = base.as_str().unwrap();
            assert!(
                tag_of(base).is_some_and(|t| !t.contains("latest")),
                "{name}: base image {base:?} is not pinned"
            );
        }
    }
    let values: Value = serde_yaml_ng::from_str(&read("deploy/helm/crawlx/values.yaml")).unwrap();
    let chart_tag = values["image"]["tag"].as_str().unwrap();
    let workspace = read("Cargo.toml");
    let version = workspace
        .lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')))
        .unwrap();
    assert_eq!(
        chart_tag,
        format!("v{version}"),
        "chart image tag follows the workspace version"
    );
    let pin = read("chromium-pin.toml");
    let chromium = pin
        .lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')))
        .unwrap();
    let registry = values["image"]["registry"].as_str().unwrap();
    assert_eq!(
        image_of(&stack, "api"),
        format!("{registry}/crawlx-api:{chart_tag}")
    );
    assert_eq!(
        image_of(&stack, "gym"),
        format!("{registry}/crawlx-gym:{chart_tag}")
    );
    assert_eq!(
        image_of(&stack, "worker"),
        format!("{registry}/crawlx-worker:{chart_tag}-chromium{chromium}"),
        "worker tag is <tag>-chromium<pin version>"
    );
    // the same PostgreSQL major as the development stack, the same MinIO image as CI
    let dev: Value = serde_yaml_ng::from_str(&read("docker/docker-compose.dev.yaml")).unwrap();
    assert_eq!(
        image_of(&stack, "postgres"),
        dev["services"]["postgres"]["image"].as_str().unwrap()
    );
    let minio = image_of(&stack, "minio");
    assert!(
        read(".github/workflows/ci.yml").contains(&minio),
        "{minio} is not the CI MinIO image"
    );
    assert_eq!(image_of(&stack, "minio-init"), minio);
}

#[test]
fn compose_environment_keeps_credentials_in_mounted_secrets_and_worker_paths_on_tmpfs() {
    let stack = compose();
    // variables read by the third-party images the stack runs, per service
    let foreign: BTreeMap<&str, &[&str]> = BTreeMap::from([
        (
            "postgres",
            &["POSTGRES_USER", "POSTGRES_DB", "POSTGRES_PASSWORD_FILE"][..],
        ),
        ("minio", &["MINIO_ROOT_USER_FILE", "MINIO_ROOT_PASSWORD_FILE"][..]),
        ("minio-init", &["BUCKET", "MC_CONFIG_DIR"][..]),
    ]);
    for (name, svc) in stack["services"].as_object().unwrap() {
        for var in raw_env(svc).keys() {
            if foreign
                .get(name.as_str())
                .is_some_and(|l| l.contains(&var.as_str()))
            {
                continue;
            }
            match var.as_str() {
                // The worker's temp directory must be backed by tmpfs.
                "TMPDIR" => {
                    assert_eq!(name, "worker");
                    let prefix = format!("{}:", raw_env(svc)["TMPDIR"]);
                    assert!(strings(&svc["tmpfs"])
                        .iter()
                        .any(|mount| mount.starts_with(&prefix)));
                }
                // Chromium's config/crash directory: must be writable under the read-only root
                "HOME" => {
                    assert_eq!(name, "worker");
                    assert!(
                        raw_env(svc)["HOME"].starts_with("/tmp/crawlx/"),
                        "HOME must live on the worker's tmpfs"
                    );
                }
                // read by `S3Blobs::new` through the SDK's environment credentials provider
                "AWS_ACCESS_KEY_ID" | "AWS_SECRET_ACCESS_KEY" => {
                    // wire-compat: SDK credential variables
                    assert_eq!(
                        name, "admin",
                        "object-store credentials belong to the object-store admin runner"
                    );
                }
                _ => {
                    assert!(
                        var.starts_with("CRAWLX_"),
                        "{name}: {var} is not a crawlx variable"
                    );
                }
            }
        }
    }
    // Secret file references must name declared secrets mounted into the same service.
    let secrets = stack["secrets"].as_object().unwrap();
    for (name, svc) in stack["services"].as_object().unwrap() {
        let mounted: BTreeSet<_> = svc["secrets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        // KMS key IDs identify public resources; they are not encryption key material.
        for (var, value) in raw_env(svc) {
            if var.ends_with("_FILE") {
                let secret = value
                    .strip_prefix("/run/secrets/")
                    .unwrap_or_else(|| panic!("{name}: {var}={value}"));
                assert!(
                    mounted.contains(secret),
                    "{name}: {var} names {secret}, which is not mounted"
                );
            } else if var != "CRAWLX_CHECKPOINT_KMS_KEY_ID"
                && ["PASSWORD", "SECRET", "TOKEN", "KEY"]
                    .iter()
                    .any(|w| var.contains(w))
            {
                assert!(
                    value.starts_with("${") && name == "admin",
                    "{name}: {var} carries a secret value instead of a *_FILE reference"
                );
            }
        }
        for secret in &mounted {
            assert!(secrets.contains_key(secret), "{name}: undeclared secret {secret}");
        }
    }
    let api_env = raw_env(service(&stack, "api"));
    assert!(
        api_env.contains_key("CRAWLX_DATABASE_URL_FILE")
            && api_env.contains_key("CRAWLX_WEBHOOK_SECRET_FILE")
    );
    assert!(raw_env(service(&stack, "worker")).contains_key("CRAWLX_DATABASE_URL_FILE"));
    // Custody: the key file reaches api and worker, the registry URL only the worker. The KMS
    // key id is the mutually exclusive alternative to the key file, so it is never offered next to it.
    let worker_env = raw_env(service(&stack, "worker"));
    assert_eq!(api_env["CRAWLX_ARTIFACT_KEY_FILE"], "/run/secrets/artifact_key");
    assert_eq!(
        worker_env["CRAWLX_ARTIFACT_KEY_FILE"],
        "/run/secrets/artifact_key"
    );
    assert_eq!(
        worker_env["CRAWLX_SECRET_REDIS_URL_FILE"],
        "/run/secrets/secret_custody_redis_url"
    );
    assert!(!api_env.contains_key("CRAWLX_SECRET_REDIS_URL_FILE"));
    for (name, svc) in stack["services"].as_object().unwrap() {
        for banned in ["CRAWLX_ARTIFACT_KMS_KEY_ID", "CRAWLX_SECRET_REDIS_URL"] {
            assert!(
                !raw_env(svc).contains_key(banned),
                "{name}: {banned} must not be set (key file and KMS are exclusive; the URL is a *_FILE)"
            );
        }
    }
    let worker_secrets = strings(&service(&stack, "worker")["secrets"]);
    let api_secrets = strings(&service(&stack, "api")["secrets"]);
    assert!(worker_secrets.contains(&"artifact_key".to_owned()));
    assert!(worker_secrets.contains(&"secret_custody_redis_url".to_owned()));
    assert!(api_secrets.contains(&"artifact_key".to_owned()));
    assert!(
        !api_secrets.iter().any(|s| s.starts_with("secret_custody")),
        "the API never reaches the secret registry"
    );
}

#[test]
fn compose_commands_are_valid_crawlx_command_lines_matching_the_kubernetes_manifests() {
    let stack = compose();
    // api: binds the container's interfaces, metrics stay on loopback
    let Command::Serve(serve) = cli_of(&stack, "api").command else {
        panic!("api runs `crawlx serve`")
    };
    assert!(
        !serve.bind.ip().is_loopback(),
        "the API must bind a non-loopback address in the container"
    );
    assert_eq!(serve.bind.port(), 8080);
    assert!(serve.metrics_bind.is_some_and(|m| m.ip().is_loopback()));
    assert_eq!(
        serve.api_keys.len(),
        1,
        "the bootstrap key comes from CRAWLX_API_KEY_SPEC"
    );
    // worker: the same limits as the chart
    let values: Value = serde_yaml_ng::from_str(&read("deploy/helm/crawlx/values.yaml")).unwrap();
    let Command::Worker(worker) = cli_of(&stack, "worker").command else {
        panic!("worker runs `crawlx worker`")
    };
    assert_eq!(
        worker.max_sessions as u64,
        values["config"]["worker"]["max_sessions"].as_u64().unwrap()
    );
    assert_eq!(
        worker.contexts_per_browser as u64,
        values["config"]["worker"]["contexts_per_browser"]
            .as_u64()
            .unwrap()
    );
    assert!(worker.metrics_bind.is_some_and(|m| m.ip().is_loopback()));
    assert!(matches!(cli_of(&stack, "migrate").command, Command::Migrate(_)));
    assert!(matches!(cli_of(&stack, "admin").command, Command::Admin(_)));
    // the flags the Kubernetes manifests pass are the ones compose passes
    for (svc, manifest) in [("api", "api-deployment"), ("worker", "worker-deployment")] {
        let k8s = read(&format!("deploy/k8s/{manifest}.yaml"));
        for arg in strings(&service(&stack, svc)["command"]) {
            if arg.starts_with("--artifacts-dir=")
                || arg.starts_with("--metrics-bind=")
                || arg.starts_with("--max-sessions=")
            {
                assert!(
                    k8s.contains(&arg),
                    "{svc}: {arg} differs from deploy/k8s/{manifest}.yaml"
                );
            }
        }
    }
    // the shared artifact store: one directory, one volume, mounted by api, worker and admin
    for svc in ["api", "worker", "admin"] {
        let mounts = strings(&service(&stack, svc)["volumes"]);
        assert!(
            mounts.contains(&"artifacts:/var/lib/crawlx/artifacts".to_owned()),
            "{svc}"
        );
    }
    // Health checks use the real command-line parser and target the expected local listeners.
    for (svc, port, path) in [
        ("api", serve.bind.port(), "/v0/health/readiness"),
        ("worker", 9464, "/metrics"),
    ] {
        let test = strings(&service(&stack, svc)["healthcheck"]["test"]);
        assert_eq!(
            test.first().map(String::as_str),
            Some("CMD"),
            "{svc}: exec form, no shell"
        );
        assert_eq!(test.get(1).map(String::as_str), Some("/usr/local/bin/crawlx"));
        let Command::Healthcheck(probe) = parse_cli(test.get(2..).unwrap()).command else {
            panic!("{svc}: the health check is `crawlx healthcheck`")
        };
        assert!(probe.url.host_str().is_some_and(|h| h == "127.0.0.1"));
        assert_eq!((probe.url.port(), probe.url.path()), (Some(port), path), "{svc}");
    }
    assert_eq!(
        worker.metrics_bind.map(|m| m.port()),
        Some(9464),
        "the worker probe reads its own metrics listener"
    );
}

/// `[host_ip, host_port, container_port]` of one published port, interpolation expanded.
fn published(port: &str) -> Vec<String> {
    expand(port).split(':').map(str::to_owned).collect()
}

#[test]
fn compose_publishes_only_the_api_and_only_on_loopback_by_default() {
    let stack = compose();
    for (name, svc) in stack["services"].as_object().unwrap() {
        let ports = svc["ports"].as_array().cloned().unwrap_or_default();
        if name != "api" {
            assert!(
                ports.is_empty(),
                "{name} must not publish ports (postgres and MinIO are internal)"
            );
            continue;
        }
        assert_eq!(ports.len(), 1);
        let parts = published(ports[0].as_str().unwrap());
        assert_eq!(
            parts,
            ["127.0.0.1", "8080", "8080"],
            "the API is published on 127.0.0.1 by default"
        );
    }
    // PostgreSQL and MinIO sit on the internal network only
    assert_eq!(stack["networks"]["backend"]["internal"], true);
    // the secret registry is internal too, and publishes nothing
    for name in ["postgres", "minio", "minio-init", "migrate", "secret-custody"] {
        assert_eq!(
            service(&stack, name)["networks"],
            serde_json::json!(["backend"]),
            "{name}"
        );
    }
    // targets are reached over the other network only by the services that need it
    for name in ["api", "worker"] {
        let nets = strings(&service(&stack, name)["networks"]);
        assert!(
            nets.contains(&"backend".to_owned()) && nets.contains(&"frontend".to_owned()),
            "{name}"
        );
    }
    assert_eq!(service(&stack, "artifacts-init")["network_mode"], "none");
}

#[test]
fn compose_worker_and_services_carry_the_plan_security_posture() {
    let stack = compose();
    let worker = service(&stack, "worker");
    let opts = strings(&worker["security_opt"]);
    let profile = opts
        .iter()
        .find_map(|o| o.strip_prefix("seccomp="))
        .expect("the worker runs under the crawlx-chromium seccomp profile");
    assert!(
        root().join("docker").join(profile).canonicalize().unwrap()
            == root()
                .join("docker/seccomp/crawlx-chromium.json")
                .canonicalize()
                .unwrap(),
        "seccomp profile path {profile}"
    );
    assert!(opts.iter().all(|o| !o.contains("unconfined")));
    assert_eq!(worker["read_only"], true);
    assert_eq!(worker["cap_drop"], serde_json::json!(["ALL"]));
    assert!(worker.get("cap_add").is_none() && worker.get("privileged").is_none());
    assert!(
        strings(&worker["tmpfs"])
            .iter()
            .any(|t| t.starts_with("/tmp/crawlx:")),
        "Chromium profiles on tmpfs"
    );
    assert!(
        worker["shm_size"].as_str().is_some(),
        "/dev/shm is sized, not disabled"
    );
    let limits = &worker["deploy"]["resources"]["limits"];
    let values: Value = serde_yaml_ng::from_str(&read("deploy/helm/crawlx/values.yaml")).unwrap();
    assert_eq!(
        limits["pids"], values["worker"]["pids"],
        "pid cap follows the chart"
    );
    assert_eq!(limits["memory"], "12G");
    let env = raw_env(worker);
    for banned in ["CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI", "CRAWLX_ALLOW_UNPINNED"] {
        assert!(
            !env.contains_key(banned),
            "{banned} must never be set in the production stack"
        );
    }
    assert!(!strings(&worker["command"])
        .iter()
        .any(|a| a.contains("no-sandbox")));
    // every service: no privileged mode, no capability added except the one-shot chown, no root
    for (name, svc) in stack["services"].as_object().unwrap() {
        assert!(svc.get("privileged").is_none(), "{name}");
        assert!(
            svc["deploy"]["resources"]["limits"]["memory"].is_string(),
            "{name}: memory limit"
        );
        let user = svc["user"].as_str();
        match name.as_str() {
            "artifacts-init" => {
                assert_eq!(user, Some("0:0"));
                assert_eq!(svc["cap_add"], serde_json::json!(["CHOWN", "FOWNER"]));
            }
            _ => {
                assert!(svc.get("cap_add").is_none(), "{name}");
                if let Some(u) = user {
                    assert!(
                        u.split(':').all(|p| p.parse::<u32>().is_ok_and(|n| n != 0)),
                        "{name}: user {u}"
                    );
                }
            }
        }
        if name != "postgres" && name != "minio" {
            assert_eq!(svc["read_only"], true, "{name}: read-only root filesystem");
        }
        if name != "postgres" {
            assert_eq!(svc["cap_drop"], serde_json::json!(["ALL"]), "{name}");
        }
        assert!(
            strings(&svc["security_opt"]).contains(&"no-new-privileges:true".to_owned())
                || name == "postgres",
            "{name}"
        );
    }
    // api and worker share uid 10001 so both can write the shared artifact directory
    assert_eq!(service(&stack, "api")["user"], "10001:10001");
    assert!(read("docker/Dockerfile.worker").contains("USER 10001:10001"));
    // the pin check searches the working directory and its ancestors: the image's working
    // directory is the one holding the pin file (from `/` a launch fails: "pin file not found")
    let worker_dockerfile = read("docker/Dockerfile.worker");
    assert!(worker_dockerfile.contains("COPY chromium-pin.toml /etc/crawlx/chromium-pin.toml"));
    assert!(worker_dockerfile.contains("WORKDIR /etc/crawlx\n"));
    // the gates directory the worker reads is a read-only mount of the host's docker/gates
    let worker_volumes = strings(&worker["volumes"]);
    assert!(
        worker_volumes.contains(&"./gates:/etc/crawlx/gates:ro".to_owned()),
        "{worker_volumes:?}"
    );
    assert_eq!(raw_env(worker)["CRAWLX_GATES_DIR"], "/etc/crawlx/gates");
    // `crawlx serve` and the gym stop on SIGINT only
    assert_eq!(service(&stack, "api")["stop_signal"], "SIGINT");
    assert_eq!(service(&stack, "gym")["stop_signal"], "SIGINT");
    // the secret registry: volatile (no RDB/AOF), noeviction, bounded, internal, no persistent volume
    let custody = service(&stack, "secret-custody");
    let command = strings(&custody["command"]).join(" ");
    for needle in [
        "--save \"\"",
        "--appendonly no",
        "--maxmemory-policy noeviction",
        "--maxmemory 256mb",
        "--protected-mode yes",
        "--aclfile",
    ] {
        assert!(
            command.contains(needle),
            "secret-custody lacks {needle:?}: {command}"
        );
    }
    assert!(
        !command.contains("--requirepass"),
        "the password comes from the mounted secret through the ACL file, never an argument"
    );
    assert!(custody.get("volumes").is_none() && custody.get("ports").is_none());
    assert_eq!(custody["networks"], serde_json::json!(["backend"]));
    assert_eq!(
        strings(&custody["secrets"]),
        ["secret_custody_redis_password"],
        "the registry sees its password only"
    );
}

#[test]
fn compose_services_have_healthchecks_and_start_in_dependency_order() {
    let stack = compose();
    for name in ["postgres", "minio", "api", "worker", "gym", "secret-custody"] {
        let test = &service(&stack, name)["healthcheck"]["test"];
        assert!(
            test.as_array().is_some_and(|t| t.len() >= 2),
            "{name}: healthcheck.test"
        );
        assert!(
            service(&stack, name)["healthcheck"]["interval"].is_string(),
            "{name}: interval"
        );
    }
    for name in ["postgres", "minio", "api", "worker", "secret-custody"] {
        assert_eq!(service(&stack, name)["restart"], "unless-stopped", "{name}");
    }
    for name in ["migrate", "minio-init", "artifacts-init", "admin", "gym"] {
        assert_eq!(
            service(&stack, name)["restart"],
            "no",
            "{name}: one-shot or smoke-only"
        );
    }
    let condition = |svc: &str, dep: &str| {
        service(&stack, svc)["depends_on"][dep]["condition"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(condition("migrate", "postgres"), "service_healthy");
    for svc in ["api", "worker"] {
        assert_eq!(condition(svc, "postgres"), "service_healthy", "{svc}");
        assert_eq!(
            condition(svc, "migrate"),
            "service_completed_successfully",
            "{svc}: `crawlx migrate` first"
        );
        assert_eq!(
            condition(svc, "artifacts-init"),
            "service_completed_successfully",
            "{svc}"
        );
    }
    assert_eq!(condition("minio-init", "minio"), "service_healthy");
    assert_eq!(condition("admin", "minio-init"), "service_completed_successfully");
    // workers wait for the volatile secret registry; the API never talks to it
    assert_eq!(condition("worker", "secret-custody"), "service_healthy");
    assert!(service(&stack, "api")["depends_on"]
        .get("secret-custody")
        .is_none());
    // `docker compose up --wait` rejects a requested one-shot that exited, so every one-shot of
    // the default profile must be somebody's `service_completed_successfully` dependency
    for (name, svc) in stack["services"].as_object().unwrap() {
        if svc["restart"] == "no" && svc.get("profiles").is_none() {
            let needed = stack["services"].as_object().unwrap().values().any(|other| {
                other["depends_on"][name.as_str()]["condition"] == "service_completed_successfully"
            });
            assert!(
                needed,
                "one-shot {name} is not a dependency of any default-profile service"
            );
        }
    }
    // the migrate one-shot uses the DDL role's DSN, not the application role's
    assert_eq!(
        raw_env(service(&stack, "migrate"))["CRAWLX_DATABASE_URL_FILE"],
        "/run/secrets/database_url_migrate"
    );
    assert_eq!(strings(&service(&stack, "migrate")["command"]), ["migrate"]);
}

/// Run `docker compose <args>` from the repository root; `None` when the plugin is missing.
fn docker_compose(args: &[&str], env: &[(&str, &str)]) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose").args(args).current_dir(root());
    for var in [
        "CRAWLX_SECRETS_DIR",
        "CRAWLX_API_BIND",
        "CRAWLX_API_PORT",
        "CRAWLX_TAG",
        "CRAWLX_REGISTRY",
        "CRAWLX_CHECKPOINT_KMS_KEY_ID",
    ] {
        cmd.env_remove(var);
    }
    cmd.envs(env.iter().copied());
    cmd.output().ok()
}

/// Is the `docker compose` plugin installed (`config` needs no daemon)?
fn compose_available() -> bool {
    docker_compose(&["version"], &[]).is_some_and(|o| o.status.success())
}

#[test]
fn docker_compose_accepts_the_stack_and_the_helper_scripts_are_sound() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for script in ["ci/compose-smoke.sh", "docker/init-compose.sh"] {
            let mode = std::fs::metadata(root().join(script))
                .unwrap()
                .permissions()
                .mode();
            assert!(mode & 0o111 != 0, "{script} is not executable");
            let text = read(script);
            assert!(
                text.starts_with("#!/usr/bin/env bash\n") && text.contains("set -euo pipefail"),
                "{script}"
            );
            if let Ok(out) = std::process::Command::new("bash")
                .arg("-n")
                .arg(script)
                .current_dir(root())
                .output()
            {
                assert!(
                    out.status.success(),
                    "bash -n {script}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
    if !compose_available() {
        eprintln!("skipping: `docker compose` is not available");
        return;
    }
    for profiles in [&[][..], &["--profile", "smoke", "--profile", "ops"][..]] {
        let mut args = vec!["-f", COMPOSE];
        args.extend_from_slice(profiles);
        args.extend(["config", "-q"]);
        let out = docker_compose(&args, &[]).unwrap();
        assert!(
            out.status.success(),
            "docker compose {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn init_compose_writes_secrets_and_an_api_key_the_server_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let run = || {
        std::process::Command::new("bash")
            .arg(root().join("docker/init-compose.sh"))
            .arg(dir.path())
            .output()
    };
    let Ok(first) = run().map(|o| (o.status.success(), o)) else {
        eprintln!("skipping: bash is not available");
        return;
    };
    assert!(first.0, "{}", String::from_utf8_lossy(&first.1.stderr));
    let secrets = dir.path().join("secrets");
    let before: BTreeMap<_, _> = std::fs::read_dir(&secrets)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().into_string().unwrap(),
                std::fs::read_to_string(e.path()).unwrap(),
            )
        })
        .collect();
    let declared: BTreeSet<String> = compose()["secrets"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(before.keys().cloned().collect::<BTreeSet<_>>(), declared);
    assert!(
        before["database_url"].starts_with("postgres://crawlx:"),
        "{}",
        before["database_url"]
    );
    assert!(before["database_url"].contains(before["postgres_password"].trim()));
    assert_eq!(before["database_url"], before["database_url_migrate"]);
    // Custody secrets: the key is 64 hex characters, the registry URL carries its password
    let artifact_key = &before["artifact_key"];
    assert!(
        artifact_key.len() == 64 && artifact_key.chars().all(|c| c.is_ascii_hexdigit()),
        "artifact_key must be exactly 64 hexadecimal characters"
    );
    assert_eq!(
        before["secret_custody_redis_url"],
        format!(
            "redis://:{}@secret-custody:6379/",
            before["secret_custody_redis_password"].trim()
        )
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&secrets), 0o700);
        assert_eq!(mode(&secrets.join("database_url")), 0o444);
        assert_eq!(mode(&secrets.join("artifact_key")), 0o444);
        assert_eq!(mode(&dir.path().join(".env")), 0o600);
    }
    let env = std::fs::read_to_string(dir.path().join(".env")).unwrap();
    let spec = env
        .lines()
        .find_map(|l| l.strip_prefix("CRAWLX_API_KEY_SPEC=\""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap();
    let (tenant, key) = spec.split_once('=').unwrap();
    assert_eq!(tenant, "default");
    assert!(
        crawlx_api::auth::parse_key(key).is_some(),
        "{key} is not an API key the server accepts"
    );
    assert!(env.contains(&format!(
        "CRAWLX_SECRETS_DIR=\"{}\"",
        secrets.canonicalize().unwrap().display()
    )));
    // a second run keeps every file: the PostgreSQL password is fixed once its volume exists
    assert!(run().unwrap().status.success());
    for (name, text) in &before {
        assert_eq!(
            &std::fs::read_to_string(secrets.join(name)).unwrap(),
            text,
            "{name} was rewritten"
        );
    }
    assert_eq!(std::fs::read_to_string(dir.path().join(".env")).unwrap(), env);
    // the generated environment makes the stack validate with the real secret paths
    let env_file = dir.path().join(".env");
    if compose_available() {
        let args = [
            "-f",
            COMPOSE,
            "--env-file",
            env_file.to_str().unwrap(),
            "--profile",
            "smoke",
            "--profile",
            "ops",
            "config",
            "-q",
        ];
        let out = docker_compose(&args, &[]).unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn checkpoint_kms_deployment_setting_is_opt_in_without_a_default_key() {
    let stack = compose();
    let setting = "CRAWLX_CHECKPOINT_KMS_KEY_ID";
    let worker_env = service(&stack, "worker")["environment"].as_object().unwrap();
    assert!(worker_env.contains_key(setting));
    assert!(
        worker_env[setting].is_null(),
        "Compose must pass through only an explicitly set host value"
    );
    assert!(!raw_env(service(&stack, "api")).contains_key(setting));
    let values: Value = serde_yaml_ng::from_str(&read("deploy/helm/crawlx/values.yaml")).unwrap();
    assert_eq!(values["capabilities"]["checkpointEncryption"]["kmsKeyId"], "");
    let helpers = read("deploy/helm/crawlx/templates/_helpers.tpl");
    assert!(helpers.contains("{{- if $c.checkpointEncryption.kmsKeyId }}"));
    assert!(helpers.contains("- name: CRAWLX_CHECKPOINT_KMS_KEY_ID"));
    assert!(helpers.contains("value: {{ $c.checkpointEncryption.kmsKeyId | quote }}"));
    if !compose_available() {
        return;
    }
    let arguments = ["-f", COMPOSE, "config", "--format", "json"];
    let absent = docker_compose(&arguments, &[]).unwrap();
    assert!(
        absent.status.success(),
        "{}",
        String::from_utf8_lossy(&absent.stderr)
    );
    let absent: Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert!(service(&absent, "worker")["environment"]
        .get(setting)
        .is_none_or(Value::is_null));
    let key_id = "arn:aws:kms:us-east-1:123456789012:key/operator-canary"; // wire-compat: key ARN shape
    let configured = docker_compose(&arguments, &[(setting, key_id)]).unwrap();
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let configured: Value = serde_json::from_slice(&configured.stdout).unwrap();
    assert_eq!(raw_env(service(&configured, "worker"))[setting], key_id);
}
