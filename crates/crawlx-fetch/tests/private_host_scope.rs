//! Private-host authority stays intersected with caller exclusions on the checked resolver path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::CreateCrawl;
use crawlx_fetch::resolver::CheckedResolution;
use crawlx_fetch::StaticResolver;
use crawlx_policy::egress::PrivateHostScope;
use crawlx_policy::{
    AuthorizationRecord, DenialReason, DenyRule, EgressLists, EgressPolicy, ExcludeHosts, ScopePolicy,
    ScopeVerdict, SharedEgressLists,
};
use std::net::IpAddr;
use url::Url;

const HOST: &str = "staging.example.test";

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn record(networks: &[&str]) -> AuthorizationRecord {
    let mut record = crawlx_policy::testkit::sample_record(
        "00000000-0000-0000-0000-000000000001".parse().unwrap(),
        "2026-01-01T00:00:00Z".parse().unwrap(),
        &["https://staging.example.test"],
    );
    record.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    record.authorized_networks = networks.iter().map(|network| network.parse().unwrap()).collect();
    record
}

fn policy(record: &AuthorizationRecord, exclusions: &[&str]) -> EgressPolicy {
    let exclusions = exclusions
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    EgressPolicy::new(false)
        .with_host_exclusions(ExcludeHosts::new(&exclusions).unwrap())
        .with_private_host_scope(PrivateHostScope::new(record))
}

#[tokio::test]
async fn allowed_network_never_overrides_excluded_hostname() {
    let record = record(&["10.20.0.0/16"]);
    let policy = policy(&record, &["^staging\\.example\\.test$"]);
    let resolver = StaticResolver::new().with(HOST, [ip("10.20.0.8")]);
    assert!(policy.check_ip(ip("10.20.0.8")).is_ok());
    assert_eq!(policy.check_host(HOST).unwrap_err().rule, DenyRule::HostExcluded);
    assert!(CheckedResolution::resolve(
        &resolver,
        &policy,
        &Url::parse("https://staging.example.test/app/").unwrap(),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn every_mixed_dns_answer_must_pass_caller_address_exclusions() {
    let record = record(&["10.20.0.0/16"]);
    let policy = policy(&record, &["10.20.0.9/32"]);
    let target = Url::parse("https://staging.example.test/app/").unwrap();
    let resolver = StaticResolver::new().with(HOST, [ip("10.20.0.8")]);
    assert!(CheckedResolution::resolve(&resolver, &policy, &target)
        .await
        .is_ok());
    for addresses in [
        [ip("10.20.0.8"), ip("10.20.0.9")],
        [ip("10.20.0.9"), ip("10.20.0.8")],
    ] {
        resolver.set(HOST, addresses);
        assert!(CheckedResolution::resolve(&resolver, &policy, &target)
            .await
            .is_err());
        assert_eq!(
            policy.check_all(HOST, &addresses).unwrap_err().rule,
            DenyRule::HostExcluded
        );
    }
    assert_eq!(
        policy.check_all(HOST, &[ip("10.20.0.9")]).unwrap_err().rule,
        DenyRule::HostExcluded,
        "the observed peer must pass the same caller exclusion",
    );
}

#[tokio::test]
async fn explicit_private_ips_remains_denied_even_inside_signed_network() {
    let record = record(&["10.20.0.0/16"]);
    let policy = policy(&record, &["private-ips"]);
    let resolver = StaticResolver::new().with(HOST, [ip("93.184.216.34"), ip("10.20.0.8")]);
    assert_eq!(
        policy.check_ip(ip("10.20.0.8")).unwrap_err().rule,
        DenyRule::HostExcluded
    );
    assert!(CheckedResolution::resolve(
        &resolver,
        &policy,
        &Url::parse("https://staging.example.test/app/").unwrap(),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn rebound_answer_cannot_leave_current_signed_network() {
    let record = record(&["10.20.0.0/16"]);
    let policy = policy(&record, &[]);
    let target = Url::parse("https://staging.example.test/app/").unwrap();
    let resolver = StaticResolver::new().with(HOST, [ip("10.20.0.8")]);
    let checked = CheckedResolution::resolve(&resolver, &policy, &target)
        .await
        .unwrap();
    assert_eq!(checked.addresses(), &[ip("10.20.0.8")]);
    resolver.set(HOST, [ip("10.21.0.8")]);
    assert!(CheckedResolution::resolve(&resolver, &policy, &target)
        .await
        .is_err());
    assert!(policy.check_all(HOST, &[ip("10.21.0.8")]).is_err());
    assert!(!checked.addresses().contains(&ip("10.21.0.8")));
}

#[tokio::test]
async fn metadata_and_link_local_are_never_authorized_dns_answers() {
    let record = record(&["0.0.0.0/0", "::/0"]);
    let policy = policy(&record, &[]);
    let target = Url::parse("https://staging.example.test/app/").unwrap();
    let resolver = StaticResolver::new();
    for (address, rule) in [
        ("169.254.169.254", DenyRule::Metadata),
        ("100.100.100.200", DenyRule::Metadata),
        ("fd00:ec2::254", DenyRule::Metadata),
        ("169.254.1.1", DenyRule::LinkLocal),
        ("fe80::1", DenyRule::LinkLocal),
    ] {
        assert_eq!(policy.check_ip(ip(address)).unwrap_err().rule, rule);
        resolver.set(HOST, [ip("10.20.0.8"), ip(address)]);
        assert!(CheckedResolution::resolve(&resolver, &policy, &target)
            .await
            .is_err());
        assert_eq!(policy.check_all(HOST, &[ip(address)]).unwrap_err().rule, rule);
    }
}

#[test]
fn empty_signed_networks_cannot_inherit_unsigned_or_deployment_allowance() {
    let record = record(&[]);
    let mut policy = policy(&record, &[]).with_lists(SharedEgressLists::new(
        EgressLists::new(
            Some(vec!["10.0.0.0/8".parse().unwrap()]),
            std::iter::empty::<&str>(),
        )
        .unwrap(),
    ));
    policy.allow_private = true;
    policy.extra_allow = vec!["10.0.0.0/8".parse().unwrap()];
    policy.deployment_exempt = true;
    assert!(policy
        .authorized_private_networks()
        .is_some_and(|networks| networks.is_empty()));
    assert!(policy.check_ip(ip("10.20.0.8")).is_err());
    assert!(policy.check_all(HOST, &[ip("10.20.0.8")]).is_err());
}

#[test]
fn signed_networks_intersect_deployment_allowlist_instead_of_union() {
    let record = record(&["10.20.0.0/16"]);
    let mut policy = policy(&record, &[]).with_lists(SharedEgressLists::new(
        EgressLists::new(
            Some(vec!["10.0.0.0/8".parse().unwrap()]),
            std::iter::empty::<&str>(),
        )
        .unwrap(),
    ));
    policy.deployment_exempt = true;
    policy.extra_allow = vec!["10.0.0.0/8".parse().unwrap()];
    assert!(policy.check_ip(ip("10.20.0.8")).is_ok());
    assert!(policy.check_ip(ip("10.21.0.8")).is_err());
}

#[tokio::test]
async fn exact_origins_prefixes_and_path_exclusions_survive_private_mapping() {
    let mut record = record(&["10.20.0.0/16"]);
    record.origins.clear();
    record.url_prefixes = vec!["https://staging.example.test/app/".to_owned()];
    record.excluded_paths = vec!["/app/secret/*".to_owned()];
    let mut policy = policy(&record, &[]);
    policy.extra_ports.push(8443);
    let target = Url::parse("https://staging.example.test/app/page").unwrap();
    let mut crawl = CreateCrawl::new(target.clone());
    crawl.safety.allow_private_networks = true;
    let scope = ScopePolicy::new(&crawl)
        .unwrap()
        .with_record_scope(record.scope());
    let resolver = StaticResolver::new().with(HOST, [ip("10.20.0.8")]);
    assert!(CheckedResolution::resolve(&resolver, &policy, &target)
        .await
        .is_ok());
    assert!(scope.decide_url(&target, 0).is_admitted());
    for outside in [
        "https://staging.example.test/other/",
        "https://staging.example.test/app/secret/token",
        "https://staging.example.test:8443/app/page",
        "http://staging.example.test/app/page",
        "https://other.example.test/app/page",
    ] {
        let outside = Url::parse(outside).unwrap();
        assert_eq!(
            policy.check_url(&outside).unwrap_err().rule,
            DenyRule::AuthorizationScope
        );
        assert!(CheckedResolution::resolve(&resolver, &policy, &outside)
            .await
            .is_err());
        assert_eq!(
            scope.decide_url(&outside, 0),
            ScopeVerdict::Denied(DenialReason::AuthorizationScope),
        );
    }
}
