//! Property tests for the egress guard (deny-range
//! table and redirect-hop recheck property).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_policy::egress::{DenyRule, DENIED_V4, DENIED_V6};
use crawlx_policy::EgressPolicy;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

fn in_v4_range(idx: usize, bits: u32) -> Ipv4Addr {
    let r = DENIED_V4[idx % DENIED_V4.len()];
    let host_mask = u32::MAX.checked_shr(r.prefix.into()).unwrap_or(0);
    Ipv4Addr::from((u32::from_be_bytes(r.base) & !host_mask) | (bits & host_mask))
}

fn in_v6_range(idx: usize, bits: u128) -> Ipv6Addr {
    let r = DENIED_V6[idx % DENIED_V6.len()];
    let base = Ipv6Addr::new(
        r.base[0], r.base[1], r.base[2], r.base[3], r.base[4], r.base[5], r.base[6], r.base[7],
    );
    let host_mask = u128::MAX.checked_shr(r.prefix.into()).unwrap_or(0);
    Ipv6Addr::from((u128::from(base) & !host_mask) | (bits & host_mask))
}

proptest! {
    #[test]
    fn any_address_inside_a_denied_v4_range_is_denied(idx in 0usize..64, bits in any::<u32>()) {
        let ip = IpAddr::V4(in_v4_range(idx, bits));
        prop_assert!(EgressPolicy::new(false).check_ip(ip).is_err());
    }

    #[test]
    fn any_address_inside_a_denied_v6_range_is_denied(idx in 0usize..64, bits in any::<u128>()) {
        let ip = IpAddr::V6(in_v6_range(idx, bits));
        prop_assert!(EgressPolicy::new(false).check_ip(ip).is_err());
    }

    #[test]
    fn mapped_form_of_a_denied_v4_is_denied(bits in any::<u32>()) {
        let v4 = Ipv4Addr::from(bits);
        let p = EgressPolicy::new(false);
        if p.check_ip(IpAddr::V4(v4)).is_err() {
            prop_assert!(p.check_ip(IpAddr::V6(v4.to_ipv6_mapped())).is_err());
        }
    }

    #[test]
    fn mapped_form_reports_the_embedded_rule(bits in any::<u32>()) {
        let v4 = Ipv4Addr::from(bits);
        let p = EgressPolicy::new(false);
        if let Err(e4) = p.check_ip(IpAddr::V4(v4)) {
            let e6 = p.check_ip(IpAddr::V6(v4.to_ipv6_mapped())).unwrap_err();
            prop_assert_eq!(e4.rule, e6.rule);
        }
    }

    #[test]
    fn metadata_is_never_exempted(allow_private in any::<bool>(), pick in 0usize..4) {
        let ip: IpAddr = ["169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"][pick].parse().unwrap();
        let mut p = EgressPolicy::new(allow_private);
        p.extra_allow = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        prop_assert_eq!(p.check_ip(ip).unwrap_err().rule, DenyRule::Metadata);
    }

    #[test]
    fn check_ip_total_over_all_addresses(v4 in any::<u32>(), v6 in any::<u128>(), allow in any::<bool>()) {
        let p = EgressPolicy::new(allow);
        let _ = p.check_ip(IpAddr::V4(Ipv4Addr::from(v4)));
        let _ = p.check_ip(IpAddr::V6(Ipv6Addr::from(v6)));
    }

    /// Every hop of a redirect chain is rechecked: the chain passes exactly
    /// when no hop targets a denied destination.
    #[test]
    fn redirect_chain_passes_iff_every_hop_passes(hops in proptest::collection::vec(0usize..12, 1..10)) {
        const TARGETS: [(&str, bool); 12] = [
            ("https://example.com/a", true),
            ("http://93.184.216.34/", true),
            ("https://cdn.example.org:443/x", true),
            ("https://[2606:4700:4700::1111]/", true),
            ("http://127.0.0.1/admin", false),
            ("http://localhost:80/", false),
            ("http://[::1]/", false),
            ("http://10.0.0.1/", false),
            ("http://169.254.169.254/latest/meta-data/", false),
            ("http://2130706433/", false),
            ("http://[::ffff:192.168.0.1]/", false),
            ("https://example.com:8443/", false),
        ];
        let p = EgressPolicy::new(false);
        let chain_ok = hops.iter().all(|&i| p.check_url(&Url::parse(TARGETS[i].0).unwrap()).is_ok());
        let expected = hops.iter().all(|&i| TARGETS[i].1);
        prop_assert_eq!(chain_ok, expected);
    }
}
