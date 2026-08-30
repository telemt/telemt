use super::*;
use crate::config::CidrRateLimitKey;

fn rate(up_bps: u64, down_bps: u64) -> RateLimitBps {
    RateLimitBps { up_bps, down_bps }
}

#[test]
fn explicit_cidr_rule_wins_over_auto_template() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
    cidr_limits.insert(
        CidrRateLimitKey::Network("203.0.113.7/32".parse().unwrap()),
        rate(2_000, 0),
    );

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("203.0.113.7".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Explicit(rule) => assert_eq!(rule.key.as_str(), "203.0.113.7/32"),
        CidrPolicyMatch::Auto { .. } => panic!("explicit CIDR must have priority"),
    }
}

#[test]
fn auto_template_uses_longest_prefix() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoV4(24), rate(1_000, 0));
    cidr_limits.insert(CidrRateLimitKey::AutoV4(32), rate(2_000, 0));

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("203.0.113.129".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Auto { key, limits } => {
            assert_eq!(key, "auto:4:203.0.113.129/32");
            assert_eq!(limits.up_bps, 2_000);
        }
        CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
    }
}

#[test]
fn dual_auto_template_maps_v6_prefix_by_four() {
    let limiter = TrafficLimiter::new();
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(CidrRateLimitKey::AutoDual(32), rate(1_000, 0));

    limiter.apply_policy(HashMap::new(), cidr_limits);
    let policy = limiter.policy.load_full();
    let matched = policy.match_cidr("2001:db8::1".parse().unwrap()).unwrap();

    match matched {
        CidrPolicyMatch::Auto { key, .. } => {
            assert_eq!(key, "auto:6:2001:db8::1/128");
        }
        CidrPolicyMatch::Explicit(_) => panic!("auto-template match expected"),
    }
}

#[test]
fn auto_cidr_bucket_key_canonicalizes_network_address() {
    assert_eq!(
        auto_cidr_bucket_key("203.0.113.129".parse().unwrap(), 24).unwrap(),
        "auto:4:203.0.113.0/24"
    );
    assert_eq!(
        auto_cidr_bucket_key("2001:db8::abcd".parse().unwrap(), 64).unwrap(),
        "auto:6:2001:db8::/64"
    );
}
