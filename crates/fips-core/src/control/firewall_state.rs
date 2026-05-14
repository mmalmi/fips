//! Read-side classifier for the `inet fips` baseline filter.
//!
//! Used by the fipstop listener panel to classify whether a listening
//! `(proto, port)` pair is accepted, filtered, unknown, or unprotected because
//! the baseline firewall table is absent.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::Value;

use crate::control::listening::Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterState {
    NoFirewall,
    Accept,
    Drop,
    Unknown,
}

impl FilterState {
    pub fn as_str(self) -> &'static str {
        match self {
            FilterState::NoFirewall => "no_firewall",
            FilterState::Accept => "accept",
            FilterState::Drop => "drop",
            FilterState::Unknown => "unknown",
        }
    }
}

pub struct FilterClassifier {
    rules: Option<Vec<Rule>>,
}

#[derive(Debug, Clone)]
struct Rule {
    matches: Vec<MatchExpr>,
    verdict: Verdict,
}

#[derive(Debug, Clone)]
enum MatchExpr {
    Iifname,
    L4Proto(Proto),
    Dport(Proto, PortMatch),
    Unrecognized,
}

#[derive(Debug, Clone)]
enum PortMatch {
    Single(u16),
    Set(Vec<u16>),
    Range(u16, u16),
}

impl PortMatch {
    fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Single(p) => *p == port,
            PortMatch::Set(ports) => ports.contains(&port),
            PortMatch::Range(lo, hi) => *lo <= port && port <= *hi,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Accept,
    Drop,
    Other,
}

impl FilterClassifier {
    pub fn no_firewall() -> Self {
        Self { rules: None }
    }

    #[cfg(target_os = "linux")]
    pub fn query() -> Self {
        let Some(json) = run_nft_list() else {
            return Self::no_firewall();
        };
        Self {
            rules: Some(parse_inbound_rules(&json)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn query() -> Self {
        Self::no_firewall()
    }

    pub fn is_active(&self) -> bool {
        self.rules.is_some()
    }

    pub fn classify(&self, proto: Proto, port: u16) -> FilterState {
        let Some(rules) = &self.rules else {
            return FilterState::NoFirewall;
        };

        let mut saw_unknown_for_port = false;

        for rule in rules {
            let mut references_port = false;
            let mut canonical_for_port = true;
            let mut has_proto_match = None;

            for matcher in &rule.matches {
                match matcher {
                    MatchExpr::Iifname => {}
                    MatchExpr::L4Proto(p) => {
                        has_proto_match = Some(*p);
                        if *p != proto {
                            canonical_for_port = false;
                        }
                    }
                    MatchExpr::Dport(p, port_match) => {
                        if *p == proto && port_match.matches(port) {
                            references_port = true;
                        } else if !port_match.matches(port) {
                            canonical_for_port = false;
                        }
                    }
                    MatchExpr::Unrecognized => {
                        if rule_might_reference_port(rule, proto, port) {
                            saw_unknown_for_port = true;
                        }
                        canonical_for_port = false;
                    }
                }
            }

            if !references_port {
                continue;
            }
            if !canonical_for_port {
                saw_unknown_for_port = true;
                continue;
            }
            if let Some(p) = has_proto_match
                && p != proto
            {
                continue;
            }

            match rule.verdict {
                Verdict::Accept => return FilterState::Accept,
                Verdict::Drop => return FilterState::Drop,
                Verdict::Other => saw_unknown_for_port = true,
            }
        }

        if saw_unknown_for_port {
            FilterState::Unknown
        } else {
            FilterState::Drop
        }
    }
}

fn rule_might_reference_port(rule: &Rule, proto: Proto, port: u16) -> bool {
    rule.matches.iter().any(|matcher| match matcher {
        MatchExpr::Dport(p, port_match) => *p == proto && port_match.matches(port),
        _ => false,
    })
}

#[cfg(target_os = "linux")]
fn run_nft_list() -> Option<Value> {
    use std::process::Command;

    let output = Command::new("nft")
        .args(["-j", "list", "table", "inet", "fips"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    serde_json::from_slice::<Value>(&output.stdout).ok()
}

fn parse_inbound_rules(json: &Value) -> Vec<Rule> {
    let Some(entries) = json.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| {
            rule.get("table").and_then(|v| v.as_str()) == Some("fips")
                && rule.get("chain").and_then(|v| v.as_str()) == Some("inbound")
        })
        .map(parse_rule)
        .collect()
}

fn parse_rule(rule: &Value) -> Rule {
    let exprs = rule
        .get("expr")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut matches = Vec::new();
    let mut verdict = Verdict::Other;

    for expr in &exprs {
        if let Some(matcher) = expr.get("match") {
            matches.push(parse_match(matcher));
        } else if expr.get("accept").is_some() {
            verdict = Verdict::Accept;
        } else if expr.get("drop").is_some() {
            verdict = Verdict::Drop;
        } else if expr.get("return").is_some()
            || expr.get("jump").is_some()
            || expr.get("goto").is_some()
            || expr.get("continue").is_some()
            || expr.get("reject").is_some()
            || expr.get("queue").is_some()
        {
            verdict = Verdict::Other;
        }
    }

    Rule { matches, verdict }
}

fn parse_match(matcher: &Value) -> MatchExpr {
    let op = matcher
        .get("op")
        .and_then(|value| value.as_str())
        .unwrap_or("==");
    let left = matcher.get("left").cloned().unwrap_or(Value::Null);
    let right = matcher.get("right").cloned().unwrap_or(Value::Null);

    if let Some(meta) = left.get("meta")
        && meta.get("key").and_then(|v| v.as_str()) == Some("iifname")
        && right.as_str().is_some()
    {
        let _ = op;
        return MatchExpr::Iifname;
    }

    if let Some(meta) = left.get("meta")
        && meta.get("key").and_then(|v| v.as_str()) == Some("l4proto")
        && let Some(proto_str) = right.as_str()
        && let Some(proto) = parse_proto(proto_str)
        && op == "=="
    {
        return MatchExpr::L4Proto(proto);
    }

    if let Some(payload) = left.get("payload")
        && payload.get("field").and_then(|v| v.as_str()) == Some("dport")
        && let Some(proto_str) = payload.get("protocol").and_then(|v| v.as_str())
        && let Some(proto) = parse_proto(proto_str)
        && op == "=="
    {
        if let Some(port) = right.as_u64() {
            return MatchExpr::Dport(proto, PortMatch::Single(port as u16));
        }
        if let Some(set) = right.get("set").and_then(|v| v.as_array()) {
            let ports: Vec<u16> = set
                .iter()
                .filter_map(|v| v.as_u64().map(|port| port as u16))
                .collect();
            if ports.len() == set.len() {
                return MatchExpr::Dport(proto, PortMatch::Set(ports));
            }
        }
        if let Some(range) = right.get("range").and_then(|v| v.as_array())
            && range.len() == 2
            && let (Some(lo), Some(hi)) = (range[0].as_u64(), range[1].as_u64())
        {
            return MatchExpr::Dport(proto, PortMatch::Range(lo as u16, hi as u16));
        }
    }

    MatchExpr::Unrecognized
}

fn parse_proto(value: &str) -> Option<Proto> {
    match value {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_classifier(rules_json: Value) -> FilterClassifier {
        let nft_json = json!({
            "nftables": rules_json
                .as_array()
                .unwrap()
                .iter()
                .map(|rule| json!({"rule": {
                    "family": "inet",
                    "table": "fips",
                    "chain": "inbound",
                    "expr": rule,
                }}))
                .collect::<Vec<_>>(),
        });
        FilterClassifier {
            rules: Some(parse_inbound_rules(&nft_json)),
        }
    }

    #[test]
    fn no_firewall_means_no_firewall() {
        let classifier = FilterClassifier::no_firewall();
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::NoFirewall);
        assert_eq!(
            classifier.classify(Proto::Udp, 5353),
            FilterState::NoFirewall
        );
    }

    #[test]
    fn empty_chain_drops_everything() {
        let classifier = make_classifier(json!([]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Drop);
        assert_eq!(classifier.classify(Proto::Udp, 5353), FilterState::Drop);
    }

    #[test]
    fn canonical_tcp_dport_accept() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 80), FilterState::Drop);
        assert_eq!(classifier.classify(Proto::Udp, 22), FilterState::Drop);
    }

    #[test]
    fn canonical_udp_dport_accept() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "udp", "field": "dport"}},
                    "right": 5353
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Udp, 5353), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 5353), FilterState::Drop);
    }

    #[test]
    fn dport_set_accept() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"set": [22, 80, 443]}
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 80), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 443), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 25), FilterState::Drop);
    }

    #[test]
    fn dport_range_accept() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"range": [22, 25]}
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 25), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Tcp, 26), FilterState::Drop);
    }

    #[test]
    fn saddr_restricted_is_unknown() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                    "right": {"prefix": {"addr": "fd97::", "len": 64}}
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Unknown);
        assert_eq!(classifier.classify(Proto::Tcp, 80), FilterState::Drop);
    }

    #[test]
    fn jump_verdict_is_unknown() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"jump": {"target": "some_chain"}}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Unknown);
    }

    #[test]
    fn explicit_drop_classifies_as_drop() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"drop": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Drop);
    }

    #[test]
    fn unrelated_rules_do_not_affect_port() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "!=",
                    "left": {"meta": {"key": "iifname"}},
                    "right": "fips0"
                }},
                {"return": null}
            ],
            [
                {"match": {
                    "op": "in",
                    "left": {"ct": {"key": "state"}},
                    "right": ["established", "related"]
                }},
                {"accept": null}
            ],
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "icmpv6", "field": "type"}},
                    "right": "echo-request"
                }},
                {"accept": null}
            ],
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Drop);
        assert_eq!(classifier.classify(Proto::Udp, 5353), FilterState::Drop);
    }

    #[test]
    fn l4proto_then_dport_accept() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"meta": {"key": "l4proto"}},
                    "right": "tcp"
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Accept);
        assert_eq!(classifier.classify(Proto::Udp, 22), FilterState::Drop);
    }

    #[test]
    fn first_accept_match_wins() {
        let classifier = make_classifier(json!([
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"accept": null}
            ],
            [
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip6", "field": "saddr"}},
                    "right": "fd00::1"
                }},
                {"match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": 22
                }},
                {"drop": null}
            ]
        ]));
        assert_eq!(classifier.classify(Proto::Tcp, 22), FilterState::Accept);
    }
}
