use crate::{Result, docker::config::ConfigVerdict};
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::Rule,
    stmt::{Counter, JumpTarget, Log, LogLevel, Match, Operator, Queue, Statement},
    types::NfFamily,
};
use std::borrow::Cow;
use std::net::IpAddr;

/// Context needed for rule generation
pub struct RuleContext<'a> {
    pub container_id: &'a str,
    pub container_name: &'a str,
    pub container_ips: &'a [IpAddr],
    pub container_ports: &'a [(u16, String)], // (port, protocol)
    pub chain_name: &'a str,
    pub table_name: &'a str,
    pub family: NfFamily,
}

/// Trait for converting config types directly to nftables rules
pub trait ToNftablesRule {
    /// Convert this configuration to nftables statements
    fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>>;

    /// Convert to a complete nftables rule
    fn to_nftables_rule(
        &self,
        ctx: &RuleContext,
        comment: Option<String>,
    ) -> Result<Rule<'static>> {
        let statements = self.to_nftables_statements()?;

        Ok(Rule {
            family: ctx.family,
            table: Cow::Owned(ctx.table_name.to_string()),
            chain: Cow::Owned(ctx.chain_name.to_string()),
            expr: Cow::Owned(statements),
            handle: None,
            index: None,
            comment: comment.map(Cow::Owned),
        })
    }

    /// Create a protocol match statement
    fn match_protocol(protocol: &str) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::Number(match protocol.to_lowercase().as_str() {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                "icmpv6" => 58,
                _ => 6, // Default to TCP
            }),
            op: Operator::EQ,
        })
    }

    /// Create a destination port match statement
    fn match_dst_port(protocol: &str, port: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("dport"),
                },
            ))),
            right: Expression::Number(port as u32),
            op: Operator::EQ,
        })
    }

    /// Create a destination port range match statement
    fn match_dst_port_range(protocol: &str, start: u16, end: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("dport"),
                },
            ))),
            right: Expression::Range(Box::new(nftables::expr::Range {
                range: [
                    Expression::Number(start as u32),
                    Expression::Number(end as u32),
                ],
            })),
            op: Operator::EQ,
        })
    }

    /// Create a source port match statement
    fn match_src_port(protocol: &str, port: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("sport"),
                },
            ))),
            right: Expression::Number(port as u32),
            op: Operator::EQ,
        })
    }

    /// Create a source IP match statement
    fn match_src_ip(ip: &str) -> Statement<'static> {
        let protocol = if ip.contains(':') { "ip6" } else { "ip" };
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed(protocol),
                    field: Cow::Borrowed("saddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(ip.to_string())),
            op: Operator::EQ,
        })
    }

    /// Create a destination IP match statement
    fn match_dst_ip(ip: &str) -> Statement<'static> {
        let protocol = if ip.contains(':') { "ip6" } else { "ip" };
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed(protocol),
                    field: Cow::Borrowed("daddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(ip.to_string())),
            op: Operator::EQ,
        })
    }

    /// Create a log statement with optional prefix
    fn log_statement(prefix: Option<&str>) -> Statement<'static> {
        Statement::Log(Some(Log {
            prefix: prefix.map(|p| Cow::Owned(p.to_string())),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: Some(LogLevel::Info),
            flags: None,
        }))
    }

    /// Create a counter statement
    fn counter_statement() -> Statement<'static> {
        Statement::Counter(Counter::Anonymous(None))
    }

    /// Convert ConfigVerdict to nftables statement
    fn verdict_to_statement(verdict: &ConfigVerdict) -> Statement<'static> {
        if !verdict.chain.is_empty() {
            // Jump to another chain
            Statement::Jump(JumpTarget {
                target: Cow::Owned(verdict.chain.clone()),
            })
        } else if verdict.queue > 0 {
            // Queue to userspace
            Statement::Queue(Queue {
                num: Expression::Number(verdict.queue as u32),
                flags: None,
            })
        } else if verdict.drop {
            // Drop the packet
            Statement::Drop(None)
        } else {
            // Default to accept
            Statement::Accept(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Create a dummy struct to test the trait methods
    struct TestRule;
    impl ToNftablesRule for TestRule {
        fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_match_protocol_tcp() {
        let stmt = TestRule::match_protocol("tcp");
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Number(6)));
        } else {
            panic!("Expected Match statement");
        }
    }

    #[test]
    fn test_match_protocol_udp() {
        let stmt = TestRule::match_protocol("udp");
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Number(17)));
        } else {
            panic!("Expected Match statement");
        }
    }

    #[test]
    fn test_match_protocol_icmp() {
        let stmt = TestRule::match_protocol("icmp");
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Number(1)));
        } else {
            panic!("Expected Match statement");
        }
    }

    #[test]
    fn test_match_protocol_icmpv6() {
        let stmt = TestRule::match_protocol("icmpv6");
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Number(58)));
        } else {
            panic!("Expected Match statement");
        }
    }

    #[test]
    fn test_match_protocol_unknown_defaults_to_tcp() {
        let stmt = TestRule::match_protocol("unknown");
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Number(6)));
        } else {
            panic!("Expected Match statement");
        }
    }

    #[test]
    fn test_match_dst_port() {
        let stmt = TestRule::match_dst_port("tcp", 80);
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_match_dst_port_range() {
        let stmt = TestRule::match_dst_port_range("tcp", 80, 90);
        if let Statement::Match(m) = stmt {
            assert!(matches!(m.right, Expression::Range(_)));
        } else {
            panic!("Expected Match statement with Range");
        }
    }

    #[test]
    fn test_match_src_port() {
        let stmt = TestRule::match_src_port("tcp", 8080);
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_match_src_ip_ipv4() {
        let stmt = TestRule::match_src_ip("192.168.1.1");
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_match_src_ip_ipv6() {
        let stmt = TestRule::match_src_ip("2001:db8::1");
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_match_dst_ip_ipv4() {
        let stmt = TestRule::match_dst_ip("10.0.0.1");
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_match_dst_ip_ipv6() {
        let stmt = TestRule::match_dst_ip("::1");
        assert!(matches!(stmt, Statement::Match(_)));
    }

    #[test]
    fn test_log_statement_with_prefix() {
        let stmt = TestRule::log_statement(Some("test-prefix"));
        if let Statement::Log(Some(log)) = stmt {
            assert_eq!(log.prefix, Some(Cow::Owned("test-prefix".to_string())));
        } else {
            panic!("Expected Log statement with prefix");
        }
    }

    #[test]
    fn test_log_statement_without_prefix() {
        let stmt = TestRule::log_statement(None);
        if let Statement::Log(Some(log)) = stmt {
            assert!(log.prefix.is_none());
        } else {
            panic!("Expected Log statement");
        }
    }

    #[test]
    fn test_counter_statement() {
        let stmt = TestRule::counter_statement();
        assert!(matches!(stmt, Statement::Counter(_)));
    }

    #[test]
    fn test_verdict_to_statement_chain() {
        let verdict = ConfigVerdict::builder().chain("my-chain".to_string()).build();
        let stmt = TestRule::verdict_to_statement(&verdict);
        assert!(matches!(stmt, Statement::Jump(_)));
    }

    #[test]
    fn test_verdict_to_statement_queue() {
        let verdict = ConfigVerdict::builder().queue(100).build();
        let stmt = TestRule::verdict_to_statement(&verdict);
        assert!(matches!(stmt, Statement::Queue(_)));
    }

    #[test]
    fn test_verdict_to_statement_drop() {
        let verdict = ConfigVerdict::builder().drop(true).build();
        let stmt = TestRule::verdict_to_statement(&verdict);
        assert!(matches!(stmt, Statement::Drop(_)));
    }

    #[test]
    fn test_verdict_to_statement_accept_default() {
        let verdict = ConfigVerdict::default();
        let stmt = TestRule::verdict_to_statement(&verdict);
        assert!(matches!(stmt, Statement::Accept(_)));
    }
}
