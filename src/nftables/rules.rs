//! Pure translation of a managed container's policy into nftables rules.
//!
//! Every rule is emitted once per address family that both the container and the rule's
//! own address list cover, so IPv4 and IPv6 traffic are matched with the right payload.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;

use nftables::expr::{
    CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, Range, SetItem,
    Verdict as NfVerdict,
};
use nftables::schema::Rule;
use nftables::stmt::{
    Counter, JumpTarget, Log, LogLevel, Match, Operator, Queue, Statement, VerdictMap,
};
use nftables::types::{NfFamily, NfHook};

use ipnet::{IpNet, Ipv4Net};

use crate::docker::config::{AddrOrRange, Protocol, RulePorts};

/// Name of harborshield's tables; it never writes into tables other software manages.
pub const TABLE: &str = "harborshield";

/// Where traffic is filtered. Routed traffic (published ports, other networks, the host)
/// crosses the `inet` hooks; traffic between containers on one bridge is switched at layer 2
/// and only the `bridge` family sees it, unless `br_netfilter` is loaded host-wide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Routed,
    Bridged,
}

impl Layer {
    pub const ALL: [Self; 2] = [Self::Routed, Self::Bridged];

    pub fn family(self) -> NfFamily {
        match self {
            Self::Routed => NfFamily::INet,
            Self::Bridged => NfFamily::Bridge,
        }
    }

    /// Base chains and their hooks. A drop in one is final; an accept only ends that chain,
    /// so other software's rules on the same hook still apply.
    pub fn base_chains(self) -> &'static [(&'static str, NfHook)] {
        match self {
            Self::Routed => &[
                ("forward", NfHook::Forward),
                ("input", NfHook::Input),
                ("output", NfHook::Output),
            ],
            Self::Bridged => &[("forward", NfHook::Forward)],
        }
    }
}

/// Prefix of every per-container chain.
pub const CHAIN_PREFIX: &str = "hs-";

/// Longest container-name part kept in a chain name, so the whole name stays under the
/// kernel's 256-byte limit.
const MAX_NAME_IN_CHAIN: usize = 200;

/// The chain that holds one container's rules.
pub fn chain_name(container_id: &str, container_name: &str) -> String {
    let short_id = container_id.get(..12).unwrap_or(container_id);
    let name: String = container_name
        .chars()
        .map(|character| match character {
            '_' | '.' | '/' => '-',
            other => other,
        })
        .take(MAX_NAME_IN_CHAIN)
        .collect();
    format!("{CHAIN_PREFIX}{name}-{short_id}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Self; 2] = [Self::V4, Self::V6];

    pub fn of(address: &IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    fn of_entry(entry: &AddrOrRange) -> Self {
        match entry {
            AddrOrRange::Addr(address) | AddrOrRange::Range(address, _) => Self::of(address),
            AddrOrRange::Net(network) => Self::of(&network.addr()),
        }
    }

    fn payload(self) -> &'static str {
        match self {
            Self::V4 => "ip",
            Self::V6 => "ip6",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedPort {
    pub port: u16,
    pub proto: Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Jump(String),
    Queue {
        number: u16,
        established: Option<EstablishedQueues>,
    },
}

/// Queues for the packets of an admitted connection after its first, by direction relative to
/// the container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EstablishedQueues {
    pub inbound: u16,
    pub outbound: u16,
}

/// Which addresses a rule admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peers {
    Any,
    Only(Vec<AddrOrRange>),
}

/// Access to the container's published ports from the Docker host itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAccess {
    /// Loopback plus, when allowed, the gateways docker-proxy connects from.
    pub sources: Vec<IpAddr>,
    pub log_prefix: Option<String>,
    pub verdict: Verdict,
}

/// Access to the container's published ports from outside the Docker host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAccess {
    pub sources: Peers,
    pub log_prefix: Option<String>,
    pub verdict: Verdict,
}

/// Traffic the container may originate, with container references already resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRule {
    pub destinations: Peers,
    pub proto: Protocol,
    pub src_ports: Vec<RulePorts>,
    pub dst_ports: Vec<RulePorts>,
    pub log_prefix: Option<String>,
    pub verdict: Verdict,
}

/// Everything needed to build one container's chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedContainer {
    pub id: String,
    pub name: String,
    pub addresses: Vec<IpAddr>,
    /// The Docker host's own addresses as seen by this container: its networks' gateways.
    /// Traffic from these, or from loopback, is never external.
    pub gateways: Vec<IpAddr>,
    pub published: Vec<PublishedPort>,
    pub localhost: Option<LocalAccess>,
    pub external: Option<ExternalAccess>,
    pub outputs: Vec<OutputRule>,
}

impl ManagedContainer {
    pub fn chain(&self) -> String {
        chain_name(&self.id, &self.name)
    }

    fn addresses_in(&self, family: Family) -> Vec<IpAddr> {
        self.addresses
            .iter()
            .copied()
            .filter(|address| Family::of(address) == family)
            .collect()
    }

    /// Published ports grouped by protocol, in a stable order.
    fn published_by_proto(&self) -> PortsByProto {
        let mut grouped = PortsByProto::new();
        for published in &self.published {
            grouped
                .entry(proto_name(published.proto))
                .or_insert_with(|| (published.proto, Vec::new()))
                .1
                .push(RulePorts::Single(published.port));
        }
        grouped
    }
}

/// The rules of a container's chain: queues for established traffic that asked for them, then
/// every other established packet, then the grants for new connections, then the default drop.
pub fn container_rules(layer: Layer, container: &ManagedContainer) -> Vec<Rule<'static>> {
    let grants = grants(container);
    let mut bodies: Vec<Vec<Statement<'static>>> = Vec::new();
    for grant in &grants {
        bodies.extend(grant.established_queue_rules());
    }
    bodies.push(vec![
        ct_match("state", established_or_related()),
        Statement::Accept(None),
    ]);
    // IPv6 resolves neighbours over ICMPv6, which conntrack does not track; without this the
    // host and peers can never reach a managed container over IPv6, as ARP is to IPv4.
    bodies.push(vec![
        Statement::Match(Match {
            left: payload("icmpv6", "type"),
            right: Expression::Named(NamedExpression::Set(vec![
                SetItem::Element(Expression::String(Cow::Borrowed("nd-neighbor-solicit"))),
                SetItem::Element(Expression::String(Cow::Borrowed("nd-neighbor-advert"))),
            ])),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]);
    bodies.extend(grants.iter().map(Grant::new_connection_rule));

    let short_id = container.id.get(..12).unwrap_or(&container.id);
    bodies.push(vec![
        Statement::Counter(Counter::Anonymous(None)),
        log(&format!("hs-drop {short_id}: ")),
        Statement::Drop(None),
    ]);

    let chain = container.chain();
    bodies
        .into_iter()
        .map(|body| rule(layer, &chain, body))
        .collect()
}

/// Which side of a grant the container is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// One admitted flow in one address family: who may open connections to whom, on which ports.
/// `None` addresses mean any address.
struct Grant {
    family: Family,
    role: Role,
    initiator: Option<Vec<Expression<'static>>>,
    /// Initiator addresses excluded even when `initiator` admits any.
    initiator_excluded: Option<Vec<Expression<'static>>>,
    responder: Option<Vec<Expression<'static>>>,
    proto: Protocol,
    initiator_ports: Vec<RulePorts>,
    responder_ports: Vec<RulePorts>,
    through_port_mapping: bool,
    log_prefix: Option<String>,
    verdict: Verdict,
}

impl Grant {
    fn new_connection_rule(&self) -> Vec<Statement<'static>> {
        let mut body = self.flow(false);
        body.extend(tail(self.log_prefix.as_deref(), &self.verdict));
        body
    }

    fn established_queue_rules(&self) -> Vec<Vec<Statement<'static>>> {
        let Verdict::Queue {
            established: Some(queues),
            ..
        } = &self.verdict
        else {
            return Vec::new();
        };
        let (forward, reverse) = match self.role {
            Role::Initiator => (queues.outbound, queues.inbound),
            Role::Responder => (queues.inbound, queues.outbound),
        };
        [(false, forward), (true, reverse)]
            .into_iter()
            .map(|(reply, queue)| {
                let mut body = vec![ct_match(
                    "state",
                    Expression::String(Cow::Borrowed("established")),
                )];
                body.extend(self.flow(reply));
                body.push(Statement::Counter(Counter::Anonymous(None)));
                body.push(queue_statement(queue));
                body
            })
            .collect()
    }

    /// Matches for packets from initiator to responder, or the reverse when `reply`.
    fn flow(&self, reply: bool) -> Vec<Statement<'static>> {
        let (source, destination, source_ports, destination_ports) = if reply {
            (
                &self.responder,
                &self.initiator,
                &self.responder_ports,
                &self.initiator_ports,
            )
        } else {
            (
                &self.initiator,
                &self.responder,
                &self.initiator_ports,
                &self.responder_ports,
            )
        };
        let mut body = Vec::new();
        if self.through_port_mapping {
            body.push(ct_match(
                "status",
                Expression::String(Cow::Borrowed("dnat")),
            ));
        }
        if let Some(addresses) = source {
            body.push(address_match(self.family, "saddr", addresses.clone()));
        }
        if let Some(excluded) = &self.initiator_excluded {
            let field = if reply { "daddr" } else { "saddr" };
            body.push(Statement::Match(Match {
                left: payload(self.family.payload(), field),
                right: set_or_single(excluded.clone()),
                op: Operator::NEQ,
            }));
        }
        if let Some(addresses) = destination {
            body.push(address_match(self.family, "daddr", addresses.clone()));
        }
        body.extend(port_matches(self.proto, source_ports, destination_ports));
        body
    }
}

/// Every grant the container's policy makes, per address family it has addresses in.
fn grants(container: &ManagedContainer) -> Vec<Grant> {
    let published = container.published_by_proto();
    let mut grants = Vec::new();
    for family in Family::ALL {
        let own: Vec<Expression<'static>> = container
            .addresses_in(family)
            .iter()
            .map(address_expr)
            .collect();
        if own.is_empty() {
            continue;
        }
        if let Some(local) = &container.localhost {
            grants.extend(localhost_grants(family, &own, local, &published));
        }
        if let Some(external) = &container.external {
            let local = local_sources(family, &container.gateways);
            grants.extend(external_grants(family, &own, &local, external, &published));
        }
        grants.extend(
            container
                .outputs
                .iter()
                .filter_map(|output| output_grant(family, &own, output)),
        );
    }
    grants
}

type PortsByProto = BTreeMap<&'static str, (Protocol, Vec<RulePorts>)>;

fn localhost_grants(
    family: Family,
    own: &[Expression<'static>],
    local: &LocalAccess,
    published: &PortsByProto,
) -> Vec<Grant> {
    let sources: Vec<Expression<'static>> = local
        .sources
        .iter()
        .filter(|source| Family::of(source) == family)
        .map(address_expr)
        .collect();
    if sources.is_empty() {
        return Vec::new();
    }
    published
        .values()
        .map(|(proto, ports)| Grant {
            family,
            role: Role::Responder,
            initiator: Some(sources.clone()),
            initiator_excluded: None,
            responder: Some(own.to_vec()),
            proto: *proto,
            initiator_ports: Vec::new(),
            responder_ports: ports.clone(),
            through_port_mapping: false,
            log_prefix: local.log_prefix.clone(),
            verdict: local.verdict.clone(),
        })
        .collect()
}

/// Loopback and the gateways in `family`: the Docker host itself.
fn local_sources(family: Family, gateways: &[IpAddr]) -> Vec<Expression<'static>> {
    let loopback = match family {
        Family::V4 => AddrOrRange::Net(IpNet::V4(Ipv4Net::new_assert(
            std::net::Ipv4Addr::new(127, 0, 0, 0),
            8,
        ))),
        Family::V6 => AddrOrRange::Addr(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    };
    std::iter::once(entry_expr(&loopback))
        .chain(
            gateways
                .iter()
                .filter(|gateway| Family::of(gateway) == family)
                .map(address_expr),
        )
        .collect()
}

fn external_grants(
    family: Family,
    own: &[Expression<'static>],
    excluded: &[Expression<'static>],
    external: &ExternalAccess,
    published: &PortsByProto,
) -> Vec<Grant> {
    let sources = match peers_in(&external.sources, family) {
        PeerMatch::Any => None,
        PeerMatch::Only(addresses) => Some(addresses),
        PeerMatch::Nothing => return Vec::new(),
    };
    // Only traffic that arrived through a port mapping, and not from the Docker host itself,
    // counts as external. Without docker-proxy, localhost connections are DNATed too.
    let excluded = excluded.to_vec();
    published
        .values()
        .map(|(proto, ports)| Grant {
            family,
            role: Role::Responder,
            initiator: sources.clone(),
            initiator_excluded: Some(excluded.clone()),
            responder: Some(own.to_vec()),
            proto: *proto,
            initiator_ports: Vec::new(),
            responder_ports: ports.clone(),
            through_port_mapping: true,
            log_prefix: external.log_prefix.clone(),
            verdict: external.verdict.clone(),
        })
        .collect()
}

fn output_grant(family: Family, own: &[Expression<'static>], output: &OutputRule) -> Option<Grant> {
    let destinations = match peers_in(&output.destinations, family) {
        PeerMatch::Any => None,
        PeerMatch::Only(addresses) => Some(addresses),
        PeerMatch::Nothing => return None,
    };
    Some(Grant {
        family,
        role: Role::Initiator,
        initiator: Some(own.to_vec()),
        initiator_excluded: None,
        responder: destinations,
        proto: output.proto,
        initiator_ports: output.src_ports.clone(),
        responder_ports: output.dst_ports.clone(),
        through_port_mapping: false,
        log_prefix: output.log_prefix.clone(),
        verdict: output.verdict.clone(),
    })
}

/// Rules of every base chain: each managed address is sent to its container's chain whether it
/// is the source or the destination. Anything else falls through untouched.
pub fn dispatch_rules(
    layer: Layer,
    base_chain: &str,
    containers: &[ManagedContainer],
) -> Vec<Rule<'static>> {
    let mut rules = Vec::new();

    for family in Family::ALL {
        let mut targets: BTreeMap<IpAddr, String> = BTreeMap::new();
        for container in containers {
            for address in container.addresses_in(family) {
                if let Some(existing) = targets.get(&address) {
                    tracing::warn!(
                        %address,
                        kept = %existing,
                        ignored = %container.chain(),
                        "two managed containers claim one address; keeping the first",
                    );
                } else {
                    targets.insert(address, container.chain());
                }
            }
        }
        if targets.is_empty() {
            continue;
        }
        let map: Vec<SetItem<'static>> = targets
            .iter()
            .map(|(address, chain)| {
                SetItem::Mapping(
                    address_expr(address),
                    Expression::Verdict(NfVerdict::Jump(JumpTarget {
                        target: Cow::Owned(chain.clone()),
                    })),
                )
            })
            .collect();
        for field in ["saddr", "daddr"] {
            rules.push(rule(
                layer,
                base_chain,
                vec![Statement::VerdictMap(VerdictMap {
                    key: payload(family.payload(), field),
                    data: Expression::Named(NamedExpression::Set(map.clone())),
                })],
            ));
        }
    }
    rules
}

/// How a peer restriction applies in one address family.
enum PeerMatch {
    /// No restriction: any address.
    Any,
    /// Only these addresses.
    Only(Vec<Expression<'static>>),
    /// The restriction lists no address in this family, so nothing in it is admitted.
    Nothing,
}

fn peers_in(peers: &Peers, family: Family) -> PeerMatch {
    match peers {
        Peers::Any => PeerMatch::Any,
        Peers::Only(entries) => {
            let matching: Vec<Expression<'static>> = entries
                .iter()
                .filter(|entry| Family::of_entry(entry) == family)
                .map(entry_expr)
                .collect();
            if matching.is_empty() {
                PeerMatch::Nothing
            } else {
                PeerMatch::Only(matching)
            }
        }
    }
}

fn rule(layer: Layer, chain: &str, body: Vec<Statement<'static>>) -> Rule<'static> {
    Rule {
        family: layer.family(),
        table: Cow::Borrowed(TABLE),
        chain: Cow::Owned(chain.to_owned()),
        expr: Cow::Owned(body),
        ..Rule::default()
    }
}

fn tail(log_prefix: Option<&str>, verdict: &Verdict) -> Vec<Statement<'static>> {
    let mut statements = vec![Statement::Counter(Counter::Anonymous(None))];
    if let Some(prefix) = log_prefix {
        statements.push(log(prefix));
    }
    statements.push(match verdict {
        Verdict::Accept => Statement::Accept(None),
        Verdict::Jump(chain) => Statement::Jump(JumpTarget {
            target: Cow::Owned(chain.clone()),
        }),
        Verdict::Queue { number, .. } => queue_statement(*number),
    });
    statements
}

fn queue_statement(number: u16) -> Statement<'static> {
    Statement::Queue(Queue {
        num: Expression::Number(u32::from(number)),
        flags: None,
    })
}

fn established_or_related() -> Expression<'static> {
    Expression::List(vec![
        Expression::String(Cow::Borrowed("established")),
        Expression::String(Cow::Borrowed("related")),
    ])
}

fn log(prefix: &str) -> Statement<'static> {
    Statement::Log(Some(Log {
        prefix: Some(Cow::Owned(prefix.to_owned())),
        group: None,
        snaplen: None,
        queue_threshold: None,
        level: Some(LogLevel::Info),
        flags: None,
    }))
}

fn port_matches(proto: Protocol, src: &[RulePorts], dst: &[RulePorts]) -> Vec<Statement<'static>> {
    let name = proto_name(proto);
    let mut statements = vec![Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::L4proto,
        })),
        right: Expression::String(Cow::Borrowed(name)),
        op: Operator::EQ,
    })];
    for (field, ports) in [("sport", src), ("dport", dst)] {
        if !ports.is_empty() {
            statements.push(Statement::Match(Match {
                left: payload(name, field),
                right: set_or_single(ports.iter().map(port_expr).collect()),
                op: Operator::EQ,
            }));
        }
    }
    statements
}

fn proto_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn ct_match(key: &'static str, right: Expression<'static>) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: Cow::Borrowed(key),
            family: None,
            dir: None,
        })),
        right,
        op: Operator::IN,
    })
}

fn address_match(
    family: Family,
    field: &'static str,
    values: Vec<Expression<'static>>,
) -> Statement<'static> {
    Statement::Match(Match {
        left: payload(family.payload(), field),
        right: set_or_single(values),
        op: Operator::EQ,
    })
}

fn payload(protocol: &'static str, field: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Borrowed(protocol),
            field: Cow::Borrowed(field),
        },
    )))
}

fn set_or_single(mut values: Vec<Expression<'static>>) -> Expression<'static> {
    if values.len() == 1
        && let Some(single) = values.pop()
    {
        return single;
    }
    Expression::Named(NamedExpression::Set(
        values.into_iter().map(SetItem::Element).collect(),
    ))
}

fn address_expr(address: &IpAddr) -> Expression<'static> {
    Expression::String(Cow::Owned(address.to_string()))
}

fn entry_expr(entry: &AddrOrRange) -> Expression<'static> {
    match entry {
        AddrOrRange::Addr(address) => address_expr(address),
        AddrOrRange::Range(start, end) => Expression::Range(Box::new(Range {
            range: [address_expr(start), address_expr(end)],
        })),
        AddrOrRange::Net(network) => Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(address_expr(&network.addr())),
            len: u32::from(network.prefix_len()),
        })),
    }
}

fn port_expr(ports: &RulePorts) -> Expression<'static> {
    match ports {
        RulePorts::Single(port) => Expression::Number(u32::from(*port)),
        RulePorts::Range(start, end) => Expression::Range(Box::new(Range {
            range: [
                Expression::Number(u32::from(*start)),
                Expression::Number(u32::from(*end)),
            ],
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use nftables::schema::Rule;
    use serde_json::{Value, json};

    use super::{
        EstablishedQueues, ExternalAccess, Layer, LocalAccess, ManagedContainer, OutputRule, Peers,
        PublishedPort, Verdict, chain_name, dispatch_rules,
    };
    use crate::docker::config::{AddrOrRange, Protocol, RulePorts};

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 18, 0, 2));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
    const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1));

    fn bare(addresses: Vec<IpAddr>) -> ManagedContainer {
        ManagedContainer {
            id: "0123456789abcdef".to_owned(),
            name: "web".to_owned(),
            addresses,
            gateways: vec![GATEWAY],
            published: vec![PublishedPort {
                port: 8080,
                proto: Protocol::Tcp,
            }],
            localhost: None,
            external: None,
            outputs: Vec::new(),
        }
    }

    fn container_rules(container: &ManagedContainer) -> Vec<Rule<'static>> {
        super::container_rules(Layer::Routed, container)
    }

    fn rendered(rules: &[Rule<'static>]) -> Vec<Value> {
        rules
            .iter()
            .map(|rule| serde_json::to_value(&rule.expr).expect("render rule"))
            .collect()
    }

    fn contains(rule: &Value, needle: &Value) -> bool {
        rule.as_array()
            .is_some_and(|statements| statements.iter().any(|statement| statement == needle))
    }

    fn verdict_of(rule: &Value) -> Option<&Value> {
        rule.as_array().and_then(|statements| statements.last())
    }

    #[test]
    fn chain_names_are_sanitised_and_bounded() {
        assert_eq!(
            chain_name("0123456789abcdef", "my_app.web"),
            "hs-my-app-web-0123456789ab"
        );
        assert_eq!(chain_name("short", "x"), "hs-x-short");
        assert!(chain_name("0123456789abcdef", &"n".repeat(300)).len() < 256);
    }

    #[test]
    fn a_container_without_grants_accepts_replies_and_drops_the_rest() {
        let rules = rendered(&container_rules(&bare(vec![V4])));
        assert_eq!(rules.len(), 3);
        assert!(
            rules
                .get(1)
                .expect("neighbour discovery rule")
                .to_string()
                .contains("nd-neighbor-advert")
        );
        let first = rules.first().expect("established rule");
        assert!(contains(first, &json!({"accept": null})));
        assert!(first.to_string().contains("established"));
        assert_eq!(
            verdict_of(rules.last().expect("drop rule")),
            Some(&json!({"drop": null}))
        );
    }

    #[test]
    fn external_grants_require_a_port_mapping_and_the_allowlist() {
        let mut container = bare(vec![V4]);
        container.external = Some(ExternalAccess {
            sources: Peers::Only(vec![AddrOrRange::Addr(IpAddr::V4(Ipv4Addr::new(
                198, 18, 0, 2,
            )))]),
            log_prefix: None,
            verdict: Verdict::Accept,
        });
        let rules = rendered(&container_rules(&container));
        let grant = rules.get(2).expect("grant after the established rule");
        assert!(contains(
            grant,
            &json!({"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}})
        ));
        assert!(contains(
            grant,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "198.18.0.2"}})
        ));
        assert!(contains(
            grant,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "172.18.0.2"}})
        ));
        assert!(contains(
            grant,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}})
        ));
        assert_eq!(verdict_of(grant), Some(&json!({"accept": null})));
    }

    #[test]
    fn external_grants_never_admit_the_docker_host_itself() {
        let mut container = bare(vec![V4]);
        container.external = Some(ExternalAccess {
            sources: Peers::Any,
            log_prefix: None,
            verdict: Verdict::Accept,
        });
        let rules = rendered(&container_rules(&container));
        let grant = rules.get(2).expect("grant");
        assert!(contains(
            grant,
            &json!({"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                "right": {"set": [{"prefix": {"addr": "127.0.0.0", "len": 8}}, "172.18.0.1"]}}})
        ));
    }

    #[test]
    fn localhost_grants_admit_the_listed_sources_without_a_port_mapping() {
        let mut container = bare(vec![V4]);
        container.localhost = Some(LocalAccess {
            sources: vec![IpAddr::V4(Ipv4Addr::LOCALHOST), GATEWAY],
            log_prefix: Some("local".to_owned()),
            verdict: Verdict::Accept,
        });
        let rules = rendered(&container_rules(&container));
        let grant = rules.get(2).expect("grant");
        assert!(!grant.to_string().contains("dnat"));
        assert!(grant.to_string().contains("172.18.0.1"));
        assert!(grant.to_string().contains("127.0.0.1"));
        assert!(contains(
            grant,
            &json!({"log": {"prefix": "local", "level": "info"}})
        ));
    }

    #[test]
    fn grants_are_emitted_only_in_families_both_sides_cover() {
        let mut container = bare(vec![V4]);
        container.external = Some(ExternalAccess {
            sources: Peers::Only(vec![AddrOrRange::Addr(V6)]),
            log_prefix: None,
            verdict: Verdict::Accept,
        });
        // The allowlist names only an IPv6 source and the container has only IPv4: no grant.
        assert_eq!(container_rules(&container).len(), 3);

        container.addresses.push(V6);
        let rules = rendered(&container_rules(&container));
        assert_eq!(rules.len(), 4);
        assert!(
            rules
                .get(2)
                .expect("v6 grant")
                .to_string()
                .contains("\"ip6\"")
        );
    }

    #[test]
    fn output_grants_to_any_destination_match_no_destination_address() {
        let mut container = bare(vec![V4]);
        container.outputs.push(OutputRule {
            destinations: Peers::Any,
            proto: Protocol::Udp,
            src_ports: Vec::new(),
            dst_ports: vec![RulePorts::Range(5000, 5010), RulePorts::Single(53)],
            log_prefix: None,
            verdict: Verdict::Jump("audit".to_owned()),
        });
        let rules = rendered(&container_rules(&container));
        let grant = rules.get(2).expect("grant");
        assert!(!grant.to_string().contains("daddr"));
        assert!(grant.to_string().contains("\"saddr\""));
        assert!(grant.to_string().contains("\"range\":[5000,5010]"));
        assert_eq!(
            verdict_of(grant),
            Some(&json!({"jump": {"target": "audit"}}))
        );
    }

    #[test]
    fn established_queues_follow_the_direction_relative_to_the_container() {
        let mut container = bare(vec![V4]);
        container.external = Some(ExternalAccess {
            sources: Peers::Any,
            log_prefix: None,
            verdict: Verdict::Queue {
                number: 10,
                established: Some(EstablishedQueues {
                    inbound: 11,
                    outbound: 12,
                }),
            },
        });
        let rules = rendered(&container_rules(&container));
        // inbound established, outbound established, established accept, neighbour discovery,
        // new grant, drop
        assert_eq!(rules.len(), 6);
        let inbound = rules.first().expect("inbound queue rule");
        let outbound = rules.get(1).expect("outbound queue rule");
        assert!(contains(
            inbound,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "172.18.0.2"}})
        ));
        assert_eq!(verdict_of(inbound), Some(&json!({"queue": {"num": 11}})));
        assert!(contains(
            outbound,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "172.18.0.2"}})
        ));
        assert!(contains(
            outbound,
            &json!({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "sport"}}, "right": 8080}})
        ));
        assert_eq!(verdict_of(outbound), Some(&json!({"queue": {"num": 12}})));
        assert_eq!(
            verdict_of(rules.get(4).expect("new grant")),
            Some(&json!({"queue": {"num": 10}}))
        );
    }

    #[test]
    fn dispatch_maps_each_family_by_source_and_destination() {
        let rules = rendered(&dispatch_rules(
            Layer::Routed,
            "forward",
            &[bare(vec![V4, V6])],
        ));
        assert_eq!(rules.len(), 4);
        let text = serde_json::to_string(&rules).expect("render");
        assert!(text.contains("\"protocol\":\"ip\""));
        assert!(text.contains("\"protocol\":\"ip6\""));
        assert!(text.contains("hs-web-0123456789ab"));
    }

    #[test]
    fn dispatch_keeps_the_first_claim_on_a_shared_address() {
        let first = bare(vec![V4]);
        let mut second = bare(vec![V4]);
        second.id = "fedcba9876543210".to_owned();
        let text = serde_json::to_string(&rendered(&dispatch_rules(
            Layer::Routed,
            "forward",
            &[first, second],
        )))
        .expect("render");
        assert!(text.contains("hs-web-0123456789ab"));
        assert!(!text.contains("hs-web-fedcba987654"));
    }

    #[test]
    fn the_bridged_layer_builds_the_same_chain_in_the_bridge_family() {
        let container = bare(vec![V4]);
        let bridged = super::container_rules(Layer::Bridged, &container);
        assert_eq!(bridged.len(), container_rules(&container).len());
        assert!(
            bridged
                .iter()
                .all(|rule| rule.family == nftables::types::NfFamily::Bridge)
        );
    }

    #[test]
    fn no_managed_containers_means_no_dispatch() {
        assert!(dispatch_rules(Layer::Routed, "input", &[]).is_empty());
    }
}
