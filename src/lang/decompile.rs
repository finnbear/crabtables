//! Kernel objects (bytecode) to nft language (AST).

use std::collections::{HashMap, HashSet};

use crate as nft;
use crate::PayloadBase;
use crate::expr as kx;
use crate::sys::*;
use crate::{Data, Family, ObjKind as KObjKind, Reg, Ruleset};

use super::ast::*;
use super::datatype::{self, Kind, Order, id};
use super::proto::{self, Layer, Proto, ethertype};
use super::typeof_udata;

/// Decompile a ruleset snapshot into tables.
pub fn ruleset(rs: &Ruleset) -> Vec<Table> {
    let mut out = Vec::new();
    for t in &rs.tables {
        out.push(table(rs, t));
    }
    out
}

/// Kernel set lookup key.
type SetKey<'a> = (Family, &'a str, &'a str);

struct Env<'a> {
    rs: &'a Ruleset,
    sets: HashMap<SetKey<'a>, (&'a nft::Set, &'a [nft::SetElem])>,
    binding: HashSet<SetKey<'a>>,
    /// Keep the elements of anonymous sets in the kernel's order (as nft
    /// prints events) instead of sorting them (as in listings).
    keep_order: bool,
}

fn env(rs: &Ruleset) -> Env<'_> {
    let mut env = Env {
        rs,
        sets: HashMap::new(),
        binding: HashSet::new(),
        keep_order: false,
    };
    for (s, e) in &rs.sets {
        env.sets.insert(
            (s.family, s.table.as_str(), s.name.as_str()),
            (s, e.as_slice()),
        );
    }
    for c in &rs.chains {
        if c.flags.unwrap_or(0) & NFT_CHAIN_BINDING != 0 {
            env.binding
                .insert((c.family, c.table.as_str(), c.name.as_str()));
        }
    }
    env
}

/// Decompile one rule; sets it refers to are looked up in `rs`.
pub fn one_rule(rs: &Ruleset, r: &nft::Rule) -> Rule {
    rule(&env(rs), r)
}

/// Decompile one rule from an event (anonymous set elements in the order
/// the kernel reported them).
pub fn event_rule(rs: &Ruleset, r: &nft::Rule) -> Rule {
    let mut e = env(rs);
    e.keep_order = true;
    rule(&e, r)
}

fn table(rs: &Ruleset, t: &nft::Table) -> Table {
    let env = env(rs);
    let fam = t.family;
    let mut items = Vec::new();
    for o in rs
        .objs
        .iter()
        .filter(|o| o.family == fam && o.table == t.name)
    {
        if let Some(o) = obj(o) {
            items.push(TableItem::Obj(o));
        }
    }
    for (s, e) in rs
        .sets
        .iter()
        .filter(|(s, _)| s.family == fam && s.table == t.name)
    {
        if s.flags & NFT_SET_ANONYMOUS != 0 {
            continue;
        }
        items.push(TableItem::Set(set(s, e)));
    }
    for f in rs
        .flowtables
        .iter()
        .filter(|f| f.family == fam && f.table == t.name)
    {
        items.push(TableItem::Flowtable(Flowtable {
            span: Span::default(),
            name_span: Span::default(),
            name: f.name.clone(),
            handle: f.handle,
            hook: "ingress".into(),
            priority: priority(fam, "ingress", f.priority.unwrap_or(0)),
            devices: {
                let mut d = f.devices.clone();
                d.sort_unstable();
                d
            },
            counter: f.flags.unwrap_or(0) & NFT_FLOWTABLE_COUNTER != 0,
            offload: f.flags.unwrap_or(0) & NFT_FLOWTABLE_HW_OFFLOAD != 0,
        }));
    }
    for c in rs
        .chains
        .iter()
        .filter(|c| c.family == fam && c.table == t.name)
    {
        if env
            .binding
            .contains(&(c.family, c.table.as_str(), c.name.as_str()))
        {
            continue;
        }
        items.push(TableItem::Chain(chain(&env, c)));
    }
    let flags = t.flags.unwrap_or(0);
    let mut fl = Vec::new();
    if flags & NFT_TABLE_F_DORMANT != 0 {
        fl.push("dormant".into());
    }
    if flags & NFT_TABLE_F_OWNER != 0 {
        fl.push("owner".into());
    }
    if flags & NFT_TABLE_F_PERSIST != 0 {
        fl.push("persist".into());
    }
    let owner = (flags & NFT_TABLE_F_OWNER != 0)
        .then(|| {
            t.owner
                .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).ok())
        })
        .flatten()
        .map(|s| s.trim().to_owned());
    Table {
        span: Span::default(),
        name_span: Span::default(),
        family: fam,
        name: t.name.clone(),
        handle: t.handle,
        flags: fl,
        comment: t.comment().map(str::to_owned),
        items,
        owner,
    }
}

// ------------------------------------------------------------------ chains

const HOOKS_INET: [&str; 6] = [
    "prerouting",
    "input",
    "forward",
    "output",
    "postrouting",
    "ingress",
];

fn hook_name(fam: Family, h: u32) -> String {
    match fam {
        Family::Netdev => if h == 0 { "ingress" } else { "egress" }.into(),
        Family::Arp => ["input", "output", "forward"]
            .get(h as usize)
            .copied()
            .unwrap_or("?")
            .into(),
        _ => HOOKS_INET.get(h as usize).copied().unwrap_or("?").into(),
    }
}

/// Standard priorities `(name, value, hooks it is valid for)`.
fn std_prios(fam: Family) -> &'static [(&'static str, i32, &'static [&'static str])] {
    const ALL: &[&str] = &[
        "prerouting",
        "input",
        "forward",
        "output",
        "postrouting",
        "ingress",
        "egress",
    ];
    match fam {
        Family::Bridge => &[
            ("dstnat", -300, &["prerouting"]),
            ("filter", -200, ALL),
            ("out", 100, &["output"]),
            ("srcnat", 300, &["postrouting"]),
        ],
        Family::Arp | Family::Netdev => &[("filter", 0, ALL)],
        _ => &[
            ("raw", -300, ALL),
            ("mangle", -150, ALL),
            ("dstnat", -100, &["prerouting", "output"]),
            ("filter", 0, ALL),
            ("security", 50, ALL),
            ("srcnat", 100, &["postrouting", "input"]),
        ],
    }
}

/// The printed form of priority `p` on `hook`.
pub fn priority(fam: Family, hook: &str, p: i32) -> Priority {
    for (name, v, hooks) in std_prios(fam) {
        if hooks.contains(&hook) && p.abs_diff(*v) <= 10 {
            return Priority {
                name: Some((*name).to_owned()),
                offset: p - v,
            };
        }
    }
    Priority {
        name: None,
        offset: p,
    }
}

fn chain(env: &Env<'_>, c: &nft::Chain) -> Chain {
    let base = c.hook.as_ref().map(|h| {
        let hook = hook_name(c.family, h.hook.0);
        let mut devices = h.devices.clone();
        devices.sort_unstable();
        if let (Some(d), true) = (&h.device, devices.is_empty()) {
            devices.push(d.clone());
        }
        BaseChain {
            ty: c
                .chain_type
                .as_ref()
                .map(|t| t.as_str().to_owned())
                .unwrap_or_else(|| "filter".into()),
            priority: priority(c.family, &hook, h.priority),
            hook,
            devices,
            policy: c.policy.map(|p| match p {
                nft::Policy::Accept => "accept".into(),
                nft::Policy::Drop => "drop".into(),
            }),
        }
    });
    Chain {
        span: Span::default(),
        base_span: Span::default(),
        name_span: Span::default(),
        name: c.name.clone(),
        handle: c.handle,
        base,
        comment: c.comment().map(str::to_owned),
        rules: chain_rules(env, c.family, &c.table, &c.name),
    }
}

fn chain_rules(env: &Env<'_>, fam: Family, table: &str, chain: &str) -> Vec<Rule> {
    env.rs
        .chain_rules(fam, table, chain)
        .map(|r| rule(env, r))
        .collect()
}

// ------------------------------------------------------------------ objects

fn l3_name(n: u16) -> Option<String> {
    match n {
        0 => None,
        2 => Some("ip".into()),
        10 => Some("ip6".into()),
        1 => Some("inet".into()),
        n => Some(n.to_string()),
    }
}

fn proto_name(n: u8) -> String {
    datatype::protocol_name(u64::from(n)).map_or_else(|| n.to_string(), str::to_owned)
}

const TCP_TIMEOUT_STATES: &[(&str, u32)] = &[
    ("syn_sent", 120),
    ("syn_recv", 60),
    ("established", 432_000),
    ("fin_wait", 120),
    ("close_wait", 60),
    ("last_ack", 30),
    ("time_wait", 120),
    ("close", 10),
    ("syn_sent2", 120),
    ("retrans", 300),
    ("unack", 300),
];
const UDP_TIMEOUT_STATES: &[(&str, u32)] = &[("unreplied", 30), ("replied", 120)];

/// Per-state timeout names and kernel defaults for a layer 4 protocol.
pub(crate) fn timeout_states(l4: u8) -> &'static [(&'static str, u32)] {
    match l4 {
        6 => TCP_TIMEOUT_STATES,
        17 | 136 => UDP_TIMEOUT_STATES,
        _ => &[("timeout", 30)],
    }
}

/// Synproxy option flags (`NF_SYNPROXY_OPT_*`).
pub(crate) const SYNPROXY_MSS: u32 = 0x01;
pub(crate) const SYNPROXY_WSCALE: u32 = 0x02;
pub(crate) const SYNPROXY_SACK_PERM: u32 = 0x04;
pub(crate) const SYNPROXY_TIMESTAMP: u32 = 0x08;

fn obj(o: &nft::Obj) -> Option<Obj> {
    let body = match &o.kind {
        KObjKind::Counter(c) => ObjBody::Counter {
            packets: c.packets,
            bytes: c.bytes,
        },
        KObjKind::Quota(q) => ObjBody::Quota(Quota {
            over: q.flags & NFT_QUOTA_F_INV != 0,
            bytes: q.bytes,
            used: q.consumed.unwrap_or(0),
        }),
        KObjKind::Limit(l) => {
            let mut l = limit(l);
            // Objects omit the default packet burst.
            if l.rate_unit.is_none() && l.burst == Some(5) {
                l.burst = None;
            }
            ObjBody::Limit(l)
        }
        KObjKind::CtHelper(h) => ObjBody::CtHelper {
            helper: h.name.clone(),
            protocol: proto_name(h.l4proto),
            l3proto: l3_name(h.l3proto.unwrap_or(0)),
        },
        KObjKind::CtTimeout(t) => {
            let states = timeout_states(t.l4proto);
            let policy = t
                .policy()
                .into_iter()
                .filter_map(|(attr, v)| {
                    let (name, def) = states.get((attr as usize).checked_sub(1)?)?;
                    (v != *def).then(|| ((*name).to_owned(), v))
                })
                .collect();
            ObjBody::CtTimeout {
                protocol: proto_name(t.l4proto),
                l3proto: l3_name(t.l3proto.unwrap_or(0)),
                policy,
            }
        }
        KObjKind::CtExpect(e) => ObjBody::CtExpect {
            protocol: proto_name(e.l4proto),
            dport: e.dport,
            timeout: u64::from(e.timeout),
            size: e.size,
            l3proto: l3_name(e.l3proto.unwrap_or(0)),
        },
        KObjKind::Synproxy(s) => {
            let fl = s.flags.unwrap_or(0);
            let mut flags = Vec::new();
            if fl & SYNPROXY_TIMESTAMP != 0 {
                flags.push("timestamp".into());
            }
            if fl & SYNPROXY_SACK_PERM != 0 {
                flags.push("sack-perm".into());
            }
            ObjBody::Synproxy {
                mss: s.mss.unwrap_or(0),
                wscale: s.wscale.unwrap_or(0),
                flags,
            }
        }
        KObjKind::Secmark(s) => ObjBody::Secmark(s.ctx.clone()),
        _ => return None,
    };
    Some(Obj {
        span: Span::default(),
        name_span: Span::default(),
        name: o.name.clone(),
        handle: o.handle,
        comment: o.comment().map(str::to_owned),
        body,
    })
}

fn bytes_rate(n: u64) -> (u64, String) {
    if n != 0 && n % (1024 * 1024) == 0 {
        (n / (1024 * 1024), "mbytes".into())
    } else if n != 0 && n % 1024 == 0 {
        (n / 1024, "kbytes".into())
    } else {
        (n, "bytes".into())
    }
}

fn limit(l: &kx::Limit) -> Limit {
    let per = match l.unit {
        1 => "second",
        60 => "minute",
        3600 => "hour",
        86400 => "day",
        604800 => "week",
        _ => "second",
    }
    .to_owned();
    let over = l.flags & NFT_LIMIT_F_INV != 0;
    match l.ty {
        nft::LimitType::Bytes => {
            let (rate, unit) = bytes_rate(l.rate);
            let (burst, burst_unit) = if l.burst == 0 {
                (None, None)
            } else {
                let (b, u) = bytes_rate(u64::from(l.burst));
                (Some(b), Some(u))
            };
            Limit {
                over,
                rate,
                rate_unit: Some(unit),
                per,
                burst,
                burst_unit,
            }
        }
        _ => Limit {
            over,
            rate: l.rate,
            rate_unit: None,
            per,
            burst: (l.burst != 0).then_some(u64::from(l.burst)),
            burst_unit: None,
        },
    }
}

// ------------------------------------------------------------------ sets

/// A component of a set key: type, field bits, and whether the kernel
/// stores it in network byte order.
#[derive(Debug, Clone, Copy)]
struct Comp {
    ty: u32,
    bits: u32,
    be: bool,
    /// Values are stored shifted left by this many bits (sub-byte fields).
    shift: u32,
}

fn type_name(id: u32) -> String {
    datatype::by_id(id).name.to_owned()
}

/// Split a concatenated type id into components.
fn split_type(mut t: u32) -> Vec<u32> {
    let mut v = Vec::new();
    while t != 0 {
        v.push(t & 0x3f);
        t >>= 6;
    }
    v.reverse();
    if v.is_empty() {
        v.push(0);
    }
    v
}

/// Type of an expression used as a set key: (type id, bits, network order).
fn expr_comp(e: &Expr) -> Option<Comp> {
    match e {
        Expr::Payload { proto: p, field } => {
            let f = proto::proto(p)?.field(field)?.1;
            Some(Comp {
                ty: f.ty,
                bits: f.len,
                be: true,
                shift: 0,
            })
        }
        Expr::Meta(k) => {
            let m = proto::meta(k)?;
            Some(Comp {
                ty: m.ty,
                bits: m.len * 8,
                be: datatype::by_id(m.ty).order == Order::Big,
                shift: 0,
            })
        }
        Expr::Ct { key, .. } => {
            let c = proto::ct(key)?;
            Some(Comp {
                ty: c.ty,
                bits: c.len * 8,
                be: datatype::by_id(c.ty).order == Order::Big,
                shift: 0,
            })
        }
        Expr::Osf { .. } => Some(Comp {
            ty: id::STRING,
            bits: 128,
            be: false,
            shift: 0,
        }),
        Expr::Numgen { .. } => Some(Comp {
            ty: id::INTEGER,
            bits: 32,
            be: false,
            shift: 0,
        }),
        _ => None,
    }
}

fn key_comps(s: &nft::Set) -> (Option<TypeSpec>, Vec<Comp>) {
    let ud = s.userdata.as_deref().unwrap_or(&[]);
    let tyof = nft::udata::iter(ud)
        .find(|(t, _)| *t == nft::udata::UDATA_SET_KEY_TYPEOF)
        .and_then(|(_, v)| typeof_udata::decode(v));
    let order = nft::udata::iter(ud)
        .find(|(t, _)| *t == nft::udata::UDATA_SET_KEYBYTEORDER)
        .and_then(|(_, v)| {
            v.get(..4)
                .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
        });
    let types = split_type(s.key_type);
    let comps: Vec<Comp> = match &tyof {
        Some(exprs) if exprs.len() == types.len() || types == [0] => exprs
            .iter()
            .map(|e| {
                expr_comp(e).unwrap_or(Comp {
                    ty: id::INTEGER,
                    bits: 32,
                    be: true,
                    shift: 0,
                })
            })
            .collect(),
        _ => {
            let n = types.len();
            types
                .iter()
                .map(|t| {
                    let ty = datatype::by_id(*t);
                    let bits = if ty.bits == 0 {
                        s.key_len.saturating_mul(8) / n as u32
                    } else {
                        ty.bits
                    };
                    let be = match (n, order) {
                        (1, Some(nft::udata::BYTEORDER_BIG)) => true,
                        (1, Some(nft::udata::BYTEORDER_HOST)) => false,
                        _ => ty.order == Order::Big,
                    };
                    Comp {
                        ty: *t,
                        bits,
                        be,
                        shift: 0,
                    }
                })
                .collect()
        }
    };
    let mut comps = comps;
    if s.flags & NFT_SET_INTERVAL != 0 {
        // Interval keys are compared as big endian numbers.
        for c in &mut comps {
            c.be = true;
        }
    }
    let spec = match tyof {
        Some(e) => TypeSpec::Typeof(e),
        None => TypeSpec::Type(types.iter().map(|t| type_name(*t)).collect()),
    };
    (Some(spec), comps)
}

fn data_spec(s: &nft::Set) -> (Option<TypeSpec>, Option<Comp>) {
    if s.flags & NFT_SET_OBJECT != 0 {
        let name = match s.obj_type.unwrap_or(0) {
            NFT_OBJECT_COUNTER => "counter",
            NFT_OBJECT_QUOTA => "quota",
            NFT_OBJECT_LIMIT => "limit",
            NFT_OBJECT_CT_HELPER => "ct helper",
            NFT_OBJECT_CT_TIMEOUT => "ct timeout",
            NFT_OBJECT_CT_EXPECT => "ct expectation",
            NFT_OBJECT_SYNPROXY => "synproxy",
            NFT_OBJECT_SECMARK => "secmark",
            _ => "object",
        };
        return (Some(TypeSpec::Type(vec![name.into()])), None);
    }
    if s.flags & NFT_SET_MAP == 0 {
        return (None, None);
    }
    let dt = s.data_type.unwrap_or(0);
    if dt == NFT_DATA_VERDICT {
        return (Some(TypeSpec::Type(vec!["verdict".into()])), None);
    }
    let ud = s.userdata.as_deref().unwrap_or(&[]);
    let tyof = nft::udata::iter(ud)
        .find(|(t, _)| *t == nft::udata::UDATA_SET_DATA_TYPEOF)
        .and_then(|(_, v)| typeof_udata::decode(v));
    let order = nft::udata::iter(ud)
        .find(|(t, _)| *t == nft::udata::UDATA_SET_DATABYTEORDER)
        .and_then(|(_, v)| {
            v.get(..4)
                .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
        });
    let types = split_type(dt);
    let ty = datatype::by_id(types[0]);
    let bits = if ty.bits == 0 {
        s.data_len.unwrap_or(4).saturating_mul(8)
    } else {
        ty.bits
    };
    let be = match order {
        Some(nft::udata::BYTEORDER_BIG) => true,
        Some(nft::udata::BYTEORDER_HOST) => false,
        _ => ty.order == Order::Big,
    };
    let comp = tyof
        .as_ref()
        .and_then(|e| e.first())
        .and_then(expr_comp)
        .unwrap_or(Comp {
            ty: types[0],
            bits,
            be,
            shift: 0,
        });
    let spec = match tyof {
        Some(e) => TypeSpec::Typeof(e),
        None => TypeSpec::Type(types.iter().map(|t| type_name(*t)).collect()),
    };
    (Some(spec), Some(comp))
}

fn set_flags(f: u32) -> Vec<String> {
    let mut v = Vec::new();
    for (bit, name) in [
        (NFT_SET_CONSTANT, "constant"),
        (NFT_SET_EVAL, "dynamic"),
        (NFT_SET_INTERVAL, "interval"),
        (NFT_SET_TIMEOUT, "timeout"),
    ] {
        if f & bit != 0 {
            v.push(name.to_owned());
        }
    }
    v
}

fn set(s: &nft::Set, elems: &[nft::SetElem]) -> Set {
    let ud = s.userdata.as_deref().unwrap_or(&[]);
    let (key, comps) = key_comps(s);
    let (data, dcomp) = data_spec(s);
    Set {
        span: Span::default(),
        name_span: Span::default(),
        name: s.name.clone(),
        handle: s.handle,
        is_map: s.flags & (NFT_SET_MAP | NFT_SET_OBJECT) != 0,
        key,
        data,
        data_interval: nft::udata::iter(ud)
            .any(|(t, v)| t == nft::udata::UDATA_SET_DATA_INTERVAL && v.first() == Some(&1)),
        flags: set_flags(s.flags),
        timeout: s.timeout.map(|d| d.as_millis() as u64).filter(|t| *t != 0),
        gc_interval: s.gc_interval.map(u64::from).filter(|t| *t != 0),
        size: s.size,
        policy: s
            .policy
            .and_then(|p| (p == NFT_SET_POL_MEMORY).then(|| "memory".to_owned())),
        auto_merge: nft::udata::iter(ud).any(|(t, _)| t == nft::udata::UDATA_SET_MERGE_ELEMENTS),
        comment: nft::udata::get_str(ud, nft::udata::UDATA_SET_COMMENT).map(str::to_owned),
        stmts: s
            .exprs
            .iter()
            .filter_map(simple_stmt)
            .map(|st| match st {
                // Set level expressions are templates without state.
                Stmt::Counter { .. } => Stmt::Counter {
                    packets: None,
                    bytes: None,
                },
                st => st,
            })
            .collect(),
        elements: Some(elements(s, elems, &comps, dcomp, false)),
    }
}

fn value_of(c: Comp, kernel: &[u8]) -> Expr {
    let ty = datatype::by_id(c.ty);
    if c.shift != 0 {
        let v = datatype::to_u128(kernel, Order::Big) >> c.shift;
        let n = c.bits.div_ceil(8) as usize;
        return Expr::Value(Value::Typed {
            ty: c.ty,
            bytes: datatype::from_u128(v, n, ty.order),
            bits: c.bits,
        });
    }
    let mut b =
        kernel[..kernel
            .len()
            .min(c.bits.div_ceil(8) as usize)
            .max(if ty.kind == Kind::Str {
                kernel.len()
            } else {
                0
            })]
            .to_vec();
    if ty.kind == Kind::Str {
        b = kernel.to_vec();
    }
    if c.be != (ty.order == Order::Big)
        && cfg!(target_endian = "little")
        && !matches!(ty.kind, Kind::Str | Kind::Ether | Kind::Ipv4 | Kind::Ipv6)
    {
        b.reverse();
    }
    Expr::Value(Value::Typed {
        ty: c.ty,
        bytes: b,
        bits: c.bits,
    })
}

/// Split a concatenated key into its components' bytes.
fn split_key<'a>(key: &'a [u8], comps: &[Comp]) -> Vec<&'a [u8]> {
    if comps.len() == 1 {
        return vec![key];
    }
    let mut v = Vec::new();
    let mut off = 0;
    for c in comps {
        let n = (c.bits.div_ceil(8) as usize).div_ceil(4) * 4;
        let end = (off + n).min(key.len());
        let real = (c.bits.div_ceil(8) as usize).min(end - off);
        v.push(&key[off..off + real]);
        off = end;
    }
    v
}

fn key_expr(key: &[u8], comps: &[Comp]) -> Expr {
    let parts: Vec<Expr> = split_key(key, comps)
        .into_iter()
        .zip(comps)
        .map(|(b, c)| value_of(*c, b))
        .collect();
    if parts.len() == 1 {
        parts.into_iter().next().unwrap()
    } else {
        Expr::Concat(parts)
    }
}

/// Whether type `ty` is printed as an address with prefixes.
fn prefixable(ty: u32) -> bool {
    matches!(ty, id::IPADDR | id::IP6ADDR)
}

/// The prefix length if `[lo, hi]` is exactly a prefix.
fn prefix_len(lo: &[u8], hi: &[u8]) -> Option<u32> {
    let bits = lo.len() as u32 * 8;
    let l = datatype::to_u128(lo, Order::Big);
    let h = datatype::to_u128(hi, Order::Big);
    for p in 0..=bits {
        let host = bits - p;
        let mask: u128 = if host >= 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        if l & mask == 0 && h == l | mask {
            return Some(p);
        }
    }
    None
}

/// The prefix length of a network order mask like `ff ff f0 00`.
fn mask_prefix(mask: &[u8]) -> Option<u32> {
    let bits = mask.len() as u32 * 8;
    if bits == 0 || bits > 128 {
        return None;
    }
    let v = datatype::to_u128(mask, Order::Big) << (128 - bits);
    let ones = v.leading_ones();
    let expect = if ones == 0 {
        0
    } else {
        u128::MAX << (128 - ones)
    };
    (v == expect).then_some(ones)
}

/// An interval `[lo, hi]` (kernel bytes, network order) as an expression.
fn interval(c: Comp, lo: &[u8], hi: &[u8]) -> Expr {
    if lo == hi {
        return value_of(c, lo);
    }
    // A string range covering every value with a prefix is a wildcard
    // (`"eth*"`).
    if matches!(c.ty, id::IFNAME | id::STRING) && lo.len() == hi.len() {
        let p = lo.iter().zip(hi).take_while(|(a, b)| a == b).count();
        if lo[p..].iter().all(|&b| b == 0) && hi[p..].iter().all(|&b| b == 0xff) {
            let prefix = String::from_utf8_lossy(&lo[..p]);
            return Expr::raw(format!("\"{prefix}*\""));
        }
    }
    if prefixable(c.ty) {
        if let Some(p) = prefix_len(lo, hi) {
            return Expr::Prefix(Box::new(value_of(c, lo)), p);
        }
    }
    Expr::Range(Box::new(value_of(c, lo)), Box::new(value_of(c, hi)))
}

fn decrement(v: &[u8]) -> Vec<u8> {
    let mut out = v.to_vec();
    for b in out.iter_mut().rev() {
        let (n, borrow) = b.overflowing_sub(1);
        *b = n;
        if !borrow {
            break;
        }
    }
    out
}

fn elem_common(s: &nft::Set, e: &nft::SetElem, out: &mut Elem, dcomp: Option<Comp>) {
    let set_timeout = s.timeout.map(|d| d.as_millis() as u64);
    out.timeout = e
        .timeout
        .map(|d| d.as_millis() as u64)
        .filter(|t| Some(*t) != set_timeout && *t != 0);
    out.expires = e.expiration.map(|d| d.as_millis() as u64);
    out.comment = e.comment().map(str::to_owned);
    out.stmts = e.exprs.iter().filter_map(simple_stmt).collect();
    out.data = match (&e.data, &e.objref) {
        (Some(Data::Verdict(v)), _) => Some(Expr::Verdict(verdict(v))),
        (Some(Data::Value(v)), _) => dcomp.map(|c| {
            // Interval data: low and high values.
            let ud = s.userdata.as_deref().unwrap_or(&[]);
            let iv = nft::udata::iter(ud)
                .any(|(t, x)| t == nft::udata::UDATA_SET_DATA_INTERVAL && x.first() == Some(&1));
            if iv && v.len() % 2 == 0 {
                let (lo, hi) = v.split_at(v.len() / 2);
                interval(Comp { be: true, ..c }, lo, hi)
            } else {
                value_of(c, v)
            }
        }),
        (None, Some(name)) => Some(string_value(name)),
        _ => None,
    };
}

fn string_value(s: &str) -> Expr {
    Expr::Value(Value::Typed {
        ty: id::STRING,
        bytes: s.as_bytes().to_vec(),
        bits: s.len() as u32 * 8,
    })
}

fn sort_key(e: &Elem) -> Vec<u128> {
    fn val(e: &Expr, v: &mut Vec<u128>) {
        match e {
            Expr::Value(Value::Typed { ty, bytes, .. }) => {
                let t = datatype::by_id(*ty);
                if bytes.len() <= 16 {
                    v.push(datatype::to_u128(bytes, t.order));
                } else {
                    v.extend(bytes.chunks(16).map(|c| datatype::to_u128(c, Order::Big)));
                }
            }
            Expr::Range(a, _) | Expr::Prefix(a, _) => val(a, v),
            Expr::Concat(p) => p.iter().for_each(|x| val(x, v)),
            _ => {}
        }
    }
    let mut v = Vec::new();
    if let Some(k) = &e.key {
        val(k, &mut v);
    } else {
        v.push(u128::MAX);
    }
    v
}

fn elements(
    s: &nft::Set,
    elems: &[nft::SetElem],
    comps: &[Comp],
    dcomp: Option<Comp>,
    keep_order: bool,
) -> Vec<Elem> {
    let mut out = Vec::new();
    let interval_set = s.flags & NFT_SET_INTERVAL != 0;
    if interval_set && comps.len() == 1 {
        // Elements come as start / end markers; sort by key (network order).
        let mut ev: Vec<&nft::SetElem> = elems.iter().collect();
        // On equal keys the end of the previous interval comes first.
        ev.sort_unstable_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then(b.is_interval_end().cmp(&a.is_interval_end()))
        });
        let mut i = 0;
        while i < ev.len() {
            let e = ev[i];
            if e.is_catchall() {
                let mut el = Elem::default();
                elem_common(s, e, &mut el, dcomp);
                out.push(el);
                i += 1;
                continue;
            }
            if e.is_interval_end() {
                i += 1;
                continue;
            }
            let lo = e.key.clone().unwrap_or_default();
            // The interval ends before the next end marker or, in anonymous
            // sets (which omit an end that is the next start), the next start.
            let hi = match ev.get(i + 1) {
                Some(n) if !n.is_catchall() => decrement(n.key.as_deref().unwrap_or(&[])),
                _ => vec![0xff; lo.len()],
            };
            let mut el = Elem::key(interval(comps[0], &lo, &hi));
            elem_common(s, e, &mut el, dcomp);
            out.push(el);
            i += 1;
        }
        return out;
    }
    for e in elems {
        let mut el = Elem::default();
        if !e.is_catchall() {
            let key = e.key.as_deref().unwrap_or(&[]);
            el.key = Some(match &e.key_end {
                Some(end) => {
                    let lo = split_key(key, comps);
                    let hi = split_key(end, comps);
                    let parts: Vec<Expr> = lo
                        .iter()
                        .zip(hi.iter())
                        .zip(comps)
                        .map(|((l, h), c)| interval(*c, l, h))
                        .collect();
                    if parts.len() == 1 {
                        parts.into_iter().next().unwrap()
                    } else {
                        Expr::Concat(parts)
                    }
                }
                None => key_expr(key, comps),
            });
        }
        elem_common(s, e, &mut el, dcomp);
        out.push(el);
    }
    // Concatenated intervals are listed in the kernel's (insertion) order.
    if !(s.flags & NFT_SET_INTERVAL != 0 && comps.len() > 1) && !keep_order {
        // (Stable: values without a numeric key keep the kernel's order.)
        out.sort_by_cached_key(sort_key);
    }
    out
}

// ------------------------------------------------------------------ rules

fn verdict(v: &nft::Verdict) -> Verdict {
    match v {
        nft::Verdict::Accept => Verdict::Accept,
        nft::Verdict::Drop => Verdict::Drop,
        nft::Verdict::Continue => Verdict::Continue,
        nft::Verdict::Return => Verdict::Return,
        nft::Verdict::Queue => Verdict::Queue,
        nft::Verdict::Jump(c) => Verdict::Jump(c.clone()),
        nft::Verdict::Goto(c) => Verdict::Goto(c.clone()),
        nft::Verdict::JumpId(i) => Verdict::Jump(format!("<chain id {i}>")),
        nft::Verdict::GotoId(i) => Verdict::Goto(format!("<chain id {i}>")),
        nft::Verdict::Break => Verdict::Continue,
        nft::Verdict::Other(c) => Verdict::Jump(format!("<verdict {c}>")),
    }
}

/// Statements that need no register context (set and element expressions).
fn simple_stmt(e: &nft::Expr) -> Option<Stmt> {
    Some(match e {
        nft::Expr::Counter(c) => Stmt::Counter {
            packets: Some(c.packets),
            bytes: Some(c.bytes),
        },
        nft::Expr::Limit(l) => Stmt::Limit(limit(l)),
        nft::Expr::Quota(q) => Stmt::Quota(Quota {
            over: q.flags & NFT_QUOTA_F_INV != 0,
            bytes: q.bytes,
            used: q.consumed.unwrap_or(0),
        }),
        nft::Expr::Connlimit(c) => Stmt::Connlimit {
            count: c.count,
            over: c.flags & NFT_CONNLIMIT_F_INV != 0,
        },
        nft::Expr::Last(l) => Stmt::Last {
            used: (l.set.unwrap_or(0) != 0).then(|| l.msecs.unwrap_or(0)),
        },
        _ => return None,
    })
}

/// What a dependency match provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provides {
    /// Layer 3 protocol (by ether type), from `meta nfproto`.
    L3(u16),
    /// Layer 3 protocol, from `meta protocol` / `ether type`.
    L3Proto(u16),
    /// Layer 4 protocol, from `meta l4proto`.
    L4(u8),
    /// Layer 4 protocol, from `ip protocol` / `ip6 nexthdr`.
    L4Payload(u8),
    /// Ethernet link layer (`meta iiftype ether`).
    Ether,
    /// VLAN header (`ether type vlan`).
    Vlan,
}

/// A register's content.
#[derive(Debug, Clone)]
struct RegVal {
    expr: Expr,
    ty: u32,
    bits: u32,
    /// Value bytes are in network order in the register.
    be: bool,
    /// Right shift to apply to compared values (sub-byte fields).
    shift: u32,
    /// Bytes occupied in the register.
    len: u32,
    /// Unresolved payload load.
    load: Option<(PayloadBase, u32, u32)>,
    /// Immediate data.
    imm: Option<Vec<u8>>,
    /// A truncated load of an address field (prefix match), in bytes.
    prefix: Option<u32>,
    /// Raw kernel mask applied by a bitwise operation.
    mask: Option<Vec<u8>>,
    /// Unresolved extension header load: (op, type, offset, len).
    xload: Option<(nft::ExthdrOp, u8, u32, u32)>,
    /// Read-modify-write of a payload load: (load, mask, xor).
    rmw: Option<(Load, Vec<u8>, Vec<u8>)>,
}

/// A payload load: base, offset and length in bytes.
type Load = (PayloadBase, u32, u32);

impl RegVal {
    fn expr(e: Expr, ty: u32, bits: u32, be: bool) -> Self {
        RegVal {
            expr: e,
            ty,
            bits,
            be,
            shift: 0,
            len: bits.div_ceil(8),
            load: None,
            imm: None,
            prefix: None,
            mask: None,
            xload: None,
            rmw: None,
        }
    }
}

struct Dec<'a, 'b> {
    env: &'a Env<'b>,
    family: Family,
    table: String,
    regs: HashMap<u32, RegVal>,
    stmts: Vec<Option<Stmt>>,
    deps: Vec<(usize, Provides)>,
    l3: Option<u16>,
    l4: Option<u8>,
    ether: bool,
    vlan: bool,
}

fn word(r: Reg) -> u32 {
    r.word_index().unwrap_or(0)
}

fn base_name(b: PayloadBase) -> &'static str {
    match b {
        PayloadBase::LinkLayer => "ll",
        PayloadBase::Network => "nh",
        PayloadBase::Transport => "th",
        PayloadBase::Inner => "ih",
        _ => "th",
    }
}

/// Whether the offsets and lengths of `e` are within what the kernel
/// accepts (so that the arithmetic on them cannot overflow).
fn plausible(e: &nft::Expr) -> bool {
    // NFT_DATA_VALUE_MAXLEN; offsets are at most 255 in the kernel.
    const LEN: u32 = 64;
    const OFF: u32 = 0xffff;
    match e {
        nft::Expr::Payload(p) => p.offset <= OFF && p.len <= LEN,
        nft::Expr::Exthdr(x) => x.offset <= OFF && x.len <= LEN,
        nft::Expr::Bitwise(b) => b.len <= LEN,
        nft::Expr::Cmp(c) => c.data.len() <= LEN as usize,
        _ => true,
    }
}

/// A mask of `bits` bits starting `rel` bits into an `nbytes` value.
fn rel_mask(rel: u32, bits: u32, nbytes: u32) -> Vec<u8> {
    let mut m = vec![0u8; nbytes as usize];
    for b in rel..(rel + bits).min(nbytes * 8) {
        m[(b / 8) as usize] |= 0x80 >> (b % 8);
    }
    m
}

fn field_mask(bo: u32, f: &proto::HdrField, nbytes: u32) -> Vec<u8> {
    let start = (bo + f.offset) - ((bo + f.offset) / 8) * 8;
    let total = nbytes * 8;
    let shift = total - start - f.len;
    let m: u128 = if f.len >= 128 {
        u128::MAX
    } else {
        ((1u128 << f.len) - 1) << shift
    };
    datatype::from_u128(m, nbytes as usize, Order::Big)
}

impl Dec<'_, '_> {
    fn push(&mut self, s: Stmt) -> usize {
        self.stmts.push(Some(s));
        self.stmts.len() - 1
    }

    fn family_l3(&self) -> Option<u16> {
        match self.family {
            Family::Ipv4 => Some(ethertype::IP),
            Family::Ipv6 => Some(ethertype::IP6),
            Family::Arp => Some(ethertype::ARP),
            _ => None,
        }
    }

    fn l2_ether(&self) -> bool {
        matches!(self.family, Family::Bridge | Family::Netdev) || self.ether
    }

    /// Consume pending dependencies that protocol `p` relies on.
    fn consume(&mut self, p: &Proto) {
        self.consume_ext(p, false)
    }

    /// `ext`: the consumer is an extension header / option access, which
    /// also consumes `ip protocol` / `ip6 nexthdr` dependencies in inet.
    fn consume_ext(&mut self, p: &Proto, ext: bool) {
        let mut wanted: Vec<Provides> = Vec::new();
        match p.layer {
            Layer::Link => {
                wanted.push(Provides::Ether);
                if p.name == "vlan" {
                    wanted.push(Provides::Vlan);
                }
            }
            Layer::Network(t) => {
                wanted.push(Provides::L3(t));
                wanted.push(Provides::L3Proto(t));
            }
            Layer::Transport(Some(n)) => {
                wanted.push(Provides::L4(n));
                if ext || matches!(self.family, Family::Ipv4 | Family::Ipv6) {
                    wanted.push(Provides::L4Payload(n));
                }
                match p.ip_version() {
                    Some(true) => wanted.push(Provides::L3(ethertype::IP)),
                    Some(false) => wanted.push(Provides::L3(ethertype::IP6)),
                    None => {}
                }
            }
            Layer::Transport(None) => {}
        }
        let mut keep = Vec::new();
        for (idx, prov) in std::mem::take(&mut self.deps) {
            if wanted.contains(&prov) {
                self.stmts[idx] = None;
            } else {
                keep.push((idx, prov));
            }
        }
        self.deps = keep;
    }

    /// Resolve a payload load (with optional mask) to a field.
    fn resolve(
        &mut self,
        base: PayloadBase,
        off: u32,
        len: u32,
        mask: Option<&[u8]>,
    ) -> Option<RegVal> {
        let candidates: Vec<&'static Proto> = match base {
            PayloadBase::LinkLayer if self.l2_ether() => {
                let mut v = vec![proto::proto("ether").unwrap()];
                if self.vlan || matches!(self.family, Family::Bridge | Family::Netdev) {
                    v.push(proto::proto("vlan").unwrap());
                }
                v
            }
            PayloadBase::Network => self
                .l3
                .or(self.family_l3())
                .and_then(proto::network)
                .into_iter()
                .collect(),
            PayloadBase::Transport => {
                let mut v: Vec<&Proto> = self.l4.and_then(proto::transport).into_iter().collect();
                v.push(proto::proto("th").unwrap());
                v
            }
            _ => Vec::new(),
        };
        for p in candidates.iter().copied() {
            for f in p.fields {
                let start_bit = p.base_offset + f.offset;
                // Position of the field within the loaded bytes.
                let Some(rel) = start_bit.checked_sub(off * 8) else {
                    continue;
                };
                if rel + f.len > len * 8 {
                    continue;
                }
                let ok = match mask {
                    None => rel == 0 && f.len == len * 8,
                    Some(m) => f.len != len * 8 && m == rel_mask(rel, f.len, len).as_slice(),
                };
                if !ok {
                    continue;
                }
                // `th` only applies when no specific transport is known.
                if p.name == "th"
                    && self
                        .l4
                        .and_then(proto::transport)
                        .is_some_and(|t| t.field(f.name).is_some())
                {
                    continue;
                }
                self.consume(p);
                let shift = len * 8 - rel - f.len;
                return Some(RegVal {
                    shift,
                    len,
                    ..RegVal::expr(
                        Expr::Payload {
                            proto: p.name.into(),
                            field: f.name.into(),
                        },
                        f.ty,
                        f.len,
                        true,
                    )
                });
            }
        }
        // A shortened load of an address field is a prefix match.
        if mask.is_none() {
            for p in &candidates {
                for f in p.fields {
                    let sb = (p.base_offset + f.offset) / 8;
                    if matches!(f.ty, id::IPADDR | id::IP6ADDR) && sb == off && len < f.len / 8 {
                        self.consume(p);
                        return Some(RegVal {
                            prefix: Some(len),
                            len,
                            ..RegVal::expr(
                                Expr::Payload {
                                    proto: p.name.into(),
                                    field: f.name.into(),
                                },
                                f.ty,
                                f.len,
                                true,
                            )
                        });
                    }
                }
            }
        }
        None
    }

    /// Whether a load does not resolve to a single field (without side effects).
    fn resolve_peek(&self, base: PayloadBase, off: u32, len: u32) -> bool {
        let candidates: Vec<&'static Proto> = match base {
            PayloadBase::Network => self
                .l3
                .or(self.family_l3())
                .and_then(proto::network)
                .into_iter()
                .collect(),
            PayloadBase::Transport => {
                let mut v: Vec<&Proto> = self.l4.and_then(proto::transport).into_iter().collect();
                v.push(proto::proto("th").unwrap());
                v
            }
            PayloadBase::LinkLayer => vec![proto::proto("ether").unwrap()],
            _ => Vec::new(),
        };
        !candidates.iter().any(|p| {
            p.fields.iter().any(|f| {
                let s = p.base_offset + f.offset;
                s / 8 == off
                    && (s + f.len).div_ceil(8) - s / 8 == len
                    && s % 8 == 0
                    && f.len % 8 == 0
            })
        })
    }

    fn raw(base: PayloadBase, off: u32, len: u32) -> RegVal {
        RegVal::expr(
            Expr::Raw {
                base: base_name(base).into(),
                offset: off * 8,
                len: len * 8,
            },
            id::BITMASK,
            len * 8,
            true,
        )
    }

    /// Finalize a register read (resolving unmasked payload loads).
    fn read(&mut self, w: u32) -> Option<RegVal> {
        let rv = self.regs.get(&w)?.clone();
        if let Some((op, ty, off, len)) = rv.xload {
            let r = self
                .resolve_exthdr(op, ty, off, len, None, false)
                .unwrap_or(rv);
            self.regs.insert(w, r.clone());
            return Some(r);
        }
        if let Some((b, o, l)) = rv.load {
            let r = self
                .resolve(b, o, l, None)
                .unwrap_or_else(|| Self::raw(b, o, l));
            self.regs.insert(w, r.clone());
            return Some(r);
        }
        Some(rv)
    }

    /// Read a (possibly concatenated) key of `len` bytes starting at `r`.
    fn read_key(&mut self, r: Reg, len: u32) -> Option<(Expr, Vec<RegVal>)> {
        let mut w = word(r);
        let mut parts = Vec::new();
        let mut got = 0;
        while got < len {
            let rv = self.read(w)?;
            let n = rv.len.div_ceil(4) * 4;
            got += if len > rv.len && parts.is_empty() && len - rv.len < 4 {
                len
            } else {
                n.max(4)
            };
            w += n.max(4) / 4;
            parts.push(rv);
            if parts.len() > 16 {
                break;
            }
        }
        let e = if parts.len() == 1 {
            parts[0].expr.clone()
        } else {
            Expr::Concat(parts.iter().map(|p| p.expr.clone()).collect())
        };
        Some((e, parts))
    }

    /// A value compared against `rv`.
    fn value(&self, rv: &RegVal, data: &[u8]) -> Expr {
        let ty = datatype::by_id(rv.ty);
        if rv.shift != 0
            || rv.bits % 8 != 0
            || (rv.len * 8 > rv.bits
                && rv.prefix.is_none()
                && rv.ty != id::BITMASK
                && datatype::by_id(rv.ty).kind != Kind::Str)
        {
            let v = datatype::to_u128(data, Order::Big) >> rv.shift;
            let n = rv.bits.div_ceil(8) as usize;
            return Expr::Value(Value::Typed {
                ty: rv.ty,
                bytes: datatype::from_u128(v, n, ty.order),
                bits: rv.bits,
            });
        }
        if rv.ty == id::BITMASK {
            let v = datatype::to_u128(data, Order::Big);
            return Expr::Value(Value::Typed {
                ty: rv.ty,
                bytes: datatype::from_u128(v, data.len(), Order::Host),
                bits: rv.bits,
            });
        }
        value_of(
            Comp {
                ty: rv.ty,
                bits: rv.bits,
                be: rv.be,
                shift: 0,
            },
            data,
        )
    }

    /// The dependency a match `left == value` represents.
    fn dependency(&self, left: &Expr, rv: &RegVal, data: &[u8]) -> Option<Provides> {
        let byte = |i: usize| data.get(i).copied().unwrap_or(0);
        match left {
            Expr::Meta(k) if k == "nfproto" => match byte(0) {
                2 => Some(Provides::L3(ethertype::IP)),
                10 => Some(Provides::L3(ethertype::IP6)),
                _ => None,
            },
            Expr::Meta(k) if k == "l4proto" => Some(Provides::L4(byte(0))),
            Expr::Meta(k) if k == "protocol" => {
                Some(Provides::L3Proto(u16::from_be_bytes([byte(0), byte(1)])))
            }
            Expr::Meta(k) if k == "iiftype" && rv.ty == id::ARPHRD => {
                (u16::from_ne_bytes([byte(0), byte(1)]) == 1).then_some(Provides::Ether)
            }
            Expr::Payload { proto: p, field } => match (p.as_str(), field.as_str()) {
                ("ether", "type") | ("vlan", "type") => {
                    match u16::from_be_bytes([byte(0), byte(1)]) {
                        ethertype::VLAN => Some(Provides::Vlan),
                        t => Some(Provides::L3Proto(t)),
                    }
                }
                ("ip", "protocol") | ("ip6", "nexthdr") => Some(Provides::L4Payload(byte(0))),
                _ => None,
            },
            _ => None,
        }
    }

    fn apply_dep(&mut self, p: Provides) {
        match p {
            Provides::L3(t) | Provides::L3Proto(t) => self.l3 = Some(t),
            Provides::L4(n) | Provides::L4Payload(n) => self.l4 = Some(n),
            Provides::Ether => self.ether = true,
            Provides::Vlan => {
                self.vlan = true;
                self.ether = true;
            }
        }
    }

    fn lookup_set(&self, name: &str) -> Option<(&nft::Set, &[nft::SetElem])> {
        self.env
            .sets
            .get(&(self.family, self.table.as_str(), name))
            .copied()
    }

    /// The set referenced by a lookup, as an expression (inline when anonymous).
    fn set_expr(&self, name: &str, key_parts: &[RegVal]) -> Expr {
        match self.lookup_set(name) {
            Some((s, elems)) if s.flags & NFT_SET_ANONYMOUS != 0 => {
                let (_, mut comps) = key_comps(s);
                // Anonymous sets may lack precise types; use the key's.
                if comps.len() == key_parts.len() {
                    for (c, p) in comps.iter_mut().zip(key_parts) {
                        if c.ty == id::INTEGER || c.ty == id::INVALID {
                            c.ty = p.ty;
                            c.be = p.be;
                            c.bits = p.bits;
                        }
                        c.shift = p.shift;
                    }
                }
                let (_, dcomp) = data_spec(s);
                Expr::Set(elements(s, elems, &comps, dcomp, self.env.keep_order))
            }
            _ => Expr::SetRef(name.to_owned()),
        }
    }

    fn regval_of_set_data(&self, name: &str) -> (u32, u32, bool) {
        match self.lookup_set(name) {
            Some((s, _)) => match data_spec(s).1 {
                Some(c) => (c.ty, c.bits, c.be),
                None => (
                    id::INTEGER,
                    s.data_len.unwrap_or(4).saturating_mul(8),
                    false,
                ),
            },
            None => (id::INTEGER, 32, false),
        }
    }

    /// Value of a register used as a statement argument of type `ty`.
    fn arg(&mut self, r: Option<Reg>, ty: u32, bits: u32, be: bool) -> Option<Expr> {
        let w = word(r?);
        let rv = self.regs.get(&w)?.clone();
        if let Some(imm) = rv.imm {
            return Some(value_of(
                Comp {
                    ty,
                    bits,
                    be,
                    shift: 0,
                },
                &imm,
            ));
        }
        self.read(w).map(|v| v.expr)
    }

    fn stmt_expr(&mut self, e: &nft::Expr) {
        if !plausible(e) {
            self.push(Stmt::Opaque(format!(
                "# unsupported expression {}",
                e.name()
            )));
            return;
        }
        match e {
            nft::Expr::Payload(p) if p.dreg.is_some() => {
                let w = word(p.dreg.unwrap());
                let rv = RegVal {
                    load: Some((p.base, p.offset, p.len)),
                    ..Self::raw(p.base, p.offset, p.len)
                };
                self.regs.insert(w, rv);
            }
            nft::Expr::Payload(p) => {
                // Read-modify-write of a field narrower than the write.
                if let Some(RegVal {
                    rmw: Some((l, mask, xor)),
                    ..
                }) = p.sreg.and_then(|r| self.regs.get(&word(r))).cloned()
                {
                    if l == (p.base, p.offset, p.len) {
                        let keep: Vec<u8> = mask.iter().map(|m| !m).collect();
                        if let Some(rv) = self.resolve(p.base, p.offset, p.len, Some(&keep)) {
                            let v: Vec<u8> = xor.iter().zip(&keep).map(|(x, k)| x & k).collect();
                            let value = self.value(&rv, &v);
                            self.push(Stmt::PayloadSet {
                                target: rv.expr,
                                value,
                            });
                            return;
                        }
                    }
                }
                // Payload write.
                let target = self
                    .resolve(p.base, p.offset, p.len, None)
                    .unwrap_or_else(|| Self::raw(p.base, p.offset, p.len));
                let value = self
                    .arg(p.sreg, target.ty, target.bits, true)
                    .unwrap_or(Expr::raw("?"));
                self.push(Stmt::PayloadSet {
                    target: target.expr,
                    value,
                });
            }
            nft::Expr::Meta(m) => {
                let def = proto::meta_by_key(m.key);
                let (name, ty, len) = match def {
                    Some(d) => (d.name.to_owned(), d.ty, d.len),
                    None => (format!("{}", m.key.raw()), id::INTEGER, 4),
                };
                let be = datatype::by_id(ty).order == Order::Big;
                if let Some(d) = m.dreg {
                    self.regs
                        .insert(word(d), RegVal::expr(Expr::Meta(name), ty, len * 8, be));
                } else {
                    let value = self.arg(m.sreg, ty, len * 8, be).unwrap_or(Expr::raw("?"));
                    self.push(Stmt::MetaSet { key: name, value });
                }
            }
            nft::Expr::Ct(c) => {
                let def = proto::ct_by_key(c.key);
                let dir = c
                    .direction
                    .map(|d| if d == 0 { "original" } else { "reply" }.to_owned());
                let (mut name, mut ty, mut len) = match def {
                    Some(d) => (d.name.to_owned(), d.ty, d.len),
                    None => (format!("{}", c.key.raw()), id::INTEGER, 4),
                };
                if len == 0 {
                    // ct saddr/daddr: family dependent.
                    let v6 = self.family == Family::Ipv6;
                    ty = if v6 { id::IP6ADDR } else { id::IPADDR };
                    len = if v6 { 16 } else { 4 };
                    name = format!("{} {name}", if v6 { "ip6" } else { "ip" });
                }
                let be = datatype::by_id(ty).order == Order::Big || c.key == nft::CtKey::Id;
                if let Some(d) = c.dreg {
                    self.regs.insert(
                        word(d),
                        RegVal::expr(Expr::Ct { dir, key: name }, ty, len * 8, be),
                    );
                } else {
                    let value = if c.key == nft::CtKey::Labels {
                        // `ct label set 5`: the bit number.
                        self.arg(c.sreg, id::CT_LABEL, 128, false)
                    } else {
                        self.arg(c.sreg, ty, len * 8, be)
                    }
                    .unwrap_or(Expr::raw("?"));
                    self.push(Stmt::CtSet {
                        key: name,
                        dir,
                        value,
                    });
                }
            }
            nft::Expr::Immediate(i) => match &i.data {
                Data::Verdict(v) => {
                    let v = match v {
                        nft::Verdict::Jump(c) | nft::Verdict::Goto(c)
                            if self.env.binding.contains(&(
                                self.family,
                                self.table.as_str(),
                                c.as_str(),
                            )) =>
                        {
                            let rules = chain_rules(self.env, self.family, &self.table, c);
                            if matches!(v, nft::Verdict::Jump(_)) {
                                Verdict::JumpBlock(rules)
                            } else {
                                Verdict::GotoBlock(rules)
                            }
                        }
                        v => verdict(v),
                    };
                    self.push(Stmt::Verdict(v));
                }
                Data::Value(b) => {
                    let mut rv =
                        RegVal::expr(Expr::raw("?"), id::INTEGER, b.len() as u32 * 8, false);
                    rv.imm = Some(b.clone());
                    rv.len = b.len() as u32;
                    self.regs.insert(word(i.dreg), rv);
                }
            },
            nft::Expr::Bitwise(b) => self.bitwise(b),
            nft::Expr::Byteorder(b) => {
                if let Some(mut rv) = self.read(word(b.sreg)) {
                    rv.be = b.op == nft::ByteorderOp::Hton;
                    self.regs.insert(word(b.dreg), rv);
                }
            }
            nft::Expr::Cmp(c) => self.cmp(c),
            nft::Expr::Range(r) => {
                if let Some(rv) = self.read(word(r.sreg)) {
                    let right = Expr::Range(
                        Box::new(self.value(&rv, &r.from)),
                        Box::new(self.value(&rv, &r.to)),
                    );
                    let op = if r.op == nft::RangeOp::Neq {
                        RelOp::Neq
                    } else {
                        RelOp::Implicit
                    };
                    self.push(Stmt::Match {
                        left: rv.expr,
                        op,
                        right,
                    });
                }
            }
            nft::Expr::Lookup(l) => {
                let key_len = self.lookup_set(&l.set).map_or(4, |(s, _)| s.key_len);
                let Some((key, parts)) = self.read_key(l.sreg, key_len) else {
                    return;
                };
                let set = self.set_expr(&l.set, &parts);
                match l.dreg {
                    None => {
                        let op = if l.flags.unwrap_or(0) & NFT_LOOKUP_F_INV != 0 {
                            RelOp::Neq
                        } else {
                            RelOp::Implicit
                        };
                        self.push(Stmt::Match {
                            left: key,
                            op,
                            right: set,
                        });
                    }
                    Some(d) if d == Reg::VERDICT => {
                        self.push(Stmt::Vmap { key, map: set });
                    }
                    Some(d) => {
                        let (ty, bits, be) = self.regval_of_set_data(&l.set);
                        self.regs.insert(
                            word(d),
                            RegVal::expr(Expr::Map(Box::new(key), Box::new(set)), ty, bits, be),
                        );
                    }
                }
            }
            nft::Expr::Dynset(d) => {
                let key_len = self.lookup_set(&d.set_name).map_or(4, |(s, _)| s.key_len);
                let Some((key, _)) = self.read_key(d.sreg_key, key_len) else {
                    return;
                };
                let data = d.sreg_data.and_then(|r| {
                    let (ty, bits, be) = self.regval_of_set_data(&d.set_name);
                    self.arg(Some(r), ty, bits, be)
                });
                let op = match d.op {
                    nft::DynsetOp::Add => "add",
                    nft::DynsetOp::Update => "update",
                    nft::DynsetOp::Delete => "delete",
                    nft::DynsetOp::Other(_) => "add",
                };
                self.push(Stmt::SetUpdate {
                    op: op.into(),
                    set: d.set_name.clone(),
                    key,
                    data,
                    timeout: d.timeout.map(|t| t.as_millis() as u64).filter(|t| *t != 0),
                    stmts: d.exprs.iter().filter_map(simple_stmt).collect(),
                });
            }
            nft::Expr::Counter(_)
            | nft::Expr::Limit(_)
            | nft::Expr::Quota(_)
            | nft::Expr::Connlimit(_)
            | nft::Expr::Last(_) => {
                if let Some(s) = simple_stmt(e) {
                    self.push(s);
                }
            }
            nft::Expr::Log(l) => self.log(l),
            nft::Expr::Objref(o) => {
                let kind = |t: Option<u32>| match t.unwrap_or(0) {
                    NFT_OBJECT_COUNTER => "counter",
                    NFT_OBJECT_QUOTA => "quota",
                    NFT_OBJECT_LIMIT => "limit",
                    NFT_OBJECT_CT_HELPER => "ct helper",
                    NFT_OBJECT_CT_TIMEOUT => "ct timeout",
                    NFT_OBJECT_CT_EXPECT => "ct expectation",
                    NFT_OBJECT_SYNPROXY => "synproxy",
                    NFT_OBJECT_SECMARK => "secmark",
                    _ => "object",
                };
                if let Some(name) = &o.imm_name {
                    let k = kind(o.imm_type.map(|t| t.raw()));
                    self.push(Stmt::Objref {
                        kind: k.into(),
                        name: string_value(name),
                    });
                } else if let (Some(r), Some(set)) = (o.set_sreg, &o.set_name) {
                    let s = self.lookup_set(set).map(|(s, _)| (s.key_len, s.obj_type));
                    let (key_len, ot) = s.unwrap_or((4, None));
                    if let Some((key, parts)) = self.read_key(r, key_len) {
                        let map = self.set_expr(set, &parts);
                        self.push(Stmt::Objref {
                            kind: kind(ot).into(),
                            name: Expr::Map(Box::new(key), Box::new(map)),
                        });
                    }
                }
            }
            nft::Expr::Reject(r) => self.reject(r),
            nft::Expr::Nat(n) => self.nat(n),
            nft::Expr::Masq(m) => {
                let port = self.ports(m.reg_proto_min, m.reg_proto_max);
                self.push(Stmt::Nat {
                    kind: NatKind::Masquerade,
                    family: None,
                    addr: None,
                    port,
                    flags: nat_flags(m.flags.unwrap_or(0)),
                });
            }
            nft::Expr::Redir(r) => {
                let port = self.ports(r.reg_proto_min, r.reg_proto_max);
                self.push(Stmt::Nat {
                    kind: NatKind::Redirect,
                    family: None,
                    addr: None,
                    port,
                    flags: nat_flags(r.flags.unwrap_or(0)),
                });
            }
            nft::Expr::Queue(q) => {
                let mut flags = Vec::new();
                let f = q.flags.unwrap_or(0);
                if f & NFT_QUEUE_FLAG_BYPASS != 0 {
                    flags.push("bypass".into());
                }
                if f & NFT_QUEUE_FLAG_CPU_FANOUT != 0 {
                    flags.push("fanout".into());
                }
                let num = if let Some(r) = q.sreg_qnum {
                    self.read(word(r)).map(|v| v.expr)
                } else {
                    let n = q.num.unwrap_or(0);
                    let t = q.total.unwrap_or(1);
                    Some(if t > 1 {
                        Expr::raw(format!("{n}-{}", u64::from(n) + u64::from(t) - 1))
                    } else {
                        Expr::raw(n.to_string())
                    })
                };
                self.push(Stmt::Queue { flags, num });
            }
            nft::Expr::Dup(d) => {
                let v6 = self.family == Family::Ipv6;
                let addr = self.arg(
                    d.sreg_addr,
                    if v6 { id::IP6ADDR } else { id::IPADDR },
                    if v6 { 128 } else { 32 },
                    true,
                );
                let dev = self.arg(d.sreg_dev, id::IFINDEX, 32, false);
                self.push(Stmt::Dup { addr, dev });
            }
            nft::Expr::Fwd(f) => {
                let dev = self
                    .arg(f.sreg_dev, id::IFINDEX, 32, false)
                    .unwrap_or(Expr::raw("?"));
                let (family, addr) = match f.nfproto {
                    Some(p) if f.sreg_addr.is_some() => {
                        let v6 = p == u32::from(NFPROTO_IPV6);
                        let a = self.arg(
                            f.sreg_addr,
                            if v6 { id::IP6ADDR } else { id::IPADDR },
                            if v6 { 128 } else { 32 },
                            true,
                        );
                        (Some(if v6 { "ip6" } else { "ip" }.to_owned()), a)
                    }
                    _ => (None, None),
                };
                self.push(Stmt::Fwd { family, addr, dev });
            }
            nft::Expr::Notrack(_) => {
                self.push(Stmt::Notrack);
            }
            nft::Expr::FlowOffload(f) => {
                self.push(Stmt::Flow(f.table_name.clone()));
            }
            nft::Expr::Tproxy(t) => {
                let v6 = t.family == u32::from(NFPROTO_IPV6);
                let addr = self.arg(
                    t.reg_addr,
                    if v6 { id::IP6ADDR } else { id::IPADDR },
                    if v6 { 128 } else { 32 },
                    true,
                );
                let port = self.arg(t.reg_port, id::INET_SERVICE, 16, true);
                let family = match self.family {
                    Family::Inet | Family::Bridge | Family::Netdev => {
                        Some(if v6 { "ip6" } else { "ip" }.to_owned())
                    }
                    _ => None,
                };
                self.push(Stmt::Tproxy { family, addr, port });
            }
            nft::Expr::Synproxy(s) => {
                let fl = s.flags.unwrap_or(0);
                let mut flags = Vec::new();
                if fl & SYNPROXY_TIMESTAMP != 0 {
                    flags.push("timestamp".into());
                }
                if fl & SYNPROXY_SACK_PERM != 0 {
                    flags.push("sack-perm".into());
                }
                self.push(Stmt::Synproxy {
                    mss: s.mss,
                    wscale: s.wscale,
                    flags,
                });
            }
            nft::Expr::Numgen(n) => {
                let mode = if n.ty == nft::NumgenType::Random {
                    "random"
                } else {
                    "inc"
                };
                self.regs.insert(
                    word(n.dreg),
                    RegVal::expr(
                        Expr::Numgen {
                            mode: mode.into(),
                            modulus: n.modulus,
                            offset: n.offset.unwrap_or(0),
                        },
                        id::INTEGER,
                        32,
                        false,
                    ),
                );
            }
            nft::Expr::Hash(h) => {
                let input = if h.ty == Some(nft::HashType::Symmetric) {
                    None
                } else {
                    h.sreg
                        .and_then(|r| self.read_key(r, h.len.unwrap_or(4)))
                        .map(|(e, _)| Box::new(e))
                };
                let e = Expr::Hash {
                    input,
                    modulus: h.modulus,
                    seed: h.seed.filter(|_| h.ty != Some(nft::HashType::Symmetric)),
                    offset: h.offset.unwrap_or(0),
                };
                self.regs
                    .insert(word(h.dreg), RegVal::expr(e, id::INTEGER, 32, false));
            }
            nft::Expr::Fib(f) => self.fib(f),
            nft::Expr::Rt(r) => {
                let (name, ty, bits, be) = match r.key {
                    nft::RtKey::ClassId => ("classid", id::REALM, 32, false),
                    nft::RtKey::Nexthop4 => ("ip nexthop", id::IPADDR, 32, true),
                    nft::RtKey::Nexthop6 => ("ip6 nexthop", id::IP6ADDR, 128, true),
                    nft::RtKey::TcpMss => ("mtu", id::INTEGER, 16, false),
                    nft::RtKey::Xfrm => ("ipsec", id::BOOLEAN, 8, false),
                    nft::RtKey::Other(_) => ("?", id::INTEGER, 32, false),
                };
                self.regs.insert(
                    word(r.dreg),
                    RegVal::expr(Expr::Rt(name.into()), ty, bits, be),
                );
            }
            nft::Expr::SocketLookup(s) => {
                let (name, ty, bits) = match s.key {
                    nft::SocketKey::Transparent => ("transparent", id::INTEGER, 8),
                    nft::SocketKey::Mark => ("mark", id::MARK, 32),
                    nft::SocketKey::Wildcard => ("wildcard", id::INTEGER, 8),
                    nft::SocketKey::CgroupV2 => ("cgroupv2", id::CGROUPV2, 64),
                    nft::SocketKey::Other(_) => ("?", id::INTEGER, 32),
                };
                let level = s.level.filter(|_| s.key == nft::SocketKey::CgroupV2);
                self.regs.insert(
                    word(s.dreg),
                    RegVal::expr(
                        Expr::Socket {
                            key: name.into(),
                            level,
                        },
                        ty,
                        bits,
                        false,
                    ),
                );
            }
            nft::Expr::Osf(o) => {
                let ttl = match o.ttl {
                    Some(1) => Some("loose".to_owned()),
                    Some(2) => Some("skip".to_owned()),
                    _ => None,
                };
                let version = o.flags.unwrap_or(0) & NFT_OSF_F_VERSION != 0;
                self.regs.insert(
                    word(o.dreg),
                    RegVal::expr(Expr::Osf { ttl, version }, id::STRING, 128, false),
                );
            }
            nft::Expr::Exthdr(x) => self.exthdr(x),
            nft::Expr::Xfrm(x) => {
                let dir = if x.dir == 0 { "in" } else { "out" };
                let (key, ty, bits, be) = match x.key {
                    1 => ("ip daddr", id::IPADDR, 32, true),
                    2 => ("ip6 daddr", id::IP6ADDR, 128, true),
                    3 => ("ip saddr", id::IPADDR, 32, true),
                    4 => ("ip6 saddr", id::IP6ADDR, 128, true),
                    5 => ("reqid", id::INTEGER, 32, false),
                    6 => ("spi", id::INTEGER, 32, true),
                    _ => ("?", id::INTEGER, 32, false),
                };
                self.regs.insert(
                    word(x.dreg),
                    RegVal::expr(
                        Expr::Ipsec {
                            dir: dir.into(),
                            spnum: x.spnum,
                            key: key.into(),
                        },
                        ty,
                        bits,
                        be,
                    ),
                );
            }
            other => {
                self.push(Stmt::Opaque(format!(
                    "# unsupported expression {}",
                    other.name()
                )));
            }
        }
    }

    fn bitwise(&mut self, b: &kx::Bitwise) {
        let w = word(b.sreg);
        let Some(src) = self.regs.get(&w).cloned() else {
            return;
        };
        let op = b.op.unwrap_or(nft::BitwiseOp::MaskXor);
        if op == nft::BitwiseOp::MaskXor {
            let mask = b.mask.clone().unwrap_or_default();
            let xor = b.xor.clone().unwrap_or_default();
            let xor_zero = xor.iter().all(|&x| x == 0);
            // A mask selecting a sub-byte field of a payload load.
            if let (Some((base, off, len)), true) = (src.load, xor_zero) {
                if let Some(rv) = self.resolve(base, off, len, Some(&mask)) {
                    self.regs.insert(word(b.dreg), rv);
                    return;
                }
            }
            if let (Some((op, ty, off, len)), true) = (src.xload, xor_zero) {
                if let Some(rv) = self.resolve_exthdr(op, ty, off, len, Some(&mask), false) {
                    self.regs.insert(word(b.dreg), rv);
                    return;
                }
            }
            if let (Some(l), false) = (src.load, xor_zero) {
                // A sub-field write: keep for the payload write.
                let mut rv = Self::raw(l.0, l.1, l.2);
                rv.rmw = Some((l, mask.clone(), xor.clone()));
                self.regs.insert(word(b.dreg), rv);
                return;
            }
            let Some(src) = self.read(w) else { return };
            let ty = src.ty;
            let mval = |v: &[u8]| {
                Box::new(self.value(
                    &RegVal {
                        shift: 0,
                        bits: src.len * 8,
                        ..src.clone()
                    },
                    v,
                ))
            };
            let all_ones = mask.iter().all(|&x| x == 0xff);
            let e = if xor_zero {
                Expr::Binop(BinOp::And, Box::new(src.expr.clone()), mval(&mask))
            } else if all_ones {
                Expr::Binop(BinOp::Xor, Box::new(src.expr.clone()), mval(&xor))
            } else if mask
                .iter()
                .zip(&xor)
                .all(|(m, x)| m & x == 0 && (m | x) == 0xff)
            {
                Expr::Binop(BinOp::Or, Box::new(src.expr.clone()), mval(&xor))
            } else {
                // nft prints the mask combined with the xor bits.
                let m: Vec<u8> = mask.iter().zip(&xor).map(|(m, x)| m | x).collect();
                Expr::Binop(
                    BinOp::Or,
                    Box::new(Expr::Binop(
                        BinOp::And,
                        Box::new(src.expr.clone()),
                        mval(&m),
                    )),
                    mval(&xor),
                )
            };
            let mut rv = RegVal { expr: e, ..src };
            rv.ty = ty;
            rv.mask = xor_zero.then_some(mask);
            self.regs.insert(word(b.dreg), rv);
        } else {
            let Some(src) = self.read(w) else { return };
            let n = b
                .data
                .as_ref()
                .and_then(|d| d.get(..4))
                .map_or(0, |d| u32::from_ne_bytes(d.try_into().unwrap()));
            let op = if op == nft::BitwiseOp::Lshift {
                BinOp::Lshift
            } else {
                BinOp::Rshift
            };
            let e = Expr::Binop(
                op,
                Box::new(src.expr.clone()),
                Box::new(Expr::raw(n.to_string())),
            );
            self.regs.insert(word(b.dreg), RegVal { expr: e, ..src });
        }
    }

    /// Split a compare of a merged load of adjacent fields.
    fn split_merged(&mut self, base: PayloadBase, off: u32, len: u32, data: &[u8]) -> bool {
        if data.len() != len as usize {
            return false;
        }
        let candidates: Vec<&'static Proto> = match base {
            PayloadBase::Network => self
                .l3
                .or(self.family_l3())
                .and_then(proto::network)
                .into_iter()
                .collect(),
            PayloadBase::Transport => {
                let mut v: Vec<&Proto> = self.l4.and_then(proto::transport).into_iter().collect();
                v.push(proto::proto("th").unwrap());
                v
            }
            PayloadBase::LinkLayer if self.l2_ether() => vec![proto::proto("ether").unwrap()],
            _ => Vec::new(),
        };
        for p in candidates {
            let mut pieces = Vec::new();
            let mut pos = off * 8;
            let end = (off + len) * 8;
            while pos < end {
                let f = p.fields.iter().find(|f| {
                    let s = p.base_offset + f.offset;
                    s == pos && f.offset % 8 == 0 && f.len % 8 == 0 && s + f.len <= end
                });
                match f {
                    Some(f) => {
                        pieces.push(f);
                        pos += f.len;
                    }
                    None => break,
                }
            }
            if pos != end || pieces.len() < 2 {
                continue;
            }
            self.consume(p);
            for f in pieces {
                let s = ((p.base_offset + f.offset) / 8 - off) as usize;
                let n = (f.len / 8) as usize;
                let rv = RegVal::expr(
                    Expr::Payload {
                        proto: p.name.into(),
                        field: f.name.into(),
                    },
                    f.ty,
                    f.len,
                    true,
                );
                let right = self.value(&rv, &data[s..s + n]);
                self.push(Stmt::Match {
                    left: rv.expr,
                    op: RelOp::Implicit,
                    right,
                });
            }
            return true;
        }
        false
    }

    fn cmp(&mut self, c: &kx::Cmp) {
        if let Some(RegVal {
            load: Some((b, o, l)),
            ..
        }) = self.regs.get(&word(c.sreg)).cloned()
        {
            if c.op == nft::CmpOp::Eq
                && self.resolve_peek(b, o, l)
                && self.split_merged(b, o, l, &c.data)
            {
                return;
            }
        }
        let Some(rv) = self.read(word(c.sreg)) else {
            return;
        };
        let op = match c.op {
            nft::CmpOp::Eq => RelOp::Implicit,
            nft::CmpOp::Neq => RelOp::Neq,
            nft::CmpOp::Lt => RelOp::Lt,
            nft::CmpOp::Lte => RelOp::Lte,
            nft::CmpOp::Gt => RelOp::Gt,
            nft::CmpOp::Gte => RelOp::Gte,
            nft::CmpOp::Other(_) => RelOp::Eq,
        };
        // Flag test: `(x & flags) != 0` is printed as `x flags`.
        if let (Expr::Binop(BinOp::And, inner, mask), RelOp::Neq) = (&rv.expr, op) {
            let is_flags = matches!(datatype::by_id(rv.ty).kind, Kind::Flags(_) | Kind::Label);
            if is_flags && c.data.iter().all(|&b| b == 0) {
                self.push(Stmt::Match {
                    left: (**inner).clone(),
                    op: RelOp::Implicit,
                    right: (**mask).clone(),
                });
                return;
            }
        }
        // Prefix matches: shortened loads and prefix masks on addresses.
        if matches!(rv.ty, id::IPADDR | id::IP6ADDR) && matches!(op, RelOp::Implicit | RelOp::Neq) {
            let full = (rv.bits / 8) as usize;
            if let Some(n) = rv.prefix {
                let mut v = c.data.clone();
                v.resize(full, 0);
                let right = Expr::Prefix(
                    Box::new(self.value(
                        &RegVal {
                            prefix: None,
                            ..rv.clone()
                        },
                        &v,
                    )),
                    n * 8,
                );
                self.push(Stmt::Match {
                    left: rv.expr,
                    op,
                    right,
                });
                return;
            }
            if let (Expr::Binop(BinOp::And, inner, _), Some(mask)) = (&rv.expr, &rv.mask) {
                if let Some(plen) = mask_prefix(mask) {
                    let right = Expr::Prefix(Box::new(self.value(&rv, &c.data)), plen);
                    self.push(Stmt::Match {
                        left: (**inner).clone(),
                        op,
                        right,
                    });
                    return;
                }
            }
        }
        let right = self.value(&rv, &c.data);
        let op = match (&rv.expr, op) {
            // Masked compares print an explicit `==`.
            (Expr::Binop(..), RelOp::Implicit) => RelOp::Eq,
            (_, op) => op,
        };
        let dep = if op == RelOp::Implicit {
            self.dependency(&rv.expr, &rv, &c.data)
        } else {
            None
        };
        let idx = self.push(Stmt::Match {
            left: rv.expr.clone(),
            op,
            right,
        });
        if let Some(p) = dep {
            self.deps.push((idx, p));
            self.apply_dep(p);
        }
    }

    fn log(&mut self, l: &kx::Log) {
        let levels = [
            "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug", "audit",
        ];
        let level = l
            .level
            .map(|v| v.raw())
            .filter(|v| *v != 4)
            .map(|v| levels.get(v as usize).copied().unwrap_or("?").to_owned());
        let flags = l.flags.filter(|f| *f != 0).map(|f| {
            if f & NF_LOG_MASK == NF_LOG_MASK {
                return "all".to_owned();
            }
            let mut parts = Vec::new();
            match (f & NF_LOG_TCPSEQ != 0, f & NF_LOG_TCPOPT != 0) {
                (true, true) => parts.push("tcp sequence,options".to_owned()),
                (true, false) => parts.push("tcp sequence".to_owned()),
                (false, true) => parts.push("tcp options".to_owned()),
                _ => {}
            }
            if f & NF_LOG_IPOPT != 0 {
                parts.push("ip options".into());
            }
            if f & NF_LOG_UID != 0 {
                parts.push("skuid".into());
            }
            if f & NF_LOG_MACDECODE != 0 {
                parts.push("ether".into());
            }
            parts.join(" ")
        });
        self.push(Stmt::Log(Log {
            prefix: l.prefix.clone(),
            group: l.group,
            snaplen: l.snaplen.filter(|n| *n != 0),
            qthreshold: l.qthreshold.filter(|n| *n != 0),
            level,
            flags,
        }));
    }

    fn reject(&mut self, r: &kx::Reject) {
        let code = r.icmp_code.unwrap_or(0);
        let (with, code) = match r.ty {
            nft::RejectType::TcpRst => (Some("tcp reset".to_owned()), None),
            nft::RejectType::IcmpxUnreach => {
                let name = datatype::ICMPX_CODES
                    .iter()
                    .find(|(_, v)| *v == u64::from(code))
                    .map(|(n, _)| *n)
                    .unwrap_or("?");
                if code == 1
                    && matches!(self.family, Family::Inet | Family::Bridge | Family::Netdev)
                {
                    (None, None)
                } else {
                    (Some("icmpx".to_owned()), Some(name.to_owned()))
                }
            }
            _ => {
                // Family specific ICMP: ICMPv6 in ip6 or after an IPv6 dependency.
                let v6 = self.family == Family::Ipv6 || self.l3 == Some(ethertype::IP6);
                if let Some(p) = proto::proto(if v6 { "ip6" } else { "ip" }) {
                    self.consume(p);
                }
                let t = datatype::by_id(if v6 { id::ICMPV6_CODE } else { id::ICMP_CODE });
                let name = datatype::symbol(t, u64::from(code))
                    .map_or_else(|| code.to_string(), str::to_owned);
                let default_code = if v6 { 4 } else { 3 };
                let native = matches!(
                    (self.family, v6),
                    (Family::Ipv4, false) | (Family::Ipv6, true)
                );
                if code == default_code && native {
                    (None, None)
                } else {
                    (
                        Some(if v6 { "icmpv6" } else { "icmp" }.to_owned()),
                        Some(name),
                    )
                }
            }
        };
        self.push(Stmt::Reject { with, code });
    }

    fn ports(&mut self, min: Option<Reg>, max: Option<Reg>) -> Option<Expr> {
        let lo = self.arg(min, id::INET_SERVICE, 16, true)?;
        match self.arg(max, id::INET_SERVICE, 16, true) {
            Some(hi) if hi != lo => Some(Expr::Range(Box::new(lo), Box::new(hi))),
            _ => Some(lo),
        }
    }

    fn nat(&mut self, n: &kx::Nat) {
        let v6 = n.family == u32::from(NFPROTO_IPV6);
        let (aty, abits) = if v6 {
            (id::IP6ADDR, 128)
        } else {
            (id::IPADDR, 32)
        };
        let addr = self.arg(n.reg_addr_min, aty, abits, true).map(|lo| {
            match self.arg(n.reg_addr_max, aty, abits, true) {
                Some(hi) if hi != lo => {
                    // Express aligned ranges as prefixes.
                    if let (
                        Expr::Value(Value::Typed { bytes: l, .. }),
                        Expr::Value(Value::Typed { bytes: h, .. }),
                    ) = (&lo, &hi)
                    {
                        if n.flags.unwrap_or(0) & NF_NAT_RANGE_NETMAP != 0 {
                            if let Some(p) = prefix_len(l, h) {
                                return Expr::Prefix(Box::new(lo.clone()), p);
                            }
                        }
                    }
                    Expr::Range(Box::new(lo), Box::new(hi))
                }
                _ => lo,
            }
        });
        let port = self.ports(n.reg_proto_min, n.reg_proto_max);
        let family = match self.family {
            Family::Inet | Family::Bridge | Family::Netdev if addr.is_some() => {
                Some(if v6 { "ip6" } else { "ip" }.to_owned())
            }
            _ => None,
        };
        let kind = if n.ty == nft::NatType::Dnat {
            NatKind::Dnat
        } else {
            NatKind::Snat
        };
        self.push(Stmt::Nat {
            kind,
            family,
            addr,
            port,
            flags: nat_flags(n.flags.unwrap_or(0)),
        });
    }

    fn fib(&mut self, f: &kx::Fib) {
        let mut flags = Vec::new();
        let fl = f.flags;
        if fl & NFTA_FIB_F_SADDR != 0 {
            flags.push("saddr".to_owned());
        }
        if fl & NFTA_FIB_F_DADDR != 0 {
            flags.push("daddr".to_owned());
        }
        if fl & NFTA_FIB_F_MARK != 0 {
            flags.push("mark".to_owned());
        }
        if fl & NFTA_FIB_F_IIF != 0 {
            flags.push("iif".to_owned());
        }
        if fl & NFTA_FIB_F_OIF != 0 {
            flags.push("oif".to_owned());
        }
        let (result, ty, bits) = match f.result {
            nft::FibResult::Oif => ("oif", id::IFINDEX, 32),
            nft::FibResult::OifName => ("oifname", id::IFNAME, 128),
            nft::FibResult::AddrType => ("type", id::FIB_ADDR, 32),
            nft::FibResult::Other(_) => ("?", id::INTEGER, 32),
        };
        let present = fl & NFTA_FIB_F_PRESENT != 0;
        let (ty, bits) = if present {
            (id::BOOLEAN, 8)
        } else {
            (ty, bits)
        };
        self.regs.insert(
            word(f.dreg),
            RegVal::expr(
                Expr::Fib {
                    flags,
                    result: result.into(),
                },
                ty,
                bits,
                false,
            ),
        );
    }

    fn exthdr(&mut self, x: &kx::Exthdr) {
        let present = x.flags.unwrap_or(0) & NFT_EXTHDR_F_PRESENT != 0;
        let op = x.op.unwrap_or(nft::ExthdrOp::Ipv6);
        match (x.dreg, x.sreg) {
            (Some(d), _) if present => {
                let rv = self
                    .resolve_exthdr(op, x.ty, x.offset, x.len, None, true)
                    .unwrap();
                self.regs.insert(word(d), rv);
            }
            (Some(d), _) => {
                let mut rv = RegVal::expr(Expr::raw("?"), id::INTEGER, x.len * 8, true);
                rv.xload = Some((op, x.ty, x.offset, x.len));
                rv.len = x.len;
                self.regs.insert(word(d), rv);
            }
            (None, Some(s)) => {
                let t = self
                    .resolve_exthdr(op, x.ty, x.offset, x.len, None, false)
                    .unwrap();
                let value = self
                    .arg(Some(s), t.ty, t.bits, true)
                    .unwrap_or(Expr::raw("?"));
                self.push(Stmt::PayloadSet {
                    target: t.expr,
                    value,
                });
            }
            _ => {}
        }
    }

    /// Resolve an extension header / option access.
    fn resolve_exthdr(
        &mut self,
        op: nft::ExthdrOp,
        ty: u8,
        off: u32,
        len: u32,
        mask: Option<&[u8]>,
        present: bool,
    ) -> Option<RegVal> {
        let (kind, table): (&str, &[ExtHdr]) = match op {
            nft::ExthdrOp::TcpOpt => ("tcp option", TCP_OPTIONS),
            nft::ExthdrOp::Ipv4 => ("ip option", IP_OPTIONS),
            nft::ExthdrOp::Sctp => ("sctp chunk", SCTP_CHUNKS),
            _ => ("exthdr", IP6_EXTHDRS),
        };
        // Dependencies: tcp options need tcp, ip options IPv4, ...
        let dep = match op {
            nft::ExthdrOp::TcpOpt => proto::proto("tcp"),
            nft::ExthdrOp::Sctp => proto::proto("sctp"),
            nft::ExthdrOp::Ipv4 => proto::proto("ip"),
            _ => proto::proto("ip6"),
        };
        if let Some(p) = dep {
            self.consume_ext(p, true);
        }
        let entry = table.iter().find(|h| h.ty == ty);
        let name = entry.map_or_else(|| ty.to_string(), |h| h.name.to_owned());
        if present {
            let desc = if kind == "exthdr" {
                format!("exthdr {name}")
            } else {
                format!("{kind} {name}")
            };
            return Some(RegVal::expr(
                Expr::Exthdr {
                    desc,
                    field: None,
                    exists: true,
                },
                id::BOOLEAN,
                8,
                false,
            ));
        }
        let desc = if kind == "exthdr" {
            name.clone()
        } else {
            format!("{kind} {name}")
        };
        let fields = entry.map_or(&[][..], |h| h.fields);
        for f in fields {
            let sb = f.1 / 8;
            let eb = (f.1 + f.2).div_ceil(8);
            if sb != off || eb - sb != len {
                continue;
            }
            let aligned = f.1 % 8 == 0 && f.2 % 8 == 0;
            let ok = match mask {
                None => aligned,
                Some(m) => {
                    let hf = proto::HdrField {
                        name: f.0,
                        offset: f.1,
                        len: f.2,
                        ty: f.3,
                    };
                    !aligned && m == field_mask(0, &hf, len).as_slice()
                }
            };
            if ok {
                let shift = eb * 8 - f.1 - f.2;
                return Some(RegVal {
                    shift,
                    len,
                    ..RegVal::expr(
                        Expr::Exthdr {
                            desc,
                            field: Some(f.0.to_owned()),
                            exists: false,
                        },
                        f.3,
                        f.2,
                        true,
                    )
                });
            }
        }
        if mask.is_some() {
            return None;
        }
        let field = format!("@{},{}", off * 8, len * 8);
        Some(RegVal {
            len,
            ..RegVal::expr(
                Expr::Exthdr {
                    desc,
                    field: Some(field),
                    exists: false,
                },
                id::BITMASK,
                len * 8,
                true,
            )
        })
    }
}

/// An extension header / option kind: type number, name and fields
/// `(name, bit offset, bit length, type id)`.
pub(crate) struct ExtHdr {
    pub ty: u8,
    pub name: &'static str,
    pub fields: &'static [(&'static str, u32, u32, u32)],
}

macro_rules! xh {
    ($ty:expr, $name:expr, [$(($f:expr, $o:expr, $l:expr, $t:expr)),* $(,)?]) => {
        ExtHdr { ty: $ty, name: $name, fields: &[$(($f, $o, $l, $t)),*] }
    };
}

const MPTCP_SUBTYPE: u32 = id::MPTCP_SUBTYPE;

/// TCP options.
pub(crate) const TCP_OPTIONS: &[ExtHdr] = &[
    xh!(0, "eol", [("kind", 0, 8, id::INTEGER)]),
    xh!(1, "nop", [("kind", 0, 8, id::INTEGER)]),
    xh!(
        2,
        "maxseg",
        [
            ("kind", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("size", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        3,
        "window",
        [
            ("kind", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("count", 16, 8, id::INTEGER)
        ]
    ),
    xh!(
        4,
        "sack-perm",
        [("kind", 0, 8, id::INTEGER), ("length", 8, 8, id::INTEGER)]
    ),
    xh!(
        5,
        "sack",
        [
            ("kind", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("left", 16, 32, id::INTEGER),
            ("right", 48, 32, id::INTEGER),
        ]
    ),
    xh!(
        8,
        "timestamp",
        [
            ("kind", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("tsval", 16, 32, id::INTEGER),
            ("tsecr", 48, 32, id::INTEGER),
        ]
    ),
    xh!(
        19,
        "md5sig",
        [("kind", 0, 8, id::INTEGER), ("length", 8, 8, id::INTEGER)]
    ),
    xh!(
        30,
        "mptcp",
        [
            ("kind", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("subtype", 16, 4, MPTCP_SUBTYPE)
        ]
    ),
    xh!(
        34,
        "fastopen",
        [("kind", 0, 8, id::INTEGER), ("length", 8, 8, id::INTEGER)]
    ),
];

/// IPv6 extension headers.
pub(crate) const IP6_EXTHDRS: &[ExtHdr] = &[
    xh!(
        0,
        "hbh",
        [
            ("nexthdr", 0, 8, id::INET_PROTOCOL),
            ("hdrlength", 8, 8, id::INTEGER)
        ]
    ),
    xh!(
        43,
        "rt",
        [
            ("nexthdr", 0, 8, id::INET_PROTOCOL),
            ("hdrlength", 8, 8, id::INTEGER),
            ("type", 16, 8, id::INTEGER),
            ("seg-left", 24, 8, id::INTEGER),
        ]
    ),
    xh!(
        44,
        "frag",
        [
            ("nexthdr", 0, 8, id::INET_PROTOCOL),
            ("reserved", 8, 8, id::INTEGER),
            ("frag-off", 16, 13, id::INTEGER),
            ("reserved2", 29, 2, id::INTEGER),
            ("more-fragments", 31, 1, id::INTEGER),
            ("id", 32, 32, id::INTEGER),
        ]
    ),
    xh!(
        60,
        "dst",
        [
            ("nexthdr", 0, 8, id::INET_PROTOCOL),
            ("hdrlength", 8, 8, id::INTEGER)
        ]
    ),
    xh!(
        135,
        "mh",
        [
            ("nexthdr", 0, 8, id::INET_PROTOCOL),
            ("hdrlength", 8, 8, id::INTEGER),
            ("type", 16, 8, id::MH_TYPE),
            ("reserved", 24, 8, id::INTEGER),
            ("checksum", 32, 16, id::INTEGER),
        ]
    ),
];

/// IPv4 options.
pub(crate) const IP_OPTIONS: &[ExtHdr] = &[
    xh!(
        131,
        "lsrr",
        [
            ("type", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("ptr", 16, 8, id::INTEGER),
            ("addr", 24, 32, id::IPADDR)
        ]
    ),
    xh!(
        7,
        "rr",
        [
            ("type", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("ptr", 16, 8, id::INTEGER),
            ("addr", 24, 32, id::IPADDR)
        ]
    ),
    xh!(
        137,
        "ssrr",
        [
            ("type", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("ptr", 16, 8, id::INTEGER),
            ("addr", 24, 32, id::IPADDR)
        ]
    ),
    xh!(
        148,
        "ra",
        [
            ("type", 0, 8, id::INTEGER),
            ("length", 8, 8, id::INTEGER),
            ("value", 16, 16, id::INTEGER)
        ]
    ),
];

/// SCTP chunks.
pub(crate) const SCTP_CHUNKS: &[ExtHdr] = &[
    xh!(
        0,
        "data",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("tsn", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        1,
        "init",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("init-tag", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        2,
        "init-ack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("init-tag", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        3,
        "sack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("cum-tsn-ack", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        4,
        "heartbeat",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        5,
        "heartbeat-ack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        6,
        "abort",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        7,
        "shutdown",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("cum-tsn-ack", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        8,
        "shutdown-ack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        9,
        "error",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        10,
        "cookie-echo",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        11,
        "cookie-ack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        12,
        "ecne",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("lowest-tsn", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        13,
        "cwr",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("lowest-tsn", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        14,
        "shutdown-complete",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER)
        ]
    ),
    xh!(
        128,
        "asconf-ack",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("seqno", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        192,
        "forward-tsn",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("new-cum-tsn", 32, 32, id::INTEGER)
        ]
    ),
    xh!(
        193,
        "asconf",
        [
            ("type", 0, 8, id::INTEGER),
            ("flags", 8, 8, id::INTEGER),
            ("length", 16, 16, id::INTEGER),
            ("seqno", 32, 32, id::INTEGER)
        ]
    ),
];

fn nat_flags(f: u32) -> Vec<String> {
    let mut v = Vec::new();
    if f & NF_NAT_RANGE_PROTO_RANDOM != 0 {
        v.push("random".into());
    }
    if f & NF_NAT_RANGE_PROTO_RANDOM_FULLY != 0 {
        v.push("fully-random".into());
    }
    if f & NF_NAT_RANGE_PERSISTENT != 0 {
        v.push("persistent".into());
    }
    if f & NF_NAT_RANGE_NETMAP != 0 {
        v.push("netmap".into());
    }
    v
}

fn rule(env: &Env<'_>, r: &nft::Rule) -> Rule {
    let mut d = Dec {
        env,
        family: r.family,
        table: r.table.clone(),
        regs: HashMap::new(),
        stmts: Vec::new(),
        deps: Vec::new(),
        l3: None,
        l4: None,
        ether: false,
        vlan: false,
    };
    for e in &r.exprs {
        d.stmt_expr(e);
    }
    Rule {
        span: Span::default(),
        stmt_spans: Vec::new(),
        stmts: d.stmts.into_iter().flatten().collect(),
        comment: r.comment().map(str::to_owned),
        handle: r.handle,
    }
}
