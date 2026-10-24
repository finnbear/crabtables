//! nft-compatible JSON (`nft -j`): output of rulesets and input of
//! commands, following libnftables' JSON schema.

use serde_json::{Map, Value as J, json};

use crate::{Family, Ruleset};

use super::ast::*;
use super::datatype::{self, Kind, Order, PrintOpts, id};
use super::error::{Error, Result};
use super::print::{self, Opts};

/// Schema version (as nft reports it).
pub const SCHEMA_VERSION: u32 = 1;

fn metainfo() -> J {
    json!({"metainfo": {
        "version": env!("CARGO_PKG_VERSION"),
        "release_name": "crabtables",
        "json_schema_version": SCHEMA_VERSION,
    }})
}

/// Format JSON like libnftables (`", "` and `": "` separators).
pub fn to_string(v: &J) -> String {
    let mut s = String::new();
    write(v, &mut s);
    s
}

fn write(v: &J, out: &mut String) {
    match v {
        J::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write(x, out);
            }
            out.push(']');
        }
        J::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push_str(": ");
                write(x, out);
            }
            out.push('}');
        }
        v => out.push_str(&serde_json::to_string(v).unwrap_or_default()),
    }
}

/// Build a JSON object from key / value pairs, skipping `None` values.
macro_rules! obj {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut m = Map::new();
        $( if let Some(v) = Opt::opt($v) { m.insert($k.to_string(), v); } )*
        J::Object(m)
    }};
}

/// Values that may be absent.
trait Opt {
    fn opt(self) -> Option<J>;
}

impl Opt for J {
    fn opt(self) -> Option<J> {
        Some(self)
    }
}

impl<T: Into<J>> Opt for Option<T> {
    fn opt(self) -> Option<J> {
        self.map(Into::into)
    }
}

fn family_str(f: Family) -> String {
    f.to_string()
}

/// JSON output of decompiled rulesets.
struct Out<'a> {
    o: &'a Opts,
    family: Family,
}

/// The JSON value of a typed value (as libnftables prints it).
fn typed(ty: u32, bytes: &[u8], bits: u32, o: &Opts) -> J {
    let t = datatype::by_id(ty);
    match t.kind {
        Kind::Boolean => J::Bool(bytes.iter().any(|&b| b != 0)),
        Kind::Duration => {
            let ms = datatype::to_u128(bytes, t.order) as u64;
            J::from(ms / 1000)
        }
        // With `-n`, libnftables prints values with a symbolic name as
        // integers in host byte order.
        Kind::SymDec(_) | Kind::SymHex(..)
            if o.numeric
                && datatype::symbol(t, datatype::to_u128(bytes, t.order) as u64).is_some() =>
        {
            J::from(datatype::to_u128(bytes, Order::Host) as u64)
        }
        Kind::SymDec(_) | Kind::SymHex(..) if o.numeric => {
            J::from(datatype::to_u128(bytes, t.order) as u64)
        }
        Kind::Flags(syms) => {
            let syms = if o.numeric { &[][..] } else { syms };
            let v = datatype::to_u128(bytes, t.order) as u64;
            let mut items = Vec::new();
            let mut rest = v;
            for (name, bit) in syms.iter() {
                if *bit != 0 && rest & bit == *bit && bit.count_ones() == 1 {
                    items.push(J::from(*name));
                    rest &= !bit;
                }
            }
            let mut b = 1u64;
            while rest != 0 {
                if rest & b != 0 {
                    items.push(J::from(b));
                    rest &= !b;
                }
                b <<= 1;
            }
            if v == 0 {
                return J::from(0);
            }
            if items.len() == 1 {
                items.pop().unwrap()
            } else {
                J::Array(items)
            }
        }
        Kind::Label => {
            let v = datatype::to_u128(bytes, Order::Host);
            J::from(v.trailing_zeros())
        }
        Kind::Ifindex => {
            let s = datatype::print(t, bytes, bits, PrintOpts::default());
            J::from(s.trim_matches('"').to_owned())
        }
        // Realms are strings (names or numbers).
        _ if ty == id::REALM => J::from(
            datatype::print(t, bytes, bits, PrintOpts::default())
                .trim_matches('"')
                .to_owned(),
        ),
        _ => {
            let s = datatype::print(t, bytes, bits, o.value_opts(false));
            text_value(&s)
        }
    }
}

/// A printed value as JSON: numbers become numbers.
fn text_value(s: &str) -> J {
    if let Some(h) = s.strip_prefix("0x") {
        if let Ok(n) = u64::from_str_radix(h, 16) {
            return J::from(n);
        }
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = s.parse::<u64>() {
            return J::from(n);
        }
    }
    J::from(s.trim_matches('"').to_owned())
}

fn verdict_json(v: &Verdict) -> J {
    match v {
        Verdict::Accept => json!({"accept": null}),
        Verdict::Drop => json!({"drop": null}),
        Verdict::Continue => json!({"continue": null}),
        Verdict::Return => json!({"return": null}),
        Verdict::Queue => json!({"queue": null}),
        Verdict::Jump(c) => json!({"jump": {"target": c}}),
        Verdict::Goto(c) => json!({"goto": {"target": c}}),
        Verdict::JumpBlock(_) | Verdict::GotoBlock(_) => J::Null,
    }
}

fn bytes_unit(n: u64) -> (u64, &'static str) {
    if n != 0 && n % (1024 * 1024) == 0 {
        (n / (1024 * 1024), "mbytes")
    } else if n != 0 && n % 1024 == 0 {
        (n / 1024, "kbytes")
    } else {
        (n, "bytes")
    }
}

/// Is a match with an implicit operator a flag test (`in`)?
fn is_flag_value(e: &Expr) -> bool {
    match e {
        Expr::Value(Value::Typed { ty, .. }) => {
            matches!(datatype::by_id(*ty).kind, Kind::Flags(_) | Kind::Label)
        }
        Expr::List(_) => true,
        _ => false,
    }
}

impl Out<'_> {
    fn value(&self, v: &Value, binop: bool) -> J {
        match v {
            Value::Raw(s) => text_value(s),
            Value::Typed { ty, bytes, bits } => {
                let t = datatype::by_id(*ty);
                if binop {
                    if let Kind::Flags(_) = t.kind {
                        // Flag combinations are ORs of the flags.
                        return match typed(*ty, bytes, *bits, self.o) {
                            J::Array(items) => {
                                let mut it = items.into_iter();
                                let mut acc = it.next().unwrap_or(J::Null);
                                for x in it {
                                    acc = json!({"|": [acc, x]});
                                }
                                acc
                            }
                            j => j,
                        };
                    }
                    if t.kind == Kind::Integer || matches!(t.kind, Kind::Hex(_)) {
                        return J::from(datatype::to_u128(bytes, t.order) as u64);
                    }
                }
                typed(*ty, bytes, *bits, self.o)
            }
        }
    }

    fn expr(&self, e: &Expr) -> J {
        self.expr_in(e, false)
    }

    fn expr_in(&self, e: &Expr, binop: bool) -> J {
        match e {
            Expr::Payload { proto, field } => {
                json!({"payload": {"protocol": proto, "field": field}})
            }
            Expr::Raw { base, offset, len } => {
                json!({"payload": {"base": base, "offset": offset, "len": len}})
            }
            Expr::Exthdr { desc, field, .. } => {
                let (kind, name) = match desc.split_once(' ') {
                    Some(("exthdr", n)) => ("exthdr", n.to_owned()),
                    Some((a, rest)) if a == "tcp" || a == "ip" || a == "sctp" => {
                        let (k2, n) = rest.split_once(' ').unwrap_or((rest, ""));
                        let kind = match (a, k2) {
                            ("tcp", _) => "tcp option",
                            ("ip", _) => "ip option",
                            _ => "sctp chunk",
                        };
                        (kind, n.to_owned())
                    }
                    _ => ("exthdr", desc.clone()),
                };
                let mut m = Map::new();
                m.insert("name".into(), J::from(name));
                if let Some(f) = field {
                    m.insert("field".into(), J::from(f.clone()));
                }
                let mut o = Map::new();
                o.insert(kind.into(), J::Object(m));
                J::Object(o)
            }
            Expr::Meta(k) => json!({"meta": {"key": k}}),
            Expr::Ct { dir, key } => {
                json!({"ct": obj!{"key" => J::from(key.clone()), "dir" => dir.clone()}})
            }
            Expr::Rt(k) => match k.split_once(' ') {
                Some((f, key)) => json!({"rt": {"key": key, "family": f}}),
                None => json!({"rt": {"key": k}}),
            },
            Expr::Socket { key, level } => {
                json!({"socket": obj!{"key" => J::from(key.clone()), "level" => *level}})
            }
            Expr::Osf { ttl, version } => json!({"osf": obj!{
                "key" => J::from(if *version { "version" } else { "name" }),
                "ttl" => ttl.clone(),
            }}),
            Expr::Fib { flags, result } => json!({"fib": {"result": result, "flags": flags}}),
            Expr::Numgen {
                mode,
                modulus,
                offset,
            } => json!({"numgen": {"mode": mode, "mod": modulus, "offset": offset}}),
            Expr::Hash {
                input,
                modulus,
                seed,
                offset,
            } => match input {
                Some(i) => json!({"jhash": obj!{
                    "mod" => J::from(*modulus),
                    "seed" => *seed,
                    "offset" => (*offset != 0).then_some(*offset),
                    "expr" => self.expr(i),
                }}),
                None => json!({"symhash": obj!{
                    "mod" => J::from(*modulus),
                    "offset" => (*offset != 0).then_some(*offset),
                }}),
            },
            Expr::Ipsec { dir, spnum, key } => {
                let (fam, k) = match key.split_once(' ') {
                    Some((f, k)) => (Some(f.to_owned()), k.to_owned()),
                    None => (None, key.clone()),
                };
                json!({"ipsec": obj!{
                    "key" => J::from(k),
                    "family" => fam,
                    "dir" => J::from(dir.clone()),
                    "spnum" => J::from(*spnum),
                }})
            }
            Expr::Concat(v) => {
                json!({"concat": v.iter().map(|x| self.expr_in(x, binop)).collect::<Vec<_>>()})
            }
            Expr::Binop(op, l, r) => {
                let mut m = Map::new();
                m.insert(
                    op.as_str().to_owned(),
                    J::Array(vec![self.expr_in(l, true), self.expr_in(r, true)]),
                );
                J::Object(m)
            }
            Expr::Value(v) => self.value(v, binop),
            Expr::Prefix(a, len) => json!({"prefix": {"addr": self.expr(a), "len": len}}),
            Expr::Range(a, b) => {
                // Range bounds are not translated to names.
                let o = Opts {
                    service: false,
                    reverse_dns: false,
                    ..*self.o
                };
                let out = Out {
                    o: &o,
                    family: self.family,
                };
                json!({"range": [out.expr(a), out.expr(b)]})
            }
            Expr::List(v) => J::Array(v.iter().map(|x| self.expr(x)).collect()),
            Expr::Set(elems) => {
                json!({"set": elems.iter().map(|e| self.elem(e)).collect::<Vec<_>>()})
            }
            Expr::SetRef(n) => J::from(format!("@{n}")),
            Expr::Map(k, m) => json!({"map": {"key": self.expr(k), "data": self.expr(m)}}),
            Expr::Verdict(v) => verdict_json(v),
            Expr::Wildcard => J::from("*"),
            Expr::Variable(v) => J::from(format!("${v}")),
        }
    }

    /// A set element (with its data for maps).
    fn elem(&self, e: &Elem) -> J {
        let key = match &e.key {
            Some(k) => self.expr(k),
            None => J::from("*"),
        };
        let mut attrs = Map::new();
        if let Some(t) = e.timeout {
            attrs.insert("timeout".into(), J::from(t / 1000));
        }
        if let (Some(x), false) = (e.expires, self.o.stateless) {
            attrs.insert("expires".into(), J::from(x / 1000));
        }
        if let Some(c) = &e.comment {
            attrs.insert("comment".into(), J::from(c.clone()));
        }
        for st in &e.stmts {
            if let J::Object(m) = self.stmt(st) {
                attrs.extend(m);
            }
        }
        let k = if attrs.is_empty() {
            key
        } else {
            let mut m = Map::new();
            m.insert("val".into(), key);
            m.extend(attrs);
            json!({"elem": J::Object(m)})
        };
        match &e.data {
            Some(d) => J::Array(vec![k, self.expr(d)]),
            None => k,
        }
    }

    fn limit(&self, l: &Limit) -> J {
        let packets = l.rate_unit.is_none();
        let burst = l.burst.unwrap_or(if packets { 5 } else { 0 });
        let mut m = obj! {
            "rate" => J::from(l.rate),
            "burst" => J::from(burst),
            "per" => J::from(l.per.clone()),
            "inv" => l.over.then_some(true),
        };
        if let (J::Object(m), Some(u)) = (&mut m, &l.rate_unit) {
            m.insert("rate_unit".into(), J::from(u.clone()));
            m.insert(
                "burst_unit".into(),
                J::from(l.burst_unit.clone().unwrap_or_else(|| "bytes".into())),
            );
        }
        m
    }

    fn quota(&self, q: &Quota) -> J {
        let (v, u) = bytes_unit(q.bytes);
        let mut m = obj! {
            "val" => J::from(v),
            "val_unit" => J::from(u),
            "inv" => q.over.then_some(true),
        };
        if q.used != 0 && !self.o.stateless {
            let (v, u) = bytes_unit(q.used);
            if let J::Object(m) = &mut m {
                m.insert("used".into(), J::from(v));
                m.insert("used_unit".into(), J::from(u));
            }
        }
        m
    }

    /// A reject code: its name, or with `-n` its number.
    fn reject_code(&self, with: &str, code: &str) -> J {
        match super::print::reject_code(with, code).filter(|_| self.o.numeric) {
            Some(v) => J::from(v),
            None => J::from(code),
        }
    }

    fn reject_default(&self) -> (&'static str, &'static str) {
        match self.family {
            Family::Ipv4 => ("icmp", "port-unreachable"),
            Family::Ipv6 => ("icmpv6", "port-unreachable"),
            _ => ("icmpx", "port-unreachable"),
        }
    }

    fn stmt(&self, st: &Stmt) -> J {
        match st {
            Stmt::Match { left, op, right } => {
                let op = match op {
                    RelOp::Implicit if is_flag_value(right) => "in",
                    RelOp::Implicit | RelOp::Eq | RelOp::Mask => "==",
                    o => o.as_str(),
                };
                let binop = matches!(left, Expr::Binop(..));
                json!({"match": {"op": op, "left": self.expr(left), "right": self.expr_in(right, binop)}})
            }
            Stmt::Verdict(v @ (Verdict::JumpBlock(_) | Verdict::GotoBlock(_))) => {
                // libnftables has no JSON for anonymous chains: their text.
                J::from(print::verdict(v, self.family, 2, self.o))
            }
            Stmt::Verdict(v) => verdict_json(v),
            Stmt::Vmap { key, map } => {
                json!({"vmap": {"key": self.expr(key), "data": self.expr(map)}})
            }
            Stmt::Counter { packets, bytes } => match (packets, bytes, self.o.stateless) {
                (Some(p), Some(b), false) => json!({"counter": {"packets": p, "bytes": b}}),
                _ => json!({"counter": null}),
            },
            Stmt::Limit(l) => json!({"limit": self.limit(l)}),
            Stmt::Quota(q) => json!({"quota": self.quota(q)}),
            Stmt::Log(l) => {
                let flags = l.flags.as_ref().map(|f| {
                    if f == "all" {
                        return J::from("all");
                    }
                    let mut items = Vec::new();
                    let words: Vec<&str> = f.split(' ').collect();
                    let mut i = 0;
                    while i < words.len() {
                        match words[i] {
                            "tcp" => {
                                for x in words.get(i + 1).unwrap_or(&"").split(',') {
                                    items.push(J::from(format!("tcp {x}")));
                                }
                                i += 2;
                            }
                            "ip" => {
                                items.push(J::from("ip options"));
                                i += 2;
                            }
                            w => {
                                items.push(J::from(w));
                                i += 1;
                            }
                        }
                    }
                    if items.len() == 1 {
                        items.pop().unwrap()
                    } else {
                        J::Array(items)
                    }
                });
                let m = obj! {
                    "prefix" => l.prefix.clone(),
                    "group" => l.group,
                    "snaplen" => l.snaplen,
                    "queue-threshold" => l.qthreshold,
                    "level" => l.level.clone(),
                    "flags" => flags,
                };
                if m.as_object().is_some_and(Map::is_empty) {
                    json!({"log": null})
                } else {
                    json!({"log": m})
                }
            }
            Stmt::Connlimit { count, over } => {
                json!({"ct count": obj!{"val" => J::from(*count), "inv" => over.then_some(true)}})
            }
            Stmt::Last { used } => match (used, self.o.stateless) {
                (Some(ms), false) => json!({"last": {"used": ms}}),
                _ => json!({"last": null}),
            },
            Stmt::Objref { kind, name } => {
                let v = match name {
                    Expr::Value(v) => match self.value(v, false) {
                        J::Number(n) => J::from(n.to_string()),
                        j => j,
                    },
                    e => self.expr(e),
                };
                let mut m = Map::new();
                m.insert(kind.clone(), v);
                J::Object(m)
            }
            Stmt::MetaSet { key, value } => {
                json!({"mangle": {"key": {"meta": {"key": key}}, "value": self.expr(value)}})
            }
            Stmt::CtSet { key, dir, value } => json!({"mangle": {
                "key": {"ct": obj!{"key" => J::from(key.clone()), "dir" => dir.clone()}},
                "value": self.expr(value),
            }}),
            Stmt::PayloadSet { target, value } => {
                json!({"mangle": {"key": self.expr(target), "value": self.expr(value)}})
            }
            Stmt::Nat {
                kind,
                family,
                addr,
                port,
                flags,
            } => {
                let name = match kind {
                    NatKind::Snat => "snat",
                    NatKind::Dnat => "dnat",
                    NatKind::Masquerade => "masquerade",
                    NatKind::Redirect => "redirect",
                };
                let flags = match flags.len() {
                    0 => None,
                    1 => Some(J::from(flags[0].clone())),
                    _ => Some(J::from(flags.clone())),
                };
                let m = obj! {
                    "family" => family.clone(),
                    "addr" => addr.as_ref().map(|a| self.expr(a)),
                    "port" => port.as_ref().map(|p| self.expr(p)),
                    "flags" => flags,
                };
                let mut o = Map::new();
                o.insert(
                    name.into(),
                    if m.as_object().is_some_and(Map::is_empty) {
                        J::Null
                    } else {
                        m
                    },
                );
                J::Object(o)
            }
            Stmt::Reject { with, code } => match (with.as_deref(), code) {
                (Some("tcp reset"), _) => json!({"reject": {"type": "tcp reset"}}),
                (Some(w), Some(c)) => {
                    json!({"reject": {"type": w, "expr": self.reject_code(w, c)}})
                }
                (Some(w), None) => json!({"reject": {"type": w}}),
                (None, _) => {
                    let (t, c) = self.reject_default();
                    json!({"reject": {"type": t, "expr": self.reject_code(t, c)}})
                }
            },
            Stmt::Queue { flags, num } => {
                let num = match num {
                    None => J::from(0),
                    Some(Expr::Value(Value::Raw(s))) => match s.split_once('-') {
                        Some((a, b)) => json!({"range": [text_value(a), text_value(b)]}),
                        None => text_value(s),
                    },
                    Some(e) => self.expr(e),
                };
                let flags = match flags.len() {
                    0 => None,
                    1 => Some(J::from(flags[0].clone())),
                    _ => Some(J::from(flags.clone())),
                };
                json!({"queue": obj!{"num" => num, "flags" => flags}})
            }
            Stmt::Dup { addr, dev } => match (addr, dev) {
                (Some(a), d) => {
                    json!({"dup": obj!{"addr" => self.expr(a), "dev" => d.as_ref().map(|d| self.expr(d))}})
                }
                (None, Some(d)) => json!({"dup": {"addr": self.expr(d)}}),
                (None, None) => json!({"dup": null}),
            },
            Stmt::Fwd { family, addr, dev } => json!({"fwd": obj!{
                "dev" => self.expr(dev),
                "family" => family.clone(),
                "addr" => addr.as_ref().map(|a| self.expr(a)),
            }}),
            Stmt::Notrack => json!({"notrack": null}),
            Stmt::Flow(ft) => json!({"flow": {"op": "add", "flowtable": format!("@{ft}")}}),
            Stmt::Tproxy { family, addr, port } => json!({"tproxy": obj!{
                "family" => family.clone(),
                "addr" => addr.as_ref().map(|a| self.expr(a)),
                "port" => port.as_ref().map(|p| self.expr(p)),
            }}),
            Stmt::Synproxy { mss, wscale, flags } => json!({"synproxy": obj!{
                "mss" => *mss,
                "wscale" => *wscale,
                "flags" => (!flags.is_empty()).then(|| J::from(flags.clone())),
            }}),
            Stmt::SetUpdate {
                op,
                set,
                key,
                data,
                timeout,
                stmts,
            } => {
                let k = self.expr(key);
                let elem = match timeout {
                    Some(t) => json!({"elem": {"val": k, "timeout": t / 1000}}),
                    None => k,
                };
                let stmts: Vec<J> = stmts.iter().map(|s| self.stmt(s)).collect();
                match data {
                    Some(d) => json!({"map": obj!{
                        "op" => J::from(op.clone()),
                        "elem" => elem,
                        "data" => self.expr(d),
                        "map" => J::from(format!("@{set}")),
                        "stmt" => (!stmts.is_empty()).then(|| J::Array(stmts.clone())),
                    }}),
                    None => json!({"set": obj!{
                        "op" => J::from(op.clone()),
                        "elem" => elem,
                        "set" => J::from(format!("@{set}")),
                        "stmt" => (!stmts.is_empty()).then(|| J::Array(stmts.clone())),
                    }}),
                }
            }
            Stmt::Meter {
                name,
                size,
                key,
                timeout,
                stmts,
            } => {
                let k = self.expr(key);
                let key = match timeout {
                    Some(t) => json!({"elem": {"val": k, "timeout": t / 1000}}),
                    None => k,
                };
                json!({"meter": obj!{
                    "name" => J::from(name.clone()),
                    "size" => *size,
                    "key" => key,
                    "stmt" => J::Array(stmts.iter().map(|s| self.stmt(s)).collect()),
                }})
            }
            Stmt::Opaque(s) => J::from(s.clone()),
        }
    }

    fn rule(&self, t: &Table, chain: &str, r: &Rule) -> J {
        json!({"rule": obj!{
            "family" => J::from(family_str(t.family)),
            "table" => J::from(t.name.clone()),
            "chain" => J::from(chain),
            "handle" => r.handle,
            "comment" => r.comment.clone(),
            "expr" => J::Array(r.stmts.iter().map(|s| self.stmt(s)).collect()),
        }})
    }

    fn typespec(&self, t: &TypeSpec) -> J {
        match t {
            TypeSpec::Type(v) if v.len() == 1 => J::from(v[0].clone()),
            TypeSpec::Type(v) => J::from(v.clone()),
            TypeSpec::Typeof(v) if v.len() == 1 => json!({"typeof": self.expr(&v[0])}),
            TypeSpec::Typeof(v) => {
                json!({"typeof": {"concat": v.iter().map(|e| self.expr(e)).collect::<Vec<_>>()}})
            }
        }
    }

    fn chain(&self, t: &Table, c: &Chain) -> J {
        let mut m = obj! {
            "family" => J::from(family_str(t.family)),
            "table" => J::from(t.name.clone()),
            "name" => J::from(c.name.clone()),
            "handle" => c.handle,
            "comment" => c.comment.clone(),
        };
        if let (J::Object(m), Some(b)) = (&mut m, &c.base) {
            match b.devices.len() {
                0 => {}
                1 => {
                    m.insert("dev".into(), J::from(b.devices[0].clone()));
                }
                _ => {
                    m.insert("dev".into(), J::from(b.devices.clone()));
                }
            }
            m.insert("type".into(), J::from(b.ty.clone()));
            m.insert("hook".into(), J::from(b.hook.clone()));
            let prio = super::compile::priority_value(t.family, &b.hook, &b.priority).unwrap_or(0);
            m.insert("prio".into(), J::from(prio));
            if let Some(p) = &b.policy {
                m.insert("policy".into(), J::from(p.clone()));
            }
        }
        json!({"chain": m})
    }

    fn set(&self, t: &Table, s: &Set) -> J {
        let mut m = obj! {
            "family" => J::from(family_str(t.family)),
            "name" => J::from(s.name.clone()),
            "table" => J::from(t.name.clone()),
            "type" => s.key.as_ref().map(|k| self.typespec(k)),
            "handle" => s.handle,
            "comment" => s.comment.clone(),
            // Map data are given by type name, also for typeof maps.
            "map" => s.data.as_ref().map(|d| match d {
                TypeSpec::Typeof(v) => {
                    let names: Vec<J> = v
                        .iter()
                        .map(|e| J::from(super::print::expr_type_name(e).unwrap_or("integer")))
                        .collect();
                    if names.len() == 1 {
                        names.into_iter().next().unwrap()
                    } else {
                        J::Array(names)
                    }
                }
                d => self.typespec(d),
            }),
            "policy" => s.policy.clone(),
            "size" => s.size,
            "flags" => (!s.flags.is_empty()).then(|| {
                // JSON lists the flags in another order than the text.
                let order = ["constant", "interval", "timeout", "dynamic"];
                let mut f = s.flags.clone();
                // (Stable: other flags keep their order.)
                f.sort_by_key(|x| order.iter().position(|o| o == x).unwrap_or(9));
                J::from(f)
            }),
            "timeout" => s.timeout.map(|t| t / 1000),
            "gc-interval" => s.gc_interval.map(|t| t / 1000),
            "auto-merge" => s.auto_merge.then_some(true),
        };
        if let J::Object(m) = &mut m {
            if let (Some(elems), false) = (&s.elements, self.o.terse) {
                if !elems.is_empty() {
                    m.insert(
                        "elem".into(),
                        J::Array(elems.iter().map(|e| self.elem(e)).collect()),
                    );
                }
            }
            if !s.stmts.is_empty() {
                m.insert(
                    "stmt".into(),
                    J::Array(s.stmts.iter().map(|x| self.stmt(x)).collect()),
                );
            }
        }
        let kw = if s.is_map { "map" } else { "set" };
        let mut o = Map::new();
        o.insert(kw.into(), m);
        J::Object(o)
    }

    fn obj(&self, t: &Table, o: &Obj) -> J {
        let mut m = obj! {
            "family" => J::from(family_str(t.family)),
            "name" => J::from(o.name.clone()),
            "table" => J::from(t.name.clone()),
            "handle" => o.handle,
            "comment" => o.comment.clone(),
        };
        let J::Object(mm) = &mut m else {
            unreachable!()
        };
        let mut put = |k: &str, v: J| {
            mm.insert(k.into(), v);
        };
        match &o.body {
            // (nft keeps counter object values even when stateless.)
            ObjBody::Counter { packets, bytes } => {
                put("packets", J::from(*packets));
                put("bytes", J::from(*bytes));
            }
            ObjBody::Quota(q) => {
                put("bytes", J::from(q.bytes));
                put("used", J::from(if self.o.stateless { 0 } else { q.used }));
                put("inv", J::from(q.over));
            }
            ObjBody::Limit(l) => {
                put("rate", J::from(l.rate));
                put("per", J::from(l.per.clone()));
                if l.over {
                    put("inv", J::from(true));
                }
                match &l.rate_unit {
                    Some(u) => {
                        put("rate_unit", J::from(u.clone()));
                        put("burst", J::from(l.burst.unwrap_or(0)));
                        put(
                            "burst_unit",
                            J::from(l.burst_unit.clone().unwrap_or_else(|| "bytes".into())),
                        );
                    }
                    None => put("burst", J::from(l.burst.unwrap_or(5))),
                }
            }
            ObjBody::CtHelper {
                helper,
                protocol,
                l3proto,
            } => {
                put("type", J::from(helper.clone()));
                put("protocol", J::from(protocol.clone()));
                put(
                    "l3proto",
                    J::from(l3proto.clone().unwrap_or_else(|| "inet".into())),
                );
            }
            ObjBody::CtTimeout {
                protocol,
                l3proto,
                policy,
            } => {
                put("protocol", J::from(protocol.clone()));
                put(
                    "l3proto",
                    J::from(l3proto.clone().unwrap_or_else(|| "inet".into())),
                );
                let mut p = Map::new();
                for (k, v) in policy {
                    p.insert(k.clone(), J::from(*v));
                }
                put("policy", J::Object(p));
            }
            ObjBody::CtExpect {
                protocol,
                dport,
                timeout,
                size,
                l3proto,
            } => {
                put("protocol", J::from(protocol.clone()));
                put("dport", J::from(*dport));
                put("timeout", J::from(*timeout));
                put("size", J::from(*size));
                put(
                    "l3proto",
                    J::from(l3proto.clone().unwrap_or_else(|| "inet".into())),
                );
            }
            ObjBody::Synproxy { mss, wscale, flags } => {
                put("mss", J::from(*mss));
                put("wscale", J::from(*wscale));
                if !flags.is_empty() {
                    put("flags", J::from(flags.clone()));
                }
            }
            ObjBody::Secmark(ctx) => put("context", J::from(ctx.clone())),
        }
        let mut out = Map::new();
        out.insert(o.body.kind().to_owned(), m);
        J::Object(out)
    }

    fn flowtable(&self, t: &Table, f: &Flowtable) -> J {
        let prio = super::compile::priority_value(t.family, &f.hook, &f.priority).unwrap_or(0);
        let dev = match f.devices.len() {
            0 => None,
            1 => Some(J::from(f.devices[0].clone())),
            _ => Some(J::from(f.devices.clone())),
        };
        json!({"flowtable": obj!{
            "family" => J::from(family_str(t.family)),
            "name" => J::from(f.name.clone()),
            "table" => J::from(t.name.clone()),
            "handle" => f.handle,
            "hook" => J::from(f.hook.clone()),
            "prio" => J::from(prio),
            "dev" => dev,
        }})
    }

    fn table_header(&self, t: &Table) -> J {
        let flags = match t.flags.len() {
            0 => None,
            1 => Some(J::from(t.flags[0].clone())),
            _ => Some(J::from(t.flags.clone())),
        };
        json!({"table": obj!{
            "family" => J::from(family_str(t.family)),
            "name" => J::from(t.name.clone()),
            "handle" => t.handle,
            "flags" => flags,
            "comment" => t.comment.clone(),
        }})
    }

    /// All items of a table, in libnftables' order: the table, chains,
    /// objects, sets, flowtables, then rules.
    fn table(&self, t: &Table, header: bool, out: &mut Vec<J>) {
        if header {
            out.push(self.table_header(t));
        }
        for it in &t.items {
            if let TableItem::Chain(c) = it {
                out.push(self.chain(t, c));
            }
        }
        for it in &t.items {
            if let TableItem::Obj(o) = it {
                out.push(self.obj(t, o));
            }
        }
        for it in &t.items {
            if let TableItem::Set(s) = it {
                out.push(self.set(t, s));
            }
        }
        for it in &t.items {
            if let TableItem::Flowtable(f) = it {
                out.push(self.flowtable(t, f));
            }
        }
        for it in &t.items {
            if let TableItem::Chain(c) = it {
                for r in &c.rules {
                    out.push(self.rule(t, &c.name, r));
                }
            }
        }
    }
}

/// What an event is about.
pub(crate) enum EventItem<'a> {
    /// The table itself.
    Table,
    /// A table item (the first of the table).
    Item,
    /// A rule of a chain.
    Rule(&'a str, &'a Rule),
    /// Element `i` of the table's first item (a set).
    Element(usize),
}

/// One event (`{"add": {...}}`), as `nft -j monitor` / `--echo` print it.
pub(crate) fn event(verb: &str, t: &Table, what: EventItem<'_>, opts: &Opts) -> String {
    let o = Out {
        o: opts,
        family: t.family,
    };
    let obj = match what {
        EventItem::Table => o.table_header(t),
        EventItem::Rule(chain, r) => o.rule(t, chain, r),
        EventItem::Item => match t.items.first() {
            Some(TableItem::Chain(c)) => o.chain(t, c),
            Some(TableItem::Set(s)) => {
                // Events do not show auto-merge.
                let mut j = o.set(t, s);
                if let Some(J::Object(m)) = j.as_object_mut().and_then(|m| m.values_mut().next()) {
                    m.shift_remove("auto-merge");
                }
                j
            }
            Some(TableItem::Obj(x)) => o.obj(t, x),
            Some(TableItem::Flowtable(f)) => o.flowtable(t, f),
            None => J::Null,
        },
        EventItem::Element(i) => match t.items.first() {
            Some(TableItem::Set(s)) => {
                let elems: Vec<J> = s
                    .elements
                    .iter()
                    .flatten()
                    .skip(i)
                    .take(1)
                    .map(|e| o.elem(e))
                    .collect();
                json!({"element": {
                    "family": family_str(t.family),
                    "table": t.name,
                    "name": s.name,
                    "elem": {"set": elems},
                }})
            }
            _ => J::Null,
        },
    };
    let mut m = Map::new();
    m.insert(verb.to_owned(), obj);
    to_string(&J::Object(m))
}

/// JSON of decompiled tables (`nft -j list ...`).
pub fn tables(tables: &[Table], opts: &Opts) -> String {
    let mut items = vec![metainfo()];
    for t in tables {
        let o = Out {
            o: opts,
            family: t.family,
        };
        o.table(t, true, &mut items);
    }
    to_string(&json!({"nftables": items})) + "\n"
}

/// Run a `list` command, producing JSON output.
pub fn list(
    rs: &Ruleset,
    kind: Option<ObjKind>,
    all: bool,
    target: &Target,
    opts: &Opts,
) -> Result<String> {
    if kind == Some(ObjKind::Table) && all {
        let mut items = vec![metainfo()];
        for t in super::decompile::ruleset(rs) {
            if target.family.is_none_or(|f| f == t.family) {
                let o = Out {
                    o: opts,
                    family: t.family,
                };
                items.push(o.table_header(&t));
            }
        }
        return Ok(to_string(&json!({"nftables": items})) + "\n");
    }
    let sel = super::list::select(super::decompile::ruleset(rs), kind, all, target)?;
    // Listing one kind of object omits the tables.
    let headers = matches!(kind, None | Some(ObjKind::Table));
    let mut items = vec![metainfo()];
    for t in &sel {
        let o = Out {
            o: opts,
            family: t.family,
        };
        o.table(t, headers, &mut items);
    }
    Ok(to_string(&json!({"nftables": items})) + "\n")
}

// ------------------------------------------------------------------ input

fn bad<T>(what: &str, v: &J) -> Result<T> {
    Err(Error::msg(format!("Invalid JSON {what}: {}", to_string(v))))
}

fn get<'a>(o: &'a J, k: &str) -> Option<&'a J> {
    o.get(k).filter(|v| !v.is_null())
}

fn s_of(o: &J, k: &str) -> Result<String> {
    match get(o, k) {
        Some(J::String(s)) => Ok(s.clone()),
        Some(J::Number(n)) => Ok(n.to_string()),
        _ => bad(&format!("object: missing \"{k}\""), o),
    }
}

fn opt_s(o: &J, k: &str) -> Option<String> {
    match get(o, k) {
        Some(J::String(s)) => Some(s.clone()),
        Some(J::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn u_of(o: &J, k: &str) -> Option<u64> {
    match get(o, k) {
        Some(J::Number(n)) => n.as_u64(),
        Some(J::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn family_of(o: &J) -> Result<Family> {
    Ok(match opt_s(o, "family").as_deref().unwrap_or("ip") {
        "ip" => Family::Ipv4,
        "ip6" => Family::Ipv6,
        "inet" => Family::Inet,
        "arp" => Family::Arp,
        "bridge" => Family::Bridge,
        "netdev" => Family::Netdev,
        f => return Err(Error::msg(format!("Invalid family '{f}'"))),
    })
}

/// Strings or a list of strings.
fn strings(v: Option<&J>) -> Vec<String> {
    match v {
        Some(J::String(s)) => vec![s.clone()],
        Some(J::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn raw(s: impl Into<String>) -> Expr {
    Expr::raw(s)
}

/// A JSON value / expression as an AST expression.
fn expr_in(v: &J) -> Result<Expr> {
    Ok(match v {
        J::String(s) if s.starts_with('@') => Expr::SetRef(s[1..].to_owned()),
        J::String(s) if s == "*" => Expr::Wildcard,
        J::String(s) => raw(s.clone()),
        J::Number(n) => raw(n.to_string()),
        J::Bool(b) => raw(if *b { "exists" } else { "missing" }),
        J::Array(a) => Expr::List(a.iter().map(expr_in).collect::<Result<_>>()?),
        J::Null => return bad("expression", v),
        J::Object(m) => {
            let Some((k, x)) = m.iter().next() else {
                return bad("expression", v);
            };
            match k.as_str() {
                "payload" => match (opt_s(x, "protocol"), opt_s(x, "base")) {
                    (Some(p), _) => Expr::Payload {
                        proto: p,
                        field: s_of(x, "field")?,
                    },
                    (None, Some(b)) => Expr::Raw {
                        base: b,
                        offset: u_of(x, "offset").unwrap_or(0) as u32,
                        len: u_of(x, "len").unwrap_or(0) as u32,
                    },
                    _ => return bad("payload", v),
                },
                "exthdr" | "tcp option" | "ip option" | "sctp chunk" => {
                    let name = s_of(x, "name")?;
                    match opt_s(x, "field") {
                        Some(f) => Expr::Exthdr {
                            desc: if k == "exthdr" {
                                name
                            } else {
                                format!("{k} {name}")
                            },
                            field: Some(f),
                            exists: false,
                        },
                        None => Expr::Exthdr {
                            desc: format!("{k} {name}"),
                            field: None,
                            exists: true,
                        },
                    }
                }
                "meta" => Expr::Meta(s_of(x, "key")?),
                "ct" => {
                    let key = s_of(x, "key")?;
                    let key = match opt_s(x, "family") {
                        Some(f) => format!("{f} {key}"),
                        None => key,
                    };
                    Expr::Ct {
                        dir: opt_s(x, "dir"),
                        key,
                    }
                }
                "rt" => {
                    let key = s_of(x, "key")?;
                    Expr::Rt(match opt_s(x, "family") {
                        Some(f) => format!("{f} {key}"),
                        None => key,
                    })
                }
                "socket" => Expr::Socket {
                    key: s_of(x, "key")?,
                    level: u_of(x, "level").map(|l| l as u32),
                },
                "osf" => Expr::Osf {
                    ttl: opt_s(x, "ttl"),
                    version: opt_s(x, "key").as_deref() == Some("version"),
                },
                "fib" => Expr::Fib {
                    flags: strings(get(x, "flags")),
                    result: s_of(x, "result")?,
                },
                "numgen" => Expr::Numgen {
                    mode: s_of(x, "mode")?,
                    modulus: u_of(x, "mod").unwrap_or(0) as u32,
                    offset: u_of(x, "offset").unwrap_or(0) as u32,
                },
                "jhash" | "symhash" => Expr::Hash {
                    input: match get(x, "expr") {
                        Some(e) => Some(Box::new(expr_in(e)?)),
                        None => None,
                    },
                    modulus: u_of(x, "mod").unwrap_or(0) as u32,
                    seed: u_of(x, "seed").map(|s| s as u32),
                    offset: u_of(x, "offset").unwrap_or(0) as u32,
                },
                "ipsec" => {
                    let key = s_of(x, "key")?;
                    Expr::Ipsec {
                        dir: opt_s(x, "dir").unwrap_or_else(|| "in".into()),
                        spnum: u_of(x, "spnum").unwrap_or(0) as u32,
                        key: match opt_s(x, "family") {
                            Some(f) => format!("{f} {key}"),
                            None => key,
                        },
                    }
                }
                "concat" => Expr::Concat(
                    x.as_array()
                        .ok_or_else(|| Error::msg("Invalid concat"))?
                        .iter()
                        .map(expr_in)
                        .collect::<Result<_>>()?,
                ),
                "&" | "|" | "^" | "<<" | ">>" => {
                    let a = x
                        .as_array()
                        .filter(|a| a.len() == 2)
                        .ok_or_else(|| Error::msg("Invalid binop"))?;
                    let op = match k.as_str() {
                        "&" => BinOp::And,
                        "|" => BinOp::Or,
                        "^" => BinOp::Xor,
                        "<<" => BinOp::Lshift,
                        _ => BinOp::Rshift,
                    };
                    Expr::Binop(op, Box::new(expr_in(&a[0])?), Box::new(expr_in(&a[1])?))
                }
                "prefix" => Expr::Prefix(
                    Box::new(expr_in(get(x, "addr").unwrap_or(&J::Null))?),
                    u_of(x, "len").unwrap_or(0) as u32,
                ),
                "range" => {
                    let a = x
                        .as_array()
                        .filter(|a| a.len() == 2)
                        .ok_or_else(|| Error::msg("Invalid range"))?;
                    Expr::Range(Box::new(expr_in(&a[0])?), Box::new(expr_in(&a[1])?))
                }
                "set" => Expr::Set(elems_in(x)?),
                "map" => Expr::Map(
                    Box::new(expr_in(get(x, "key").unwrap_or(&J::Null))?),
                    Box::new(expr_in(get(x, "data").unwrap_or(&J::Null))?),
                ),
                "accept" | "drop" | "continue" | "return" | "jump" | "goto" | "queue" => {
                    Expr::Verdict(verdict_in(k, x)?)
                }
                _ => return bad("expression", v),
            }
        }
    })
}

fn verdict_in(k: &str, x: &J) -> Result<Verdict> {
    Ok(match k {
        "accept" => Verdict::Accept,
        "drop" => Verdict::Drop,
        "continue" => Verdict::Continue,
        "return" => Verdict::Return,
        "queue" => Verdict::Queue,
        "jump" => Verdict::Jump(s_of(x, "target")?),
        _ => Verdict::Goto(s_of(x, "target")?),
    })
}

/// Elements of a set (`[ elem, ... ]` or a single element).
fn elems_in(v: &J) -> Result<Vec<Elem>> {
    match v {
        J::Array(a) => a.iter().map(elem_in).collect(),
        v => Ok(vec![elem_in(v)?]),
    }
}

fn elem_in(v: &J) -> Result<Elem> {
    // Map elements are `[key, data]`.
    if let J::Array(a) = v {
        if a.len() == 2 {
            let mut e = elem_in(&a[0])?;
            e.data = Some(expr_in(&a[1])?);
            return Ok(e);
        }
    }
    if let Some(x) = v.get("elem") {
        let mut e = Elem::key(expr_in(get(x, "val").unwrap_or(&J::Null))?);
        e.timeout = u_of(x, "timeout").map(|t| t * 1000);
        e.expires = u_of(x, "expires").map(|t| t * 1000);
        e.comment = opt_s(x, "comment");
        if let J::Object(m) = x {
            for (k, sv) in m {
                if matches!(k.as_str(), "counter" | "quota" | "limit" | "last") {
                    let mut o = Map::new();
                    o.insert(k.clone(), sv.clone());
                    e.stmts.push(stmt_in(&J::Object(o))?);
                }
            }
        }
        return Ok(e);
    }
    Ok(Elem::key(expr_in(v)?))
}

fn limit_in(x: &J) -> Limit {
    let unit = opt_s(x, "rate_unit").filter(|u| u != "packets");
    Limit {
        over: get(x, "inv").and_then(J::as_bool).unwrap_or(false),
        rate: u_of(x, "rate").unwrap_or(0),
        burst: u_of(x, "burst").filter(|b| unit.is_some() || *b != 0),
        burst_unit: unit
            .as_ref()
            .map(|_| opt_s(x, "burst_unit").unwrap_or_else(|| "bytes".into())),
        rate_unit: unit,
        per: opt_s(x, "per").unwrap_or_else(|| "second".into()),
    }
}

fn unit_mul(u: Option<String>) -> u64 {
    match u.as_deref() {
        Some("kbytes") => 1024,
        Some("mbytes") => 1024 * 1024,
        Some("gbytes") => 1024 * 1024 * 1024,
        _ => 1,
    }
}

fn quota_in(x: &J) -> Quota {
    Quota {
        over: get(x, "inv").and_then(J::as_bool).unwrap_or(false),
        bytes: u_of(x, "val").unwrap_or(0) * unit_mul(opt_s(x, "val_unit")),
        used: u_of(x, "used").unwrap_or(0) * unit_mul(opt_s(x, "used_unit")),
    }
}

/// A rule statement.
fn stmt_in(v: &J) -> Result<Stmt> {
    // Anonymous chains have no JSON form; nft prints them as text.
    if let J::String(s) = v {
        let r = super::parse::parse_rule(s)?;
        return r
            .stmts
            .into_iter()
            .next()
            .ok_or_else(|| Error::msg("Invalid statement"));
    }
    let Some((k, x)) = v.as_object().and_then(|m| m.iter().next()) else {
        return bad("statement", v);
    };
    Ok(match k.as_str() {
        "match" => {
            let op = match opt_s(x, "op").as_deref().unwrap_or("==") {
                "in" => RelOp::Implicit,
                "==" => RelOp::Eq,
                "!=" => RelOp::Neq,
                "<" => RelOp::Lt,
                ">" => RelOp::Gt,
                "<=" => RelOp::Lte,
                ">=" => RelOp::Gte,
                o => return Err(Error::msg(format!("Unknown relational op '{o}'"))),
            };
            Stmt::Match {
                left: expr_in(get(x, "left").unwrap_or(&J::Null))?,
                op,
                right: expr_in(get(x, "right").unwrap_or(&J::Null))?,
            }
        }
        "accept" | "drop" | "continue" | "return" | "jump" | "goto" => {
            Stmt::Verdict(verdict_in(k, x)?)
        }
        "vmap" => Stmt::Vmap {
            key: expr_in(get(x, "key").unwrap_or(&J::Null))?,
            map: expr_in(get(x, "data").unwrap_or(&J::Null))?,
        },
        "counter" | "quota" | "limit" | "synproxy" | "ct helper" | "ct timeout"
        | "ct expectation" | "secmark"
            if matches!(x, J::String(_)) || x.get("map").is_some() =>
        {
            let name = match x {
                J::String(s) => raw(format!("\"{s}\"")),
                m => expr_in(&{
                    let mut o = Map::new();
                    o.insert("map".into(), m["map"].clone());
                    J::Object(o)
                })?,
            };
            Stmt::Objref {
                kind: k.clone(),
                name,
            }
        }
        "counter" => Stmt::Counter {
            packets: u_of(x, "packets"),
            bytes: u_of(x, "bytes"),
        },
        "limit" => Stmt::Limit(limit_in(x)),
        "quota" => Stmt::Quota(quota_in(x)),
        "log" => {
            let flags = strings(get(x, "flags"));
            Stmt::Log(Log {
                prefix: opt_s(x, "prefix"),
                group: u_of(x, "group").map(|g| g as u16),
                snaplen: u_of(x, "snaplen").map(|g| g as u32),
                qthreshold: u_of(x, "queue-threshold").map(|g| g as u16),
                level: opt_s(x, "level"),
                flags: (!flags.is_empty()).then(|| flags.join(" ")),
            })
        }
        "ct count" => Stmt::Connlimit {
            count: u_of(x, "val").unwrap_or(0) as u32,
            over: get(x, "inv").and_then(J::as_bool).unwrap_or(false),
        },
        "last" => Stmt::Last {
            used: u_of(x, "used"),
        },
        "mangle" => {
            let key = expr_in(get(x, "key").unwrap_or(&J::Null))?;
            let value = expr_in(get(x, "value").unwrap_or(&J::Null))?;
            match key {
                Expr::Meta(key) => Stmt::MetaSet { key, value },
                Expr::Ct { dir, key } => Stmt::CtSet { key, dir, value },
                target => Stmt::PayloadSet { target, value },
            }
        }
        "snat" | "dnat" | "masquerade" | "redirect" => Stmt::Nat {
            kind: match k.as_str() {
                "snat" => NatKind::Snat,
                "dnat" => NatKind::Dnat,
                "masquerade" => NatKind::Masquerade,
                _ => NatKind::Redirect,
            },
            family: opt_s(x, "family"),
            addr: get(x, "addr").map(expr_in).transpose()?,
            port: get(x, "port").map(expr_in).transpose()?,
            flags: strings(get(x, "flags")),
        },
        "reject" => match opt_s(x, "type").as_deref() {
            None => Stmt::Reject {
                with: None,
                code: None,
            },
            Some("tcp reset") => Stmt::Reject {
                with: Some("tcp reset".into()),
                code: None,
            },
            Some(t) => Stmt::Reject {
                with: Some(t.to_owned()),
                code: Some(opt_s(x, "expr").unwrap_or_else(|| "port-unreachable".into())),
            },
        },
        "queue" => Stmt::Queue {
            flags: strings(get(x, "flags")),
            num: match get(x, "num") {
                Some(J::Object(m)) if m.contains_key("range") => {
                    let a = &m["range"];
                    Some(raw(format!("{}-{}", a[0], a[1])))
                }
                Some(n) => Some(expr_in(n)?),
                None => None,
            },
        },
        "dup" => Stmt::Dup {
            addr: get(x, "addr").map(expr_in).transpose()?,
            dev: get(x, "dev").map(expr_in).transpose()?,
        },
        "fwd" => Stmt::Fwd {
            family: opt_s(x, "family"),
            addr: get(x, "addr").map(expr_in).transpose()?,
            dev: expr_in(get(x, "dev").unwrap_or(&J::Null))?,
        },
        "notrack" => Stmt::Notrack,
        "flow" => Stmt::Flow(s_of(x, "flowtable")?.trim_start_matches('@').to_owned()),
        "tproxy" => Stmt::Tproxy {
            family: opt_s(x, "family"),
            addr: get(x, "addr").map(expr_in).transpose()?,
            port: get(x, "port").map(expr_in).transpose()?,
        },
        "synproxy" => Stmt::Synproxy {
            mss: u_of(x, "mss").map(|v| v as u16),
            wscale: u_of(x, "wscale").map(|v| v as u8),
            flags: strings(get(x, "flags")),
        },
        "meter" => {
            let (key, timeout) = match get(x, "key") {
                Some(e) if e.get("elem").is_some() => {
                    let el = &e["elem"];
                    (
                        expr_in(get(el, "val").unwrap_or(&J::Null))?,
                        u_of(el, "timeout").map(|t| t * 1000),
                    )
                }
                Some(e) => (expr_in(e)?, None),
                None => return bad("meter", v),
            };
            Stmt::Meter {
                name: s_of(x, "name")?,
                size: u_of(x, "size").map(|n| n as u32),
                key,
                timeout,
                stmts: match get(x, "stmt") {
                    Some(J::Array(a)) => a.iter().map(stmt_in).collect::<Result<_>>()?,
                    Some(o) => vec![stmt_in(o)?],
                    None => Vec::new(),
                },
            }
        }
        "set" | "map" => {
            let (key, timeout) = match get(x, "elem") {
                Some(e) if e.get("elem").is_some() => {
                    let el = &e["elem"];
                    (
                        expr_in(get(el, "val").unwrap_or(&J::Null))?,
                        u_of(el, "timeout").map(|t| t * 1000),
                    )
                }
                Some(e) => (expr_in(e)?, None),
                None => return bad("set statement", v),
            };
            let stmts = match get(x, "stmt") {
                Some(J::Array(a)) => a.iter().map(stmt_in).collect::<Result<_>>()?,
                _ => Vec::new(),
            };
            Stmt::SetUpdate {
                op: opt_s(x, "op").unwrap_or_else(|| "add".into()),
                set: s_of(x, k)?.trim_start_matches('@').to_owned(),
                key,
                data: get(x, "data").map(expr_in).transpose()?,
                timeout,
                stmts,
            }
        }
        _ => return bad("statement", v),
    })
}

fn obj_body(kind: &str, x: &J) -> Result<ObjBody> {
    Ok(match kind {
        "counter" => ObjBody::Counter {
            packets: u_of(x, "packets").unwrap_or(0),
            bytes: u_of(x, "bytes").unwrap_or(0),
        },
        "quota" => ObjBody::Quota(Quota {
            over: get(x, "inv").and_then(J::as_bool).unwrap_or(false),
            bytes: u_of(x, "bytes").unwrap_or(0),
            used: u_of(x, "used").unwrap_or(0),
        }),
        "limit" => {
            let mut l = limit_in(x);
            if let Some(u) = opt_s(x, "unit").filter(|u| u != "packets") {
                l.rate_unit = Some(u);
                l.burst_unit = Some("bytes".into());
            }
            ObjBody::Limit(l)
        }
        "ct helper" => ObjBody::CtHelper {
            helper: s_of(x, "type")?,
            protocol: s_of(x, "protocol")?,
            l3proto: opt_s(x, "l3proto"),
        },
        "ct timeout" => ObjBody::CtTimeout {
            protocol: s_of(x, "protocol")?,
            l3proto: opt_s(x, "l3proto"),
            policy: match get(x, "policy") {
                Some(J::Object(m)) => m
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0) as u32))
                    .collect(),
                _ => Vec::new(),
            },
        },
        "ct expectation" => ObjBody::CtExpect {
            protocol: s_of(x, "protocol")?,
            dport: u_of(x, "dport").unwrap_or(0) as u16,
            timeout: u_of(x, "timeout").unwrap_or(0),
            size: u_of(x, "size").unwrap_or(0) as u8,
            l3proto: opt_s(x, "l3proto"),
        },
        "synproxy" => ObjBody::Synproxy {
            mss: u_of(x, "mss").unwrap_or(0) as u16,
            wscale: u_of(x, "wscale").unwrap_or(0) as u8,
            flags: strings(get(x, "flags")),
        },
        "secmark" => ObjBody::Secmark(s_of(x, "context")?),
        _ => return Err(Error::msg(format!("Unknown object type '{kind}'"))),
    })
}

fn typespec_in(v: &J) -> Result<TypeSpec> {
    Ok(match v {
        J::String(s) => TypeSpec::Type(vec![s.clone()]),
        J::Array(a) => TypeSpec::Type(
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect(),
        ),
        J::Object(m) if m.contains_key("typeof") => match expr_in(&m["typeof"])? {
            Expr::Concat(v) => TypeSpec::Typeof(v),
            e => TypeSpec::Typeof(vec![e]),
        },
        _ => return bad("set type", v),
    })
}

fn set_in(kind: &str, x: &J) -> Result<Set> {
    let data = get(x, "map").map(typespec_in).transpose()?;
    Ok(Set {
        name: s_of(x, "name")?,
        handle: u_of(x, "handle"),
        is_map: kind == "map" || data.is_some(),
        key: Some(typespec_in(get(x, "type").unwrap_or(&J::Null))?),
        data,
        flags: strings(get(x, "flags")),
        timeout: u_of(x, "timeout").map(|t| t * 1000),
        gc_interval: u_of(x, "gc-interval").map(|t| t * 1000),
        size: u_of(x, "size").map(|s| s as u32),
        policy: opt_s(x, "policy"),
        auto_merge: get(x, "auto-merge").and_then(J::as_bool).unwrap_or(false),
        comment: opt_s(x, "comment"),
        stmts: match get(x, "stmt") {
            Some(J::Array(a)) => a.iter().map(stmt_in).collect::<Result<_>>()?,
            _ => Vec::new(),
        },
        elements: get(x, "elem").map(elems_in).transpose()?,
        ..Default::default()
    })
}

fn obj_kind_of(k: &str) -> Option<ObjKind> {
    Some(match k {
        "table" => ObjKind::Table,
        "chain" => ObjKind::Chain,
        "rule" => ObjKind::Rule,
        "set" => ObjKind::Set,
        "map" => ObjKind::Map,
        "element" => ObjKind::Element,
        "flowtable" => ObjKind::Flowtable,
        "meter" => ObjKind::Meter,
        "counter" => ObjKind::Counter,
        "quota" => ObjKind::Quota,
        "limit" => ObjKind::Limit,
        "ct helper" => ObjKind::CtHelper,
        "ct timeout" => ObjKind::CtTimeout,
        "ct expectation" => ObjKind::CtExpect,
        "synproxy" => ObjKind::Synproxy,
        "secmark" => ObjKind::Secmark,
        _ => return None,
    })
}

/// Plural kinds of `list` commands.
fn plural_of(k: &str) -> Option<ObjKind> {
    Some(match k {
        "tables" => ObjKind::Table,
        "chains" => ObjKind::Chain,
        "sets" => ObjKind::Set,
        "maps" => ObjKind::Map,
        "flowtables" => ObjKind::Flowtable,
        "meters" => ObjKind::Meter,
        "counters" => ObjKind::Counter,
        "quotas" => ObjKind::Quota,
        "limits" => ObjKind::Limit,
        "ct helpers" => ObjKind::CtHelper,
        "ct timeouts" => ObjKind::CtTimeout,
        "ct expectations" => ObjKind::CtExpect,
        "synproxys" => ObjKind::Synproxy,
        "secmarks" => ObjKind::Secmark,
        "rules" => ObjKind::Rule,
        _ => return None,
    })
}

fn target_in(kind: ObjKind, x: &J) -> Result<Target> {
    Ok(Target {
        family: Some(family_of(x)?),
        table: if kind == ObjKind::Table {
            opt_s(x, "name")
        } else {
            opt_s(x, "table")
        },
        name: if kind == ObjKind::Table {
            None
        } else if kind == ObjKind::Rule {
            opt_s(x, "chain")
        } else {
            opt_s(x, "name")
        },
        handle: u_of(x, "handle"),
        ..Default::default()
    })
}

/// One `{"<kind>": {...}}` object under a command.
fn command_in(verb: &str, item: &J, explicit: bool) -> Result<Vec<Cmd>> {
    let Some((k, x)) = item.as_object().and_then(|m| m.iter().next()) else {
        return bad("command", item);
    };
    let create = verb == "create";
    if matches!(verb, "list" | "reset" | "flush") && (k == "ruleset" || plural_of(k).is_some()) {
        let family = get(x, "family").map(|_| family_of(x)).transpose()?;
        let target = Target {
            family,
            table: opt_s(x, "table"),
            ..Default::default()
        };
        return Ok(vec![match (verb, k.as_str()) {
            ("list", "ruleset") => Cmd::List {
                kind: None,
                all: true,
                target,
            },
            ("flush", "ruleset") => Cmd::Flush { kind: None, target },
            ("list", k) => Cmd::List {
                kind: plural_of(k),
                all: true,
                target,
            },
            (_, k) => Cmd::Reset {
                kind: plural_of(k).unwrap(),
                all: true,
                target,
            },
        }]);
    }
    let kind = obj_kind_of(k).ok_or_else(|| Error::msg(format!("Unknown object '{k}'")))?;
    match verb {
        "add" | "create" | "insert" | "replace" => {}
        "delete" | "destroy" => {
            if kind == ObjKind::Element {
                return element_in(verb, x);
            }
            return Ok(vec![Cmd::Delete {
                destroy: verb == "destroy",
                kind,
                target: target_in(kind, x)?,
            }]);
        }
        "flush" => {
            return Ok(vec![Cmd::Flush {
                kind: Some(kind),
                target: target_in(kind, x)?,
            }]);
        }
        "list" => {
            return Ok(vec![Cmd::List {
                kind: Some(kind),
                all: false,
                target: target_in(kind, x)?,
            }]);
        }
        "reset" => {
            if kind == ObjKind::Element {
                return element_in(verb, x);
            }
            return Ok(vec![Cmd::Reset {
                kind,
                all: false,
                target: target_in(kind, x)?,
            }]);
        }
        "rename" => {
            return Ok(vec![Cmd::Rename {
                target: target_in(kind, x)?,
                new_name: s_of(x, "newname")?,
            }]);
        }
        v => return Err(Error::msg(format!("Unknown command '{v}'"))),
    }
    let family = family_of(x)?;
    Ok(vec![match kind {
        ObjKind::Table => {
            let flags = strings(get(x, "flags"));
            Cmd::Table {
                create,
                table: Table {
                    family,
                    name: s_of(x, "name")?,
                    flags,
                    comment: opt_s(x, "comment"),
                    ..Default::default()
                },
            }
        }
        ObjKind::Chain => {
            let base = opt_s(x, "hook").map(|hook| BaseChain {
                ty: opt_s(x, "type").unwrap_or_else(|| "filter".into()),
                devices: strings(get(x, "dev")),
                priority: match get(x, "prio") {
                    Some(J::Number(n)) => Priority {
                        name: None,
                        offset: n.as_i64().unwrap_or(0) as i32,
                    },
                    Some(J::String(s)) => Priority {
                        name: Some(s.clone()),
                        offset: 0,
                    },
                    _ => Priority::default(),
                },
                policy: opt_s(x, "policy"),
                hook,
            });
            Cmd::Chain {
                create,
                family,
                table: s_of(x, "table")?,
                table_span: Span::default(),
                chain: Chain {
                    name: s_of(x, "name")?,
                    base,
                    comment: opt_s(x, "comment"),
                    ..Default::default()
                },
            }
        }
        ObjKind::Rule => {
            let stmts = match get(x, "expr") {
                Some(J::Array(a)) => a.iter().map(stmt_in).collect::<Result<_>>()?,
                _ => Vec::new(),
            };
            let op = match verb {
                "insert" => RuleOp::Insert,
                "replace" => RuleOp::Replace,
                _ => RuleOp::Add,
            };
            let pos = match (op, u_of(x, "handle"), u_of(x, "index")) {
                (RuleOp::Replace, Some(h), _) => Some(RulePos::Handle(h)),
                // Handles position explicit add / insert commands; those of
                // listed rules are ignored.
                (_, Some(h), _) if explicit => Some(RulePos::Position(h)),
                (_, _, Some(i)) => Some(RulePos::Index(i as u32)),
                _ => None,
            };
            Cmd::Rule {
                op,
                family,
                table: s_of(x, "table")?,
                table_span: Span::default(),
                chain: s_of(x, "chain")?,
                chain_span: Span::default(),
                pos_span: Span::default(),
                pos,
                rule: Rule {
                    stmts,
                    comment: opt_s(x, "comment"),
                    ..Default::default()
                },
                span: Span::default(),
                stmt_spans: Vec::new(),
            }
        }
        ObjKind::Set | ObjKind::Map => Cmd::Set {
            create,
            family,
            table: s_of(x, "table")?,
            table_span: Span::default(),
            set: set_in(k, x)?,
        },
        ObjKind::Element => return element_in(verb, x),
        ObjKind::Flowtable => Cmd::Flowtable {
            create,
            family,
            table: s_of(x, "table")?,
            table_span: Span::default(),
            ft: Flowtable {
                name: s_of(x, "name")?,
                hook: opt_s(x, "hook").unwrap_or_else(|| "ingress".into()),
                priority: Priority {
                    name: None,
                    offset: get(x, "prio").and_then(J::as_i64).unwrap_or(0) as i32,
                },
                devices: strings(get(x, "dev")),
                ..Default::default()
            },
        },
        k => Cmd::Obj {
            create,
            family,
            table: s_of(x, "table")?,
            table_span: Span::default(),
            obj: Obj {
                span: Span::default(),
                name_span: Span::default(),
                name: s_of(x, "name")?,
                handle: None,
                comment: opt_s(x, "comment"),
                body: obj_body(
                    match k {
                        ObjKind::Counter => "counter",
                        ObjKind::Quota => "quota",
                        ObjKind::Limit => "limit",
                        ObjKind::CtHelper => "ct helper",
                        ObjKind::CtTimeout => "ct timeout",
                        ObjKind::CtExpect => "ct expectation",
                        ObjKind::Synproxy => "synproxy",
                        _ => "secmark",
                    },
                    x,
                )?,
            },
        },
    }])
}

fn element_in(verb: &str, x: &J) -> Result<Vec<Cmd>> {
    Ok(vec![Cmd::Element {
        op: verb.to_owned(),
        family: family_of(x)?,
        table: s_of(x, "table")?,
        table_span: Span::default(),
        set: s_of(x, "name")?,
        set_span: Span::default(),
        elems: elems_in(get(x, "elem").unwrap_or(&J::Array(Vec::new())))?,
    }])
}

/// Parse JSON input (`nft -j -f`): commands, or a listing (whose objects
/// are added).
pub fn parse(text: &str) -> Result<Vec<Cmd>> {
    let v: J = serde_json::from_str(text)
        .map_err(|e| Error::msg(format!("Failed to parse JSON input: {e}")))?;
    let items = v
        .get("nftables")
        .and_then(J::as_array)
        .ok_or_else(|| Error::msg("Input does not contain 'nftables' array."))?;
    let mut cmds = Vec::new();
    for it in items {
        let Some((k, x)) = it.as_object().and_then(|m| m.iter().next()) else {
            return bad("item", it);
        };
        match k.as_str() {
            "metainfo" => {}
            "add" | "create" | "insert" | "replace" | "delete" | "destroy" | "list" | "reset"
            | "flush" | "rename" => {
                cmds.extend(command_in(k, x, true)?);
            }
            _ => cmds.extend(command_in("add", it, false)?),
        }
    }
    Ok(cmds)
}

#[allow(dead_code)]
fn unsupported<T>(what: &str) -> Result<T> {
    Err(Error::msg(format!("JSON: unsupported {what}")))
}
