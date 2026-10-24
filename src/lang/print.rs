//! Printing of the AST in the format of `nft list`.

use std::fmt::Write as _;

use crate::Family;

use super::ast::*;
use super::datatype::{self, Kind, PrintOpts};

/// Output options (the `nft` command line flags).
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts {
    /// `-a`: print handles.
    pub handles: bool,
    /// Symbolic constants as numbers (`-n`).
    pub numeric: bool,
    /// IP protocols as numbers (`-p`, `-n`).
    pub numeric_proto: bool,
    /// Chain priorities as numbers (`-y`, `-n`).
    pub numeric_prio: bool,
    /// Times in seconds (`-T`, `-n`).
    pub numeric_time: bool,
    /// Service names for ports (`-S`).
    pub service: bool,
    /// Host names for addresses (`-N`).
    pub reverse_dns: bool,
    /// User and group names (`-u`).
    pub guid: bool,
    /// `-s`: omit stateful information (counters, quotas, expiry).
    pub stateless: bool,
    /// `-t`: omit set elements.
    pub terse: bool,
    /// Do not separate table items with blank lines (as `list chains`).
    pub compact: bool,
    /// Print set elements on one line (as `get element`).
    pub inline_elements: bool,
}

impl Opts {
    /// Options for printing values.
    pub(crate) fn value_opts(&self, in_set: bool) -> PrintOpts {
        PrintOpts {
            numeric: self.numeric,
            numeric_proto: self.numeric_proto,
            numeric_time: self.numeric_time,
            service: self.service,
            reverse_dns: self.reverse_dns,
            guid: self.guid,
            in_set,
        }
    }
}

/// The number of reject code `code` of reject type `with` (`icmp`,
/// `icmpv6`, `icmpx`).
pub(crate) fn reject_code(with: &str, code: &str) -> Option<u64> {
    let syms = match with {
        "icmpx" => datatype::ICMPX_CODES,
        w => match datatype::by_id(if w == "icmpv6" {
            datatype::id::ICMPV6_CODE
        } else {
            datatype::id::ICMP_CODE
        })
        .kind
        {
            Kind::SymDec(s) => s,
            _ => &[],
        },
    };
    syms.iter().find(|(n, _)| *n == code).map(|(_, v)| *v)
}

/// Where a value is printed, which affects flag formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Plain value position (`tcp flags syn,ack`).
    Plain,
    /// After an explicit relational operator (`== syn | ack`).
    Relational,
    /// Operand of a binary operation (`& (syn | ack)`).
    Binop,
    /// Element of a named set.
    InSet,
    /// Right side of a relational expression whose left side is a
    /// binary operation (`ip frag-off & 0x1fff != 0x0`).
    BinopRhs,
}

struct P<'a> {
    o: &'a Opts,
    family: Family,
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

impl P<'_> {
    fn value(&self, v: &Value, ctx: Ctx) -> String {
        match v {
            Value::Raw(s) => s.clone(),
            Value::Typed { ty, bytes, bits } => {
                let t = datatype::by_id(*ty);
                let opts = self.o.value_opts(ctx == Ctx::InSet);
                if let Kind::Flags(syms) = t.kind {
                    let syms = if self.o.numeric { &[][..] } else { syms };
                    let n = datatype::to_u128(bytes, t.order) as u64;
                    let s = match ctx {
                        Ctx::Plain | Ctx::InSet => datatype::print_flags(syms, n, ","),
                        Ctx::Relational | Ctx::Binop | Ctx::BinopRhs => {
                            datatype::print_flags(syms, n, " | ")
                        }
                    };
                    if ctx == Ctx::Binop && n.count_ones() > 1 {
                        return format!("({s})");
                    }
                    return s;
                }
                // Integers in bit operations are printed in hex.
                if matches!(ctx, Ctx::Binop | Ctx::BinopRhs)
                    && t.kind == Kind::Integer
                    && t.id != datatype::id::INET_SERVICE
                {
                    return format!("0x{:x}", datatype::to_u128(bytes, t.order));
                }
                datatype::print(t, bytes, *bits, opts)
            }
        }
    }

    fn expr(&self, e: &Expr, ctx: Ctx) -> String {
        match e {
            Expr::Payload { proto, field } => format!("{proto} {field}"),
            Expr::Raw { base, offset, len } => format!("@{base},{offset},{len}"),
            Expr::Exthdr { desc, field, .. } => match field {
                Some(f) => format!("{desc} {f}"),
                None => desc.clone(),
            },
            Expr::Meta(k) => match super::proto::meta(k) {
                Some(m) if m.unqualified => k.clone(),
                _ => format!("meta {k}"),
            },
            Expr::Ct { dir, key } => match dir {
                Some(d) => format!("ct {d} {key}"),
                None => format!("ct {key}"),
            },
            Expr::Rt(k) => format!("rt {k}"),
            Expr::Socket { key, level } => match level {
                Some(l) => format!("socket {key} level {l}"),
                None => format!("socket {key}"),
            },
            Expr::Osf { ttl, version } => {
                let mut s = String::from("osf");
                if let Some(t) = ttl {
                    let _ = write!(s, " ttl {t}");
                }
                s.push_str(if *version { " version" } else { " name" });
                s
            }
            Expr::Fib { flags, result } => format!("fib {} {result}", flags.join(" . ")),
            Expr::Numgen {
                mode,
                modulus,
                offset,
            } => {
                let mut s = format!("numgen {mode} mod {modulus}");
                if *offset != 0 {
                    let _ = write!(s, " offset {offset}");
                }
                s
            }
            Expr::Hash {
                input,
                modulus,
                seed,
                offset,
            } => {
                let mut s = match input {
                    Some(i) => format!("jhash {} mod {modulus}", self.expr(i, Ctx::Plain)),
                    None => format!("symhash mod {modulus}"),
                };
                if let Some(seed) = seed {
                    let _ = write!(s, " seed 0x{seed:x}");
                }
                if *offset != 0 {
                    let _ = write!(s, " offset {offset}");
                }
                s
            }
            Expr::Ipsec { dir, spnum, key } => {
                if *spnum == 0 {
                    format!("ipsec {dir} {key}")
                } else {
                    format!("ipsec {dir} spnum {spnum} {key}")
                }
            }
            Expr::Concat(v) => v
                .iter()
                .map(|e| self.expr(e, ctx))
                .collect::<Vec<_>>()
                .join(" . "),
            Expr::Binop(op, l, r) => {
                let ls = match **l {
                    Expr::Binop(..) => self.expr(l, Ctx::Binop),
                    _ => self.expr(l, Ctx::Plain),
                };
                let rs = match **r {
                    Expr::Binop(..) => format!("({})", self.expr(r, Ctx::Binop)),
                    _ => self.expr(r, Ctx::Binop),
                };
                format!("{ls} {} {rs}", op.as_str())
            }
            Expr::Value(v) => self.value(v, ctx),
            Expr::Prefix(e, len) => format!("{}/{len}", self.expr(e, ctx)),
            Expr::Range(a, b) => {
                // Range bounds are not translated to names.
                let o = Opts {
                    service: false,
                    reverse_dns: false,
                    ..*self.o
                };
                let p = P {
                    o: &o,
                    family: self.family,
                };
                format!("{}-{}", p.expr(a, ctx), p.expr(b, ctx))
            }
            Expr::List(v) => v
                .iter()
                .map(|e| self.expr(e, ctx))
                .collect::<Vec<_>>()
                .join(","),
            Expr::Set(elems) => {
                let items: Vec<String> = elems.iter().map(|e| self.elem(e, Ctx::Plain)).collect();
                format!("{{ {} }}", items.join(", "))
            }
            Expr::SetRef(n) => format!("@{n}"),
            Expr::Map(k, m) => format!(
                "{} map {}",
                self.expr(k, Ctx::Plain),
                self.expr(m, Ctx::Plain)
            ),
            Expr::Verdict(v) => self.verdict(v, 2),
            Expr::Wildcard => "*".into(),
            Expr::Variable(v) => format!("${v}"),
        }
    }

    fn elem(&self, e: &Elem, ctx: Ctx) -> String {
        let mut s = match &e.key {
            Some(k) => self.expr(k, ctx),
            None => "*".into(),
        };
        for st in &e.stmts {
            let _ = write!(s, " {}", self.stmt(st, 2));
        }
        if let Some(t) = e.timeout {
            let _ = write!(s, " timeout {}", self.time(t));
        }
        if let (Some(x), false) = (e.expires, self.o.stateless) {
            let _ = write!(s, " expires {}", self.time(x));
        }
        if let Some(c) = &e.comment {
            let _ = write!(s, " comment {}", quote(c));
        }
        if let Some(d) = &e.data {
            let _ = write!(s, " : {}", self.expr(d, ctx));
        }
        s
    }

    fn verdict(&self, v: &Verdict, depth: usize) -> String {
        match v {
            Verdict::Accept => "accept".into(),
            Verdict::Drop => "drop".into(),
            Verdict::Continue => "continue".into(),
            Verdict::Return => "return".into(),
            Verdict::Queue => "queue".into(),
            Verdict::Jump(c) => format!("jump {c}"),
            Verdict::Goto(c) => format!("goto {c}"),
            Verdict::JumpBlock(rules) | Verdict::GotoBlock(rules) => {
                let kw = if matches!(v, Verdict::JumpBlock(_)) {
                    "jump"
                } else {
                    "goto"
                };
                let mut s = format!("{kw} {{\n");
                for r in rules {
                    // Rules of anonymous chains are printed without handles.
                    let o = Opts {
                        handles: false,
                        ..*self.o
                    };
                    let inner = P {
                        o: &o,
                        family: self.family,
                    };
                    let _ = writeln!(s, "{}{}", tabs(depth + 1), inner.rule(r, depth + 1));
                }
                let _ = write!(s, "{}}}", tabs(depth));
                s
            }
        }
    }

    fn bytes_unit(n: u64) -> String {
        if n != 0 && n % (1024 * 1024) == 0 {
            format!("{} mbytes", n / (1024 * 1024))
        } else if n != 0 && n % 1024 == 0 {
            format!("{} kbytes", n / 1024)
        } else {
            format!("{n} bytes")
        }
    }

    /// A limit; `stmt`: a statement (not an object).
    fn limit(&self, l: &Limit, stmt: bool) -> String {
        let mut s = String::from("rate ");
        if l.over {
            s.push_str("over ");
        }
        match &l.rate_unit {
            Some(u) => {
                let _ = write!(s, "{} {u}/{}", l.rate, l.per);
            }
            None => {
                let _ = write!(s, "{}/{}", l.rate, l.per);
            }
        }
        // nft shows the default burst with numeric times.
        let burst = match l.burst {
            None if stmt && self.o.numeric_time && l.rate_unit.is_none() => Some(5),
            b => b,
        };
        if let Some(b) = burst {
            let _ = write!(
                s,
                " burst {b} {}",
                l.burst_unit.as_deref().unwrap_or("packets")
            );
        }
        s
    }

    fn quota(&self, q: &Quota) -> String {
        let mut s = String::new();
        if q.over {
            s.push_str("over ");
        }
        s.push_str(&Self::bytes_unit(q.bytes));
        if q.used != 0 && !self.o.stateless {
            let _ = write!(s, " used {}", Self::bytes_unit(q.used));
        }
        s
    }

    fn stmt(&self, st: &Stmt, depth: usize) -> String {
        match st {
            Stmt::Match { left, op, right } => {
                let l = self.expr(left, Ctx::Plain);
                match op {
                    RelOp::Implicit => format!("{l} {}", self.expr(right, Ctx::Plain)),
                    op => {
                        let ctx = if matches!(left, Expr::Binop(..)) {
                            Ctx::BinopRhs
                        } else {
                            Ctx::Relational
                        };
                        format!("{l} {} {}", op.as_str(), self.expr(right, ctx))
                    }
                }
            }
            Stmt::Verdict(v) => self.verdict(v, depth),
            Stmt::Vmap { key, map } => format!(
                "{} vmap {}",
                self.expr(key, Ctx::Plain),
                self.expr(map, Ctx::Plain)
            ),
            Stmt::Counter { packets, bytes } => match (packets, bytes, self.o.stateless) {
                (Some(p), Some(b), false) => format!("counter packets {p} bytes {b}"),
                _ => "counter".into(),
            },
            Stmt::Limit(l) => format!("limit {}", self.limit(l, true)),
            Stmt::Quota(q) => format!("quota {}", self.quota(q)),
            Stmt::Log(l) => {
                let mut s = String::from("log");
                if let Some(p) = &l.prefix {
                    let _ = write!(s, " prefix {}", quote(p));
                }
                if let Some(g) = l.group {
                    let _ = write!(s, " group {g}");
                }
                if let Some(n) = l.snaplen {
                    let _ = write!(s, " snaplen {n}");
                }
                if let Some(n) = l.qthreshold {
                    let _ = write!(s, " queue-threshold {n}");
                }
                if let Some(lv) = &l.level {
                    let _ = write!(s, " level {lv}");
                }
                if let Some(f) = &l.flags {
                    // Each group of flags has its own keyword.
                    let words: Vec<&str> = f.split(' ').collect();
                    let mut i = 0;
                    while i < words.len() {
                        let n = if matches!(words[i], "tcp" | "ip") {
                            2
                        } else {
                            1
                        };
                        let end = (i + n).min(words.len());
                        let _ = write!(s, " flags {}", words[i..end].join(" "));
                        i = end;
                    }
                }
                s
            }
            Stmt::Connlimit { count, over } => {
                if *over {
                    format!("ct count over {count}")
                } else {
                    format!("ct count {count}")
                }
            }
            Stmt::Last { used } => match (used, self.o.stateless) {
                (_, true) => "last".into(),
                (None, _) => "last used never".into(),
                (Some(ms), _) => format!("last used {}", self.time(*ms)),
            },
            Stmt::Objref { kind, name } => {
                let n = self.expr(name, Ctx::Plain);
                match kind.as_str() {
                    "ct helper" | "ct timeout" | "ct expectation" => format!("{kind} set {n}"),
                    "secmark" => format!("meta secmark set {n}"),
                    _ => format!("{kind} name {n}"),
                }
            }
            Stmt::MetaSet { key, value } => {
                let k = self.expr(&Expr::Meta(key.clone()), Ctx::Plain);
                format!("{k} set {}", self.expr(value, Ctx::Plain))
            }
            Stmt::CtSet { key, dir, value } => {
                let k = self.expr(
                    &Expr::Ct {
                        dir: dir.clone(),
                        key: key.clone(),
                    },
                    Ctx::Plain,
                );
                format!("{k} set {}", self.expr(value, Ctx::Plain))
            }
            Stmt::PayloadSet { target, value } => {
                format!(
                    "{} set {}",
                    self.expr(target, Ctx::Plain),
                    self.expr(value, Ctx::Plain)
                )
            }
            Stmt::Nat {
                kind,
                family,
                addr,
                port,
                flags,
            } => {
                let mut s = String::from(match kind {
                    NatKind::Snat => "snat",
                    NatKind::Dnat => "dnat",
                    NatKind::Masquerade => "masquerade",
                    NatKind::Redirect => "redirect",
                });
                if let Some(f) = family {
                    let _ = write!(s, " {f}");
                }
                if addr.is_some() || port.is_some() {
                    s.push_str(" to ");
                }
                if let Some(a) = addr {
                    let a6 = matches!(family.as_deref(), Some("ip6"));
                    let txt = self.expr(a, Ctx::Plain);
                    if a6 && port.is_some() && !matches!(a, Expr::Map(..)) {
                        let _ = write!(s, "[{txt}]");
                    } else {
                        s.push_str(&txt);
                    }
                }
                if let Some(p) = port {
                    let _ = write!(s, ":{}", self.expr(p, Ctx::Plain));
                }
                if !flags.is_empty() {
                    let _ = write!(s, " {}", flags.join(","));
                }
                s
            }
            Stmt::Reject { with, code } => match (with, code) {
                (None, _) => "reject".into(),
                (Some(w), None) => format!("reject with {w}"),
                (Some(w), Some(c)) if self.o.numeric => match reject_code(w, c) {
                    Some(v) => format!("reject with {w} {v}"),
                    None => format!("reject with {w} {c}"),
                },
                (Some(w), Some(c)) => format!("reject with {w} {c}"),
            },
            Stmt::Queue { flags, num } => {
                let mut s = String::from("queue");
                if !flags.is_empty() {
                    let _ = write!(s, " flags {}", flags.join(","));
                }
                if let Some(n) = num {
                    let _ = write!(s, " to {}", self.expr(n, Ctx::Plain));
                }
                s
            }
            Stmt::Dup { addr, dev } => {
                let mut s = String::from("dup");
                if let Some(a) = addr {
                    let _ = write!(s, " to {}", self.expr(a, Ctx::Plain));
                }
                if let Some(d) = dev {
                    let kw = if addr.is_some() { "device" } else { "to" };
                    let _ = write!(s, " {kw} {}", self.expr(d, Ctx::Plain));
                }
                s
            }
            Stmt::Fwd { family, addr, dev } => {
                let mut s = String::from("fwd");
                if let Some(f) = family {
                    let _ = write!(s, " {f}");
                }
                match addr {
                    Some(a) => {
                        let _ = write!(
                            s,
                            " to {} device {}",
                            self.expr(a, Ctx::Plain),
                            self.expr(dev, Ctx::Plain)
                        );
                    }
                    None => {
                        let _ = write!(s, " to {}", self.expr(dev, Ctx::Plain));
                    }
                }
                s
            }
            Stmt::Notrack => "notrack".into(),
            Stmt::Flow(ft) => format!("flow add @{ft}"),
            Stmt::Tproxy { family, addr, port } => {
                let mut s = String::from("tproxy");
                if let Some(f) = family {
                    let _ = write!(s, " {f}");
                }
                s.push_str(" to ");
                if let Some(a) = addr {
                    let txt = self.expr(a, Ctx::Plain);
                    if family.as_deref() == Some("ip6") && port.is_some() {
                        let _ = write!(s, "[{txt}]");
                    } else {
                        s.push_str(&txt);
                    }
                }
                if let Some(p) = port {
                    let _ = write!(s, ":{}", self.expr(p, Ctx::Plain));
                }
                s
            }
            Stmt::Synproxy { mss, wscale, flags } => {
                let mut s = String::from("synproxy");
                if let Some(m) = mss {
                    let _ = write!(s, " mss {m}");
                }
                if let Some(w) = wscale {
                    let _ = write!(s, " wscale {w}");
                }
                for f in flags {
                    let _ = write!(s, " {f}");
                }
                s
            }
            Stmt::SetUpdate {
                op,
                set,
                key,
                data,
                timeout,
                stmts,
            } => {
                let mut s = format!("{op} @{set} {{ {}", self.expr(key, Ctx::Plain));
                if let Some(t) = timeout {
                    let _ = write!(s, " timeout {}", self.time(*t));
                }
                for st in stmts {
                    let _ = write!(s, " {}", self.stmt(st, depth));
                }
                if let Some(d) = data {
                    let _ = write!(s, " : {}", self.expr(d, Ctx::Plain));
                }
                s.push_str(" }");
                s
            }
            Stmt::Meter {
                name,
                size,
                key,
                timeout,
                stmts,
            } => {
                let mut s = format!("meter {name}");
                if let Some(n) = size {
                    let _ = write!(s, " size {n}");
                }
                let _ = write!(s, " {{ {}", self.expr(key, Ctx::Plain));
                if let Some(t) = timeout {
                    let _ = write!(s, " timeout {}", self.time(*t));
                }
                for st in stmts {
                    let _ = write!(s, " {}", self.stmt(st, depth));
                }
                s.push_str(" }");
                s
            }
            Stmt::Opaque(s) => s.clone(),
        }
    }

    fn rule(&self, r: &Rule, depth: usize) -> String {
        let mut s = r
            .stmts
            .iter()
            .map(|st| self.stmt(st, depth))
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(c) = &r.comment {
            if !s.is_empty() {
                s.push(' ');
            }
            let _ = write!(s, "comment {}", quote(c));
        }
        if let (true, Some(h)) = (self.o.handles, r.handle) {
            let _ = write!(s, " # handle {h}");
        }
        s
    }

    fn time(&self, ms: u64) -> String {
        datatype::time_ms(ms, self.o.numeric_time)
    }

    fn handle_comment(&self, h: Option<u64>) -> String {
        match (self.o.handles, h) {
            (true, Some(h)) => format!(" # handle {h}"),
            _ => String::new(),
        }
    }

    fn priority(&self, hook: &str, p: &Priority) -> String {
        if self.o.numeric_prio {
            if let Ok(v) = super::compile::priority_value(self.family, hook, p) {
                return v.to_string();
            }
        }
        match &p.name {
            Some(n) if p.offset > 0 => format!("{n} + {}", p.offset),
            Some(n) if p.offset < 0 => format!("{n} - {}", -p.offset),
            Some(n) => n.clone(),
            None => p.offset.to_string(),
        }
    }

    fn devices(devs: &[String]) -> String {
        if devs.len() == 1 {
            format!("device {}", quote(&devs[0]))
        } else {
            format!("devices = {{ {} }}", devs.join(", "))
        }
    }

    fn chain(&self, c: &Chain, out: &mut String) {
        let _ = writeln!(
            out,
            "\tchain {} {{{}",
            c.name,
            self.handle_comment(c.handle)
        );
        if let Some(cm) = &c.comment {
            let _ = writeln!(out, "\t\tcomment {}", quote(cm));
        }
        if let Some(b) = &c.base {
            let _ = write!(out, "\t\ttype {} hook {}", b.ty, b.hook);
            if !b.devices.is_empty() {
                let _ = write!(out, " {}", Self::devices(&b.devices));
            }
            let _ = write!(out, " priority {};", self.priority(&b.hook, &b.priority));
            if let Some(p) = &b.policy {
                let _ = write!(out, " policy {p};");
            }
            out.push('\n');
        }
        for r in &c.rules {
            let _ = writeln!(out, "\t\t{}", self.rule(r, 2));
        }
        out.push_str("\t}\n");
    }

    fn typespec(&self, t: &TypeSpec) -> String {
        match t {
            TypeSpec::Type(v) => v.join(" . "),
            TypeSpec::Typeof(v) => v
                .iter()
                .map(|e| self.expr(e, Ctx::Plain))
                .collect::<Vec<_>>()
                .join(" . "),
        }
    }

    fn set(&self, s: &Set, out: &mut String) {
        let kw = if s.is_map { "map" } else { "set" };
        let _ = writeln!(out, "\t{kw} {} {{{}", s.name, self.handle_comment(s.handle));
        let typeof_ = matches!(s.key, Some(TypeSpec::Typeof(_)));
        let mut line = String::from(if typeof_ { "typeof " } else { "type " });
        if let Some(k) = &s.key {
            line.push_str(&self.typespec(k));
        }
        if let Some(d) = &s.data {
            line.push_str(" : ");
            if s.data_interval {
                line.push_str("interval ");
            }
            line.push_str(&self.typespec(d));
        }
        let _ = writeln!(out, "\t\t{line}");
        if let Some(p) = &s.policy {
            let _ = writeln!(out, "\t\tpolicy {p}");
        }
        if let Some(n) = s.size {
            let _ = writeln!(out, "\t\tsize {n}");
        }
        // A set timeout implies the timeout flag, which is shown only along
        // with other flags.
        let only_timeout = s.timeout.is_some() && s.flags == ["timeout"];
        if !s.flags.is_empty() && !only_timeout {
            let _ = writeln!(out, "\t\tflags {}", s.flags.join(","));
        }
        if !s.stmts.is_empty() {
            let v: Vec<String> = s.stmts.iter().map(|st| self.stmt(st, 2)).collect();
            let _ = writeln!(out, "\t\t{}", v.join(" "));
        }
        if s.auto_merge {
            out.push_str("\t\tauto-merge\n");
        }
        if let Some(t) = s.timeout {
            let _ = writeln!(out, "\t\ttimeout {}", self.time(t));
        }
        if let Some(t) = s.gc_interval {
            let _ = writeln!(out, "\t\tgc-interval {}", self.time(t));
        }
        if let Some(c) = &s.comment {
            let _ = writeln!(out, "\t\tcomment {}", quote(c));
        }
        if let (Some(elems), false) = (&s.elements, self.o.terse) {
            if !elems.is_empty() {
                out.push_str("\t\telements = { ");
                let per_line = if s.is_map
                    || s.flags.iter().any(|f| f == "timeout")
                    || elems
                        .iter()
                        .any(|e| e.comment.is_some() || !e.stmts.is_empty() || e.timeout.is_some())
                {
                    Some(1)
                } else {
                    match &s.key {
                        Some(TypeSpec::Type(names)) if names.len() == 1 => {
                            datatype::by_name(&names[0])
                                .and_then(|t| datatype::elements_per_line(t.id))
                        }
                        Some(TypeSpec::Typeof(exprs)) if exprs.len() == 1 => {
                            elem_type_of(&elems[0])
                                .or_else(|| expr_type(&exprs[0]))
                                .and_then(datatype::elements_per_line)
                        }
                        _ => None,
                    }
                };
                let per_line = if self.o.inline_elements {
                    usize::MAX
                } else {
                    per_line.unwrap_or(1)
                };
                for (i, e) in elems.iter().enumerate() {
                    out.push_str(&self.elem(e, Ctx::InSet));
                    if i + 1 < elems.len() {
                        if (i + 1) % per_line == 0 {
                            out.push_str(",\n\t\t\t     ");
                        } else {
                            out.push_str(", ");
                        }
                    }
                }
                out.push_str(" }\n");
            }
        }
        out.push_str("\t}\n");
    }

    fn obj(&self, o: &Obj, out: &mut String) {
        let _ = writeln!(
            out,
            "\t{} {} {{{}",
            o.body.kind(),
            o.name,
            self.handle_comment(o.handle)
        );
        if let Some(c) = &o.comment {
            let _ = writeln!(out, "\t\tcomment {}", quote(c));
        }
        match &o.body {
            ObjBody::Counter { packets, bytes } => {
                if !self.o.stateless {
                    let _ = writeln!(out, "\t\tpackets {packets} bytes {bytes}");
                }
            }
            ObjBody::Quota(q) => {
                let _ = writeln!(out, "\t\t{}", self.quota(q));
            }
            ObjBody::Limit(l) => {
                let _ = writeln!(out, "\t\t{}", self.limit(l, false));
            }
            ObjBody::CtHelper {
                helper,
                protocol,
                l3proto,
            } => {
                let _ = writeln!(out, "\t\ttype {} protocol {protocol}", quote(helper));
                if let Some(l) = l3proto {
                    let _ = writeln!(out, "\t\tl3proto {l}");
                }
            }
            ObjBody::CtTimeout {
                protocol,
                l3proto,
                policy,
            } => {
                let _ = writeln!(out, "\t\tprotocol {protocol}");
                if let Some(l) = l3proto {
                    let _ = writeln!(out, "\t\tl3proto {l}");
                }
                let p: Vec<String> = policy
                    .iter()
                    .map(|(s, v)| format!("{s} : {}", self.time(u64::from(*v) * 1000)))
                    .collect();
                let _ = writeln!(out, "\t\tpolicy = {{ {} }}", p.join(", "));
            }
            ObjBody::CtExpect {
                protocol,
                dport,
                timeout,
                size,
                l3proto,
            } => {
                let _ = writeln!(out, "\t\tprotocol {protocol}");
                let _ = writeln!(out, "\t\tdport {dport}");
                let _ = writeln!(out, "\t\ttimeout {}", self.time(*timeout));
                let _ = writeln!(out, "\t\tsize {size}");
                if let Some(l) = l3proto {
                    let _ = writeln!(out, "\t\tl3proto {l}");
                }
            }
            ObjBody::Synproxy { mss, wscale, flags } => {
                let _ = writeln!(out, "\t\tmss {mss}");
                let _ = writeln!(out, "\t\twscale {wscale}");
                if !flags.is_empty() {
                    let _ = writeln!(out, "\t\t{}", flags.join(" "));
                }
            }
            ObjBody::Secmark(ctx) => {
                let _ = writeln!(out, "\t\t{}", quote(ctx));
            }
        }
        out.push_str("\t}\n");
    }

    fn flowtable(&self, f: &Flowtable, out: &mut String) {
        let _ = writeln!(
            out,
            "\tflowtable {} {{{}",
            f.name,
            self.handle_comment(f.handle)
        );
        let _ = writeln!(
            out,
            "\t\thook {} priority {}",
            f.hook,
            self.priority(&f.hook, &f.priority)
        );
        if !f.devices.is_empty() {
            let _ = writeln!(out, "\t\tdevices = {{ {} }}", f.devices.join(", "));
        }
        if f.offload {
            out.push_str("\t\tflags offload\n");
        }
        if f.counter {
            out.push_str("\t\tcounter\n");
        }
        out.push_str("\t}\n");
    }

    fn table(&self, t: &Table, out: &mut String) {
        let mut hdr = self.handle_comment(t.handle);
        if let Some(p) = &t.owner {
            if hdr.is_empty() {
                hdr = format!(" # progname {p}");
            } else {
                let _ = write!(hdr, " progname {p}");
            }
        }
        let _ = writeln!(out, "table {} {} {{{hdr}", t.family, t.name);
        let mut head = false;
        if !t.flags.is_empty() {
            let _ = writeln!(out, "\tflags {}", t.flags.join(","));
            head = true;
        }
        if let Some(c) = &t.comment {
            let _ = writeln!(out, "\tcomment {}", quote(c));
            head = true;
        }
        for (i, item) in t.items.iter().enumerate() {
            if (i > 0 || head) && !self.o.compact {
                out.push('\n');
            }
            match item {
                TableItem::Chain(c) => self.chain(c, out),
                TableItem::Set(s) => self.set(s, out),
                TableItem::Obj(o) => self.obj(o, out),
                TableItem::Flowtable(f) => self.flowtable(f, out),
            }
        }
        out.push_str("}\n");
    }
}

/// The type id of an element's key, if it is a single typed value.
fn elem_type_of(e: &Elem) -> Option<u32> {
    let mut k = e.key.as_ref()?;
    loop {
        match k {
            Expr::Value(Value::Typed { ty, .. }) => return Some(*ty),
            Expr::Range(a, _) | Expr::Prefix(a, _) => k = a,
            _ => return None,
        }
    }
}

/// The name of the datatype of a (typeof) expression.
#[cfg(feature = "lang_json")]
pub(crate) fn expr_type_name(e: &Expr) -> Option<&'static str> {
    expr_type(e).map(|t| datatype::by_id(t).name)
}

/// The datatype of a (typeof) key expression.
fn expr_type(e: &Expr) -> Option<u32> {
    match e {
        Expr::Payload { proto, field } => Some(super::proto::proto(proto)?.field(field)?.1.ty),
        Expr::Meta(k) => Some(super::proto::meta(k)?.ty),
        Expr::Ct { key, .. } => Some(super::proto::ct(key)?.ty),
        _ => None,
    }
}

fn tabs(n: usize) -> String {
    "\t".repeat(n)
}

/// Print tables like `nft list ruleset`.
pub fn tables(tables: &[Table], o: &Opts) -> String {
    let mut out = String::new();
    for t in tables {
        P {
            o,
            family: t.family,
        }
        .table(t, &mut out);
    }
    out
}

/// Print a table item as in a listing (indented by one tab).
pub(crate) fn item(item: &TableItem, family: Family, o: &Opts) -> String {
    let p = P { o, family };
    let mut out = String::new();
    match item {
        TableItem::Chain(c) => p.chain(c, &mut out),
        TableItem::Set(s) => p.set(s, &mut out),
        TableItem::Obj(x) => p.obj(x, &mut out),
        TableItem::Flowtable(f) => p.flowtable(f, &mut out),
    }
    out
}

/// Print a set element (as in a set's element list).
pub(crate) fn elem(e: &Elem, family: Family, o: &Opts) -> String {
    P { o, family }.elem(e, Ctx::InSet)
}

/// Print a chain priority.
pub(crate) fn priority(hook: &str, p: &Priority, family: Family, o: &Opts) -> String {
    P { o, family }.priority(hook, p)
}

/// Print one rule's statements (without indentation).
pub fn rule(r: &Rule, family: Family, o: &Opts) -> String {
    P { o, family }.rule(r, 2)
}

/// Print an expression.
pub fn expr(e: &Expr, family: Family, o: &Opts) -> String {
    P { o, family }.expr(e, Ctx::Plain)
}

impl P<'_> {
    #[allow(dead_code)]
    fn family(&self) -> Family {
        self.family
    }
}

/// Print a verdict; anonymous chains are indented for nesting `depth`.
pub fn verdict(v: &Verdict, family: Family, depth: usize, o: &Opts) -> String {
    P { o, family }.verdict(v, depth)
}
