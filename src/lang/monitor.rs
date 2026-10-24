//! Ruleset change events as text, as `nft monitor` and `nft --echo` print
//! them.

use crate as nft;
use crate::monitor::Event;
use crate::{Family, Object, Ruleset};

use super::ast::{Table, TableItem};
use super::decompile;
use super::print::{self, Opts};

/// Kind of object an event line is about (for `nft monitor` filters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Tables.
    Tables,
    /// Chains.
    Chains,
    /// Rules.
    Rules,
    /// Sets and maps.
    Sets,
    /// Set elements.
    Elements,
    /// Stateful objects.
    Objects,
    /// Flowtables.
    Flowtables,
    /// New generation (end of a transaction).
    Generation,
    /// Packet trace.
    Trace,
}

/// One printed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// A creation (`add`) rather than a deletion.
    pub new: bool,
    /// Object kind.
    pub kind: Kind,
    /// The text (without newline).
    pub text: String,
}

/// Prints events, keeping the state needed to print them like nft
/// (anonymous sets and chains, set definitions for elements).
#[derive(Debug)]
pub struct Printer {
    cache: Ruleset,
    opts: Opts,
    /// Element events of one set, printed together (interval elements
    /// come in parts).
    pending: Option<(bool, nft::SetElemList)>,
    /// Print JSON objects (`{"add": {...}}`) instead of text.
    json: bool,
}

/// What a JSON event is about.
#[cfg_attr(not(feature = "lang_json"), allow(dead_code))]
enum What<'a> {
    Table,
    Item,
    Rule(&'a nft::Rule),
    Element(usize),
}

fn is_anon_set(s: &nft::Set) -> bool {
    s.flags & nft::sys::NFT_SET_ANONYMOUS != 0
}

fn is_binding(c: &nft::Chain) -> bool {
    c.flags.unwrap_or(0) & nft::sys::NFT_CHAIN_BINDING != 0
}

/// One line of block items joined: `{ a; b; }` (or without separators).
fn one_line(block: &str, sep: &str, end: &str) -> String {
    let lines: Vec<&str> = block.lines().collect();
    let head = lines.first().copied().unwrap_or_default();
    let hp = head.split_once('{').map_or("", |(_, h)| h);
    let inner: Vec<String> = lines
        .iter()
        .skip(1)
        .take(lines.len().saturating_sub(2))
        .map(|l| l.trim_start_matches('\t'))
        .filter(|l| *l != "auto-merge")
        .map(|l| format!("{l}{sep}"))
        .collect();
    if inner.is_empty() {
        return format!("{{{hp}{end}");
    }
    format!("{{{hp} {}{end}", inner.join(" "))
}

impl Printer {
    /// A printer starting from a snapshot of the ruleset.
    pub fn new(cache: Ruleset, opts: Opts) -> Self {
        Printer {
            cache,
            opts,
            pending: None,
            json: false,
        }
    }

    /// Print events as JSON (with the `lang_json` feature; otherwise text).
    pub fn with_json(mut self, json: bool) -> Self {
        self.json = json && cfg!(feature = "lang_json");
        self
    }

    /// The JSON of an event, if printing JSON.
    fn json(
        &self,
        new: bool,
        family: Family,
        table: &str,
        rs: Ruleset,
        what: What<'_>,
    ) -> Option<String> {
        if !self.json {
            return None;
        }
        let t = self.table_of(family, table, rs)?;
        self.json_of(new, &t, what)
    }

    /// The JSON of an event about (an item of) decompiled table `t`.
    #[allow(unused_variables)]
    fn json_of(&self, new: bool, t: &Table, what: What<'_>) -> Option<String> {
        #[cfg(feature = "lang_json")]
        {
            use super::json::{EventItem, event};
            let verb = if new { "add" } else { "delete" };
            let r;
            let w = match what {
                What::Table => EventItem::Table,
                What::Item => EventItem::Item,
                What::Element(i) => EventItem::Element(i),
                What::Rule(kr) => {
                    let mut x = decompile::event_rule(&self.cache, kr);
                    if !new {
                        // nft omits the set lookups of deleted rules.
                        x.stmts.retain(|st| {
                            !matches!(
                                st,
                                super::ast::Stmt::Match {
                                    right: super::ast::Expr::Set(_) | super::ast::Expr::SetRef(_),
                                    ..
                                }
                            )
                        });
                    }
                    r = x;
                    EventItem::Rule(&kr.chain, &r)
                }
            };
            return Some(event(verb, t, w, &self.opts));
        }
        #[allow(unreachable_code)]
        None
    }

    fn handle(&self, h: Option<u64>) -> String {
        match (self.opts.handles, h) {
            (true, Some(h)) => format!(" # handle {h}"),
            _ => String::new(),
        }
    }

    /// The decompiled table holding only `rs`'s objects.
    fn table_of(&self, family: Family, table: &str, mut rs: Ruleset) -> Option<Table> {
        if !rs.tables.is_empty() {
            return decompile::ruleset(&rs).pop();
        }
        let t = self
            .cache
            .tables
            .iter()
            .find(|t| t.family == family && t.name == table)
            .cloned()
            .unwrap_or_else(|| nft::Table::new(family, table));
        rs.tables = vec![t];
        decompile::ruleset(&rs).pop()
    }

    fn item_line(&self, family: Family, table: &str, rs: Ruleset) -> Option<String> {
        let t = self.table_of(family, table, rs)?;
        let item = t.items.first()?;
        let block = print::item(item, family, &self.opts);
        Some(match item {
            TableItem::Set(_) => one_line(&block, ";", " } "),
            TableItem::Flowtable(_) => one_line(&block, ";", " }"),
            TableItem::Obj(o) => match o.body.kind() {
                "counter" | "quota" | "limit" | "secmark" => one_line(&block, "", " } "),
                "synproxy" => {
                    let l = one_line(&block, "", " } ");
                    l.replacen(" } ", "; } ", 1)
                }
                _ => one_line(&block, ";", " } "),
            },
            TableItem::Chain(_) => String::new(),
        })
    }

    fn flush(&mut self, out: &mut Vec<Line>) {
        let Some((new, l)) = self.pending.take() else {
            return;
        };
        let Some(set) = self
            .cache
            .sets
            .iter()
            .find(|(s, _)| s.family == l.family && s.table == l.table && s.name == l.set)
            .map(|(s, _)| s.clone())
        else {
            return;
        };
        let rs = Ruleset {
            sets: vec![(set, l.elems.clone())],
            ..Default::default()
        };
        let Some(t) = self.table_of(l.family, &l.table, rs) else {
            return;
        };
        let Some(TableItem::Set(s)) = t.items.first() else {
            return;
        };
        if self.json {
            for i in 0..s.elements.as_ref().map_or(0, Vec::len) {
                if let Some(j) = self.json_of(new, &t, What::Element(i)) {
                    out.push(Line {
                        new,
                        kind: Kind::Elements,
                        text: j,
                    });
                }
            }
            return;
        }
        for e in s.elements.iter().flatten() {
            out.push(Line {
                new,
                kind: Kind::Elements,
                text: format!(
                    "{} element {} {} {} {{ {} }}",
                    if new { "add" } else { "delete" },
                    l.family,
                    l.table,
                    l.set,
                    print::elem(e, l.family, &self.opts)
                ),
            });
        }
    }

    /// Lines for an event (events of set elements are printed when the
    /// next other event, or [`Printer::finish`], comes).
    pub fn event(&mut self, ev: &Event) -> Vec<Line> {
        let mut out = Vec::new();
        let (new, obj) = match ev {
            Event::New(o) => (true, o),
            Event::Del(o) => (false, o),
            Event::Commit(g) => {
                self.flush(&mut out);
                out.push(Line {
                    new: true,
                    kind: Kind::Generation,
                    text: format!(
                        "# new generation {} by process {} ({})",
                        g.id,
                        g.proc_pid.unwrap_or(0),
                        g.proc_name.as_deref().unwrap_or("")
                    ),
                });
                return out;
            }
            Event::Trace(t) => {
                self.flush(&mut out);
                for text in self.trace(t) {
                    out.push(Line {
                        new: true,
                        kind: Kind::Trace,
                        text,
                    });
                }
                return out;
            }
            _ => return out,
        };
        if let Object::SetElems(l) = obj {
            let anon = self
                .cache
                .sets
                .iter()
                .find(|(s, _)| s.family == l.family && s.table == l.table && s.name == l.set)
                .is_some_and(|(s, _)| is_anon_set(s));
            if anon {
                // Kept for the rule that uses the set.
                if let Some((_, e)) =
                    self.cache.sets.iter_mut().find(|(s, _)| {
                        s.family == l.family && s.table == l.table && s.name == l.set
                    })
                {
                    e.extend(l.elems.iter().cloned());
                }
                return out;
            }
            match &mut self.pending {
                Some((n, p))
                    if *n == new
                        && p.family == l.family
                        && p.table == l.table
                        && p.set == l.set =>
                {
                    p.elems.extend(l.elems.iter().cloned());
                }
                _ => {
                    self.flush(&mut out);
                    self.pending = Some((new, l.clone()));
                }
            }
            return out;
        }
        self.flush(&mut out);
        let verb = if new { "add" } else { "delete" };
        match obj {
            Object::Table(t) => {
                let fam = t.family;
                if new {
                    self.cache.tables.push(t.clone());
                } else {
                    self.cache
                        .tables
                        .retain(|x| !(x.family == t.family && x.name == t.name));
                }
                // (Deletions show what the kernel reports, like additions.)
                let flags = decompile::ruleset(&Ruleset {
                    tables: vec![t.clone()],
                    ..Default::default()
                })
                .pop()
                .map(|x| x.flags)
                .unwrap_or_default();
                let mut text = format!("{verb} table {fam} {}", t.name);
                if !flags.is_empty() {
                    text.push_str(&format!(" {{ flags {}; }}", flags.join(",")));
                }
                text.push_str(&self.handle(t.handle));
                let text = self
                    .json(
                        new,
                        t.family,
                        &t.name,
                        Ruleset {
                            tables: vec![t.clone()],
                            ..Default::default()
                        },
                        What::Table,
                    )
                    .unwrap_or(text);
                out.push(Line {
                    new,
                    kind: Kind::Tables,
                    text,
                });
            }
            Object::Chain(c) => {
                if new {
                    self.cache.chains.push(c.clone());
                } else {
                    self.cache.chains.retain(|x| {
                        !(x.family == c.family && x.table == c.table && x.name == c.name)
                    });
                }
                if is_binding(c) {
                    return out;
                }
                let mut s = format!("{verb} chain {} {} {}", c.family, c.table, c.name);
                {
                    let rs = Ruleset {
                        chains: vec![c.clone()],
                        ..Default::default()
                    };
                    if let Some(TableItem::Chain(ch)) = self
                        .table_of(c.family, &c.table, rs)
                        .and_then(|t| t.items.into_iter().next())
                    {
                        // nft prints a deleted chain in full only if it has
                        // devices.
                        let full = new || ch.base.as_ref().is_some_and(|b| !b.devices.is_empty());
                        if let Some(b) = ch.base.as_ref().filter(|_| full) {
                            s.push_str(&format!(" {{ type {} hook {} ", b.ty, b.hook));
                            if !b.devices.is_empty() {
                                s.push_str(&format!("devices = {{ {} }} ", b.devices.join(", ")));
                            }
                            s.push_str(&format!(
                                "priority {}; policy {}; }}",
                                print::priority(&b.hook, &b.priority, c.family, &self.opts),
                                b.policy.as_deref().unwrap_or("accept")
                            ));
                        }
                        if full {
                            s.push_str(&self.handle(c.handle));
                        }
                    }
                }
                let rs = Ruleset {
                    chains: vec![c.clone()],
                    ..Default::default()
                };
                let s = self
                    .json(new, c.family, &c.table, rs, What::Item)
                    .unwrap_or(s);
                out.push(Line {
                    new,
                    kind: Kind::Chains,
                    text: s,
                });
            }
            Object::Rule(r) => {
                let binding = self.cache.chains.iter().any(|c| {
                    c.family == r.family && c.table == r.table && c.name == r.chain && is_binding(c)
                });
                if new {
                    self.cache.rules.push(r.clone());
                }
                if binding || r.chain.is_empty() {
                    return out;
                }
                let text = if new {
                    format!(
                        "add rule {} {} {} {}{}",
                        r.family,
                        r.table,
                        r.chain,
                        print::rule(
                            &decompile::event_rule(&self.cache, r),
                            r.family,
                            &Opts {
                                handles: false,
                                ..self.opts
                            }
                        ),
                        self.handle(r.handle)
                    )
                } else {
                    format!(
                        "delete rule {} {} {} handle {}",
                        r.family,
                        r.table,
                        r.chain,
                        r.handle.unwrap_or(0)
                    )
                };
                let text = self
                    .json(new, r.family, &r.table, Ruleset::default(), What::Rule(r))
                    .unwrap_or(text);
                out.push(Line {
                    new,
                    kind: Kind::Rules,
                    text,
                });
            }
            Object::Set(s) => {
                if !new {
                    self.cache.sets.retain(|(x, _)| {
                        !(x.family == s.family && x.table == s.table && x.name == s.name)
                    });
                } else {
                    self.cache.sets.push((s.clone(), Vec::new()));
                }
                if is_anon_set(s) {
                    return out;
                }
                // (Maps are deleted as sets.)
                let kw = if new && (s.flags & nft::sys::NFT_SET_MAP != 0 || s.obj_type.is_some()) {
                    "map"
                } else {
                    "set"
                };
                let mut text = format!("{verb} {kw} {} {} {}", s.family, s.table, s.name);
                if new {
                    let rs = Ruleset {
                        sets: vec![(s.clone(), Vec::new())],
                        ..Default::default()
                    };
                    if let Some(l) = self.item_line(s.family, &s.table, rs) {
                        text.push(' ');
                        text.push_str(&l);
                    }
                }
                let rs = Ruleset {
                    sets: vec![(s.clone(), Vec::new())],
                    ..Default::default()
                };
                let text = self
                    .json(new, s.family, &s.table, rs, What::Item)
                    .unwrap_or(text);
                out.push(Line {
                    new,
                    kind: Kind::Sets,
                    text,
                });
            }
            Object::Obj(o) => {
                let rs = Ruleset {
                    objs: vec![o.clone()],
                    ..Default::default()
                };
                let Some(t) = self.table_of(o.family, &o.table, rs.clone()) else {
                    return out;
                };
                let Some(TableItem::Obj(x)) = t.items.first() else {
                    return out;
                };
                let mut text = format!(
                    "{verb} {} {} {} {}",
                    x.body.kind(),
                    o.family,
                    o.table,
                    o.name
                );
                if new {
                    if let Some(l) = self.item_line(o.family, &o.table, rs.clone()) {
                        text.push(' ');
                        text.push_str(&l);
                    }
                }
                let text = self
                    .json(new, o.family, &o.table, rs, What::Item)
                    .unwrap_or(text);
                out.push(Line {
                    new,
                    kind: Kind::Objects,
                    text,
                });
            }
            Object::Flowtable(f) => {
                let mut text = format!("{verb} flowtable {} {} {}", f.family, f.table, f.name);
                if new {
                    let rs = Ruleset {
                        flowtables: vec![f.clone()],
                        ..Default::default()
                    };
                    if let Some(l) = self.item_line(f.family, &f.table, rs) {
                        text.push(' ');
                        text.push_str(&l);
                    }
                }
                let rs = Ruleset {
                    flowtables: vec![f.clone()],
                    ..Default::default()
                };
                let text = self
                    .json(new, f.family, &f.table, rs, What::Item)
                    .unwrap_or(text);
                out.push(Line {
                    new,
                    kind: Kind::Flowtables,
                    text,
                });
            }
            _ => {}
        }
        out
    }

    /// Lines still buffered.
    pub fn finish(&mut self) -> Vec<Line> {
        let mut out = Vec::new();
        self.flush(&mut out);
        out
    }
}

// ------------------------------------------------------------------ traces

use super::datatype::{self, Kind as DKind, id};
use super::proto::{self as protos, HdrField, ethertype, ipproto};

/// Fields printed for a protocol in traces, in nft's order (others are
/// filtered, like checksums).
fn trace_fields(name: &str) -> Vec<HdrField> {
    let order: &[&str] = match name {
        "ether" => &["saddr", "daddr", "type"],
        "ip" => &[
            "saddr", "daddr", "dscp", "ecn", "ttl", "id", "protocol", "length",
        ],
        "ip6" => &[
            "saddr",
            "daddr",
            "dscp",
            "ecn",
            "hoplimit",
            "flowlabel",
            "nexthdr",
            "length",
        ],
        "tcp" => &["sport", "dport", "flags", "window"],
        "udp" | "udplite" => &["sport", "dport", "length"],
        "igmp" => &["type", "mrt"],
        _ => &[],
    };
    let Some(p) = protos::proto(name) else {
        return Vec::new();
    };
    if !order.is_empty() {
        return order
            .iter()
            .filter_map(|f| p.field(f).map(|(_, x)| *x))
            .collect();
    }
    // The first field at each offset, in header order, without checksums.
    let mut extra: Vec<HdrField> = Vec::new();
    if name == "icmpv6" {
        // Neighbor discovery fields (not matched in rules here).
        extra.push(HdrField {
            name: "taddr",
            offset: 64,
            len: 128,
            ty: id::IP6ADDR,
        });
    }
    let mut out = Vec::new();
    let mut off = 0;
    while let Some(f) = p
        .fields
        .iter()
        .chain(extra.iter())
        .find(|f| f.offset == off)
    {
        if f.name != "checksum" {
            out.push(*f);
        }
        off += f.len;
    }
    out
}

/// The bits `off..off + len` of `data` as big endian bytes; a field
/// extending past the data has the available bits (right aligned).
fn field_bytes(data: &[u8], off: u32, len: u32) -> Option<Vec<u8>> {
    let total = data.len() as u32 * 8;
    if off >= total {
        return None;
    }
    let avail = len.min(total - off);
    let nbytes = len.div_ceil(8) as usize;
    let mut out = vec![0u8; nbytes];
    // Bit i of the value (from its least significant bit).
    for i in 0..avail {
        let src = off + avail - 1 - i;
        let bit = (data[(src / 8) as usize] >> (7 - src % 8)) & 1;
        if bit != 0 {
            out[nbytes - 1 - (i / 8) as usize] |= 1 << (i % 8);
        }
    }
    Some(out)
}

impl Printer {
    fn trace_value(&self, f: &HdrField, bytes: &[u8]) -> String {
        let t = datatype::by_id(f.ty);
        // Flags are compared as a whole: a symbol, or hex.
        if let DKind::Flags(syms) = t.kind {
            let v = datatype::to_u128(bytes, t.order) as u64;
            return match syms.iter().find(|(_, x)| *x == v) {
                Some((n, _)) => format!("== {n}"),
                None => format!("== 0x{v:x}"),
            };
        }
        // Packet data is in network order.
        let mut b = bytes.to_vec();
        if t.order == datatype::Order::Host && cfg!(target_endian = "little") {
            b.reverse();
        }
        datatype::print(t, &b, f.len, self.opts.value_opts(false))
    }

    /// Statements describing a header, and the protocol of the next one.
    fn trace_header(&self, proto: &str, data: &[u8], out: &mut Vec<String>) -> Option<u32> {
        let mut next = None;
        for f in trace_fields(proto) {
            let Some(b) = field_bytes(data, f.offset, f.len) else {
                break;
            };
            let v = datatype::to_u128(&b, datatype::Order::Big) as u32;
            match (proto, f.name) {
                ("ether", "type") => {
                    // A dependency of the network header.
                    next = Some(v);
                    if matches!(v as u16, ethertype::IP | ethertype::IP6 | ethertype::ARP) {
                        continue;
                    }
                }
                ("ip", "protocol") | ("ip6", "nexthdr") => next = Some(v),
                _ => {}
            }
            out.push(format!("{proto} {} {}", f.name, self.trace_value(&f, &b)));
        }
        next
    }

    fn trace(&self, t: &nft::monitor::Trace) -> Vec<String> {
        use nft::monitor::TraceType;
        let fam =
            Family::from_raw(t.family).map_or_else(|_| "unknown".to_owned(), |f| f.to_string());
        let mut hdr = format!("trace id {:08x} {fam} ", t.id.unwrap_or(0));
        for s in [&t.table, &t.chain].into_iter().flatten() {
            hdr.push_str(s);
            hdr.push(' ');
        }
        let mark = match t.mark {
            Some(m) if m != 0 => format!("meta mark 0x{m:08x} "),
            _ => String::new(),
        };
        let mut lines = Vec::new();
        match t.ty {
            Some(TraceType::Rule) => {
                if t.ll_header.is_some() || t.network_header.is_some() {
                    lines.push(format!("{hdr}packet: {}", self.trace_packet(t)));
                }
                if let Some(h) = t.rule_handle {
                    let rule = self.cache.rules.iter().find(|r| {
                        r.handle == Some(h)
                            && r.family.raw() == t.family
                            && Some(&r.table) == t.table.as_ref()
                            && Some(&r.chain) == t.chain.as_ref()
                    });
                    let text = match rule {
                        Some(r) => super::rule_text(
                            &self.cache,
                            r,
                            &Opts {
                                handles: false,
                                ..self.opts
                            },
                        ),
                        None => format!("handle {h}"),
                    };
                    let v = t.verdict.as_ref().map_or_else(String::new, verdict_text);
                    lines.push(format!("{hdr}rule {text} (verdict {v})"));
                }
            }
            Some(TraceType::Policy) => {
                let p = match t.policy {
                    Some(0) => "drop",
                    _ => "accept",
                };
                lines.push(format!("{hdr}policy {p} {mark}"));
            }
            _ => {}
        }
        lines
    }

    fn trace_packet(&self, t: &nft::monitor::Trace) -> String {
        let mut out: Vec<String> = Vec::new();
        for (k, i) in [("iif", t.iif), ("oif", t.oif)] {
            if let Some(i) = i {
                match datatype::ifindex_name(i) {
                    Some(n) => out.push(format!("{k} \"{n}\"")),
                    None => out.push(format!("{k} {i}")),
                }
            }
        }
        let mut stmts = Vec::new();
        let mut l3: Option<&str> = None;
        if let (Some(ll), Some(1)) = (&t.ll_header, t.iiftype) {
            // Ethernet (ARPHRD_ETHER).
            l3 = match self.trace_header("ether", ll, &mut stmts).map(|v| v as u16) {
                Some(ethertype::IP) => Some("ip"),
                Some(ethertype::IP6) => Some("ip6"),
                Some(ethertype::ARP) => Some("arp"),
                _ => None,
            };
        }
        if l3.is_none() {
            l3 = match t.nfproto {
                Some(2) => Some("ip"),
                Some(10) => Some("ip6"),
                _ => match t.family {
                    2 => Some("ip"),
                    10 => Some("ip6"),
                    _ => None,
                },
            };
        }
        let mut l4 = None;
        if let (Some(nh), Some(p)) = (&t.network_header, l3) {
            l4 = self.trace_header(p, nh, &mut stmts);
        }
        if let (Some(th), Some(p)) = (&t.transport_header, l4) {
            let name = match p as u8 {
                ipproto::TCP => Some("tcp"),
                ipproto::UDP => Some("udp"),
                ipproto::UDPLITE => Some("udplite"),
                ipproto::ICMP => Some("icmp"),
                ipproto::ICMPV6 => Some("icmpv6"),
                ipproto::IGMP => Some("igmp"),
                ipproto::SCTP => Some("sctp"),
                ipproto::DCCP => Some("dccp"),
                ipproto::ESP => Some("esp"),
                ipproto::AH => Some("ah"),
                ipproto::COMP => Some("comp"),
                ipproto::GRE => Some("gre"),
                _ => None,
            };
            if let Some(n) = name {
                self.trace_header(n, th, &mut stmts);
            }
        }
        out.extend(stmts);
        let mut s = out.join(" ");
        s.push(' ');
        s
    }
}

fn verdict_text(v: &nft::Verdict) -> String {
    match v {
        nft::Verdict::Accept => "accept".into(),
        nft::Verdict::Drop => "drop".into(),
        nft::Verdict::Continue => "continue".into(),
        nft::Verdict::Return => "return".into(),
        nft::Verdict::Break => "break".into(),
        nft::Verdict::Queue => "queue".into(),
        nft::Verdict::Jump(c) => format!("jump {c}"),
        nft::Verdict::Goto(c) => format!("goto {c}"),
        nft::Verdict::JumpId(_) => "jump".into(),
        nft::Verdict::GotoId(_) => "goto".into(),
        nft::Verdict::Other(c) => format!("unknown {c}"),
    }
}
