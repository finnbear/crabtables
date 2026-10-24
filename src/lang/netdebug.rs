//! `--debug=netlink`: kernel objects in the text format of libnftnl (as
//! `nft --debug=netlink` prints them).

use std::fmt::Write;

use crate as nft;
use crate::expr as kx;
use crate::sys::*;
use crate::{Data, Family, Object, PayloadBase, Reg};

fn reg(r: Reg) -> u32 {
    r.0
}

/// Data as host order 32-bit words.
fn words(d: &[u8]) -> String {
    d.chunks(4)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            format!("0x{:08x}", u32::from_ne_bytes(b))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn verdict(v: &nft::Verdict) -> String {
    match v {
        nft::Verdict::Accept => "accept".into(),
        nft::Verdict::Drop => "drop".into(),
        nft::Verdict::Continue => "continue".into(),
        nft::Verdict::Return => "return".into(),
        nft::Verdict::Break => "break".into(),
        nft::Verdict::Queue => "queue".into(),
        nft::Verdict::Jump(c) => format!("jump -> {c}"),
        nft::Verdict::Goto(c) => format!("goto -> {c}"),
        nft::Verdict::JumpId(_) => "jump".into(),
        nft::Verdict::GotoId(_) => "goto".into(),
        nft::Verdict::Other(c) => format!("unknown {c}"),
    }
}

fn base(b: PayloadBase) -> &'static str {
    match b {
        PayloadBase::LinkLayer => "link",
        PayloadBase::Network => "network",
        PayloadBase::Transport => "transport",
        PayloadBase::Inner => "inner",
        _ => "unknown",
    }
}

fn meta_key(k: nft::MetaKey) -> String {
    use nft::MetaKey::*;
    match k {
        Len => "len",
        Protocol => "protocol",
        Priority => "priority",
        Mark => "mark",
        Iif => "iif",
        Oif => "oif",
        IifName => "iifname",
        OifName => "oifname",
        IifType => "iiftype",
        OifType => "oiftype",
        SkUid => "skuid",
        SkGid => "skgid",
        NfTrace => "nftrace",
        RtClassId => "rtclassid",
        Secmark => "secmark",
        NfProto => "nfproto",
        L4Proto => "l4proto",
        BriIifName => "bri_iifname",
        BriOifName => "bri_oifname",
        PktType => "pkttype",
        Cpu => "cpu",
        IifGroup => "iifgroup",
        OifGroup => "oifgroup",
        Cgroup => "cgroup",
        Prandom => "prandom",
        Secpath => "secpath",
        IifKind => "iifkind",
        OifKind => "oifkind",
        BriIifPvid => "bri_iifpvid",
        BriIifVproto => "bri_iifvproto",
        TimeNs => "time",
        TimeDay => "day",
        TimeHour => "hour",
        Sdif => "sdif",
        SdifName => "sdifname",
        BriBroute => "bri_broute",
        Other(n) => return format!("unknown {n}"),
    }
    .into()
}

fn ct_key(k: nft::CtKey) -> String {
    use nft::CtKey::*;
    match k {
        State => "state",
        Direction => "direction",
        Status => "status",
        Mark => "mark",
        Secmark => "secmark",
        Expiration => "expiration",
        Helper => "helper",
        L3Protocol => "l3protocol",
        Src => "src",
        Dst => "dst",
        Protocol => "protocol",
        ProtoSrc => "proto_src",
        ProtoDst => "proto_dst",
        Labels => "label",
        Pkts => "packets",
        Bytes => "bytes",
        AvgPkt => "avgpkt",
        Zone => "zone",
        EventMask => "event",
        SrcIp => "src_ip",
        DstIp => "dst_ip",
        SrcIp6 => "src_ip6",
        DstIp6 => "dst_ip6",
        Id => "id",
        Other(n) => return format!("unknown {n}"),
    }
    .into()
}

fn cmp_op(op: nft::CmpOp) -> &'static str {
    match op {
        nft::CmpOp::Eq => "eq",
        nft::CmpOp::Neq => "neq",
        nft::CmpOp::Lt => "lt",
        nft::CmpOp::Lte => "lte",
        nft::CmpOp::Gt => "gt",
        nft::CmpOp::Gte => "gte",
        nft::CmpOp::Other(_) => "unknown",
    }
}

fn unit(secs: u64) -> String {
    match secs {
        1 => "second".into(),
        60 => "minute".into(),
        3600 => "hour".into(),
        86400 => "day".into(),
        604800 => "week".into(),
        n => format!("error {n}"),
    }
}

fn limit(l: &kx::Limit) -> String {
    format!(
        "limit rate {}/{} burst {} type {} flags 0x{:x}",
        l.rate,
        unit(l.unit),
        l.burst,
        if l.ty == nft::LimitType::Bytes {
            "bytes"
        } else {
            "packets"
        },
        l.flags
    )
}

/// One expression, without the surrounding brackets. `dump`: the
/// expression comes from a kernel dump (which always carries some
/// optional attributes).
pub fn expr(e: &kx::Expr, dump: bool) -> String {
    use kx::Expr as E;
    match e {
        E::Immediate(i) => match &i.data {
            Data::Verdict(v) => format!("immediate reg {} {}", reg(i.dreg), verdict(v)),
            Data::Value(d) => format!("immediate reg {} {}", reg(i.dreg), words(d)),
        },
        E::Cmp(c) => format!(
            "cmp {} reg {} {}",
            cmp_op(c.op),
            reg(c.sreg),
            words(&c.data)
        ),
        E::Payload(p) => match (p.dreg, p.sreg) {
            (Some(d), _) => format!(
                "payload load {}b @ {} header + {} => reg {}",
                p.len,
                base(p.base),
                p.offset,
                reg(d)
            ),
            (None, Some(s)) => format!(
                "payload write reg {} => {}b @ {} header + {} csum_type {} csum_off {} csum_flags 0x{:x}",
                reg(s),
                p.len,
                base(p.base),
                p.offset,
                p.csum_type.unwrap_or(0),
                p.csum_offset.unwrap_or(0),
                p.csum_flags.unwrap_or(0)
            ),
            _ => "payload".into(),
        },
        E::Meta(m) => match (m.dreg, m.sreg) {
            (Some(d), _) => format!("meta load {} => reg {}", meta_key(m.key), reg(d)),
            (None, Some(s)) => format!("meta set {} with reg {}", meta_key(m.key), reg(s)),
            _ => "meta".into(),
        },
        E::Ct(c) => {
            let dir = match c.direction {
                Some(0) => " , dir original",
                Some(1) => " , dir reply",
                _ => "",
            };
            match (c.dreg, c.sreg) {
                (Some(d), _) => format!("ct load {} => reg {}{dir}", ct_key(c.key), reg(d)),
                (None, Some(s)) => format!("ct set {} with reg {}{dir}", ct_key(c.key), reg(s)),
                _ => "ct".into(),
            }
        }
        E::Bitwise(b) => match b.op.unwrap_or(nft::BitwiseOp::MaskXor) {
            nft::BitwiseOp::Lshift | nft::BitwiseOp::Rshift => {
                let n = b
                    .data
                    .as_ref()
                    .and_then(|d| d.get(..4))
                    .map_or(0, |d| u32::from_ne_bytes(d.try_into().unwrap()));
                let op = if b.op == Some(nft::BitwiseOp::Lshift) {
                    "<<"
                } else {
                    ">>"
                };
                format!(
                    "bitwise reg {} = ( reg {} {op} 0x{n:08x} )",
                    reg(b.dreg),
                    reg(b.sreg)
                )
            }
            _ => format!(
                "bitwise reg {} = ( reg {} & {} ) ^ {}",
                reg(b.dreg),
                reg(b.sreg),
                words(b.mask.as_deref().unwrap_or(&[])),
                words(b.xor.as_deref().unwrap_or(&[]))
            ),
        },
        E::Byteorder(b) => format!(
            "byteorder reg {} = {}(reg {}, {}, {})",
            reg(b.dreg),
            if b.op == nft::ByteorderOp::Hton {
                "hton"
            } else {
                "ntoh"
            },
            reg(b.sreg),
            b.size,
            b.len
        ),
        E::Range(r) => format!(
            "range {} reg {} {} {}",
            if r.op == nft::RangeOp::Neq {
                "neq"
            } else {
                "eq"
            },
            reg(r.sreg),
            words(&r.from),
            words(&r.to)
        ),
        E::Lookup(l) => {
            let mut s = format!("lookup reg {} set {}", reg(l.sreg), l.set);
            if let Some(d) = l.dreg {
                let _ = write!(s, " dreg {}", reg(d));
            }
            if let Some(f) = l.flags {
                let _ = write!(s, " 0x{f:x}");
            }
            s
        }
        E::Dynset(d) => {
            let op = match d.op {
                nft::DynsetOp::Add => "add",
                nft::DynsetOp::Update => "update",
                nft::DynsetOp::Delete => "delete",
                nft::DynsetOp::Other(_) => "unknown",
            };
            let mut s = format!("dynset {op} reg_key {} set {}", reg(d.sreg_key), d.set_name);
            if let Some(r) = d.sreg_data {
                let _ = write!(s, " sreg_data {}", reg(r));
            }
            match d.timeout {
                Some(t) => {
                    let _ = write!(s, " timeout {}ms", t.as_millis());
                }
                // The kernel always reports a timeout.
                None if dump => s.push_str(" timeout 0ms"),
                None => {}
            }
            for x in &d.exprs {
                let _ = write!(s, " expr [ {} ]", expr(x, dump));
            }
            s
        }
        E::Counter(c) => format!("counter pkts {} bytes {}", c.packets, c.bytes),
        E::Limit(l) => limit(l),
        E::Quota(q) => format!(
            "quota bytes {} consumed {} flags {}",
            q.bytes,
            q.consumed.unwrap_or(0),
            q.flags
        ),
        E::Connlimit(c) => format!("connlimit count {} flags {}", c.count, c.flags),
        E::Last(l) => match (l.set, l.msecs) {
            (Some(1), Some(ms)) => format!("last {ms}"),
            _ => "last never".into(),
        },
        E::Log(l) => {
            let mut s = String::from("log ");
            if let Some(p) = &l.prefix {
                let _ = write!(s, "prefix {p} ");
            }
            if let Some(g) = l.group {
                let _ = write!(
                    s,
                    "group {g} snaplen {} qthreshold {} ",
                    l.snaplen.unwrap_or(0),
                    l.qthreshold.unwrap_or(0)
                );
            } else if let Some(lv) = l.level {
                let _ = write!(s, "level {} ", lv.raw());
            }
            let f = l.flags.unwrap_or(0);
            for (bit, name) in [
                (NF_LOG_TCPSEQ, "tcpseq"),
                (NF_LOG_TCPOPT, "tcpopt"),
                (NF_LOG_IPOPT, "ipopt"),
                (NF_LOG_UID, "uid"),
                (NF_LOG_MACDECODE, "macdecode"),
            ] {
                if f & bit != 0 {
                    let _ = write!(s, "{name} ");
                }
            }
            s.trim_end().to_owned()
        }
        E::Objref(o) => match (&o.imm_name, &o.set_name) {
            (Some(n), _) => format!("objref type {} name {n}", o.imm_type.map_or(0, |t| t.raw())),
            (None, Some(set)) => format!("objref sreg {} set {set}", o.set_sreg.map_or(0, reg)),
            _ => "objref".into(),
        },
        E::Reject(r) => format!(
            "reject type {} code {}",
            r.ty.raw(),
            r.icmp_code.unwrap_or(0)
        ),
        E::Nat(n) => {
            let mut s = format!(
                "nat {} {}",
                if n.ty == nft::NatType::Snat {
                    "snat"
                } else {
                    "dnat"
                },
                match n.family {
                    2 => "ip",
                    10 => "ip6",
                    1 => "inet",
                    _ => "unknown",
                }
            );
            for (name, r) in [
                ("addr_min", n.reg_addr_min),
                ("addr_max", n.reg_addr_max),
                ("proto_min", n.reg_proto_min),
                ("proto_max", n.reg_proto_max),
            ] {
                if let Some(r) = r {
                    let _ = write!(s, " {name} reg {}", reg(r));
                }
            }
            if let Some(f) = n.flags {
                let _ = write!(s, " flags 0x{f:x}");
            }
            s
        }
        E::Masq(m) => {
            let mut s = String::from("masq");
            if let Some(a) = m.reg_proto_min {
                let _ = write!(s, " proto_min reg {}", reg(a));
            }
            if let Some(b) = m.reg_proto_max {
                let _ = write!(s, " proto_max reg {}", reg(b));
            }
            if let Some(f) = m.flags {
                let _ = write!(s, " flags 0x{f:x}");
            }
            s
        }
        E::Redir(r) => {
            let mut s = String::from("redir");
            if let Some(a) = r.reg_proto_min {
                let _ = write!(s, " proto_min reg {}", reg(a));
            }
            if let Some(b) = r.reg_proto_max {
                let _ = write!(s, " proto_max reg {}", reg(b));
            }
            if let Some(f) = r.flags {
                let _ = write!(s, " flags 0x{f:x}");
            }
            s
        }
        E::Queue(q) => match q.sreg_qnum {
            Some(r) => format!("queue sreg_qnum {}{}", reg(r), queue_flags(q.flags)),
            None => {
                let n = q.num.unwrap_or(0);
                let t = q.total.unwrap_or(1);
                if t > 1 {
                    format!("queue num {n}-{}{}", n + t - 1, queue_flags(q.flags))
                } else {
                    format!("queue num {n}{}", queue_flags(q.flags))
                }
            }
        },
        E::Dup(d) => {
            let mut s = String::from("dup");
            if let Some(a) = d.sreg_addr {
                let _ = write!(s, " sreg_addr {}", reg(a));
            }
            if let Some(b) = d.sreg_dev {
                let _ = write!(s, " sreg_dev {}", reg(b));
            }
            s
        }
        E::Fwd(f) => {
            let mut s = String::from("fwd");
            if let Some(d) = f.sreg_dev {
                let _ = write!(s, " sreg_dev {}", reg(d));
            }
            if let Some(a) = f.sreg_addr {
                let _ = write!(
                    s,
                    " sreg_addr {} nfproto {}",
                    reg(a),
                    f.nfproto.unwrap_or(0)
                );
            }
            s
        }
        E::Notrack(_) => "notrack".into(),
        E::FlowOffload(f) => format!("flow_offload flowtable {}", f.table_name),
        E::Tproxy(t) => {
            let mut s = format!(
                "tproxy {}",
                match t.family {
                    2 => "ip",
                    10 => "ip6",
                    _ => "inet",
                }
            );
            if let Some(a) = t.reg_addr {
                let _ = write!(s, " addr reg {}", reg(a));
            }
            if let Some(p) = t.reg_port {
                let _ = write!(s, " port reg {}", reg(p));
            }
            s
        }
        E::Synproxy(sp) => format!(
            "synproxy mss {} wscale {}",
            sp.mss.unwrap_or(0),
            sp.wscale.unwrap_or(0)
        ),
        E::Numgen(n) => {
            let mut s = format!(
                "numgen reg {} = {} mod {}",
                reg(n.dreg),
                if n.ty == nft::NumgenType::Random {
                    "random"
                } else {
                    "inc"
                },
                n.modulus
            );
            if let Some(o) = n.offset.filter(|o| *o != 0) {
                let _ = write!(s, " offset {o}");
            }
            s
        }
        E::Hash(h) => {
            let mut s = if h.ty == Some(nft::HashType::Symmetric) {
                format!("hash reg {} = symhash() % mod {}", reg(h.dreg), h.modulus)
            } else {
                format!(
                    "hash reg {} = jhash(reg {}, {}, 0x{:x}) % mod {}",
                    reg(h.dreg),
                    h.sreg.map_or(0, reg),
                    h.len.unwrap_or(0),
                    h.seed.unwrap_or(0),
                    h.modulus
                )
            };
            if let Some(o) = h.offset.filter(|o| *o != 0) {
                let _ = write!(s, " offset {o}");
            }
            s
        }
        E::Fib(f) => {
            let mut flags = Vec::new();
            for (bit, name) in [
                (NFTA_FIB_F_SADDR, "saddr"),
                (NFTA_FIB_F_DADDR, "daddr"),
                (NFTA_FIB_F_MARK, "mark"),
                (NFTA_FIB_F_IIF, "iif"),
                (NFTA_FIB_F_OIF, "oif"),
            ] {
                if f.flags & bit != 0 {
                    flags.push(name);
                }
            }
            let result = match f.result {
                nft::FibResult::Oif => "oif",
                nft::FibResult::OifName => "oifname",
                nft::FibResult::AddrType => "type",
                nft::FibResult::Other(_) => "unknown",
            };
            let present = if f.flags & NFTA_FIB_F_PRESENT != 0 {
                " present"
            } else {
                ""
            };
            format!(
                "fib {} {result}{present} => reg {}",
                flags.join(" . "),
                reg(f.dreg)
            )
        }
        E::Exthdr(x) => {
            let op = match x.op {
                Some(nft::ExthdrOp::TcpOpt) => "tcpopt ",
                Some(nft::ExthdrOp::Ipv4) => "ipv4 ",
                Some(nft::ExthdrOp::Ipv6) => "ipv6 ",
                _ => "",
            };
            let present = if x.flags.unwrap_or(0) & NFT_EXTHDR_F_PRESENT != 0 {
                " present"
            } else {
                ""
            };
            match (x.dreg, x.sreg) {
                (Some(d), _) => format!(
                    "exthdr load {op}{}b @ {} + {}{present} => reg {}",
                    x.len,
                    x.ty,
                    x.offset,
                    reg(d)
                ),
                (None, Some(s)) => format!(
                    "exthdr write {op}reg {} => {}b @ {} + {}",
                    reg(s),
                    x.len,
                    x.ty,
                    x.offset
                ),
                _ => "exthdr".into(),
            }
        }
        E::SocketLookup(s) => {
            let key = match s.key {
                nft::SocketKey::Transparent => "transparent",
                nft::SocketKey::Mark => "mark",
                nft::SocketKey::Wildcard => "wildcard",
                nft::SocketKey::CgroupV2 => "cgroupv2",
                nft::SocketKey::Other(_) => "unknown",
            };
            format!("socket load {key} => reg {}", reg(s.dreg))
        }
        E::Rt(r) => {
            let key = match r.key {
                nft::RtKey::ClassId => "classid",
                nft::RtKey::Nexthop4 => "nexthop4",
                nft::RtKey::Nexthop6 => "nexthop6",
                nft::RtKey::TcpMss => "tcpmss",
                nft::RtKey::Xfrm => "ipsec",
                nft::RtKey::Other(_) => "unknown",
            };
            format!("rt load {key} => reg {}", reg(r.dreg))
        }
        E::Osf(o) => format!("osf dreg {}", reg(o.dreg)),
        E::Xfrm(x) => {
            let key = match x.key {
                1 => "daddr4",
                2 => "daddr6",
                3 => "saddr4",
                4 => "saddr6",
                5 => "reqid",
                6 => "spi",
                _ => "unknown",
            };
            format!(
                "xfrm load {} {} {key} => reg {}",
                if x.dir == 0 { "in" } else { "out" },
                x.spnum,
                reg(x.dreg)
            )
        }
        E::Tunnel(t) => format!("tunnel key {} dreg {}", t.key, reg(t.dreg)),
        E::Unknown(u) => format!("{} (unknown)", u.name),
    }
}

fn queue_flags(f: Option<u16>) -> String {
    let f = f.unwrap_or(0);
    let mut s = String::new();
    if f & NFT_QUEUE_FLAG_BYPASS != 0 {
        s.push_str(" bypass");
    }
    if f & NFT_QUEUE_FLAG_CPU_FANOUT != 0 {
        s.push_str(" fanout");
    }
    s
}

fn family(f: Family) -> &'static str {
    match f {
        Family::Ipv4 => "ip",
        Family::Ipv6 => "ip6",
        Family::Inet => "inet",
        Family::Arp => "arp",
        Family::Bridge => "bridge",
        Family::Netdev => "netdev",
        _ => "unknown",
    }
}

fn userdata(u: &[u8]) -> String {
    let mut s = String::from("  userdata = { ");
    for b in u {
        if b.is_ascii_graphic() || *b == b' ' {
            s.push(*b as char);
        } else {
            let _ = write!(s, "\\x{b:02x}");
        }
    }
    s.push_str(" }");
    s
}

/// A rule: a header line (with handle and position from a dump) and its
/// expressions.
pub fn rule(r: &nft::Rule, dump: bool) -> String {
    let mut s = format!("{} {}", family(r.family), r.table);
    if !r.chain.is_empty() {
        let _ = write!(s, " {}", r.chain);
    }
    if let Some(h) = r.handle {
        let _ = write!(s, " {h}");
        if let Some(p) = r.position {
            let _ = write!(s, " {p}");
        }
    }
    s.push('\n');
    for e in &r.exprs {
        let _ = writeln!(s, "  [ {} ]", expr(e, dump));
    }
    if let Some(u) = &r.userdata {
        let _ = writeln!(s, "{}", userdata(u));
    }
    s
}

fn element(e: &nft::SetElem) -> String {
    let mut s = String::from("\telement ");
    if let Some(k) = &e.key {
        s.push_str(&words(k).replace("0x", ""));
        s.push(' ');
    }
    if let Some(k) = &e.key_end {
        let _ = write!(s, " - {} ", words(k).replace("0x", ""));
    }
    s.push_str(" : ");
    match (&e.data, &e.objref) {
        (Some(Data::Verdict(v)), _) => {
            let _ = write!(s, "{} ", verdict(v));
        }
        (Some(Data::Value(d)), _) => {
            let _ = write!(s, "{} ", words(d).replace("0x", ""));
        }
        _ => {}
    }
    let _ = write!(s, "{} [end]", e.flags.unwrap_or(0));
    if let Some(u) = &e.userdata {
        s.push_str(&userdata(u));
    }
    s
}

/// The elements of a set from a dump: `family table @set` and one line
/// per element.
pub fn set_elements(s: &nft::Set, elems: &[nft::SetElem]) -> String {
    let mut out = format!("{} {} @{}\n", family(s.family), s.table, s.name);
    for e in elems {
        out.push_str(&element(e));
        out.push('\n');
    }
    out
}

/// A batch's objects, as `nft --debug=netlink` prints them when sending
/// them.
pub fn batch(b: &nft::Batch) -> String {
    let mut out = String::new();
    // Deletions are not printed, except of elements.
    for (_, obj) in b
        .objects()
        .into_iter()
        .filter(|(new, o)| *new || matches!(o, Object::SetElems(_)))
    {
        match obj {
            Object::Chain(c) => {
                let name = if c.name.is_empty() { "(null)" } else { &c.name };
                let _ = writeln!(out, "{} {} {name} use 0", family(c.family), c.table);
            }
            Object::Rule(r) => out.push_str(&rule(&r, false)),
            Object::Set(s) => {
                let _ = write!(out, "{} {} {:x}", s.name, s.table, s.flags);
                if let Some(t) = s.timeout {
                    let _ = write!(out, " timeout {}ms", t.as_millis());
                }
                if let Some(g) = s.gc_interval {
                    let _ = write!(out, " gc_interval {g}ms");
                }
                if let Some(p) = s.policy {
                    let _ = write!(out, " policy {p}");
                }
                if let Some(n) = s.size {
                    let _ = write!(out, " size {n}");
                }
                out.push('\n');
            }
            Object::SetElems(l) => {
                let _ = writeln!(out, "{} {} 0", l.set, l.table);
                for e in &l.elems {
                    out.push_str(&element(e));
                }
                out.push('\n');
            }
            Object::Obj(o) => {
                let k = obj_kind(&o.kind);
                // libnftnl closes the timeout policy without a space.
                let close = if k.ends_with(']') { "" } else { " ]" };
                let _ = writeln!(out, "table (null) name (null) use 0 [ {k}{close}");
            }
            Object::Flowtable(f) => {
                let _ = writeln!(
                    out,
                    "flow table (null) (null) use 0 size 0 flags {:x}",
                    f.flags.unwrap_or(0)
                );
            }
            _ => {}
        }
    }
    out
}

fn obj_kind(k: &nft::ObjKind) -> String {
    match k {
        nft::ObjKind::Counter(c) => format!("counter pkts {} bytes {}", c.packets, c.bytes),
        nft::ObjKind::Quota(q) => format!("quota bytes {} flags {}", q.bytes, q.flags),
        nft::ObjKind::Limit(l) => format!(
            "limit rate {} unit {} burst {} type {} flags {}",
            l.rate,
            l.unit,
            l.burst,
            l.ty.raw(),
            l.flags
        ),
        nft::ObjKind::CtHelper(h) => format!(
            "ct_helper name {} family {} protocol {}",
            h.name,
            h.l3proto.unwrap_or(0),
            h.l4proto
        ),
        nft::ObjKind::CtTimeout(t) => {
            let names = super::decompile::timeout_states(t.l4proto);
            let mut p = String::new();
            for (attr, v) in t.policy() {
                let name = names
                    .get((attr as usize).wrapping_sub(1))
                    .map_or_else(|| attr.to_string(), |(n, _)| n.to_uppercase());
                let _ = write!(p, "{name} = {v},");
            }
            format!(
                "ct_timeout family {} protocol {} policy = {{{p}}}]",
                t.l3proto.unwrap_or(0),
                t.l4proto
            )
        }
        nft::ObjKind::CtExpect(e) => format!(
            "ct_expect family {} protocol {} dport {} timeout {} size {}",
            e.l3proto.unwrap_or(0),
            e.l4proto,
            e.dport,
            e.timeout,
            e.size
        ),
        nft::ObjKind::Synproxy(s) => format!(
            "synproxy mss {} wscale {}",
            s.mss.unwrap_or(0),
            s.wscale.unwrap_or(0)
        ),
        nft::ObjKind::Secmark(s) => format!("secmark {}", s.ctx),
        _ => "unknown".into(),
    }
}

/// A ruleset dump, as `nft --debug=netlink list ...` prints it before the
/// listing: for each table, its set elements, then its rules.
pub fn ruleset(rs: &nft::Ruleset) -> String {
    let mut out = String::new();
    let mut tables: Vec<(Family, &str)> = rs
        .tables
        .iter()
        .map(|t| (t.family, t.name.as_str()))
        .collect();
    // Objects of tables missing from the dump still print, at the end.
    for (f, t) in rs
        .sets
        .iter()
        .map(|(s, _)| (s.family, s.table.as_str()))
        .chain(rs.rules.iter().map(|r| (r.family, r.table.as_str())))
    {
        if !tables.contains(&(f, t)) {
            tables.push((f, t));
        }
    }
    for (f, t) in tables {
        for (s, elems) in rs
            .sets
            .iter()
            .filter(|(s, _)| s.family == f && s.table == t)
        {
            out.push_str(&set_elements(s, elems));
        }
        for r in rs.rules.iter().filter(|r| r.family == f && r.table == t) {
            out.push_str(&rule(r, true));
        }
    }
    out
}
