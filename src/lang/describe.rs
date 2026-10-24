//! `describe`: the type of an expression, as `nft describe` prints it.

use std::fmt::Write;

use super::ast::Expr;
use super::datatype::{self, Kind, Symbols, id};
use super::error::{Error, Result};
use super::proto;

/// Description, base type and symbol table of a type (as nft shows them).
pub(crate) fn type_info(ty: u32, time_of_packet: bool) -> (&'static str, &'static str) {
    match ty {
        id::INVALID => ("invalid", ""),
        id::INTEGER => ("integer", ""),
        id::STRING => ("string", ""),
        id::IPADDR => ("IPv4 address", "integer"),
        id::IP6ADDR => ("IPv6 address", "integer"),
        id::ETHERADDR => ("Ethernet address", "link layer address, integer"),
        id::ETHERTYPE => ("Ethernet protocol", "integer"),
        id::ARPOP => ("ARP operation", "integer"),
        id::INET_PROTOCOL => ("Internet protocol", "integer"),
        id::INET_SERVICE => ("internet network service", "integer"),
        id::ICMP_TYPE => ("ICMP type", "integer"),
        id::TCP_FLAG => ("TCP flag", "bitmask, integer"),
        id::DCCP_PKTTYPE => ("DCCP packet type", "integer"),
        id::MH_TYPE => ("Mobility Header Type", "integer"),
        id::TIME => ("relative time", "integer"),
        id::MARK => ("packet mark", "integer"),
        id::IFINDEX => ("network interface index", "integer"),
        id::ARPHRD => ("network interface type", "integer"),
        id::REALM => ("routing realm", "integer"),
        id::CLASSID => ("TC classid", "integer"),
        id::UID => ("user ID", "integer"),
        id::GID => ("group ID", "integer"),
        id::CT_STATE => ("conntrack state", "bitmask, integer"),
        id::CT_DIR => ("conntrack direction", "integer"),
        id::CT_STATUS => ("conntrack status", "bitmask, integer"),
        id::ICMP6_TYPE => ("ICMPv6 type", "integer"),
        id::CT_LABEL => ("conntrack label", "bitmask, integer"),
        id::PKTTYPE => ("packet type", "integer"),
        id::ICMP_CODE => ("icmp code", "integer"),
        id::ICMPV6_CODE => ("icmpv6 code", "integer"),
        id::ICMPX_CODE => ("icmpx code", "integer"),
        id::DEVGROUP => ("devgroup name", "integer"),
        id::DSCP => ("Differentiated Services Code Point", "integer"),
        id::ECN => ("Explicit Congestion Notification", "integer"),
        id::FIB_ADDR => ("fib address type", "integer"),
        id::BOOLEAN => ("boolean type", "integer"),
        id::CT_EVENTBIT => ("conntrack event bits", "bitmask, integer"),
        id::IFNAME => ("network interface name", "string"),
        id::IGMP_TYPE => ("IGMP type", "integer"),
        id::TIME_DATE if time_of_packet => ("Relative time of packet reception", "integer"),
        id::TIME_DATE => ("relative time", "integer"),
        id::TIME_HOUR => ("Hour of day of packet reception", "integer"),
        id::TIME_DAY => ("Day of week of packet reception", "integer"),
        id::CGROUPV2 => ("cgroupsv2 path", "integer"),
        id::NFPROTO => ("netfilter protocol", "integer"),
        id::MPTCP_SUBTYPE => ("mptcp option subtype", "integer"),
        _ => ("integer", ""),
    }
}

/// Symbols listed by `describe`, in nft's order, and whether they are
/// shown in hexadecimal.
fn symbols(ty: u32) -> Option<(Vec<(String, u64)>, bool)> {
    fn own(s: Symbols) -> Vec<(String, u64)> {
        s.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect()
    }
    let t = datatype::by_id(ty);
    let syms = match t.kind {
        Kind::SymDec(s) | Kind::SymHex(s, _) | Kind::Flags(s) => own(s),
        Kind::Day => datatype::DAYS
            .iter()
            .enumerate()
            .map(|(i, d)| ((*d).to_owned(), i as u64))
            .collect(),
        Kind::Boolean => vec![("exists".into(), 1), ("missing".into(), 0)],
        Kind::IpRoute2(file) => datatype::iproute2_names(file).to_vec(),
        _ => return None,
    };
    let syms = match ty {
        // nft lists conntrack states in this order.
        id::CT_STATE => ["invalid", "new", "established", "related", "untracked"]
            .iter()
            .filter_map(|n| syms.iter().find(|(s, _)| s == n).cloned())
            .collect(),
        // ICMP codes are not listed.
        id::ICMP_CODE | id::ICMPV6_CODE | id::ICMPX_CODE => return None,
        _ => syms,
    };
    let hex = matches!(
        ty,
        id::ETHERTYPE
            | id::ARPHRD
            | id::CT_STATE
            | id::CT_STATUS
            | id::CT_EVENTBIT
            | id::TCP_FLAG
            | id::DSCP
            | id::ECN
            | id::ARPOP
            | id::DCCP_PKTTYPE
    );
    Some((syms, hex))
}

/// Kind, type and size in bits of an expression.
fn expr_type(e: &Expr) -> Result<(&'static str, u32, u32)> {
    Ok(match e {
        Expr::Payload { proto: p, field } => {
            let pr = proto::proto(p).ok_or_else(|| Error::msg(format!("unknown protocol {p}")))?;
            let (_, f) = pr
                .field(field)
                .ok_or_else(|| Error::msg(format!("unknown field {p} {field}")))?;
            ("payload", f.ty, f.len)
        }
        Expr::Raw { base, offset, len } => {
            // A raw transport header range matching a `th` field has its type.
            let th = proto::proto("th").unwrap();
            match th
                .fields
                .iter()
                .find(|f| base == "th" && f.offset == *offset && f.len == *len)
            {
                Some(f) => ("payload", f.ty, f.len),
                None => ("payload", id::INTEGER, *len),
            }
        }
        Expr::Meta(k) => {
            let m = proto::meta(k).ok_or_else(|| Error::msg(format!("unknown meta key {k}")))?;
            let bits = match k.as_str() {
                "nftrace" | "broute" => 1,
                _ => m.len * 8,
            };
            ("meta", m.ty, bits)
        }
        Expr::Ct { key, .. } => {
            let c = proto::ct(key).ok_or_else(|| Error::msg(format!("unknown ct key {key}")))?;
            ("ct", c.ty, c.len * 8)
        }
        Expr::Exthdr {
            desc,
            field,
            exists,
        } => {
            if *exists || field.is_none() {
                ("exthdr", id::BOOLEAN, 1)
            } else {
                let (_, ty, bits) = super::compile::exthdr_field(desc, field.as_deref().unwrap())?;
                ("exthdr", ty, bits)
            }
        }
        Expr::Fib { result, .. } => match result.as_str() {
            "oif" => ("fib", id::IFINDEX, 32),
            "oifname" => ("fib", id::IFNAME, 128),
            _ => ("fib", id::FIB_ADDR, 32),
        },
        Expr::Osf { .. } => ("osf", id::STRING, 128),
        Expr::Socket { key, .. } => match key.as_str() {
            "mark" => ("socket", id::MARK, 32),
            "cgroupv2" => ("socket", id::CGROUPV2, 64),
            _ => ("socket", id::INTEGER, 8),
        },
        Expr::Rt(k) => match k.as_str() {
            "classid" => ("rt", id::REALM, 32),
            "mtu" => ("rt", id::INTEGER, 16),
            "ipsec" => ("rt", id::BOOLEAN, 8),
            "ip6 nexthop" => ("rt", id::IP6ADDR, 128),
            _ => ("rt", id::IPADDR, 32),
        },
        Expr::Numgen { .. } => ("numgen", id::INTEGER, 32),
        Expr::Hash { .. } => ("hash", id::INTEGER, 32),
        Expr::Ipsec { key, .. } => match key.as_str() {
            "ip saddr" | "ip daddr" => ("xfrm", id::IPADDR, 32),
            "ip6 saddr" | "ip6 daddr" => ("xfrm", id::IP6ADDR, 128),
            _ => ("xfrm", id::INTEGER, 32),
        },
        _ => return Err(Error::msg("syntax error, unexpected expression")),
    })
}

/// `nft describe <expr>`.
pub fn describe(e: &Expr) -> Result<String> {
    let (kind, ty, bits) = expr_type(e)?;
    let t = datatype::by_id(ty);
    let time_of_packet = matches!(e, Expr::Meta(k) if k == "time");
    let (desc, base) = type_info(ty, time_of_packet);
    // The mptcp subtype is an integer type with its own description.
    let name = if ty == id::MPTCP_SUBTYPE {
        "integer"
    } else {
        t.name
    };
    let mut out = format!("{kind} expression, datatype {name} ({desc})");
    if ty == id::INVALID {
        out.push('\n');
        return Ok(out);
    }
    if !base.is_empty() {
        let _ = write!(out, " (basetype {base})");
    }
    if matches!(t.kind, Kind::Str) {
        let _ = writeln!(out, ", {} characters", bits / 8);
    } else {
        let _ = writeln!(out, ", {bits} bits");
    }
    if ty == id::INET_PROTOCOL {
        // The first name of each protocol number up to 255.
        let mut seen = std::collections::HashSet::new();
        for (name, n) in datatype::protocol_table() {
            if *n <= 255 && seen.insert(*n) {
                let _ = writeln!(out, "\t{name:<30}\t{n}");
            }
        }
        return Ok(out);
    }
    if let Some((syms, hex)) = symbols(ty) {
        let from = match t.kind {
            Kind::IpRoute2(file) => format!(" from {}", datatype::iproute2_path(file)),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "\npre-defined symbolic constants{from} (in {}):",
            if hex { "hexadecimal" } else { "decimal" }
        );
        let width = t.bits.div_ceil(8) as usize * 2;
        for (name, v) in syms {
            if hex {
                let _ = writeln!(out, "\t{name:<30}\t0x{v:0width$x}");
            } else {
                let _ = writeln!(out, "\t{name:<30}\t{v:>20}");
            }
        }
    }
    Ok(out)
}
