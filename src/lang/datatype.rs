//! nft data types: parsing and printing of values.
//!
//! Values are kept as the bytes the kernel compares, in the byte order of
//! the type (network order for addresses and ports, host order for marks,
//! interface indexes and other metadata).

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::error::{Error, Result};

/// Byte order of a type's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Network byte order (big endian).
    Big,
    /// Host byte order.
    Host,
}

/// Symbolic constants of a type.
pub type Symbols = &'static [(&'static str, u64)];

/// How values of a type are printed and parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Decimal integer.
    Integer,
    /// Hexadecimal integer, zero padded to `width` digits (0 = no padding).
    Hex(usize),
    /// Symbolic constants; other values printed in decimal.
    SymDec(Symbols),
    /// Symbolic constants; other values printed as zero padded hex.
    SymHex(Symbols, usize),
    /// A bit mask of symbolic flags.
    Flags(Symbols),
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// Link layer (MAC) address.
    Ether,
    /// NUL padded string (`"lo"`).
    Str,
    /// Verdict.
    Verdict,
    /// Relative time in milliseconds (`1m30s`).
    Duration,
    /// Interface index, printed as a name.
    Ifindex,
    /// Traffic control class id (`1:2`).
    Classid,
    /// Day of the week.
    Day,
    /// Seconds since midnight (`"17:00"`).
    Hour,
    /// Nanoseconds since the epoch (`"2023-11-14 22:13:20"`).
    Date,
    /// Boolean (`exists` / `missing`).
    Boolean,
    /// Conntrack label bit.
    Label,
    /// IP protocol numbers (names from `/etc/protocols`).
    Protocol,
    /// Integers with names from an iproute2 table (`group`, `rt_realms`).
    IpRoute2(&'static str),
}

/// An nft data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Type {
    /// Type id stored in set key types.
    pub id: u32,
    /// Name (`ipv4_addr`).
    pub name: &'static str,
    /// Size in bits (0 for variable / concatenations).
    pub bits: u32,
    /// Byte order.
    pub order: Order,
    /// Printing/parsing behaviour.
    pub kind: Kind,
}

impl Type {
    /// Size in bytes (register storage).
    pub fn bytes(&self) -> u32 {
        self.bits.div_ceil(8)
    }
}

macro_rules! ty {
    ($id:expr, $name:expr, $bits:expr, $order:ident, $kind:expr) => {
        Type {
            id: $id,
            name: $name,
            bits: $bits,
            order: Order::$order,
            kind: $kind,
        }
    };
}

pub(crate) const ETHER_TYPES: Symbols = &[
    ("ip", 0x0800),
    ("arp", 0x0806),
    ("ip6", 0x86dd),
    ("8021q", 0x8100),
    ("8021ad", 0x88a8),
    ("vlan", 0x8100),
];
const ARP_OPS: Symbols = &[
    ("request", 1),
    ("reply", 2),
    ("rrequest", 3),
    ("rreply", 4),
    ("inrequest", 8),
    ("inreply", 9),
    ("nak", 10),
];
const ICMP_TYPES: Symbols = &[
    ("echo-reply", 0),
    ("destination-unreachable", 3),
    ("source-quench", 4),
    ("redirect", 5),
    ("echo-request", 8),
    ("router-advertisement", 9),
    ("router-solicitation", 10),
    ("time-exceeded", 11),
    ("parameter-problem", 12),
    ("timestamp-request", 13),
    ("timestamp-reply", 14),
    ("info-request", 15),
    ("info-reply", 16),
    ("address-mask-request", 17),
    ("address-mask-reply", 18),
];
const ICMP6_TYPES: Symbols = &[
    ("destination-unreachable", 1),
    ("packet-too-big", 2),
    ("time-exceeded", 3),
    ("parameter-problem", 4),
    ("echo-request", 128),
    ("echo-reply", 129),
    ("mld-listener-query", 130),
    ("mld-listener-report", 131),
    ("mld-listener-done", 132),
    ("mld-listener-reduction", 132),
    ("nd-router-solicit", 133),
    ("nd-router-advert", 134),
    ("nd-neighbor-solicit", 135),
    ("nd-neighbor-advert", 136),
    ("nd-redirect", 137),
    ("router-renumbering", 138),
    ("ind-neighbor-solicit", 141),
    ("ind-neighbor-advert", 142),
    ("mld2-listener-report", 143),
];
const TCP_FLAGS: Symbols = &[
    ("fin", 1),
    ("syn", 2),
    ("rst", 4),
    ("psh", 8),
    ("ack", 16),
    ("urg", 32),
    ("ecn", 64),
    ("cwr", 128),
];
const CT_STATES: Symbols = &[
    ("invalid", 1),
    ("established", 2),
    ("related", 4),
    ("new", 8),
    ("untracked", 64),
];
const CT_DIRS: Symbols = &[("original", 0), ("reply", 1)];
const CT_STATUS: Symbols = &[
    ("expected", 1),
    ("seen-reply", 2),
    ("assured", 4),
    ("confirmed", 8),
    ("snat", 16),
    ("dnat", 32),
    ("dying", 512),
];
const CT_EVENTS: Symbols = &[
    ("new", 1),
    ("related", 2),
    ("destroy", 4),
    ("reply", 8),
    ("assured", 16),
    ("protoinfo", 32),
    ("helper", 64),
    ("mark", 128),
    ("seqadj", 256),
    ("secmark", 512),
    ("label", 1024),
];
const PKT_TYPES: Symbols = &[
    ("host", 0),
    ("unicast", 0),
    ("broadcast", 1),
    ("multicast", 2),
    ("other", 3),
];
const ICMP_CODES: Symbols = &[
    ("net-unreachable", 0),
    ("host-unreachable", 1),
    ("prot-unreachable", 2),
    ("port-unreachable", 3),
    ("frag-needed", 4),
    ("net-prohibited", 9),
    ("host-prohibited", 10),
    ("admin-prohibited", 13),
];
const ICMP6_CODES: Symbols = &[
    ("no-route", 0),
    ("admin-prohibited", 1),
    ("addr-unreachable", 3),
    ("port-unreachable", 4),
    ("policy-fail", 5),
    ("reject-route", 6),
];
pub(crate) const ICMPX_CODES: Symbols = &[
    ("no-route", 0),
    ("port-unreachable", 1),
    ("host-unreachable", 2),
    ("admin-prohibited", 3),
];
const DSCP: Symbols = &[
    ("cs0", 0x00),
    ("cs1", 0x08),
    ("cs2", 0x10),
    ("cs3", 0x18),
    ("cs4", 0x20),
    ("cs5", 0x28),
    ("cs6", 0x30),
    ("cs7", 0x38),
    ("df", 0x00),
    ("be", 0x00),
    ("lephb", 0x01),
    ("af11", 0x0a),
    ("af12", 0x0c),
    ("af13", 0x0e),
    ("af21", 0x12),
    ("af22", 0x14),
    ("af23", 0x16),
    ("af31", 0x1a),
    ("af32", 0x1c),
    ("af33", 0x1e),
    ("af41", 0x22),
    ("af42", 0x24),
    ("af43", 0x26),
    ("va", 0x2c),
    ("ef", 0x2e),
];
const ECN: Symbols = &[("not-ect", 0), ("ect1", 1), ("ect0", 2), ("ce", 3)];
const FIB_ADDRTYPES: Symbols = &[
    ("unspec", 0),
    ("unicast", 1),
    ("local", 2),
    ("broadcast", 3),
    ("anycast", 4),
    ("multicast", 5),
    ("blackhole", 6),
    ("unreachable", 7),
    ("prohibit", 8),
];
const IFACE_TYPES: Symbols = &[
    ("ether", 1),
    ("ppp", 512),
    ("ipip", 768),
    ("ipip6", 769),
    ("loopback", 772),
    ("sit", 776),
    ("ipgre", 778),
];
const NFPROTOS: Symbols = &[("ipv4", 2), ("ipv6", 10)];
const IGMP_TYPES: Symbols = &[
    ("membership-query", 0x11),
    ("membership-report-v1", 0x12),
    ("membership-report-v2", 0x16),
    ("membership-report-v3", 0x22),
    ("leave-group", 0x17),
];
const DCCP_TYPES: Symbols = &[
    ("request", 0),
    ("response", 1),
    ("data", 2),
    ("ack", 3),
    ("dataack", 4),
    ("closereq", 5),
    ("close", 6),
    ("reset", 7),
    ("sync", 8),
    ("syncack", 9),
];
const MH_TYPES: Symbols = &[
    ("binding-refresh-request", 0),
    ("home-test-init", 1),
    ("careof-test-init", 2),
    ("home-test", 3),
    ("careof-test", 4),
    ("binding-update", 5),
    ("binding-acknowledgement", 6),
    ("binding-error", 7),
    ("fast-binding-update", 8),
    ("fast-binding-acknowledgement", 9),
    ("fast-binding-advertisement", 10),
    ("experimental-mobility-header", 11),
    ("home-agent-switch-message", 12),
];
const MPTCP_SUBTYPES: Symbols = &[
    ("mp-capable", 0),
    ("mp-join", 1),
    ("dss", 2),
    ("add-addr", 3),
    ("remove-addr", 4),
    ("mp-prio", 5),
    ("mp-fail", 6),
    ("mp-fastclose", 7),
    ("mp-tcprst", 8),
];
pub(crate) const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// Type ids.
pub mod id {
    #![allow(missing_docs)]
    pub const INVALID: u32 = 0;
    pub const VERDICT: u32 = 1;
    pub const NFPROTO: u32 = 2;
    pub const BITMASK: u32 = 3;
    pub const INTEGER: u32 = 4;
    pub const STRING: u32 = 5;
    pub const LLADDR: u32 = 6;
    pub const IPADDR: u32 = 7;
    pub const IP6ADDR: u32 = 8;
    pub const ETHERADDR: u32 = 9;
    pub const ETHERTYPE: u32 = 10;
    pub const ARPOP: u32 = 11;
    pub const INET_PROTOCOL: u32 = 12;
    pub const INET_SERVICE: u32 = 13;
    pub const ICMP_TYPE: u32 = 14;
    pub const TCP_FLAG: u32 = 15;
    pub const DCCP_PKTTYPE: u32 = 16;
    pub const MH_TYPE: u32 = 17;
    pub const TIME: u32 = 18;
    pub const MARK: u32 = 19;
    pub const IFINDEX: u32 = 20;
    pub const ARPHRD: u32 = 21;
    pub const REALM: u32 = 22;
    pub const CLASSID: u32 = 23;
    pub const UID: u32 = 24;
    pub const GID: u32 = 25;
    pub const CT_STATE: u32 = 26;
    pub const CT_DIR: u32 = 27;
    pub const CT_STATUS: u32 = 28;
    pub const ICMP6_TYPE: u32 = 29;
    pub const CT_LABEL: u32 = 30;
    pub const PKTTYPE: u32 = 31;
    pub const ICMP_CODE: u32 = 32;
    pub const ICMPV6_CODE: u32 = 33;
    pub const ICMPX_CODE: u32 = 34;
    pub const DEVGROUP: u32 = 35;
    pub const DSCP: u32 = 36;
    pub const ECN: u32 = 37;
    pub const FIB_ADDR: u32 = 38;
    pub const BOOLEAN: u32 = 39;
    pub const CT_EVENTBIT: u32 = 40;
    pub const IFNAME: u32 = 41;
    pub const IGMP_TYPE: u32 = 42;
    pub const TIME_DATE: u32 = 43;
    pub const TIME_HOUR: u32 = 44;
    pub const TIME_DAY: u32 = 45;
    pub const CGROUPV2: u32 = 46;
    /// MPTCP option subtype. nft has no id for it; this one is not sent
    /// to the kernel.
    pub const MPTCP_SUBTYPE: u32 = 47;
}

/// All types, indexed by id.
pub static TYPES: &[Type] = &[
    ty!(id::INVALID, "invalid", 0, Big, Kind::Integer),
    ty!(id::VERDICT, "verdict", 32, Host, Kind::Verdict),
    ty!(id::NFPROTO, "nf_proto", 8, Host, Kind::SymDec(NFPROTOS)),
    ty!(id::BITMASK, "bitmask", 0, Host, Kind::Hex(0)),
    ty!(id::INTEGER, "integer", 0, Host, Kind::Integer),
    ty!(id::STRING, "string", 0, Host, Kind::Str),
    ty!(id::LLADDR, "ll_addr", 0, Big, Kind::Ether),
    ty!(id::IPADDR, "ipv4_addr", 32, Big, Kind::Ipv4),
    ty!(id::IP6ADDR, "ipv6_addr", 128, Big, Kind::Ipv6),
    ty!(id::ETHERADDR, "ether_addr", 48, Big, Kind::Ether),
    ty!(
        id::ETHERTYPE,
        "ether_type",
        16,
        Big,
        Kind::SymHex(ETHER_TYPES, 4)
    ),
    ty!(id::ARPOP, "arp_op", 16, Big, Kind::SymDec(ARP_OPS)),
    ty!(id::INET_PROTOCOL, "inet_proto", 8, Big, Kind::Protocol),
    ty!(id::INET_SERVICE, "inet_service", 16, Big, Kind::Integer),
    ty!(id::ICMP_TYPE, "icmp_type", 8, Big, Kind::SymDec(ICMP_TYPES)),
    ty!(id::TCP_FLAG, "tcp_flag", 8, Big, Kind::Flags(TCP_FLAGS)),
    ty!(
        id::DCCP_PKTTYPE,
        "dccp_pkttype",
        4,
        Big,
        Kind::SymDec(DCCP_TYPES)
    ),
    ty!(id::MH_TYPE, "mh_type", 8, Big, Kind::SymDec(MH_TYPES)),
    ty!(id::TIME, "time", 64, Host, Kind::Duration),
    ty!(id::MARK, "mark", 32, Host, Kind::Hex(8)),
    ty!(id::IFINDEX, "iface_index", 32, Host, Kind::Ifindex),
    ty!(
        id::ARPHRD,
        "iface_type",
        16,
        Host,
        Kind::SymDec(IFACE_TYPES)
    ),
    ty!(id::REALM, "realm", 32, Host, Kind::IpRoute2("rt_realms")),
    ty!(id::CLASSID, "classid", 32, Host, Kind::Classid),
    ty!(id::UID, "uid", 32, Host, Kind::Integer),
    ty!(id::GID, "gid", 32, Host, Kind::Integer),
    ty!(id::CT_STATE, "ct_state", 32, Host, Kind::Flags(CT_STATES)),
    ty!(id::CT_DIR, "ct_dir", 8, Host, Kind::SymDec(CT_DIRS)),
    ty!(id::CT_STATUS, "ct_status", 32, Host, Kind::Flags(CT_STATUS)),
    ty!(
        id::ICMP6_TYPE,
        "icmpv6_type",
        8,
        Big,
        Kind::SymDec(ICMP6_TYPES)
    ),
    ty!(id::CT_LABEL, "ct_label", 128, Host, Kind::Label),
    ty!(id::PKTTYPE, "pkt_type", 8, Host, Kind::SymDec(PKT_TYPES)),
    ty!(id::ICMP_CODE, "icmp_code", 8, Big, Kind::SymDec(ICMP_CODES)),
    ty!(
        id::ICMPV6_CODE,
        "icmpv6_code",
        8,
        Big,
        Kind::SymDec(ICMP6_CODES)
    ),
    ty!(
        id::ICMPX_CODE,
        "icmpx_code",
        8,
        Big,
        Kind::SymDec(ICMPX_CODES)
    ),
    ty!(id::DEVGROUP, "devgroup", 32, Host, Kind::IpRoute2("group")),
    ty!(id::DSCP, "dscp", 6, Big, Kind::SymHex(DSCP, 2)),
    ty!(id::ECN, "ecn", 2, Big, Kind::SymHex(ECN, 1)),
    ty!(
        id::FIB_ADDR,
        "fib_addrtype",
        32,
        Host,
        Kind::SymDec(FIB_ADDRTYPES)
    ),
    ty!(id::BOOLEAN, "boolean", 1, Host, Kind::Boolean),
    ty!(
        id::CT_EVENTBIT,
        "ct_event",
        32,
        Host,
        Kind::Flags(CT_EVENTS)
    ),
    ty!(id::IFNAME, "ifname", 128, Host, Kind::Str),
    ty!(id::IGMP_TYPE, "igmp_type", 8, Big, Kind::SymDec(IGMP_TYPES)),
    ty!(id::TIME_DATE, "time", 64, Host, Kind::Date),
    ty!(id::TIME_HOUR, "hour", 32, Host, Kind::Hour),
    ty!(id::TIME_DAY, "day", 8, Host, Kind::Day),
    ty!(id::CGROUPV2, "cgroupsv2", 64, Host, Kind::Integer),
    ty!(
        id::MPTCP_SUBTYPE,
        "mptcp_subtype",
        4,
        Big,
        Kind::SymDec(MPTCP_SUBTYPES)
    ),
];

/// The type with the given id (`invalid` if unknown).
pub fn by_id(id: u32) -> &'static Type {
    TYPES.get(id as usize).unwrap_or(&TYPES[0])
}

/// The type with the given name, as used in `type` declarations.
pub fn by_name(name: &str) -> Option<&'static Type> {
    match name {
        // `time` names the duration type in declarations.
        "time" => Some(&TYPES[id::TIME as usize]),
        _ => TYPES.iter().find(|t| t.name == name),
    }
}

/// Maximum elements per line when nft prints a named set of this type
/// (`None`: one element per line).
pub(crate) fn elements_per_line(id: u32) -> Option<usize> {
    match id {
        id::NFPROTO
        | id::INTEGER
        | id::ARPOP
        | id::INET_PROTOCOL
        | id::INET_SERVICE
        | id::TCP_FLAG
        | id::DCCP_PKTTYPE
        | id::MARK
        | id::IFINDEX
        | id::CLASSID
        | id::UID
        | id::GID
        | id::CT_DIR => Some(5),
        id::IPADDR | id::CT_STATE | id::CT_STATUS | id::PKTTYPE => Some(2),
        _ => None,
    }
}

// ------------------------------------------------------------------ integers

/// Interpret `bytes` (in `order`) as an unsigned integer.
pub fn to_u128(bytes: &[u8], order: Order) -> u128 {
    let mut v = 0u128;
    let it: Box<dyn Iterator<Item = &u8>> = match order {
        Order::Big => Box::new(bytes.iter()),
        Order::Host if cfg!(target_endian = "little") => Box::new(bytes.iter().rev()),
        Order::Host => Box::new(bytes.iter()),
    };
    for b in it.take(16) {
        v = (v << 8) | u128::from(*b);
    }
    v
}

/// Encode an integer in `len` bytes with the given byte order.
pub fn from_u128(v: u128, len: usize, order: Order) -> Vec<u8> {
    let be = v.to_be_bytes();
    let mut out = if len <= 16 {
        be[16 - len..].to_vec()
    } else {
        [vec![0; len - 16], be.to_vec()].concat()
    };
    if order == Order::Host && cfg!(target_endian = "little") {
        out.reverse();
    }
    out
}

fn sym_name(syms: Symbols, v: u64) -> Option<&'static str> {
    syms.iter().find(|(_, x)| *x == v).map(|(n, _)| *n)
}

fn sym_value(syms: Symbols, s: &str) -> Option<u64> {
    syms.iter().find(|(n, _)| *n == s).map(|(_, v)| *v)
}

/// Print a duration given in milliseconds the way nft does (`1h2m3s4ms`).
pub fn duration_ms(ms: u64) -> String {
    if ms == 0 {
        return "0s".into();
    }
    let mut s = String::new();
    let (d, rest) = (ms / 86_400_000, ms % 86_400_000);
    let (h, rest) = (rest / 3_600_000, rest % 3_600_000);
    let (m, rest) = (rest / 60_000, rest % 60_000);
    let (sec, msec) = (rest / 1000, rest % 1000);
    for (v, u) in [(d, "d"), (h, "h"), (m, "m"), (sec, "s"), (msec, "ms")] {
        if v > 0 {
            let _ = write!(s, "{v}{u}");
        }
    }
    s
}

/// Parse an nft duration (`1h30m`, `500ms`, `10`) into milliseconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    if let Ok(v) = s.parse::<u64>() {
        return Ok(v * 1000);
    }
    let mut total = 0u64;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let mut unit = c.to_string();
        if c == 'm' && chars.peek() == Some(&'s') {
            unit.push(chars.next().unwrap());
        }
        let n: u64 = num
            .parse()
            .map_err(|_| Error::msg(format!("invalid time `{s}`")))?;
        num.clear();
        total += n * match unit.as_str() {
            "d" => 86_400_000,
            "h" => 3_600_000,
            "m" => 60_000,
            "s" => 1000,
            "ms" => 1,
            _ => return Err(Error::msg(format!("invalid time unit in `{s}`"))),
        };
        any = true;
    }
    if !num.is_empty() || !any {
        return Err(Error::msg(format!("invalid time `{s}`")));
    }
    Ok(total)
}

// ------------------------------------------------------------------ system names

fn read_names(path: &str, num_col: usize, name_col: usize) -> Vec<(String, u64)> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut v = Vec::new();
    for line in s.lines() {
        let line = line.split('#').next().unwrap_or("");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > num_col.max(name_col) {
            let num = f[num_col].split('/').next().unwrap_or("");
            let n = if let Some(h) = num.strip_prefix("0x") {
                u64::from_str_radix(h, 16).ok()
            } else {
                num.parse().ok()
            };
            if let Some(n) = n {
                v.push((f[name_col].to_owned(), n));
            }
        }
    }
    v
}

/// The protocol names of `/etc/protocols`, in file order.
pub fn protocol_table() -> &'static [(String, u64)] {
    protocols()
}

fn protocols() -> &'static [(String, u64)] {
    static P: std::sync::OnceLock<Vec<(String, u64)>> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        let mut v = read_names("/etc/protocols", 1, 0);
        if v.is_empty() {
            for (n, p) in [
                ("icmp", 1),
                ("igmp", 2),
                ("tcp", 6),
                ("udp", 17),
                ("ipv6", 41),
                ("gre", 47),
                ("esp", 50),
                ("ah", 51),
            ] {
                v.push((n.to_owned(), p));
            }
            for (n, p) in [
                ("ipv6-icmp", 58),
                ("sctp", 132),
                ("udplite", 136),
                ("dccp", 33),
                ("comp", 108),
            ] {
                v.push((n.to_owned(), p));
            }
        }
        v
    })
}

/// Name of IP protocol `n` (as `nft` prints it), if known.
/// The path of an iproute2 table (`/etc/iproute2` overrides
/// `/usr/share/iproute2`).
pub fn iproute2_path(file: &str) -> String {
    let etc = format!("/etc/iproute2/{file}");
    if std::path::Path::new(&etc).exists() {
        etc
    } else {
        format!("/usr/share/iproute2/{file}")
    }
}

/// The `(name, value)` entries of an iproute2 table (`group` or
/// `rt_realms`; read once).
pub fn iproute2_names(file: &str) -> &'static [(String, u64)] {
    use std::sync::OnceLock;
    static GROUP: OnceLock<Vec<(String, u64)>> = OnceLock::new();
    static REALMS: OnceLock<Vec<(String, u64)>> = OnceLock::new();
    let cell = match file {
        "group" => &GROUP,
        "rt_realms" => &REALMS,
        _ => return &[],
    };
    cell.get_or_init(|| read_names(&iproute2_path(file), 0, 1))
}

/// The name of IP protocol `n` (from `/etc/protocols`).
pub fn protocol_name(n: u64) -> Option<&'static str> {
    protocols()
        .iter()
        .find(|(_, p)| *p == n)
        .map(|(s, _)| s.as_str())
}

/// Number of the IP protocol `name`.
pub fn protocol_number(name: &str) -> Option<u64> {
    match name {
        // Aliases nft accepts.
        "icmpv6" => return Some(58),
        "comp" => return Some(108),
        _ => {}
    }
    protocols().iter().find(|(s, _)| s == name).map(|(_, p)| *p)
}

fn services() -> &'static [(String, u64)] {
    static S: std::sync::OnceLock<Vec<(String, u64)>> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let mut v = read_names("/etc/services", 1, 0);
        if v.is_empty() {
            for (n, p) in [
                ("ftp", 21),
                ("ssh", 22),
                ("telnet", 23),
                ("smtp", 25),
                ("domain", 53),
                ("http", 80),
            ] {
                v.push((n.to_owned(), p));
            }
            for (n, p) in [
                ("https", 443),
                ("ntp", 123),
                ("snmp", 161),
                ("imap", 143),
                ("pop3", 110),
            ] {
                v.push((n.to_owned(), p));
            }
        }
        v
    })
}

/// Service name of port `n` (from `/etc/services`).
pub fn service_name(n: u64) -> Option<&'static str> {
    services()
        .iter()
        .find(|(_, p)| *p == n)
        .map(|(s, _)| s.as_str())
}

/// A system file of names, read once (empty if unreadable).
fn etc_file(path: &'static str) -> &'static str {
    use std::sync::OnceLock;
    static PASSWD: OnceLock<String> = OnceLock::new();
    static GROUP: OnceLock<String> = OnceLock::new();
    static HOSTS: OnceLock<String> = OnceLock::new();
    let cell = match path {
        "/etc/passwd" => &PASSWD,
        "/etc/group" => &GROUP,
        _ => &HOSTS,
    };
    cell.get_or_init(|| std::fs::read_to_string(path).unwrap_or_default())
}

/// Name of user or group `id` in `file` (`/etc/passwd`, `/etc/group`).
fn account_name(file: &'static str, id: u64) -> Option<String> {
    etc_file(file).lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.get(2)?.parse::<u64>().ok()? == id).then(|| f[0].to_owned())
    })
}

/// Host name of `a` (from `/etc/hosts`), as `getnameinfo` finds it.
fn host_name(a: std::net::IpAddr) -> Option<String> {
    etc_file("/etc/hosts").lines().find_map(|l| {
        let l = l.split('#').next()?;
        let mut f = l.split_whitespace();
        let addr: std::net::IpAddr = f.next()?.parse().ok()?;
        (addr == a).then(|| f.next().map(str::to_owned)).flatten()
    })
}

/// Print a time in milliseconds: `1h30m`, or with `numeric` in whole
/// seconds (`5400s`).
pub fn time_ms(ms: u64, numeric: bool) -> String {
    if numeric {
        format!("{}s", ms / 1000)
    } else {
        duration_ms(ms)
    }
}

/// Port of the service `name` (from `/etc/services`).
pub fn service_port(name: &str) -> Option<u64> {
    services().iter().find(|(s, _)| s == name).map(|(_, p)| *p)
}

/// Interface name of index `i`.
pub fn ifindex_name(i: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` has room for IF_NAMESIZE bytes as required.
    let p = unsafe { libc::if_indextoname(i, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Index of interface `name`.
pub fn ifindex_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL terminated string.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// Offset of local time from UTC in seconds at `t`.
fn tz_offset(t: i64) -> i64 {
    // SAFETY: localtime_r only writes into `tm`.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let tt = t as libc::time_t;
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn print_date(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let local = secs + tz_offset(secs);
    let (y, m, d) = civil_from_days(local.div_euclid(86_400));
    let s = local.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

fn parse_date(s: &str) -> Result<u64> {
    if let Ok(v) = s.parse::<u64>() {
        return Ok(v * 1_000_000_000);
    }
    let bad = || Error::msg(format!("invalid date `{s}`"));
    let (date, time) = s.split_once(' ').unwrap_or((s, "00:00:00"));
    let dp: Vec<&str> = date.split('-').collect();
    let tp: Vec<&str> = time.split(':').collect();
    if dp.len() != 3 || tp.len() < 2 {
        return Err(bad());
    }
    let n = |x: &str| x.parse::<i64>().map_err(|_| bad());
    let days = days_from_civil(n(dp[0])?, n(dp[1])? as u32, n(dp[2])? as u32);
    let mut t = days * 86_400
        + n(tp[0])? * 3600
        + n(tp[1])? * 60
        + if tp.len() > 2 { n(tp[2])? } else { 0 };
    t -= tz_offset(t);
    Ok(t as u64 * 1_000_000_000)
}

fn print_hour(secs: u64) -> String {
    let local = (secs as i64 + tz_offset(0)).rem_euclid(86_400);
    let (h, m, s) = (local / 3600, local % 3600 / 60, local % 60);
    if s == 0 {
        format!("{h:02}:{m:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn parse_hour(s: &str) -> Result<u64> {
    let bad = || Error::msg(format!("invalid hour `{s}`"));
    let p: Vec<&str> = s.split(':').collect();
    if p.len() < 2 || p.len() > 3 {
        return Err(bad());
    }
    let n = |x: &str| x.parse::<i64>().map_err(|_| bad());
    let local = n(p[0])? * 3600 + n(p[1])? * 60 + if p.len() == 3 { n(p[2])? } else { 0 };
    Ok((local - tz_offset(0)).rem_euclid(86_400) as u64)
}

// ------------------------------------------------------------------ printing

/// Options affecting how values are printed.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrintOpts {
    /// Print symbolic constants as numbers (part of `nft -n`).
    pub numeric: bool,
    /// Print IP protocols as numbers (`nft -p`).
    pub numeric_proto: bool,
    /// Print service names for ports (`nft -S`).
    pub service: bool,
    /// Print host names for addresses (`nft -N`).
    pub reverse_dns: bool,
    /// Print user and group names (`nft -u`).
    pub guid: bool,
    /// Print times in seconds (`nft -T`).
    pub numeric_time: bool,
    /// Value appears in a named set's element list.
    pub in_set: bool,
}

/// Print `bytes` as a value of type `t` (`bits` gives the field width).
pub fn print(t: &Type, bytes: &[u8], bits: u32, opts: PrintOpts) -> String {
    let order = t.order;
    let v = || to_u128(bytes, order);
    match t.kind {
        Kind::Integer if opts.service && t.id == id::INET_SERVICE => {
            let n = v() as u64;
            match service_name(n) {
                Some(s) => format!("\"{s}\""),
                None => n.to_string(),
            }
        }
        Kind::Integer if opts.guid && matches!(t.id, id::UID | id::GID) => {
            let n = v() as u64;
            let file = if t.id == id::UID {
                "/etc/passwd"
            } else {
                "/etc/group"
            };
            match account_name(file, n) {
                Some(s) => format!("\"{s}\""),
                None => n.to_string(),
            }
        }
        Kind::Integer => {
            if t.id == id::INTEGER && bits > 64 {
                format!("0x{:x}", v())
            } else {
                v().to_string()
            }
        }
        Kind::Hex(w) => format!("0x{:0w$x}", v(), w = w),
        Kind::SymDec(syms) => {
            let n = v();
            // ICMP codes are only symbolic in `reject` statements.
            if matches!(t.id, id::ICMPX_CODE | id::ICMP_CODE | id::ICMPV6_CODE) {
                return n.to_string();
            }
            match (opts.numeric, sym_name(syms, n as u64)) {
                (false, Some(s)) => s.to_owned(),
                _ => n.to_string(),
            }
        }
        Kind::SymHex(syms, w) => match (opts.numeric, sym_name(syms, v() as u64)) {
            (false, Some(s)) => s.to_owned(),
            _ => format!("0x{:0w$x}", v(), w = w),
        },
        Kind::Flags(_) if opts.numeric => print_flags(&[], v() as u64, ","),
        Kind::Flags(syms) => print_flags(syms, v() as u64, ","),
        Kind::Ipv4 => match bytes {
            [a, b, c, d] => {
                let a = Ipv4Addr::new(*a, *b, *c, *d);
                match opts.reverse_dns.then(|| host_name(a.into())).flatten() {
                    Some(h) => h,
                    None => a.to_string(),
                }
            }
            _ => hex_bytes(bytes),
        },
        Kind::Ipv6 => match <[u8; 16]>::try_from(bytes) {
            Ok(b) => {
                let a = Ipv6Addr::from(b);
                match opts.reverse_dns.then(|| host_name(a.into())).flatten() {
                    Some(h) => h,
                    None => print_ipv6(a),
                }
            }
            Err(_) => hex_bytes(bytes),
        },
        Kind::Ether => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        Kind::Str => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let s = String::from_utf8_lossy(&bytes[..end]);
            // A string not NUL terminated within its field is a prefix
            // match (`eth*`).
            if t.id == id::IFNAME && end == bytes.len() && (bytes.len() as u32) * 8 < bits {
                format!("\"{s}*\"")
            } else {
                format!("\"{s}\"")
            }
        }
        Kind::Verdict => v().to_string(),
        Kind::Duration => time_ms(v() as u64, opts.numeric_time),
        Kind::Ifindex => {
            let i = v() as u32;
            match ifindex_name(i) {
                Some(n) => format!("\"{n}\""),
                _ => i.to_string(),
            }
        }
        Kind::Classid => {
            let n = v() as u32;
            match n {
                0xffff_ffff => "root".into(),
                0 => "none".into(),
                n => format!("{:x}:{:x}", n >> 16, n & 0xffff),
            }
        }
        Kind::Day => {
            let n = v() as usize;
            match DAYS.get(n) {
                Some(d) if !opts.numeric => format!("\"{d}\""),
                _ => n.to_string(),
            }
        }
        Kind::Hour => format!("\"{}\"", print_hour(v() as u64)),
        Kind::Date => format!("\"{}\"", print_date(v() as u64)),
        Kind::Boolean if opts.numeric => v().to_string(),
        Kind::Boolean => if v() != 0 { "exists" } else { "missing" }.to_owned(),
        Kind::Label => {
            let n = v();
            if n == 0 {
                return "0".into();
            }
            let bits: Vec<String> = (0..128)
                .filter(|b| n & (1u128 << b) != 0)
                .map(|b| b.to_string())
                .collect();
            bits.join(",")
        }
        Kind::Protocol => {
            let n = v() as u64;
            match protocol_name(n) {
                Some(s) if !opts.numeric_proto => s.to_owned(),
                _ => n.to_string(),
            }
        }
        Kind::IpRoute2(file) => {
            let n = v() as u64;
            match iproute2_names(file).iter().find(|(_, x)| *x == n) {
                Some((name, _)) if !opts.numeric => format!("\"{name}\""),
                _ => n.to_string(),
            }
        }
    }
}

/// The symbolic name of value `v` of type `t`, if it has one.
pub fn symbol(t: &Type, v: u64) -> Option<&'static str> {
    match t.kind {
        Kind::SymDec(s) | Kind::SymHex(s, _) | Kind::Flags(s) => sym_name(s, v),
        _ => None,
    }
}

/// Print a flag set (`syn,ack`), unknown bits as hex.
pub fn print_flags(syms: Symbols, v: u64, sep: &str) -> String {
    if v == 0 {
        return "0x0".into();
    }
    let mut parts = Vec::new();
    for bit in 0..64 {
        let b = 1u64 << bit;
        if v & b != 0 {
            match sym_name(syms, b) {
                Some(s) => parts.push(s.to_owned()),
                None => parts.push(format!("0x{b:x}")),
            }
        }
    }
    parts.join(sep)
}

fn print_ipv6(a: Ipv6Addr) -> String {
    // nft prints v4-mapped addresses as ::ffff:a.b.c.d, which std does too.
    a.to_string()
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

// ------------------------------------------------------------------ parsing

fn parse_int(s: &str) -> Option<u128> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse `text` as a value of type `t`, `len` bytes long.
pub fn parse(t: &Type, text: &str, len: usize) -> Result<Vec<u8>> {
    let bad = || match t.kind {
        // nft resolves unparsable addresses as host names.
        Kind::Ipv4 | Kind::Ipv6 => Error::about(
            "Could not resolve hostname: Name or service not known",
            text,
        ),
        _ => Error::about(format!("Could not parse {} value `{text}`", t.name), text),
    };
    let int = |v: u128| -> Result<Vec<u8>> {
        if len < 16 && v >> (len * 8) != 0 {
            if t.id == id::INET_SERVICE {
                return Err(Error::about("Service out of range", text));
            }
            return Err(Error::about(
                format!(
                    "Value {text} exceeds valid range 0-{}",
                    (1u128 << (len * 8)) - 1
                ),
                text,
            ));
        }
        Ok(from_u128(v, len, t.order))
    };
    match t.kind {
        Kind::Integer | Kind::Hex(_) | Kind::Verdict => match t.id {
            id::INET_SERVICE => {
                match parse_int(text).or_else(|| service_port(text).map(u128::from)) {
                    Some(v) => int(v),
                    None => Err(Error::about(
                        "Could not resolve service: Servname not supported for ai_socktype",
                        text,
                    )),
                }
            }
            id::UID | id::GID if parse_int(text).is_none() => {
                let file = if t.id == id::UID {
                    "/etc/passwd"
                } else {
                    "/etc/group"
                };
                let n = etc_file(file).lines().find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.first() == Some(&text))
                        .then(|| f.get(2).and_then(|x| x.parse::<u128>().ok()))
                        .flatten()
                });
                n.map_or_else(|| Err(bad()), int)
            }
            _ => parse_int(text).map_or_else(|| Err(bad()), int),
        },
        Kind::SymDec(syms) | Kind::SymHex(syms, _) => {
            match sym_value(syms, text)
                .map(u128::from)
                .or_else(|| parse_int(text))
            {
                Some(v) => int(v),
                None => Err(bad()),
            }
        }
        Kind::Flags(syms) => {
            let mut v = 0u128;
            for part in text.split(',') {
                let part = part.trim();
                v |= sym_value(syms, part)
                    .map(u128::from)
                    .or_else(|| parse_int(part))
                    .ok_or_else(bad)?;
            }
            int(v)
        }
        Kind::Ipv4 => text
            .parse::<Ipv4Addr>()
            .map(|a| a.octets().to_vec())
            .map_err(|_| bad()),
        Kind::Ipv6 => {
            let t = text.trim_start_matches('[').trim_end_matches(']');
            t.parse::<Ipv6Addr>()
                .map(|a| a.octets().to_vec())
                .map_err(|_| bad())
        }
        Kind::Ether => {
            let v: std::result::Result<Vec<u8>, _> =
                text.split(':').map(|x| u8::from_str_radix(x, 16)).collect();
            v.map_err(|_| bad())
        }
        Kind::Str => {
            let s = text.trim_matches('"');
            if s.len() > len && len > 0 {
                return Err(Error::msg(format!("String `{s}` too long")));
            }
            if let Some(prefix) = s.strip_suffix('*') {
                return Ok(prefix.as_bytes().to_vec());
            }
            let mut v = s.as_bytes().to_vec();
            if len > 0 {
                v.resize(len, 0);
            }
            Ok(v)
        }
        Kind::Duration => int(u128::from(parse_duration(text)?)),
        Kind::Ifindex => {
            let s = text.trim_matches('"');
            let i = parse_int(s).map(|v| v as u32).or_else(|| ifindex_of(s));
            i.map_or_else(
                || Err(Error::msg(format!("Interface does not exist: {s}"))),
                |i| int(u128::from(i)),
            )
        }
        Kind::Classid => {
            let v = match text {
                "root" => 0xffff_ffff,
                "none" => 0,
                _ => {
                    let (a, b) = text.split_once(':').ok_or_else(bad)?;
                    let a = u32::from_str_radix(a, 16).map_err(|_| bad())?;
                    let b = if b.is_empty() {
                        0
                    } else {
                        u32::from_str_radix(b, 16).map_err(|_| bad())?
                    };
                    (a << 16) | b
                }
            };
            int(u128::from(v))
        }
        Kind::Day => {
            let s = text.trim_matches('"');
            let n = DAYS
                .iter()
                .position(|d| d.eq_ignore_ascii_case(s) || d[..3].eq_ignore_ascii_case(s))
                .map(|n| n as u128)
                .or_else(|| parse_int(s));
            n.map_or_else(|| Err(bad()), int)
        }
        Kind::Hour => int(u128::from(parse_hour(text.trim_matches('"'))?)),
        Kind::Date => int(u128::from(parse_date(text.trim_matches('"'))?)),
        Kind::Boolean => match text {
            "exists" | "true" | "1" => int(1),
            "missing" | "false" | "0" => int(0),
            _ => Err(bad()),
        },
        Kind::Label => {
            let mut v = 0u128;
            for p in text.split(',') {
                let b: u32 = p.trim().parse().map_err(|_| bad())?;
                v |= 1u128 << b.min(127);
            }
            int(v)
        }
        Kind::IpRoute2(file) => {
            let s = text.trim_matches('"');
            match parse_int(s).or_else(|| {
                iproute2_names(file)
                    .iter()
                    .find(|(n, _)| n == s)
                    .map(|(_, v)| u128::from(*v))
            }) {
                Some(v) => int(v),
                None => Err(bad()),
            }
        }
        Kind::Protocol => match parse_int(text).or_else(|| protocol_number(text).map(u128::from)) {
            Some(v) => int(v),
            None => Err(bad()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration_ms(90_000), "1m30s");
        assert_eq!(duration_ms(3_599_996), "59m59s996ms");
        assert_eq!(parse_duration("1h30m").unwrap(), 5_400_000);
        assert_eq!(parse_duration("500ms").unwrap(), 500);
        assert_eq!(parse_duration("10").unwrap(), 10_000);
    }

    #[test]
    fn values() {
        let p = |name, s, len| parse(by_name(name).unwrap(), s, len).unwrap();
        let pr =
            |name, b: &[u8], bits| print(by_name(name).unwrap(), b, bits, PrintOpts::default());
        assert_eq!(pr("mark", &p("mark", "5", 4), 32), "0x00000005");
        assert_eq!(
            pr("ct_state", &p("ct_state", "established,related", 4), 32),
            "established,related"
        );
        assert_eq!(pr("ct_state", &0x30u32.to_ne_bytes(), 32), "0x10,0x20");
        assert_eq!(pr("ether_type", &[0x88, 0xcc], 16), "0x88cc");
        assert_eq!(pr("dscp", &[7], 6), "0x07");
        assert_eq!(pr("inet_proto", &[6], 8), "tcp");
        assert_eq!(pr("classid", &p("classid", "1:2", 4), 32), "1:2");
        assert_eq!(
            pr("ipv6_addr", &p("ipv6_addr", "::ffff:1.2.3.4", 16), 128),
            "::ffff:1.2.3.4"
        );
        assert_eq!(pr("ifname", &p("ifname", "\"eth*\"", 16), 128), "\"eth*\"");
        assert_eq!(pr("ifname", &p("ifname", "\"lo\"", 16), 128), "\"lo\"");
        assert_eq!(pr("tcp_flag", &[0x40], 8), "ecn");
        assert_eq!(p("inet_service", "ssh", 2), vec![0, 22]);
        assert_eq!(pr("day", &p("day", "Wednesday", 1), 8), "\"Wednesday\"");
    }
}
