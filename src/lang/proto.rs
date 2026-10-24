//! Protocol header definitions, meta keys and conntrack keys.

use crate::PayloadBase;
use crate::{CtKey, MetaKey};

use super::datatype::id;

/// A header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdrField {
    /// Field name (`dport`).
    pub name: &'static str,
    /// Offset in bits from the start of the header.
    pub offset: u32,
    /// Length in bits.
    pub len: u32,
    /// Data type id.
    pub ty: u32,
}

/// How a protocol is selected (its dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Link layer header.
    Link,
    /// Network layer header with this ether type.
    Network(u16),
    /// Transport layer header with this IP protocol number (`None` for `th`).
    Transport(Option<u8>),
}

/// A protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proto {
    /// Name (`tcp`).
    pub name: &'static str,
    /// nft's protocol description id (used in set `typeof` user data).
    pub desc: u32,
    /// Payload base.
    pub base: PayloadBase,
    /// Offset of this header from the payload base, in bits (e.g. vlan
    /// sits after the 14 byte ethernet header).
    pub base_offset: u32,
    /// Layer and selector.
    pub layer: Layer,
    /// Fields, in nft's field index order (index = position + 1).
    pub fields: &'static [HdrField],
}

impl Proto {
    /// The field with the given name, with its typeof index.
    pub fn field(&self, name: &str) -> Option<(usize, &'static HdrField)> {
        self.fields
            .iter()
            .enumerate()
            .find(|(_, f)| f.name == name)
            .map(|(i, f)| (i + 1, f))
    }

    /// Whether this is a network layer protocol available only for IPv4
    /// (`Some(true)`), IPv6 (`Some(false)`) or both / not applicable.
    pub fn ip_version(&self) -> Option<bool> {
        match self.name {
            // igmp is IPv4 only too, but nft keeps its `meta nfproto`.
            "ip" | "icmp" => Some(true),
            "ip6" | "icmpv6" => Some(false),
            _ => None,
        }
    }
}

macro_rules! f {
    ($name:expr, $off:expr, $len:expr, $ty:expr) => {
        HdrField {
            name: $name,
            offset: $off,
            len: $len,
            ty: $ty,
        }
    };
}

use id::*;

/// IP protocol numbers.
pub mod ipproto {
    #![allow(missing_docs)]
    pub const ICMP: u8 = 1;
    pub const IGMP: u8 = 2;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const DCCP: u8 = 33;
    pub const GRE: u8 = 47;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const COMP: u8 = 108;
    pub const SCTP: u8 = 132;
    pub const UDPLITE: u8 = 136;
}

/// Ether types.
pub mod ethertype {
    #![allow(missing_docs)]
    pub const IP: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IP6: u16 = 0x86dd;
    pub const VLAN: u16 = 0x8100;
}

const LL: PayloadBase = PayloadBase::LinkLayer;
const NH: PayloadBase = PayloadBase::Network;
const TH: PayloadBase = PayloadBase::Transport;

/// All protocols, in nft description id order where it matters.
pub static PROTOS: &[Proto] = &[
    Proto {
        name: "ether",
        desc: 17,
        base: LL,
        base_offset: 0,
        layer: Layer::Link,
        fields: &[
            f!("daddr", 0, 48, ETHERADDR),
            f!("saddr", 48, 48, ETHERADDR),
            f!("type", 96, 16, ETHERTYPE),
        ],
    },
    Proto {
        name: "vlan",
        desc: 16,
        base: LL,
        base_offset: 112,
        layer: Layer::Link,
        fields: &[
            f!("pcp", 0, 3, INTEGER),
            f!("dei", 3, 1, INTEGER),
            f!("cfi", 3, 1, INTEGER),
            f!("id", 4, 12, INTEGER),
            f!("type", 16, 16, ETHERTYPE),
        ],
    },
    Proto {
        name: "arp",
        desc: 15,
        base: NH,
        base_offset: 0,
        layer: Layer::Network(ethertype::ARP),
        fields: &[
            f!("htype", 0, 16, INTEGER),
            f!("ptype", 16, 16, ETHERTYPE),
            f!("hlen", 32, 8, INTEGER),
            f!("plen", 40, 8, INTEGER),
            f!("operation", 48, 16, ARPOP),
            f!("saddr ether", 64, 48, ETHERADDR),
            f!("saddr ip", 112, 32, IPADDR),
            f!("daddr ether", 144, 48, ETHERADDR),
            f!("daddr ip", 192, 32, IPADDR),
        ],
    },
    Proto {
        name: "ip",
        desc: 12,
        base: NH,
        base_offset: 0,
        layer: Layer::Network(ethertype::IP),
        fields: &[
            f!("version", 0, 4, INTEGER),
            f!("hdrlength", 4, 4, INTEGER),
            f!("dscp", 8, 6, DSCP),
            f!("ecn", 14, 2, ECN),
            f!("length", 16, 16, INTEGER),
            f!("id", 32, 16, INTEGER),
            f!("frag-off", 48, 16, INTEGER),
            f!("ttl", 64, 8, INTEGER),
            f!("protocol", 72, 8, INET_PROTOCOL),
            f!("checksum", 80, 16, INTEGER),
            f!("saddr", 96, 32, IPADDR),
            f!("daddr", 128, 32, IPADDR),
        ],
    },
    Proto {
        name: "ip6",
        desc: 13,
        base: NH,
        base_offset: 0,
        layer: Layer::Network(ethertype::IP6),
        fields: &[
            f!("version", 0, 4, INTEGER),
            f!("dscp", 4, 6, DSCP),
            f!("ecn", 10, 2, ECN),
            f!("flowlabel", 12, 20, INTEGER),
            f!("length", 32, 16, INTEGER),
            f!("nexthdr", 48, 8, INET_PROTOCOL),
            f!("hoplimit", 56, 8, INTEGER),
            f!("saddr", 64, 128, IP6ADDR),
            f!("daddr", 192, 128, IP6ADDR),
        ],
    },
    Proto {
        name: "ah",
        desc: 1,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::AH)),
        fields: &[
            f!("nexthdr", 0, 8, INET_PROTOCOL),
            f!("hdrlength", 8, 8, INTEGER),
            f!("reserved", 16, 16, INTEGER),
            f!("spi", 32, 32, INTEGER),
            f!("sequence", 64, 32, INTEGER),
        ],
    },
    Proto {
        name: "esp",
        desc: 2,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::ESP)),
        fields: &[f!("spi", 0, 32, INTEGER), f!("sequence", 32, 32, INTEGER)],
    },
    Proto {
        name: "comp",
        desc: 3,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::COMP)),
        fields: &[
            f!("nexthdr", 0, 8, INET_PROTOCOL),
            f!("flags", 8, 8, BITMASK),
            f!("cpi", 16, 16, INTEGER),
        ],
    },
    Proto {
        name: "icmp",
        desc: 4,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::ICMP)),
        fields: &[
            f!("type", 0, 8, ICMP_TYPE),
            f!("code", 8, 8, ICMP_CODE),
            f!("checksum", 16, 16, INTEGER),
            f!("id", 32, 16, INTEGER),
            f!("sequence", 48, 16, INTEGER),
            f!("gateway", 32, 32, IPADDR),
            f!("mtu", 48, 16, INTEGER),
        ],
    },
    Proto {
        name: "icmpv6",
        desc: 14,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::ICMPV6)),
        fields: &[
            f!("type", 0, 8, ICMP6_TYPE),
            f!("code", 8, 8, ICMPV6_CODE),
            f!("checksum", 16, 16, INTEGER),
            f!("parameter-problem", 32, 32, INTEGER),
            f!("mtu", 32, 32, INTEGER),
            f!("id", 32, 16, INTEGER),
            f!("sequence", 48, 16, INTEGER),
            f!("max-delay", 32, 16, INTEGER),
        ],
    },
    Proto {
        name: "igmp",
        desc: 5,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::IGMP)),
        fields: &[
            f!("type", 0, 8, IGMP_TYPE),
            f!("mrt", 8, 8, INTEGER),
            f!("checksum", 16, 16, INTEGER),
            f!("group", 32, 32, IPADDR),
        ],
    },
    Proto {
        name: "udp",
        desc: 6,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::UDP)),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
            f!("length", 32, 16, INTEGER),
            f!("checksum", 48, 16, INTEGER),
        ],
    },
    Proto {
        name: "udplite",
        desc: 7,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::UDPLITE)),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
            f!("csumcov", 32, 16, INTEGER),
            f!("checksum", 48, 16, INTEGER),
        ],
    },
    Proto {
        name: "tcp",
        desc: 8,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::TCP)),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
            f!("sequence", 32, 32, INTEGER),
            f!("ackseq", 64, 32, INTEGER),
            f!("doff", 96, 4, INTEGER),
            f!("reserved", 100, 4, INTEGER),
            f!("flags", 104, 8, TCP_FLAG),
            f!("window", 112, 16, INTEGER),
            f!("checksum", 128, 16, INTEGER),
            f!("urgptr", 144, 16, INTEGER),
        ],
    },
    Proto {
        name: "dccp",
        desc: 9,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::DCCP)),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
            f!("type", 67, 4, DCCP_PKTTYPE),
        ],
    },
    Proto {
        name: "sctp",
        desc: 10,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::SCTP)),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
            f!("vtag", 32, 32, INTEGER),
            f!("checksum", 64, 32, INTEGER),
        ],
    },
    Proto {
        name: "th",
        desc: 11,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(None),
        fields: &[
            f!("sport", 0, 16, INET_SERVICE),
            f!("dport", 16, 16, INET_SERVICE),
        ],
    },
    Proto {
        name: "gre",
        desc: 20,
        base: TH,
        base_offset: 0,
        layer: Layer::Transport(Some(ipproto::GRE)),
        fields: &[
            f!("version", 13, 3, INTEGER),
            f!("flags", 0, 5, BITMASK),
            f!("protocol", 16, 16, ETHERTYPE),
        ],
    },
];

/// The protocol named `name`.
pub fn proto(name: &str) -> Option<&'static Proto> {
    PROTOS.iter().find(|p| p.name == name)
}

/// The protocol with nft description id `desc`.
pub fn proto_by_desc(desc: u32) -> Option<&'static Proto> {
    PROTOS.iter().find(|p| p.desc == desc)
}

/// The transport protocol with IP protocol number `n`.
pub fn transport(n: u8) -> Option<&'static Proto> {
    PROTOS.iter().find(|p| p.layer == Layer::Transport(Some(n)))
}

/// The network protocol with ether type `t`.
pub fn network(t: u16) -> Option<&'static Proto> {
    PROTOS.iter().find(|p| p.layer == Layer::Network(t))
}

// ------------------------------------------------------------------ meta

/// A meta key: name, kernel key, length in bytes, type id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaDef {
    /// Name (`iifname`).
    pub name: &'static str,
    /// Kernel key.
    pub key: MetaKey,
    /// Length in bytes.
    pub len: u32,
    /// Data type id.
    pub ty: u32,
    /// Printed without the `meta` prefix (`iifname "lo"`).
    pub unqualified: bool,
}

macro_rules! m {
    ($name:expr, $key:ident, $len:expr, $ty:expr, $unq:expr) => {
        MetaDef {
            name: $name,
            key: MetaKey::$key,
            len: $len,
            ty: $ty,
            unqualified: $unq,
        }
    };
}

/// Meta keys.
pub static METAS: &[MetaDef] = &[
    m!("length", Len, 4, INTEGER, false),
    m!("protocol", Protocol, 2, ETHERTYPE, false),
    m!("priority", Priority, 4, CLASSID, false),
    m!("mark", Mark, 4, MARK, false),
    m!("iif", Iif, 4, IFINDEX, true),
    m!("oif", Oif, 4, IFINDEX, true),
    m!("iifname", IifName, 16, IFNAME, true),
    m!("oifname", OifName, 16, IFNAME, true),
    m!("iiftype", IifType, 2, ARPHRD, false),
    m!("oiftype", OifType, 2, ARPHRD, false),
    m!("skuid", SkUid, 4, UID, false),
    m!("skgid", SkGid, 4, GID, false),
    m!("nftrace", NfTrace, 1, INTEGER, false),
    m!("rtclassid", RtClassId, 4, REALM, false),
    m!("secmark", Secmark, 4, INTEGER, false),
    m!("nfproto", NfProto, 1, NFPROTO, false),
    m!("l4proto", L4Proto, 1, INET_PROTOCOL, false),
    m!("ibrname", BriIifName, 16, IFNAME, false),
    m!("obrname", BriOifName, 16, IFNAME, false),
    m!("pkttype", PktType, 1, PKTTYPE, false),
    m!("cpu", Cpu, 4, INTEGER, false),
    m!("iifgroup", IifGroup, 4, DEVGROUP, true),
    m!("oifgroup", OifGroup, 4, DEVGROUP, true),
    m!("cgroup", Cgroup, 4, INTEGER, false),
    m!("random", Prandom, 4, INTEGER, false),
    m!("ipsec", Secpath, 1, BOOLEAN, false),
    m!("iifkind", IifKind, 16, IFNAME, false),
    m!("oifkind", OifKind, 16, IFNAME, false),
    m!("ibrpvid", BriIifPvid, 2, INTEGER, false),
    m!("ibrvproto", BriIifVproto, 2, ETHERTYPE, false),
    m!("time", TimeNs, 8, TIME_DATE, false),
    m!("day", TimeDay, 1, TIME_DAY, false),
    m!("hour", TimeHour, 4, TIME_HOUR, false),
    m!("sdif", Sdif, 4, IFINDEX, false),
    m!("sdifname", SdifName, 16, IFNAME, false),
    m!("broute", BriBroute, 1, INTEGER, false),
];

/// The meta key named `name`.
pub fn meta(name: &str) -> Option<&'static MetaDef> {
    METAS.iter().find(|m| m.name == name)
}

/// The definition of kernel meta key `key`.
pub fn meta_by_key(key: MetaKey) -> Option<&'static MetaDef> {
    METAS.iter().find(|m| m.key == key)
}

// ------------------------------------------------------------------ ct

/// A conntrack key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtDef {
    /// Name (`proto-dst`).
    pub name: &'static str,
    /// Kernel key.
    pub key: CtKey,
    /// Length in bytes (0: depends on the address family).
    pub len: u32,
    /// Data type id.
    pub ty: u32,
    /// Whether the key requires a direction.
    pub dir_required: bool,
}

macro_rules! c {
    ($name:expr, $key:ident, $len:expr, $ty:expr, $dir:expr) => {
        CtDef {
            name: $name,
            key: CtKey::$key,
            len: $len,
            ty: $ty,
            dir_required: $dir,
        }
    };
}

/// Conntrack keys.
pub static CTS: &[CtDef] = &[
    c!("state", State, 4, CT_STATE, false),
    c!("direction", Direction, 1, CT_DIR, false),
    c!("status", Status, 4, CT_STATUS, false),
    c!("mark", Mark, 4, MARK, false),
    c!("secmark", Secmark, 4, INTEGER, false),
    c!("expiration", Expiration, 4, TIME, false),
    c!("helper", Helper, 16, STRING, false),
    c!("l3proto", L3Protocol, 1, NFPROTO, false),
    c!("saddr", Src, 0, INVALID, true),
    c!("daddr", Dst, 0, INVALID, true),
    c!("protocol", Protocol, 1, INET_PROTOCOL, false),
    c!("proto-src", ProtoSrc, 2, INET_SERVICE, true),
    c!("proto-dst", ProtoDst, 2, INET_SERVICE, true),
    c!("label", Labels, 16, CT_LABEL, false),
    c!("packets", Pkts, 8, INTEGER, false),
    c!("bytes", Bytes, 8, INTEGER, false),
    c!("avgpkt", AvgPkt, 8, INTEGER, false),
    c!("zone", Zone, 2, INTEGER, false),
    c!("event", EventMask, 4, CT_EVENTBIT, false),
    c!("ip saddr", SrcIp, 4, IPADDR, true),
    c!("ip daddr", DstIp, 4, IPADDR, true),
    c!("ip6 saddr", SrcIp6, 16, IP6ADDR, true),
    c!("ip6 daddr", DstIp6, 16, IP6ADDR, true),
    c!("id", Id, 4, INTEGER, false),
];

/// The conntrack key named `name`.
pub fn ct(name: &str) -> Option<&'static CtDef> {
    CTS.iter().find(|c| c.name == name)
}

/// The definition of kernel conntrack key `key`.
pub fn ct_by_key(key: CtKey) -> Option<&'static CtDef> {
    CTS.iter().find(|c| c.key == key)
}
