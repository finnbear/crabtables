//! The rule builder and packet fields.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::expr::*;
use crate::objects::Rule;
use crate::sys::*;
use crate::types::*;
use crate::udata;

/// Something that can be matched or used as a set key: a packet field,
/// metadata, or conntrack key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Field {
    /// `ip saddr` (4 bytes).
    IpSaddr,
    /// `ip daddr` (4 bytes).
    IpDaddr,
    /// `ip protocol` (1 byte).
    IpProtocol,
    /// `ip ttl` (1 byte).
    IpTtl,
    /// `ip6 saddr` (16 bytes).
    Ip6Saddr,
    /// `ip6 daddr` (16 bytes).
    Ip6Daddr,
    /// `ip6 nexthdr` (1 byte).
    Ip6Nexthdr,
    /// `tcp sport` (2 bytes, implies `meta l4proto tcp`).
    TcpSport,
    /// `tcp dport` (2 bytes, implies `meta l4proto tcp`).
    TcpDport,
    /// `udp sport` (2 bytes, implies `meta l4proto udp`).
    UdpSport,
    /// `udp dport` (2 bytes, implies `meta l4proto udp`).
    UdpDport,
    /// `th sport`: transport source port without protocol check.
    ThSport,
    /// `th dport`: transport destination port without protocol check.
    ThDport,
    /// `meta l4proto` (1 byte).
    L4Proto,
    /// `meta nfproto` (1 byte).
    NfProto,
    /// `meta mark` (4 bytes, host byte order).
    Mark,
    /// `meta iif` (4 bytes, host byte order).
    Iif,
    /// `meta oif` (4 bytes, host byte order).
    Oif,
    /// `meta iifname` (16 bytes, NUL padded).
    IifName,
    /// `meta oifname` (16 bytes, NUL padded).
    OifName,
    /// `meta skuid` (4 bytes, host byte order).
    SkUid,
    /// `meta skgid` (4 bytes, host byte order).
    SkGid,
    /// `ct state` (4 bytes, host byte order bitmask).
    CtState,
    /// `ct mark` (4 bytes, host byte order).
    CtMark,
    /// `ether saddr` (6 bytes).
    EtherSaddr,
    /// `ether daddr` (6 bytes).
    EtherDaddr,
    /// Raw payload bytes.
    Payload {
        /// Header base.
        base: PayloadBase,
        /// Offset in bytes.
        offset: u32,
        /// Length in bytes.
        len: u32,
    },
    /// Any meta key with the given length.
    Meta(MetaKey, u32),
    /// A conntrack key, optionally for one direction of the connection
    /// (`ct original saddr`, `ct reply proto-dst`, `ct bytes`, ...).
    Ct(CtKey, Option<CtDir>),
}

/// Direction of a conntrack tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CtDir {
    /// The original direction (from the initiator).
    Original,
    /// The reply direction.
    Reply,
}

impl CtDir {
    fn raw(self) -> u8 {
        match self {
            CtDir::Original => 0,
            CtDir::Reply => 1,
        }
    }
}

fn ct_len(key: CtKey) -> u32 {
    match key {
        CtKey::Direction | CtKey::L3Protocol | CtKey::Protocol => 1,
        CtKey::ProtoSrc | CtKey::ProtoDst | CtKey::Zone => 2,
        CtKey::Pkts | CtKey::Bytes | CtKey::AvgPkt => 8,
        CtKey::Helper | CtKey::Labels | CtKey::Src | CtKey::Dst | CtKey::SrcIp6 | CtKey::DstIp6 => {
            16
        }
        _ => 4,
    }
}

fn ct_host_order(key: CtKey) -> bool {
    !matches!(
        key,
        CtKey::Src
            | CtKey::Dst
            | CtKey::SrcIp
            | CtKey::DstIp
            | CtKey::SrcIp6
            | CtKey::DstIp6
            | CtKey::ProtoSrc
            | CtKey::ProtoDst
            | CtKey::Id
            | CtKey::Helper
    )
}

/// Protocol dependency of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dep {
    None,
    NfProto(u8),
    /// `meta protocol` (EtherType), in the bridge and netdev families.
    EtherType(u16),
    L4Proto(u8),
}

impl Field {
    /// Length of the field in bytes.
    pub fn len(&self) -> u32 {
        match self {
            Field::IpSaddr | Field::IpDaddr => 4,
            Field::IpProtocol
            | Field::IpTtl
            | Field::Ip6Nexthdr
            | Field::L4Proto
            | Field::NfProto => 1,
            Field::Ip6Saddr | Field::Ip6Daddr => 16,
            Field::TcpSport
            | Field::TcpDport
            | Field::UdpSport
            | Field::UdpDport
            | Field::ThSport
            | Field::ThDport => 2,
            Field::Mark
            | Field::Iif
            | Field::Oif
            | Field::SkUid
            | Field::SkGid
            | Field::CtState
            | Field::CtMark => 4,
            Field::IifName | Field::OifName => 16,
            Field::EtherSaddr | Field::EtherDaddr => 6,
            Field::Payload { len, .. } => *len,
            Field::Meta(_, len) => *len,
            Field::Ct(key, _) => ct_len(*key),
        }
    }

    /// Fields always have a non-zero length.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The nft data type id of this field (see [`crate::datatype`]).
    pub fn datatype(&self) -> u32 {
        use crate::objects::datatype::*;
        match self {
            Field::IpSaddr | Field::IpDaddr => IPADDR,
            Field::Ip6Saddr | Field::Ip6Daddr => IP6ADDR,
            Field::IpProtocol | Field::Ip6Nexthdr | Field::L4Proto => INET_PROTOCOL,
            Field::NfProto => NFPROTO,
            Field::TcpSport
            | Field::TcpDport
            | Field::UdpSport
            | Field::UdpDport
            | Field::ThSport
            | Field::ThDport => INET_SERVICE,
            Field::Mark | Field::CtMark => MARK,
            Field::Iif | Field::Oif => IFINDEX,
            Field::IifName | Field::OifName => IFNAME,
            Field::SkUid => UID,
            Field::SkGid => GID,
            Field::CtState => CT_STATE,
            Field::EtherSaddr | Field::EtherDaddr => ETHERADDR,
            Field::IpTtl | Field::Payload { .. } | Field::Meta(..) => INTEGER,
            Field::Ct(key, _) => match key {
                CtKey::State => CT_STATE,
                CtKey::Direction => CT_DIR,
                CtKey::Status => CT_STATUS,
                CtKey::Mark => MARK,
                CtKey::Expiration => TIME,
                CtKey::Helper => STRING,
                CtKey::L3Protocol => NFPROTO,
                CtKey::SrcIp | CtKey::DstIp => IPADDR,
                CtKey::SrcIp6 | CtKey::DstIp6 => IP6ADDR,
                CtKey::Protocol => INET_PROTOCOL,
                CtKey::ProtoSrc | CtKey::ProtoDst => INET_SERVICE,
                CtKey::Labels => CT_LABEL,
                CtKey::EventMask => CT_EVENTBIT,
                _ => INTEGER,
            },
        }
    }

    /// Whether values of this field are in host byte order (as opposed to
    /// network byte order).
    pub fn host_order(&self) -> bool {
        matches!(
            self,
            Field::Mark
                | Field::Iif
                | Field::Oif
                | Field::SkUid
                | Field::SkGid
                | Field::CtState
                | Field::CtMark
                | Field::Meta(..)
        ) || matches!(self, Field::Ct(key, _) if ct_host_order(*key))
    }

    fn dep(&self, family: Family) -> Dep {
        // As nft: `meta nfproto` in inet, `meta protocol` in bridge and
        // netdev (where nfproto is the family itself).
        let l2 = matches!(family, Family::Bridge | Family::Netdev);
        let inet = family == Family::Inet;
        match self {
            Field::IpSaddr | Field::IpDaddr | Field::IpProtocol | Field::IpTtl if l2 => {
                Dep::EtherType(0x0800)
            }
            Field::Ip6Saddr | Field::Ip6Daddr | Field::Ip6Nexthdr if l2 => Dep::EtherType(0x86dd),
            Field::IpSaddr | Field::IpDaddr | Field::IpProtocol | Field::IpTtl if inet => {
                Dep::NfProto(NFPROTO_IPV4)
            }
            Field::Ip6Saddr | Field::Ip6Daddr | Field::Ip6Nexthdr if inet => {
                Dep::NfProto(NFPROTO_IPV6)
            }
            Field::TcpSport | Field::TcpDport => Dep::L4Proto(libc::IPPROTO_TCP as u8),
            Field::UdpSport | Field::UdpDport => Dep::L4Proto(libc::IPPROTO_UDP as u8),
            _ => Dep::None,
        }
    }

    /// The expression loading this field into `dreg`.
    pub fn load(&self, dreg: Reg) -> Expr {
        let p = |base, offset, len| {
            Expr::Payload(Payload {
                dreg: Some(dreg),
                base,
                offset,
                len,
                ..Default::default()
            })
        };
        let nh = PayloadBase::Network;
        let th = PayloadBase::Transport;
        let meta = |key| {
            Expr::Meta(Meta {
                dreg: Some(dreg),
                key,
                sreg: None,
            })
        };
        let ct = |key| {
            Expr::Ct(Ct {
                dreg: Some(dreg),
                key,
                direction: None,
                sreg: None,
            })
        };
        match *self {
            Field::IpSaddr => p(nh, 12, 4),
            Field::IpDaddr => p(nh, 16, 4),
            Field::IpProtocol => p(nh, 9, 1),
            Field::IpTtl => p(nh, 8, 1),
            Field::Ip6Saddr => p(nh, 8, 16),
            Field::Ip6Daddr => p(nh, 24, 16),
            Field::Ip6Nexthdr => p(nh, 6, 1),
            Field::TcpSport | Field::UdpSport | Field::ThSport => p(th, 0, 2),
            Field::TcpDport | Field::UdpDport | Field::ThDport => p(th, 2, 2),
            Field::L4Proto => meta(MetaKey::L4Proto),
            Field::NfProto => meta(MetaKey::NfProto),
            Field::Mark => meta(MetaKey::Mark),
            Field::Iif => meta(MetaKey::Iif),
            Field::Oif => meta(MetaKey::Oif),
            Field::IifName => meta(MetaKey::IifName),
            Field::OifName => meta(MetaKey::OifName),
            Field::SkUid => meta(MetaKey::SkUid),
            Field::SkGid => meta(MetaKey::SkGid),
            Field::CtState => ct(CtKey::State),
            Field::CtMark => ct(CtKey::Mark),
            Field::EtherSaddr => p(PayloadBase::LinkLayer, 6, 6),
            Field::EtherDaddr => p(PayloadBase::LinkLayer, 0, 6),
            Field::Payload { base, offset, len } => p(base, offset, len),
            Field::Meta(key, _) => meta(key),
            Field::Ct(key, dir) => Expr::Ct(Ct {
                dreg: Some(dreg),
                key,
                direction: dir.map(CtDir::raw),
                sreg: None,
            }),
        }
    }
}

/// Conversion of values into the byte representation of a field.
pub trait IntoValue {
    /// Encode `self` as a value of `field`: integers in host byte order for
    /// host byte order fields, big-endian otherwise.
    fn into_value(self, field: &Field) -> Vec<u8>;
}

impl IntoValue for Vec<u8> {
    fn into_value(self, _: &Field) -> Vec<u8> {
        self
    }
}
impl IntoValue for &[u8] {
    fn into_value(self, _: &Field) -> Vec<u8> {
        self.to_vec()
    }
}
impl<const N: usize> IntoValue for [u8; N] {
    fn into_value(self, _: &Field) -> Vec<u8> {
        self.to_vec()
    }
}
impl IntoValue for Ipv4Addr {
    fn into_value(self, _: &Field) -> Vec<u8> {
        self.octets().to_vec()
    }
}
impl IntoValue for Ipv6Addr {
    fn into_value(self, _: &Field) -> Vec<u8> {
        self.octets().to_vec()
    }
}
impl IntoValue for IpAddr {
    fn into_value(self, f: &Field) -> Vec<u8> {
        match self {
            IpAddr::V4(a) => a.into_value(f),
            IpAddr::V6(a) => a.into_value(f),
        }
    }
}
impl IntoValue for &str {
    /// Interface names are NUL padded to the field length.
    fn into_value(self, f: &Field) -> Vec<u8> {
        let mut v = self.as_bytes().to_vec();
        v.resize(f.len() as usize, 0);
        v
    }
}

macro_rules! int_value {
    ($($t:ty),*) => {$(
        impl IntoValue for $t {
            fn into_value(self, f: &Field) -> Vec<u8> {
                let len = f.len() as usize;
                let v = self as u64;
                if f.host_order() {
                    v.to_ne_bytes()[if cfg!(target_endian = "little") { 0..len.min(8) } else { 8 - len.min(8)..8 }].to_vec()
                } else {
                    v.to_be_bytes()[8 - len.min(8)..].to_vec()
                }
            }
        }
    )*};
}
int_value!(u8, u16, u32, u64);

/// The set key for values of the given fields: each value is sized to its
/// field and, in a concatenation, padded to a multiple of 4 bytes (see
/// [`concat_len`]).
pub fn concat_key(parts: &[(&Field, Vec<u8>)]) -> Vec<u8> {
    if let [(f, d)] = parts {
        let mut d = d.clone();
        d.resize(f.len() as usize, 0);
        return d;
    }
    let mut v = Vec::new();
    for (f, d) in parts {
        let mut d = d.clone();
        d.resize(f.len() as usize, 0);
        let padded = d.len().div_ceil(4) * 4;
        d.resize(padded, 0);
        v.extend_from_slice(&d);
    }
    v
}

/// The key length of a set keyed by `fields`: the field's length, or for a
/// concatenation the sum of the lengths padded to multiples of 4 bytes.
pub fn concat_len(fields: &[Field]) -> u32 {
    if fields.len() == 1 {
        fields[0].len()
    } else {
        fields.iter().map(|f| f.len().div_ceil(4) * 4).sum()
    }
}

/// Builds a [`Rule`] from the same expression sequences `nft` generates,
/// so that `nft list` displays it naturally.
///
/// ```
/// use crabtables::{Family, Field, RuleBuilder};
///
/// // tcp dport 22 counter accept
/// let rule = RuleBuilder::new(Family::Inet, "filter", "input")
///     .match_eq(Field::TcpDport, 22u16)
///     .counter()
///     .accept()
///     .build();
/// assert_eq!(rule.exprs.len(), 6);
/// ```
#[derive(Debug, Clone)]
pub struct RuleBuilder {
    rule: Rule,
    deps: Vec<Dep>,
}

impl RuleBuilder {
    /// Start a rule for the given chain.
    pub fn new(family: Family, table: impl Into<String>, chain: impl Into<String>) -> Self {
        RuleBuilder {
            rule: Rule::new(family, table, chain),
            deps: Vec::new(),
        }
    }

    /// The rule.
    pub fn build(self) -> Rule {
        self.rule
    }

    /// Append a raw expression.
    pub fn expr(mut self, e: impl Into<Expr>) -> Self {
        self.rule.exprs.push(e.into());
        self
    }

    /// Set an nft-compatible comment.
    pub fn comment(mut self, c: &str) -> Self {
        self.rule.userdata = Some(udata::comment(c));
        self
    }

    fn dep(mut self, d: Dep) -> Self {
        if d == Dep::None || self.deps.contains(&d) {
            return self;
        }
        self.deps.push(d);
        let (field, v) = match d {
            Dep::NfProto(p) => (Field::NfProto, vec![p]),
            Dep::EtherType(t) => (Field::Meta(MetaKey::Protocol, 2), t.to_be_bytes().to_vec()),
            Dep::L4Proto(p) => (Field::L4Proto, vec![p]),
            Dep::None => unreachable!(),
        };
        self.cmp_field(&field, CmpOp::Eq, v)
    }

    fn cmp_field(mut self, f: &Field, op: CmpOp, v: Vec<u8>) -> Self {
        self.rule.exprs.push(f.load(Reg::R1));
        self.rule.exprs.push(Expr::Cmp(Cmp {
            sreg: Reg::R1,
            op,
            data: v,
        }));
        self
    }

    /// Load `fields` into consecutive registers starting at [`Reg::R1`]
    /// (adding protocol dependencies first). Returns the key register.
    fn load_key(mut self, fields: &[Field]) -> Self {
        let family = self.rule.family;
        for f in fields {
            self = self.dep(f.dep(family));
        }
        let mut reg = Reg::R1;
        for f in fields {
            self.rule.exprs.push(f.load(reg));
            reg = reg.next_after(f.len());
        }
        self
    }

    /// Match `field == value`, e.g. `.match_eq(Field::TcpDport, 22u16)`.
    pub fn match_eq(self, field: Field, value: impl IntoValue) -> Self {
        self.match_cmp(field, CmpOp::Eq, value)
    }

    /// Match `field != value`.
    pub fn match_neq(self, field: Field, value: impl IntoValue) -> Self {
        self.match_cmp(field, CmpOp::Neq, value)
    }

    /// Match `field <op> value`. Note that `<`, `>` etc. compare bytes in
    /// memory order, which is correct for network byte order fields.
    ///
    /// Ordered comparisons of multi-byte host byte order values (e.g.
    /// `ct bytes > 1000`, `ct expiration < 10s`) convert the register to
    /// network byte order first, as nft does.
    pub fn match_cmp(mut self, field: Field, op: CmpOp, value: impl IntoValue) -> Self {
        let mut v = value.into_value(&field);
        let family = self.rule.family;
        self = self.dep(field.dep(family));
        let ordered = !matches!(op, CmpOp::Eq | CmpOp::Neq);
        let len = field.len();
        if ordered && field.host_order() && matches!(len, 2 | 4 | 8) {
            self.rule.exprs.push(field.load(Reg::R1));
            self.rule.exprs.push(Expr::Byteorder(Byteorder {
                sreg: Reg::R1,
                dreg: Reg::R1,
                op: ByteorderOp::Hton,
                len,
                size: len,
            }));
            if cfg!(target_endian = "little") {
                v.reverse();
            }
            self.rule.exprs.push(Expr::Cmp(Cmp {
                sreg: Reg::R1,
                op,
                data: v,
            }));
            return self;
        }
        self.cmp_field(&field, op, v)
    }

    /// Match `field & mask == value` (`ct mark and 0xff == 0x1`).
    pub fn match_masked(
        mut self,
        field: Field,
        mask: impl IntoValue,
        value: impl IntoValue,
    ) -> Self {
        let (mask, v) = (mask.into_value(&field), value.into_value(&field));
        let family = self.rule.family;
        self = self.dep(field.dep(family));
        self.rule.exprs.push(field.load(Reg::R1));
        self.rule.exprs.push(Expr::Bitwise(Bitwise {
            sreg: Reg::R1,
            dreg: Reg::R1,
            len: field.len(),
            op: Some(BitwiseOp::MaskXor),
            xor: Some(vec![0; mask.len()]),
            mask: Some(mask),
            data: None,
        }));
        self.rule.exprs.push(Expr::Cmp(Cmp {
            sreg: Reg::R1,
            op: CmpOp::Eq,
            data: v,
        }));
        self
    }

    /// Match if any of the flag `bits` are set in a bitmask field
    /// (`ct state new,established`, `ct status assured`).
    pub fn match_flags(mut self, field: Field, bits: impl IntoValue) -> Self {
        let bits = bits.into_value(&field);
        let family = self.rule.family;
        self = self.dep(field.dep(family));
        let n = bits.len();
        self.rule.exprs.push(field.load(Reg::R1));
        self.rule.exprs.push(Expr::Bitwise(Bitwise {
            sreg: Reg::R1,
            dreg: Reg::R1,
            len: field.len(),
            op: Some(BitwiseOp::MaskXor),
            mask: Some(bits),
            xor: Some(vec![0; n]),
            data: None,
        }));
        self.rule.exprs.push(Expr::Cmp(Cmp {
            sreg: Reg::R1,
            op: CmpOp::Neq,
            data: vec![0; n],
        }));
        self
    }

    /// Match an inclusive range `lo <= field <= hi` (`tcp dport 1000-2000`).
    pub fn match_range(mut self, field: Field, lo: impl IntoValue, hi: impl IntoValue) -> Self {
        let (lo, hi) = (lo.into_value(&field), hi.into_value(&field));
        let family = self.rule.family;
        self = self.dep(field.dep(family));
        self.rule.exprs.push(field.load(Reg::R1));
        self.rule.exprs.push(Expr::Range(Range {
            sreg: Reg::R1,
            op: RangeOp::Eq,
            from: lo,
            to: hi,
        }));
        self
    }

    /// Match the network prefix of an address field (`ip saddr 10.0.0.0/8`).
    pub fn match_prefix(mut self, field: Field, addr: impl IntoValue, prefix_len: u32) -> Self {
        let addr = addr.into_value(&field);
        let family = self.rule.family;
        self = self.dep(field.dep(family));
        let full = field.len();
        let bits = prefix_len.min(full * 8);
        if bits % 8 == 0 {
            // Byte aligned: load only the prefix bytes (as nft does).
            let n = bits / 8;
            let load = match field.load(Reg::R1) {
                Expr::Payload(mut p) => {
                    p.len = n;
                    Expr::Payload(p)
                }
                e => e,
            };
            self.rule.exprs.push(load);
            self.rule.exprs.push(Expr::Cmp(Cmp {
                sreg: Reg::R1,
                op: CmpOp::Eq,
                data: addr[..n as usize].to_vec(),
            }));
        } else {
            let mask = prefix_mask(full, bits);
            let masked: Vec<u8> = addr.iter().zip(&mask).map(|(a, m)| a & m).collect();
            self.rule.exprs.push(field.load(Reg::R1));
            self.rule.exprs.push(Expr::Bitwise(Bitwise {
                sreg: Reg::R1,
                dreg: Reg::R1,
                len: full,
                op: Some(BitwiseOp::MaskXor),
                mask: Some(mask),
                xor: Some(vec![0; full as usize]),
                data: None,
            }));
            self.rule.exprs.push(Expr::Cmp(Cmp {
                sreg: Reg::R1,
                op: CmpOp::Eq,
                data: masked,
            }));
        }
        self
    }

    /// Match raw payload bits, like nft's `@th,16,16 0x1234` (`base`,
    /// offset and length in **bits**). Non byte-aligned matches are masked
    /// as nft does. `value` is right-aligned in `bit_len` bits.
    ///
    /// # Panics
    ///
    /// If `bit_len` is 0 or greater than 64.
    pub fn match_bits(
        mut self,
        base: PayloadBase,
        bit_offset: u32,
        bit_len: u32,
        value: u64,
    ) -> Self {
        assert!(
            (1..=64).contains(&bit_len),
            "match_bits: bit_len must be within 1..=64"
        );
        let byte_off = bit_offset / 8;
        let shift = bit_offset % 8;
        let nbytes = (shift + bit_len).div_ceil(8);
        self.rule.exprs.push(Expr::Payload(Payload {
            dreg: Some(Reg::R1),
            base,
            offset: byte_off,
            len: nbytes,
            ..Default::default()
        }));
        // Bits of interest, left aligned at `shift` within `nbytes`.
        let total = nbytes * 8;
        let low = total - shift - bit_len;
        let to_bytes = |v: u128| -> Vec<u8> { v.to_be_bytes()[16 - nbytes as usize..].to_vec() };
        let maskv: u128 = ((1u128 << bit_len) - 1) << low;
        let val = (u128::from(value) << low) & maskv;
        if shift != 0 || bit_len % 8 != 0 {
            self.rule.exprs.push(Expr::Bitwise(Bitwise {
                sreg: Reg::R1,
                dreg: Reg::R1,
                len: nbytes,
                op: Some(BitwiseOp::MaskXor),
                mask: Some(to_bytes(maskv)),
                xor: Some(vec![0; nbytes as usize]),
                data: None,
            }));
        }
        self.rule.exprs.push(Expr::Cmp(Cmp {
            sreg: Reg::R1,
            op: CmpOp::Eq,
            data: to_bytes(val),
        }));
        self
    }

    /// Match conntrack state (`ct state established,related`), with
    /// `NF_CT_STATE_*_BIT` flags.
    pub fn ct_state(self, bits: u32) -> Self {
        self.match_flags(Field::CtState, bits)
    }

    /// Match conntrack status bits (`ct status assured`), with
    /// `IPS_*` bits (e.g. `1 << 2` for assured, `1 << 5` for dnat).
    pub fn ct_status(self, bits: u32) -> Self {
        self.match_flags(Field::Ct(CtKey::Status, None), bits)
    }

    /// Match if the (concatenated) key is in the named set.
    pub fn in_set(self, set: &str, key: &[Field]) -> Self {
        self.lookup(set, key, None, 0)
    }

    /// Match if the (concatenated) key is **not** in the named set.
    pub fn not_in_set(self, set: &str, key: &[Field]) -> Self {
        self.lookup(set, key, None, NFT_LOOKUP_F_INV)
    }

    /// Look up the key in a map, storing the value in `dreg`.
    pub fn map_lookup(self, set: &str, key: &[Field], dreg: Reg) -> Self {
        self.lookup(set, key, Some(dreg), 0)
    }

    /// Look up the key in a verdict map and apply the verdict (`vmap`).
    pub fn vmap(self, set: &str, key: &[Field]) -> Self {
        self.lookup(set, key, Some(Reg::VERDICT), 0)
    }

    fn lookup(mut self, set: &str, key: &[Field], dreg: Option<Reg>, flags: u32) -> Self {
        self = self.load_key(key);
        self.rule.exprs.push(Expr::Lookup(Lookup {
            set: set.to_owned(),
            set_id: None,
            sreg: Reg::R1,
            dreg,
            flags: Some(flags),
        }));
        self
    }

    /// Add the packet's `key` to a set, or update it (`add @set { ip saddr
    /// timeout 10s }`, `update @set { ... }`). `exprs` are stateful
    /// expressions for the element, such as [`limit_expr`] or [`Counter`].
    pub fn dynset(
        mut self,
        op: DynsetOp,
        set: &str,
        key: &[Field],
        timeout: Option<Duration>,
        exprs: Vec<Expr>,
    ) -> Self {
        self = self.load_key(key);
        self.rule.exprs.push(Expr::Dynset(Dynset {
            set_name: set.to_owned(),
            set_id: None,
            op,
            sreg_key: Reg::R1,
            sreg_data: None,
            timeout,
            flags: None,
            exprs,
        }));
        self
    }

    /// Generate a number (`numgen inc mod N offset O`) and use it as key of
    /// a verdict map.
    pub fn numgen_vmap(mut self, ty: NumgenType, modulus: u32, offset: u32, set: &str) -> Self {
        self.rule.exprs.push(Expr::Numgen(Numgen {
            dreg: Reg::R1,
            modulus,
            ty,
            offset: (offset != 0).then_some(offset),
        }));
        self.rule.exprs.push(Expr::Lookup(Lookup {
            set: set.to_owned(),
            set_id: None,
            sreg: Reg::R1,
            dreg: Some(Reg::VERDICT),
            flags: Some(0),
        }));
        self
    }

    /// Add a counter.
    pub fn counter(self) -> Self {
        self.expr(Counter::default())
    }

    /// Reference a named counter (`counter name "x"`).
    pub fn counter_named(self, name: &str) -> Self {
        self.expr(Objref {
            imm_type: Some(ObjType::Counter),
            imm_name: Some(name.to_owned()),
            ..Default::default()
        })
    }

    /// Match while under `rate` packets per `per` (`limit rate 10/second`).
    pub fn limit(self, rate: u64, per: Duration, burst: u32) -> Self {
        self.expr(limit_expr(rate, per, burst, LimitType::Packets, false))
    }

    /// Match while **over** `rate` packets per `per`
    /// (`limit rate over 10/second`).
    pub fn limit_over(self, rate: u64, per: Duration, burst: u32) -> Self {
        self.expr(limit_expr(rate, per, burst, LimitType::Packets, true))
    }

    /// Match while under `bytes` bytes per `per`.
    pub fn limit_bytes(self, bytes: u64, per: Duration, burst: u32) -> Self {
        self.expr(limit_expr(bytes, per, burst, LimitType::Bytes, false))
    }

    /// Match if the number of connections is at most `count`
    /// (`ct count 5`) or, with `over`, above it (`ct count over 5`).
    pub fn connlimit(self, count: u32, over: bool) -> Self {
        self.expr(Connlimit {
            count,
            flags: if over { NFT_CONNLIMIT_F_INV } else { 0 },
        })
    }

    /// Log to NFLOG group `group` (`log group N prefix "..."`).
    pub fn log_group(self, group: u16, prefix: Option<&str>) -> Self {
        self.expr(Log {
            group: Some(group),
            prefix: prefix.map(str::to_owned),
            ..Default::default()
        })
    }

    /// Log with the given log expression.
    pub fn log(self, l: Log) -> Self {
        self.expr(l)
    }

    /// Set the packet mark (`meta mark set 0x...`).
    pub fn set_mark(mut self, mark: u32) -> Self {
        self.rule.exprs.push(Expr::Immediate(Immediate {
            dreg: Reg::R1,
            data: Data::Value(mark.to_ne_bytes().to_vec()),
        }));
        self.rule.exprs.push(Expr::Meta(Meta {
            dreg: None,
            key: MetaKey::Mark,
            sreg: Some(Reg::R1),
        }));
        self
    }

    /// Set a conntrack key to a value (`ct mark set 0x10`, `ct zone set 3`,
    /// `ct event set new`). The value is encoded like the key's field.
    ///
    /// `ct zone set` must run before conntrack (a raw priority chain) in
    /// both directions to take effect.
    pub fn ct_set(mut self, key: CtKey, value: impl IntoValue) -> Self {
        let v = value.into_value(&Field::Ct(key, None));
        self.rule.exprs.push(Expr::Immediate(Immediate {
            dreg: Reg::R1,
            data: Data::Value(v),
        }));
        self.rule.exprs.push(Expr::Ct(Ct {
            dreg: None,
            key,
            direction: None,
            sreg: Some(Reg::R1),
        }));
        self
    }

    /// Set a conntrack key from a field (`ct mark set meta mark`).
    pub fn ct_set_from(mut self, key: CtKey, from: Field) -> Self {
        let family = self.rule.family;
        self = self.dep(from.dep(family));
        self.rule.exprs.push(from.load(Reg::R1));
        self.rule.exprs.push(Expr::Ct(Ct {
            dreg: None,
            key,
            direction: None,
            sreg: Some(Reg::R1),
        }));
        self
    }

    /// Set a meta key from a field (`meta mark set ct mark`).
    pub fn meta_set_from(mut self, key: MetaKey, from: Field) -> Self {
        let family = self.rule.family;
        self = self.dep(from.dep(family));
        self.rule.exprs.push(from.load(Reg::R1));
        self.rule.exprs.push(Expr::Meta(Meta {
            dreg: None,
            key,
            sreg: Some(Reg::R1),
        }));
        self
    }

    /// Set conntrack label `bit` (`ct label set 5`).
    pub fn ct_label_set(self, bit: u32) -> Self {
        let mut v = vec![0u8; 16];
        if let Some(b) = v.get_mut((bit / 8) as usize) {
            *b |= 1 << (bit % 8);
        }
        self.ct_set(CtKey::Labels, v)
    }

    /// Do not track the packet (`notrack`; raw priority chains).
    pub fn notrack(self) -> Self {
        self.expr(Notrack {})
    }

    fn objref(self, ty: ObjType, name: &str) -> Self {
        self.expr(Objref {
            imm_type: Some(ty),
            imm_name: Some(name.to_owned()),
            ..Default::default()
        })
    }

    /// Assign a conntrack helper object (`ct helper set "ftp"`).
    pub fn ct_helper(self, name: &str) -> Self {
        self.objref(ObjType::CtHelper, name)
    }

    /// Assign a conntrack timeout policy object (`ct timeout set "x"`).
    ///
    /// Only affects new, not yet confirmed connections: use it in a chain
    /// that runs after conntrack (priority above -200, e.g. filter
    /// `output`/`prerouting`), not in a raw chain.
    pub fn ct_timeout(self, name: &str) -> Self {
        self.objref(ObjType::CtTimeout, name)
    }

    /// Create an expectation from an expectation object (`ct expectation set "x"`).
    ///
    /// Like timeouts, this only acts on new, unconfirmed connections.
    pub fn ct_expectation(self, name: &str) -> Self {
        self.objref(ObjType::CtExpect, name)
    }

    /// Use a named quota (`quota name "x"`).
    pub fn quota_named(self, name: &str) -> Self {
        self.objref(ObjType::Quota, name)
    }

    /// Use a named limit (`limit name "x"`).
    pub fn limit_named(self, name: &str) -> Self {
        self.objref(ObjType::Limit, name)
    }

    /// Destination NAT to `addr` and optionally `port`
    /// (`dnat ip to 10.0.0.1:80`; nat chains only).
    pub fn dnat(self, addr: IpAddr, port: Option<u16>) -> Self {
        self.nat(NatType::Dnat, Some((addr, addr)), port.map(|p| (p, p)), 0)
    }

    /// Source NAT to `addr` and optionally `port` (`snat ip to 10.0.0.1`).
    pub fn snat(self, addr: IpAddr, port: Option<u16>) -> Self {
        self.nat(NatType::Snat, Some((addr, addr)), port.map(|p| (p, p)), 0)
    }

    /// General NAT: address range, port range and `NF_NAT_RANGE_*` flags
    /// (`snat ip to 1.2.3.4-1.2.3.10:1000-2000 random,persistent`).
    pub fn nat(
        mut self,
        ty: NatType,
        addrs: Option<(IpAddr, IpAddr)>,
        ports: Option<(u16, u16)>,
        flags: u32,
    ) -> Self {
        let mut nat = Nat {
            ty,
            ..Default::default()
        };
        nat.family = match addrs {
            Some((IpAddr::V6(_), _)) => u32::from(NFPROTO_IPV6),
            _ => match self.rule.family {
                Family::Ipv6 => u32::from(NFPROTO_IPV6),
                _ => u32::from(NFPROTO_IPV4),
            },
        };
        let mut reg = 1;
        let mut imm = |s: &mut Self, v: Vec<u8>| -> Reg {
            let r = Reg(reg);
            reg += 1;
            s.rule.exprs.push(Expr::Immediate(Immediate {
                dreg: r,
                data: Data::Value(v),
            }));
            r
        };
        let ip = |a: IpAddr| a.into_value(&Field::IpSaddr);
        if let Some((lo, hi)) = addrs {
            nat.reg_addr_min = Some(imm(&mut self, ip(lo)));
            if hi != lo {
                nat.reg_addr_max = Some(imm(&mut self, ip(hi)));
            }
        }
        let mut flags = flags;
        if let Some((lo, hi)) = ports {
            nat.reg_proto_min = Some(imm(&mut self, lo.to_be_bytes().to_vec()));
            if hi != lo {
                nat.reg_proto_max = Some(imm(&mut self, hi.to_be_bytes().to_vec()));
            }
            flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
        }
        nat.flags = (flags != 0).then_some(flags);
        self.expr(nat)
    }

    /// Masquerade (`masquerade`, `masquerade random`), with
    /// `NF_NAT_RANGE_*` flags.
    pub fn masquerade(self, flags: u32) -> Self {
        self.expr(Masq {
            flags: (flags != 0).then_some(flags),
            ..Default::default()
        })
    }

    /// Redirect to the local host, optionally to `port` (`redirect to :8080`).
    pub fn redirect(mut self, port: Option<u16>) -> Self {
        let mut r = Redir::default();
        if let Some(p) = port {
            self.rule.exprs.push(Expr::Immediate(Immediate {
                dreg: Reg::R1,
                data: Data::Value(p.to_be_bytes().to_vec()),
            }));
            r.reg_proto_min = Some(Reg::R1);
            r.flags = Some(NF_NAT_RANGE_PROTO_SPECIFIED);
        }
        self.expr(r)
    }

    /// Send the packet to NFQUEUE queue `first` (or, with `count` > 1, to
    /// one of `first..first+count`), with `NFT_QUEUE_FLAG_*` flags
    /// (`queue flags bypass,fanout to 3-4`). See [`crate::nfqueue`].
    pub fn queue(self, first: u16, count: u16, flags: u16) -> Self {
        self.expr(Queue {
            num: Some(first),
            total: Some(count.max(1)),
            flags: (flags != 0).then_some(flags),
            sreg_qnum: None,
        })
    }

    /// Reject with a TCP reset (implies `meta l4proto tcp`).
    pub fn reject_tcp_reset(self) -> Self {
        self.dep(Dep::L4Proto(libc::IPPROTO_TCP as u8))
            .expr(Reject {
                ty: RejectType::TcpRst,
                icmp_code: None,
            })
    }

    /// Reject with a family independent ICMP code (`NFT_REJECT_ICMPX_*`).
    pub fn reject_icmpx(self, code: u8) -> Self {
        self.expr(Reject {
            ty: RejectType::IcmpxUnreach,
            icmp_code: Some(code),
        })
    }

    /// Apply a verdict.
    pub fn verdict(self, v: Verdict) -> Self {
        self.expr(Immediate {
            dreg: Reg::VERDICT,
            data: Data::Verdict(v),
        })
    }

    /// `accept`
    pub fn accept(self) -> Self {
        self.verdict(Verdict::Accept)
    }

    /// `drop`
    pub fn drop(self) -> Self {
        self.verdict(Verdict::Drop)
    }

    /// `jump chain`
    pub fn jump(self, chain: &str) -> Self {
        self.verdict(Verdict::Jump(chain.to_owned()))
    }

    /// `goto chain`
    pub fn goto(self, chain: &str) -> Self {
        self.verdict(Verdict::Goto(chain.to_owned()))
    }

    /// `return`
    pub fn ret(self) -> Self {
        self.verdict(Verdict::Return)
    }
}

/// A `limit` expression for `rate` per `per`.
pub fn limit_expr(rate: u64, per: Duration, burst: u32, ty: LimitType, over: bool) -> Limit {
    Limit {
        rate,
        unit: per.as_secs().max(1),
        burst,
        ty,
        flags: if over { NFT_LIMIT_F_INV } else { 0 },
    }
}

fn prefix_mask(len: u32, bits: u32) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let start = i * 8;
            if bits >= start + 8 {
                0xff
            } else if bits <= start {
                0
            } else {
                0xffu8 << (8 - (bits - start))
            }
        })
        .collect()
}

impl crate::objects::Set {
    /// A set keyed by the given (possibly concatenated) fields: sets the key
    /// type, length, field lengths and the byte order hint `nft` needs to
    /// display host byte order keys such as marks.
    pub fn keyed(
        family: Family,
        table: impl Into<String>,
        name: impl Into<String>,
        key: &[Field],
    ) -> Self {
        crate::objects::Set::new(family, table, name, 0, 0).with_key(key)
    }

    /// Set the key from fields (see [`Set::keyed`](crate::Set::keyed)).
    pub fn with_key(mut self, key: &[Field]) -> Self {
        let types: Vec<u32> = key.iter().map(Field::datatype).collect();
        self.key_type = crate::objects::datatype::concat(&types);
        self.key_len = concat_len(key);
        if key.len() > 1 {
            self.flags |= NFT_SET_CONCAT;
            self.field_lens = key.iter().map(Field::len).collect();
        } else {
            self.field_lens.clear();
        }
        let order = if key.len() == 1 {
            nft_byteorder(&key[0])
        } else {
            udata::BYTEORDER_BIG
        };
        self.userdata = Some(set_udata(
            self.userdata.take(),
            udata::UDATA_SET_KEYBYTEORDER,
            order,
        ));
        self
    }

    /// Make this a map whose values are of the given field's type (e.g.
    /// `Field::Mark` for `ip saddr map { ... : 0x1 }`).
    pub fn with_map_data(mut self, data: Field) -> Self {
        self.flags |= NFT_SET_MAP;
        self.data_type = Some(data.datatype());
        self.data_len = Some(data.len());
        let order = nft_byteorder(&data);
        self.userdata = Some(set_udata(
            self.userdata.take(),
            udata::UDATA_SET_DATABYTEORDER,
            order,
        ));
        self
    }
}

/// The byte order nft associates with a field's values (strings count as
/// host order).
fn nft_byteorder(f: &Field) -> u32 {
    if f.host_order() || matches!(f, Field::IifName | Field::OifName) {
        udata::BYTEORDER_HOST
    } else {
        udata::BYTEORDER_BIG
    }
}

/// Replace (or add) a u32 entry in set user data.
fn set_udata(old: Option<Vec<u8>>, ty: u8, v: u32) -> Vec<u8> {
    let mut u = udata::Udata::new();
    if let Some(old) = old {
        for (t, val) in udata::iter(&old) {
            if t != ty {
                u.push(t, val);
            }
        }
    }
    u.push_u32(ty, v);
    u.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(22u16.into_value(&Field::TcpDport), vec![0, 22]);
        assert_eq!(1u32.into_value(&Field::Mark), 1u32.to_ne_bytes().to_vec());
        assert_eq!("lo".into_value(&Field::IifName).len(), 16);
        assert_eq!(prefix_mask(4, 20), vec![0xff, 0xff, 0xf0, 0]);
        assert_eq!(concat_len(&[Field::IpSaddr, Field::TcpDport]), 8);
        assert_eq!(
            concat_key(&[
                (&Field::IpSaddr, vec![1, 2, 3, 4]),
                (&Field::TcpDport, vec![0, 80])
            ]),
            vec![1, 2, 3, 4, 0, 80, 0, 0]
        );
        assert_eq!(Reg::R1.next_after(4), Reg::r32(1));
        assert_eq!(Reg::R1.next_after(16), Reg::r32(4));
    }
}
