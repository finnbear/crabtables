//! Common value types: families, registers, verdicts, data and typed
//! enumerations of kernel constants.

use crate::error::{Error, Result};
use crate::nl::{Attr, Attrs, Writer};
use crate::sys::*;

/// Netfilter protocol family of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Family {
    /// `AF_UNSPEC`: only valid for requests spanning all families.
    Unspec = NFPROTO_UNSPEC,
    /// `inet` (IPv4 + IPv6).
    #[default]
    Inet = NFPROTO_INET,
    /// `ip`.
    Ipv4 = NFPROTO_IPV4,
    /// `arp`.
    Arp = NFPROTO_ARP,
    /// `netdev`.
    Netdev = NFPROTO_NETDEV,
    /// `bridge`.
    Bridge = NFPROTO_BRIDGE,
    /// `ip6`.
    Ipv6 = NFPROTO_IPV6,
}

impl Family {
    /// All concrete families (excluding [`Family::Unspec`]).
    pub const ALL: [Family; 6] = [
        Family::Inet,
        Family::Ipv4,
        Family::Arp,
        Family::Netdev,
        Family::Bridge,
        Family::Ipv6,
    ];

    /// Convert from the raw value.
    pub fn from_raw(v: u8) -> Result<Self> {
        Ok(match v {
            NFPROTO_UNSPEC => Family::Unspec,
            NFPROTO_INET => Family::Inet,
            NFPROTO_IPV4 => Family::Ipv4,
            NFPROTO_ARP => Family::Arp,
            NFPROTO_NETDEV => Family::Netdev,
            NFPROTO_BRIDGE => Family::Bridge,
            NFPROTO_IPV6 => Family::Ipv6,
            _ => return Err(Error::malformed("unknown protocol family")),
        })
    }

    /// The raw value.
    pub fn raw(self) -> u8 {
        self as u8
    }

    /// The name used by `nft` (`inet`, `ip`, `ip6`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Family::Unspec => "unspec",
            Family::Inet => "inet",
            Family::Ipv4 => "ip",
            Family::Arp => "arp",
            Family::Netdev => "netdev",
            Family::Bridge => "bridge",
            Family::Ipv6 => "ip6",
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// An nf_tables register.
///
/// Registers 1-4 are 16 bytes wide; the 32-bit registers `r32(0..16)` alias
/// the same storage (`Reg::R1` == `r32(0..4)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Reg(pub u32);

impl Reg {
    /// The verdict register.
    pub const VERDICT: Reg = Reg(NFT_REG_VERDICT);
    /// 128-bit register 1.
    pub const R1: Reg = Reg(NFT_REG_1);
    /// 128-bit register 2.
    pub const R2: Reg = Reg(NFT_REG_2);
    /// 128-bit register 3.
    pub const R3: Reg = Reg(NFT_REG_3);
    /// 128-bit register 4.
    pub const R4: Reg = Reg(NFT_REG_4);

    /// 32-bit register `n` (0..16).
    pub const fn r32(n: u32) -> Reg {
        Reg(NFT_REG32_00 + n)
    }

    /// Offset of this register in 32-bit words from the start of register
    /// storage (excluding the verdict register), if it is a data register.
    pub fn word_index(self) -> Option<u32> {
        match self.0 {
            1..=4 => Some((self.0 - 1) * 4),
            8..=23 => Some(self.0 - 8),
            _ => None,
        }
    }

    /// The register that follows a value of `len` bytes stored in this one,
    /// as used when loading concatenations. Always returns a 32-bit register.
    pub fn next_after(self, len: u32) -> Reg {
        let w = self.word_index().unwrap_or(0);
        Reg::r32(w + len.div_ceil(4))
    }
}

/// A verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Verdict {
    /// Accept the packet.
    Accept,
    /// Drop the packet.
    Drop,
    /// Queue the packet (the queue number is encoded in the upper 16 bits
    /// of the verdict code; use the `queue` expression instead for nft-style
    /// queueing).
    Queue,
    /// Continue with the next rule.
    Continue,
    /// Stop evaluating the current rule.
    Break,
    /// Return from the current chain.
    Return,
    /// Jump to a chain, returning afterwards.
    Jump(String),
    /// Go to a chain without returning.
    Goto(String),
    /// Jump to a chain created in the same batch, by chain id.
    JumpId(u32),
    /// Go to a chain created in the same batch, by chain id.
    GotoId(u32),
    /// Any other raw verdict code.
    Other(i32),
}

impl Verdict {
    /// The raw verdict code.
    pub fn code(&self) -> i32 {
        match self {
            Verdict::Accept => NF_ACCEPT,
            Verdict::Drop => NF_DROP,
            Verdict::Queue => NF_QUEUE,
            Verdict::Continue => NFT_CONTINUE,
            Verdict::Break => NFT_BREAK,
            Verdict::Return => NFT_RETURN,
            Verdict::Jump(_) | Verdict::JumpId(_) => NFT_JUMP,
            Verdict::Goto(_) | Verdict::GotoId(_) => NFT_GOTO,
            Verdict::Other(c) => *c,
        }
    }

    /// The raw code as used for a base chain policy.
    pub(crate) fn from_policy(code: u32) -> Verdict {
        match code as i32 {
            NF_ACCEPT => Verdict::Accept,
            NF_DROP => Verdict::Drop,
            c => Verdict::Other(c),
        }
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        w.put_be32(NFTA_VERDICT_CODE, self.code() as u32);
        match self {
            Verdict::Jump(c) | Verdict::Goto(c) => w.put_str(NFTA_VERDICT_CHAIN, c),
            Verdict::JumpId(id) | Verdict::GotoId(id) => w.put_be32(NFTA_VERDICT_CHAIN_ID, *id),
            _ => {}
        }
    }

    /// Decode the content of an `NFTA_DATA_VERDICT` nest.
    pub fn decode(attrs: Attrs<'_>) -> Result<Verdict> {
        let mut code = None;
        let mut chain = None;
        let mut chain_id = None;
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_VERDICT_CODE => code = Some(a.be32()? as i32),
                NFTA_VERDICT_CHAIN => chain = Some(a.string()?),
                NFTA_VERDICT_CHAIN_ID => chain_id = Some(a.be32()?),
                _ => {}
            }
        }
        let code = code.ok_or_else(|| Error::malformed("verdict without code"))?;
        Ok(match (code, chain, chain_id) {
            (NF_ACCEPT, ..) => Verdict::Accept,
            (NF_DROP, ..) => Verdict::Drop,
            (NF_QUEUE, ..) => Verdict::Queue,
            (NFT_CONTINUE, ..) => Verdict::Continue,
            (NFT_BREAK, ..) => Verdict::Break,
            (NFT_RETURN, ..) => Verdict::Return,
            (NFT_JUMP, Some(c), _) => Verdict::Jump(c),
            (NFT_GOTO, Some(c), _) => Verdict::Goto(c),
            (NFT_JUMP, None, Some(id)) => Verdict::JumpId(id),
            (NFT_GOTO, None, Some(id)) => Verdict::GotoId(id),
            (c, ..) => Verdict::Other(c),
        })
    }
}

/// Data carried in a register, set element key or map value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Data {
    /// Raw bytes (at most 64).
    Value(Vec<u8>),
    /// A verdict.
    Verdict(Verdict),
}

impl Default for Data {
    fn default() -> Self {
        Data::Value(Vec::new())
    }
}

impl From<Verdict> for Data {
    fn from(v: Verdict) -> Self {
        Data::Verdict(v)
    }
}

impl From<Vec<u8>> for Data {
    fn from(v: Vec<u8>) -> Self {
        Data::Value(v)
    }
}

impl From<&[u8]> for Data {
    fn from(v: &[u8]) -> Self {
        Data::Value(v.to_vec())
    }
}

impl Data {
    /// Encode the *contents* of an `NFTA_DATA_*` nest.
    pub(crate) fn encode(&self, w: &mut Writer) {
        match self {
            Data::Value(v) => w.put(NFTA_DATA_VALUE, v),
            Data::Verdict(v) => w.nest(NFTA_DATA_VERDICT, |w| v.encode(w)),
        }
    }

    pub(crate) fn decode(attrs: Attrs<'_>) -> Result<Data> {
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_DATA_VALUE => return Ok(Data::Value(a.data.to_vec())),
                NFTA_DATA_VERDICT => return Ok(Data::Verdict(Verdict::decode(a.nested())?)),
                _ => {}
            }
        }
        Err(Error::malformed("empty data attribute"))
    }

    /// The raw value, if this is not a verdict.
    pub fn as_value(&self) -> Option<&[u8]> {
        match self {
            Data::Value(v) => Some(v),
            Data::Verdict(_) => None,
        }
    }

    /// The verdict, if this is one.
    pub fn as_verdict(&self) -> Option<&Verdict> {
        match self {
            Data::Verdict(v) => Some(v),
            Data::Value(_) => None,
        }
    }
}

// ------------------------------------------------------------- attr codecs

/// Types that can be encoded as a single attribute.
pub(crate) trait AttrValue: Sized {
    fn put(&self, w: &mut Writer, ty: u16);
    fn get(a: &Attr<'_>) -> Result<Self>;
}

impl AttrValue for u8 {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_u8(ty, *self)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.u8()
    }
}
impl AttrValue for u16 {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be16(ty, *self)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be16()
    }
}
impl AttrValue for u32 {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be32(ty, *self)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be32()
    }
}
impl AttrValue for i32 {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be32(ty, *self as u32)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be32().map(|v| v as i32)
    }
}
impl AttrValue for u64 {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be64(ty, *self)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be64()
    }
}
impl AttrValue for String {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_str(ty, self)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.string()
    }
}
impl AttrValue for Reg {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be32(ty, self.0)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be32().map(Reg)
    }
}
impl AttrValue for Data {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.nest(ty, |w| self.encode(w))
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        Data::decode(a.nested())
    }
}

/// Raw binary attribute payload (e.g. user data).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bytes(pub Vec<u8>);

impl AttrValue for Bytes {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put(ty, &self.0)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        Ok(Bytes(a.data.to_vec()))
    }
}

/// Field encoding used by the expression macros: plain values are always
/// encoded, `Option`s only when present.
pub(crate) trait Field {
    fn put_field(&self, w: &mut Writer, ty: u16);
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()>;
}

impl<T: AttrValue> Field for T {
    fn put_field(&self, w: &mut Writer, ty: u16) {
        self.put(w, ty)
    }
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()> {
        *self = T::get(a)?;
        Ok(())
    }
}

impl<T: AttrValue> Field for Option<T> {
    fn put_field(&self, w: &mut Writer, ty: u16) {
        if let Some(v) = self {
            v.put(w, ty)
        }
    }
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()> {
        *self = Some(T::get(a)?);
        Ok(())
    }
}

/// Byte value stored in a nested `NFTA_DATA_VALUE` (used for compare
/// operands, bitwise masks, ...).
pub(crate) trait ValueField {
    fn put_field(&self, w: &mut Writer, ty: u16);
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()>;
}

fn decode_value(a: &Attr<'_>) -> Result<Vec<u8>> {
    match Data::decode(a.nested())? {
        Data::Value(v) => Ok(v),
        Data::Verdict(_) => Err(Error::malformed("expected value, got verdict")),
    }
}

impl ValueField for Vec<u8> {
    fn put_field(&self, w: &mut Writer, ty: u16) {
        w.nest(ty, |w| w.put(NFTA_DATA_VALUE, self))
    }
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()> {
        *self = decode_value(a)?;
        Ok(())
    }
}

impl ValueField for Option<Vec<u8>> {
    fn put_field(&self, w: &mut Writer, ty: u16) {
        if let Some(v) = self {
            w.nest(ty, |w| w.put(NFTA_DATA_VALUE, v))
        }
    }
    fn set_field(&mut self, a: &Attr<'_>) -> Result<()> {
        *self = Some(decode_value(a)?);
        Ok(())
    }
}

/// Define a `u32`-backed enum with an `Other` fallback.
macro_rules! u32_enum {
    ($(#[$m:meta])* pub enum $name:ident { $($(#[$vm:meta])* $var:ident = $val:expr,)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $($(#[$vm])* $var,)*
            /// A value not known to this crate.
            Other(u32),
        }

        impl $name {
            /// Convert from the raw value.
            pub fn from_raw(v: u32) -> Self {
                #[allow(unreachable_patterns)]
                match v {
                    $(x if x == $val => $name::$var,)*
                    v => $name::Other(v),
                }
            }

            /// The raw value.
            pub fn raw(self) -> u32 {
                match self {
                    $($name::$var => $val,)*
                    $name::Other(v) => v,
                }
            }
        }

        impl From<u32> for $name {
            fn from(v: u32) -> Self {
                Self::from_raw(v)
            }
        }

        impl From<$name> for u32 {
            fn from(v: $name) -> u32 {
                v.raw()
            }
        }

        impl AttrValue for $name {
            fn put(&self, w: &mut Writer, ty: u16) {
                w.put_be32(ty, self.raw())
            }
            fn get(a: &Attr<'_>) -> Result<Self> {
                a.be32().map(Self::from_raw)
            }
        }
    };
}

u32_enum! {
    /// Comparison operator of the `cmp` expression.
    pub enum CmpOp {
        /// `==`
        #[default]
        Eq = NFT_CMP_EQ,
        /// `!=`
        Neq = NFT_CMP_NEQ,
        /// `<`
        Lt = NFT_CMP_LT,
        /// `<=`
        Lte = NFT_CMP_LTE,
        /// `>`
        Gt = NFT_CMP_GT,
        /// `>=`
        Gte = NFT_CMP_GTE,
    }
}

u32_enum! {
    /// Operator of the `range` expression.
    pub enum RangeOp {
        /// Value within range.
        #[default]
        Eq = NFT_RANGE_EQ,
        /// Value outside range.
        Neq = NFT_RANGE_NEQ,
    }
}

u32_enum! {
    /// Header base of a `payload` expression.
    pub enum PayloadBase {
        /// Link layer header (`@ll`).
        LinkLayer = NFT_PAYLOAD_LL_HEADER,
        /// Network header (`@nh`).
        #[default]
        Network = NFT_PAYLOAD_NETWORK_HEADER,
        /// Transport header (`@th`).
        Transport = NFT_PAYLOAD_TRANSPORT_HEADER,
        /// Inner header (`@ih`).
        Inner = NFT_PAYLOAD_INNER_HEADER,
        /// Tunnel header.
        Tunnel = NFT_PAYLOAD_TUN_HEADER,
    }
}

u32_enum! {
    /// Key of the `meta` expression.
    pub enum MetaKey {
        /// Packet length.
        #[default]
        Len = NFT_META_LEN,
        /// Ethertype protocol.
        Protocol = NFT_META_PROTOCOL,
        /// TC packet priority.
        Priority = NFT_META_PRIORITY,
        /// Packet mark.
        Mark = NFT_META_MARK,
        /// Input interface index.
        Iif = NFT_META_IIF,
        /// Output interface index.
        Oif = NFT_META_OIF,
        /// Input interface name.
        IifName = NFT_META_IIFNAME,
        /// Output interface name.
        OifName = NFT_META_OIFNAME,
        /// Input interface type.
        IifType = NFT_META_IIFTYPE,
        /// Output interface type.
        OifType = NFT_META_OIFTYPE,
        /// Socket UID.
        SkUid = NFT_META_SKUID,
        /// Socket GID.
        SkGid = NFT_META_SKGID,
        /// Packet trace flag.
        NfTrace = NFT_META_NFTRACE,
        /// Routing realm.
        RtClassId = NFT_META_RTCLASSID,
        /// Security mark.
        Secmark = NFT_META_SECMARK,
        /// Netfilter protocol (IPv4/IPv6 within `inet`).
        NfProto = NFT_META_NFPROTO,
        /// Layer 4 protocol.
        L4Proto = NFT_META_L4PROTO,
        /// Bridge input interface name.
        BriIifName = NFT_META_BRI_IIFNAME,
        /// Bridge output interface name.
        BriOifName = NFT_META_BRI_OIFNAME,
        /// Packet type (unicast, broadcast, ...).
        PktType = NFT_META_PKTTYPE,
        /// CPU number.
        Cpu = NFT_META_CPU,
        /// Input interface group.
        IifGroup = NFT_META_IIFGROUP,
        /// Output interface group.
        OifGroup = NFT_META_OIFGROUP,
        /// Socket control group id.
        Cgroup = NFT_META_CGROUP,
        /// Pseudo random number.
        Prandom = NFT_META_PRANDOM,
        /// Whether the packet has a secpath (IPsec).
        Secpath = NFT_META_SECPATH,
        /// Input interface kind.
        IifKind = NFT_META_IIFKIND,
        /// Output interface kind.
        OifKind = NFT_META_OIFKIND,
        /// Bridge port PVID.
        BriIifPvid = NFT_META_BRI_IIFPVID,
        /// Bridge port VLAN protocol.
        BriIifVproto = NFT_META_BRI_IIFVPROTO,
        /// Time in nanoseconds since the epoch.
        TimeNs = NFT_META_TIME_NS,
        /// Day of week.
        TimeDay = NFT_META_TIME_DAY,
        /// Seconds since midnight.
        TimeHour = NFT_META_TIME_HOUR,
        /// Index of the VRF slave device the packet arrived through.
        Sdif = NFT_META_SDIF,
        /// Name of the VRF slave device the packet arrived through.
        SdifName = NFT_META_SDIFNAME,
        /// Bridge `broute` (route instead of bridging the packet).
        BriBroute = NFT_META_BRI_BROUTE,
    }
}

u32_enum! {
    /// Key of the `ct` expression.
    pub enum CtKey {
        /// Connection state bitmask.
        #[default]
        State = NFT_CT_STATE,
        /// Packet direction.
        Direction = NFT_CT_DIRECTION,
        /// Status bits.
        Status = NFT_CT_STATUS,
        /// Connection mark.
        Mark = NFT_CT_MARK,
        /// Security mark.
        Secmark = NFT_CT_SECMARK,
        /// Remaining lifetime.
        Expiration = NFT_CT_EXPIRATION,
        /// Helper name.
        Helper = NFT_CT_HELPER,
        /// Layer 3 protocol.
        L3Protocol = NFT_CT_L3PROTOCOL,
        /// Source address (direction dependent).
        Src = NFT_CT_SRC,
        /// Destination address (direction dependent).
        Dst = NFT_CT_DST,
        /// Layer 4 protocol.
        Protocol = NFT_CT_PROTOCOL,
        /// Source port.
        ProtoSrc = NFT_CT_PROTO_SRC,
        /// Destination port.
        ProtoDst = NFT_CT_PROTO_DST,
        /// Labels.
        Labels = NFT_CT_LABELS,
        /// Packet count.
        Pkts = NFT_CT_PKTS,
        /// Byte count.
        Bytes = NFT_CT_BYTES,
        /// Average packet size.
        AvgPkt = NFT_CT_AVGPKT,
        /// Zone.
        Zone = NFT_CT_ZONE,
        /// Event mask.
        EventMask = NFT_CT_EVENTMASK,
        /// IPv4 source address.
        SrcIp = NFT_CT_SRC_IP,
        /// IPv4 destination address.
        DstIp = NFT_CT_DST_IP,
        /// IPv6 source address.
        SrcIp6 = NFT_CT_SRC_IP6,
        /// IPv6 destination address.
        DstIp6 = NFT_CT_DST_IP6,
        /// Conntrack id.
        Id = NFT_CT_ID,
    }
}

u32_enum! {
    /// Operation of the `dynset` expression.
    pub enum DynsetOp {
        /// Add the element if it does not exist.
        #[default]
        Add = NFT_DYNSET_OP_ADD,
        /// Add or refresh the element.
        Update = NFT_DYNSET_OP_UPDATE,
        /// Delete the element.
        Delete = NFT_DYNSET_OP_DELETE,
    }
}

u32_enum! {
    /// Type of the `limit` expression.
    pub enum LimitType {
        /// Packets per unit.
        #[default]
        Packets = NFT_LIMIT_PKTS,
        /// Bytes per unit.
        Bytes = NFT_LIMIT_PKT_BYTES,
    }
}

u32_enum! {
    /// Type of the `numgen` expression.
    pub enum NumgenType {
        /// Incrementing counter.
        #[default]
        Incremental = NFT_NG_INCREMENTAL,
        /// Random.
        Random = NFT_NG_RANDOM,
    }
}

u32_enum! {
    /// Type of the `hash` expression.
    pub enum HashType {
        /// Jenkins hash of the source register.
        #[default]
        Jenkins = NFT_HASH_JENKINS,
        /// Symmetric hash of the flow.
        Symmetric = NFT_HASH_SYM,
    }
}

u32_enum! {
    /// Type of the `nat` expression.
    pub enum NatType {
        /// Source NAT.
        #[default]
        Snat = NFT_NAT_SNAT,
        /// Destination NAT.
        Dnat = NFT_NAT_DNAT,
    }
}

u32_enum! {
    /// Type of the `reject` expression.
    pub enum RejectType {
        /// ICMP unreachable with a family specific code.
        #[default]
        IcmpUnreach = NFT_REJECT_ICMP_UNREACH,
        /// TCP reset.
        TcpRst = NFT_REJECT_TCP_RST,
        /// Family independent ICMP unreachable.
        IcmpxUnreach = NFT_REJECT_ICMPX_UNREACH,
    }
}

u32_enum! {
    /// Operation of the `byteorder` expression.
    pub enum ByteorderOp {
        /// Network to host.
        #[default]
        Ntoh = NFT_BYTEORDER_NTOH,
        /// Host to network.
        Hton = NFT_BYTEORDER_HTON,
    }
}

u32_enum! {
    /// Operation of the `bitwise` expression.
    pub enum BitwiseOp {
        /// `(reg & mask) ^ xor`
        #[default]
        MaskXor = NFT_BITWISE_MASK_XOR,
        /// Left shift.
        Lshift = NFT_BITWISE_LSHIFT,
        /// Right shift.
        Rshift = NFT_BITWISE_RSHIFT,
    }
}

u32_enum! {
    /// Operation of the `exthdr` expression.
    pub enum ExthdrOp {
        /// IPv6 extension header.
        #[default]
        Ipv6 = NFT_EXTHDR_OP_IPV6,
        /// TCP option.
        TcpOpt = NFT_EXTHDR_OP_TCPOPT,
        /// IPv4 option.
        Ipv4 = NFT_EXTHDR_OP_IPV4,
        /// SCTP chunk.
        Sctp = NFT_EXTHDR_OP_SCTP,
        /// DCCP option.
        Dccp = NFT_EXTHDR_OP_DCCP,
    }
}

u32_enum! {
    /// Result type of the `fib` expression.
    pub enum FibResult {
        /// Output interface index.
        #[default]
        Oif = NFT_FIB_RESULT_OIF,
        /// Output interface name.
        OifName = NFT_FIB_RESULT_OIFNAME,
        /// Address type.
        AddrType = NFT_FIB_RESULT_ADDRTYPE,
    }
}

u32_enum! {
    /// Key of the `rt` expression.
    pub enum RtKey {
        /// Routing realm.
        #[default]
        ClassId = NFT_RT_CLASSID,
        /// IPv4 next hop.
        Nexthop4 = NFT_RT_NEXTHOP4,
        /// IPv6 next hop.
        Nexthop6 = NFT_RT_NEXTHOP6,
        /// TCP MSS of the route.
        TcpMss = NFT_RT_TCPMSS,
        /// Whether the route has an xfrm.
        Xfrm = NFT_RT_XFRM,
    }
}

u32_enum! {
    /// Key of the `socket` expression.
    pub enum SocketKey {
        /// Transparent socket flag.
        #[default]
        Transparent = NFT_SOCKET_TRANSPARENT,
        /// Socket mark.
        Mark = NFT_SOCKET_MARK,
        /// Bound to wildcard address.
        Wildcard = NFT_SOCKET_WILDCARD,
        /// Cgroup v2 id.
        CgroupV2 = NFT_SOCKET_CGROUPV2,
    }
}

u32_enum! {
    /// Stateful object type.
    pub enum ObjType {
        /// Counter.
        #[default]
        Counter = NFT_OBJECT_COUNTER,
        /// Quota.
        Quota = NFT_OBJECT_QUOTA,
        /// Conntrack helper.
        CtHelper = NFT_OBJECT_CT_HELPER,
        /// Rate limit.
        Limit = NFT_OBJECT_LIMIT,
        /// Connection limit.
        Connlimit = NFT_OBJECT_CONNLIMIT,
        /// Tunnel.
        Tunnel = NFT_OBJECT_TUNNEL,
        /// Conntrack timeout policy.
        CtTimeout = NFT_OBJECT_CT_TIMEOUT,
        /// Security mark.
        Secmark = NFT_OBJECT_SECMARK,
        /// Conntrack expectation.
        CtExpect = NFT_OBJECT_CT_EXPECT,
        /// Synproxy.
        Synproxy = NFT_OBJECT_SYNPROXY,
    }
}

u32_enum! {
    /// Syslog level of the `log` expression.
    pub enum LogLevel {
        /// emerg
        #[default]
        Emerg = NFT_LOGLEVEL_EMERG,
        /// alert
        Alert = NFT_LOGLEVEL_ALERT,
        /// crit
        Crit = NFT_LOGLEVEL_CRIT,
        /// err
        Err = NFT_LOGLEVEL_ERR,
        /// warn
        Warning = NFT_LOGLEVEL_WARNING,
        /// notice
        Notice = NFT_LOGLEVEL_NOTICE,
        /// info
        Info = NFT_LOGLEVEL_INFO,
        /// debug
        Debug = NFT_LOGLEVEL_DEBUG,
        /// audit
        Audit = NFT_LOGLEVEL_AUDIT,
    }
}

/// Hook number of a base chain. The meaning depends on the table family,
/// so several constants share the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hook(pub u32);

impl Hook {
    /// inet/ip/ip6/bridge `prerouting`.
    pub const PREROUTING: Hook = Hook(NF_INET_PRE_ROUTING);
    /// inet/ip/ip6/bridge `input`.
    pub const INPUT: Hook = Hook(NF_INET_LOCAL_IN);
    /// inet/ip/ip6/bridge `forward`.
    pub const FORWARD: Hook = Hook(NF_INET_FORWARD);
    /// inet/ip/ip6/bridge `output`.
    pub const OUTPUT: Hook = Hook(NF_INET_LOCAL_OUT);
    /// inet/ip/ip6/bridge `postrouting`.
    pub const POSTROUTING: Hook = Hook(NF_INET_POST_ROUTING);
    /// inet `ingress`.
    pub const INGRESS: Hook = Hook(NF_INET_INGRESS);
    /// netdev `ingress`.
    pub const NETDEV_INGRESS: Hook = Hook(NF_NETDEV_INGRESS);
    /// netdev `egress`.
    pub const NETDEV_EGRESS: Hook = Hook(NF_NETDEV_EGRESS);
    /// arp `input`.
    pub const ARP_IN: Hook = Hook(NF_ARP_IN);
    /// arp `output`.
    pub const ARP_OUT: Hook = Hook(NF_ARP_OUT);
}

impl AttrValue for Hook {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be32(ty, self.0)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be32().map(Hook)
    }
}

/// Encode a list of names as `NFTA_DEVICE_NAME` attributes.
pub(crate) fn encode_devices(w: &mut Writer, ty: u16, devs: &[String]) {
    w.nest(ty, |w| {
        for d in devs {
            w.put_str(NFTA_DEVICE_NAME, d);
        }
    });
}

pub(crate) fn decode_devices(a: &Attr<'_>) -> Result<Vec<String>> {
    let mut v = Vec::new();
    for d in a.nested() {
        let d = d?;
        if d.ty == NFTA_DEVICE_NAME {
            v.push(d.string()?);
        }
    }
    Ok(v)
}
