//! Rule expressions.
//!
//! Every kernel expression is represented by a struct whose fields map 1:1
//! to the expression's netlink attributes. Optional attributes are `Option`s
//! and are only sent when present. Expressions not known to this crate are
//! preserved losslessly as [`Expr::Unknown`].

use std::time::Duration;

use crate::error::{Error, Result};
use crate::nl::{Attr, Attrs, Writer};
use crate::sys::*;
use crate::types::*;

/// Encoding of an expression's private attributes.
pub(crate) trait ExprData: Sized {
    /// Kernel name of the expression.
    const NAME: &'static str;
    fn encode(&self, w: &mut Writer);
    fn decode(attrs: Attrs<'_>) -> Result<Self>;
}

macro_rules! put_field {
    ($w:ident, $v:expr, $attr:expr) => {
        Field::put_field($v, $w, $attr)
    };
    ($w:ident, $v:expr, $attr:expr, value) => {
        ValueField::put_field($v, $w, $attr)
    };
}

macro_rules! set_field {
    ($a:ident, $v:expr) => {
        Field::set_field($v, &$a)?
    };
    ($a:ident, $v:expr, value) => {
        ValueField::set_field($v, &$a)?
    };
}

macro_rules! expr {
    (
        $(#[$m:meta])*
        pub struct $name:ident = $kname:literal {
            $(
                $(#[$fm:meta])*
                pub $field:ident : $ty:ty = $attr:ident $(as $codec:ident)?,
            )*
        }
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            $($(#[$fm])* pub $field: $ty,)*
        }

        impl ExprData for $name {
            const NAME: &'static str = $kname;

            #[allow(unused_variables)]
            fn encode(&self, w: &mut Writer) {
                $(put_field!(w, &self.$field, $attr $(, $codec)?);)*
            }

            #[allow(unused_mut)]
            fn decode(attrs: Attrs<'_>) -> Result<Self> {
                let mut s = Self::default();
                for a in attrs {
                    let a = a?;
                    match a.ty {
                        $($attr => set_field!(a, &mut s.$field $(, $codec)?),)*
                        _ => {}
                    }
                }
                Ok(s)
            }
        }

        impl From<$name> for Expr {
            fn from(e: $name) -> Expr {
                Expr::$name(e)
            }
        }
    };
}

impl AttrValue for Duration {
    fn put(&self, w: &mut Writer, ty: u16) {
        w.put_be64(ty, self.as_millis().min(u64::MAX as u128) as u64)
    }
    fn get(a: &Attr<'_>) -> Result<Self> {
        a.be64().map(Duration::from_millis)
    }
}

expr! {
    /// Load immediate data into a register (`immediate`). Verdicts are
    /// loaded into [`Reg::VERDICT`].
    pub struct Immediate = "immediate" {
        /// Destination register.
        pub dreg: Reg = NFTA_IMMEDIATE_DREG,
        /// Data or verdict.
        pub data: Data = NFTA_IMMEDIATE_DATA,
    }
}

expr! {
    /// Compare a register with a value (`cmp`).
    pub struct Cmp = "cmp" {
        /// Source register.
        pub sreg: Reg = NFTA_CMP_SREG,
        /// Operator.
        pub op: CmpOp = NFTA_CMP_OP,
        /// Value to compare against.
        pub data: Vec<u8> = NFTA_CMP_DATA as value,
    }
}

expr! {
    /// Bitwise operation (`bitwise`).
    pub struct Bitwise = "bitwise" {
        /// Source register.
        pub sreg: Reg = NFTA_BITWISE_SREG,
        /// Destination register.
        pub dreg: Reg = NFTA_BITWISE_DREG,
        /// Length in bytes.
        pub len: u32 = NFTA_BITWISE_LEN,
        /// Operation (absent means mask/xor on old kernels).
        pub op: Option<BitwiseOp> = NFTA_BITWISE_OP,
        /// Mask for [`BitwiseOp::MaskXor`].
        pub mask: Option<Vec<u8>> = NFTA_BITWISE_MASK as value,
        /// Xor value for [`BitwiseOp::MaskXor`].
        pub xor: Option<Vec<u8>> = NFTA_BITWISE_XOR as value,
        /// Shift amount (4 bytes, host order) for shifts.
        pub data: Option<Vec<u8>> = NFTA_BITWISE_DATA as value,
    }
}

expr! {
    /// Byte order conversion (`byteorder`).
    pub struct Byteorder = "byteorder" {
        /// Source register.
        pub sreg: Reg = NFTA_BYTEORDER_SREG,
        /// Destination register.
        pub dreg: Reg = NFTA_BYTEORDER_DREG,
        /// Direction.
        pub op: ByteorderOp = NFTA_BYTEORDER_OP,
        /// Total length in bytes.
        pub len: u32 = NFTA_BYTEORDER_LEN,
        /// Element size (2, 4 or 8).
        pub size: u32 = NFTA_BYTEORDER_SIZE,
    }
}

expr! {
    /// Inclusive range check (`range`).
    pub struct Range = "range" {
        /// Source register.
        pub sreg: Reg = NFTA_RANGE_SREG,
        /// In or not in range.
        pub op: RangeOp = NFTA_RANGE_OP,
        /// Lower bound.
        pub from: Vec<u8> = NFTA_RANGE_FROM_DATA as value,
        /// Upper bound.
        pub to: Vec<u8> = NFTA_RANGE_TO_DATA as value,
    }
}

expr! {
    /// Set or map lookup (`lookup`). With `dreg` set to [`Reg::VERDICT`] this
    /// is a verdict map (`vmap`).
    pub struct Lookup = "lookup" {
        /// Set name.
        pub set: String = NFTA_LOOKUP_SET,
        /// Set id (for sets created in the same batch).
        pub set_id: Option<u32> = NFTA_LOOKUP_SET_ID,
        /// Key register.
        pub sreg: Reg = NFTA_LOOKUP_SREG,
        /// Destination register for maps.
        pub dreg: Option<Reg> = NFTA_LOOKUP_DREG,
        /// `NFT_LOOKUP_F_*` flags (`F_INV` for "not in set").
        pub flags: Option<u32> = NFTA_LOOKUP_FLAGS,
    }
}

expr! {
    /// Load or store packet data (`payload`).
    pub struct Payload = "payload" {
        /// Destination register (load).
        pub dreg: Option<Reg> = NFTA_PAYLOAD_DREG,
        /// Header base.
        pub base: PayloadBase = NFTA_PAYLOAD_BASE,
        /// Offset in bytes.
        pub offset: u32 = NFTA_PAYLOAD_OFFSET,
        /// Length in bytes.
        pub len: u32 = NFTA_PAYLOAD_LEN,
        /// Source register (store).
        pub sreg: Option<Reg> = NFTA_PAYLOAD_SREG,
        /// Checksum type to update (store).
        pub csum_type: Option<u32> = NFTA_PAYLOAD_CSUM_TYPE,
        /// Checksum offset (store).
        pub csum_offset: Option<u32> = NFTA_PAYLOAD_CSUM_OFFSET,
        /// Checksum flags (store).
        pub csum_flags: Option<u32> = NFTA_PAYLOAD_CSUM_FLAGS,
    }
}

expr! {
    /// Extension header / option access (`exthdr`).
    pub struct Exthdr = "exthdr" {
        /// Destination register (load).
        pub dreg: Option<Reg> = NFTA_EXTHDR_DREG,
        /// Header / option type.
        pub ty: u8 = NFTA_EXTHDR_TYPE,
        /// Offset within the header.
        pub offset: u32 = NFTA_EXTHDR_OFFSET,
        /// Length.
        pub len: u32 = NFTA_EXTHDR_LEN,
        /// `NFT_EXTHDR_F_*` flags.
        pub flags: Option<u32> = NFTA_EXTHDR_FLAGS,
        /// Header kind.
        pub op: Option<ExthdrOp> = NFTA_EXTHDR_OP,
        /// Source register (store).
        pub sreg: Option<Reg> = NFTA_EXTHDR_SREG,
    }
}

expr! {
    /// Packet metadata (`meta`).
    pub struct Meta = "meta" {
        /// Destination register (load).
        pub dreg: Option<Reg> = NFTA_META_DREG,
        /// Key.
        pub key: MetaKey = NFTA_META_KEY,
        /// Source register (store).
        pub sreg: Option<Reg> = NFTA_META_SREG,
    }
}

expr! {
    /// Routing information (`rt`).
    pub struct Rt = "rt" {
        /// Destination register.
        pub dreg: Reg = NFTA_RT_DREG,
        /// Key.
        pub key: RtKey = NFTA_RT_KEY,
    }
}

expr! {
    /// Hashing (`hash`).
    pub struct Hash = "hash" {
        /// Source register (jenkins).
        pub sreg: Option<Reg> = NFTA_HASH_SREG,
        /// Destination register.
        pub dreg: Reg = NFTA_HASH_DREG,
        /// Length of input (jenkins).
        pub len: Option<u32> = NFTA_HASH_LEN,
        /// Modulus.
        pub modulus: u32 = NFTA_HASH_MODULUS,
        /// Seed (jenkins).
        pub seed: Option<u32> = NFTA_HASH_SEED,
        /// Offset added to the result.
        pub offset: Option<u32> = NFTA_HASH_OFFSET,
        /// Hash type.
        pub ty: Option<HashType> = NFTA_HASH_TYPE,
    }
}

expr! {
    /// Socket lookup (`socket`).
    pub struct SocketLookup = "socket" {
        /// Key.
        pub key: SocketKey = NFTA_SOCKET_KEY,
        /// Destination register.
        pub dreg: Reg = NFTA_SOCKET_DREG,
        /// Cgroup level for [`SocketKey::CgroupV2`].
        pub level: Option<u32> = NFTA_SOCKET_LEVEL,
    }
}

expr! {
    /// Connection tracking (`ct`).
    pub struct Ct = "ct" {
        /// Destination register (load).
        pub dreg: Option<Reg> = NFTA_CT_DREG,
        /// Key.
        pub key: CtKey = NFTA_CT_KEY,
        /// Direction (0 = original, 1 = reply).
        pub direction: Option<u8> = NFTA_CT_DIRECTION,
        /// Source register (store).
        pub sreg: Option<Reg> = NFTA_CT_SREG,
    }
}

expr! {
    /// Offload the flow to a flowtable (`flow_offload`).
    pub struct FlowOffload = "flow_offload" {
        /// Flowtable name.
        pub table_name: String = NFTA_FLOW_TABLE_NAME,
    }
}

expr! {
    /// Rate limit (`limit`). Matches while under the limit, or while over it
    /// if `flags` contains `NFT_LIMIT_F_INV`.
    pub struct Limit = "limit" {
        /// Rate (packets or bytes per unit).
        pub rate: u64 = NFTA_LIMIT_RATE,
        /// Unit in seconds (1 = second, 60 = minute, ...).
        pub unit: u64 = NFTA_LIMIT_UNIT,
        /// Burst.
        pub burst: u32 = NFTA_LIMIT_BURST,
        /// Packets or bytes.
        pub ty: LimitType = NFTA_LIMIT_TYPE,
        /// `NFT_LIMIT_F_*` flags.
        pub flags: u32 = NFTA_LIMIT_FLAGS,
    }
}

expr! {
    /// Connection count limit (`connlimit`, nft `ct count`).
    pub struct Connlimit = "connlimit" {
        /// Connection count.
        pub count: u32 = NFTA_CONNLIMIT_COUNT,
        /// `NFT_CONNLIMIT_F_INV` to match when *over* the count.
        pub flags: u32 = NFTA_CONNLIMIT_FLAGS,
    }
}

expr! {
    /// Packet and byte counter (`counter`).
    pub struct Counter = "counter" {
        /// Byte count.
        pub bytes: u64 = NFTA_COUNTER_BYTES,
        /// Packet count.
        pub packets: u64 = NFTA_COUNTER_PACKETS,
    }
}

expr! {
    /// Time since last match (`last`).
    pub struct Last = "last" {
        /// `1` once the expression has matched (`msecs` is then valid).
        pub set: Option<u32> = NFTA_LAST_SET,
        /// Milliseconds since last match.
        pub msecs: Option<u64> = NFTA_LAST_MSECS,
    }
}

expr! {
    /// Log the packet (`log`). With `group` set, the packet is sent to
    /// NFLOG; see [`crate::nflog`].
    pub struct Log = "log" {
        /// NFLOG group.
        pub group: Option<u16> = NFTA_LOG_GROUP,
        /// Prefix string.
        pub prefix: Option<String> = NFTA_LOG_PREFIX,
        /// Bytes of packet to copy (NFLOG).
        pub snaplen: Option<u32> = NFTA_LOG_SNAPLEN,
        /// Packets to queue in the kernel before sending (NFLOG).
        pub qthreshold: Option<u16> = NFTA_LOG_QTHRESHOLD,
        /// Syslog level (not with `group`).
        pub level: Option<LogLevel> = NFTA_LOG_LEVEL,
        /// `NF_LOG_*` flags (not with `group`).
        pub flags: Option<u32> = NFTA_LOG_FLAGS,
    }
}

expr! {
    /// Queue to userspace (`queue`).
    pub struct Queue = "queue" {
        /// First queue number.
        pub num: Option<u16> = NFTA_QUEUE_NUM,
        /// Number of queues.
        pub total: Option<u16> = NFTA_QUEUE_TOTAL,
        /// `NFT_QUEUE_FLAG_*`.
        pub flags: Option<u16> = NFTA_QUEUE_FLAGS,
        /// Register holding the queue number.
        pub sreg_qnum: Option<Reg> = NFTA_QUEUE_SREG_QNUM,
    }
}

expr! {
    /// Byte quota (`quota`).
    pub struct Quota = "quota" {
        /// Quota in bytes.
        pub bytes: u64 = NFTA_QUOTA_BYTES,
        /// `NFT_QUOTA_F_*` flags.
        pub flags: u32 = NFTA_QUOTA_FLAGS,
        /// Consumed bytes.
        pub consumed: Option<u64> = NFTA_QUOTA_CONSUMED,
    }
}

expr! {
    /// Reject the packet (`reject`).
    pub struct Reject = "reject" {
        /// Reject type.
        pub ty: RejectType = NFTA_REJECT_TYPE,
        /// ICMP code.
        pub icmp_code: Option<u8> = NFTA_REJECT_ICMP_CODE,
    }
}

expr! {
    /// Network address translation (`nat`).
    pub struct Nat = "nat" {
        /// SNAT or DNAT.
        pub ty: NatType = NFTA_NAT_TYPE,
        /// Address family (`NFPROTO_IPV4` / `NFPROTO_IPV6`).
        pub family: u32 = NFTA_NAT_FAMILY,
        /// Register with the minimum address.
        pub reg_addr_min: Option<Reg> = NFTA_NAT_REG_ADDR_MIN,
        /// Register with the maximum address.
        pub reg_addr_max: Option<Reg> = NFTA_NAT_REG_ADDR_MAX,
        /// Register with the minimum port.
        pub reg_proto_min: Option<Reg> = NFTA_NAT_REG_PROTO_MIN,
        /// Register with the maximum port.
        pub reg_proto_max: Option<Reg> = NFTA_NAT_REG_PROTO_MAX,
        /// `NF_NAT_RANGE_*` flags.
        pub flags: Option<u32> = NFTA_NAT_FLAGS,
    }
}

expr! {
    /// Transparent proxy (`tproxy`).
    pub struct Tproxy = "tproxy" {
        /// Address family.
        pub family: u32 = NFTA_TPROXY_FAMILY,
        /// Register with the address.
        pub reg_addr: Option<Reg> = NFTA_TPROXY_REG_ADDR,
        /// Register with the port.
        pub reg_port: Option<Reg> = NFTA_TPROXY_REG_PORT,
    }
}

expr! {
    /// Masquerade (`masq`).
    pub struct Masq = "masq" {
        /// `NF_NAT_RANGE_*` flags.
        pub flags: Option<u32> = NFTA_MASQ_FLAGS,
        /// Register with the minimum port.
        pub reg_proto_min: Option<Reg> = NFTA_MASQ_REG_PROTO_MIN,
        /// Register with the maximum port.
        pub reg_proto_max: Option<Reg> = NFTA_MASQ_REG_PROTO_MAX,
    }
}

expr! {
    /// Redirect to local host (`redir`).
    pub struct Redir = "redir" {
        /// Register with the minimum port.
        pub reg_proto_min: Option<Reg> = NFTA_REDIR_REG_PROTO_MIN,
        /// Register with the maximum port.
        pub reg_proto_max: Option<Reg> = NFTA_REDIR_REG_PROTO_MAX,
        /// `NF_NAT_RANGE_*` flags.
        pub flags: Option<u32> = NFTA_REDIR_FLAGS,
    }
}

expr! {
    /// Duplicate the packet (`dup`).
    pub struct Dup = "dup" {
        /// Register with the destination address.
        pub sreg_addr: Option<Reg> = NFTA_DUP_SREG_ADDR,
        /// Register with the output device index.
        pub sreg_dev: Option<Reg> = NFTA_DUP_SREG_DEV,
    }
}

expr! {
    /// Forward the packet (`fwd`, netdev family).
    pub struct Fwd = "fwd" {
        /// Register with the output device index.
        pub sreg_dev: Option<Reg> = NFTA_FWD_SREG_DEV,
        /// Register with the next hop address.
        pub sreg_addr: Option<Reg> = NFTA_FWD_SREG_ADDR,
        /// Next hop family.
        pub nfproto: Option<u32> = NFTA_FWD_NFPROTO,
    }
}

expr! {
    /// Reference to a stateful object (`objref`), either by name or through
    /// an object map.
    pub struct Objref = "objref" {
        /// Object type (immediate reference).
        pub imm_type: Option<ObjType> = NFTA_OBJREF_IMM_TYPE,
        /// Object name (immediate reference).
        pub imm_name: Option<String> = NFTA_OBJREF_IMM_NAME,
        /// Key register (map reference).
        pub set_sreg: Option<Reg> = NFTA_OBJREF_SET_SREG,
        /// Map name.
        pub set_name: Option<String> = NFTA_OBJREF_SET_NAME,
        /// Map id.
        pub set_id: Option<u32> = NFTA_OBJREF_SET_ID,
    }
}

expr! {
    /// FIB lookup (`fib`).
    pub struct Fib = "fib" {
        /// Destination register.
        pub dreg: Reg = NFTA_FIB_DREG,
        /// Result type.
        pub result: FibResult = NFTA_FIB_RESULT,
        /// `NFTA_FIB_F_*` flags.
        pub flags: u32 = NFTA_FIB_FLAGS,
    }
}

expr! {
    /// Number generator (`numgen`).
    pub struct Numgen = "numgen" {
        /// Destination register.
        pub dreg: Reg = NFTA_NG_DREG,
        /// Modulus.
        pub modulus: u32 = NFTA_NG_MODULUS,
        /// Incremental or random.
        pub ty: NumgenType = NFTA_NG_TYPE,
        /// Offset added to the result.
        pub offset: Option<u32> = NFTA_NG_OFFSET,
    }
}

expr! {
    /// Passive OS fingerprinting (`osf`).
    pub struct Osf = "osf" {
        /// Destination register.
        pub dreg: Reg = NFTA_OSF_DREG,
        /// TTL handling.
        pub ttl: Option<u8> = NFTA_OSF_TTL,
        /// `NFT_OSF_F_*` flags.
        pub flags: Option<u32> = NFTA_OSF_FLAGS,
    }
}

expr! {
    /// SYN proxy (`synproxy`).
    pub struct Synproxy = "synproxy" {
        /// MSS.
        pub mss: Option<u16> = NFTA_SYNPROXY_MSS,
        /// Window scale.
        pub wscale: Option<u8> = NFTA_SYNPROXY_WSCALE,
        /// Options (`NF_SYNPROXY_OPT_*`: timestamps, SACK, ...).
        pub flags: Option<u32> = NFTA_SYNPROXY_FLAGS,
    }
}

expr! {
    /// IPsec state (`xfrm`).
    pub struct Xfrm = "xfrm" {
        /// Destination register.
        pub dreg: Reg = NFTA_XFRM_DREG,
        /// Key (`NFT_XFRM_KEY_*`: addresses, reqid, SPI).
        pub key: u32 = NFTA_XFRM_KEY,
        /// Direction (0 = in, 1 = out).
        pub dir: u8 = NFTA_XFRM_DIR,
        /// Security path index.
        pub spnum: u32 = NFTA_XFRM_SPNUM,
    }
}

expr! {
    /// Tunnel metadata (`tunnel`).
    pub struct Tunnel = "tunnel" {
        /// Key.
        pub key: u32 = NFTA_TUNNEL_KEY,
        /// Destination register.
        pub dreg: Reg = NFTA_TUNNEL_DREG,
        /// Mode.
        pub mode: Option<u32> = NFTA_TUNNEL_MODE,
    }
}

expr! {
    /// Disable connection tracking for the packet (`notrack`).
    pub struct Notrack = "notrack" {}
}

/// Add, update or delete set elements from the packet path (`dynset`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Dynset {
    /// Set name.
    pub set_name: String,
    /// Set id (for sets created in the same batch).
    pub set_id: Option<u32>,
    /// Operation.
    pub op: DynsetOp,
    /// Key register.
    pub sreg_key: Reg,
    /// Data register (for maps).
    pub sreg_data: Option<Reg>,
    /// Element timeout (`None` means the set default).
    pub timeout: Option<Duration>,
    /// `NFT_DYNSET_F_*` flags.
    pub flags: Option<u32>,
    /// Stateful expressions attached to the element (e.g. `limit`,
    /// `counter`, `connlimit`).
    pub exprs: Vec<Expr>,
}

impl ExprData for Dynset {
    const NAME: &'static str = "dynset";

    fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_DYNSET_SET_NAME, &self.set_name);
        self.set_id.put_field(w, NFTA_DYNSET_SET_ID);
        self.op.put(w, NFTA_DYNSET_OP);
        self.sreg_key.put(w, NFTA_DYNSET_SREG_KEY);
        self.sreg_data.put_field(w, NFTA_DYNSET_SREG_DATA);
        self.timeout.put_field(w, NFTA_DYNSET_TIMEOUT);
        self.flags.put_field(w, NFTA_DYNSET_FLAGS);
        encode_expr_set(w, NFTA_DYNSET_EXPR, NFTA_DYNSET_EXPRESSIONS, &self.exprs);
    }

    fn decode(attrs: Attrs<'_>) -> Result<Self> {
        let mut s = Self::default();
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_DYNSET_SET_NAME => s.set_name = a.string()?,
                NFTA_DYNSET_SET_ID => s.set_id.set_field(&a)?,
                NFTA_DYNSET_OP => s.op.set_field(&a)?,
                NFTA_DYNSET_SREG_KEY => s.sreg_key.set_field(&a)?,
                NFTA_DYNSET_SREG_DATA => s.sreg_data.set_field(&a)?,
                // The kernel always dumps a timeout (0 = set default) but
                // rejects one for sets without NFT_SET_TIMEOUT.
                NFTA_DYNSET_TIMEOUT => {
                    s.timeout = Some(Duration::get(&a)?).filter(|t| !t.is_zero())
                }
                NFTA_DYNSET_FLAGS => s.flags.set_field(&a)?,
                NFTA_DYNSET_EXPR => s.exprs.push(Expr::decode(a.nested())?),
                NFTA_DYNSET_EXPRESSIONS => s.exprs.extend(decode_expr_list(a.nested())?),
                _ => {}
            }
        }
        Ok(s)
    }
}

impl From<Dynset> for Expr {
    fn from(e: Dynset) -> Expr {
        Expr::Dynset(e)
    }
}

/// An expression not known to this crate, kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Unknown {
    /// Kernel expression name.
    pub name: String,
    /// Raw content of `NFTA_EXPR_DATA` (a sequence of attributes).
    pub data: Vec<u8>,
}

macro_rules! expr_enum {
    ($($var:ident,)*) => {
        /// A rule expression.
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[non_exhaustive]
        pub enum Expr {
            $(
                #[allow(missing_docs)]
                $var($var),
            )*
            /// An expression not known to this crate (e.g. `match`/`target`
            /// from iptables-nft), preserved verbatim.
            Unknown(Unknown),
        }

        impl Expr {
            /// The kernel name of the expression.
            pub fn name(&self) -> &str {
                match self {
                    $(Expr::$var(_) => $var::NAME,)*
                    Expr::Unknown(u) => &u.name,
                }
            }

            fn encode_data(&self, w: &mut Writer) {
                match self {
                    $(Expr::$var(e) => e.encode(w),)*
                    Expr::Unknown(u) => w.put_raw(&u.data),
                }
            }

            fn decode_data(name: &str, data: Option<Attr<'_>>) -> Result<Expr> {
                let attrs = data.map(|a| a.nested()).unwrap_or(Attrs::new(&[]));
                Ok(match name {
                    $($var::NAME => Expr::$var($var::decode(attrs)?),)*
                    _ => Expr::Unknown(Unknown {
                        name: name.to_owned(),
                        data: attrs.remaining().to_vec(),
                    }),
                })
            }
        }
    };
}

expr_enum! {
    Immediate, Cmp, Bitwise, Byteorder, Range, Lookup, Dynset, Payload, Exthdr,
    Meta, Rt, Hash, SocketLookup, Ct, FlowOffload, Limit, Connlimit, Counter, Last,
    Log, Queue, Quota, Reject, Nat, Tproxy, Masq, Redir, Dup, Fwd, Objref, Fib,
    Numgen, Osf, Synproxy, Xfrm, Tunnel, Notrack,
}

impl From<Unknown> for Expr {
    fn from(e: Unknown) -> Expr {
        Expr::Unknown(e)
    }
}

impl Expr {
    /// Encode as `NFTA_EXPR_NAME` + `NFTA_EXPR_DATA` (the content of an
    /// expression nest).
    pub(crate) fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_EXPR_NAME, self.name());
        w.nest(NFTA_EXPR_DATA, |w| self.encode_data(w));
    }

    /// Decode the content of an expression nest.
    pub(crate) fn decode(attrs: Attrs<'_>) -> Result<Expr> {
        let mut name = None;
        let mut data = None;
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_EXPR_NAME => name = Some(a.str()?),
                NFTA_EXPR_DATA => data = Some(a),
                _ => {}
            }
        }
        let name = name.ok_or_else(|| Error::malformed("expression without name"))?;
        Ok(Expr::decode_data(name, data)?.normalize())
    }

    /// Smooth over asymmetries between what the kernel dumps and what it
    /// accepts, so that dumped expressions can be sent back unchanged.
    fn normalize(self) -> Expr {
        match self {
            // exthdr writes dump NFTA_EXTHDR_FLAGS = 0, which the kernel
            // rejects for writes.
            Expr::Exthdr(mut e) if e.sreg.is_some() && e.flags == Some(0) => {
                e.flags = None;
                Expr::Exthdr(e)
            }
            // osf always dumps NFTA_OSF_FLAGS, but only accepts
            // NFT_OSF_F_VERSION there.
            Expr::Osf(mut e) if e.flags == Some(0) => {
                e.flags = None;
                Expr::Osf(e)
            }
            e => e,
        }
    }
}

/// Encode a list of expressions as nested `NFTA_LIST_ELEM`s under `ty`.
pub(crate) fn encode_expr_list(w: &mut Writer, ty: u16, exprs: &[Expr]) {
    w.nest(ty, |w| {
        for e in exprs {
            w.nest(NFTA_LIST_ELEM, |w| e.encode(w));
        }
    });
}

/// Encode an expression set the way the kernel dumps it: a single
/// expression under `single`, several as a list under `list`.
pub(crate) fn encode_expr_set(w: &mut Writer, single: u16, list: u16, exprs: &[Expr]) {
    match exprs {
        [] => {}
        [e] => w.nest(single, |w| e.encode(w)),
        _ => encode_expr_list(w, list, exprs),
    }
}

/// Decode a list of `NFTA_LIST_ELEM` expression nests.
pub(crate) fn decode_expr_list(attrs: Attrs<'_>) -> Result<Vec<Expr>> {
    let mut v = Vec::new();
    for a in attrs {
        let a = a?;
        if a.ty == NFTA_LIST_ELEM {
            v.push(Expr::decode(a.nested())?);
        }
    }
    Ok(v)
}
