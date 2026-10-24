//! Ruleset objects: tables, chains, rules, sets, set elements, stateful
//! objects, flowtables and the ruleset generation.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::expr::{Counter, Expr, ExprData, decode_expr_list, encode_expr_list, encode_expr_set};
use crate::nl::{Attr, Attrs, Writer};
use crate::sys::*;
use crate::types::*;
use crate::udata;

/// Encoding of a ruleset object as the attributes of a `NEW*` message.
pub(crate) trait NlObject: Sized {
    /// `NFT_MSG_NEW*` message type.
    const NEW: u8;
    fn family(&self) -> Family;
    /// Encode attributes for a `NEW*` message.
    fn encode(&self, w: &mut Writer);
    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self>;
}

// ------------------------------------------------------------------ table

/// A table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Table {
    /// Family.
    pub family: Family,
    /// Name.
    pub name: String,
    /// `NFT_TABLE_F_*` flags (dormant, owner, persist).
    pub flags: Option<u32>,
    /// Kernel handle (read only).
    pub handle: Option<u64>,
    /// Number of chains/sets/objects using the table (read only).
    pub use_count: Option<u32>,
    /// User data (see [`crate::udata`]).
    pub userdata: Option<Vec<u8>>,
    /// Port id of the owning socket for `NFT_TABLE_F_OWNER` tables (read only).
    pub owner: Option<u32>,
}

impl Table {
    /// A new table.
    pub fn new(family: Family, name: impl Into<String>) -> Self {
        Table {
            family,
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Set an nft-compatible comment.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.userdata = Some(udata::comment(comment));
        self
    }

    /// The nft comment, if any.
    pub fn comment(&self) -> Option<&str> {
        udata::get_str(self.userdata.as_deref()?, udata::UDATA_COMMENT)
    }
}

impl NlObject for Table {
    const NEW: u8 = NFT_MSG_NEWTABLE;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_TABLE_NAME, &self.name);
        self.flags.put_field(w, NFTA_TABLE_FLAGS);
        if let Some(u) = &self.userdata {
            w.put(NFTA_TABLE_USERDATA, u);
        }
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut t = Table {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_TABLE_NAME => t.name = a.string()?,
                NFTA_TABLE_FLAGS => t.flags = Some(a.be32()?),
                NFTA_TABLE_USE => t.use_count = Some(a.be32()?),
                NFTA_TABLE_HANDLE => t.handle = Some(a.be64()?),
                NFTA_TABLE_USERDATA => t.userdata = Some(a.data.to_vec()),
                NFTA_TABLE_OWNER => t.owner = Some(a.be32()?),
                _ => {}
            }
        }
        Ok(t)
    }
}

// ------------------------------------------------------------------ chain

/// Base chain type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ChainType {
    /// `filter`
    Filter,
    /// `nat`
    Nat,
    /// `route`
    Route,
    /// Any other type name.
    Other(String),
}

impl ChainType {
    /// Kernel name.
    pub fn as_str(&self) -> &str {
        match self {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
            ChainType::Route => "route",
            ChainType::Other(s) => s,
        }
    }

    fn from_name(s: &str) -> Self {
        match s {
            "filter" => ChainType::Filter,
            "nat" => ChainType::Nat,
            "route" => ChainType::Route,
            s => ChainType::Other(s.to_owned()),
        }
    }
}

/// Base chain policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Policy {
    /// Accept packets reaching the end of the chain.
    Accept,
    /// Drop packets reaching the end of the chain.
    Drop,
}

impl Policy {
    fn raw(self) -> u32 {
        match self {
            Policy::Accept => NF_ACCEPT as u32,
            Policy::Drop => NF_DROP as u32,
        }
    }
}

/// Hook registration of a base chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainHook {
    /// Hook number.
    pub hook: Hook,
    /// Priority (lower runs first).
    pub priority: i32,
    /// Single device (netdev family, legacy attribute).
    pub device: Option<String>,
    /// Devices (netdev family / inet ingress).
    pub devices: Vec<String>,
}

/// A chain. A chain with a [`ChainHook`] is a base chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Chain {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Chain name.
    pub name: String,
    /// Kernel handle (read only; see [`Batch::rename_chain`](crate::Batch::rename_chain)
    /// and [`Batch::delete_chain_by_handle`](crate::Batch::delete_chain_by_handle)).
    pub handle: Option<u64>,
    /// Hook (base chains only).
    pub hook: Option<ChainHook>,
    /// Policy (base chains only).
    pub policy: Option<Policy>,
    /// Chain type (base chains only).
    pub chain_type: Option<ChainType>,
    /// Packet and byte counters (base chains).
    pub counters: Option<Counter>,
    /// `NFT_CHAIN_*` flags.
    pub flags: Option<u32>,
    /// Transaction id for referencing the chain within the same batch.
    pub id: Option<u32>,
    /// User data.
    pub userdata: Option<Vec<u8>>,
    /// Number of references (read only).
    pub use_count: Option<u32>,
}

impl Chain {
    /// A new regular chain.
    pub fn new(family: Family, table: impl Into<String>, name: impl Into<String>) -> Self {
        Chain {
            family,
            table: table.into(),
            name: name.into(),
            ..Default::default()
        }
    }

    /// Make this a base chain.
    pub fn with_hook(mut self, chain_type: ChainType, hook: Hook, priority: i32) -> Self {
        self.chain_type = Some(chain_type);
        self.hook = Some(ChainHook {
            hook,
            priority,
            ..Default::default()
        });
        self
    }

    /// Set the base chain devices (netdev family).
    pub fn with_devices(mut self, devices: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let h = self.hook.get_or_insert_with(Default::default);
        h.devices = devices.into_iter().map(Into::into).collect();
        self
    }

    /// Set the policy.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set an nft-compatible comment.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.userdata = Some(udata::comment(comment));
        self
    }

    /// The nft comment, if any.
    pub fn comment(&self) -> Option<&str> {
        udata::get_str(self.userdata.as_deref()?, udata::UDATA_COMMENT)
    }

    /// Whether this is a base chain.
    pub fn is_base(&self) -> bool {
        self.hook.is_some()
    }
}

impl NlObject for Chain {
    const NEW: u8 = NFT_MSG_NEWCHAIN;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_CHAIN_TABLE, &self.table);
        // Binding chains created by id get a kernel-assigned name.
        if !self.name.is_empty() || self.id.is_none() {
            w.put_str(NFTA_CHAIN_NAME, &self.name);
        }
        if let Some(h) = &self.hook {
            w.nest(NFTA_CHAIN_HOOK, |w| {
                w.put_be32(NFTA_HOOK_HOOKNUM, h.hook.0);
                w.put_be32(NFTA_HOOK_PRIORITY, h.priority as u32);
                if let Some(d) = &h.device {
                    w.put_str(NFTA_HOOK_DEV, d);
                }
                if !h.devices.is_empty() {
                    encode_devices(w, NFTA_HOOK_DEVS, &h.devices);
                }
            });
        }
        if let Some(p) = self.policy {
            w.put_be32(NFTA_CHAIN_POLICY, p.raw());
        }
        if let Some(t) = &self.chain_type {
            w.put_str(NFTA_CHAIN_TYPE, t.as_str());
        }
        if let Some(c) = &self.counters {
            w.nest(NFTA_CHAIN_COUNTERS, |w| c.encode(w));
        }
        self.flags.put_field(w, NFTA_CHAIN_FLAGS);
        self.id.put_field(w, NFTA_CHAIN_ID);
        if let Some(u) = &self.userdata {
            w.put(NFTA_CHAIN_USERDATA, u);
        }
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut c = Chain {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_CHAIN_TABLE => c.table = a.string()?,
                NFTA_CHAIN_HANDLE => c.handle = Some(a.be64()?),
                NFTA_CHAIN_NAME => c.name = a.string()?,
                NFTA_CHAIN_HOOK => {
                    let mut h = ChainHook::default();
                    for a in a.nested() {
                        let a = a?;
                        match a.ty {
                            NFTA_HOOK_HOOKNUM => h.hook = Hook(a.be32()?),
                            NFTA_HOOK_PRIORITY => h.priority = a.be32()? as i32,
                            NFTA_HOOK_DEV => h.device = Some(a.string()?),
                            NFTA_HOOK_DEVS => h.devices = decode_devices(&a)?,
                            _ => {}
                        }
                    }
                    c.hook = Some(h);
                }
                NFTA_CHAIN_POLICY => {
                    c.policy = match Verdict::from_policy(a.be32()?) {
                        Verdict::Accept => Some(Policy::Accept),
                        Verdict::Drop => Some(Policy::Drop),
                        _ => return Err(Error::malformed("unknown chain policy")),
                    }
                }
                NFTA_CHAIN_TYPE => c.chain_type = Some(ChainType::from_name(a.str()?)),
                NFTA_CHAIN_COUNTERS => c.counters = Some(Counter::decode(a.nested())?),
                NFTA_CHAIN_FLAGS => c.flags = Some(a.be32()?),
                NFTA_CHAIN_ID => c.id = Some(a.be32()?),
                NFTA_CHAIN_USERDATA => c.userdata = Some(a.data.to_vec()),
                NFTA_CHAIN_USE => c.use_count = Some(a.be32()?),
                _ => {}
            }
        }
        Ok(c)
    }
}

// ------------------------------------------------------------------ rule

/// A rule: a list of expressions in a chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rule {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Chain name. May be empty if `chain_id` is set.
    pub chain: String,
    /// Kernel handle (set by dumps; used by replace/delete).
    pub handle: Option<u64>,
    /// Handle of the rule to add after ([`Batch::add_rule`](crate::Batch::add_rule))
    /// or insert before ([`Batch::insert_rule`](crate::Batch::insert_rule)).
    /// Dumps set it to the handle of the preceding rule; clear it before
    /// adding a dumped rule elsewhere.
    pub position: Option<u64>,
    /// Transaction id of this rule, for `position_id` of later rules.
    pub id: Option<u32>,
    /// Transaction id of a rule (created in the same batch) to position at.
    pub position_id: Option<u32>,
    /// Transaction id of the chain (created in the same batch).
    pub chain_id: Option<u32>,
    /// Expressions.
    pub exprs: Vec<Expr>,
    /// User data (see [`crate::udata`]).
    pub userdata: Option<Vec<u8>>,
    /// Compat info `(l4proto, flags)` used by iptables-nft.
    pub compat: Option<(u32, u32)>,
}

impl Rule {
    /// A new, empty rule.
    pub fn new(family: Family, table: impl Into<String>, chain: impl Into<String>) -> Self {
        Rule {
            family,
            table: table.into(),
            chain: chain.into(),
            ..Default::default()
        }
    }

    /// Append an expression.
    pub fn with(mut self, e: impl Into<Expr>) -> Self {
        self.exprs.push(e.into());
        self
    }

    /// Append an expression.
    pub fn push(&mut self, e: impl Into<Expr>) -> &mut Self {
        self.exprs.push(e.into());
        self
    }

    /// Set an nft-compatible comment.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.userdata = Some(udata::comment(comment));
        self
    }

    /// The nft comment, if any.
    pub fn comment(&self) -> Option<&str> {
        udata::get_str(self.userdata.as_deref()?, udata::UDATA_COMMENT)
    }

    /// Iterate over the counters of this rule.
    pub fn counters(&self) -> impl Iterator<Item = &Counter> {
        self.exprs.iter().filter_map(|e| match e {
            Expr::Counter(c) => Some(c),
            _ => None,
        })
    }

    pub(crate) fn encode_with(&self, w: &mut Writer, handle: bool) {
        w.put_str(NFTA_RULE_TABLE, &self.table);
        if !self.chain.is_empty() || self.chain_id.is_none() {
            w.put_str(NFTA_RULE_CHAIN, &self.chain);
        }
        if handle {
            self.handle.put_field(w, NFTA_RULE_HANDLE);
        }
        self.position.put_field(w, NFTA_RULE_POSITION);
        if !self.exprs.is_empty() {
            encode_expr_list(w, NFTA_RULE_EXPRESSIONS, &self.exprs);
        }
        if let Some((proto, flags)) = self.compat {
            w.nest(NFTA_RULE_COMPAT, |w| {
                w.put_be32(NFTA_RULE_COMPAT_PROTO, proto);
                w.put_be32(NFTA_RULE_COMPAT_FLAGS, flags);
            });
        }
        if let Some(u) = &self.userdata {
            w.put(NFTA_RULE_USERDATA, u);
        }
        self.id.put_field(w, NFTA_RULE_ID);
        self.position_id.put_field(w, NFTA_RULE_POSITION_ID);
        self.chain_id.put_field(w, NFTA_RULE_CHAIN_ID);
    }
}

impl NlObject for Rule {
    const NEW: u8 = NFT_MSG_NEWRULE;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        self.encode_with(w, false)
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut r = Rule {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_RULE_TABLE => r.table = a.string()?,
                NFTA_RULE_CHAIN => r.chain = a.string()?,
                NFTA_RULE_HANDLE => r.handle = Some(a.be64()?),
                NFTA_RULE_EXPRESSIONS => r.exprs = decode_expr_list(a.nested())?,
                NFTA_RULE_COMPAT => {
                    let (mut p, mut f) = (0, 0);
                    for a in a.nested() {
                        let a = a?;
                        match a.ty {
                            NFTA_RULE_COMPAT_PROTO => p = a.be32()?,
                            NFTA_RULE_COMPAT_FLAGS => f = a.be32()?,
                            _ => {}
                        }
                    }
                    r.compat = Some((p, f));
                }
                // Dumps report the handle of the preceding rule here. It is
                // implied by the dump order and would be wrong when the
                // rule is added elsewhere, so it is not decoded.
                NFTA_RULE_POSITION => r.position = Some(a.be64()?),
                NFTA_RULE_USERDATA => r.userdata = Some(a.data.to_vec()),
                NFTA_RULE_ID => r.id = Some(a.be32()?),
                NFTA_RULE_POSITION_ID => r.position_id = Some(a.be32()?),
                NFTA_RULE_CHAIN_ID => r.chain_id = Some(a.be32()?),
                _ => {}
            }
        }
        Ok(r)
    }
}

// ------------------------------------------------------------------ set

/// Data type identifiers used by `nft` for set keys and data
/// (`NFTA_SET_KEY_TYPE` / `NFTA_SET_DATA_TYPE`). The kernel does not
/// interpret them, but `nft` needs them to display sets.
pub mod datatype {
    /// Invalid / unknown.
    pub const INVALID: u32 = 0;
    /// `verdict`
    pub const VERDICT: u32 = 1;
    /// `nf_proto`
    pub const NFPROTO: u32 = 2;
    /// `bitmask`
    pub const BITMASK: u32 = 3;
    /// `integer`
    pub const INTEGER: u32 = 4;
    /// `string`
    pub const STRING: u32 = 5;
    /// `lladdr`
    pub const LLADDR: u32 = 6;
    /// `ipv4_addr`
    pub const IPADDR: u32 = 7;
    /// `ipv6_addr`
    pub const IP6ADDR: u32 = 8;
    /// `ether_addr`
    pub const ETHERADDR: u32 = 9;
    /// `ether_type`
    pub const ETHERTYPE: u32 = 10;
    /// `arp_op`
    pub const ARPOP: u32 = 11;
    /// `inet_proto`
    pub const INET_PROTOCOL: u32 = 12;
    /// `inet_service`
    pub const INET_SERVICE: u32 = 13;
    /// `icmp_type`
    pub const ICMP_TYPE: u32 = 14;
    /// `tcp_flag`
    pub const TCP_FLAG: u32 = 15;
    /// `dccp_pkttype`
    pub const DCCP_PKTTYPE: u32 = 16;
    /// `mh_type`
    pub const MH_TYPE: u32 = 17;
    /// `time` (a duration)
    pub const TIME: u32 = 18;
    /// `mark`
    pub const MARK: u32 = 19;
    /// `iface_index`
    pub const IFINDEX: u32 = 20;
    /// `iface_type`
    pub const ARPHRD: u32 = 21;
    /// `realm`
    pub const REALM: u32 = 22;
    /// `classid`
    pub const CLASSID: u32 = 23;
    /// `uid`
    pub const UID: u32 = 24;
    /// `gid`
    pub const GID: u32 = 25;
    /// `ct_state`
    pub const CT_STATE: u32 = 26;
    /// `ct_dir`
    pub const CT_DIR: u32 = 27;
    /// `ct_status`
    pub const CT_STATUS: u32 = 28;
    /// `icmpv6_type`
    pub const ICMP6_TYPE: u32 = 29;
    /// `ct_label`
    pub const CT_LABEL: u32 = 30;
    /// `pkt_type`
    pub const PKTTYPE: u32 = 31;
    /// `icmp_code`
    pub const ICMP_CODE: u32 = 32;
    /// `icmpv6_code`
    pub const ICMPV6_CODE: u32 = 33;
    /// `icmpx_code`
    pub const ICMPX_CODE: u32 = 34;
    /// `devgroup`
    pub const DEVGROUP: u32 = 35;
    /// `dscp`
    pub const DSCP: u32 = 36;
    /// `ecn`
    pub const ECN: u32 = 37;
    /// `fib_addrtype`
    pub const FIB_ADDR: u32 = 38;
    /// `boolean`
    pub const BOOLEAN: u32 = 39;
    /// `ct_event`
    pub const CT_EVENTBIT: u32 = 40;
    /// `ifname`
    pub const IFNAME: u32 = 41;
    /// `igmp_type`
    pub const IGMP_TYPE: u32 = 42;
    /// `time` (a date and time, as `meta time`)
    pub const TIME_DATE: u32 = 43;
    /// `hour` (`meta hour`)
    pub const TIME_HOUR: u32 = 44;
    /// `day` (`meta day`)
    pub const TIME_DAY: u32 = 45;
    /// `cgroupsv2`
    pub const CGROUPV2: u32 = 46;

    /// Bits per component of a concatenated type.
    pub const TYPE_BITS: u32 = 6;

    /// The type id of a concatenation of the given types (in order).
    pub fn concat(types: &[u32]) -> u32 {
        types.iter().fold(0, |acc, t| (acc << TYPE_BITS) | t)
    }
}

/// A set or map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Set {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Set name. For anonymous sets use a name like `__set%d`; the kernel
    /// replaces `%d`.
    pub name: String,
    /// Kernel handle (read only).
    pub handle: Option<u64>,
    /// `NFT_SET_*` flags.
    pub flags: u32,
    /// Key data type (see [`datatype`]).
    pub key_type: u32,
    /// Key length in bytes (concatenation fields are each padded to 4 bytes).
    pub key_len: u32,
    /// Data type for maps (see [`datatype`]; [`NFT_DATA_VERDICT`] for vmaps).
    pub data_type: Option<u32>,
    /// Data length for maps.
    pub data_len: Option<u32>,
    /// Object type for object maps.
    pub obj_type: Option<u32>,
    /// `NFT_SET_POL_*` policy.
    pub policy: Option<u32>,
    /// Maximum number of elements.
    pub size: Option<u32>,
    /// Field lengths of a concatenated key (required for interval
    /// concatenations).
    pub field_lens: Vec<u32>,
    /// Transaction id, for referencing the set within the same batch.
    pub id: Option<u32>,
    /// Default element timeout.
    pub timeout: Option<Duration>,
    /// Garbage collection interval in milliseconds.
    pub gc_interval: Option<u32>,
    /// User data (see [`crate::udata`]).
    pub userdata: Option<Vec<u8>>,
    /// Stateful expressions attached to every element.
    pub exprs: Vec<Expr>,
}

impl Set {
    /// A new set with a key of the given type and length.
    pub fn new(
        family: Family,
        table: impl Into<String>,
        name: impl Into<String>,
        key_type: u32,
        key_len: u32,
    ) -> Self {
        Set {
            family,
            table: table.into(),
            name: name.into(),
            key_type,
            key_len,
            ..Default::default()
        }
    }

    /// Turn this set into a map with the given data type and length.
    pub fn map(mut self, data_type: u32, data_len: u32) -> Self {
        self.flags |= NFT_SET_MAP;
        self.data_type = Some(data_type);
        self.data_len = Some(data_len);
        self
    }

    /// Turn this set into a verdict map.
    pub fn vmap(self) -> Self {
        self.map(NFT_DATA_VERDICT, 0)
    }

    /// Add `NFT_SET_*` flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags |= flags;
        self
    }

    /// Set a default timeout (also sets `NFT_SET_TIMEOUT`).
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.flags |= NFT_SET_TIMEOUT;
        self.timeout = Some(t);
        self
    }

    /// Set the maximum number of elements.
    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the user data.
    pub fn with_userdata(mut self, u: Vec<u8>) -> Self {
        self.userdata = Some(u);
        self
    }

    /// Set the transaction id.
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Whether this is a map.
    pub fn is_map(&self) -> bool {
        self.flags & NFT_SET_MAP != 0
    }

    /// Whether this is an interval set.
    pub fn is_interval(&self) -> bool {
        self.flags & NFT_SET_INTERVAL != 0
    }
}

impl NlObject for Set {
    const NEW: u8 = NFT_MSG_NEWSET;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        self.encode_with_id(w, self.id)
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        Set::decode_attrs(family, attrs)
    }
}

impl Set {
    pub(crate) fn encode_with_id(&self, w: &mut Writer, id: Option<u32>) {
        w.put_str(NFTA_SET_TABLE, &self.table);
        w.put_str(NFTA_SET_NAME, &self.name);
        w.put_be32(NFTA_SET_FLAGS, self.flags);
        w.put_be32(NFTA_SET_KEY_TYPE, self.key_type);
        w.put_be32(NFTA_SET_KEY_LEN, self.key_len);
        self.data_type.put_field(w, NFTA_SET_DATA_TYPE);
        self.data_len.put_field(w, NFTA_SET_DATA_LEN);
        self.obj_type.put_field(w, NFTA_SET_OBJ_TYPE);
        self.policy.put_field(w, NFTA_SET_POLICY);
        if self.size.is_some() || !self.field_lens.is_empty() {
            w.nest(NFTA_SET_DESC, |w| {
                self.size.put_field(w, NFTA_SET_DESC_SIZE);
                if !self.field_lens.is_empty() {
                    w.nest(NFTA_SET_DESC_CONCAT, |w| {
                        for l in &self.field_lens {
                            w.nest(NFTA_LIST_ELEM, |w| w.put_be32(NFTA_SET_FIELD_LEN, *l));
                        }
                    });
                }
            });
        }
        id.put_field(w, NFTA_SET_ID);
        self.timeout.put_field(w, NFTA_SET_TIMEOUT);
        self.gc_interval.put_field(w, NFTA_SET_GC_INTERVAL);
        if let Some(u) = &self.userdata {
            w.put(NFTA_SET_USERDATA, u);
        }
        encode_expr_set(w, NFTA_SET_EXPR, NFTA_SET_EXPRESSIONS, &self.exprs);
    }

    fn decode_attrs(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut s = Set {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_SET_TABLE => s.table = a.string()?,
                NFTA_SET_NAME => s.name = a.string()?,
                NFTA_SET_HANDLE => s.handle = Some(a.be64()?),
                NFTA_SET_FLAGS => s.flags = a.be32()?,
                NFTA_SET_KEY_TYPE => s.key_type = a.be32()?,
                NFTA_SET_KEY_LEN => s.key_len = a.be32()?,
                NFTA_SET_DATA_TYPE => s.data_type = Some(a.be32()?),
                NFTA_SET_DATA_LEN => s.data_len = Some(a.be32()?),
                NFTA_SET_OBJ_TYPE => s.obj_type = Some(a.be32()?),
                NFTA_SET_POLICY => s.policy = Some(a.be32()?),
                NFTA_SET_DESC => {
                    for a in a.nested() {
                        let a = a?;
                        match a.ty {
                            NFTA_SET_DESC_SIZE => s.size = Some(a.be32()?),
                            NFTA_SET_DESC_CONCAT => {
                                for f in a.nested() {
                                    for l in f?.nested() {
                                        let l = l?;
                                        if l.ty == NFTA_SET_FIELD_LEN {
                                            s.field_lens.push(l.be32()?);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                NFTA_SET_ID => s.id = Some(a.be32()?),
                NFTA_SET_TIMEOUT => s.timeout = Some(Duration::get(&a)?),
                NFTA_SET_GC_INTERVAL => s.gc_interval = Some(a.be32()?),
                NFTA_SET_USERDATA => s.userdata = Some(a.data.to_vec()),
                NFTA_SET_EXPR => s.exprs.push(Expr::decode(a.nested())?),
                NFTA_SET_EXPRESSIONS => s.exprs.extend(decode_expr_list(a.nested())?),
                _ => {}
            }
        }
        Ok(s)
    }
}

// ------------------------------------------------------------------ elements

/// A set element.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetElem {
    /// Key. `None` only for the catch-all element.
    pub key: Option<Vec<u8>>,
    /// End of the range (inclusive) for concatenated interval sets.
    pub key_end: Option<Vec<u8>>,
    /// Map data.
    pub data: Option<Data>,
    /// `NFT_SET_ELEM_*` flags.
    pub flags: Option<u32>,
    /// Timeout.
    pub timeout: Option<Duration>,
    /// Remaining time until expiry (dumps; may also be set on add).
    pub expiration: Option<Duration>,
    /// User data.
    pub userdata: Option<Vec<u8>>,
    /// Stateful expressions of this element.
    pub exprs: Vec<Expr>,
    /// Object reference for object maps.
    pub objref: Option<String>,
}

impl SetElem {
    /// An element with the given key.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        SetElem {
            key: Some(key.into()),
            ..Default::default()
        }
    }

    /// The catch-all (`*`) element.
    pub fn catchall() -> Self {
        SetElem {
            flags: Some(NFT_SET_ELEM_CATCHALL),
            ..Default::default()
        }
    }

    /// An interval end marker element (for non-concatenated interval sets).
    pub fn interval_end(key: impl Into<Vec<u8>>) -> Self {
        SetElem {
            key: Some(key.into()),
            flags: Some(NFT_SET_ELEM_INTERVAL_END),
            ..Default::default()
        }
    }

    /// Set map data.
    pub fn with_data(mut self, d: impl Into<Data>) -> Self {
        self.data = Some(d.into());
        self
    }

    /// Set a verdict as map data.
    pub fn with_verdict(self, v: Verdict) -> Self {
        self.with_data(Data::Verdict(v))
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Set the remaining time until expiry (at most the timeout).
    pub fn with_expiration(mut self, e: Duration) -> Self {
        self.expiration = Some(e);
        self
    }

    /// Set the range end (concatenated interval sets).
    pub fn with_key_end(mut self, k: impl Into<Vec<u8>>) -> Self {
        self.key_end = Some(k.into());
        self
    }

    /// Set an nft comment.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.userdata = Some(udata::comment(comment));
        self
    }

    /// Attach a stateful expression.
    pub fn with_expr(mut self, e: impl Into<Expr>) -> Self {
        self.exprs.push(e.into());
        self
    }

    /// The nft comment, if any.
    pub fn comment(&self) -> Option<&str> {
        udata::get_str(self.userdata.as_deref()?, udata::UDATA_COMMENT)
    }

    /// Whether this is an interval end marker.
    pub fn is_interval_end(&self) -> bool {
        self.flags.unwrap_or(0) & NFT_SET_ELEM_INTERVAL_END != 0
    }

    /// Whether this is the catch-all element.
    pub fn is_catchall(&self) -> bool {
        self.flags.unwrap_or(0) & NFT_SET_ELEM_CATCHALL != 0
    }

    /// The elements representing the inclusive range `[start, end]` in a
    /// non-concatenated interval set: `start` (carrying `data`, if any) and
    /// an interval-end marker at `end + 1`. If `end` is the maximum value,
    /// no end marker is needed and only one element is returned.
    pub fn range(start: &[u8], end: &[u8], data: Option<Data>) -> Result<Vec<SetElem>> {
        if start.len() != end.len() {
            return Err(Error::invalid("range bounds have different lengths"));
        }
        if start > end {
            return Err(Error::invalid("range start is greater than its end"));
        }
        let mut v = vec![SetElem {
            key: Some(start.to_vec()),
            data,
            ..Default::default()
        }];
        if let Some(next) = increment_be(end) {
            v.push(SetElem::interval_end(next));
        }
        Ok(v)
    }

    pub(crate) fn encode(&self, w: &mut Writer) {
        if let Some(k) = &self.key {
            w.nest(NFTA_SET_ELEM_KEY, |w| w.put(NFTA_DATA_VALUE, k));
        }
        if let Some(k) = &self.key_end {
            w.nest(NFTA_SET_ELEM_KEY_END, |w| w.put(NFTA_DATA_VALUE, k));
        }
        if let Some(d) = &self.data {
            d.put(w, NFTA_SET_ELEM_DATA);
        }
        self.flags.put_field(w, NFTA_SET_ELEM_FLAGS);
        self.timeout.put_field(w, NFTA_SET_ELEM_TIMEOUT);
        self.expiration.put_field(w, NFTA_SET_ELEM_EXPIRATION);
        if let Some(u) = &self.userdata {
            w.put(NFTA_SET_ELEM_USERDATA, u);
        }
        if let Some(o) = &self.objref {
            w.put_str(NFTA_SET_ELEM_OBJREF, o);
        }
        encode_expr_set(
            w,
            NFTA_SET_ELEM_EXPR,
            NFTA_SET_ELEM_EXPRESSIONS,
            &self.exprs,
        );
    }

    pub(crate) fn decode(attrs: Attrs<'_>) -> Result<Self> {
        let mut e = SetElem::default();
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_SET_ELEM_KEY => e.key = Some(value_of(&a)?),
                NFTA_SET_ELEM_KEY_END => e.key_end = Some(value_of(&a)?),
                NFTA_SET_ELEM_DATA => e.data = Some(Data::get(&a)?),
                NFTA_SET_ELEM_FLAGS => e.flags = Some(a.be32()?),
                NFTA_SET_ELEM_TIMEOUT => e.timeout = Some(Duration::get(&a)?),
                NFTA_SET_ELEM_EXPIRATION => e.expiration = Some(Duration::get(&a)?),
                NFTA_SET_ELEM_USERDATA => e.userdata = Some(a.data.to_vec()),
                NFTA_SET_ELEM_OBJREF => e.objref = Some(a.string()?),
                NFTA_SET_ELEM_EXPR => e.exprs.push(Expr::decode(a.nested())?),
                NFTA_SET_ELEM_EXPRESSIONS => e.exprs.extend(decode_expr_list(a.nested())?),
                _ => {}
            }
        }
        Ok(e)
    }
}

fn value_of(a: &Attr<'_>) -> Result<Vec<u8>> {
    match Data::decode(a.nested())? {
        Data::Value(v) => Ok(v),
        Data::Verdict(_) => Err(Error::malformed("set element key is a verdict")),
    }
}

/// Big-endian increment; `None` on overflow.
pub(crate) fn increment_be(v: &[u8]) -> Option<Vec<u8>> {
    let mut out = v.to_vec();
    for b in out.iter_mut().rev() {
        let (n, carry) = b.overflowing_add(1);
        *b = n;
        if !carry {
            return Some(out);
        }
    }
    None
}

/// Elements of one set, as carried in a single `NEWSETELEM` / `DELSETELEM`
/// message or returned by a dump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetElemList {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Set name.
    pub set: String,
    /// Set transaction id (for sets created in the same batch).
    pub set_id: Option<u32>,
    /// Elements.
    pub elems: Vec<SetElem>,
}

impl SetElemList {
    /// An element list for the given set.
    pub fn new(family: Family, table: impl Into<String>, set: impl Into<String>) -> Self {
        SetElemList {
            family,
            table: table.into(),
            set: set.into(),
            ..Default::default()
        }
    }

    /// Add an element.
    pub fn with(mut self, e: SetElem) -> Self {
        self.elems.push(e);
        self
    }

    pub(crate) fn encode_header(&self, w: &mut Writer) {
        w.put_str(NFTA_SET_ELEM_LIST_TABLE, &self.table);
        w.put_str(NFTA_SET_ELEM_LIST_SET, &self.set);
        self.set_id.put_field(w, NFTA_SET_ELEM_LIST_SET_ID);
    }
}

impl NlObject for SetElemList {
    const NEW: u8 = NFT_MSG_NEWSETELEM;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        self.encode_header(w);
        if !self.elems.is_empty() {
            w.nest(NFTA_SET_ELEM_LIST_ELEMENTS, |w| {
                for e in &self.elems {
                    w.nest(NFTA_LIST_ELEM, |w| e.encode(w));
                }
            });
        }
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut l = SetElemList {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_SET_ELEM_LIST_TABLE => l.table = a.string()?,
                NFTA_SET_ELEM_LIST_SET => l.set = a.string()?,
                NFTA_SET_ELEM_LIST_SET_ID => l.set_id = Some(a.be32()?),
                NFTA_SET_ELEM_LIST_ELEMENTS => {
                    for e in a.nested() {
                        let e = e?;
                        if e.ty == NFTA_LIST_ELEM {
                            l.elems.push(SetElem::decode(e.nested())?);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(l)
    }
}

// ------------------------------------------------------------------ objects

/// Conntrack helper object.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CtHelper {
    /// Helper name (e.g. `ftp`).
    pub name: String,
    /// Layer 3 protocol (`NFPROTO_*`); `None` for the table's family.
    pub l3proto: Option<u16>,
    /// Layer 4 protocol.
    pub l4proto: u8,
}

/// Conntrack timeout policy object.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CtTimeout {
    /// Layer 3 protocol.
    pub l3proto: Option<u16>,
    /// Layer 4 protocol.
    pub l4proto: u8,
    /// Raw `NFTA_CT_TIMEOUT_DATA` attributes: per-state timeouts in seconds
    /// (be32) with `CTA_TIMEOUT_*` attribute types. See [`CtTimeout::new`].
    pub data: Vec<u8>,
}

impl CtTimeout {
    /// A timeout policy for `l4proto` (and optionally one l3 protocol)
    /// with per-state timeouts in seconds, keyed by `CTA_TIMEOUT_*`
    /// constants (e.g. [`CTA_TIMEOUT_TCP_ESTABLISHED`]).
    pub fn new(l3proto: Option<u16>, l4proto: u8, timeouts: &[(u16, u32)]) -> Self {
        let mut w = Writer::new();
        for &(state, secs) in timeouts {
            w.put_be32(state, secs);
        }
        CtTimeout {
            l3proto,
            l4proto,
            data: w.into_bytes(),
        }
    }

    /// The per-state timeouts `(CTA_TIMEOUT_* attribute, seconds)`.
    pub fn policy(&self) -> Vec<(u16, u32)> {
        Attrs::new(&self.data)
            .flatten()
            .filter_map(|a| a.be32().ok().map(|v| (a.ty, v)))
            .collect()
    }
}

/// Conntrack expectation object.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CtExpect {
    /// Layer 3 protocol.
    pub l3proto: Option<u16>,
    /// Layer 4 protocol.
    pub l4proto: u8,
    /// Destination port.
    pub dport: u16,
    /// Timeout in milliseconds.
    pub timeout: u32,
    /// Maximum expectations.
    pub size: u8,
}

/// Security mark object.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Secmark {
    /// Security context.
    pub ctx: String,
}

/// The type-specific part of a stateful object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ObjKind {
    /// Named counter.
    Counter(crate::expr::Counter),
    /// Named quota.
    Quota(crate::expr::Quota),
    /// Named limit.
    Limit(crate::expr::Limit),
    /// Named connection limit.
    Connlimit(crate::expr::Connlimit),
    /// Conntrack helper.
    CtHelper(CtHelper),
    /// Conntrack timeout policy.
    CtTimeout(CtTimeout),
    /// Conntrack expectation.
    CtExpect(CtExpect),
    /// Security mark.
    Secmark(Secmark),
    /// Synproxy.
    Synproxy(crate::expr::Synproxy),
    /// Unknown object type, kept verbatim.
    Unknown {
        /// `NFT_OBJECT_*` type.
        ty: u32,
        /// Raw `NFTA_OBJ_DATA` content.
        data: Vec<u8>,
    },
}

impl ObjKind {
    /// The `NFT_OBJECT_*` type.
    pub fn obj_type(&self) -> u32 {
        match self {
            ObjKind::Counter(_) => NFT_OBJECT_COUNTER,
            ObjKind::Quota(_) => NFT_OBJECT_QUOTA,
            ObjKind::Limit(_) => NFT_OBJECT_LIMIT,
            ObjKind::Connlimit(_) => NFT_OBJECT_CONNLIMIT,
            ObjKind::CtHelper(_) => NFT_OBJECT_CT_HELPER,
            ObjKind::CtTimeout(_) => NFT_OBJECT_CT_TIMEOUT,
            ObjKind::CtExpect(_) => NFT_OBJECT_CT_EXPECT,
            ObjKind::Secmark(_) => NFT_OBJECT_SECMARK,
            ObjKind::Synproxy(_) => NFT_OBJECT_SYNPROXY,
            ObjKind::Unknown { ty, .. } => *ty,
        }
    }

    fn encode(&self, w: &mut Writer) {
        match self {
            ObjKind::Counter(c) => c.encode(w),
            ObjKind::Quota(q) => q.encode(w),
            ObjKind::Limit(l) => l.encode(w),
            ObjKind::Connlimit(c) => c.encode(w),
            ObjKind::Synproxy(s) => s.encode(w),
            ObjKind::CtHelper(h) => {
                w.put_str(NFTA_CT_HELPER_NAME, &h.name);
                h.l3proto.put_field(w, NFTA_CT_HELPER_L3PROTO);
                w.put_u8(NFTA_CT_HELPER_L4PROTO, h.l4proto);
            }
            ObjKind::CtTimeout(t) => {
                t.l3proto.put_field(w, NFTA_CT_TIMEOUT_L3PROTO);
                w.put_u8(NFTA_CT_TIMEOUT_L4PROTO, t.l4proto);
                w.nest(NFTA_CT_TIMEOUT_DATA, |w| w.put_raw(&t.data));
            }
            ObjKind::CtExpect(e) => {
                e.l3proto.put_field(w, NFTA_CT_EXPECT_L3PROTO);
                w.put_u8(NFTA_CT_EXPECT_L4PROTO, e.l4proto);
                w.put_be16(NFTA_CT_EXPECT_DPORT, e.dport);
                // The only nf_tables attribute in host byte order.
                w.put(NFTA_CT_EXPECT_TIMEOUT, &e.timeout.to_ne_bytes());
                w.put_u8(NFTA_CT_EXPECT_SIZE, e.size);
            }
            ObjKind::Secmark(s) => w.put_str(NFTA_SECMARK_CTX, &s.ctx),
            ObjKind::Unknown { data, .. } => w.put_raw(data),
        }
    }

    fn decode(ty: u32, attrs: Attrs<'_>) -> Result<Self> {
        Ok(match ty {
            NFT_OBJECT_COUNTER => ObjKind::Counter(ExprData::decode(attrs)?),
            NFT_OBJECT_QUOTA => ObjKind::Quota(ExprData::decode(attrs)?),
            NFT_OBJECT_LIMIT => ObjKind::Limit(ExprData::decode(attrs)?),
            NFT_OBJECT_CONNLIMIT => ObjKind::Connlimit(ExprData::decode(attrs)?),
            NFT_OBJECT_SYNPROXY => ObjKind::Synproxy(ExprData::decode(attrs)?),
            NFT_OBJECT_CT_HELPER => {
                let mut h = CtHelper::default();
                for a in attrs {
                    let a = a?;
                    match a.ty {
                        NFTA_CT_HELPER_NAME => h.name = a.string()?,
                        NFTA_CT_HELPER_L3PROTO => h.l3proto = Some(a.be16()?),
                        NFTA_CT_HELPER_L4PROTO => h.l4proto = a.u8()?,
                        _ => {}
                    }
                }
                ObjKind::CtHelper(h)
            }
            NFT_OBJECT_CT_TIMEOUT => {
                let mut t = CtTimeout::default();
                for a in attrs {
                    let a = a?;
                    match a.ty {
                        NFTA_CT_TIMEOUT_L3PROTO => t.l3proto = Some(a.be16()?),
                        NFTA_CT_TIMEOUT_L4PROTO => t.l4proto = a.u8()?,
                        NFTA_CT_TIMEOUT_DATA => t.data = a.data.to_vec(),
                        _ => {}
                    }
                }
                ObjKind::CtTimeout(t)
            }
            NFT_OBJECT_CT_EXPECT => {
                let mut e = CtExpect::default();
                for a in attrs {
                    let a = a?;
                    match a.ty {
                        NFTA_CT_EXPECT_L3PROTO => e.l3proto = Some(a.be16()?),
                        NFTA_CT_EXPECT_L4PROTO => e.l4proto = a.u8()?,
                        NFTA_CT_EXPECT_DPORT => e.dport = a.be16()?,
                        NFTA_CT_EXPECT_TIMEOUT => e.timeout = a.ne32()?,
                        NFTA_CT_EXPECT_SIZE => e.size = a.u8()?,
                        _ => {}
                    }
                }
                ObjKind::CtExpect(e)
            }
            NFT_OBJECT_SECMARK => {
                let mut s = Secmark::default();
                for a in attrs {
                    let a = a?;
                    if a.ty == NFTA_SECMARK_CTX {
                        s.ctx = a.string()?;
                    }
                }
                ObjKind::Secmark(s)
            }
            ty => ObjKind::Unknown {
                ty,
                data: attrs.remaining().to_vec(),
            },
        })
    }
}

/// A named stateful object (counter, quota, limit, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Obj {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Object name.
    pub name: String,
    /// Kernel handle (read only).
    pub handle: Option<u64>,
    /// Reference count (read only).
    pub use_count: Option<u32>,
    /// User data.
    pub userdata: Option<Vec<u8>>,
    /// Type and state.
    pub kind: ObjKind,
}

impl Obj {
    /// A new object.
    pub fn new(
        family: Family,
        table: impl Into<String>,
        name: impl Into<String>,
        kind: ObjKind,
    ) -> Self {
        Obj {
            family,
            table: table.into(),
            name: name.into(),
            handle: None,
            use_count: None,
            userdata: None,
            kind,
        }
    }

    /// Set an nft comment.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.userdata = Some(udata::comment(comment));
        self
    }

    /// The nft comment, if any.
    pub fn comment(&self) -> Option<&str> {
        udata::get_str(self.userdata.as_deref()?, udata::UDATA_COMMENT)
    }
}

impl NlObject for Obj {
    const NEW: u8 = NFT_MSG_NEWOBJ;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_OBJ_TABLE, &self.table);
        w.put_str(NFTA_OBJ_NAME, &self.name);
        w.put_be32(NFTA_OBJ_TYPE, self.kind.obj_type());
        w.nest(NFTA_OBJ_DATA, |w| self.kind.encode(w));
        if let Some(u) = &self.userdata {
            w.put(NFTA_OBJ_USERDATA, u);
        }
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let (mut table, mut name, mut handle, mut use_count, mut userdata) =
            (None, None, None, None, None);
        let mut ty = None;
        let mut data = None;
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_OBJ_TABLE => table = Some(a.string()?),
                NFTA_OBJ_NAME => name = Some(a.string()?),
                NFTA_OBJ_TYPE => ty = Some(a.be32()?),
                NFTA_OBJ_DATA => data = Some(a),
                NFTA_OBJ_USE => use_count = Some(a.be32()?),
                NFTA_OBJ_HANDLE => handle = Some(a.be64()?),
                NFTA_OBJ_USERDATA => userdata = Some(a.data.to_vec()),
                _ => {}
            }
        }
        let ty = ty.ok_or_else(|| Error::malformed("object without type"))?;
        let attrs = data.map(|a| a.nested()).unwrap_or(Attrs::new(&[]));
        Ok(Obj {
            family,
            table: table.unwrap_or_default(),
            name: name.unwrap_or_default(),
            handle,
            use_count,
            userdata,
            kind: ObjKind::decode(ty, attrs)?,
        })
    }
}

// ------------------------------------------------------------------ flowtable

/// A flowtable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Flowtable {
    /// Family.
    pub family: Family,
    /// Table name.
    pub table: String,
    /// Name.
    pub name: String,
    /// Kernel handle (read only).
    pub handle: Option<u64>,
    /// Hook number (always ingress).
    pub hook: Option<Hook>,
    /// Priority.
    pub priority: Option<i32>,
    /// Devices.
    pub devices: Vec<String>,
    /// `NFT_FLOWTABLE_*` flags.
    pub flags: Option<u32>,
    /// Reference count (read only).
    pub use_count: Option<u32>,
}

impl NlObject for Flowtable {
    const NEW: u8 = NFT_MSG_NEWFLOWTABLE;

    fn family(&self) -> Family {
        self.family
    }

    fn encode(&self, w: &mut Writer) {
        w.put_str(NFTA_FLOWTABLE_TABLE, &self.table);
        w.put_str(NFTA_FLOWTABLE_NAME, &self.name);
        if self.hook.is_some() || self.priority.is_some() || !self.devices.is_empty() {
            w.nest(NFTA_FLOWTABLE_HOOK, |w| {
                self.hook.put_field(w, NFTA_FLOWTABLE_HOOK_NUM);
                self.priority.put_field(w, NFTA_FLOWTABLE_HOOK_PRIORITY);
                if !self.devices.is_empty() {
                    encode_devices(w, NFTA_FLOWTABLE_HOOK_DEVS, &self.devices);
                }
            });
        }
        self.flags.put_field(w, NFTA_FLOWTABLE_FLAGS);
    }

    fn decode(family: Family, attrs: Attrs<'_>) -> Result<Self> {
        let mut f = Flowtable {
            family,
            ..Default::default()
        };
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_FLOWTABLE_TABLE => f.table = a.string()?,
                NFTA_FLOWTABLE_NAME => f.name = a.string()?,
                NFTA_FLOWTABLE_HANDLE => f.handle = Some(a.be64()?),
                NFTA_FLOWTABLE_USE => f.use_count = Some(a.be32()?),
                NFTA_FLOWTABLE_FLAGS => f.flags = Some(a.be32()?),
                NFTA_FLOWTABLE_HOOK => {
                    for a in a.nested() {
                        let a = a?;
                        match a.ty {
                            NFTA_FLOWTABLE_HOOK_NUM => f.hook = Some(Hook(a.be32()?)),
                            NFTA_FLOWTABLE_HOOK_PRIORITY => f.priority = Some(a.be32()? as i32),
                            NFTA_FLOWTABLE_HOOK_DEVS => f.devices = decode_devices(&a)?,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(f)
    }
}

// ------------------------------------------------------------------ generation

/// The ruleset generation, incremented on every committed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Gen {
    /// Generation id.
    pub id: u32,
    /// PID of the process that made the last change (notifications only).
    pub proc_pid: Option<u32>,
    /// Name of that process.
    pub proc_name: Option<String>,
}

impl Gen {
    pub(crate) fn decode(attrs: Attrs<'_>) -> Result<Self> {
        let mut g = Gen::default();
        for a in attrs {
            let a = a?;
            match a.ty {
                NFTA_GEN_ID => g.id = a.be32()?,
                NFTA_GEN_PROC_PID => g.proc_pid = Some(a.be32()?),
                NFTA_GEN_PROC_NAME => g.proc_name = Some(a.string()?),
                _ => {}
            }
        }
        Ok(g)
    }
}

/// Any ruleset object, as carried in notifications and echo replies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Object {
    /// A table.
    Table(Table),
    /// A chain.
    Chain(Chain),
    /// A rule.
    Rule(Rule),
    /// A set.
    Set(Set),
    /// Set elements.
    SetElems(SetElemList),
    /// A stateful object.
    Obj(Obj),
    /// A flowtable.
    Flowtable(Flowtable),
    /// A generation.
    Gen(Gen),
}

impl Object {
    /// Decode an nf_tables message of the given subtype: whether it creates
    /// (`true`) or deletes the object, and the object. `Ok(None)` for
    /// messages without an object.
    pub fn decode(subtype: u8, family: u8, attrs: Attrs<'_>) -> Result<Option<(bool, Object)>> {
        let fam = || Family::from_raw(family);
        Ok(Some(match subtype {
            NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE => (
                subtype == NFT_MSG_NEWTABLE,
                Object::Table(Table::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN => (
                subtype == NFT_MSG_NEWCHAIN,
                Object::Chain(Chain::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWRULE | NFT_MSG_DELRULE => (
                subtype == NFT_MSG_NEWRULE,
                Object::Rule(Rule::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWSET | NFT_MSG_DELSET => (
                subtype == NFT_MSG_NEWSET,
                Object::Set(Set::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM => (
                subtype == NFT_MSG_NEWSETELEM,
                Object::SetElems(SetElemList::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWOBJ | NFT_MSG_DELOBJ => (
                subtype == NFT_MSG_NEWOBJ,
                Object::Obj(Obj::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWFLOWTABLE | NFT_MSG_DELFLOWTABLE => (
                subtype == NFT_MSG_NEWFLOWTABLE,
                Object::Flowtable(Flowtable::decode(fam()?, attrs)?),
            ),
            NFT_MSG_NEWGEN => (true, Object::Gen(Gen::decode(attrs)?)),
            _ => return Ok(None),
        }))
    }
}
