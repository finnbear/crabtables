//! Atomic transactions.
//!
//! A [`Batch`] collects ruleset changes that the kernel applies atomically:
//! either every operation succeeds, or none is applied. Each method returns
//! the operation's index, which identifies it in errors
//! ([`MessageError::index`]).
//!
//! The batch only encodes messages; sending is done by
//! [`Socket::commit`](crate::Socket::commit), the async equivalent, or by
//! your own I/O through [`Batch::encode`] and [`BatchResponse`].

use crate::describe;
use crate::error::{BatchError, Error, MessageError, Result};
use crate::nl::{ErrorMsg, Messages, Writer};
use crate::objects::*;
use crate::sys::*;
use crate::types::*;

/// Upper bound for the payload of a nested attribute (the length field is
/// 16 bits). Element lists are split into several messages below this.
const MAX_NEST: usize = 0xffff - 64;

#[derive(Debug, Clone, Copy)]
struct MsgMeta {
    /// Byte offset of the message in `body`.
    offset: usize,
    /// Operation index.
    op: usize,
    /// Index of the first element in this message (element lists only).
    elem_base: usize,
}

/// A transaction of ruleset changes.
#[derive(Debug, Clone, Default)]
pub struct Batch {
    body: Writer,
    msgs: Vec<MsgMeta>,
    ops: usize,
    genid: Option<u32>,
    echo: bool,
    next_id: u32,
}

impl Batch {
    /// An empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only commit if the ruleset generation still equals `genid`
    /// (optimistic concurrency control). Otherwise the kernel rejects the
    /// batch with `ERESTART`.
    pub fn with_genid(mut self, genid: u32) -> Self {
        self.genid = Some(genid);
        self
    }

    /// Set or clear the generation id check.
    pub fn set_genid(&mut self, genid: Option<u32>) {
        self.genid = genid;
    }

    /// Request echo replies (`NLM_F_ECHO`) for operations added after this
    /// call. Echoed objects carry kernel-assigned values such as rule
    /// handles and are returned in [`BatchOutcome::echoes`].
    pub fn set_echo(&mut self, echo: bool) {
        self.echo = echo;
    }

    /// Allocate a transaction id, unique within this batch, for
    /// [`Set::id`], [`Chain::id`] or [`Rule::id`]. Ids allow later
    /// operations in the same batch to refer to new objects (e.g.
    /// [`Lookup::set_id`](crate::expr::Lookup::set_id)).
    ///
    /// Sets without an id are given one automatically.
    pub fn alloc_id(&mut self) -> u32 {
        // Start high so that automatically allocated ids do not collide
        // with small hand-picked ones.
        self.next_id = self.next_id.wrapping_add(1);
        0x8000_0000 | self.next_id
    }

    /// Number of operations.
    pub fn len(&self) -> usize {
        self.ops
    }

    /// Whether the batch has no operations.
    pub fn is_empty(&self) -> bool {
        self.ops == 0
    }

    /// Number of netlink messages (excluding batch begin/end).
    pub fn message_count(&self) -> usize {
        self.msgs.len()
    }

    /// Encoded size of the operations in bytes.
    pub fn byte_len(&self) -> usize {
        self.body.len()
    }

    /// Remove all operations.
    pub fn clear(&mut self) {
        self.body.clear();
        self.msgs.clear();
        self.ops = 0;
    }

    fn begin(
        &mut self,
        subtype: u8,
        flags: u16,
        family: Family,
        elem_base: usize,
    ) -> crate::nl::MsgToken {
        self.msgs.push(MsgMeta {
            offset: self.body.len(),
            op: self.ops,
            elem_base,
        });
        let mut flags = flags | NLM_F_REQUEST;
        if self.echo {
            flags |= NLM_F_ECHO;
        }
        let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(subtype);
        self.body.begin_msg(ty, flags, 0, family.raw(), 0)
    }

    fn finish_op(&mut self) -> usize {
        self.ops += 1;
        self.ops - 1
    }

    /// Add an arbitrary nf_tables message. `subtype` is an `NFT_MSG_*`
    /// value; `f` writes the attributes.
    pub fn raw(
        &mut self,
        subtype: u8,
        flags: u16,
        family: Family,
        f: impl FnOnce(&mut Writer),
    ) -> usize {
        let m = self.begin(subtype, flags, family, 0);
        f(&mut self.body);
        self.body.end_msg(m);
        self.finish_op()
    }

    fn object<T: NlObject>(&mut self, obj: &T, flags: u16) -> usize {
        let m = self.begin(T::NEW, flags, obj.family(), 0);
        obj.encode(&mut self.body);
        self.body.end_msg(m);
        self.finish_op()
    }

    // ---------------------------------------------------------- tables

    /// Add a table. If it exists, its flags are updated (e.g. dormant);
    /// its user data (comment) cannot be changed.
    pub fn add_table(&mut self, t: &Table) -> usize {
        self.object(t, NLM_F_CREATE)
    }

    /// Add a table, failing with `EEXIST` if it exists.
    pub fn create_table(&mut self, t: &Table) -> usize {
        self.object(t, NLM_F_CREATE | NLM_F_EXCL)
    }

    /// Delete a table and everything in it.
    pub fn delete_table(&mut self, family: Family, name: &str) -> usize {
        self.raw(NFT_MSG_DELTABLE, 0, family, |w| {
            w.put_str(NFTA_TABLE_NAME, name)
        })
    }

    /// Delete a table by handle.
    pub fn delete_table_by_handle(&mut self, family: Family, handle: u64) -> usize {
        self.raw(NFT_MSG_DELTABLE, 0, family, |w| {
            w.put_be64(NFTA_TABLE_HANDLE, handle)
        })
    }

    /// Delete a table if it exists (no error if it does not; kernel >= 6.3).
    pub fn destroy_table(&mut self, family: Family, name: &str) -> usize {
        self.raw(NFT_MSG_DESTROYTABLE, 0, family, |w| {
            w.put_str(NFTA_TABLE_NAME, name)
        })
    }

    /// Delete all tables of `family`, or of all families with
    /// [`Family::Unspec`] (`nft flush ruleset`).
    pub fn flush_ruleset(&mut self, family: Family) -> usize {
        self.raw(NFT_MSG_DELTABLE, 0, family, |_| {})
    }

    /// Delete all rules in all chains of a table (`nft flush table`).
    pub fn flush_table(&mut self, family: Family, table: &str) -> usize {
        self.raw(NFT_MSG_DELRULE, 0, family, |w| {
            w.put_str(NFTA_RULE_TABLE, table)
        })
    }

    // ---------------------------------------------------------- chains

    /// Add a chain. If it exists, it is updated (e.g. the policy of a base
    /// chain); its user data (comment) cannot be changed.
    pub fn add_chain(&mut self, c: &Chain) -> usize {
        self.object(c, NLM_F_CREATE)
    }

    /// Add a chain, failing with `EEXIST` if it exists.
    pub fn create_chain(&mut self, c: &Chain) -> usize {
        self.object(c, NLM_F_CREATE | NLM_F_EXCL)
    }

    /// Rename the chain with the given handle.
    pub fn rename_chain(
        &mut self,
        family: Family,
        table: &str,
        handle: u64,
        new_name: &str,
    ) -> usize {
        self.raw(NFT_MSG_NEWCHAIN, 0, family, |w| {
            w.put_str(NFTA_CHAIN_TABLE, table);
            w.put_be64(NFTA_CHAIN_HANDLE, handle);
            w.put_str(NFTA_CHAIN_NAME, new_name);
        })
    }

    /// Delete an (empty, unreferenced) chain.
    pub fn delete_chain(&mut self, family: Family, table: &str, name: &str) -> usize {
        self.raw(NFT_MSG_DELCHAIN, 0, family, |w| {
            w.put_str(NFTA_CHAIN_TABLE, table);
            w.put_str(NFTA_CHAIN_NAME, name);
        })
    }

    /// Delete a chain by handle.
    pub fn delete_chain_by_handle(&mut self, family: Family, table: &str, handle: u64) -> usize {
        self.raw(NFT_MSG_DELCHAIN, 0, family, |w| {
            w.put_str(NFTA_CHAIN_TABLE, table);
            w.put_be64(NFTA_CHAIN_HANDLE, handle);
        })
    }

    /// Delete a chain if it exists (kernel >= 6.3).
    pub fn destroy_chain(&mut self, family: Family, table: &str, name: &str) -> usize {
        self.raw(NFT_MSG_DESTROYCHAIN, 0, family, |w| {
            w.put_str(NFTA_CHAIN_TABLE, table);
            w.put_str(NFTA_CHAIN_NAME, name);
        })
    }

    /// Delete all rules of a chain (`nft flush chain`).
    pub fn flush_chain(&mut self, family: Family, table: &str, chain: &str) -> usize {
        self.raw(NFT_MSG_DELRULE, 0, family, |w| {
            w.put_str(NFTA_RULE_TABLE, table);
            w.put_str(NFTA_RULE_CHAIN, chain);
        })
    }

    // ---------------------------------------------------------- rules

    /// Append a rule to its chain, or after the rule with handle
    /// `rule.position` if set.
    pub fn add_rule(&mut self, r: &Rule) -> usize {
        self.object(r, NLM_F_CREATE | NLM_F_APPEND)
    }

    /// Prepend a rule to its chain, or insert it before the rule with
    /// handle `rule.position` if set.
    pub fn insert_rule(&mut self, r: &Rule) -> usize {
        self.object(r, NLM_F_CREATE)
    }

    /// Replace the rule with handle `rule.handle`.
    pub fn replace_rule(&mut self, r: &Rule) -> Result<usize> {
        if r.handle.is_none() {
            return Err(Error::invalid("replace_rule requires a handle"));
        }
        let m = self.begin(NFT_MSG_NEWRULE, NLM_F_REPLACE, r.family, 0);
        r.encode_with(&mut self.body, true);
        self.body.end_msg(m);
        Ok(self.finish_op())
    }

    /// Delete a rule by handle.
    pub fn delete_rule(&mut self, family: Family, table: &str, chain: &str, handle: u64) -> usize {
        self.rule_by_handle(NFT_MSG_DELRULE, family, table, chain, handle)
    }

    /// Delete a rule by handle if it exists (kernel >= 6.3).
    pub fn destroy_rule(&mut self, family: Family, table: &str, chain: &str, handle: u64) -> usize {
        self.rule_by_handle(NFT_MSG_DESTROYRULE, family, table, chain, handle)
    }

    fn rule_by_handle(
        &mut self,
        msg: u8,
        family: Family,
        table: &str,
        chain: &str,
        handle: u64,
    ) -> usize {
        self.raw(msg, 0, family, |w| {
            w.put_str(NFTA_RULE_TABLE, table);
            w.put_str(NFTA_RULE_CHAIN, chain);
            w.put_be64(NFTA_RULE_HANDLE, handle);
        })
    }

    // ---------------------------------------------------------- sets

    /// Add a set. Adding an identical existing set is a no-op; a different
    /// set with the same name fails with `EEXIST`.
    pub fn add_set(&mut self, s: &Set) -> usize {
        self.set(s, NLM_F_CREATE)
    }

    /// Add a set, failing with `EEXIST` if it exists.
    pub fn create_set(&mut self, s: &Set) -> usize {
        self.set(s, NLM_F_CREATE | NLM_F_EXCL)
    }

    fn set(&mut self, s: &Set, flags: u16) -> usize {
        // The kernel requires a transaction id for every new set.
        let id = match s.id {
            Some(id) => id,
            None => self.alloc_id(),
        };
        let m = self.begin(NFT_MSG_NEWSET, flags, s.family, 0);
        s.encode_with_id(&mut self.body, Some(id));
        self.body.end_msg(m);
        self.finish_op()
    }

    /// Delete a set.
    pub fn delete_set(&mut self, family: Family, table: &str, name: &str) -> usize {
        self.raw(NFT_MSG_DELSET, 0, family, |w| {
            w.put_str(NFTA_SET_TABLE, table);
            w.put_str(NFTA_SET_NAME, name);
        })
    }

    /// Delete a set if it exists (kernel >= 6.3).
    pub fn destroy_set(&mut self, family: Family, table: &str, name: &str) -> usize {
        self.raw(NFT_MSG_DESTROYSET, 0, family, |w| {
            w.put_str(NFTA_SET_TABLE, table);
            w.put_str(NFTA_SET_NAME, name);
        })
    }

    /// Remove all elements of a set (`nft flush set`).
    pub fn flush_set(&mut self, family: Family, table: &str, set: &str) -> usize {
        self.raw(NFT_MSG_DELSETELEM, 0, family, |w| {
            w.put_str(NFTA_SET_ELEM_LIST_TABLE, table);
            w.put_str(NFTA_SET_ELEM_LIST_SET, set);
        })
    }

    /// Add elements. Adding an existing element is not an error; on recent
    /// kernels (observed on 6.12) its timeout and expiration are updated
    /// to the given values, which refreshes entries of dynamic blocklists.
    /// Use [`Batch::create_elems`] to fail on existing elements.
    pub fn add_elems(&mut self, l: &SetElemList) -> usize {
        self.elems(NFT_MSG_NEWSETELEM, NLM_F_CREATE, l)
    }

    /// Add elements, failing with `EEXIST` if any exists.
    pub fn create_elems(&mut self, l: &SetElemList) -> usize {
        self.elems(NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_EXCL, l)
    }

    /// Delete elements (each must exist). An empty list deletes nothing
    /// (use [`Batch::flush_set`] to delete all elements).
    pub fn delete_elems(&mut self, l: &SetElemList) -> usize {
        self.elems(NFT_MSG_DELSETELEM, 0, l)
    }

    /// Delete elements if they exist (kernel >= 6.3).
    pub fn destroy_elems(&mut self, l: &SetElemList) -> usize {
        self.elems(NFT_MSG_DESTROYSETELEM, 0, l)
    }

    fn elems(&mut self, subtype: u8, flags: u16, l: &SetElemList) -> usize {
        let mut i = 0;
        loop {
            let base = i;
            let m = self.begin(subtype, flags, l.family, base);
            l.encode_header(&mut self.body);
            // Always with the element list: without it, the kernel deletes
            // every element (that is `flush_set`).
            {
                let nest = self.body.begin_nest(NFTA_SET_ELEM_LIST_ELEMENTS);
                let nest_start = self.body.len();
                while i < l.elems.len() {
                    let before = self.body.len();
                    self.body.nest(NFTA_LIST_ELEM, |w| l.elems[i].encode(w));
                    if self.body.len() - nest_start > MAX_NEST && i > base {
                        // Does not fit: move this element to the next message.
                        self.body.truncate(before);
                        break;
                    }
                    i += 1;
                }
                self.body.end_nest(nest);
            }
            self.body.end_msg(m);
            if i >= l.elems.len() {
                break;
            }
        }
        self.finish_op()
    }

    // ---------------------------------------------------------- objects

    /// Add a stateful object. If it exists, types that support updates
    /// (e.g. quotas) are updated; others (e.g. counters) are left unchanged.
    pub fn add_obj(&mut self, o: &Obj) -> usize {
        self.object(o, NLM_F_CREATE)
    }

    /// Add a stateful object, failing with `EEXIST` if it exists.
    pub fn create_obj(&mut self, o: &Obj) -> usize {
        self.object(o, NLM_F_CREATE | NLM_F_EXCL)
    }

    /// Delete a stateful object.
    pub fn delete_obj(&mut self, family: Family, table: &str, name: &str, ty: ObjType) -> usize {
        self.obj_by_name(NFT_MSG_DELOBJ, family, table, name, ty)
    }

    /// Delete a stateful object if it exists (kernel >= 6.3).
    pub fn destroy_obj(&mut self, family: Family, table: &str, name: &str, ty: ObjType) -> usize {
        self.obj_by_name(NFT_MSG_DESTROYOBJ, family, table, name, ty)
    }

    fn obj_by_name(
        &mut self,
        msg: u8,
        family: Family,
        table: &str,
        name: &str,
        ty: ObjType,
    ) -> usize {
        self.raw(msg, 0, family, |w| {
            w.put_str(NFTA_OBJ_TABLE, table);
            w.put_str(NFTA_OBJ_NAME, name);
            w.put_be32(NFTA_OBJ_TYPE, ty.raw());
        })
    }

    // ---------------------------------------------------------- flowtables

    /// Add a flowtable.
    pub fn add_flowtable(&mut self, f: &Flowtable) -> usize {
        self.object(f, NLM_F_CREATE)
    }

    /// Delete a flowtable.
    pub fn delete_flowtable(&mut self, family: Family, table: &str, name: &str) -> usize {
        self.raw(NFT_MSG_DELFLOWTABLE, 0, family, |w| {
            w.put_str(NFTA_FLOWTABLE_TABLE, table);
            w.put_str(NFTA_FLOWTABLE_NAME, name);
        })
    }

    // ---------------------------------------------------------- encoding

    /// Encode the complete batch (begin, operations, end) into `out`,
    /// numbering messages from `seq`. Returns the response collector.
    ///
    /// After sending `out`, also send [`BatchResponse::sentinel`] so the end
    /// of the responses can be detected.
    pub fn encode(&self, out: &mut Vec<u8>, seq: u32) -> Result<BatchResponse> {
        self.encode_with(out, seq, true)
    }

    /// Like [`Batch::encode`], but for a dry run: the batch end message is
    /// left out, so the kernel validates every operation (reporting errors
    /// as usual) and then discards the batch.
    pub fn encode_check(&self, out: &mut Vec<u8>, seq: u32) -> Result<BatchResponse> {
        self.encode_with(out, seq, false)
    }

    fn encode_with(&self, out: &mut Vec<u8>, seq: u32, end: bool) -> Result<BatchResponse> {
        self.body.check()?;
        out.clear();
        out.reserve(self.body.len() + 64);
        let mut w = Writer::with_capacity(32);
        let m = w.begin_msg(
            NFNL_MSG_BATCH_BEGIN,
            NLM_F_REQUEST,
            seq,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES.into(),
        );
        if let Some(g) = self.genid {
            w.put_be32(NFNL_BATCH_GENID, g);
        }
        w.end_msg(m);
        out.extend_from_slice(w.as_bytes());
        let body_start = out.len();
        out.extend_from_slice(self.body.as_bytes());
        for (i, m) in self.msgs.iter().enumerate() {
            let s = seq.wrapping_add(1 + i as u32);
            let o = body_start + m.offset + 8;
            out[o..o + 4].copy_from_slice(&s.to_ne_bytes());
        }
        if !end {
            return Ok(BatchResponse::new(seq, self.msgs.len() as u32));
        }
        let end_seq = seq.wrapping_add(1 + self.msgs.len() as u32);
        let mut w = Writer::with_capacity(32);
        let m = w.begin_msg(
            NFNL_MSG_BATCH_END,
            NLM_F_REQUEST,
            end_seq,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES.into(),
        );
        w.end_msg(m);
        out.extend_from_slice(w.as_bytes());
        Ok(BatchResponse::new(seq, self.msgs.len() as u32))
    }

    /// Decode the batch's messages back into objects: for each message,
    /// whether it creates (`true`) or deletes the object, and the object.
    /// Messages that do not carry an object (e.g. flushes of a whole
    /// ruleset) or fail to decode are skipped.
    pub fn objects(&self) -> Vec<(bool, Object)> {
        crate::nl::Messages::new(self.body.as_bytes())
            .filter_map(|m| m.ok())
            .filter_map(|msg| {
                msg.nfgen()
                    .and_then(|(h, attrs)| Object::decode(msg.subtype(), h.family, attrs))
                    .ok()
                    .flatten()
            })
            .collect()
    }

    /// The operation adding or deleting elements of the set of `l`.
    fn elems_op(&self, l: &SetElemList) -> Option<usize> {
        (0..self.msgs.len()).find_map(|mi| {
            let msg = Messages::new(self.msg_bytes(mi)).next()?.ok()?;
            if !matches!(msg.subtype(), NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM) {
                return None;
            }
            let (h, attrs) = msg.nfgen().ok()?;
            let (_, Object::SetElems(m)) =
                Object::decode(msg.subtype(), h.family, attrs).ok()??
            else {
                return None;
            };
            (m.family == l.family && m.table == l.table && m.set == l.set)
                .then_some(self.msgs[mi].op)
        })
    }

    /// The encoded operation messages (without batch begin/end and with
    /// zero sequence numbers).
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }

    /// Upper estimate of the receive buffer space (in kernel accounting
    /// units) that the responses to this batch can occupy: an error per
    /// message, plus the echoed objects. Used to size the receive buffer so
    /// that no response is lost.
    pub fn response_size_hint(&self) -> usize {
        // A small netlink message occupies about 1 KiB of receive buffer
        // (skb overhead included).
        const PER_MSG: usize = 1024;
        let mut n = 4096;
        for (i, m) in self.msgs.iter().enumerate() {
            n += PER_MSG;
            let flags = u16::from_ne_bytes([
                self.body.as_bytes()[m.offset + 6],
                self.body.as_bytes()[m.offset + 7],
            ]);
            if flags & NLM_F_ECHO != 0 {
                n += PER_MSG + 2 * self.msg_bytes(i).len();
            }
        }
        n
    }

    fn msg_bytes(&self, i: usize) -> &[u8] {
        let start = self.msgs[i].offset;
        let end = self.msgs.get(i + 1).map_or(self.body.len(), |m| m.offset);
        &self.body.as_bytes()[start..end]
    }
}

/// The result of a successfully committed batch.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchOutcome {
    /// Ruleset generation after the commit (as observed right after it).
    pub genid: u32,
    /// Echoed objects for operations added with [`Batch::set_echo`]
    /// enabled, as `(operation index, object)`, in the order the kernel
    /// reported them. The kernel reports set elements one by one, without
    /// a reference to the message; their index is that of the operation
    /// on elements of the same set (`usize::MAX` if unknown, e.g. for
    /// elements of a set created in the same batch).
    pub echoes: Vec<(usize, Object)>,
    /// Whether some responses (echoes) were lost because the receive
    /// buffer overflowed (or could not be decoded). The batch itself was
    /// committed.
    pub responses_lost: bool,
}

impl BatchOutcome {
    /// Handles of the rules echoed by the kernel, in operation order.
    pub fn rule_handles(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.echoes.iter().filter_map(|(i, o)| match o {
            Object::Rule(r) => r.handle.map(|h| (*i, h)),
            _ => None,
        })
    }
}

/// An error response as received, before it is matched to the batch.
#[derive(Debug)]
struct RawError {
    seq: u32,
    errno: i32,
    message: Option<String>,
    offset: Option<u32>,
    miss_type: Option<u32>,
    missing: bool,
}

/// Sans-IO collector of the kernel's responses to a batch.
#[derive(Debug)]
pub struct BatchResponse {
    seq: u32,
    nmsgs: u32,
    errors: Vec<RawError>,
    echoes: Vec<(u32, Object)>,
    genid: Option<u32>,
    lost: bool,
    done: bool,
    sentinel_error: Option<i32>,
    genid_before: Option<u32>,
    echo_errors: usize,
}

impl BatchResponse {
    fn new(seq: u32, nmsgs: u32) -> Self {
        BatchResponse {
            seq,
            nmsgs,
            errors: Vec::new(),
            echoes: Vec::new(),
            genid: None,
            lost: false,
            done: false,
            sentinel_error: None,
            genid_before: None,
            echo_errors: 0,
        }
    }

    fn sentinel_seq(&self) -> u32 {
        self.seq.wrapping_add(self.nmsgs + 2)
    }

    /// Encode the request that terminates the response stream (a
    /// `GETGEN`, whose reply follows all batch responses).
    pub fn sentinel(&self, out: &mut Vec<u8>) {
        out.clear();
        let mut w = Writer::with_capacity(20);
        let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(NFT_MSG_GETGEN);
        let m = w.begin_msg(ty, NLM_F_REQUEST, self.sentinel_seq(), NFPROTO_UNSPEC, 0);
        w.end_msg(m);
        out.extend_from_slice(w.as_bytes());
    }

    /// Provide the ruleset generation observed before the batch was sent.
    /// If responses are lost, it is used to determine whether the batch was
    /// committed (the generation changed) or rejected with lost errors.
    pub fn set_genid_before(&mut self, genid: Option<u32>) {
        self.genid_before = genid;
    }

    /// Record that the socket reported `ENOBUFS` (responses were lost).
    pub fn set_lost(&mut self) {
        self.lost = true;
    }

    /// Whether the sentinel reply has been received.
    pub fn is_done(&self) -> bool {
        self.done
    }

    fn in_batch(&self, seq: u32) -> bool {
        seq.wrapping_sub(self.seq) <= self.nmsgs + 1
    }

    /// Process one received datagram.
    pub fn feed(&mut self, datagram: &[u8]) -> Result<()> {
        for msg in Messages::new(datagram) {
            let msg = msg?;
            if msg.ty == NLMSG_ERROR {
                let e = ErrorMsg::parse(&msg)?;
                if e.req_seq == self.sentinel_seq() {
                    self.sentinel_error = Some(-e.error);
                    self.done = true;
                } else if e.error != 0 && self.in_batch(e.req_seq) {
                    let missing = e.ext_miss_type.is_some();
                    let off = if missing {
                        e.ext_miss_nest
                    } else {
                        e.ext_offset
                    };
                    self.errors.push(RawError {
                        seq: e.req_seq,
                        errno: -e.error,
                        message: e.ext_msg.map(str::to_owned),
                        offset: off,
                        miss_type: e.ext_miss_type,
                        missing,
                    });
                }
                continue;
            }
            if msg.subsys() != NFNL_SUBSYS_NFTABLES {
                continue;
            }
            if msg.seq == self.sentinel_seq() && msg.subtype() == NFT_MSG_NEWGEN {
                let (_, attrs) = msg.nfgen()?;
                self.genid = Some(Gen::decode(attrs)?.id);
                self.done = true;
            } else if self.in_batch(msg.seq)
                // The kernel reports set elements without a sequence number.
                || (msg.seq == 0
                    && matches!(msg.subtype(), NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM))
            {
                // An echo. Failing to decode it must not turn a committed
                // batch into an error: count it as lost instead.
                match msg
                    .nfgen()
                    .and_then(|(h, attrs)| Object::decode(msg.subtype(), h.family, attrs))
                {
                    Ok(Some((_, obj))) => self.echoes.push((msg.seq, obj)),
                    Ok(None) => {}
                    Err(_) => self.echo_errors += 1,
                }
            }
        }
        Ok(())
    }

    /// Produce the final result. `batch` must be the batch this collector
    /// was created for; it is used to describe failed operations.
    pub fn finish(self, batch: &Batch) -> Result<BatchOutcome> {
        let op_of = |seq: u32| -> Option<usize> {
            let rel = seq.wrapping_sub(self.seq);
            (1..=self.nmsgs).contains(&rel).then(|| rel as usize - 1)
        };
        // If responses were lost without any error being seen, the errors
        // may have been lost: decide by whether the generation changed, if
        // it is known.
        let (failed_silently, outcome_unknown) = if self.lost && self.errors.is_empty() {
            match (self.genid_before, self.genid) {
                (Some(before), Some(after)) => (before == after, false),
                _ => (true, true),
            }
        } else {
            (false, false)
        };
        if !self.errors.is_empty() || failed_silently {
            let mut errors = Vec::with_capacity(self.errors.len());
            for RawError {
                seq,
                errno,
                message,
                offset: off,
                miss_type,
                missing,
            } in self.errors
            {
                let me = match op_of(seq) {
                    Some(mi) => {
                        let meta = batch.msgs[mi];
                        let bytes = batch.msg_bytes(mi);
                        MessageError {
                            index: Some(meta.op),
                            errno,
                            message,
                            operation: describe::operation(bytes),
                            location: off.map(|o| {
                                describe::locate(
                                    bytes,
                                    o as usize,
                                    meta.elem_base,
                                    missing,
                                    miss_type,
                                )
                            }),
                        }
                    }
                    None => MessageError {
                        index: None,
                        errno,
                        message,
                        operation: if seq == self.seq {
                            "batch begin".into()
                        } else {
                            "batch end".into()
                        },
                        location: None,
                    },
                };
                errors.push(me);
            }
            return Err(Error::Batch(BatchError {
                errors,
                responses_lost: self.lost,
                outcome_unknown,
            }));
        }
        if let Some(e) = self.sentinel_error {
            return Err(Error::Kernel(crate::error::KernelError {
                errno: e,
                message: None,
            }));
        }
        let echoes = self
            .echoes
            .into_iter()
            .filter_map(|(seq, o)| match (seq, &o) {
                // Elements: the operation adding elements to that set.
                (0, Object::SetElems(l)) => Some((batch.elems_op(l).unwrap_or(usize::MAX), o)),
                _ => op_of(seq).map(|mi| (batch.msgs[mi].op, o)),
            })
            .collect();
        Ok(BatchOutcome {
            genid: self.genid.unwrap_or(0),
            echoes,
            responses_lost: self.lost || self.echo_errors > 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_are_split() {
        let mut b = Batch::new();
        let mut l = SetElemList::new(Family::Inet, "t", "s");
        for i in 0..20000u32 {
            l.elems.push(SetElem::new(i.to_be_bytes().to_vec()));
        }
        let idx = b.add_elems(&l);
        assert_eq!(idx, 0);
        assert_eq!(b.len(), 1);
        assert!(b.message_count() > 1);
        let mut out = Vec::new();
        b.encode(&mut out, 100).unwrap();
        // All messages parse and contain all elements in order.
        let mut n = 0u32;
        for m in Messages::new(&out) {
            let m = m.unwrap();
            if m.subsys() != NFNL_SUBSYS_NFTABLES {
                continue;
            }
            let (h, attrs) = m.nfgen().unwrap();
            let d = SetElemList::decode(Family::from_raw(h.family).unwrap(), attrs).unwrap();
            for e in d.elems {
                assert_eq!(e.key.unwrap(), n.to_be_bytes());
                n += 1;
            }
        }
        assert_eq!(n, 20000);
    }

    /// Decide the outcome when responses were lost (sans-IO).
    #[test]
    fn lost_responses() {
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Inet, "a"));
        let mut out = Vec::new();
        let gen_msg = |r: &BatchResponse, id: u32| {
            let mut w = Writer::new();
            let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(NFT_MSG_NEWGEN);
            let m = w.begin_msg(ty, 0, r.sentinel_seq(), 0, 0);
            w.put_be32(NFTA_GEN_ID, id);
            w.end_msg(m);
            w.into_bytes()
        };
        // Generation unchanged: the batch failed, its errors were lost.
        let mut r = b.encode(&mut out, 1).unwrap();
        r.set_genid_before(Some(5));
        r.set_lost();
        r.feed(&gen_msg(&r, 5)).unwrap();
        assert!(r.is_done());
        match r.finish(&b) {
            Err(Error::Batch(e)) => {
                assert!(e.responses_lost && e.errors.is_empty() && !e.outcome_unknown)
            }
            x => panic!("{x:?}"),
        }
        // Generation changed: committed, some echoes lost.
        let mut r = b.encode(&mut out, 1).unwrap();
        r.set_genid_before(Some(5));
        r.set_lost();
        r.feed(&gen_msg(&r, 6)).unwrap();
        let o = r.finish(&b).unwrap();
        assert!(o.responses_lost);
        assert_eq!(o.genid, 6);
        // No information: reported as unknown (error).
        let mut r = b.encode(&mut out, 1).unwrap();
        r.set_lost();
        r.feed(&gen_msg(&r, 6)).unwrap();
        match r.finish(&b) {
            Err(Error::Batch(e)) => assert!(e.outcome_unknown),
            x => panic!("{x:?}"),
        }
    }

    #[test]
    fn sequence_numbers() {
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Inet, "a"));
        b.add_table(&Table::new(Family::Inet, "b"));
        let mut out = Vec::new();
        let r = b.encode(&mut out, 7).unwrap();
        let seqs: Vec<u32> = Messages::new(&out).map(|m| m.unwrap().seq).collect();
        assert_eq!(seqs, vec![7, 8, 9, 10]);
        let mut s = Vec::new();
        r.sentinel(&mut s);
        assert_eq!(Messages::new(&s).next().unwrap().unwrap().seq, 11);
    }
}
