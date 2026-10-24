//! Sans-IO request encoders and response collectors for nf_tables queries.
//!
//! These types are used by [`Socket`](crate::Socket) and the async socket,
//! and can drive any other I/O implementation: encode a request with
//! [`Request::encode`], send it, and pass every received datagram to
//! [`Collector::feed`] until it reports completion.

use std::collections::{HashMap, HashSet};

use crate::batch::Batch;
use crate::error::{Error, KernelError, Result};
use crate::expr::{Expr, Immediate};
use crate::nl::{ErrorMsg, Messages, Msg, Writer};
use crate::objects::*;
use crate::sys::*;
use crate::types::*;

/// An nf_tables query (dump or single object get).
#[derive(Debug, Clone)]
pub struct Request {
    subtype: u8,
    family: Family,
    dump: bool,
    attrs: Writer,
}

impl Request {
    /// A request of the given `NFT_MSG_GET*` type.
    pub fn new(subtype: u8, family: Family, dump: bool) -> Self {
        Request {
            subtype,
            family,
            dump,
            attrs: Writer::new(),
        }
    }

    /// Attribute writer for filter attributes.
    pub fn attrs(&mut self) -> &mut Writer {
        &mut self.attrs
    }

    /// Whether this is a dump.
    pub fn is_dump(&self) -> bool {
        self.dump
    }

    /// Encode with the given sequence number.
    pub fn encode(&self, out: &mut Vec<u8>, seq: u32) -> Collector {
        out.clear();
        let mut w = Writer::with_capacity(32 + self.attrs.len());
        let mut flags = NLM_F_REQUEST;
        if self.dump {
            flags |= NLM_F_DUMP;
        } else {
            flags |= NLM_F_ACK;
        }
        let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(self.subtype);
        let m = w.begin_msg(ty, flags, seq, self.family.raw(), 0);
        w.put_raw(self.attrs.as_bytes());
        w.end_msg(m);
        out.extend_from_slice(w.as_bytes());
        Collector {
            seq,
            dump: self.dump,
            done: false,
            interrupted: false,
            error: None,
        }
    }

    /// Dump tables.
    pub fn tables(family: Family) -> Self {
        Request::new(NFT_MSG_GETTABLE, family, true)
    }

    /// Get one table.
    pub fn table(family: Family, name: &str) -> Self {
        let mut r = Request::new(NFT_MSG_GETTABLE, family, false);
        r.attrs.put_str(NFTA_TABLE_NAME, name);
        r
    }

    /// Dump chains, optionally of one table.
    pub fn chains(family: Family, table: Option<&str>) -> Self {
        let mut r = Request::new(NFT_MSG_GETCHAIN, family, true);
        if let Some(t) = table {
            r.attrs.put_str(NFTA_CHAIN_TABLE, t);
        }
        r
    }

    /// Get one chain.
    pub fn chain(family: Family, table: &str, name: &str) -> Self {
        let mut r = Request::new(NFT_MSG_GETCHAIN, family, false);
        r.attrs.put_str(NFTA_CHAIN_TABLE, table);
        r.attrs.put_str(NFTA_CHAIN_NAME, name);
        r
    }

    /// Dump rules, optionally of one table / chain. With `reset`, counters
    /// and quotas are atomically read and zeroed.
    pub fn rules(family: Family, table: Option<&str>, chain: Option<&str>, reset: bool) -> Self {
        let ty = if reset {
            NFT_MSG_GETRULE_RESET
        } else {
            NFT_MSG_GETRULE
        };
        let mut r = Request::new(ty, family, true);
        if let Some(t) = table {
            r.attrs.put_str(NFTA_RULE_TABLE, t);
        }
        if let Some(c) = chain {
            r.attrs.put_str(NFTA_RULE_CHAIN, c);
        }
        r
    }

    /// Get one rule by handle.
    pub fn rule(family: Family, table: &str, chain: &str, handle: u64, reset: bool) -> Self {
        let ty = if reset {
            NFT_MSG_GETRULE_RESET
        } else {
            NFT_MSG_GETRULE
        };
        let mut r = Request::new(ty, family, false);
        r.attrs.put_str(NFTA_RULE_TABLE, table);
        r.attrs.put_str(NFTA_RULE_CHAIN, chain);
        r.attrs.put_be64(NFTA_RULE_HANDLE, handle);
        r
    }

    /// Dump sets, optionally of one table.
    pub fn sets(family: Family, table: Option<&str>) -> Self {
        let mut r = Request::new(NFT_MSG_GETSET, family, true);
        if let Some(t) = table {
            r.attrs.put_str(NFTA_SET_TABLE, t);
        }
        r
    }

    /// Get one set.
    pub fn set(family: Family, table: &str, name: &str) -> Self {
        let mut r = Request::new(NFT_MSG_GETSET, family, false);
        r.attrs.put_str(NFTA_SET_TABLE, table);
        r.attrs.put_str(NFTA_SET_NAME, name);
        r
    }

    /// Dump the elements of a set. With `reset`, element counters/quotas
    /// are zeroed (kernel >= 6.5).
    pub fn elems(family: Family, table: &str, set: &str, reset: bool) -> Self {
        let ty = if reset {
            NFT_MSG_GETSETELEM_RESET
        } else {
            NFT_MSG_GETSETELEM
        };
        let mut r = Request::new(ty, family, true);
        r.attrs.put_str(NFTA_SET_ELEM_LIST_TABLE, table);
        r.attrs.put_str(NFTA_SET_ELEM_LIST_SET, set);
        r
    }

    /// Get specific elements of a set (the kernel looks up each key; for
    /// interval sets, the containing interval is returned).
    pub fn get_elems(
        family: Family,
        table: &str,
        set: &str,
        keys: &[SetElem],
        reset: bool,
    ) -> Self {
        let ty = if reset {
            NFT_MSG_GETSETELEM_RESET
        } else {
            NFT_MSG_GETSETELEM
        };
        let mut r = Request::new(ty, family, false);
        r.attrs.put_str(NFTA_SET_ELEM_LIST_TABLE, table);
        r.attrs.put_str(NFTA_SET_ELEM_LIST_SET, set);
        r.attrs.nest(NFTA_SET_ELEM_LIST_ELEMENTS, |w| {
            for e in keys {
                w.nest(NFTA_LIST_ELEM, |w| e.encode(w));
            }
        });
        r
    }

    /// Dump stateful objects, optionally filtered by table and type. With
    /// `reset`, counters and quotas are atomically read and zeroed.
    pub fn objs(family: Family, table: Option<&str>, ty: Option<ObjType>, reset: bool) -> Self {
        let msg = if reset {
            NFT_MSG_GETOBJ_RESET
        } else {
            NFT_MSG_GETOBJ
        };
        let mut r = Request::new(msg, family, true);
        if let Some(t) = table {
            r.attrs.put_str(NFTA_OBJ_TABLE, t);
        }
        if let Some(t) = ty {
            r.attrs.put_be32(NFTA_OBJ_TYPE, t.raw());
        }
        r
    }

    /// Get one stateful object.
    pub fn obj(family: Family, table: &str, name: &str, ty: ObjType, reset: bool) -> Self {
        let msg = if reset {
            NFT_MSG_GETOBJ_RESET
        } else {
            NFT_MSG_GETOBJ
        };
        let mut r = Request::new(msg, family, false);
        r.attrs.put_str(NFTA_OBJ_TABLE, table);
        r.attrs.put_str(NFTA_OBJ_NAME, name);
        r.attrs.put_be32(NFTA_OBJ_TYPE, ty.raw());
        r
    }

    /// Dump flowtables.
    pub fn flowtables(family: Family, table: Option<&str>) -> Self {
        let mut r = Request::new(NFT_MSG_GETFLOWTABLE, family, true);
        if let Some(t) = table {
            r.attrs.put_str(NFTA_FLOWTABLE_TABLE, t);
        }
        r
    }

    /// Get the ruleset generation.
    pub fn generation() -> Self {
        Request::new(NFT_MSG_GETGEN, Family::Unspec, false)
    }
}

/// Collects the responses to a [`Request`].
#[derive(Debug)]
pub struct Collector {
    seq: u32,
    dump: bool,
    done: bool,
    interrupted: bool,
    error: Option<KernelError>,
}

impl Collector {
    /// Whether the response is complete.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Whether the dump was interrupted by a concurrent ruleset change
    /// (`NLM_F_DUMP_INTR`), in which case its results are inconsistent and
    /// the request should be repeated.
    pub fn interrupted(&self) -> bool {
        self.interrupted
    }

    /// Process one datagram, calling `f` for every data message belonging
    /// to this request.
    pub fn feed(
        &mut self,
        datagram: &[u8],
        mut f: impl FnMut(&Msg<'_>) -> Result<()>,
    ) -> Result<()> {
        for msg in Messages::new(datagram) {
            let msg = msg?;
            if msg.seq != self.seq || self.done {
                // Stale response to an earlier request (e.g. one that was
                // abandoned after an error): ignore.
                continue;
            }
            if msg.flags & NLM_F_DUMP_INTR != 0 {
                self.interrupted = true;
            }
            match msg.ty {
                NLMSG_DONE => self.done = true,
                NLMSG_ERROR => {
                    let e = ErrorMsg::parse(&msg)?;
                    if e.error != 0 {
                        self.error = Some(KernelError {
                            errno: -e.error,
                            message: e.ext_msg.map(str::to_owned),
                        });
                    }
                    // An ack (error 0) terminates a non-dump request; an
                    // error terminates any request.
                    self.done = true;
                }
                NLMSG_NOOP => {}
                NLMSG_OVERRUN => return Err(Error::malformed("netlink overrun")),
                _ => {
                    f(&msg)?;
                    // Note: for non-dump requests we asked for an ACK, which
                    // follows the reply.
                }
            }
        }
        Ok(())
    }

    /// Final status.
    pub fn finish(self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::Kernel(e)),
            None if !self.done => Err(Error::malformed("incomplete response")),
            None => Ok(()),
        }
    }

    /// Whether this collects a dump.
    pub fn is_dump(&self) -> bool {
        self.dump
    }
}

/// Decode a data message into an object of type `T`.
pub(crate) fn decode_msg<T: NlObject>(msg: &Msg<'_>) -> Result<T> {
    let (h, attrs) = msg.nfgen()?;
    T::decode(Family::from_raw(h.family)?, attrs)
}

/// Trait for objects that can be decoded from dump messages.
pub trait Decode: Sized {
    /// Decode from an nf_tables message.
    fn decode_msg(msg: &Msg<'_>) -> Result<Self>;
}

macro_rules! impl_decode {
    ($($t:ty),*) => {$(
        impl Decode for $t {
            fn decode_msg(msg: &Msg<'_>) -> Result<Self> {
                decode_msg(msg)
            }
        }
    )*};
}
impl_decode!(Table, Chain, Rule, Set, SetElemList, Obj, Flowtable);

impl Decode for Gen {
    fn decode_msg(msg: &Msg<'_>) -> Result<Self> {
        let (_, attrs) = msg.nfgen()?;
        Gen::decode(attrs)
    }
}

/// A consistent snapshot of a ruleset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ruleset {
    /// Generation the snapshot was taken at.
    pub genid: u32,
    /// Tables.
    pub tables: Vec<Table>,
    /// Chains.
    pub chains: Vec<Chain>,
    /// Sets with their elements (including anonymous sets).
    pub sets: Vec<(Set, Vec<SetElem>)>,
    /// Stateful objects.
    pub objs: Vec<Obj>,
    /// Flowtables.
    pub flowtables: Vec<Flowtable>,
    /// Rules, in chain order.
    pub rules: Vec<Rule>,
}

impl Ruleset {
    /// Rules of one chain.
    pub fn chain_rules<'a>(
        &'a self,
        family: Family,
        table: &'a str,
        chain: &'a str,
    ) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules
            .iter()
            .filter(move |r| r.family == family && r.table == table && r.chain == chain)
    }

    /// Build a batch that recreates this ruleset (into an empty ruleset).
    ///
    /// Read-only attributes (handles, use counts, owners) are dropped.
    /// Anonymous sets are recreated under their existing names so that
    /// rules can refer to them.
    pub fn to_batch(&self) -> Batch {
        let mut b = Batch::new();
        for t in &self.tables {
            let mut t = t.clone();
            if let Some(f) = &mut t.flags {
                // The owner flag binds the table to the creating socket.
                *f &= !NFT_TABLE_F_OWNER;
            }
            b.add_table(&t);
        }
        for c in &self.chains {
            let mut c = c.clone();
            c.handle = None;
            if c.hook.is_none() {
                c.counters = None;
            }
            b.add_chain(&c);
        }
        for o in &self.objs {
            b.add_obj(o);
        }
        for f in &self.flowtables {
            b.add_flowtable(f);
        }
        for (s, elems) in &self.sets {
            b.add_set(s);
            if !elems.is_empty() {
                let mut l = SetElemList::new(s.family, s.table.clone(), s.name.clone());
                l.elems = elems.clone();
                b.add_elems(&l);
            }
        }
        // Rules of binding chains (anonymous `jump { ... }` chains) must be
        // added before the rule that jumps to (and thereby binds) the chain.
        type Key<'a> = (Family, &'a str, &'a str);
        let binding: HashSet<Key<'_>> = self
            .chains
            .iter()
            .filter(|c| c.flags.unwrap_or(0) & NFT_CHAIN_BINDING != 0)
            .map(|c| (c.family, c.table.as_str(), c.name.as_str()))
            .collect();
        let mut by_chain: HashMap<Key<'_>, Vec<&Rule>> = HashMap::new();
        for r in &self.rules {
            by_chain
                .entry((r.family, r.table.as_str(), r.chain.as_str()))
                .or_default()
                .push(r);
        }
        fn emit<'a>(
            key: Key<'a>,
            by_chain: &HashMap<Key<'a>, Vec<&'a Rule>>,
            binding: &HashSet<Key<'a>>,
            emitted: &mut HashSet<Key<'a>>,
            b: &mut Batch,
        ) {
            for r in by_chain.get(&key).map(Vec::as_slice).unwrap_or(&[]) {
                for e in &r.exprs {
                    if let Expr::Immediate(Immediate {
                        data: Data::Verdict(Verdict::Jump(t) | Verdict::Goto(t)),
                        ..
                    }) = e
                    {
                        let target = (key.0, key.1, t.as_str());
                        if binding.contains(&target) && emitted.insert(target) {
                            emit(target, by_chain, binding, emitted, b);
                        }
                    }
                }
                let mut r = (*r).clone();
                r.handle = None;
                r.position = None;
                b.add_rule(&r);
            }
        }
        let mut emitted = HashSet::new();
        for c in &self.chains {
            let key = (c.family, c.table.as_str(), c.name.as_str());
            if !binding.contains(&key) {
                emit(key, &by_chain, &binding, &mut emitted, &mut b);
            }
        }
        // Binding chains that nothing jumps to.
        for c in &self.chains {
            let key = (c.family, c.table.as_str(), c.name.as_str());
            if binding.contains(&key) && emitted.insert(key) {
                emit(key, &by_chain, &binding, &mut emitted, &mut b);
            }
        }
        b
    }
}
