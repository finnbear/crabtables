//! Ruleset change notifications (like `nft monitor`).
//!
//! The kernel broadcasts every committed change to the `NFNLGRP_NFTABLES`
//! multicast group: one message per created or deleted object, followed by
//! a [`Gen`] message for the new generation. Packets marked with
//! `meta nftrace set 1` are reported to `NFNLGRP_NFTRACE` ([`Trace`]).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use netlink_sys::Socket as NlSocket;

use crate::error::{Error, Result};
use crate::nl::{Attrs, Messages, Msg};
use crate::objects::{Gen, Object};
use crate::socket::{RECV_BUF, is_enobufs, open_socket, recv_datagram};
use crate::sys::*;
use crate::types::Verdict;

/// A ruleset change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
    /// An object was created (or, for rules/chains, possibly replaced).
    New(Object),
    /// An object was deleted.
    Del(Object),
    /// A transaction was committed; this follows its other events.
    Commit(Gen),
    /// A packet trace event (see [`Monitor::with_trace`]).
    Trace(Trace),
    /// Notifications were lost because the receive buffer overflowed: the
    /// local view must be re-synchronized (e.g. with
    /// [`Socket::list_ruleset`](crate::Socket::list_ruleset)).
    Overrun,
}

/// Kind of a trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TraceType {
    /// The packet reached the end of a base chain; `verdict` is its policy.
    Policy,
    /// The packet reached the end of a regular chain and returns.
    Return,
    /// A rule matched; `rule_handle` identifies it.
    Rule,
    /// Unknown type.
    Other(u32),
}

/// A packet trace event, generated for packets with `meta nftrace set 1`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Trace {
    /// Family of the table.
    pub family: u8,
    /// Event kind.
    pub ty: Option<TraceType>,
    /// Table name.
    pub table: Option<String>,
    /// Chain name.
    pub chain: Option<String>,
    /// Handle of the matching rule.
    pub rule_handle: Option<u64>,
    /// Verdict.
    pub verdict: Option<Verdict>,
    /// Trace id, identical for all events of the same packet.
    pub id: Option<u32>,
    /// Link layer header.
    pub ll_header: Option<Vec<u8>>,
    /// Network header.
    pub network_header: Option<Vec<u8>>,
    /// Transport header.
    pub transport_header: Option<Vec<u8>>,
    /// Input interface index.
    pub iif: Option<u32>,
    /// Input interface type.
    pub iiftype: Option<u16>,
    /// Output interface index.
    pub oif: Option<u32>,
    /// Output interface type.
    pub oiftype: Option<u16>,
    /// Packet mark.
    pub mark: Option<u32>,
    /// Netfilter protocol of the packet.
    pub nfproto: Option<u32>,
    /// Chain policy (for [`TraceType::Policy`]).
    pub policy: Option<u32>,
}

fn parse_trace(family: u8, attrs: Attrs<'_>) -> Result<Trace> {
    let mut t = Trace {
        family,
        ..Default::default()
    };
    for a in attrs {
        let a = a?;
        match a.ty {
            NFTA_TRACE_TABLE => t.table = Some(a.string()?),
            NFTA_TRACE_CHAIN => t.chain = Some(a.string()?),
            NFTA_TRACE_RULE_HANDLE => t.rule_handle = Some(a.be64()?),
            NFTA_TRACE_TYPE => {
                t.ty = Some(match a.be32()? {
                    1 => TraceType::Policy,
                    2 => TraceType::Return,
                    3 => TraceType::Rule,
                    x => TraceType::Other(x),
                })
            }
            NFTA_TRACE_VERDICT => t.verdict = Some(Verdict::decode(a.nested())?),
            NFTA_TRACE_ID => t.id = Some(a.be32()?),
            NFTA_TRACE_LL_HEADER => t.ll_header = Some(a.data.to_vec()),
            NFTA_TRACE_NETWORK_HEADER => t.network_header = Some(a.data.to_vec()),
            NFTA_TRACE_TRANSPORT_HEADER => t.transport_header = Some(a.data.to_vec()),
            NFTA_TRACE_IIF => t.iif = Some(a.be32()?),
            NFTA_TRACE_IIFTYPE => t.iiftype = Some(a.be16()?),
            NFTA_TRACE_OIF => t.oif = Some(a.be32()?),
            NFTA_TRACE_OIFTYPE => t.oiftype = Some(a.be16()?),
            NFTA_TRACE_MARK => t.mark = Some(a.be32()?),
            NFTA_TRACE_NFPROTO => t.nfproto = Some(a.be32()?),
            NFTA_TRACE_POLICY => t.policy = Some(a.be32()?),
            _ => {}
        }
    }
    Ok(t)
}

/// Decode the events contained in one datagram (sans-IO). Messages that
/// cannot be decoded are skipped, and the first such error is returned
/// after all others are decoded into `out`.
pub fn parse_events(datagram: &[u8], out: &mut Vec<Event>) -> Result<()> {
    let mut first_err = None;
    for m in Messages::new(datagram) {
        let m = match m {
            Ok(m) => m,
            Err(e) => {
                // (The rest of the datagram cannot be framed.)
                first_err.get_or_insert(e);
                break;
            }
        };
        if let Err(e) = parse_event(&m, out) {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn parse_event(m: &Msg<'_>, out: &mut Vec<Event>) -> Result<()> {
    if m.subsys() != NFNL_SUBSYS_NFTABLES {
        return Ok(());
    }
    let (h, attrs) = m.nfgen()?;
    if m.subtype() == NFT_MSG_TRACE {
        out.push(Event::Trace(parse_trace(h.family, attrs)?));
        return Ok(());
    }
    if let Some((new, obj)) = Object::decode(m.subtype(), h.family, attrs)? {
        out.push(match obj {
            Object::Gen(g) => Event::Commit(g),
            o if new => Event::New(o),
            o => Event::Del(o),
        });
    }
    Ok(())
}

/// A socket subscribed to ruleset change notifications.
#[derive(Debug)]
pub struct Monitor {
    sock: NlSocket,
    rbuf: Vec<u8>,
    /// A decoding error to report after the events decoded before it.
    pending_err: Option<Error>,
}

impl Monitor {
    /// Subscribe to ruleset changes in the current network namespace.
    pub fn new() -> Result<Self> {
        Self::with_groups(true, false)
    }

    /// Subscribe to packet trace events only (`nft monitor trace`).
    pub fn with_trace() -> Result<Self> {
        Self::with_groups(false, true)
    }

    /// Subscribe to ruleset changes and/or trace events.
    pub fn with_groups(changes: bool, trace: bool) -> Result<Self> {
        let (sock, _) = open_socket()?;
        if changes {
            sock.add_membership(NFNLGRP_NFTABLES)?;
        }
        if trace {
            sock.add_membership(NFNLGRP_NFTRACE)?;
        }
        Ok(Monitor {
            sock,
            rbuf: Vec::new(),
            pending_err: None,
        })
    }

    /// Make [`Monitor::recv`] fail with a `WouldBlock` I/O error if nothing
    /// arrives within `timeout` (`None` waits forever).
    pub fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        Ok(crate::socket::set_recv_timeout(
            self.sock.as_raw_fd(),
            timeout,
        )?)
    }

    /// Block until notifications arrive and return them.
    ///
    /// A message that cannot be decoded is reported as an error, after the
    /// events received before it (by the next call).
    pub fn recv(&mut self) -> Result<Vec<Event>> {
        if let Some(e) = self.pending_err.take() {
            return Err(e);
        }
        let mut v = Vec::new();
        match self.recv_into(&mut v, 0) {
            Ok(true) => Ok(v),
            Ok(false) => Err(Error::Io(io::ErrorKind::WouldBlock.into())),
            Err(e) => self.defer(v, e),
        }
    }

    /// Return pending notifications without blocking (possibly none).
    pub fn try_recv(&mut self) -> Result<Vec<Event>> {
        if let Some(e) = self.pending_err.take() {
            return Err(e);
        }
        let mut v = Vec::new();
        loop {
            match self.recv_into(&mut v, libc::MSG_DONTWAIT) {
                Ok(true) => {}
                Ok(false) => return Ok(v),
                Err(e) => return self.defer(v, e),
            }
        }
    }

    /// Return the events `v`, and the error `e` with the next call.
    fn defer(&mut self, v: Vec<Event>, e: Error) -> Result<Vec<Event>> {
        if v.is_empty() {
            Err(e)
        } else {
            self.pending_err = Some(e);
            Ok(v)
        }
    }

    fn recv_into(&mut self, v: &mut Vec<Event>, flags: i32) -> Result<bool> {
        loop {
            match recv_datagram(&self.sock, &mut self.rbuf, RECV_BUF, flags) {
                Ok(_) => {
                    parse_events(&self.rbuf, v)?;
                    return Ok(true);
                }
                Err(e) if is_enobufs(&e) => {
                    v.push(Event::Overrun);
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl AsRawFd for Monitor {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl AsFd for Monitor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sock.as_fd()
    }
}
