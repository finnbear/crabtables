//! NFLOG: receive packets logged by `log group N` rules (nfnetlink_log).
//!
//! Use a dedicated [`NflogSocket`] (or the async variant) per set of
//! groups; it is independent of any nf_tables [`Socket`](crate::Socket).
//!
//! # Overflow accounting
//!
//! If the application does not read fast enough, the kernel drops log
//! messages and reports `ENOBUFS` on the socket. Each such report is counted
//! in [`Stats::overruns`]. When the group is configured with
//! [`GroupConfig::seq`] (the default), every packet carries a per-group
//! sequence number and the exact number of lost packets is computed from
//! gaps: [`Stats::lost`]. Losses at the very end are only detected once the
//! next packet of that group arrives.
//!
//! ```no_run
//! use crabtables::nflog::{GroupConfig, NflogSocket};
//! let mut s = NflogSocket::new()?;
//! s.bind(&GroupConfig::new(5))?;
//! loop {
//!     for pkt in s.recv()? {
//!         let pkt = pkt?;
//!         println!("{:?} {} bytes", pkt.prefix, pkt.payload.len());
//!     }
//!     println!("lost so far: {}", s.stats().lost);
//! }
//! # Ok::<(), crabtables::Error>(())
//! ```

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::{Duration, Instant};

use netlink_sys::Socket as NlSocket;

use crate::error::{Error, KernelError, Result};
use crate::nl::{ErrorMsg, Messages, Msg, Writer};
use crate::socket::{
    initial_seq, is_enobufs, open_socket, recv_datagram, setsockopt_int, wait_readable,
};
use crate::sys::*;

/// How much of each packet the kernel copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CopyMode {
    /// Nothing but the existence of the packet.
    None,
    /// Metadata only (no payload).
    Meta,
    /// Metadata and up to this many bytes of payload (`0xffff` for all).
    /// The rule's `snaplen` further limits the size.
    Packet(u32),
}

/// Configuration of a log group.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupConfig {
    /// Group number (`log group N`).
    pub group: u16,
    /// Copy mode.
    pub copy_mode: CopyMode,
    /// Size of the kernel's per-group message buffer in bytes.
    pub nlbufsiz: Option<u32>,
    /// Maximum time the kernel holds queued packets before sending.
    pub timeout: Option<Duration>,
    /// Number of packets the kernel batches into one datagram before
    /// sending (`None` keeps the kernel default of 100).
    pub qthresh: Option<u32>,
    /// `NFULNL_CFG_F_*` flags.
    pub flags: u16,
}

impl GroupConfig {
    /// Default configuration: copy whole packets, per-group sequence
    /// numbers enabled (for loss detection), and immediate delivery
    /// (`qthresh` 1).
    ///
    /// Note that the kernel's own default queue threshold is 100 packets
    /// with a 1 second flush timeout, which delays delivery of sparse
    /// traffic by up to a second. Raise [`GroupConfig::qthresh`] (and lower
    /// [`GroupConfig::timeout`]) to batch packets for higher throughput.
    /// A `queue-threshold` on the `log` rule overrides the group's value.
    pub fn new(group: u16) -> Self {
        GroupConfig {
            group,
            copy_mode: CopyMode::Packet(0xffff),
            nlbufsiz: None,
            timeout: None,
            qthresh: Some(1),
            flags: NFULNL_CFG_F_SEQ,
        }
    }

    /// Set the copy mode.
    pub fn copy_mode(mut self, m: CopyMode) -> Self {
        self.copy_mode = m;
        self
    }

    /// Set the kernel buffer size.
    pub fn nlbufsiz(mut self, n: u32) -> Self {
        self.nlbufsiz = Some(n);
        self
    }

    /// Set the flush timeout (resolution 10 ms).
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Set the queue threshold.
    pub fn qthresh(mut self, n: u32) -> Self {
        self.qthresh = Some(n);
        self
    }

    /// Enable or disable per-group sequence numbers.
    pub fn seq(mut self, on: bool) -> Self {
        if on {
            self.flags |= NFULNL_CFG_F_SEQ;
        } else {
            self.flags &= !NFULNL_CFG_F_SEQ;
        }
        self
    }

    /// Enable or disable global sequence numbers.
    pub fn seq_global(mut self, on: bool) -> Self {
        if on {
            self.flags |= NFULNL_CFG_F_SEQ_GLOBAL;
        } else {
            self.flags &= !NFULNL_CFG_F_SEQ_GLOBAL;
        }
        self
    }

    /// Enable or disable conntrack information (`NFULA_CT`,
    /// `NFULA_CT_INFO`). The kernel only adds it when the
    /// `nf_conntrack_netlink` module is loaded and the packet is tracked,
    /// i.e. conntrack is active in the network namespace (some rule uses a
    /// `ct` expression).
    pub fn conntrack(mut self, on: bool) -> Self {
        if on {
            self.flags |= NFULNL_CFG_F_CONNTRACK;
        } else {
            self.flags &= !NFULNL_CFG_F_CONNTRACK;
        }
        self
    }

    /// Size of receive buffer needed for one datagram of this group.
    pub(crate) fn datagram_size(&self) -> usize {
        let copy = match self.copy_mode {
            CopyMode::Packet(n) => n as usize,
            _ => 0,
        };
        // The kernel allocates max(nlbufsiz, size of one message).
        (self.nlbufsiz.unwrap_or(0) as usize)
            .max(copy + 1024)
            .max(64 * 1024)
            + 4096
    }
}

fn config_msg(out: &mut Vec<u8>, seq: u32, group: u16, cmd: Option<u8>, cfg: Option<&GroupConfig>) {
    let mut w = Writer::with_capacity(64);
    let ty = (u16::from(NFNL_SUBSYS_ULOG) << 8) | u16::from(NFULNL_MSG_CONFIG);
    let m = w.begin_msg(ty, NLM_F_REQUEST | NLM_F_ACK, seq, NFPROTO_UNSPEC, group);
    if let Some(c) = cmd {
        w.put_u8(NFULA_CFG_CMD, c);
    }
    if let Some(cfg) = cfg {
        let (range, mode) = match cfg.copy_mode {
            CopyMode::None => (0, NFULNL_COPY_NONE),
            CopyMode::Meta => (0, NFULNL_COPY_META),
            CopyMode::Packet(n) => (n, NFULNL_COPY_PACKET),
        };
        let mut v = [0u8; 6];
        v[..4].copy_from_slice(&range.to_be_bytes());
        v[4] = mode;
        w.put(NFULA_CFG_MODE, &v);
        if let Some(n) = cfg.nlbufsiz {
            w.put_be32(NFULA_CFG_NLBUFSIZ, n);
        }
        if let Some(t) = cfg.timeout {
            w.put_be32(
                NFULA_CFG_TIMEOUT,
                (t.as_millis() / 10).min(u32::MAX as u128) as u32,
            );
        }
        if let Some(n) = cfg.qthresh {
            w.put_be32(NFULA_CFG_QTHRESH, n);
        }
        w.put_be16(NFULA_CFG_FLAGS, cfg.flags);
    }
    w.end_msg(m);
    out.clear();
    out.extend_from_slice(w.as_bytes());
}

/// Encode a request binding `cfg.group` to the sending socket and applying
/// the configuration (sans-IO).
pub fn bind_request(out: &mut Vec<u8>, seq: u32, cfg: &GroupConfig) {
    config_msg(out, seq, cfg.group, Some(NFULNL_CFG_CMD_BIND), Some(cfg));
}

/// Encode a request changing the configuration of a bound group (sans-IO).
pub fn config_request(out: &mut Vec<u8>, seq: u32, cfg: &GroupConfig) {
    config_msg(out, seq, cfg.group, None, Some(cfg));
}

/// Encode a request unbinding a group (sans-IO).
pub fn unbind_request(out: &mut Vec<u8>, seq: u32, group: u16) {
    config_msg(out, seq, group, Some(NFULNL_CFG_CMD_UNBIND), None);
}

/// A logged packet, borrowing from the receive buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Log group.
    pub group: u16,
    /// Protocol family (`NFPROTO_*`) of the hook that logged the packet.
    pub family: u8,
    /// Link layer protocol (ethertype).
    pub hw_protocol: u16,
    /// Netfilter hook number.
    pub hook: u8,
    /// Packet mark.
    pub mark: Option<u32>,
    /// Timestamp (time since the Unix epoch), if the packet has one.
    pub timestamp: Option<Duration>,
    /// Input interface index.
    pub indev: Option<u32>,
    /// Output interface index.
    pub outdev: Option<u32>,
    /// Physical input interface (bridge).
    pub physindev: Option<u32>,
    /// Physical output interface (bridge).
    pub physoutdev: Option<u32>,
    /// Source hardware address.
    pub hwaddr: Option<&'a [u8]>,
    /// Packet data (starting at the network header).
    pub payload: &'a [u8],
    /// Log prefix (without terminating NUL).
    pub prefix: Option<&'a [u8]>,
    /// UID of the local socket.
    pub uid: Option<u32>,
    /// GID of the local socket.
    pub gid: Option<u32>,
    /// Per-group sequence number.
    pub seq: Option<u32>,
    /// Global sequence number.
    pub seq_global: Option<u32>,
    /// Hardware type (`ARPHRD_*`).
    pub hwtype: Option<u16>,
    /// Link layer header.
    pub hwheader: Option<&'a [u8]>,
    /// Link layer header length.
    pub hwlen: Option<u16>,
    /// Raw conntrack attributes (`NFULA_CT`).
    pub ct: Option<&'a [u8]>,
    /// Conntrack info (`enum ip_conntrack_info`).
    pub ct_info: Option<u32>,
    /// VLAN `(protocol, tci)`.
    pub vlan: Option<(u16, u16)>,
    /// Full layer 2 header.
    pub l2hdr: Option<&'a [u8]>,
}

impl Packet<'_> {
    /// The prefix as a string, if valid UTF-8.
    pub fn prefix_str(&self) -> Option<&str> {
        self.prefix.and_then(|p| std::str::from_utf8(p).ok())
    }

    /// Copy into an owned packet.
    pub fn to_owned(&self) -> OwnedPacket {
        // (Exhaustive, so that no field is forgotten.)
        let &Packet {
            group,
            family,
            hw_protocol,
            hook,
            mark,
            timestamp,
            indev,
            outdev,
            physindev,
            physoutdev,
            hwaddr,
            payload,
            prefix,
            uid,
            gid,
            seq,
            seq_global,
            hwtype,
            hwheader,
            hwlen,
            ct,
            ct_info,
            vlan,
            l2hdr,
        } = self;
        OwnedPacket {
            group,
            family,
            hw_protocol,
            hook,
            mark,
            timestamp,
            indev,
            outdev,
            physindev,
            physoutdev,
            hwaddr: hwaddr.map(<[u8]>::to_vec),
            payload: payload.to_vec(),
            prefix: prefix.map(<[u8]>::to_vec),
            uid,
            gid,
            seq,
            seq_global,
            hwtype,
            hwheader: hwheader.map(<[u8]>::to_vec),
            hwlen,
            ct: ct.map(<[u8]>::to_vec),
            ct_info,
            vlan,
            l2hdr: l2hdr.map(<[u8]>::to_vec),
        }
    }
}

/// An owned copy of a [`Packet`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub struct OwnedPacket {
    pub group: u16,
    pub family: u8,
    pub hw_protocol: u16,
    pub hook: u8,
    pub mark: Option<u32>,
    pub timestamp: Option<Duration>,
    pub indev: Option<u32>,
    pub outdev: Option<u32>,
    pub physindev: Option<u32>,
    pub physoutdev: Option<u32>,
    pub hwaddr: Option<Vec<u8>>,
    pub payload: Vec<u8>,
    pub prefix: Option<Vec<u8>>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub seq: Option<u32>,
    pub seq_global: Option<u32>,
    pub hwtype: Option<u16>,
    pub hwheader: Option<Vec<u8>>,
    pub hwlen: Option<u16>,
    pub ct: Option<Vec<u8>>,
    pub ct_info: Option<u32>,
    pub vlan: Option<(u16, u16)>,
    pub l2hdr: Option<Vec<u8>>,
}

/// Parse an `NFULNL_MSG_PACKET` message.
pub fn parse_packet<'a>(msg: &Msg<'a>) -> Result<Packet<'a>> {
    let (h, attrs) = msg.nfgen()?;
    let mut p = Packet {
        group: h.res_id,
        family: h.family,
        ..Default::default()
    };
    let be32 = |d: &[u8]| -> Result<u32> {
        d.get(..4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            .ok_or(Error::malformed("short nflog attribute"))
    };
    let be16 = |d: &[u8]| -> Result<u16> {
        d.get(..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(Error::malformed("short nflog attribute"))
    };
    for a in attrs {
        let a = a?;
        let d = a.data;
        match a.ty {
            NFULA_PACKET_HDR => {
                if d.len() < 3 {
                    return Err(Error::malformed("short NFULA_PACKET_HDR"));
                }
                p.hw_protocol = u16::from_be_bytes([d[0], d[1]]);
                p.hook = d[2];
            }
            NFULA_MARK => p.mark = Some(be32(d)?),
            NFULA_TIMESTAMP => {
                if d.len() < 16 {
                    return Err(Error::malformed("short NFULA_TIMESTAMP"));
                }
                let sec = u64::from_be_bytes(d[0..8].try_into().unwrap());
                let usec = u64::from_be_bytes(d[8..16].try_into().unwrap());
                p.timestamp = Duration::from_secs(sec).checked_add(Duration::from_micros(usec));
            }
            NFULA_IFINDEX_INDEV => p.indev = Some(be32(d)?),
            NFULA_IFINDEX_OUTDEV => p.outdev = Some(be32(d)?),
            NFULA_IFINDEX_PHYSINDEV => p.physindev = Some(be32(d)?),
            NFULA_IFINDEX_PHYSOUTDEV => p.physoutdev = Some(be32(d)?),
            NFULA_HWADDR => {
                let len = be16(d)? as usize;
                p.hwaddr = d.get(4..4 + len.min(8));
            }
            NFULA_PAYLOAD => p.payload = d,
            NFULA_PREFIX => {
                let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
                p.prefix = Some(&d[..end]);
            }
            NFULA_UID => p.uid = Some(be32(d)?),
            NFULA_GID => p.gid = Some(be32(d)?),
            NFULA_SEQ => p.seq = Some(be32(d)?),
            NFULA_SEQ_GLOBAL => p.seq_global = Some(be32(d)?),
            NFULA_HWTYPE => p.hwtype = Some(be16(d)?),
            NFULA_HWHEADER => p.hwheader = Some(d),
            NFULA_HWLEN => p.hwlen = Some(be16(d)?),
            NFULA_CT => p.ct = Some(d),
            NFULA_CT_INFO => p.ct_info = Some(be32(d)?),
            NFULA_VLAN => {
                let (mut proto, mut tci) = (0, 0);
                for v in a.nested() {
                    let v = v?;
                    match v.ty {
                        NFULA_VLAN_PROTO => proto = v.be16()?,
                        NFULA_VLAN_TCI => tci = v.be16()?,
                        _ => {}
                    }
                }
                p.vlan = Some((proto, tci));
            }
            NFULA_L2HDR => p.l2hdr = Some(d),
            _ => {}
        }
    }
    Ok(p)
}

/// Delivery statistics of an NFLOG socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stats {
    /// Packets delivered to the application.
    pub received: u64,
    /// Number of times the kernel reported a receive buffer overrun
    /// (`ENOBUFS`), i.e. dropped one or more messages.
    pub overruns: u64,
    /// Number of packets known to be lost, from sequence number gaps
    /// (requires [`GroupConfig::seq`]).
    pub lost: u64,
}

/// Per-group sequence tracking for loss detection (sans-IO).
#[derive(Debug, Default, Clone)]
pub struct SeqTracker {
    next: HashMap<u16, u32>,
}

impl SeqTracker {
    /// Account for a received packet. Returns the number of packets of this
    /// group that were lost immediately before it.
    pub fn track(&mut self, group: u16, seq: u32) -> u64 {
        let lost = match self.next.get(&group) {
            // A number lower than expected (e.g. after the group was
            // re-bound, which resets the kernel's counter) is not a loss.
            Some(&expected) => match seq.wrapping_sub(expected) {
                gap if gap < u32::MAX / 2 => u64::from(gap),
                _ => 0,
            },
            None => 0,
        };
        self.next.insert(group, seq.wrapping_add(1));
        lost
    }

    /// Expect `next` as the next sequence number of `group` (e.g. the first
    /// number after binding).
    pub fn set_next(&mut self, group: u16, next: u32) {
        self.next.insert(group, next);
    }

    /// Forget the state of a group (e.g. after re-binding it, which resets
    /// the kernel's counter).
    pub fn reset(&mut self, group: u16) {
        self.next.remove(&group);
    }
}

/// The packets contained in one received datagram.
///
/// [`Stats`] (received and lost counts) are updated as the packets are
/// iterated, so iterate to the end to keep them accurate.
#[derive(Debug)]
pub struct Packets<'a> {
    msgs: Messages<'a>,
    tracker: &'a mut SeqTracker,
    stats: &'a mut Stats,
}

impl<'a> Packets<'a> {
    /// Iterate over the packets of `datagram`, updating `tracker` and `stats`
    /// (sans-IO entry point).
    pub fn new(datagram: &'a [u8], tracker: &'a mut SeqTracker, stats: &'a mut Stats) -> Self {
        Packets {
            msgs: Messages::new(datagram),
            tracker,
            stats,
        }
    }
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<Packet<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let msg = match self.msgs.next()? {
                Ok(m) => m,
                Err(e) => return Some(Err(e)),
            };
            if msg.subsys() != NFNL_SUBSYS_ULOG || msg.subtype() != NFULNL_MSG_PACKET {
                // NLMSG_DONE terminating a batch, stray acks, ...
                continue;
            }
            let p = parse_packet(&msg);
            if let Ok(p) = &p {
                self.stats.received += 1;
                if let Some(seq) = p.seq {
                    self.stats.lost += self.tracker.track(p.group, seq);
                }
            }
            return Some(p);
        }
    }
}

/// I/O independent state of an NFLOG socket, shared by the blocking and
/// async implementations.
#[derive(Debug)]
pub(crate) struct NflogCore {
    pub(crate) seq: u32,
    pub(crate) rbuf: Vec<u8>,
    pub(crate) rbuf_size: usize,
    pub(crate) sbuf: Vec<u8>,
    pending: VecDeque<Vec<u8>>,
    tracker: SeqTracker,
    /// Tracker change once the pending bind (`Some(first number)`) or
    /// unbind (`None`) succeeds.
    on_ack: Option<(u16, Option<u32>)>,
    pub(crate) stats: Stats,
}

impl NflogCore {
    pub(crate) fn new() -> Self {
        NflogCore {
            seq: initial_seq(),
            rbuf: Vec::new(),
            rbuf_size: GroupConfig::new(0).datagram_size(),
            sbuf: Vec::new(),
            pending: VecDeque::new(),
            tracker: SeqTracker::default(),
            on_ack: None,
            stats: Stats::default(),
        }
    }

    pub(crate) fn prepare_bind(&mut self, cfg: &GroupConfig) {
        self.rbuf_size = self.rbuf_size.max(cfg.datagram_size());
        self.seq = self.seq.wrapping_add(1);
        bind_request(&mut self.sbuf, self.seq, cfg);
        // A new instance numbers packets from 0.
        self.on_ack = Some((cfg.group, Some(0)));
    }

    pub(crate) fn prepare_configure(&mut self, cfg: &GroupConfig) {
        self.rbuf_size = self.rbuf_size.max(cfg.datagram_size());
        self.seq = self.seq.wrapping_add(1);
        config_request(&mut self.sbuf, self.seq, cfg);
        self.on_ack = None;
    }

    pub(crate) fn prepare_unbind(&mut self, group: u16) {
        self.seq = self.seq.wrapping_add(1);
        unbind_request(&mut self.sbuf, self.seq, group);
        self.on_ack = Some((group, None));
    }

    /// Process a datagram received while waiting for a config ack. Returns
    /// the ack result once found; other datagrams are queued.
    pub(crate) fn on_config_datagram(&mut self) -> Result<Option<Result<()>>> {
        if let Some(r) = check_ack(&self.rbuf, self.seq)? {
            // (A failed re-bind keeps the current numbering.)
            if let (Ok(()), Some((n, next))) = (&r, self.on_ack.take()) {
                match next {
                    Some(next) => self.tracker.set_next(n, next),
                    None => self.tracker.reset(n),
                }
            }
            return Ok(Some(r));
        }
        // Packets that arrived before the ack are delivered later.
        if self.pending.len() < MAX_PENDING {
            self.pending.push_back(self.rbuf.clone());
        } else {
            self.stats.overruns += 1;
        }
        Ok(None)
    }

    /// Move a queued datagram into the receive buffer, if any.
    pub(crate) fn take_pending(&mut self) -> bool {
        match self.pending.pop_front() {
            Some(d) => {
                self.rbuf = d;
                true
            }
            None => false,
        }
    }

    /// Classify a receive error: `Ok(())` if it is an overrun (counted) or
    /// interruption that should be retried.
    pub(crate) fn retryable(&mut self, e: io::Error) -> Result<()> {
        if is_enobufs(&e) {
            self.stats.overruns += 1;
            Ok(())
        } else if e.kind() == io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(e.into())
        }
    }

    pub(crate) fn packets(&mut self) -> Packets<'_> {
        Packets::new(&self.rbuf, &mut self.tracker, &mut self.stats)
    }
}

pub(crate) fn set_rcvbuf(fd: RawFd, size: usize) -> Result<()> {
    let v = i32::try_from(size).unwrap_or(i32::MAX);
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, v)
        .or_else(|_| setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, v))?;
    Ok(())
}

/// A socket receiving NFLOG packets.
#[derive(Debug)]
pub struct NflogSocket {
    sock: NlSocket,
    core: NflogCore,
}

impl NflogSocket {
    /// Open a socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (sock, _) = open_socket()?;
        Ok(NflogSocket {
            sock,
            core: NflogCore::new(),
        })
    }

    /// Set the socket receive buffer size in bytes (the kernel doubles it).
    /// A larger buffer reduces overruns under bursts.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        set_rcvbuf(self.sock.as_raw_fd(), size)
    }

    /// Statistics so far.
    pub fn stats(&self) -> Stats {
        self.core.stats
    }

    /// Make [`NflogSocket::recv`] fail with a `WouldBlock` I/O error if no
    /// packet arrives within `timeout` (`None` waits forever).
    pub fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        Ok(crate::socket::set_recv_timeout(
            self.sock.as_raw_fd(),
            timeout,
        )?)
    }

    /// Bind a group to this socket and configure it. Fails with `EPERM` if
    /// another socket has bound the group, and `EBUSY` if this socket
    /// already has.
    pub fn bind(&mut self, cfg: &GroupConfig) -> Result<()> {
        self.core.prepare_bind(cfg);
        self.config_roundtrip()
    }

    /// Change the configuration of a group bound to this socket.
    pub fn configure(&mut self, cfg: &GroupConfig) -> Result<()> {
        self.core.prepare_configure(cfg);
        self.config_roundtrip()
    }

    /// Unbind a group.
    pub fn unbind(&mut self, group: u16) -> Result<()> {
        self.core.prepare_unbind(group);
        self.config_roundtrip()
    }

    fn config_roundtrip(&mut self) -> Result<()> {
        self.sock.send(&self.core.sbuf, 0)?;
        // Set after an overrun.
        let mut deadline = None;
        loop {
            if let Some(d) = deadline {
                wait_readable(self.sock.as_raw_fd(), d).map_err(|_| ack_lost())?;
            }
            match recv_datagram(&self.sock, &mut self.core.rbuf, self.core.rbuf_size, 0) {
                Ok(_) => {
                    if let Some(r) = self.core.on_config_datagram()? {
                        return r;
                    }
                }
                Err(e) => {
                    if is_enobufs(&e) {
                        deadline.get_or_insert_with(|| Instant::now() + ACK_GRACE);
                    }
                    self.core.retryable(e)?;
                }
            }
        }
    }

    /// Block until a datagram arrives and return its packets.
    pub fn recv(&mut self) -> Result<Packets<'_>> {
        if !self.core.take_pending() {
            loop {
                match recv_datagram(&self.sock, &mut self.core.rbuf, self.core.rbuf_size, 0) {
                    Ok(_) => break,
                    Err(e) => self.core.retryable(e)?,
                }
            }
        }
        Ok(self.core.packets())
    }

    /// Return the packets of a datagram if one is available, without blocking.
    pub fn try_recv(&mut self) -> Result<Option<Packets<'_>>> {
        if !self.core.take_pending() {
            loop {
                match recv_datagram(
                    &self.sock,
                    &mut self.core.rbuf,
                    self.core.rbuf_size,
                    libc::MSG_DONTWAIT,
                ) {
                    Ok(_) => break,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(e) => self.core.retryable(e)?,
                }
            }
        }
        Ok(Some(self.core.packets()))
    }
}

/// If `datagram` contains the ack for `seq`, return its result.
/// How long to wait for a configuration ack after a receive overrun, which
/// may have dropped it (it is queued when the request is sent, so it is
/// found soon if it was not).
pub(crate) const ACK_GRACE: Duration = Duration::from_secs(1);

/// Datagrams kept while waiting for a configuration ack, at most (the
/// excess is dropped, counted as overruns, and the packets as lost).
pub(crate) const MAX_PENDING: usize = 4096;

/// The error when a configuration ack was not received after an overrun.
pub(crate) fn ack_lost() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "acknowledgement lost in a receive buffer overrun (the request may have taken effect)",
    ))
}

pub(crate) fn check_ack(datagram: &[u8], seq: u32) -> Result<Option<Result<()>>> {
    for m in Messages::new(datagram) {
        let m = m?;
        if m.ty == NLMSG_ERROR && m.seq == seq {
            let e = ErrorMsg::parse(&m)?;
            return Ok(Some(if e.error == 0 {
                Ok(())
            } else {
                Err(Error::Kernel(KernelError {
                    errno: -e.error,
                    message: e.ext_msg.map(str::to_owned),
                }))
            }));
        }
    }
    Ok(None)
}

impl AsRawFd for NflogSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl AsFd for NflogSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sock.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_tracker() {
        let mut t = SeqTracker::default();
        assert_eq!(t.track(1, 0), 0);
        assert_eq!(t.track(1, 1), 0);
        assert_eq!(t.track(1, 5), 3);
        assert_eq!(t.track(2, 100), 0);
        assert_eq!(t.track(1, 6), 0);
        // wrap-around
        assert_eq!(t.track(3, u32::MAX), 0);
        assert_eq!(t.track(3, 1), 1);
        // going backwards is not a loss
        assert_eq!(t.track(3, 0), 0);
    }
}
