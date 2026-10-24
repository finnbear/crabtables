//! NFQUEUE: receive packets sent to userspace by `queue` rules
//! (nfnetlink_queue) and decide their fate.
//!
//! Each queue is bound by one socket. Received packets are held by the
//! kernel until a verdict is issued, either with [`NfqSocket::verdict`] or
//! through a [`VerdictHandle`], which can be cloned and sent to other
//! threads (verdicts may be issued in any order).
//!
//! # Loss accounting
//!
//! The kernel numbers queued packets per queue. If a packet cannot be
//! delivered because the socket's receive buffer is full, it is dropped
//! (or accepted, with [`QueueConfig::fail_open`]) and its id is skipped:
//! [`Stats::lost`] counts such gaps and [`Stats::overruns`] the `ENOBUFS`
//! reports. Packets dropped because the queue was full
//! ([`QueueConfig::max_len`]) never get an id; see [`proc_stats`].
//!
//! ```no_run
//! use crabtables::nfqueue::{NfqSocket, QueueConfig, QueueVerdict};
//! let mut q = NfqSocket::new()?;
//! q.bind(&QueueConfig::new(0))?;
//! let v = q.verdicts();
//! loop {
//!     for p in q.recv()? {
//!         let p = p?;
//!         let verdict = if p.payload.len() > 1000 { QueueVerdict::Drop } else { QueueVerdict::Accept };
//!         v.verdict(p.queue, p.id, verdict)?;
//!     }
//! }
//! # Ok::<(), crabtables::Error>(())
//! ```

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use netlink_sys::Socket as NlSocket;

use crate::error::{Error, Result};
use crate::nflog::{ACK_GRACE, CopyMode, MAX_PENDING, SeqTracker, ack_lost, check_ack, set_rcvbuf};
use crate::nl::{Messages, Msg, Writer};
use crate::socket::{
    initial_seq, is_enobufs, open_socket, recv_datagram, setsockopt_int, wait_readable,
};
use crate::sys::*;

/// Configuration of a queue.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QueueConfig {
    /// Queue number (`queue num N`).
    pub queue: u16,
    /// How much of each packet is copied to userspace.
    pub copy_mode: CopyMode,
    /// Maximum number of packets waiting for a verdict (kernel default 1024).
    pub max_len: Option<u32>,
    /// `NFQA_CFG_F_*` flags to set.
    pub flags: u32,
    /// Flags to clear (sent with the mask so that they are disabled).
    pub clear_flags: u32,
}

impl QueueConfig {
    /// Copy whole packets; no special flags.
    pub fn new(queue: u16) -> Self {
        QueueConfig {
            queue,
            copy_mode: CopyMode::Packet(0xffff),
            max_len: None,
            flags: 0,
            clear_flags: 0,
        }
    }

    /// Set the copy mode.
    pub fn copy_mode(mut self, m: CopyMode) -> Self {
        self.copy_mode = m;
        self
    }

    /// Set the maximum queue length.
    pub fn max_len(mut self, n: u32) -> Self {
        self.max_len = Some(n);
        self
    }

    fn flag(mut self, f: u32, on: bool) -> Self {
        if on {
            self.flags |= f;
            self.clear_flags &= !f;
        } else {
            self.flags &= !f;
            self.clear_flags |= f;
        }
        self
    }

    /// Accept packets instead of dropping them when the queue is full or
    /// the socket cannot take them (`NFQA_CFG_F_FAIL_OPEN`).
    pub fn fail_open(self, on: bool) -> Self {
        self.flag(NFQA_CFG_F_FAIL_OPEN, on)
    }

    /// Include conntrack information (`NFQA_CFG_F_CONNTRACK`; needs the
    /// `nf_conntrack_netlink` module).
    pub fn conntrack(self, on: bool) -> Self {
        self.flag(NFQA_CFG_F_CONNTRACK, on)
    }

    /// Deliver GSO packets unsegmented (`NFQA_CFG_F_GSO`).
    pub fn gso(self, on: bool) -> Self {
        self.flag(NFQA_CFG_F_GSO, on)
    }

    /// Include socket UID/GID (`NFQA_CFG_F_UID_GID`).
    pub fn uid_gid(self, on: bool) -> Self {
        self.flag(NFQA_CFG_F_UID_GID, on)
    }

    /// Include the security context (`NFQA_CFG_F_SECCTX`).
    pub fn secctx(self, on: bool) -> Self {
        self.flag(NFQA_CFG_F_SECCTX, on)
    }

    pub(crate) fn datagram_size(&self) -> usize {
        let copy = match self.copy_mode {
            CopyMode::Packet(n) => n as usize,
            _ => 0,
        };
        (copy + 4096).max(64 * 1024)
    }
}

fn config_msg(out: &mut Vec<u8>, seq: u32, queue: u16, cmd: Option<u8>, cfg: Option<&QueueConfig>) {
    let mut w = Writer::with_capacity(64);
    let ty = (u16::from(NFNL_SUBSYS_QUEUE) << 8) | u16::from(NFQNL_MSG_CONFIG);
    let m = w.begin_msg(ty, NLM_F_REQUEST | NLM_F_ACK, seq, NFPROTO_UNSPEC, queue);
    if let Some(c) = cmd {
        w.put(NFQA_CFG_CMD, &[c, 0, 0, 0]);
    }
    if let Some(cfg) = cfg {
        let (range, mode) = match cfg.copy_mode {
            CopyMode::None => (0, NFQNL_COPY_NONE),
            CopyMode::Meta => (0, NFQNL_COPY_META),
            CopyMode::Packet(n) => (n, NFQNL_COPY_PACKET),
        };
        let mut p = [0u8; 5];
        p[..4].copy_from_slice(&range.to_be_bytes());
        p[4] = mode;
        w.put(NFQA_CFG_PARAMS, &p);
        if let Some(n) = cfg.max_len {
            w.put_be32(NFQA_CFG_QUEUE_MAXLEN, n);
        }
        let mask = cfg.flags | cfg.clear_flags;
        if mask != 0 {
            w.put_be32(NFQA_CFG_MASK, mask);
            w.put_be32(NFQA_CFG_FLAGS, cfg.flags);
        }
    }
    w.end_msg(m);
    out.clear();
    out.extend_from_slice(w.as_bytes());
}

/// Encode a request binding a queue to the sending socket and configuring
/// it (sans-IO).
pub fn bind_request(out: &mut Vec<u8>, seq: u32, cfg: &QueueConfig) {
    config_msg(out, seq, cfg.queue, Some(NFQNL_CFG_CMD_BIND), Some(cfg));
}

/// Encode a request changing the configuration of a bound queue (sans-IO).
pub fn config_request(out: &mut Vec<u8>, seq: u32, cfg: &QueueConfig) {
    config_msg(out, seq, cfg.queue, None, Some(cfg));
}

/// Encode a request unbinding a queue (sans-IO).
pub fn unbind_request(out: &mut Vec<u8>, seq: u32, queue: u16) {
    config_msg(out, seq, queue, Some(NFQNL_CFG_CMD_UNBIND), None);
}

/// The fate of a queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QueueVerdict {
    /// Let the packet continue (with the next hook entry).
    Accept,
    /// Drop the packet.
    Drop,
    /// Re-run the hook from its start (use a mark to avoid loops).
    Repeat,
    /// Accept and skip the remaining entries of this hook.
    Stop,
    /// Send the packet to another queue.
    Queue(u16),
    /// Any raw verdict code.
    Other(u32),
}

impl QueueVerdict {
    /// The raw verdict code.
    pub fn code(self) -> u32 {
        match self {
            QueueVerdict::Accept => NF_ACCEPT as u32,
            QueueVerdict::Drop => NF_DROP as u32,
            QueueVerdict::Repeat => NF_REPEAT as u32,
            QueueVerdict::Stop => NF_STOP as u32,
            QueueVerdict::Queue(q) => NF_QUEUE as u32 | (u32::from(q) << 16),
            QueueVerdict::Other(c) => c,
        }
    }
}

/// Optional changes applied together with a verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerdictOptions<'a> {
    /// New packet mark.
    pub mark: Option<u32>,
    /// New skb priority.
    pub priority: Option<u32>,
    /// Replacement packet data (starting at the network header). Checksums
    /// are not recomputed.
    pub payload: Option<&'a [u8]>,
    /// New conntrack mark (needs `nf_conntrack_netlink`).
    pub ct_mark: Option<u32>,
}

/// Encode a verdict message (sans-IO). Fails with [`Error::TooLarge`] if
/// the replacement payload does not fit in a netlink attribute (65531
/// bytes).
pub fn verdict_msg(
    out: &mut Vec<u8>,
    queue: u16,
    id: u32,
    verdict: QueueVerdict,
    opts: &VerdictOptions<'_>,
) -> Result<()> {
    encode_verdict(out, NFQNL_MSG_VERDICT, queue, id, verdict, opts)
}

/// Encode a batch verdict for all packets with ids up to `max_id` (sans-IO).
/// Batch verdicts can only carry a mark and a priority.
pub fn verdict_batch_msg(
    out: &mut Vec<u8>,
    queue: u16,
    max_id: u32,
    verdict: QueueVerdict,
    mark: Option<u32>,
) {
    let opts = VerdictOptions {
        mark,
        ..Default::default()
    };
    // (Cannot fail without a payload.)
    let _ = encode_verdict(out, NFQNL_MSG_VERDICT_BATCH, queue, max_id, verdict, &opts);
}

fn encode_verdict(
    out: &mut Vec<u8>,
    ty: u8,
    queue: u16,
    id: u32,
    verdict: QueueVerdict,
    opts: &VerdictOptions<'_>,
) -> Result<()> {
    out.clear();
    let mut w = Writer::with_capacity(64 + opts.payload.map_or(0, <[u8]>::len));
    let t = (u16::from(NFNL_SUBSYS_QUEUE) << 8) | u16::from(ty);
    let m = w.begin_msg(t, NLM_F_REQUEST, 0, NFPROTO_UNSPEC, queue);
    let mut hdr = [0u8; 8];
    hdr[..4].copy_from_slice(&verdict.code().to_be_bytes());
    hdr[4..].copy_from_slice(&id.to_be_bytes());
    w.put(NFQA_VERDICT_HDR, &hdr);
    if let Some(mark) = opts.mark {
        w.put_be32(NFQA_MARK, mark);
    }
    if let Some(p) = opts.priority {
        w.put_be32(NFQA_PRIORITY, p);
    }
    if let Some(ct) = opts.ct_mark {
        w.nest(NFQA_CT, |w| w.put_be32(CTA_MARK, ct));
    }
    if let Some(p) = opts.payload {
        w.put(NFQA_PAYLOAD, p);
    }
    w.end_msg(m);
    w.check()?;
    out.extend_from_slice(w.as_bytes());
    Ok(())
}

/// A queued packet, borrowing from the receive buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueuedPacket<'a> {
    /// Queue number.
    pub queue: u16,
    /// Protocol family (`NFPROTO_*`).
    pub family: u8,
    /// Packet id, needed for the verdict.
    pub id: u32,
    /// Link layer protocol (ethertype).
    pub hw_protocol: u16,
    /// Netfilter hook.
    pub hook: u8,
    /// Packet mark.
    pub mark: Option<u32>,
    /// Timestamp (time since the Unix epoch).
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
    /// Packet data (network header onwards), possibly truncated.
    pub payload: &'a [u8],
    /// Raw conntrack attributes (`NFQA_CT`).
    pub ct: Option<&'a [u8]>,
    /// Conntrack info (`enum ip_conntrack_info`).
    pub ct_info: Option<u32>,
    /// Full length of the packet when `payload` was truncated.
    pub cap_len: Option<u32>,
    /// `NFQA_SKB_*` flags (checksum state, GSO).
    pub skb_info: Option<u32>,
    /// Socket UID (with [`QueueConfig::uid_gid`]).
    pub uid: Option<u32>,
    /// Socket GID (with [`QueueConfig::uid_gid`]).
    pub gid: Option<u32>,
    /// Security context (with [`QueueConfig::secctx`]).
    pub secctx: Option<&'a [u8]>,
    /// VLAN `(protocol, tci)`.
    pub vlan: Option<(u16, u16)>,
    /// Layer 2 header (bridge family).
    pub l2hdr: Option<&'a [u8]>,
    /// skb priority.
    pub priority: Option<u32>,
    /// cgroup classid.
    pub cgroup_classid: Option<u32>,
}

impl QueuedPacket<'_> {
    /// The full packet length (`cap_len` if truncated, else the payload length).
    pub fn len(&self) -> usize {
        self.cap_len.map_or(self.payload.len(), |l| l as usize)
    }

    /// Whether the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse an `NFQNL_MSG_PACKET` message.
pub fn parse_packet<'a>(msg: &Msg<'a>) -> Result<QueuedPacket<'a>> {
    let (h, attrs) = msg.nfgen()?;
    let mut p = QueuedPacket {
        queue: h.res_id,
        family: h.family,
        ..Default::default()
    };
    let be32 = |d: &[u8]| -> Result<u32> {
        d.get(..4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            .ok_or(Error::malformed("short nfqueue attribute"))
    };
    let mut have_hdr = false;
    for a in attrs {
        let a = a?;
        let d = a.data;
        match a.ty {
            NFQA_PACKET_HDR => {
                if d.len() < 7 {
                    return Err(Error::malformed("short NFQA_PACKET_HDR"));
                }
                p.id = u32::from_be_bytes(d[0..4].try_into().unwrap());
                p.hw_protocol = u16::from_be_bytes([d[4], d[5]]);
                p.hook = d[6];
                have_hdr = true;
            }
            NFQA_MARK => p.mark = Some(be32(d)?),
            NFQA_TIMESTAMP => {
                if d.len() < 16 {
                    return Err(Error::malformed("short NFQA_TIMESTAMP"));
                }
                let sec = u64::from_be_bytes(d[0..8].try_into().unwrap());
                let usec = u64::from_be_bytes(d[8..16].try_into().unwrap());
                p.timestamp = Duration::from_secs(sec).checked_add(Duration::from_micros(usec));
            }
            NFQA_IFINDEX_INDEV => p.indev = Some(be32(d)?),
            NFQA_IFINDEX_OUTDEV => p.outdev = Some(be32(d)?),
            NFQA_IFINDEX_PHYSINDEV => p.physindev = Some(be32(d)?),
            NFQA_IFINDEX_PHYSOUTDEV => p.physoutdev = Some(be32(d)?),
            NFQA_HWADDR => {
                let len = d
                    .get(..2)
                    .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]) as usize);
                p.hwaddr = d.get(4..4 + len.min(8));
            }
            NFQA_PAYLOAD => p.payload = d,
            NFQA_CT => p.ct = Some(d),
            NFQA_CT_INFO => p.ct_info = Some(be32(d)?),
            NFQA_CAP_LEN => p.cap_len = Some(be32(d)?),
            NFQA_SKB_INFO => p.skb_info = Some(be32(d)?),
            NFQA_UID => p.uid = Some(be32(d)?),
            NFQA_GID => p.gid = Some(be32(d)?),
            NFQA_SECCTX => p.secctx = Some(d.strip_suffix(&[0]).unwrap_or(d)),
            NFQA_VLAN => {
                let (mut proto, mut tci) = (0, 0);
                for v in a.nested() {
                    let v = v?;
                    match v.ty {
                        NFQA_VLAN_PROTO => proto = v.be16()?,
                        NFQA_VLAN_TCI => tci = v.be16()?,
                        _ => {}
                    }
                }
                p.vlan = Some((proto, tci));
            }
            NFQA_L2HDR => p.l2hdr = Some(d),
            NFQA_PRIORITY => p.priority = Some(be32(d)?),
            NFQA_CGROUP_CLASSID => p.cgroup_classid = Some(be32(d)?),
            _ => {}
        }
    }
    if !have_hdr {
        return Err(Error::malformed("queued packet without header"));
    }
    Ok(p)
}

/// Delivery statistics of a queue socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stats {
    /// Packets received.
    pub received: u64,
    /// `ENOBUFS` reports (receive buffer overruns).
    pub overruns: u64,
    /// Packets known to be lost from id gaps.
    pub lost: u64,
    /// Errors the kernel reported for verdicts (e.g. unknown packet ids).
    pub verdict_errors: u64,
}

/// The packets contained in one received datagram.
#[derive(Debug)]
pub struct QueuePackets<'a> {
    msgs: Messages<'a>,
    tracker: &'a mut SeqTracker,
    stats: &'a mut Stats,
}

impl<'a> QueuePackets<'a> {
    /// Iterate over the packets of `datagram` (sans-IO entry point).
    pub fn new(datagram: &'a [u8], tracker: &'a mut SeqTracker, stats: &'a mut Stats) -> Self {
        QueuePackets {
            msgs: Messages::new(datagram),
            tracker,
            stats,
        }
    }
}

impl<'a> Iterator for QueuePackets<'a> {
    type Item = Result<QueuedPacket<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let msg = match self.msgs.next()? {
                Ok(m) => m,
                Err(e) => return Some(Err(e)),
            };
            if msg.ty == NLMSG_ERROR {
                // Errors for verdicts sent without acknowledgement.
                if let Ok(e) = crate::nl::ErrorMsg::parse(&msg) {
                    if e.error != 0 {
                        self.stats.verdict_errors += 1;
                    }
                }
                continue;
            }
            if msg.subsys() != NFNL_SUBSYS_QUEUE || msg.subtype() != NFQNL_MSG_PACKET {
                continue;
            }
            let p = parse_packet(&msg);
            if let Ok(p) = &p {
                self.stats.received += 1;
                self.stats.lost += self.tracker.track(p.queue, p.id);
            }
            return Some(p);
        }
    }
}

/// Sends verdicts. Cheap to clone; usable from any thread.
#[derive(Debug, Clone)]
pub struct VerdictHandle {
    sock: Arc<NlSocket>,
}

impl VerdictHandle {
    #[cfg(feature = "tokio")]
    pub(crate) fn from_arc(sock: Arc<NlSocket>) -> Self {
        VerdictHandle { sock }
    }

    fn send(&self, buf: &[u8]) -> Result<()> {
        loop {
            match self.sock.send(buf, 0) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Issue a verdict for packet `id` of `queue`.
    pub fn verdict(&self, queue: u16, id: u32, verdict: QueueVerdict) -> Result<()> {
        self.verdict_with(queue, id, verdict, &VerdictOptions::default())
    }

    /// Issue a verdict, changing the mark, priority, payload or ct mark.
    pub fn verdict_with(
        &self,
        queue: u16,
        id: u32,
        verdict: QueueVerdict,
        opts: &VerdictOptions<'_>,
    ) -> Result<()> {
        let mut buf = Vec::new();
        verdict_msg(&mut buf, queue, id, verdict, opts)?;
        self.send(&buf)
    }

    /// Issue the same verdict for every pending packet with an id up to
    /// and including `max_id`.
    pub fn verdict_batch(
        &self,
        queue: u16,
        max_id: u32,
        verdict: QueueVerdict,
        mark: Option<u32>,
    ) -> Result<()> {
        let mut buf = Vec::new();
        verdict_batch_msg(&mut buf, queue, max_id, verdict, mark);
        self.send(&buf)
    }
}

/// I/O independent state shared by the blocking and async queue sockets.
#[derive(Debug)]
pub(crate) struct NfqCore {
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

impl NfqCore {
    pub(crate) fn new() -> Self {
        NfqCore {
            seq: initial_seq(),
            rbuf: Vec::new(),
            rbuf_size: 64 * 1024 + 4096,
            sbuf: Vec::new(),
            pending: VecDeque::new(),
            tracker: SeqTracker::default(),
            on_ack: None,
            stats: Stats::default(),
        }
    }

    pub(crate) fn prepare_bind(&mut self, cfg: &QueueConfig) {
        self.rbuf_size = self.rbuf_size.max(cfg.datagram_size());
        self.seq = self.seq.wrapping_add(1);
        bind_request(&mut self.sbuf, self.seq, cfg);
        // A new queue numbers packets from 1.
        self.on_ack = Some((cfg.queue, Some(1)));
    }

    pub(crate) fn prepare_configure(&mut self, cfg: &QueueConfig) {
        self.rbuf_size = self.rbuf_size.max(cfg.datagram_size());
        self.seq = self.seq.wrapping_add(1);
        config_request(&mut self.sbuf, self.seq, cfg);
        self.on_ack = None;
    }

    pub(crate) fn prepare_unbind(&mut self, queue: u16) {
        self.seq = self.seq.wrapping_add(1);
        unbind_request(&mut self.sbuf, self.seq, queue);
        self.on_ack = Some((queue, None));
    }

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
        if self.pending.len() < MAX_PENDING {
            self.pending.push_back(self.rbuf.clone());
        } else {
            self.stats.overruns += 1;
        }
        Ok(None)
    }

    pub(crate) fn take_pending(&mut self) -> bool {
        match self.pending.pop_front() {
            Some(d) => {
                self.rbuf = d;
                true
            }
            None => false,
        }
    }

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

    /// Whether the receive buffer holds at least one queued packet. If not
    /// (e.g. only verdict errors), the errors are accounted for.
    pub(crate) fn has_packets(&mut self) -> bool {
        let has = Messages::new(&self.rbuf)
            .flatten()
            .any(|m| m.subsys() == NFNL_SUBSYS_QUEUE && m.subtype() == NFQNL_MSG_PACKET);
        if !has {
            self.packets().for_each(drop);
        }
        has
    }

    pub(crate) fn packets(&mut self) -> QueuePackets<'_> {
        QueuePackets::new(&self.rbuf, &mut self.tracker, &mut self.stats)
    }
}

/// A socket receiving packets from NFQUEUE queues.
#[derive(Debug)]
pub struct NfqSocket {
    sock: Arc<NlSocket>,
    core: NfqCore,
}

impl NfqSocket {
    /// Open a socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (sock, _) = open_socket()?;
        Ok(NfqSocket {
            sock: Arc::new(sock),
            core: NfqCore::new(),
        })
    }

    /// A handle for issuing verdicts, also from other threads.
    pub fn verdicts(&self) -> VerdictHandle {
        VerdictHandle {
            sock: self.sock.clone(),
        }
    }

    /// Issue a verdict (see [`VerdictHandle::verdict`]).
    pub fn verdict(&self, queue: u16, id: u32, verdict: QueueVerdict) -> Result<()> {
        self.verdicts().verdict(queue, id, verdict)
    }

    /// Set the socket receive buffer size (the kernel doubles it).
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        set_rcvbuf(self.sock.as_raw_fd(), size)
    }

    /// Make [`NfqSocket::recv`] fail with `WouldBlock` after `timeout`.
    pub fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        Ok(crate::socket::set_recv_timeout(
            self.sock.as_raw_fd(),
            timeout,
        )?)
    }

    /// Statistics so far.
    pub fn stats(&self) -> Stats {
        self.core.stats
    }

    /// Bind a queue and configure it. Fails with `EPERM` if another socket
    /// has bound the queue, `EBUSY` if this one has.
    pub fn bind(&mut self, cfg: &QueueConfig) -> Result<()> {
        self.core.prepare_bind(cfg);
        self.config_roundtrip()
    }

    /// Change the configuration of a bound queue.
    pub fn configure(&mut self, cfg: &QueueConfig) -> Result<()> {
        self.core.prepare_configure(cfg);
        self.config_roundtrip()
    }

    /// Unbind a queue. Packets still waiting for a verdict are dropped (as
    /// they are when the socket is closed).
    pub fn unbind(&mut self, queue: u16) -> Result<()> {
        self.core.prepare_unbind(queue);
        self.config_roundtrip()
    }

    fn config_roundtrip(&mut self) -> Result<()> {
        self.sock.send(&self.core.sbuf, 0)?;
        // Set after an overrun (see `nflog::ACK_GRACE`).
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

    /// Block until packets arrive and return them (one datagram's worth).
    pub fn recv(&mut self) -> Result<QueuePackets<'_>> {
        loop {
            if !self.core.take_pending() {
                match recv_datagram(&self.sock, &mut self.core.rbuf, self.core.rbuf_size, 0) {
                    Ok(_) => {}
                    Err(e) => {
                        self.core.retryable(e)?;
                        continue;
                    }
                }
            }
            if self.core.has_packets() {
                return Ok(self.core.packets());
            }
        }
    }

    /// Return packets if some are available, without blocking.
    pub fn try_recv(&mut self) -> Result<Option<QueuePackets<'_>>> {
        loop {
            if !self.core.take_pending() {
                match recv_datagram(
                    &self.sock,
                    &mut self.core.rbuf,
                    self.core.rbuf_size,
                    libc::MSG_DONTWAIT,
                ) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(e) => {
                        self.core.retryable(e)?;
                        continue;
                    }
                }
            }
            if self.core.has_packets() {
                return Ok(Some(self.core.packets()));
            }
        }
    }

    /// Suppress `ENOBUFS` reports (`NETLINK_NO_ENOBUFS`); losses are then
    /// only visible as id gaps.
    pub fn set_no_enobufs(&self, on: bool) -> Result<()> {
        Ok(setsockopt_int(
            self.sock.as_raw_fd(),
            libc::SOL_NETLINK,
            NETLINK_NO_ENOBUFS,
            i32::from(on),
        )?)
    }
}

impl AsRawFd for NfqSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl AsFd for NfqSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sock.as_fd()
    }
}

/// Per-queue kernel statistics from `/proc/net/netfilter/nfnetlink_queue`
/// (of the current network namespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcStats {
    /// Queue number.
    pub queue: u16,
    /// Port id of the bound socket.
    pub portid: u32,
    /// Packets currently waiting for a verdict.
    pub waiting: u32,
    /// Copy mode.
    pub copy_mode: u8,
    /// Copy range.
    pub copy_range: u32,
    /// Packets dropped because the queue was full.
    pub queue_dropped: u32,
    /// Packets dropped because they could not be delivered to the socket.
    pub user_dropped: u32,
    /// Last packet id.
    pub id_sequence: u32,
}

/// Read the kernel's per-queue statistics (of the calling thread's
/// network namespace).
pub fn proc_stats() -> Result<Vec<ProcStats>> {
    // `/proc/net` follows the main thread's namespace; prefer the caller's.
    let s = std::fs::read_to_string("/proc/thread-self/net/netfilter/nfnetlink_queue")
        .or_else(|_| std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue"))?;
    let mut v = Vec::new();
    for line in s.lines() {
        let f: Vec<u64> = line
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if f.len() >= 8 {
            v.push(ProcStats {
                queue: f[0] as u16,
                portid: f[1] as u32,
                waiting: f[2] as u32,
                copy_mode: f[3] as u8,
                copy_range: f[4] as u32,
                queue_dropped: f[5] as u32,
                user_dropped: f[6] as u32,
                id_sequence: f[7] as u32,
            });
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_encoding() {
        let mut out = Vec::new();
        verdict_msg(
            &mut out,
            7,
            42,
            QueueVerdict::Queue(3),
            &VerdictOptions {
                mark: Some(5),
                ..Default::default()
            },
        )
        .unwrap();
        let m = Messages::new(&out).next().unwrap().unwrap();
        assert_eq!(
            (m.subsys(), m.subtype()),
            (NFNL_SUBSYS_QUEUE, NFQNL_MSG_VERDICT)
        );
        let (h, attrs) = m.nfgen().unwrap();
        assert_eq!(h.res_id, 7);
        let a: Vec<_> = attrs.collect::<Result<_>>().unwrap();
        assert_eq!(a[0].data, [0, 3, 0, 3, 0, 0, 0, 42]);
        assert_eq!(a[1].be32().unwrap(), 5);
    }

    #[test]
    fn verdict_payload_too_large() {
        let mut out = Vec::new();
        let opts = |p| VerdictOptions {
            payload: Some(p),
            ..Default::default()
        };
        let big = vec![0u8; 65531];
        verdict_msg(&mut out, 0, 1, QueueVerdict::Accept, &opts(&big)).unwrap();
        let big = vec![0u8; 65532];
        let e = verdict_msg(&mut out, 0, 1, QueueVerdict::Accept, &opts(&big));
        assert!(matches!(e, Err(Error::TooLarge)), "{e:?}");
    }
}
