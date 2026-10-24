//! Blocking nf_tables socket.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use netlink_sys::Socket as NlSocket;

use crate::batch::{Batch, BatchOutcome};
use crate::error::{Error, Result};
use crate::nl::Msg;
use crate::proto::{Decode, Request};
use crate::sys::*;

/// Receive buffer size. Kernel netlink dumps are at most 32 KiB per datagram.
pub(crate) const RECV_BUF: usize = 64 * 1024;

pub(crate) fn setsockopt_int(fd: RawFd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    // SAFETY: `val` is a valid c_int for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn getsockopt_int(fd: RawFd, level: i32, opt: i32) -> io::Result<i32> {
    let mut val: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `val` and `len` are valid for writes for the duration of the call.
    let r = unsafe {
        libc::getsockopt(
            fd,
            level,
            opt,
            &mut val as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(val)
    }
}

/// Set `SO_RCVTIMEO` (`None` blocks forever).
pub(crate) fn set_recv_timeout(fd: RawFd, t: Option<std::time::Duration>) -> io::Result<()> {
    let tv = match t {
        // A zero timeval means "forever": round tiny timeouts up to 1 µs.
        Some(t) => {
            let t = t.max(std::time::Duration::from_micros(1));
            libc::timeval {
                tv_sec: t.as_secs().min(i64::MAX as u64) as libc::time_t,
                tv_usec: t.subsec_micros() as libc::suseconds_t,
            }
        }
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    // SAFETY: `tv` is a valid timeval for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Make sure the socket can send a datagram of `len` bytes.
pub(crate) fn ensure_sndbuf(fd: RawFd, len: usize) -> io::Result<()> {
    let cur = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF)? as usize;
    // Netlink rejects messages larger than sndbuf - 32.
    if len + 1024 <= cur {
        return Ok(());
    }
    let want = i32::try_from(len + 4096).unwrap_or(i32::MAX);
    // The kernel doubles the value; SO_SNDBUFFORCE ignores wmem_max but
    // needs CAP_NET_ADMIN (which nf_tables needs anyway).
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, want)
        .or_else(|_| setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, want))
}

/// Make sure the receive buffer can hold `need` bytes (kernel accounting).
/// Returns whether the buffer was too small.
pub(crate) fn ensure_rcvbuf(fd: RawFd, need: usize) -> io::Result<bool> {
    // getsockopt reports the doubled value actually used by the kernel.
    let cur = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)? as usize;
    if need <= cur {
        return Ok(false);
    }
    // The kernel doubles the requested value.
    let want = i32::try_from(need.div_ceil(2).min(1 << 30)).unwrap_or(i32::MAX);
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, want)
        .or_else(|_| setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, want))?;
    Ok(true)
}

/// Create and configure a NETLINK_NETFILTER socket.
pub(crate) fn open_socket() -> Result<(NlSocket, u32)> {
    let mut sock = NlSocket::new(NETLINK_NETFILTER)?;
    let addr = sock.bind_auto()?;
    let fd = sock.as_raw_fd();
    // Extended acks (error messages and offsets) and capped acks (the
    // kernel does not echo the whole failed request back).
    let _ = setsockopt_int(fd, libc::SOL_NETLINK, NETLINK_EXT_ACK, 1);
    let _ = setsockopt_int(fd, libc::SOL_NETLINK, NETLINK_CAP_ACK, 1);
    Ok((sock, addr.port_number()))
}

/// Receive one datagram of at most `size` bytes into `buf` (whose length
/// is set to the datagram length). The buffer is not zero-filled.
pub(crate) fn recv_datagram(
    sock: &NlSocket,
    buf: &mut Vec<u8>,
    size: usize,
    flags: i32,
) -> io::Result<usize> {
    buf.clear();
    buf.reserve(size);
    let cap = buf.capacity();
    // `Vec<u8>` as `BufMut` receives into the spare capacity.
    let n = sock.recv(buf, flags | libc::MSG_TRUNC)?;
    if n > cap {
        buf.clear();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink datagram truncated",
        ));
    }
    debug_assert_eq!(buf.len(), n);
    Ok(n)
}

/// Wait until `fd` is readable, failing with `TimedOut` once `deadline`
/// passes.
pub(crate) fn wait_readable(fd: RawFd, deadline: std::time::Instant) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: `p` is one valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r > 0 {
            return Ok(());
        }
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

pub(crate) fn is_enobufs(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOBUFS)
}

/// A netlink socket for managing nf_tables.
///
/// Every socket has its own netlink port id and sequence numbers, so any
/// number of sockets can be used concurrently (e.g. from different
/// threads). A single socket is not `Sync`; wrap it in a mutex to share it.
#[derive(Debug)]
pub struct Socket {
    sock: NlSocket,
    portid: u32,
    seq: u32,
    rbuf: Vec<u8>,
    sbuf: Vec<u8>,
}

impl Socket {
    /// Open a new socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (sock, portid) = open_socket()?;
        Ok(Socket {
            sock,
            portid,
            seq: initial_seq(),
            rbuf: Vec::with_capacity(RECV_BUF),
            sbuf: Vec::new(),
        })
    }

    /// The netlink port id of this socket (owner of `NFT_TABLE_F_OWNER` tables).
    pub fn port_id(&self) -> u32 {
        self.portid
    }

    /// Set the receive buffer size (the kernel doubles it).
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let v = i32::try_from(size).unwrap_or(i32::MAX);
        let fd = self.sock.as_raw_fd();
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, v)
            .or_else(|_| setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, v))?;
        Ok(())
    }

    /// Fail blocking operations with [`Error::Io`] (`WouldBlock`) if no
    /// response arrives within `timeout`. `None` (the default) waits
    /// forever. The kernel answers immediately, so this only guards against
    /// unexpected conditions.
    pub fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        Ok(set_recv_timeout(self.sock.as_raw_fd(), timeout)?)
    }

    fn next_seq(&mut self, n: u32) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(n);
        s
    }

    fn send_sbuf(&mut self) -> Result<()> {
        ensure_sndbuf(self.sock.as_raw_fd(), self.sbuf.len())?;
        let n = self.sock.send(&self.sbuf, 0)?;
        if n != self.sbuf.len() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink send",
            )));
        }
        Ok(())
    }

    /// Atomically apply a batch.
    ///
    /// On failure nothing was changed, and the returned
    /// [`Error::Batch`] lists every rejected operation.
    pub fn commit(&mut self, batch: &Batch) -> Result<BatchOutcome> {
        self.commit_with(batch, true).map(|o| o.unwrap_or_default())
    }

    /// Validate a batch without applying it (a dry run, like `nft -c`).
    /// Returns the same errors as [`Socket::commit`] would.
    pub fn check(&mut self, batch: &Batch) -> Result<()> {
        self.commit_with(batch, false).map(|_| ())
    }

    fn commit_with(&mut self, batch: &Batch, apply: bool) -> Result<Option<BatchOutcome>> {
        // Large batches can produce more responses than fit in the receive
        // buffer: grow it, and remember the generation so that the outcome
        // can be determined even if responses are lost anyway.
        let genid_before = if ensure_rcvbuf(self.sock.as_raw_fd(), batch.response_size_hint())? {
            Some(self.get_gen()?)
        } else {
            None
        };
        let seq = self.next_seq(batch.message_count() as u32 + 3);
        let mut resp = if apply {
            batch.encode(&mut self.sbuf, seq)?
        } else {
            batch.encode_check(&mut self.sbuf, seq)?
        };
        resp.set_genid_before(genid_before);
        self.send_sbuf()?;
        // The kernel processes the batch synchronously while sending, so all
        // its responses are queued now. Drain them before sending the
        // sentinel so that a full receive buffer cannot swallow it.
        loop {
            match recv_datagram(&self.sock, &mut self.rbuf, RECV_BUF, libc::MSG_DONTWAIT) {
                Ok(_) => resp.feed(&self.rbuf)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if is_enobufs(&e) => resp.set_lost(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        resp.sentinel(&mut self.sbuf);
        self.send_sbuf()?;
        while !resp.is_done() {
            match recv_datagram(&self.sock, &mut self.rbuf, RECV_BUF, 0) {
                Ok(_) => resp.feed(&self.rbuf)?,
                Err(e) if is_enobufs(&e) => resp.set_lost(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        let out = resp.finish(batch)?;
        Ok(apply.then_some(out))
    }

    /// Execute a request, calling `f` for each reply message. Returns
    /// whether a dump was interrupted by a concurrent change.
    pub fn request(
        &mut self,
        req: &Request,
        mut f: impl FnMut(&Msg<'_>) -> Result<()>,
    ) -> Result<bool> {
        let seq = self.next_seq(1);
        let mut col = req.encode(&mut self.sbuf, seq);
        self.send_sbuf()?;
        let mut err = None;
        while !col.is_done() {
            match recv_datagram(&self.sock, &mut self.rbuf, RECV_BUF, 0) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            // Keep reading after a callback error so that the socket is left
            // without stale data.
            col.feed(&self.rbuf, |m| {
                if err.is_none() {
                    if let Err(e) = f(m) {
                        err = Some(e);
                    }
                }
                Ok(())
            })?;
        }
        let interrupted = col.interrupted();
        col.finish()?;
        match err {
            Some(e) => Err(e),
            None => Ok(interrupted),
        }
    }

    fn dump_vec_once<T: Decode>(&mut self, req: &Request) -> Result<(Vec<T>, bool)> {
        let mut v = Vec::new();
        let intr = self.request(req, |m| {
            v.push(T::decode_msg(m)?);
            Ok(())
        })?;
        Ok((v, intr))
    }
}

/// A random-ish initial sequence number, so that independent sockets and
/// processes do not use the same numbers.
pub(crate) fn initial_seq() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(0);
    t ^ std::process::id().rotate_left(16)
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sock.as_fd()
    }
}

crate::client::client_methods!(Socket, sync);
