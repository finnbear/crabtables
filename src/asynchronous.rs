//! Async sockets for tokio (feature `tokio`).
//!
//! [`AsyncSocket`], [`AsyncNflogSocket`], [`AsyncNfqSocket`] and
//! [`AsyncMonitor`] have the API of their blocking counterparts, with
//! `async` methods. Create them inside a tokio runtime with I/O enabled.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use ::tokio::io::unix::AsyncFd;
use netlink_sys::Socket as NlSocket;

use crate::batch::{Batch, BatchOutcome};
use crate::error::{Error, Result};
use crate::nflog::{GroupConfig, NflogCore, Packets, Stats, set_rcvbuf};
use crate::nl::Msg;
use crate::proto::{Decode, Request};
use crate::socket::{
    RECV_BUF, ensure_rcvbuf, ensure_sndbuf, initial_seq, is_enobufs, open_socket, recv_datagram,
};

fn open_async() -> Result<(AsyncFd<NlSocket>, u32)> {
    let (sock, portid) = open_socket()?;
    sock.set_non_blocking(true)?;
    // SAFETY: `NlSocket` owns its file descriptor, keeps it open until it
    // is dropped (which happens when the `AsyncFd` is dropped) and always
    // returns the same descriptor from `as_raw_fd`.
    let fd = unsafe { AsyncFd::register(sock) }.map_err(|e| e.into_parts().1)?;
    Ok((fd, portid))
}

/// Access to the netlink socket behind an `AsyncFd`.
trait AsNl: AsRawFd {
    fn nl(&self) -> &NlSocket;
}
impl AsNl for NlSocket {
    fn nl(&self) -> &NlSocket {
        self
    }
}
impl AsNl for std::sync::Arc<NlSocket> {
    fn nl(&self) -> &NlSocket {
        self
    }
}

/// Receive one datagram, waiting for readiness.
async fn recv_async<T: AsNl>(fd: &AsyncFd<T>, buf: &mut Vec<u8>, size: usize) -> io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|s| recv_datagram(s.get_ref().nl(), buf, size, 0)) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

/// Send one datagram, waiting for writability if needed.
async fn send_async<T: AsNl>(fd: &AsyncFd<T>, buf: &[u8]) -> Result<()> {
    ensure_sndbuf(fd.as_raw_fd(), buf.len())?;
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|s| s.get_ref().nl().send(buf, 0)) {
            Ok(Ok(n)) if n == buf.len() => return Ok(()),
            Ok(Ok(_)) => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short netlink send",
                )));
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_would_block) => continue,
        }
    }
}

/// Async version of [`Socket`](crate::Socket).
#[derive(Debug)]
pub struct AsyncSocket {
    fd: AsyncFd<NlSocket>,
    portid: u32,
    seq: u32,
    rbuf: Vec<u8>,
    sbuf: Vec<u8>,
}

impl AsyncSocket {
    /// Open a new socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (fd, portid) = open_async()?;
        Ok(AsyncSocket {
            fd,
            portid,
            seq: initial_seq(),
            rbuf: Vec::with_capacity(RECV_BUF),
            sbuf: Vec::new(),
        })
    }

    /// The netlink port id of this socket.
    pub fn port_id(&self) -> u32 {
        self.portid
    }

    /// Set the receive buffer size (the kernel doubles it).
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        set_rcvbuf(self.fd.as_raw_fd(), size)
    }

    fn next_seq(&mut self, n: u32) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(n);
        s
    }

    /// Atomically apply a batch. See [`Socket::commit`](crate::Socket::commit).
    ///
    /// Not cancel safe in the sense that if the future is dropped after the
    /// batch was sent, it may have been applied without the outcome being
    /// reported; the socket itself stays usable (late responses are
    /// ignored).
    pub async fn commit(&mut self, batch: &Batch) -> Result<BatchOutcome> {
        self.commit_with(batch, true)
            .await
            .map(|o| o.unwrap_or_default())
    }

    /// Validate a batch without applying it. See
    /// [`Socket::check`](crate::Socket::check).
    pub async fn check(&mut self, batch: &Batch) -> Result<()> {
        self.commit_with(batch, false).await.map(|_| ())
    }

    async fn commit_with(&mut self, batch: &Batch, apply: bool) -> Result<Option<BatchOutcome>> {
        let genid_before = if ensure_rcvbuf(self.fd.as_raw_fd(), batch.response_size_hint())? {
            Some(self.get_gen().await?)
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
        send_async(&self.fd, &self.sbuf).await?;
        // Batch responses are queued synchronously during the send; drain
        // them without waiting before sending the sentinel.
        loop {
            match recv_datagram(
                self.fd.get_ref(),
                &mut self.rbuf,
                RECV_BUF,
                libc::MSG_DONTWAIT,
            ) {
                Ok(_) => resp.feed(&self.rbuf)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if is_enobufs(&e) => resp.set_lost(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        resp.sentinel(&mut self.sbuf);
        send_async(&self.fd, &self.sbuf).await?;
        while !resp.is_done() {
            match recv_async(&self.fd, &mut self.rbuf, RECV_BUF).await {
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
    /// whether a dump was interrupted. See [`Socket::request`](crate::Socket::request).
    pub async fn request(
        &mut self,
        req: &Request,
        mut f: impl FnMut(&Msg<'_>) -> Result<()>,
    ) -> Result<bool> {
        let seq = self.next_seq(1);
        let mut col = req.encode(&mut self.sbuf, seq);
        send_async(&self.fd, &self.sbuf).await?;
        let mut err = None;
        while !col.is_done() {
            match recv_async(&self.fd, &mut self.rbuf, RECV_BUF).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
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

    async fn dump_vec_once<T: Decode>(&mut self, req: &Request) -> Result<(Vec<T>, bool)> {
        let mut v = Vec::new();
        let intr = self
            .request(req, |m| {
                v.push(T::decode_msg(m)?);
                Ok(())
            })
            .await?;
        Ok((v, intr))
    }
}

impl AsRawFd for AsyncSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for AsyncSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.get_ref().as_fd()
    }
}

crate::client::client_methods!(AsyncSocket, async);

/// Async version of [`NflogSocket`](crate::nflog::NflogSocket).
#[derive(Debug)]
pub struct AsyncNflogSocket {
    fd: AsyncFd<NlSocket>,
    core: NflogCore,
}

impl AsyncNflogSocket {
    /// Open a socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (fd, _) = open_async()?;
        Ok(AsyncNflogSocket {
            fd,
            core: NflogCore::new(),
        })
    }

    /// Set the socket receive buffer size in bytes (the kernel doubles it).
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        set_rcvbuf(self.fd.as_raw_fd(), size)
    }

    /// Statistics so far.
    pub fn stats(&self) -> Stats {
        self.core.stats
    }

    /// Bind and configure a group. See [`NflogSocket::bind`](crate::nflog::NflogSocket::bind).
    pub async fn bind(&mut self, cfg: &GroupConfig) -> Result<()> {
        self.core.prepare_bind(cfg);
        self.config_roundtrip().await
    }

    /// Change the configuration of a bound group.
    pub async fn configure(&mut self, cfg: &GroupConfig) -> Result<()> {
        self.core.prepare_configure(cfg);
        self.config_roundtrip().await
    }

    /// Unbind a group.
    pub async fn unbind(&mut self, group: u16) -> Result<()> {
        self.core.prepare_unbind(group);
        self.config_roundtrip().await
    }

    async fn config_roundtrip(&mut self) -> Result<()> {
        send_async(&self.fd, &self.core.sbuf).await?;
        // Set after an overrun (see `nflog::ACK_GRACE`).
        let mut deadline = None;
        loop {
            let recv = recv_async(&self.fd, &mut self.core.rbuf, self.core.rbuf_size);
            let r = match deadline {
                None => recv.await,
                Some(d) => ::tokio::time::timeout_at(d, recv)
                    .await
                    .map_err(|_| crate::nflog::ack_lost())?,
            };
            match r {
                Ok(_) => {
                    if let Some(r) = self.core.on_config_datagram()? {
                        return r;
                    }
                }
                Err(e) => {
                    if is_enobufs(&e) {
                        deadline.get_or_insert_with(|| {
                            ::tokio::time::Instant::now() + crate::nflog::ACK_GRACE
                        });
                    }
                    self.core.retryable(e)?;
                }
            }
        }
    }

    /// Wait for a datagram and return its packets.
    ///
    /// Cancel safe: if the future is dropped before completion, no packets
    /// are lost.
    pub async fn recv(&mut self) -> Result<Packets<'_>> {
        if !self.core.take_pending() {
            loop {
                match recv_async(&self.fd, &mut self.core.rbuf, self.core.rbuf_size).await {
                    Ok(_) => break,
                    Err(e) => self.core.retryable(e)?,
                }
            }
        }
        Ok(self.core.packets())
    }
}

impl AsRawFd for AsyncNflogSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Async version of [`Monitor`](crate::monitor::Monitor).
#[derive(Debug)]
pub struct AsyncMonitor {
    fd: AsyncFd<NlSocket>,
    rbuf: Vec<u8>,
    pending_err: Option<crate::Error>,
}

impl AsyncMonitor {
    /// Subscribe to ruleset changes in the current network namespace.
    pub fn new() -> Result<Self> {
        let (fd, _) = open_async()?;
        fd.get_ref().add_membership(crate::sys::NFNLGRP_NFTABLES)?;
        Ok(AsyncMonitor {
            fd,
            rbuf: Vec::new(),
            pending_err: None,
        })
    }

    /// Wait for notifications and return them. A message that cannot be
    /// decoded is reported as an error, after the events received before it
    /// (by the next call).
    pub async fn recv(&mut self) -> Result<Vec<crate::monitor::Event>> {
        if let Some(e) = self.pending_err.take() {
            return Err(e);
        }
        let mut v = Vec::new();
        loop {
            match recv_async(&self.fd, &mut self.rbuf, RECV_BUF).await {
                Ok(_) => {
                    if let Err(e) = crate::monitor::parse_events(&self.rbuf, &mut v) {
                        if v.is_empty() {
                            return Err(e);
                        }
                        self.pending_err = Some(e);
                    }
                    return Ok(v);
                }
                Err(e) if is_enobufs(&e) => {
                    v.push(crate::monitor::Event::Overrun);
                    return Ok(v);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// Async version of [`NfqSocket`](crate::nfqueue::NfqSocket).
#[derive(Debug)]
pub struct AsyncNfqSocket {
    fd: AsyncFd<std::sync::Arc<NlSocket>>,
    core: crate::nfqueue::NfqCore,
}

impl AsyncNfqSocket {
    /// Open a socket in the current network namespace.
    pub fn new() -> Result<Self> {
        let (sock, _) = open_socket()?;
        sock.set_non_blocking(true)?;
        let sock = std::sync::Arc::new(sock);
        // SAFETY: the `Arc` keeps the socket (and so its descriptor) alive
        // for as long as the `AsyncFd` exists; `as_raw_fd` is stable.
        let fd = unsafe { AsyncFd::register(sock) }.map_err(|e| e.into_parts().1)?;
        Ok(AsyncNfqSocket {
            fd,
            core: crate::nfqueue::NfqCore::new(),
        })
    }

    /// A handle for issuing verdicts (non-blocking sends), also from other
    /// threads or tasks.
    pub fn verdicts(&self) -> crate::nfqueue::VerdictHandle {
        crate::nfqueue::VerdictHandle::from_arc(self.fd.get_ref().clone())
    }

    /// Set the socket receive buffer size in bytes.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        set_rcvbuf(self.fd.as_raw_fd(), size)
    }

    /// Statistics so far.
    pub fn stats(&self) -> crate::nfqueue::Stats {
        self.core.stats
    }

    /// Bind and configure a queue.
    pub async fn bind(&mut self, cfg: &crate::nfqueue::QueueConfig) -> Result<()> {
        self.core.prepare_bind(cfg);
        self.config_roundtrip().await
    }

    /// Change the configuration of a bound queue.
    pub async fn configure(&mut self, cfg: &crate::nfqueue::QueueConfig) -> Result<()> {
        self.core.prepare_configure(cfg);
        self.config_roundtrip().await
    }

    /// Unbind a queue.
    pub async fn unbind(&mut self, queue: u16) -> Result<()> {
        self.core.prepare_unbind(queue);
        self.config_roundtrip().await
    }

    async fn config_roundtrip(&mut self) -> Result<()> {
        send_async(&self.fd, &self.core.sbuf).await?;
        // Set after an overrun (see `nflog::ACK_GRACE`).
        let mut deadline = None;
        loop {
            let recv = recv_async(&self.fd, &mut self.core.rbuf, self.core.rbuf_size);
            let r = match deadline {
                None => recv.await,
                Some(d) => ::tokio::time::timeout_at(d, recv)
                    .await
                    .map_err(|_| crate::nflog::ack_lost())?,
            };
            match r {
                Ok(_) => {
                    if let Some(r) = self.core.on_config_datagram()? {
                        return r;
                    }
                }
                Err(e) => {
                    if is_enobufs(&e) {
                        deadline.get_or_insert_with(|| {
                            ::tokio::time::Instant::now() + crate::nflog::ACK_GRACE
                        });
                    }
                    self.core.retryable(e)?;
                }
            }
        }
    }

    /// Wait for packets and return them (cancel safe).
    pub async fn recv(&mut self) -> Result<crate::nfqueue::QueuePackets<'_>> {
        loop {
            if !self.core.take_pending() {
                match recv_async(&self.fd, &mut self.core.rbuf, self.core.rbuf_size).await {
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
}

impl AsRawFd for AsyncNfqSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
