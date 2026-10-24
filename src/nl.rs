//! Sans-IO netlink message encoding and decoding primitives.
//!
//! [`Writer`] appends netlink messages and attributes to a growable buffer.
//! [`Messages`] and [`Attrs`] iterate over received data without copying.
//! Nothing in this module performs I/O, so it can be driven by any runtime.

use crate::error::{Error, Result};
use crate::sys::*;

/// Round `len` up to the netlink alignment (4 bytes).
#[inline]
pub const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Marker for an open message, returned by [`Writer::begin_msg`].
#[derive(Debug)]
#[must_use]
pub struct MsgToken(usize);

/// Marker for an open nested attribute, returned by [`Writer::begin_nest`].
#[derive(Debug)]
#[must_use]
pub struct NestToken(usize);

/// An append-only netlink message writer.
///
/// Attribute length overflows (a nested attribute larger than 64 KiB) do not
/// panic; they are recorded and reported by [`Writer::check`].
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
    overflow: bool,
    nul_in_str: bool,
}

impl Writer {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty writer with preallocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            overflow: false,
            nul_in_str: false,
        }
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Mutable access to the encoded bytes (e.g. to patch sequence numbers).
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Discard all content, keeping the allocation.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.overflow = false;
        self.nul_in_str = false;
    }

    /// Truncate to `len` bytes (used to roll back a partially written message).
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    /// Return an error if any attribute or message overflowed its length
    /// field, or a string attribute contained a NUL byte.
    pub fn check(&self) -> Result<()> {
        if self.overflow {
            Err(Error::TooLarge)
        } else if self.nul_in_str {
            Err(Error::invalid("string attribute contains a NUL byte"))
        } else {
            Ok(())
        }
    }

    /// Consume the writer, returning the bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    #[inline]
    fn pad(&mut self) {
        let n = align(self.buf.len()) - self.buf.len();
        self.buf.extend_from_slice(&[0u8; 3][..n]);
    }

    /// Begin a netlink message with an `nfgenmsg` header.
    ///
    /// `res_id` is written in network byte order, as nfnetlink expects.
    pub fn begin_msg(
        &mut self,
        ty: u16,
        flags: u16,
        seq: u32,
        family: u8,
        res_id: u16,
    ) -> MsgToken {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: kernel
        self.buf.push(family);
        self.buf.push(NFNETLINK_V0);
        self.buf.extend_from_slice(&res_id.to_be_bytes());
        MsgToken(start)
    }

    /// Finish a message started with [`Writer::begin_msg`].
    pub fn end_msg(&mut self, tok: MsgToken) {
        self.pad();
        let len = self.buf.len() - tok.0;
        let len32 = u32::try_from(len).unwrap_or_else(|_| {
            self.overflow = true;
            u32::MAX
        });
        self.buf[tok.0..tok.0 + 4].copy_from_slice(&len32.to_ne_bytes());
    }

    /// Append a raw attribute.
    pub fn put(&mut self, ty: u16, data: &[u8]) {
        let len = NLA_HDRLEN + data.len();
        let len16 = u16::try_from(len).unwrap_or_else(|_| {
            self.overflow = true;
            u16::MAX
        });
        self.buf.extend_from_slice(&len16.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
    }

    /// Append pre-encoded bytes (e.g. a sequence of complete attributes),
    /// padded to the netlink alignment.
    pub fn put_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.pad();
    }

    /// Append a `u8` attribute.
    pub fn put_u8(&mut self, ty: u16, v: u8) {
        self.put(ty, &[v]);
    }

    /// Append a big-endian `u16` attribute.
    pub fn put_be16(&mut self, ty: u16, v: u16) {
        self.put(ty, &v.to_be_bytes());
    }

    /// Append a big-endian `u32` attribute.
    pub fn put_be32(&mut self, ty: u16, v: u32) {
        self.put(ty, &v.to_be_bytes());
    }

    /// Append a big-endian `u64` attribute.
    pub fn put_be64(&mut self, ty: u16, v: u64) {
        self.put(ty, &v.to_be_bytes());
    }

    /// Append a NUL-terminated string attribute.
    pub fn put_str(&mut self, ty: u16, s: &str) {
        if s.as_bytes().contains(&0) {
            self.nul_in_str = true;
        }
        let len = NLA_HDRLEN + s.len() + 1;
        let len16 = u16::try_from(len).unwrap_or_else(|_| {
            self.overflow = true;
            u16::MAX
        });
        self.buf.extend_from_slice(&len16.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        self.pad();
    }

    /// Begin a nested attribute (sets `NLA_F_NESTED`).
    pub fn begin_nest(&mut self, ty: u16) -> NestToken {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        NestToken(start)
    }

    /// Finish a nested attribute.
    pub fn end_nest(&mut self, tok: NestToken) {
        let len = self.buf.len() - tok.0;
        let len16 = u16::try_from(len).unwrap_or_else(|_| {
            self.overflow = true;
            u16::MAX
        });
        self.buf[tok.0..tok.0 + 2].copy_from_slice(&len16.to_ne_bytes());
    }

    /// Write a nested attribute whose content is produced by `f`.
    #[inline]
    pub fn nest(&mut self, ty: u16, f: impl FnOnce(&mut Self)) {
        let tok = self.begin_nest(ty);
        f(self);
        self.end_nest(tok);
    }
}

// ------------------------------------------------------------------ parsing

/// A received netlink message (header fields plus payload).
#[derive(Debug, Clone, Copy)]
pub struct Msg<'a> {
    /// `nlmsg_type`.
    pub ty: u16,
    /// `nlmsg_flags`.
    pub flags: u16,
    /// `nlmsg_seq`.
    pub seq: u32,
    /// `nlmsg_pid`.
    pub pid: u32,
    /// Bytes after the netlink header.
    pub payload: &'a [u8],
}

impl<'a> Msg<'a> {
    /// The nfnetlink subsystem id (high byte of the type).
    pub fn subsys(&self) -> u8 {
        (self.ty >> 8) as u8
    }

    /// The nfnetlink message type within the subsystem (low byte).
    pub fn subtype(&self) -> u8 {
        (self.ty & 0xff) as u8
    }

    /// Split the `nfgenmsg` header off an nfnetlink payload.
    pub fn nfgen(&self) -> Result<(NfGenMsg, Attrs<'a>)> {
        if self.payload.len() < NFGENMSG_LEN {
            return Err(Error::malformed("short nfgenmsg"));
        }
        let h = NfGenMsg {
            family: self.payload[0],
            version: self.payload[1],
            res_id: u16::from_be_bytes([self.payload[2], self.payload[3]]),
        };
        Ok((h, Attrs::new(&self.payload[NFGENMSG_LEN..])))
    }
}

/// The nfnetlink generic header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfGenMsg {
    /// Address/protocol family.
    pub family: u8,
    /// Always `NFNETLINK_V0`.
    pub version: u8,
    /// Resource id (host byte order). For nf_tables dumps this is the
    /// lower 16 bits of the ruleset generation id.
    pub res_id: u16,
}

/// Iterator over the netlink messages contained in one datagram.
#[derive(Debug, Clone)]
pub struct Messages<'a> {
    buf: &'a [u8],
}

impl<'a> Messages<'a> {
    /// Iterate over the messages in `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<Msg<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < NLMSG_HDRLEN {
            self.buf = &[];
            return Some(Err(Error::malformed("truncated netlink header")));
        }
        let len = u32::from_ne_bytes(self.buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > self.buf.len() {
            self.buf = &[];
            return Some(Err(Error::malformed("bad netlink message length")));
        }
        let msg = Msg {
            ty: u16::from_ne_bytes([self.buf[4], self.buf[5]]),
            flags: u16::from_ne_bytes([self.buf[6], self.buf[7]]),
            seq: u32::from_ne_bytes(self.buf[8..12].try_into().unwrap()),
            pid: u32::from_ne_bytes(self.buf[12..16].try_into().unwrap()),
            payload: &self.buf[NLMSG_HDRLEN..len],
        };
        let adv = align(len).min(self.buf.len());
        self.buf = &self.buf[adv..];
        Some(Ok(msg))
    }
}

/// A single netlink attribute.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    /// Attribute type with the flag bits removed.
    pub ty: u16,
    /// Whether `NLA_F_NESTED` was set.
    pub nested_flag: bool,
    /// Attribute payload.
    pub data: &'a [u8],
}

impl<'a> Attr<'a> {
    /// Interpret the payload as nested attributes.
    pub fn nested(&self) -> Attrs<'a> {
        Attrs::new(self.data)
    }

    /// Interpret as a `u8`.
    pub fn u8(&self) -> Result<u8> {
        match self.data {
            [v, ..] => Ok(*v),
            _ => Err(Error::malformed("expected u8 attribute")),
        }
    }

    /// Interpret as a big-endian `u16`.
    pub fn be16(&self) -> Result<u16> {
        self.data
            .get(..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| Error::malformed("expected be16 attribute"))
    }

    /// Interpret as a big-endian `u32`.
    pub fn be32(&self) -> Result<u32> {
        self.data
            .get(..4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Error::malformed("expected be32 attribute"))
    }

    /// Interpret as a big-endian `u64`.
    pub fn be64(&self) -> Result<u64> {
        self.data
            .get(..8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Error::malformed("expected be64 attribute"))
    }

    /// Interpret as a native-endian `u32`.
    pub fn ne32(&self) -> Result<u32> {
        self.data
            .get(..4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Error::malformed("expected u32 attribute"))
    }

    /// Interpret as a (possibly NUL-terminated) UTF-8 string.
    pub fn str(&self) -> Result<&'a str> {
        let d = self.data;
        let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
        std::str::from_utf8(&d[..end])
            .map_err(|_| Error::malformed("invalid utf-8 in string attribute"))
    }

    /// Interpret as a string, returning an owned copy.
    pub fn string(&self) -> Result<String> {
        self.str().map(str::to_owned)
    }
}

/// Iterator over a sequence of attributes.
#[derive(Debug, Clone, Copy)]
pub struct Attrs<'a> {
    buf: &'a [u8],
}

impl<'a> Attrs<'a> {
    /// Iterate over the attributes in `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// The remaining unparsed bytes.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Result<Attr<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < NLA_HDRLEN {
            // Trailing bytes smaller than a header are padding.
            self.buf = &[];
            return None;
        }
        let len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        let ty = u16::from_ne_bytes([self.buf[2], self.buf[3]]);
        if len < NLA_HDRLEN || len > self.buf.len() {
            self.buf = &[];
            return Some(Err(Error::malformed("bad attribute length")));
        }
        let attr = Attr {
            ty: ty & NLA_TYPE_MASK,
            nested_flag: ty & NLA_F_NESTED != 0,
            data: &self.buf[NLA_HDRLEN..len],
        };
        let adv = align(len).min(self.buf.len());
        self.buf = &self.buf[adv..];
        Some(Ok(attr))
    }
}

/// Parsed contents of an `NLMSG_ERROR` message.
#[derive(Debug, Clone)]
pub struct ErrorMsg<'a> {
    /// Negative errno, or 0 for an acknowledgement.
    pub error: i32,
    /// Header fields of the request that caused this error.
    pub req_len: u32,
    /// Type of the request.
    pub req_ty: u16,
    /// Flags of the request.
    pub req_flags: u16,
    /// Sequence number of the request.
    pub req_seq: u32,
    /// Extended ack: human readable message.
    pub ext_msg: Option<&'a str>,
    /// Extended ack: offset of the offending attribute, relative to the
    /// start of the request's netlink header.
    pub ext_offset: Option<u32>,
    /// Extended ack: type of a missing attribute.
    pub ext_miss_type: Option<u32>,
    /// Extended ack: offset of the nest in which an attribute was missing.
    pub ext_miss_nest: Option<u32>,
}

impl<'a> ErrorMsg<'a> {
    /// Parse an `NLMSG_ERROR` message.
    pub fn parse(msg: &Msg<'a>) -> Result<Self> {
        let p = msg.payload;
        if p.len() < 4 + NLMSG_HDRLEN {
            return Err(Error::malformed("short NLMSG_ERROR"));
        }
        let mut e = ErrorMsg {
            error: i32::from_ne_bytes(p[0..4].try_into().unwrap()),
            req_len: u32::from_ne_bytes(p[4..8].try_into().unwrap()),
            req_ty: u16::from_ne_bytes([p[8], p[9]]),
            req_flags: u16::from_ne_bytes([p[10], p[11]]),
            req_seq: u32::from_ne_bytes(p[12..16].try_into().unwrap()),
            ext_msg: None,
            ext_offset: None,
            ext_miss_type: None,
            ext_miss_nest: None,
        };
        if msg.flags & NLM_F_ACK_TLVS != 0 {
            // Unless NLM_F_CAPPED is set, the original message follows.
            let skip = if msg.flags & NLM_F_CAPPED != 0 {
                4 + NLMSG_HDRLEN
            } else {
                4 + align(e.req_len as usize)
            };
            if let Some(tlvs) = p.get(skip..) {
                for a in Attrs::new(tlvs).flatten() {
                    match a.ty {
                        NLMSGERR_ATTR_MSG => e.ext_msg = a.str().ok(),
                        NLMSGERR_ATTR_OFFS => e.ext_offset = a.ne32().ok(),
                        NLMSGERR_ATTR_MISS_TYPE => e.ext_miss_type = a.ne32().ok(),
                        NLMSGERR_ATTR_MISS_NEST => e.ext_miss_nest = a.ne32().ok(),
                        _ => {}
                    }
                }
            }
        }
        Ok(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_attrs() {
        let mut w = Writer::new();
        let m = w.begin_msg(0x0a06, NLM_F_REQUEST, 7, 1, 0);
        w.put_str(1, "tbl");
        w.put_be32(2, 0xdeadbeef);
        let n = w.begin_nest(4);
        w.put_u8(1, 9);
        w.put_be64(2, 1 << 40);
        w.end_nest(n);
        w.end_msg(m);
        w.check().unwrap();
        assert_eq!(w.len() % 4, 0);

        let msgs: Vec<_> = Messages::new(w.as_bytes()).collect::<Result<_>>().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = msgs[0];
        assert_eq!(
            (msg.ty, msg.seq, msg.subsys(), msg.subtype()),
            (0x0a06, 7, 10, 6)
        );
        let (h, attrs) = msg.nfgen().unwrap();
        assert_eq!(h.family, 1);
        let attrs: Vec<_> = attrs.collect::<Result<_>>().unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].str().unwrap(), "tbl");
        assert_eq!(attrs[1].be32().unwrap(), 0xdeadbeef);
        assert!(attrs[2].nested_flag);
        let inner: Vec<_> = attrs[2].nested().collect::<Result<_>>().unwrap();
        assert_eq!(inner[0].u8().unwrap(), 9);
        assert_eq!(inner[1].be64().unwrap(), 1 << 40);
    }

    #[test]
    fn malformed_input_does_not_panic() {
        // Random garbage must only ever produce errors.
        let mut seed = 0x1234_5678u32;
        for len in 0..200 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            for m in Messages::new(&buf).flatten() {
                let _ = m.nfgen().map(|(_, a)| a.count());
                let _ = ErrorMsg::parse(&m);
            }
            for a in Attrs::new(&buf).flatten() {
                let _ = (a.u8(), a.be16(), a.be32(), a.be64(), a.str());
                let _ = a.nested().count();
            }
        }
    }

    #[test]
    fn overflow_detected() {
        let mut w = Writer::new();
        let n = w.begin_nest(1);
        for _ in 0..20000 {
            w.put_be32(1, 0);
        }
        w.end_nest(n);
        assert!(w.check().is_err());
    }
}
