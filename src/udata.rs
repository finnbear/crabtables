//! The user data TLV format used by `nft` (`NFTA_*_USERDATA`).
//!
//! The kernel stores user data opaquely; `nft` uses it for comments and
//! for type information it needs to pretty-print sets. Each entry is
//! `type: u8, len: u8, value: [u8; len]`.

/// Comment on a table, chain, rule, set element or object (type 0 in all
/// of these).
pub const UDATA_COMMENT: u8 = 0;

/// Set user data: key byte order (u32, host order; 1 = host, 2 = big endian).
pub const UDATA_SET_KEYBYTEORDER: u8 = 0;
/// Set user data: data byte order.
pub const UDATA_SET_DATABYTEORDER: u8 = 1;
/// Set user data: automatic merge of adjacent intervals (u32 1).
pub const UDATA_SET_MERGE_ELEMENTS: u8 = 2;
/// Set user data: key `typeof` expression.
pub const UDATA_SET_KEY_TYPEOF: u8 = 3;
/// Set user data: data `typeof` expression.
pub const UDATA_SET_DATA_TYPEOF: u8 = 4;
/// Set user data: stateful expression template.
pub const UDATA_SET_EXPR: u8 = 5;
/// Set user data: data is an interval.
pub const UDATA_SET_DATA_INTERVAL: u8 = 6;
/// Set user data: comment.
pub const UDATA_SET_COMMENT: u8 = 7;

/// Set element user data: flags (`1` = open interval end).
pub const UDATA_SET_ELEM_FLAGS: u8 = 1;

/// nft byte order value for host byte order.
pub const BYTEORDER_HOST: u32 = 1;
/// nft byte order value for big endian (network) byte order.
pub const BYTEORDER_BIG: u32 = 2;

/// A builder / parser for user data TLVs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Udata(pub Vec<u8>);

impl Udata {
    /// Empty user data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a raw entry. Values longer than 255 bytes are truncated.
    pub fn push(&mut self, ty: u8, value: &[u8]) -> &mut Self {
        let v = &value[..value.len().min(255)];
        self.0.push(ty);
        self.0.push(v.len() as u8);
        self.0.extend_from_slice(v);
        self
    }

    /// Append a NUL-terminated string entry (as nft does for comments).
    pub fn push_str(&mut self, ty: u8, s: &str) -> &mut Self {
        let mut v = s.as_bytes()[..s.len().min(254)].to_vec();
        v.push(0);
        self.push(ty, &v)
    }

    /// Append a host-order u32 entry.
    pub fn push_u32(&mut self, ty: u8, v: u32) -> &mut Self {
        self.push(ty, &v.to_ne_bytes())
    }

    /// Iterate over `(type, value)` entries. Stops at the first malformed entry.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8])> {
        iter(&self.0)
    }

    /// Look up the first entry of type `ty`.
    pub fn get(&self, ty: u8) -> Option<&[u8]> {
        self.iter().find(|(t, _)| *t == ty).map(|(_, v)| v)
    }

    /// Bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Iterate over the entries of raw user data.
pub fn iter(buf: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = buf;
    std::iter::from_fn(move || {
        let [ty, len, tail @ ..] = rest else {
            return None;
        };
        let len = *len as usize;
        if tail.len() < len {
            rest = &[];
            return None;
        }
        let (v, r) = tail.split_at(len);
        rest = r;
        Some((*ty, v))
    })
}

/// Build user data containing only a comment.
pub fn comment(s: &str) -> Vec<u8> {
    let mut u = Udata::new();
    u.push_str(UDATA_COMMENT, s);
    u.into_bytes()
}

/// Extract a string entry of type `ty` from raw user data.
pub fn get_str(buf: &[u8], ty: u8) -> Option<&str> {
    let v = iter(buf).find(|(t, _)| *t == ty)?.1;
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    std::str::from_utf8(&v[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut u = Udata::new();
        u.push_u32(UDATA_SET_KEYBYTEORDER, BYTEORDER_BIG)
            .push_str(UDATA_SET_COMMENT, "hi");
        assert_eq!(get_str(&u.0, UDATA_SET_COMMENT), Some("hi"));
        assert_eq!(
            u.get(UDATA_SET_KEYBYTEORDER),
            Some(&BYTEORDER_BIG.to_ne_bytes()[..])
        );
        assert_eq!(get_str(&comment("abc"), UDATA_COMMENT), Some("abc"));
        // malformed: length beyond end
        assert_eq!(iter(&[0, 5, 1]).count(), 0);
    }
}
