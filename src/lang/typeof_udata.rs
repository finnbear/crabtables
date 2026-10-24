//! nft's encoding of `typeof` set key / data expressions in set user data.
//!
//! The format (nested TLVs of `type: u8, len: u8, value`) is:
//! `0: u32 expression kind`, `1: nested kind specific data`. Kinds used:
//! value (4), payload (7), meta (9), ct (12), concatenation (13),
//! numgen (23). Concatenation data holds one numbered entry per component.

use crate::udata;

use super::ast::Expr;
use super::proto;

const KIND_VALUE: u32 = 4;
const KIND_VERDICT: u32 = 1;
const KIND_PAYLOAD: u32 = 7;
const KIND_META: u32 = 9;
const KIND_CT: u32 = 12;
const KIND_CONCAT: u32 = 13;
const KIND_NUMGEN: u32 = 23;
const KIND_OSF: u32 = 11;

fn u32_of(v: &[u8]) -> Option<u32> {
    v.get(..4)
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

fn get(data: &[u8], ty: u8) -> Option<&[u8]> {
    udata::iter(data).find(|(t, _)| *t == ty).map(|(_, v)| v)
}

/// Decode a typeof expression. Returns `None` for plain values (sets
/// declared with `type`) and unknown encodings.
pub fn decode(buf: &[u8]) -> Option<Vec<Expr>> {
    let kind = u32_of(get(buf, 0)?)?;
    let data = get(buf, 1).unwrap_or(&[]);
    match kind {
        KIND_CONCAT => {
            let mut v = Vec::new();
            for (_, comp) in udata::iter(data) {
                v.extend(decode(comp)?);
            }
            Some(v)
        }
        KIND_VALUE | KIND_VERDICT => None,
        _ => Some(vec![decode_one(kind, data)?]),
    }
}

fn decode_one(kind: u32, data: &[u8]) -> Option<Expr> {
    match kind {
        KIND_PAYLOAD => {
            let desc = u32_of(get(data, 0)?)?;
            let field = u32_of(get(data, 1)?)? as usize;
            let p = proto::proto_by_desc(desc)?;
            let f = p.fields.get(field.checked_sub(1)?)?;
            Some(Expr::Payload {
                proto: p.name.to_owned(),
                field: f.name.to_owned(),
            })
        }
        KIND_META => {
            let key = u32_of(get(data, 0)?)?;
            let m = proto::meta_by_key(crate::MetaKey::from_raw(key))?;
            Some(Expr::Meta(m.name.to_owned()))
        }
        KIND_CT => {
            let key = u32_of(get(data, 0)?)?;
            let dir = get(data, 1).and_then(u32_of).unwrap_or(u32::MAX);
            let c = proto::ct_by_key(crate::CtKey::from_raw(key))?;
            let dir = match dir {
                0 => Some("original".to_owned()),
                1 => Some("reply".to_owned()),
                _ => None,
            };
            Some(Expr::Ct {
                dir,
                key: c.name.to_owned(),
            })
        }
        KIND_OSF => Some(Expr::Osf {
            ttl: None,
            version: false,
        }),
        KIND_NUMGEN => {
            let mode = u32_of(get(data, 0)?)?;
            let modulus = u32_of(get(data, 1)?)?;
            let offset = get(data, 2).and_then(u32_of).unwrap_or(0);
            Some(Expr::Numgen {
                mode: if mode == 0 { "inc" } else { "random" }.into(),
                modulus,
                offset,
            })
        }
        _ => None,
    }
}

/// Encode typeof expressions (`None` if an expression cannot be encoded).
pub fn encode(exprs: &[Expr], payload_bits: impl Fn(&Expr) -> Option<u32>) -> Option<Vec<u8>> {
    if exprs.len() == 1 {
        return encode_one(&exprs[0], &payload_bits);
    }
    let mut data = udata::Udata::new();
    for (i, e) in exprs.iter().enumerate() {
        data.push(i as u8, &encode_one(e, &payload_bits)?);
    }
    let mut u = udata::Udata::new();
    u.push_u32(0, KIND_CONCAT);
    u.push(1, &data.0);
    Some(u.into_bytes())
}

fn encode_one(e: &Expr, payload_bits: &impl Fn(&Expr) -> Option<u32>) -> Option<Vec<u8>> {
    let mut data = udata::Udata::new();
    let kind = match e {
        Expr::Payload { proto: p, field } => {
            let pr = proto::proto(p)?;
            let (idx, f) = pr.field(field)?;
            data.push_u32(0, pr.desc);
            data.push_u32(1, idx as u32);
            if f.ty == super::datatype::id::INTEGER {
                data.push_u32(4, payload_bits(e).unwrap_or(f.len));
            }
            KIND_PAYLOAD
        }
        Expr::Meta(k) => {
            let m = proto::meta(k)?;
            data.push_u32(0, m.key.raw());
            KIND_META
        }
        Expr::Ct { dir, key } => {
            let c = proto::ct(key)?;
            data.push_u32(0, c.key.raw());
            let d = match dir.as_deref() {
                Some("original") => 0,
                Some("reply") => 1,
                _ => u32::MAX,
            };
            data.push_u32(1, d);
            KIND_CT
        }
        Expr::Numgen {
            mode,
            modulus,
            offset,
        } => {
            data.push_u32(0, u32::from(mode == "random"));
            data.push_u32(1, *modulus);
            data.push_u32(2, *offset);
            KIND_NUMGEN
        }
        Expr::Osf { .. } => KIND_OSF,
        _ => return None,
    };
    let mut u = udata::Udata::new();
    u.push_u32(0, kind);
    u.push(1, &data.0);
    Some(u.into_bytes())
}

/// The user data nft attaches to a set declared with `type` (a value
/// expression).
pub fn value_marker() -> Vec<u8> {
    let mut u = udata::Udata::new();
    u.push_u32(0, KIND_VALUE);
    u.push(1, &[]);
    u.into_bytes()
}

/// The user data nft attaches for verdict map data.
pub fn verdict_marker() -> Vec<u8> {
    let mut u = udata::Udata::new();
    u.push_u32(0, KIND_VERDICT);
    u.push(1, &[]);
    u.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_observed() {
        // typeof ip saddr . meta mark, as written by nft.
        let b = [
            0x00, 0x04, 0x0d, 0, 0, 0, 0x01, 0x26, 0x00, 0x14, 0x00, 0x04, 0x07, 0, 0, 0, 0x01,
            0x0c, 0x00, 0x04, 0x0c, 0, 0, 0, 0x01, 0x04, 0x0b, 0, 0, 0, 0x01, 0x0e, 0x00, 0x04,
            0x09, 0, 0, 0, 0x01, 0x06, 0x00, 0x04, 0x03, 0, 0, 0,
        ];
        let e = decode(&b).unwrap();
        assert_eq!(
            e,
            vec![
                Expr::Payload {
                    proto: "ip".into(),
                    field: "saddr".into()
                },
                Expr::Meta("mark".into())
            ]
        );
        let enc = encode(&e, |_| None).unwrap();
        assert_eq!(enc, b);
        // A `type ipv4_addr` set.
        assert_eq!(decode(&[0, 4, 4, 0, 0, 0, 1, 0]), None);
        assert_eq!(value_marker(), [0, 4, 4, 0, 0, 0, 1, 0]);
    }
}
