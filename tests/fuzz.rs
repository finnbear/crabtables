//! Decoders must never panic, whatever the input: mutate real kernel
//! messages and decode them.
mod common;
use common::*;
use crabtables::nl::{Attrs, Messages};
use crabtables::proto::Request;
use crabtables::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn mutated_kernel_messages() {
    netns();
    nft_script(include_str!("data/corpus.nft"));
    let mut s = Socket::new().unwrap();
    let mut msgs: Vec<(u8, u8, Vec<u8>)> = Vec::new();
    let mut reqs = vec![
        Request::tables(Family::Unspec),
        Request::chains(Family::Unspec, None),
        Request::rules(Family::Unspec, None, None, false),
        Request::sets(Family::Unspec, None),
        Request::objs(Family::Unspec, None, None, false),
        Request::flowtables(Family::Unspec, None),
    ];
    for set in s.list_sets(Family::Unspec, None).unwrap() {
        reqs.push(Request::elems(set.family, &set.table, &set.name, false));
    }
    for r in &reqs {
        s.request(r, |m| {
            let (h, _) = m.nfgen()?;
            msgs.push((m.subtype(), h.family, m.payload[4..].to_vec()));
            Ok(())
        })
        .unwrap();
    }
    assert!(msgs.len() > 100);
    #[cfg(feature = "lang")]
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut decoded_ok = 0usize;
    for (sub, fam, payload) in &msgs {
        // Unmodified messages decode.
        assert!(
            Object::decode(*sub, *fam, Attrs::new(payload))
                .unwrap()
                .is_some()
        );
        for _ in 0..300 {
            let mut p = payload.clone();
            match rng.below(4) {
                0 => {
                    let n = 1 + rng.below(4);
                    for _ in 0..n {
                        let i = rng.below(p.len());
                        p[i] ^= 1 << rng.below(8);
                    }
                }
                1 => p.truncate(rng.below(p.len())),
                2 => {
                    // Corrupt a 16-bit field at an aligned offset (attribute lengths/types).
                    let i = rng.below(p.len() / 2) * 2;
                    if i + 1 < p.len() {
                        let v = rng.next() as u16;
                        p[i..i + 2].copy_from_slice(&v.to_ne_bytes());
                    }
                }
                _ => {
                    let i = rng.below(p.len());
                    let extra: Vec<u8> = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
                    p.splice(i..i, extra);
                }
            }
            if let Ok(Some(_o)) = Object::decode(*sub, *fam, Attrs::new(&p)) {
                decoded_ok += 1;
                // Rules with any values decompile and print.
                #[cfg(feature = "lang")]
                if let (_, Object::Rule(r)) = _o {
                    let ast = crabtables::lang::decompile::one_rule(&rs, &r);
                    crabtables::lang::print::rule(&ast, r.family, &Default::default());
                }
            }
            // Also through the message-level parsers.
            let _ = Messages::new(&p).count();
            for m in Messages::new(&p).flatten() {
                let _ = crabtables::nflog::parse_packet(&m);
            }
        }
    }
    eprintln!(
        "{} messages, {decoded_ok} mutated messages still decoded",
        msgs.len()
    );
}

#[test]
fn garbage_responses() {
    // Feeding garbage into the response collectors produces errors, not panics.
    let mut rng = Rng(42);
    let b = {
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Inet, "t"));
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "c")
                .match_eq(Field::TcpDport, 1u16)
                .accept()
                .build(),
        );
        b
    };
    for _ in 0..20000 {
        let len = rng.below(200);
        let mut d: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if d.len() >= 16 && rng.below(2) == 0 {
            // Plausible header: correct length, error or nftables type.
            let l = d.len() as u32;
            d[0..4].copy_from_slice(&l.to_ne_bytes());
            let ty: u16 = if rng.below(2) == 0 {
                2
            } else {
                0x0a00 | rng.below(34) as u16
            };
            d[4..6].copy_from_slice(&ty.to_ne_bytes());
        }
        let mut out = Vec::new();
        let mut r = b.encode(&mut out, 1000).unwrap();
        let _ = r.feed(&d);
        let _ = r.finish(&b);
        let mut c = Request::tables(Family::Inet).encode(&mut out, 5);
        let _ = c.feed(&d, |_| Ok(()));
    }
}

/// Extreme chain priorities print.
#[cfg(feature = "lang")]
#[test]
fn extreme_priorities() {
    use crabtables::lang::decompile::priority;
    for p in [i32::MIN, i32::MIN + 1, -1, 0, i32::MAX] {
        for h in ["input", "prerouting", "ingress"] {
            priority(Family::Inet, h, p);
            priority(Family::Bridge, h, p);
        }
    }
}

/// Out-of-range packet timestamps do not panic.
#[test]
fn huge_timestamps() {
    use crabtables::sys::*;
    // An NFLOG or NFQUEUE packet message with a packet header and a
    // timestamp of u64::MAX seconds and microseconds.
    let msg = |ty: u16, hdr_attr: u16, ts_attr: u16| {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&12u16.to_ne_bytes());
        attrs.extend_from_slice(&hdr_attr.to_ne_bytes());
        attrs.extend_from_slice(&[0, 0, 0, 1, 8, 0, 3, 0]);
        attrs.extend_from_slice(&20u16.to_ne_bytes());
        attrs.extend_from_slice(&ts_attr.to_ne_bytes());
        attrs.extend_from_slice(&[0xff; 16]);
        let mut m = Vec::new();
        m.extend_from_slice(&(20 + attrs.len() as u32).to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        m.extend_from_slice(&[2, 0, 0, 0]);
        m.extend_from_slice(&attrs);
        m
    };
    let m = msg(
        u16::from(NFNL_SUBSYS_ULOG) << 8,
        NFULA_PACKET_HDR,
        NFULA_TIMESTAMP,
    );
    let m = Messages::new(&m).next().unwrap().unwrap();
    let p = crabtables::nflog::parse_packet(&m).unwrap();
    assert_eq!(p.timestamp, None);
    let m = msg(
        u16::from(NFNL_SUBSYS_QUEUE) << 8,
        NFQA_PACKET_HDR,
        NFQA_TIMESTAMP,
    );
    let m = Messages::new(&m).next().unwrap().unwrap();
    let p = crabtables::nfqueue::parse_packet(&m).unwrap();
    assert_eq!(p.timestamp, None);
}
