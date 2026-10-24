//! Userspace-only codec benchmark (no kernel access needed).
use std::time::{Duration, Instant};

use crabtables::nl::{Attrs, Messages};
use crabtables::*;

fn main() {
    let mut best = [Duration::MAX; 3];
    for _ in 0..15 {
        let t = Instant::now();
        let mut l = SetElemList::new(Family::Inet, "t", "s");
        for i in 0..200_000u32 {
            l.elems.push(
                SetElem::new(i.to_be_bytes().to_vec()).with_timeout(Duration::from_secs(3600)),
            );
        }
        let mut b = Batch::new();
        b.add_elems(&l);
        for i in 0..20_000u16 {
            b.add_rule(
                &RuleBuilder::new(Family::Inet, "t", "c")
                    .match_eq(Field::TcpDport, i)
                    .counter()
                    .accept()
                    .build(),
            );
        }
        best[0] = best[0].min(t.elapsed());
        let mut out = Vec::new();
        let t = Instant::now();
        b.encode(&mut out, 1).unwrap();
        best[1] = best[1].min(t.elapsed());
        let t = Instant::now();
        let mut n = 0;
        for m in Messages::new(&out) {
            let m = m.unwrap();
            if m.subsys() == 10 {
                let (h, attrs) = m.nfgen().unwrap();
                if let Some((_, o)) =
                    Object::decode(m.subtype(), h.family, Attrs::new(attrs.remaining())).unwrap()
                {
                    n += match o {
                        Object::SetElems(l) => l.elems.len(),
                        _ => 1,
                    };
                }
            }
        }
        assert_eq!(n, 220_000);
        best[2] = best[2].min(t.elapsed());
    }
    println!(
        "build+encode batch: {:?}  frame: {:?}  decode: {:?}",
        best[0], best[1], best[2]
    );
}
