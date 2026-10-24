//! Round trip a large ruleset written by `nft` through this crate:
//! decode everything from the kernel, flush, re-create it from the decoded
//! objects, and check that `nft` sees exactly the same ruleset.
mod common;
use common::*;
use crabtables::*;

/// `nft list ruleset` with the time-dependent `expires` fields removed.
fn listing() -> String {
    strip_expires(&ruleset())
}

fn strip_expires(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("expires ") {
        out.push_str(&rest[..i + "expires ".len()]);
        rest = &rest[i + "expires ".len()..];
        let end = rest.find([' ', ',', '}', '\n']).unwrap_or(rest.len());
        out.push('X');
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn check_known(e: &Expr, ctx: &str) {
    match e {
        Expr::Unknown(u) => panic!("unknown expression {} in {ctx}", u.name),
        Expr::Dynset(d) => d.exprs.iter().for_each(|e| check_known(e, ctx)),
        _ => {}
    }
}

/// Strip fields that legitimately differ between two dumps.
fn canonical(mut rs: Ruleset) -> Ruleset {
    rs.genid = 0;
    for t in &mut rs.tables {
        t.handle = None;
    }
    for c in &mut rs.chains {
        c.handle = None;
    }
    for (s, e) in &mut rs.sets {
        s.handle = None;
        for e in e.iter_mut() {
            e.expiration = None;
        }
        e.sort_by(|a, b| a.key.cmp(&b.key));
    }
    for o in &mut rs.objs {
        o.handle = None;
    }
    for f in &mut rs.flowtables {
        f.handle = None;
    }
    for r in &mut rs.rules {
        r.handle = None;
        r.position = None;
    }
    rs
}

#[test]
fn corpus_roundtrip() {
    roundtrip(include_str!("data/corpus.nft"), 8, 80);
}

#[test]
fn corpus2_roundtrip() {
    roundtrip(include_str!("data/corpus2.nft"), 1, 80);
}

fn roundtrip(script: &str, min_tables: usize, min_rules: usize) {
    netns();
    nft_script(script);
    let before = listing();

    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    assert!(rs.tables.len() >= min_tables, "{:?}", rs.tables);
    assert!(rs.rules.len() > min_rules, "only {} rules", rs.rules.len());
    for r in &rs.rules {
        for e in &r.exprs {
            check_known(e, &format!("rule {} {} {}", r.family, r.table, r.chain));
        }
    }
    for (set, elems) in &rs.sets {
        set.exprs.iter().for_each(|e| check_known(e, &set.name));
        for el in elems {
            el.exprs.iter().for_each(|e| check_known(e, &set.name));
        }
    }

    // Flush everything with our own batch.
    let mut b = Batch::new();
    b.flush_ruleset(Family::Unspec);
    s.commit(&b).unwrap();
    assert_eq!(ruleset(), "");
    assert!(s.list_tables(Family::Unspec).unwrap().is_empty());

    // With the json feature, go through JSON on the way.
    #[cfg(feature = "json")]
    let rs = {
        let j = rs.to_json().unwrap();
        let back = Ruleset::from_json(&j).unwrap();
        assert_eq!(back, rs, "JSON round trip");
        back
    };

    // Re-create from the decoded objects.
    let batch = rs.to_batch();
    if let Err(e) = s.commit(&batch) {
        panic!("re-create failed: {e}\n{e:#?}");
    }
    let after = listing();
    if before != after {
        let b: Vec<_> = before.lines().collect();
        let a: Vec<_> = after.lines().collect();
        for (i, (x, y)) in b.iter().zip(a.iter()).enumerate() {
            if x != y {
                panic!("listing differs at line {i}:\n  nft:  {x}\n  ours: {y}\n\nfull:\n{after}");
            }
        }
        panic!("listing length differs:\n{before}\n----\n{after}");
    }

    // Decoding the re-created ruleset yields the same objects.
    let rs2 = s.list_ruleset(Family::Unspec).unwrap();
    let (c1, c2) = (canonical(rs), canonical(rs2));
    assert_eq!(c1.tables, c2.tables);
    assert_eq!(c1.chains, c2.chains);
    assert_eq!(c1.objs, c2.objs);
    assert_eq!(c1.flowtables, c2.flowtables);
    for (x, y) in c1.sets.iter().zip(c2.sets.iter()) {
        assert_eq!(x, y);
    }
    assert_eq!(c1.sets.len(), c2.sets.len());
    for (x, y) in c1.rules.iter().zip(c2.rules.iter()) {
        assert_eq!(x, y);
    }
    assert_eq!(c1.rules.len(), c2.rules.len());
}
