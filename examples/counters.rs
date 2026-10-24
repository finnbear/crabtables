//! Print every counter in the ruleset: rule counters, named counters and
//! per-element counters. With `--reset`, counters are atomically read and
//! zeroed.
use crabtables::*;

fn main() -> Result<()> {
    let reset = std::env::args().any(|a| a == "--reset");
    let mut s = Socket::new()?;
    let rules = if reset {
        s.list_rules_reset(Family::Unspec, None, None)?.items
    } else {
        s.list_rules(Family::Unspec, None, None)?
    };
    for r in &rules {
        for c in r.counters() {
            println!(
                "rule {} {} {} handle {}: {} packets {} bytes",
                r.family,
                r.table,
                r.chain,
                r.handle.unwrap_or(0),
                c.packets,
                c.bytes
            );
        }
    }
    let objs = if reset {
        s.list_objs_reset(Family::Unspec, None, Some(ObjType::Counter))?
            .items
    } else {
        s.list_objs(Family::Unspec, None, Some(ObjType::Counter))?
    };
    for o in objs {
        if let ObjKind::Counter(c) = o.kind {
            println!(
                "counter {} {} {}: {} packets {} bytes",
                o.family, o.table, o.name, c.packets, c.bytes
            );
        }
    }
    for set in s.list_sets(Family::Unspec, None)? {
        for e in s.list_elems(set.family, &set.table, &set.name)? {
            for x in &e.exprs {
                if let Expr::Counter(c) = x {
                    println!(
                        "set {} {} key {:02x?}: {} packets {} bytes",
                        set.table, set.name, e.key, c.packets, c.bytes
                    );
                }
            }
        }
    }
    Ok(())
}
