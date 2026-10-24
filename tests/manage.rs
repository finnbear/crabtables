//! Ruleset management: positions, replace, echo, flushes, deletes, owner
//! and persistent tables, objects, concatenated intervals.
mod common;
use std::time::Duration;

use common::*;
use crabtables::expr::*;
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

fn comments(s: &mut Socket, chain: &str) -> Vec<String> {
    s.list_rules(F, Some("t"), Some(chain))
        .unwrap()
        .iter()
        .map(|r| r.comment().unwrap_or("").to_owned())
        .collect()
}

fn rule(c: &str) -> Rule {
    RuleBuilder::new(F, "t", "c").counter().comment(c).build()
}

fn setup() -> Socket {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(&Chain::new(F, "t", "c"));
    s.commit(&b).unwrap();
    s
}

#[test]
fn echo_returns_handles() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(&rule("no-echo"));
    b.set_echo(true);
    let i1 = b.add_rule(&rule("a"));
    let i2 = b.add_rule(&rule("b"));
    let out = s.commit(&b).unwrap();
    let handles: Vec<_> = out.rule_handles().collect();
    assert_eq!(handles.len(), 2, "{:?}", out.echoes);
    assert_eq!((handles[0].0, handles[1].0), (i1, i2));
    let rules = s.list_rules(F, Some("t"), Some("c")).unwrap();
    assert_eq!(rules[1].handle, Some(handles[0].1));
    assert_eq!(rules[2].handle, Some(handles[1].1));
    match &out.echoes[0].1 {
        Object::Rule(r) => assert_eq!(r.comment(), Some("a")),
        o => panic!("{o:?}"),
    }
}

#[test]
fn positions_insert_replace_delete() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(&rule("a"));
    b.add_rule(&rule("c"));
    s.commit(&b).unwrap();
    let rules = s.list_rules(F, Some("t"), Some("c")).unwrap();
    let (ha, hc) = (rules[0].handle.unwrap(), rules[1].handle.unwrap());

    let mut b = Batch::new();
    // After a, before c, at the front, at the end.
    let mut r = rule("b");
    r.position = Some(ha);
    b.add_rule(&r);
    let mut r = rule("b2");
    r.position = Some(hc);
    b.insert_rule(&r);
    b.insert_rule(&rule("first"));
    b.add_rule(&rule("last"));
    s.commit(&b).unwrap();
    assert_eq!(
        comments(&mut s, "c"),
        ["first", "a", "b", "b2", "c", "last"]
    );

    // Replace c, delete a.
    let mut r = rule("C");
    r.handle = Some(hc);
    let mut b = Batch::new();
    b.replace_rule(&r).unwrap();
    b.delete_rule(F, "t", "c", ha);
    s.commit(&b).unwrap();
    assert_eq!(comments(&mut s, "c"), ["first", "b", "b2", "C", "last"]);
    let mut b = Batch::new();
    assert!(b.replace_rule(&rule("no handle")).is_err());

    // Rules positioned relative to rules of the same batch, by id.
    let mut b = Batch::new();
    let id = b.alloc_id();
    let mut x = rule("x");
    x.id = Some(id);
    b.insert_rule(&x);
    let mut y = rule("y");
    y.position_id = Some(id);
    b.add_rule(&y);
    s.commit(&b).unwrap();
    assert_eq!(
        comments(&mut s, "c"),
        ["x", "y", "first", "b", "b2", "C", "last"]
    );
}

#[test]
fn flush_and_delete_parts() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_chain(&Chain::new(F, "t", "d"));
    b.add_rule(&rule("c1"));
    b.add_rule(&RuleBuilder::new(F, "t", "d").counter().build());
    b.add_set(&Set::new(F, "t", "s", datatype::INET_SERVICE, 2));
    b.add_elems(
        &SetElemList::new(F, "t", "s")
            .with(SetElem::new(vec![0, 22]))
            .with(SetElem::new(vec![0, 80]))
            .with(SetElem::new(vec![1, 0])),
    );
    b.add_table(&Table::new(Family::Ipv4, "four"));
    b.add_table(&Table::new(Family::Ipv6, "six"));
    s.commit(&b).unwrap();

    // flush chain: only that chain.
    let mut b = Batch::new();
    b.flush_chain(F, "t", "c");
    s.commit(&b).unwrap();
    assert!(s.list_rules(F, Some("t"), Some("c")).unwrap().is_empty());
    assert_eq!(s.list_rules(F, Some("t"), Some("d")).unwrap().len(), 1);

    // delete specific elements.
    let mut b = Batch::new();
    b.delete_elems(&SetElemList::new(F, "t", "s").with(SetElem::new(vec![0, 80])));
    s.commit(&b).unwrap();
    let keys: Vec<_> = s
        .list_elems(F, "t", "s")
        .unwrap()
        .into_iter()
        .map(|e| e.key.unwrap())
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(!keys.contains(&vec![0, 80]));

    // flush set.
    let mut b = Batch::new();
    b.flush_set(F, "t", "s");
    s.commit(&b).unwrap();
    assert!(s.list_elems(F, "t", "s").unwrap().is_empty());

    // flush table: rules gone, chains and sets remain.
    let mut b = Batch::new();
    b.add_rule(&rule("again"));
    b.flush_table(F, "t");
    s.commit(&b).unwrap();
    assert!(s.list_rules(F, Some("t"), None).unwrap().is_empty());
    assert_eq!(s.list_chains(F, Some("t")).unwrap().len(), 2);
    assert_eq!(s.list_sets(F, Some("t")).unwrap().len(), 1);

    // delete set and chain.
    let mut b = Batch::new();
    b.delete_set(F, "t", "s");
    b.delete_chain(F, "t", "d");
    s.commit(&b).unwrap();
    assert!(s.list_sets(F, None).unwrap().is_empty());
    assert_eq!(s.list_chains(F, None).unwrap().len(), 1);

    // flush only the ip family.
    let mut b = Batch::new();
    b.flush_ruleset(Family::Ipv4);
    s.commit(&b).unwrap();
    let names: Vec<_> = s
        .list_tables(Family::Unspec)
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, ["t", "six"]);

    // flush everything.
    let mut b = Batch::new();
    b.flush_ruleset(Family::Unspec);
    s.commit(&b).unwrap();
    assert_eq!(ruleset(), "");
}

#[test]
fn delete_by_handle_and_rename() {
    let mut s = setup();
    let c = s.get_chain(F, "t", "c").unwrap();
    let mut b = Batch::new();
    b.rename_chain(F, "t", c.handle.unwrap(), "renamed");
    s.commit(&b).unwrap();
    assert_eq!(s.list_chains(F, Some("t")).unwrap()[0].name, "renamed");
    let mut b = Batch::new();
    b.delete_chain_by_handle(F, "t", c.handle.unwrap());
    s.commit(&b).unwrap();
    assert!(s.list_chains(F, Some("t")).unwrap().is_empty());
    let t = s.get_table(F, "t").unwrap();
    let mut b = Batch::new();
    b.delete_table_by_handle(F, t.handle.unwrap());
    s.commit(&b).unwrap();
    assert!(s.list_tables(F).unwrap().is_empty());
}

#[test]
fn chain_policy_update_and_comments() {
    let mut s = setup();
    let mut b = Batch::new();
    let chain = Chain::new(F, "t", "in")
        .with_hook(ChainType::Filter, Hook::INPUT, -5)
        .with_policy(Policy::Accept)
        .with_comment("base");
    b.add_chain(&chain);
    b.add_table(
        &Table::new(F, "t2")
            .with_comment("second")
            .with_flags(NFT_TABLE_F_DORMANT),
    );
    s.commit(&b).unwrap();
    // Update the policy of the existing chain (keep the rest).
    let mut b = Batch::new();
    b.add_chain(&Chain {
        policy: Some(Policy::Drop),
        ..chain.clone()
    });
    s.commit(&b).unwrap();
    let c = s.get_chain(F, "t", "in").unwrap();
    assert_eq!(c.policy, Some(Policy::Drop));
    assert_eq!(c.comment(), Some("base"));
    assert_eq!(c.hook.as_ref().unwrap().priority, -5);
    assert_eq!(c.chain_type, Some(ChainType::Filter));
    let t = s.get_table(F, "t2").unwrap();
    assert_eq!(t.comment(), Some("second"));
    assert_eq!(t.flags.unwrap() & NFT_TABLE_F_DORMANT, NFT_TABLE_F_DORMANT);
    assert_contains_lines(
        &ruleset(),
        "table inet t2 {\nflags dormant\ncomment \"second\"",
    );
    assert_contains_lines(
        &ruleset(),
        "chain in {\ncomment \"base\"\ntype filter hook input priority filter - 5; policy drop;",
    );
}

#[test]
fn owner_table_disappears_with_socket() {
    netns();
    {
        let mut owner = Socket::new().unwrap();
        let mut b = Batch::new();
        b.add_table(&Table::new(F, "owned").with_flags(NFT_TABLE_F_OWNER));
        owner.commit(&b).unwrap();
        let mut other = Socket::new().unwrap();
        let t = other.get_table(F, "owned").unwrap();
        assert_eq!(t.owner, Some(owner.port_id()));
        // Another socket cannot modify an owned table.
        let mut b = Batch::new();
        b.add_chain(&Chain::new(F, "owned", "x"));
        assert_eq!(other.commit(&b).unwrap_err().errno(), Some(libc::EPERM));
    }
    let mut s = Socket::new().unwrap();
    assert!(
        s.list_tables(F).unwrap().is_empty(),
        "owned table is removed when its socket closes"
    );
}

#[test]
fn persist_table_survives_socket() {
    netns();
    {
        let mut owner = Socket::new().unwrap();
        let mut b = Batch::new();
        b.add_table(&Table::new(F, "kept").with_flags(NFT_TABLE_F_OWNER | NFT_TABLE_F_PERSIST));
        owner.commit(&b).unwrap();
        let t = Socket::new().unwrap().get_table(F, "kept").unwrap();
        assert_eq!(t.owner, Some(owner.port_id()));
    }
    // Released, not removed: no longer owned, so others may change it.
    let mut s = Socket::new().unwrap();
    let t = s.get_table(F, "kept").unwrap();
    assert_eq!(t.owner, None);
    assert_eq!(t.flags.unwrap_or(0) & NFT_TABLE_F_OWNER, 0);
    let mut b = Batch::new();
    b.add_chain(&Chain::new(F, "kept", "x"));
    s.commit(&b).unwrap();
}

#[test]
fn objects() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_obj(
        &Obj::new(
            F,
            "t",
            "lim",
            ObjKind::Limit(limit_expr(
                10,
                Duration::from_secs(60),
                3,
                LimitType::Packets,
                false,
            )),
        )
        .with_comment("x"),
    );
    b.add_obj(&Obj::new(
        F,
        "t",
        "q",
        ObjKind::Quota(Quota {
            bytes: 5000,
            flags: NFT_QUOTA_F_INV,
            consumed: None,
        }),
    ));
    b.add_obj(&Obj::new(
        F,
        "t",
        "h",
        ObjKind::CtHelper(CtHelper {
            name: "ftp".into(),
            l3proto: Some(NFPROTO_IPV4.into()),
            l4proto: libc::IPPROTO_TCP as u8,
        }),
    ));
    s.commit(&b).unwrap();
    let rs = ruleset();
    assert_contains_lines(
        &rs,
        "limit lim {\ncomment \"x\"\nrate 10/minute burst 3 packets\n}",
    );
    assert_contains_lines(&rs, "quota q {\nover 5000 bytes\n}");
    assert_contains_lines(
        &rs,
        "ct helper h {\ntype \"ftp\" protocol tcp\nl3proto ip\n}",
    );
    // nft cannot display named connlimit objects (it asserts), so check
    // those through our own dump only.
    let mut b = Batch::new();
    b.add_obj(&Obj::new(
        F,
        "t",
        "cl",
        ObjKind::Connlimit(Connlimit { count: 4, flags: 0 }),
    ));
    s.commit(&b).unwrap();
    match s.get_obj(F, "t", "cl", ObjType::Connlimit).unwrap().kind {
        ObjKind::Connlimit(c) => assert_eq!(c.count, 4),
        k => panic!("{k:?}"),
    }
    let mut b = Batch::new();
    b.delete_obj(F, "t", "lim", ObjType::Limit);
    b.destroy_obj(F, "t", "nope", ObjType::Limit);
    s.commit(&b).unwrap();
    assert_eq!(s.list_objs(F, Some("t"), None).unwrap().len(), 3);
    assert!(
        s.get_obj(F, "t", "lim", ObjType::Limit)
            .unwrap_err()
            .is_not_found()
    );
    assert_eq!(
        s.list_objs(F, Some("t"), Some(ObjType::Quota))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn concatenated_intervals_and_catchall() {
    let mut s = setup();
    let fields = [Field::IpSaddr, Field::TcpDport];
    let mut b = Batch::new();
    let mut set = Set::new(
        F,
        "t",
        "ci",
        datatype::concat(&[datatype::IPADDR, datatype::INET_SERVICE]),
        concat_len(&fields),
    )
    .with_flags(NFT_SET_INTERVAL | NFT_SET_CONCAT);
    set.field_lens = vec![4, 2];
    b.add_set(&set);
    let key = |ip: [u8; 4], port: u16| {
        concat_key(&[
            (&fields[0], ip.to_vec()),
            (&fields[1], port.to_be_bytes().to_vec()),
        ])
    };
    b.add_elems(
        &SetElemList::new(F, "t", "ci")
            .with(SetElem::new(key([10, 0, 0, 0], 80)).with_key_end(key([10, 0, 0, 255], 90))),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "c")
            .in_set("ci", &fields)
            .accept()
            .build(),
    );
    // A map with a catch-all element.
    b.add_set(&Set::new(F, "t", "m", datatype::IPADDR, 4).vmap());
    b.add_elems(
        &SetElemList::new(F, "t", "m")
            .with(SetElem::new(vec![1, 2, 3, 4]).with_verdict(Verdict::Accept))
            .with(SetElem::catchall().with_verdict(Verdict::Drop)),
    );
    s.commit(&b).unwrap();
    let rs = ruleset();
    assert_contains_lines(
        &rs,
        "set ci {\ntype ipv4_addr . inet_service\nflags interval\nelements = { 10.0.0.0/24 . 80-90 }",
    );
    assert_contains_lines(&rs, "elements = { 1.2.3.4 : accept,\n* : drop }");
    assert!(rs.contains("ip saddr . tcp dport @ci accept"));
    let e = s.list_elems(F, "t", "m").unwrap();
    assert!(
        e.iter()
            .any(|e| e.is_catchall() && e.data == Some(Data::Verdict(Verdict::Drop)))
    );
}

#[test]
fn large_batches() {
    let mut s = setup();
    // 100k set elements in one transaction.
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "big", datatype::IPADDR, 4).with_flags(NFT_SET_TIMEOUT));
    let mut l = SetElemList::new(F, "t", "big");
    for i in 0..100_000u32 {
        l.elems
            .push(SetElem::new(i.to_be_bytes().to_vec()).with_timeout(Duration::from_secs(3600)));
    }
    b.add_elems(&l);
    let t = std::time::Instant::now();
    s.commit(&b).unwrap();
    eprintln!(
        "100k elements: {:?} ({} bytes, {} messages)",
        t.elapsed(),
        b.byte_len(),
        b.message_count()
    );
    let t = std::time::Instant::now();
    assert_eq!(s.list_elems(F, "t", "big").unwrap().len(), 100_000);
    eprintln!("dump 100k elements: {:?}", t.elapsed());

    // 10k rules.
    let mut b = Batch::new();
    for i in 0..10_000u16 {
        b.add_rule(
            &RuleBuilder::new(F, "t", "c")
                .match_eq(Field::TcpDport, i)
                .counter()
                .accept()
                .build(),
        );
    }
    let t = std::time::Instant::now();
    s.commit(&b).unwrap();
    eprintln!("10k rules: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    assert_eq!(s.list_rules(F, Some("t"), None).unwrap().len(), 10_000);
    eprintln!("dump 10k rules: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    eprintln!("snapshot: {:?}", t.elapsed());
    assert_eq!(rs.rules.len(), 10_000);
    assert_eq!(rs.sets[0].1.len(), 100_000);

    // Flushing a large set and deleting the table.
    let mut b = Batch::new();
    b.flush_set(F, "t", "big");
    b.delete_table(F, "t");
    s.commit(&b).unwrap();
    assert_eq!(ruleset(), "");
}

#[test]
fn concurrent_sockets_and_threads() {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(&Chain::new(F, "t", "c"));
    s.commit(&b).unwrap();
    // Threads inherit the namespace of the spawning thread.
    let handles: Vec<_> = (0..4)
        .map(|t| {
            std::thread::spawn(move || {
                let mut s = Socket::new().unwrap();
                for i in 0..50u16 {
                    let mut b = Batch::new();
                    b.add_rule(
                        &RuleBuilder::new(F, "t", "c")
                            .match_eq(Field::TcpDport, t * 1000 + i)
                            .accept()
                            .build(),
                    );
                    s.commit(&b).unwrap();
                    // Dumps during concurrent changes are retried, never inconsistent.
                    let n = s.list_rules(F, Some("t"), None).unwrap().len();
                    assert!(n > 0);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.list_rules(F, Some("t"), None).unwrap().len(), 200);
}

#[test]
fn dumped_objects_can_be_added_elsewhere() {
    let mut s = setup();
    let mut b = Batch::new();
    for c in ["a", "b", "c"] {
        b.add_rule(&rule(c));
    }
    s.commit(&b).unwrap();
    // Copy the chain and its rules into another table, unchanged except for
    // the table name.
    let chain = s.get_chain(F, "t", "c").unwrap();
    let rules = s.list_rules(F, Some("t"), Some("c")).unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "copy"));
    b.add_chain(&Chain {
        table: "copy".into(),
        ..chain
    });
    for r in rules {
        b.add_rule(&Rule {
            table: "copy".into(),
            ..r
        });
    }
    s.commit(&b).unwrap();
    let copied: Vec<_> = s
        .list_rules(F, Some("copy"), Some("c"))
        .unwrap()
        .iter()
        .map(|r| r.comment().unwrap().to_owned())
        .collect();
    assert_eq!(copied, ["a", "b", "c"]);
}

#[test]
fn echo_for_many_rules() {
    let mut s = setup();
    let mut b = Batch::new();
    b.set_echo(true);
    for i in 0..10_000u16 {
        b.add_rule(
            &RuleBuilder::new(F, "t", "c")
                .match_eq(Field::TcpDport, i)
                .accept()
                .build(),
        );
    }
    let out = s.commit(&b).unwrap();
    assert!(!out.responses_lost);
    let handles: Vec<_> = out.rule_handles().collect();
    assert_eq!(handles.len(), 10_000);
    let dumped: Vec<_> = s
        .list_rules(F, Some("t"), Some("c"))
        .unwrap()
        .iter()
        .map(|r| r.handle.unwrap())
        .collect();
    assert_eq!(handles.iter().map(|h| h.1).collect::<Vec<_>>(), dumped);
}
