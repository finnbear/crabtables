//! Functional tests: real packets over loopback, verified via counters.
mod common;
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use common::*;
use crabtables::expr::*;
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

fn base(s: &mut Socket) {
    let mut b = Batch::new();
    b.add_table(&Table::new(F, "t"));
    b.add_chain(&Chain::new(F, "t", "out").with_hook(ChainType::Filter, Hook::OUTPUT, 0));
    s.commit(&b).unwrap();
}

fn send_udp(to: Ipv4Addr, port: u16, n: usize) {
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..n {
        tx.send_to(&[0u8; 10], (to, port)).unwrap();
    }
}

/// Packet count of the counter in the rule with the given comment.
fn counter_of(s: &mut Socket, chain: &str, comment: &str) -> u64 {
    let rules = s.list_rules(F, Some("t"), Some(chain)).unwrap();
    let r = rules
        .iter()
        .find(|r| r.comment() == Some(comment))
        .unwrap_or_else(|| panic!("no rule {comment}"));
    r.counters().map(|c| c.packets).sum()
}

fn counted_chain(b: &mut Batch, name: &str) {
    b.add_chain(&Chain::new(F, "t", name));
    b.add_rule(
        &RuleBuilder::new(F, "t", name)
            .counter()
            .comment(name)
            .build(),
    );
}

#[test]
fn interval_vmap_jumps() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    for c in ["a", "b", "c"] {
        counted_chain(&mut b, c);
    }
    b.add_set(
        &Set::new(F, "t", "iv", datatype::IPADDR, 4)
            .vmap()
            .with_flags(NFT_SET_INTERVAL),
    );
    let mut l = SetElemList::new(F, "t", "iv");
    let ip = |d: u8| Ipv4Addr::new(127, 0, 0, d).octets();
    l.elems
        .extend(SetElem::range(&ip(0), &ip(9), Some(Verdict::Jump("a".into()).into())).unwrap());
    l.elems
        .extend(SetElem::range(&ip(10), &ip(19), Some(Verdict::Jump("b".into()).into())).unwrap());
    l.elems
        .extend(SetElem::range(&ip(20), &ip(29), Some(Verdict::Goto("c".into()).into())).unwrap());
    b.add_elems(&l);
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5000u16)
            .vmap("iv", &[Field::IpDaddr])
            .build(),
    );
    s.commit(&b).unwrap();
    assert_contains_lines(
        &ruleset(),
        "elements = { 127.0.0.0-127.0.0.9 : jump a,\n127.0.0.10-127.0.0.19 : jump b,\n127.0.0.20-127.0.0.29 : goto c }",
    );

    send_udp(Ipv4Addr::new(127, 0, 0, 5), 5000, 3);
    send_udp(Ipv4Addr::new(127, 0, 0, 9), 5000, 1);
    send_udp(Ipv4Addr::new(127, 0, 0, 10), 5000, 2);
    send_udp(Ipv4Addr::new(127, 0, 0, 25), 5000, 4);
    send_udp(Ipv4Addr::new(127, 0, 0, 30), 5000, 5);
    assert_eq!(counter_of(&mut s, "a", "a"), 4);
    assert_eq!(counter_of(&mut s, "b", "b"), 2);
    assert_eq!(counter_of(&mut s, "c", "c"), 4);

    // Lookup of a single address returns the containing interval.
    let found = s
        .get_elems(F, "t", "iv", &[SetElem::new(ip(15).to_vec())])
        .unwrap();
    assert_eq!(found[0].key.as_deref(), Some(&ip(10)[..]));
    assert_eq!(
        found[0].data,
        Some(Data::Verdict(Verdict::Jump("b".into())))
    );
    assert!(
        s.get_elems(F, "t", "iv", &[SetElem::new(ip(40).to_vec())])
            .unwrap_err()
            .is_not_found()
    );
}

#[test]
fn numgen_round_robin() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    counted_chain(&mut b, "a");
    counted_chain(&mut b, "b");
    b.add_set(&Set::new(F, "t", "ng", datatype::INTEGER, 4).vmap());
    b.add_elems(
        &SetElemList::new(F, "t", "ng")
            .with(
                SetElem::new(10u32.to_ne_bytes().to_vec()).with_verdict(Verdict::Jump("a".into())),
            )
            .with(
                SetElem::new(11u32.to_ne_bytes().to_vec()).with_verdict(Verdict::Jump("b".into())),
            ),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5000u16)
            .numgen_vmap(NumgenType::Incremental, 2, 10, "ng")
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::LOCALHOST, 5000, 10);
    assert_eq!(counter_of(&mut s, "a", "a"), 5);
    assert_eq!(counter_of(&mut s, "b", "b"), 5);
}

#[test]
fn limit_rate() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5001u16)
            .limit_over(5, Duration::from_secs(1), 5)
            .counter()
            .comment("over")
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5001u16)
            .limit(5, Duration::from_secs(1), 5)
            .counter()
            .comment("under")
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::LOCALHOST, 5001, 50);
    let over = counter_of(&mut s, "out", "over");
    let under = counter_of(&mut s, "out", "under");
    // The burst lets the first ~5 through; everything else is over.
    assert!((40..=46).contains(&over), "over = {over}");
    assert!((4..=10).contains(&under), "under = {under}");
}

#[test]
fn raw_transport_offsets() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    let port: u16 = 5002; // 0x138a
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
            .match_bits(PayloadBase::Transport, 16, 16, port.into())
            .counter()
            .comment("aligned")
            .build(),
    );
    // The upper 12 bits of the destination port: 0x138.
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
            .match_bits(PayloadBase::Transport, 16, 12, u64::from(port >> 4))
            .counter()
            .comment("unaligned")
            .build(),
    );
    // Bits 4..16 of the destination port (low 12 bits): 0x38a.
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::L4Proto, libc::IPPROTO_UDP as u8)
            .match_bits(PayloadBase::Transport, 20, 12, u64::from(port & 0xfff))
            .counter()
            .comment("unaligned2")
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::LOCALHOST, port, 3);
    send_udp(Ipv4Addr::LOCALHOST, port + 1, 2); // 0x138b: matches only "unaligned"
    assert_eq!(counter_of(&mut s, "out", "aligned"), 3);
    assert_eq!(counter_of(&mut s, "out", "unaligned"), 5);
    assert_eq!(counter_of(&mut s, "out", "unaligned2"), 3);
}

#[test]
fn dynset_with_timeouts() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    b.add_set(
        &Set::new(F, "t", "seen", datatype::IPADDR, 4)
            .with_flags(NFT_SET_EVAL)
            .with_timeout(Duration::from_secs(60)),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5003u16)
            .dynset(
                DynsetOp::Add,
                "seen",
                &[Field::IpDaddr],
                Some(Duration::from_millis(1500)),
                vec![],
            )
            .build(),
    );
    s.commit(&b).unwrap();
    assert!(s.list_elems(F, "t", "seen").unwrap().is_empty());
    send_udp(Ipv4Addr::new(127, 0, 0, 7), 5003, 1);
    let e = s.list_elems(F, "t", "seen").unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].key.as_deref(), Some(&[127, 0, 0, 7][..]));
    assert_eq!(e[0].timeout, Some(Duration::from_millis(1500)));
    assert!(e[0].expiration.unwrap() <= Duration::from_millis(1500));
    std::thread::sleep(Duration::from_millis(2000));
    assert!(
        s.list_elems(F, "t", "seen").unwrap().is_empty(),
        "element must expire"
    );
}

#[test]
fn static_element_timeouts() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "tmo", datatype::IPADDR, 4).with_flags(NFT_SET_TIMEOUT));
    b.add_elems(
        &SetElemList::new(F, "t", "tmo")
            .with(SetElem::new(vec![127, 0, 0, 8]).with_timeout(Duration::from_secs(1)))
            .with(
                SetElem::new(vec![127, 0, 0, 9])
                    .with_timeout(Duration::from_secs(3600))
                    .with_comment("long"),
            ),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .in_set("tmo", &[Field::IpDaddr])
            .counter()
            .comment("hit")
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::new(127, 0, 0, 8), 5004, 1);
    assert_eq!(counter_of(&mut s, "out", "hit"), 1);
    assert!(ruleset().contains("127.0.0.9 timeout 1h expires"));
    std::thread::sleep(Duration::from_millis(1500));
    send_udp(Ipv4Addr::new(127, 0, 0, 8), 5004, 1);
    assert_eq!(
        counter_of(&mut s, "out", "hit"),
        1,
        "expired element no longer matches"
    );
    let e = s.list_elems(F, "t", "tmo").unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].comment(), Some("long"));
}

#[test]
fn connlimit_rejects_extra_connections() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::TcpDport, 6000u16)
            .ct_state(NF_CT_STATE_NEW_BIT)
            .connlimit(2, true)
            .counter()
            .comment("over")
            .reject_tcp_reset()
            .build(),
    );
    s.commit(&b).unwrap();
    let l = TcpListener::bind("127.0.0.1:6000").unwrap();
    let c1 = TcpStream::connect("127.0.0.1:6000").unwrap();
    let c2 = TcpStream::connect("127.0.0.1:6000").unwrap();
    let r3 = TcpStream::connect_timeout(&"127.0.0.1:6000".parse().unwrap(), Duration::from_secs(2));
    assert!(r3.is_err(), "third connection must be rejected");
    assert_eq!(counter_of(&mut s, "out", "over"), 1);
    drop((c1, c2, l));
}

#[test]
fn counters_read_and_reset() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    b.add_obj(&Obj::new(
        F,
        "t",
        "named",
        ObjKind::Counter(Counter::default()),
    ));
    b.add_obj(&Obj::new(
        F,
        "t",
        "q",
        ObjKind::Quota(Quota {
            bytes: 1_000_000,
            flags: 0,
            consumed: None,
        }),
    ));
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5005u16)
            .counter()
            .counter_named("named")
            .comment("c")
            .build(),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5005u16)
            .expr(Objref {
                imm_type: Some(ObjType::Quota),
                imm_name: Some("q".into()),
                ..Default::default()
            })
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::LOCALHOST, 5005, 7);

    let rules = s.list_rules(F, Some("t"), Some("out")).unwrap();
    let c = rules[0].counters().next().unwrap();
    assert_eq!(c.packets, 7);
    assert_eq!(c.bytes, 7 * (20 + 8 + 10));

    // Atomic read + reset.
    let rules = s.list_rules_reset(F, Some("t"), Some("out")).unwrap();
    assert!(!rules.interrupted);
    assert_eq!(rules.items[0].counters().next().unwrap().packets, 7);
    assert_eq!(counter_of(&mut s, "out", "c"), 0);

    match s.get_obj(F, "t", "named", ObjType::Counter).unwrap().kind {
        ObjKind::Counter(c) => assert_eq!((c.packets, c.bytes), (7, 7 * 38)),
        k => panic!("{k:?}"),
    }
    match s.reset_obj(F, "t", "named", ObjType::Counter).unwrap().kind {
        ObjKind::Counter(c) => assert_eq!(c.packets, 7),
        k => panic!("{k:?}"),
    }
    match s.get_obj(F, "t", "named", ObjType::Counter).unwrap().kind {
        ObjKind::Counter(c) => assert_eq!(c.packets, 0),
        k => panic!("{k:?}"),
    }
    match s.get_obj(F, "t", "q", ObjType::Quota).unwrap().kind {
        ObjKind::Quota(q) => assert_eq!(q.consumed, Some(7 * 38)),
        k => panic!("{k:?}"),
    }
    let objs = s.list_objs(F, Some("t"), None).unwrap();
    assert_eq!(objs.len(), 2);
    let objs = s
        .list_objs_reset(F, Some("t"), Some(ObjType::Quota))
        .unwrap();
    assert_eq!(objs.items.len(), 1);
    match s.get_obj(F, "t", "q", ObjType::Quota).unwrap().kind {
        ObjKind::Quota(q) => assert_eq!(q.consumed.unwrap_or(0), 0),
        k => panic!("{k:?}"),
    }
}

#[test]
fn set_element_counters_and_meters() {
    netns();
    let mut s = Socket::new().unwrap();
    base(&mut s);
    let mut b = Batch::new();
    // A set whose elements each carry a counter.
    let mut set = Set::new(F, "t", "ctr", datatype::IPADDR, 4).with_flags(NFT_SET_EXPR);
    set.exprs.push(Counter::default().into());
    b.add_set(&set);
    b.add_elems(
        &SetElemList::new(F, "t", "ctr")
            .with(SetElem::new(vec![127, 0, 0, 2]).with_expr(Counter::default()))
            .with(SetElem::new(vec![127, 0, 0, 3]).with_expr(Counter::default())),
    );
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5006u16)
            .in_set("ctr", &[Field::IpDaddr])
            .build(),
    );
    // A meter: per-destination rate limit, elements created by dynset.
    b.add_set(&Set::new(F, "t", "m", datatype::IPADDR, 4).with_flags(NFT_SET_EVAL));
    b.add_rule(
        &RuleBuilder::new(F, "t", "out")
            .match_eq(Field::UdpDport, 5007u16)
            .dynset(
                DynsetOp::Update,
                "m",
                &[Field::IpDaddr],
                None,
                vec![limit_expr(2, Duration::from_secs(60), 2, LimitType::Packets, true).into()],
            )
            .counter()
            .comment("over")
            .build(),
    );
    s.commit(&b).unwrap();
    send_udp(Ipv4Addr::new(127, 0, 0, 2), 5006, 3);
    send_udp(Ipv4Addr::new(127, 0, 0, 3), 5006, 1);
    let e = s.list_elems(F, "t", "ctr").unwrap();
    let count = |k: u8| -> u64 {
        let el = e
            .iter()
            .find(|x| x.key.as_deref() == Some(&[127, 0, 0, k][..]))
            .unwrap();
        match &el.exprs[0] {
            Expr::Counter(c) => c.packets,
            x => panic!("{x:?}"),
        }
    };
    assert_eq!((count(2), count(3)), (3, 1));

    // Element counters can be reset.
    if kernel_at_least(6, 5) {
        s.list_elems_reset(F, "t", "ctr").unwrap();
        let e = s.list_elems(F, "t", "ctr").unwrap();
        assert!(
            e.iter()
                .all(|x| matches!(&x.exprs[0], Expr::Counter(c) if c.packets == 0))
        );
    }

    send_udp(Ipv4Addr::new(127, 0, 0, 4), 5007, 10);
    send_udp(Ipv4Addr::new(127, 0, 0, 5), 5007, 1);
    // 127.0.0.4: 2 within burst, 8 over; 127.0.0.5: within.
    assert_eq!(counter_of(&mut s, "out", "over"), 8);
    assert_eq!(s.list_elems(F, "t", "m").unwrap().len(), 2);
}
