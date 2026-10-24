//! Batch failures: atomicity and precise error locations.
mod common;
use common::*;
use crabtables::*;

fn setup() -> Socket {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "c"));
    b.add_set(&Set::new(Family::Inet, "t", "s", datatype::IPADDR, 4));
    s.commit(&b).unwrap();
    s
}

fn fail(s: &mut Socket, b: &Batch) -> BatchError {
    let before = ruleset();
    let e = s.commit(b).unwrap_err();
    assert_eq!(ruleset(), before, "failed batch must not change anything");
    match e {
        Error::Batch(b) => b,
        e => panic!("expected batch error, got {e}"),
    }
}

#[test]
fn missing_jump_target() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_chain(&Chain::new(Family::Inet, "t", "ok"));
    b.add_rule(&RuleBuilder::new(Family::Inet, "t", "c").counter().build());
    let idx = b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "c")
            .counter()
            .jump("nope")
            .build(),
    );
    let e = fail(&mut s, &b);
    assert_eq!(e.errors.len(), 1);
    let m = &e.errors[0];
    assert_eq!(m.index, Some(idx));
    assert_eq!(m.errno, libc::ENOENT);
    assert_eq!(m.operation, "add rule inet t c");
    let loc = m.location.as_ref().unwrap();
    assert_eq!(loc.expr_index, Some(1));
    assert_eq!(loc.expr_name.as_deref(), Some("immediate"));
    assert_eq!(loc.detail.as_deref(), Some("jump nope"));
    let text = e.to_string();
    assert!(
        text.contains("batch operation #2") && text.contains("jump nope"),
        "{text}"
    );
}

#[test]
fn missing_set() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "c")
            .in_set("nope", &[Field::IpSaddr])
            .accept()
            .build(),
    );
    let e = fail(&mut s, &b);
    let loc = e.errors[0].location.as_ref().unwrap();
    // meta nfproto, cmp, payload, lookup
    assert_eq!(loc.expr_index, Some(3));
    assert_eq!(loc.expr_name.as_deref(), Some("lookup"));
    assert_eq!(loc.detail.as_deref(), Some("set nope"));
}

#[test]
fn missing_chain_and_table() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(&RuleBuilder::new(Family::Inet, "t", "nope").accept().build());
    b.add_rule(&RuleBuilder::new(Family::Inet, "nope", "c").accept().build());
    let e = fail(&mut s, &b);
    assert_eq!(e.errors.len(), 2, "all failures are reported");
    assert_eq!(e.errors[0].index, Some(0));
    assert_eq!(
        e.errors[0].location.as_ref().unwrap().attr_path,
        vec!["NFTA_RULE_CHAIN"]
    );
    assert_eq!(e.errors[1].index, Some(1));
    assert_eq!(
        e.errors[1].location.as_ref().unwrap().attr_path,
        vec!["NFTA_RULE_TABLE"]
    );
}

#[test]
fn exists_and_not_found() {
    let mut s = setup();
    let mut b = Batch::new();
    b.create_table(&Table::new(Family::Inet, "t"));
    let e = s.commit(&b).unwrap_err();
    assert!(e.is_exists(), "{e}");
    // add_table on an existing table is fine.
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    s.commit(&b).unwrap();

    let mut b = Batch::new();
    b.delete_table(Family::Inet, "nope");
    assert!(s.commit(&b).unwrap_err().is_not_found());
    // destroy ignores missing objects (kernel 6.3+).
    let destroy = kernel_at_least(6, 3);
    let mut b = Batch::new();
    b.destroy_table(Family::Inet, "nope");
    b.destroy_chain(Family::Inet, "t", "nope");
    b.destroy_set(Family::Inet, "t", "nope");
    b.destroy_rule(Family::Inet, "t", "c", 999_999);
    b.destroy_elems(&SetElemList::new(Family::Inet, "t", "s").with(SetElem::new(vec![1, 1, 1, 1])));
    if destroy {
        s.commit(&b).unwrap();
    }

    assert!(
        s.get_table(Family::Inet, "nope")
            .unwrap_err()
            .is_not_found()
    );
    assert!(
        s.get_chain(Family::Inet, "t", "nope")
            .unwrap_err()
            .is_not_found()
    );
    assert!(
        s.get_set(Family::Inet, "t", "nope")
            .unwrap_err()
            .is_not_found()
    );
    assert!(
        s.list_elems(Family::Inet, "t", "nope")
            .unwrap_err()
            .is_not_found()
    );
    assert_eq!(s.get_table(Family::Inet, "t").unwrap().name, "t");
}

#[test]
fn element_errors_point_at_the_element() {
    let mut s = setup();
    // 20000 elements are split over several messages; the duplicate is
    // reported with its index in the list we passed.
    let mut b = Batch::new();
    let mut l = SetElemList::new(Family::Inet, "t", "s");
    for i in 0..20000u32 {
        l.elems
            .push(SetElem::new((0x0a00_0000 + i).to_be_bytes().to_vec()));
    }
    b.add_elems(&l);
    s.commit(&b).unwrap();

    let mut b = Batch::new();
    let mut l2 = SetElemList::new(Family::Inet, "t", "s");
    for i in 0..20000u32 {
        l2.elems
            .push(SetElem::new((0x0b00_0000 + i).to_be_bytes().to_vec()));
    }
    l2.elems[17123] = SetElem::new(0x0a00_0005u32.to_be_bytes().to_vec());
    let idx = b.create_elems(&l2);
    assert!(b.message_count() > 1);
    let e = fail(&mut s, &b);
    assert_eq!(e.errors.len(), 1, "{e}");
    let m = &e.errors[0];
    assert_eq!(m.index, Some(idx));
    assert_eq!(m.errno, libc::EEXIST);
    let loc = m.location.as_ref().unwrap();
    assert_eq!(loc.elem_index, Some(17123));
    assert_eq!(loc.detail.as_deref(), Some("key 0a000005"));
    assert_eq!(s.list_elems(Family::Inet, "t", "s").unwrap().len(), 20000);

    // Wrong key length.
    let mut b = Batch::new();
    b.add_elems(
        &SetElemList::new(Family::Inet, "t", "s")
            .with(SetElem::new(vec![1, 2, 3, 4]))
            .with(SetElem::new(vec![1, 2, 3])),
    );
    let e = fail(&mut s, &b);
    assert_eq!(e.errors[0].errno, libc::EINVAL);
    assert_eq!(e.errors[0].location.as_ref().unwrap().elem_index, Some(1));
}

#[test]
fn unknown_and_invalid_expressions() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(
        &Rule::new(Family::Inet, "t", "c")
            .with(expr::Counter::default())
            .with(expr::Unknown {
                name: "bogus".into(),
                data: vec![],
            }),
    );
    let e = fail(&mut s, &b);
    let loc = e.errors[0].location.as_ref().unwrap();
    assert_eq!(
        (loc.expr_index, loc.expr_name.as_deref()),
        (Some(1), Some("bogus"))
    );

    let mut b = Batch::new();
    b.add_rule(&Rule::new(Family::Inet, "t", "c").with(expr::Meta {
        dreg: Some(Reg(77)),
        key: MetaKey::Mark,
        sreg: None,
    }));
    let e = fail(&mut s, &b);
    assert_eq!(e.errors[0].errno, libc::ERANGE);
}

#[test]
fn generation_check() {
    let mut s = setup();
    let genid = s.get_gen().unwrap();
    let mut b = Batch::new().with_genid(genid.wrapping_add(1));
    b.add_table(&Table::new(Family::Inet, "z"));
    let e = s.commit(&b).unwrap_err();
    assert!(e.is_generation_mismatch(), "{e}");
    assert_eq!(e.as_batch().unwrap().errors[0].index, None);

    let mut b = Batch::new().with_genid(genid);
    b.add_table(&Table::new(Family::Inet, "z"));
    let out = s.commit(&b).unwrap();
    assert_eq!(out.genid, genid.wrapping_add(1));
}

#[test]
fn busy_chain() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_chain(&Chain::new(Family::Inet, "t", "d"));
    b.add_rule(&RuleBuilder::new(Family::Inet, "t", "c").jump("d").build());
    s.commit(&b).unwrap();
    let mut b = Batch::new();
    b.delete_chain(Family::Inet, "t", "d");
    let e = fail(&mut s, &b);
    assert_eq!(e.errors[0].errno, libc::EBUSY);
    assert_eq!(e.errors[0].operation, "delete chain inet t d");
}

#[test]
fn socket_survives_errors() {
    // After many failures the socket is still in sync.
    let mut s = setup();
    for _ in 0..50 {
        let mut b = Batch::new();
        b.add_rule(&RuleBuilder::new(Family::Inet, "t", "nope").accept().build());
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "c")
                .jump("nope")
                .build(),
        );
        assert_eq!(
            s.commit(&b).unwrap_err().as_batch().unwrap().errors.len(),
            2
        );
        assert!(s.get_table(Family::Inet, "nope").is_err());
        assert_eq!(s.list_chains(Family::Inet, Some("t")).unwrap().len(), 1);
    }
}

#[test]
fn every_error_of_a_huge_batch_is_reported() {
    let mut s = setup();
    let mut b = Batch::new();
    for i in 0..50_000u16 {
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "nope")
                .match_eq(Field::TcpDport, i)
                .accept()
                .build(),
        );
    }
    let e = fail(&mut s, &b);
    assert!(!e.responses_lost);
    assert_eq!(e.errors.len(), 50_000);
    assert!(
        e.errors
            .iter()
            .enumerate()
            .all(|(i, m)| m.index == Some(i) && m.errno == libc::ENOENT)
    );
}
