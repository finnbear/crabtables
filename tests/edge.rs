//! Edge cases and limits.
mod common;
use std::time::Duration;

use common::*;
use crabtables::sys::*;
use crabtables::*;

const F: Family = Family::Inet;

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
fn empty_batch_and_empty_rule() {
    let mut s = setup();
    let genid = s.get_gen().unwrap();
    let out = s.commit(&Batch::new()).unwrap();
    assert_eq!(out.genid, genid, "empty batch does not bump the generation");
    let mut b = Batch::new();
    b.add_rule(&Rule::new(F, "t", "c"));
    s.commit(&b).unwrap();
    let r = s.list_rules(F, Some("t"), Some("c")).unwrap();
    assert_eq!(r.len(), 1);
    assert!(r[0].exprs.is_empty());
}

#[test]
fn name_limits_and_unicode() {
    let mut s = setup();
    let long = "x".repeat(255);
    let mut b = Batch::new();
    b.add_chain(&Chain::new(F, "t", long.clone()));
    b.add_table(&Table::new(F, "tåble-ü"));
    s.commit(&b).unwrap();
    assert!(s.get_chain(F, "t", &long).is_ok());
    assert_eq!(s.get_table(F, "tåble-ü").unwrap().name, "tåble-ü");
    let mut b = Batch::new();
    b.add_chain(&Chain::new(F, "t", "x".repeat(256)));
    let e = s.commit(&b).unwrap_err();
    assert!(
        matches!(
            e.errno(),
            Some(libc::ENAMETOOLONG) | Some(libc::EINVAL) | Some(libc::ERANGE)
        ),
        "{e}"
    );

    // Interior NUL bytes are rejected before anything is sent.
    let mut b = Batch::new();
    b.add_chain(&Chain::new(F, "t", "a\0b"));
    assert!(matches!(s.commit(&b).unwrap_err(), Error::InvalidInput(_)));
}

#[test]
fn userdata_and_comment_limits() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(F, "t", "c")
            .comment(&"c".repeat(128))
            .build(),
    );
    s.commit(&b).unwrap();
    let mut r = Rule::new(F, "t", "c");
    r.userdata = Some(vec![0; 257]);
    let mut b = Batch::new();
    b.add_rule(&r);
    let e = s.commit(&b).unwrap_err();
    assert!(e.as_batch().is_some(), "{e}");
    assert!(ruleset().contains(&format!("comment \"{}\"", "c".repeat(128))));
}

#[test]
fn expression_limit() {
    let mut s = setup();
    // The kernel accepts at most 128 expressions per rule.
    let mut r = Rule::new(F, "t", "c");
    for _ in 0..200 {
        r.exprs.push(expr::Counter::default().into());
    }
    let mut b = Batch::new();
    b.add_rule(&r);
    let e = s.commit(&b).unwrap_err();
    assert_eq!(e.errno(), Some(libc::EINVAL), "{e}");
    r.exprs.truncate(128);
    let mut b = Batch::new();
    b.add_rule(&r);
    s.commit(&b).unwrap();
}

#[test]
fn key_length_limits() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "k64", datatype::INTEGER, 64));
    b.add_elems(&SetElemList::new(F, "t", "k64").with(SetElem::new(vec![7; 64])));
    s.commit(&b).unwrap();
    assert_eq!(
        s.list_elems(F, "t", "k64").unwrap()[0].key.as_deref(),
        Some(&[7u8; 64][..])
    );
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "k65", datatype::INTEGER, 65));
    assert!(s.commit(&b).is_err());
}

#[test]
fn overlapping_intervals_are_rejected() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "iv", datatype::IPADDR, 4).with_flags(NFT_SET_INTERVAL));
    let mut l = SetElemList::new(F, "t", "iv");
    l.elems
        .extend(SetElem::range(&[10, 0, 0, 0], &[10, 0, 0, 255], None).unwrap());
    b.add_elems(&l);
    s.commit(&b).unwrap();
    let mut b = Batch::new();
    let mut l = SetElemList::new(F, "t", "iv");
    l.elems
        .extend(SetElem::range(&[10, 0, 0, 100], &[10, 0, 1, 10], None).unwrap());
    b.add_elems(&l);
    let e = s.commit(&b).unwrap_err();
    assert!(
        e.as_batch().unwrap().errors[0]
            .location
            .as_ref()
            .unwrap()
            .elem_index
            .is_some(),
        "{e}"
    );
    // Ranges up to the maximum value need no end marker.
    let r = SetElem::range(&[255, 255, 255, 0], &[255, 255, 255, 255], None).unwrap();
    assert_eq!(r.len(), 1);
    assert!(SetElem::range(&[2], &[1], None).is_err());
    assert!(SetElem::range(&[1, 2], &[1], None).is_err());
}

#[test]
fn same_batch_references() {
    let mut s = setup();
    // A set created and used in the same batch, referenced by id.
    let mut b = Batch::new();
    let id = b.alloc_id();
    b.add_set(&Set::new(F, "t", "new", datatype::IPADDR, 4).with_id(id));
    let mut r = RuleBuilder::new(F, "t", "c")
        .in_set("new", &[Field::IpSaddr])
        .accept()
        .build();
    if let Some(Expr::Lookup(l)) = r.exprs.iter_mut().find(|e| matches!(e, Expr::Lookup(_))) {
        l.set_id = Some(id);
    }
    b.add_rule(&r);
    // A chain created and jumped to in the same batch.
    b.add_chain(&Chain::new(F, "t", "later"));
    b.add_rule(&RuleBuilder::new(F, "t", "c").jump("later").build());
    s.commit(&b).unwrap();

    // Deleting a set and using it in the same batch fails as a whole.
    let mut b = Batch::new();
    b.add_set(&Set::new(F, "t", "gone", datatype::IPADDR, 4));
    b.delete_set(F, "t", "gone");
    b.add_rule(
        &RuleBuilder::new(F, "t", "c")
            .in_set("gone", &[Field::IpSaddr])
            .build(),
    );
    let e = s.commit(&b).unwrap_err();
    assert_eq!(e.as_batch().unwrap().errors[0].index, Some(2), "{e}");
    assert!(s.get_set(F, "t", "gone").is_err());
}

#[test]
fn set_default_timeout_applies() {
    let mut s = setup();
    let mut b = Batch::new();
    b.add_set(
        &Set::new(F, "t", "s", datatype::IPADDR, 4)
            .with_timeout(Duration::from_secs(90))
            .with_size(10),
    );
    b.add_elems(&SetElemList::new(F, "t", "s").with(SetElem::new(vec![1, 1, 1, 1])));
    s.commit(&b).unwrap();
    let set = s.get_set(F, "t", "s").unwrap();
    assert_eq!(set.timeout, Some(Duration::from_secs(90)));
    assert_eq!(set.size, Some(10));
    let e = s.list_elems(F, "t", "s").unwrap();
    assert!(e[0].expiration.unwrap() <= Duration::from_secs(90));
    // Size limit: 10 elements max.
    let mut b = Batch::new();
    let mut l = SetElemList::new(F, "t", "s");
    for i in 0..10u32 {
        l.elems
            .push(SetElem::new((0x0200_0000 + i).to_be_bytes().to_vec()));
    }
    b.add_elems(&l);
    let e = s.commit(&b).unwrap_err();
    assert_eq!(e.errno(), Some(libc::ENFILE), "{e}");
}

#[test]
fn element_timeout_refresh() {
    let mut s = setup();
    let elem = |t: u64| SetElem::new(vec![1, 1, 1, 1]).with_timeout(Duration::from_secs(t));
    let mut b = Batch::new();
    b.add_set(&Set::keyed(F, "t", "s", &[Field::IpSaddr]).with_flags(NFT_SET_TIMEOUT));
    b.add_elems(&SetElemList::new(F, "t", "s").with(elem(3600)));
    s.commit(&b).unwrap();
    let exp = |s: &mut Socket| s.list_elems(F, "t", "s").unwrap()[0].expiration.unwrap();
    assert!(exp(&mut s) > Duration::from_secs(3500));
    // Re-adding updates the timeout (kernel 6.10+).
    if !kernel_at_least(6, 10) {
        return;
    }
    let mut b = Batch::new();
    b.add_elems(&SetElemList::new(F, "t", "s").with(elem(10)));
    s.commit(&b).unwrap();
    assert!(exp(&mut s) <= Duration::from_secs(10));
    // An explicit expiration is honoured.
    let mut b = Batch::new();
    b.add_elems(
        &SetElemList::new(F, "t", "s").with(elem(3600).with_expiration(Duration::from_secs(20))),
    );
    s.commit(&b).unwrap();
    let e = exp(&mut s);
    assert!(
        e <= Duration::from_secs(20) && e > Duration::from_secs(15),
        "{e:?}"
    );
    // create_elems refuses existing elements; delete + add in one batch replaces.
    let mut b = Batch::new();
    b.create_elems(&SetElemList::new(F, "t", "s").with(elem(5)));
    assert!(s.commit(&b).unwrap_err().is_exists());
    let mut b = Batch::new();
    b.delete_elems(&SetElemList::new(F, "t", "s").with(elem(5)));
    b.add_elems(&SetElemList::new(F, "t", "s").with(elem(30)));
    s.commit(&b).unwrap();
    assert!(exp(&mut s) <= Duration::from_secs(30));
}
