//! Regression tests for problems reported against similar libraries
//! (rustables, mullvad/nftnl-rs, google/nftables), to make sure this crate
//! does not share them.
mod common;
use std::time::{Duration, Instant};

use common::*;
use crabtables::*;

fn table_chain(s: &mut Socket) {
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "c"));
    s.commit(&b).unwrap();
}

/// An empty batch must not hang (rustables #11).
#[test]
fn empty_batch() {
    netns();
    let mut s = Socket::new().unwrap();
    s.set_recv_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = Instant::now();
    s.commit(&Batch::new()).unwrap();
    s.check(&Batch::new()).unwrap();
    assert!(t.elapsed() < Duration::from_secs(1));
}

/// Many responses in one batch (errors for every operation, or echoes)
/// must not overflow the receive buffer and lose any (google #103, #235,
/// #350).
#[test]
fn many_responses() {
    netns();
    let mut s = Socket::new().unwrap();
    table_chain(&mut s);
    // 20 000 operations, each rejected.
    let mut b = Batch::new();
    for i in 0..20_000u16 {
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "nope")
                .match_eq(Field::TcpDport, i)
                .accept()
                .build(),
        );
    }
    let e = s.commit(&b).unwrap_err();
    let be = e.as_batch().unwrap();
    assert!(!be.responses_lost);
    assert_eq!(be.errors.len(), 20_000);
    assert_eq!(be.errors[19_999].index, Some(19_999));
    // 20 000 echoed rules.
    let mut b = Batch::new();
    b.set_echo(true);
    for i in 0..20_000u16 {
        b.add_rule(
            &RuleBuilder::new(Family::Inet, "t", "c")
                .match_eq(Field::TcpDport, i)
                .counter()
                .accept()
                .build(),
        );
    }
    let out = s.commit(&b).unwrap();
    assert!(!out.responses_lost);
    assert_eq!(out.rule_handles().count(), 20_000);
}

/// Flushing a set always empties it (google #305).
#[test]
fn flush_set_reliable() {
    netns();
    let mut s = Socket::new().unwrap();
    table_chain(&mut s);
    let mut b = Batch::new();
    b.add_set(&Set::keyed(Family::Inet, "t", "s", &[Field::IpSaddr]));
    s.commit(&b).unwrap();
    for round in 0..200u32 {
        let mut l = SetElemList::new(Family::Inet, "t", "s");
        for i in 0..100u32 {
            l.elems
                .push(SetElem::new((round << 8 | i).to_be_bytes().to_vec()));
        }
        let mut b = Batch::new();
        b.add_elems(&l);
        s.commit(&b).unwrap();
        let mut b = Batch::new();
        b.flush_set(Family::Inet, "t", "s");
        s.commit(&b).unwrap();
        assert!(
            s.list_elems(Family::Inet, "t", "s").unwrap().is_empty(),
            "round {round}"
        );
    }
}

/// An element of the wrong length is rejected, not silently dropped
/// (google #128).
#[test]
fn wrong_key_length_fails() {
    netns();
    let mut s = Socket::new().unwrap();
    table_chain(&mut s);
    let mut b = Batch::new();
    b.add_set(&Set::keyed(Family::Inet, "t", "s", &[Field::IpSaddr]));
    s.commit(&b).unwrap();
    let mut b = Batch::new();
    // An IPv6 address in an IPv4 set.
    b.add_elems(&SetElemList::new(Family::Inet, "t", "s").with(SetElem::new(vec![0; 16])));
    let e = s.commit(&b).unwrap_err();
    assert_eq!(e.errno(), Some(libc::EINVAL), "{e}");
    assert!(s.list_elems(Family::Inet, "t", "s").unwrap().is_empty());
}

/// Exact interface name matches stay exact (mullvad/nftnl-rs #81): the
/// name is NUL padded, so `br1` does not match `br10`.
#[test]
fn interface_name_is_exact() {
    netns();
    let mut s = Socket::new().unwrap();
    table_chain(&mut s);
    let mut b = Batch::new();
    b.add_rule(
        &RuleBuilder::new(Family::Inet, "t", "c")
            .match_eq(Field::IifName, "br1")
            .accept()
            .build(),
    );
    s.commit(&b).unwrap();
    let listing = nft(&["list", "chain", "inet", "t", "c"]);
    assert!(listing.contains("iifname \"br1\" accept"), "{listing}");
}

/// Sets and maps of every kind can be listed (rustables #8, google #171).
#[test]
fn list_sets_and_maps() {
    netns();
    nft_script(
        "table inet t {
            set a { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 } }
            set b { type ipv4_addr . inet_service; elements = { 1.2.3.4 . 80 } }
            set c { type ifname; flags interval; elements = { \"eth*\" } }
            map d { type ipv4_addr : verdict; elements = { 1.1.1.1 : drop } }
            map e { type ipv4_addr : ipv4_addr . inet_service; elements = { 1.1.1.1 : 2.2.2.2 . 80 } }
            map f { type ipv4_addr : counter; }
            set g { type ipv4_addr; flags dynamic, timeout; timeout 1m; counter; }
            map h { typeof ip saddr : meta mark; flags interval; elements = { 10.0.0.0/8 : 1 } }
        }",
    );
    let mut s = Socket::new().unwrap();
    let sets = s.list_sets(Family::Unspec, None).unwrap();
    assert_eq!(sets.len(), 8);
    for set in &sets {
        s.list_elems(set.family, &set.table, &set.name).unwrap();
    }
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    assert_eq!(rs.sets.len(), 8);
}

/// Async sockets in a multi-threaded runtime: commits work and sockets are
/// closed exactly once (rustables #12).
#[cfg(feature = "tokio")]
#[test]
fn async_multi_thread() {
    netns();
    // Worker threads are created now, in this network namespace.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for _ in 0..20 {
            let mut s = AsyncSocket::new().unwrap();
            let mut b = Batch::new();
            b.add_table(&Table::new(Family::Inet, "t"));
            b.add_chain(
                &Chain::new(Family::Inet, "t", "input")
                    .with_hook(ChainType::Filter, Hook::INPUT, 0)
                    .with_policy(Policy::Accept),
            );
            s.commit(&b).await.unwrap();
            drop(s);
            let m = AsyncMonitor::new().unwrap();
            drop(m);
        }
    });
    drop(rt);
}

/// Deleting an empty list of elements deletes nothing (without the element
/// list attribute, the kernel would flush the set).
#[test]
fn delete_no_elems() {
    netns();
    let mut s = Socket::new().unwrap();
    table_chain(&mut s);
    let mut b = Batch::new();
    b.add_set(&Set::keyed(Family::Inet, "t", "s", &[Field::IpSaddr]));
    b.add_elems(&SetElemList::new(Family::Inet, "t", "s").with(SetElem::new(vec![1, 2, 3, 4])));
    s.commit(&b).unwrap();
    let mut b = Batch::new();
    b.delete_elems(&SetElemList::new(Family::Inet, "t", "s"));
    let _ = s.commit(&b);
    assert_eq!(s.list_elems(Family::Inet, "t", "s").unwrap().len(), 1);
}
