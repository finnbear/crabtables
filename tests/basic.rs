mod common;
use common::*;
use crabtables::*;

#[test]
fn create_table_chain_rule() {
    netns();
    let mut s = Socket::new().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(
        &Chain::new(Family::Inet, "t", "c")
            .with_hook(ChainType::Filter, Hook::INPUT, 0)
            .with_policy(Policy::Accept),
    );
    b.add_rule(&Rule::new(Family::Inet, "t", "c").with(expr::Counter::default()));
    let out = s.commit(&b).unwrap();
    assert!(out.genid > 0);
    let rs = ruleset();
    assert_contains_lines(
        &rs,
        "table inet t {\nchain c {\ntype filter hook input priority filter; policy accept;\ncounter packets 0 bytes 0\n}\n}",
    );

    let tables = s.list_tables(Family::Unspec).unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].name, "t");
    let chains = s.list_chains(Family::Inet, Some("t")).unwrap();
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].hook.as_ref().unwrap().hook, Hook::INPUT);
    let rules = s.list_rules(Family::Inet, Some("t"), Some("c")).unwrap();
    assert_eq!(rules.len(), 1);
    assert!(matches!(rules[0].exprs[0], Expr::Counter(_)));
    assert_eq!(s.get_gen().unwrap(), out.genid);
}

#[test]
fn check_is_a_dry_run() {
    netns();
    let mut s = Socket::new().unwrap();
    let gen0 = s.get_gen().unwrap();
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "t"));
    b.add_chain(&Chain::new(Family::Inet, "t", "c"));
    b.add_rule(&Rule::new(Family::Inet, "t", "c").with(expr::Counter::default()));
    s.check(&b).unwrap();
    assert!(s.list_tables(Family::Unspec).unwrap().is_empty());
    assert_eq!(s.get_gen().unwrap(), gen0);
    // Errors are reported as for a commit.
    let mut bad = Batch::new();
    bad.add_table(&Table::new(Family::Inet, "t"));
    bad.add_rule(&Rule::new(Family::Inet, "t", "nope").with(expr::Counter::default()));
    let e = s.check(&bad).unwrap_err();
    let be = e.as_batch().unwrap();
    assert_eq!(be.errors.len(), 1);
    assert_eq!(be.errors[0].index, Some(1));
    assert_eq!(be.errors[0].errno, libc::ENOENT);
    assert!(s.list_tables(Family::Unspec).unwrap().is_empty());
    // The socket remains usable.
    s.commit(&b).unwrap();
    assert_eq!(s.list_tables(Family::Unspec).unwrap().len(), 1);
}
