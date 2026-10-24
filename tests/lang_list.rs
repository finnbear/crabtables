//! Our listing of rulesets loaded by `nft` must equal `nft list ruleset`.
#[path = "lang_common/mod.rs"]
mod common;
use common::*;
use crabtables::{Family, Socket};

fn check(script: &str) {
    netns();
    for d in ["d0", "d1", "eth0", "eth1"] {
        std::process::Command::new("ip")
            .args(["link", "add", d, "type", "dummy"])
            .status()
            .unwrap();
    }
    nft_script(script);
    let listing = nft(&["list", "ruleset"]);
    let want = strip_expires(&listing);
    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let got = strip_expires(&crabtables::lang::list_ruleset(&rs, &Default::default()));
    if let Some(d) = diff(&want, &got) {
        panic!("listing differs:\n{d}");
    }
    // Parsing the listing and printing it again gives the same text.
    let cmds = crabtables::lang::parse::parse(&listing)
        .unwrap_or_else(|e| panic!("parse: {}", e.render(&listing, Some("listing"))));
    let tables: Vec<_> = cmds
        .into_iter()
        .map(|c| match c {
            crabtables::lang::ast::Cmd::Table { table, .. } => table,
            c => panic!("unexpected {c:?}"),
        })
        .collect();
    let again = strip_expires(&crabtables::lang::print::tables(
        &tables,
        &Default::default(),
    ));
    if let Some(d) = diff(&want, &again) {
        panic!("reprinted parse differs:\n{d}");
    }
}

#[test]
fn corpus() {
    check(include_str!("data/corpus.nft"));
}

#[test]
fn corpus2() {
    check(include_str!("data/corpus2.nft"));
}

#[test]
fn types() {
    check(include_str!("data/types.nft"));
}

#[test]
fn objects() {
    check(include_str!("data/objects.nft"));
}

#[test]
fn sets_and_statements() {
    check(include_str!("data/sets.nft"));
}

#[test]
fn extra() {
    check(include_str!("data/extra.nft"));
}

#[test]
fn wiki() {
    check(include_str!("data/wiki.nft"));
}
