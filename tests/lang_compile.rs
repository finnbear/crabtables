//! Rulesets compiled by us must equal rulesets loaded by `nft`: same
//! bytecode (`nft --debug=netlink list ruleset`) and same listing.
#[path = "lang_common/mod.rs"]
mod common;
use common::*;
use crabtables::{Family, Socket};

fn setup() {
    netns();
    for d in ["d0", "d1", "eth0", "eth1"] {
        std::process::Command::new("ip")
            .args(["link", "add", d, "type", "dummy"])
            .status()
            .unwrap();
    }
}

/// Bytecode and listing of the ruleset, plus the kernel's set objects.
fn snapshot() -> (String, String, String) {
    // Element order of hash sets depends on a per-set random seed.
    let mut bytecode = String::new();
    let mut elems: Vec<&str> = Vec::new();
    let raw = strip_expires(&nft(&["--debug=netlink", "list", "ruleset"]));
    // Binding chains are numbered by a counter shared by all namespaces.
    let raw = {
        let mut out = String::new();
        let mut rest = raw.as_str();
        while let Some(i) = rest.find("__chain") {
            out.push_str(&rest[..i + 7]);
            rest = rest[i + 7..].trim_start_matches(|c: char| c.is_ascii_digit());
            out.push('N');
        }
        out.push_str(rest);
        out
    };
    for l in raw.lines() {
        if l.starts_with("\telement ") {
            elems.push(l);
            continue;
        }
        elems.sort();
        for e in elems.drain(..) {
            bytecode.push_str(e);
            bytecode.push('\n');
        }
        bytecode.push_str(l);
        bytecode.push('\n');
    }
    elems.sort();
    for e in elems.drain(..) {
        bytecode.push_str(e);
        bytecode.push('\n');
    }
    let listing = strip_expires(&nft(&["list", "ruleset"]));
    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let mut sets = String::new();
    for (set, _) in &rs.sets {
        let mut set = set.clone();
        set.handle = None;
        sets.push_str(&format!("{set:?}\n"));
    }
    (bytecode, listing, sets)
}

fn by_nft(script: &str) -> (String, String, String) {
    let script = script.to_owned();
    std::thread::spawn(move || {
        setup();
        nft_script(&script);
        snapshot()
    })
    .join()
    .unwrap()
}

fn by_us(script: &str) -> (String, String, String) {
    let script = script.to_owned();
    std::thread::spawn(move || {
        setup();
        let cmds = crabtables::lang::parse::parse(&script)
            .unwrap_or_else(|e| panic!("parse: {}", e.render(&script, Some("script"))));
        let mut c = crabtables::lang::compile::Compiler::new();
        c.compile(&cmds)
            .unwrap_or_else(|e| panic!("compile: {}", e.render(&script, Some("script"))));
        let (batch, sources) = c.into_batch();
        let mut s = Socket::new().unwrap();
        if let Err(e) = s.commit(&batch) {
            let mut msg = format!("commit: {e}\n");
            if let Some(b) = e.as_batch() {
                for m in &b.errors {
                    if let Some(src) = m.index.and_then(|i| sources.get(i)) {
                        let span = m
                            .location
                            .as_ref()
                            .and_then(|l| l.expr_index)
                            .and_then(|i| src.expr_spans.get(i))
                            .copied()
                            .unwrap_or(src.span);
                        msg.push_str(
                            &crabtables::lang::Error::at(m.to_string(), span)
                                .render(&script, Some("script")),
                        );
                    }
                }
            }
            panic!("{msg}");
        }
        snapshot()
    })
    .join()
    .unwrap()
}

/// Differences between two bytecode dumps, by rule / set block.
fn block_diff(want: &str, got: &str) -> String {
    fn blocks(s: &str) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for l in s.lines() {
            if !l.starts_with([' ', '\t']) || v.is_empty() {
                v.push(String::new());
            }
            let b = v.last_mut().unwrap();
            b.push_str(l);
            b.push('\n');
        }
        v
    }
    let (w, g) = (blocks(want), blocks(got));
    let mut out = String::new();
    let mut n = 0;
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (
            w.get(i).map_or("", String::as_str),
            g.get(i).map_or("", String::as_str),
        );
        if a != b {
            out.push_str(&format!("--- nft:\n{a}+++ ours:\n{b}\n"));
            n += 1;
            if n >= 6 {
                break;
            }
        }
    }
    out
}

fn check(script: &str) {
    let want = by_nft(script);
    if std::env::var_os("DUMP_NFT").is_some() {
        eprintln!("{}\n{}", want.0, want.2);
    }
    let got = by_us(script);
    if want.0 != got.0 {
        panic!("bytecode differs:\n{}", block_diff(&want.0, &got.0));
    }
    if let Some(d) = diff(&want.1, &got.1) {
        panic!("listing differs:\n{d}");
    }
    if let Some(d) = diff(&want.2, &got.2) {
        panic!("sets differ:\n{d}");
    }
}

#[test]
fn basic() {
    check(
        "table inet t {
  chain c {
    type filter hook input priority filter; policy accept;
    tcp dport 22 accept
    ct state new,established counter
    ct state established
    ct state == established
    ip saddr 10.0.0.0/8 drop
    ip saddr 10.16.0.0/12 drop
    tcp dport { 22, 80 }
    tcp dport { 22 }
    meta mark > 5
    tcp dport 1-1000
    ip ttl set 64
    tcp dport set 80
    ip saddr set 1.2.3.4
  }
}
",
    );
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
