//! Our JSON (`nft -j`) output and input must match nft's.
#![cfg(feature = "json")]
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

/// Drop the metainfo item and time dependent values.
fn normalize(s: &str) -> String {
    let mut v: serde_json::Value =
        serde_json::from_str(s).unwrap_or_else(|e| panic!("bad JSON {e}: {s}"));
    if let Some(items) = v["nftables"].as_array_mut() {
        items.retain(|i| i.get("metainfo").is_none());
    }
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                if m.contains_key("expires") {
                    m.insert("expires".into(), 0.into());
                }
                m.values_mut().for_each(strip);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut v);
    // One item per line for readable diffs.
    let mut out = String::new();
    for i in v["nftables"].as_array().unwrap() {
        out.push_str(&crabtables::lang::json::to_string(i));
        out.push('\n');
    }
    out
}

fn check(script: &str) {
    setup();
    nft_script(script);
    let want = normalize(&nft(&["-j", "list", "ruleset"]));
    let mut s = Socket::new().unwrap();
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    let got = crabtables::lang::json::tables(
        &crabtables::lang::decompile::ruleset(&rs),
        &Default::default(),
    );
    let got = normalize(&got);
    if let Some(d) = diff(&want, &got) {
        panic!("JSON differs:\n{d}");
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

/// Loading nft's JSON listing with our JSON parser and compiler gives the
/// same ruleset as nft loading the script.
fn check_input(script: &str) {
    let script = script.to_owned();
    let (want_json, want) = std::thread::spawn({
        let script = script.clone();
        move || {
            setup();
            nft_script(&script);
            (
                nft(&["-j", "list", "ruleset"]),
                strip_expires(&nft(&["list", "ruleset"])),
            )
        }
    })
    .join()
    .unwrap();
    let got = std::thread::spawn(move || {
        setup();
        let cmds =
            crabtables::lang::json::parse(&want_json).unwrap_or_else(|e| panic!("parse: {e}"));
        let mut c = crabtables::lang::compile::Compiler::new();
        c.compile(&cmds).unwrap_or_else(|e| panic!("compile: {e}"));
        let (batch, _) = c.into_batch();
        Socket::new()
            .unwrap()
            .commit(&batch)
            .unwrap_or_else(|e| panic!("commit: {e}"));
        strip_expires(&nft(&["list", "ruleset"]))
    })
    .join()
    .unwrap();
    if let Some(d) = diff(&want, &got) {
        panic!("ruleset loaded from JSON differs:\n{d}");
    }
}

#[test]
fn input_corpus() {
    check_input(include_str!("data/corpus.nft"));
}

#[test]
fn input_corpus2() {
    check_input(include_str!("data/corpus2.nft"));
}

#[test]
fn input_types() {
    check_input(include_str!("data/types.nft"));
}

#[test]
fn input_objects() {
    check_input(include_str!("data/objects.nft"));
}

#[test]
fn input_sets_and_statements() {
    check_input(include_str!("data/sets.nft"));
}

#[test]
fn input_extra() {
    // nft's JSON does not represent typeof map data, interval map data
    // or flowtable counters: leave those out.
    let s: String = include_str!("data/extra.nft")
        .lines()
        .filter(|l| !l.contains("map tm") && !l.contains("map dm") && !l.contains("@tm"))
        .map(|l| l.replace("counter; }", "}") + "\n")
        .collect();
    check_input(&s);
}

#[test]
fn wiki() {
    check(include_str!("data/wiki.nft"));
}
