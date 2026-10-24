//! Compare crabtables with the nftables project's tools on the same work:
//! the same rulesets, given as nft syntax, loaded and listed by
//!
//! * crabtables' typed API (the same objects, built in code),
//! * crabtables' `lang` (in process: parse, compile, commit; list and print),
//! * libnftables (the nftables project's in-process API, loaded at run time),
//! * `nfcrt` and `nft` (one process per command).
//!
//! Prints a Markdown table of the medians of three runs. Run it in a
//! throwaway network namespace (it flushes the ruleset!), after building
//! `nfcrt`:
//!
//! ```sh
//! cargo build --release -p nfcrt
//! cargo build --release --features lang --example bench
//! sudo unshare -n target/release/examples/bench
//! ```
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crabtables::lang::{compile::Compiler, parse};
use crabtables::sys::NFT_SET_TIMEOUT;
use crabtables::*;

/// Set elements and rules in the bulk tests.
const ELEMS: u32 = 200_000;
const RULES: u16 = 20_000;
/// Single-rule transactions (in process; processes run fewer).
const TXNS: u16 = 1_000;
const PROC_TXNS: u16 = 200;

type CtxNew = unsafe extern "C" fn(u32) -> *mut c_void;
type CtxFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type RunCmd = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type GetOutput = unsafe extern "C" fn(*mut c_void) -> *const c_char;

/// libnftables, opened at run time.
struct LibNftables {
    ctx: *mut c_void,
    run: RunCmd,
    output: GetOutput,
}

impl LibNftables {
    fn open() -> Option<Self> {
        // SAFETY: dlopen/dlsym with NUL terminated names; every symbol is
        // checked to exist and has the C signature of libnftables' public
        // API (nftables/libnftables.h).
        unsafe {
            let lib = libc::dlopen(c"libnftables.so.1".as_ptr(), libc::RTLD_NOW);
            if lib.is_null() {
                return None;
            }
            let sym = |n: &CStr| Some(libc::dlsym(lib, n.as_ptr())).filter(|p| !p.is_null());
            let new = std::mem::transmute::<*mut c_void, CtxNew>(sym(c"nft_ctx_new")?);
            let buffer = std::mem::transmute::<*mut c_void, CtxFn>(sym(c"nft_ctx_buffer_output")?);
            let run = std::mem::transmute::<*mut c_void, RunCmd>(sym(c"nft_run_cmd_from_buffer")?);
            let output =
                std::mem::transmute::<*mut c_void, GetOutput>(sym(c"nft_ctx_get_output_buffer")?);
            let ctx = new(0);
            if ctx.is_null() || buffer(ctx) != 0 {
                return None;
            }
            Some(LibNftables { ctx, run, output })
        }
    }

    /// Run commands; the length of their output.
    fn run(&self, cmds: &str) -> usize {
        let c = CString::new(cmds).unwrap();
        // SAFETY: `ctx` is a live context and `c` a NUL terminated string.
        unsafe {
            assert_eq!(
                (self.run)(self.ctx, c.as_ptr()),
                0,
                "libnftables: {cmds:.60}"
            );
            CStr::from_ptr((self.output)(self.ctx)).to_bytes().len()
        }
    }
}

/// crabtables' in-process text API.
fn lang_run(s: &mut Socket, cmds: &str) {
    let cmds = parse::parse(cmds).unwrap();
    let mut c = Compiler::new();
    c.compile(&cmds).unwrap();
    s.commit(&c.into_batch().0).unwrap();
}

/// `list ruleset` with crabtables' in-process text API: the text length.
fn lang_list(s: &mut Socket) -> usize {
    let rs = s.list_ruleset(Family::Unspec).unwrap();
    crabtables::lang::list_ruleset(&rs, &Default::default()).len()
}

fn process(bin: &str, args: &[&str]) {
    let st = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "{bin} {args:?}");
}

fn flush(s: &mut Socket) {
    let mut b = Batch::new();
    b.flush_ruleset(Family::Unspec);
    s.commit(&b).unwrap();
}

fn time(f: impl FnOnce()) -> Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

fn fmt(d: Duration) -> String {
    if d >= Duration::from_secs(1) {
        format!("{:.2} s", d.as_secs_f64())
    } else if d >= Duration::from_millis(10) {
        format!("{:.0} ms", d.as_secs_f64() * 1e3)
    } else if d >= Duration::from_millis(1) {
        format!("{:.1} ms", d.as_secs_f64() * 1e3)
    } else {
        format!("{:.0} µs", d.as_secs_f64() * 1e6)
    }
}

/// `200 000`.
fn thousands(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// `nfcrt`: `$NFCRT`, or next to this example's directory.
fn nfcrt() -> String {
    std::env::var("NFCRT").unwrap_or_else(|_| {
        let exe = std::env::current_exe().unwrap();
        let dir: PathBuf = exe.parent().unwrap().parent().unwrap().into();
        dir.join("nfcrt").display().to_string()
    })
}

/// One run of every measurement.
fn run() -> Vec<(String, [Option<Duration>; 5])> {
    let mut s = Socket::new().unwrap();
    let lib = LibNftables::open();
    let nfcrt = nfcrt();
    let file = std::env::temp_dir().join("crabtables-bench.nft");
    let file = file.to_str().unwrap();
    flush(&mut s);

    let mut elems =
        String::from("table inet t {\n set s { type ipv4_addr; flags timeout; elements = {\n");
    for i in 0..ELEMS {
        elems.push_str(&format!("{} timeout 1h,\n", std::net::Ipv4Addr::from(i)));
    }
    elems.push_str("}; }; }\n");
    let mut rules = String::from("table inet t {\n chain c { type filter hook input priority 0;\n");
    for i in 0..RULES {
        rules.push_str(&format!("tcp dport {i} counter accept\n"));
    }
    rules.push_str("}; }\n");

    // Columns: typed API, lang, libnftables, nfcrt, nft.
    let mut table: Vec<(String, [Option<Duration>; 5])> = Vec::new();

    // ------------------------------------------------------------ elements
    let typed_elems = || {
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Inet, "t"));
        b.add_set(
            &Set::new(Family::Inet, "t", "s", datatype::IPADDR, 4).with_flags(NFT_SET_TIMEOUT),
        );
        let mut l = SetElemList::new(Family::Inet, "t", "s");
        for i in 0..ELEMS {
            l.elems.push(
                SetElem::new(i.to_be_bytes().to_vec()).with_timeout(Duration::from_secs(3600)),
            );
        }
        b.add_elems(&l);
        b
    };
    std::fs::write(file, &elems).unwrap();
    let mut load = [None; 5];
    load[0] = Some(time(|| {
        s.commit(&typed_elems()).unwrap();
    }));
    flush(&mut s);
    load[1] = Some(time(|| lang_run(&mut s, &elems)));
    flush(&mut s);
    if let Some(l) = &lib {
        load[2] = Some(time(|| {
            l.run(&elems);
        }));
        flush(&mut s);
    }
    load[3] = Some(time(|| process(&nfcrt, &["-f", file])));
    flush(&mut s);
    load[4] = Some(time(|| process("nft", &["-f", file])));
    table.push((format!("load {} set elements", thousands(ELEMS)), load));

    let list_set = "list set inet t s";
    let mut list = [None; 5];
    list[0] = Some(time(|| {
        assert_eq!(
            s.list_elems(Family::Inet, "t", "s").unwrap().len(),
            ELEMS as usize
        )
    }));
    list[1] = Some(time(|| {
        lang_list(&mut s);
    }));
    if let Some(l) = &lib {
        list[2] = Some(time(|| {
            l.run(list_set);
        }));
    }
    list[3] = Some(time(|| {
        process(&nfcrt, &list_set.split(' ').collect::<Vec<_>>())
    }));
    list[4] = Some(time(|| {
        process("nft", &list_set.split(' ').collect::<Vec<_>>())
    }));
    table.push((format!("list {} set elements", thousands(ELEMS)), list));
    flush(&mut s);

    // ------------------------------------------------------------ rules
    let typed_rules = || {
        let mut b = Batch::new();
        b.add_table(&Table::new(Family::Inet, "t"));
        b.add_chain(&Chain::new(Family::Inet, "t", "c").with_hook(
            ChainType::Filter,
            Hook::INPUT,
            0,
        ));
        for i in 0..RULES {
            b.add_rule(
                &RuleBuilder::new(Family::Inet, "t", "c")
                    .match_eq(Field::TcpDport, i)
                    .counter()
                    .accept()
                    .build(),
            );
        }
        b
    };
    std::fs::write(file, &rules).unwrap();
    let mut load = [None; 5];
    load[0] = Some(time(|| {
        s.commit(&typed_rules()).unwrap();
    }));
    flush(&mut s);
    load[1] = Some(time(|| lang_run(&mut s, &rules)));
    flush(&mut s);
    if let Some(l) = &lib {
        load[2] = Some(time(|| {
            l.run(&rules);
        }));
        flush(&mut s);
    }
    load[3] = Some(time(|| process(&nfcrt, &["-f", file])));
    flush(&mut s);
    load[4] = Some(time(|| process("nft", &["-f", file])));
    table.push((format!("load {} rules", thousands(RULES.into())), load));

    let mut list = [None; 5];
    list[0] = Some(time(|| {
        assert_eq!(
            s.list_ruleset(Family::Unspec).unwrap().rules.len(),
            RULES as usize
        )
    }));
    list[1] = Some(time(|| {
        lang_list(&mut s);
    }));
    if let Some(l) = &lib {
        list[2] = Some(time(|| {
            l.run("list ruleset");
        }));
    }
    list[3] = Some(time(|| process(&nfcrt, &["list", "ruleset"])));
    list[4] = Some(time(|| process("nft", &["list", "ruleset"])));
    table.push((format!("list {} rules", thousands(RULES.into())), list));
    flush(&mut s);

    // ------------------------------------------------------------ small transactions
    let setup = "add table inet t; add chain inet t c";
    let rule = |i: u16| format!("add rule inet t c tcp dport {i} accept");
    let per = |d: Duration, n: u16| d / u32::from(n);
    let mut txn = [None; 5];
    lang_run(&mut s, setup);
    txn[0] = Some(per(
        time(|| {
            for i in 0..TXNS {
                let mut b = Batch::new();
                b.add_rule(
                    &RuleBuilder::new(Family::Inet, "t", "c")
                        .match_eq(Field::TcpDport, i)
                        .accept()
                        .build(),
                );
                s.commit(&b).unwrap();
            }
        }),
        TXNS,
    ));
    flush(&mut s);
    lang_run(&mut s, setup);
    txn[1] = Some(per(
        time(|| {
            for i in 0..TXNS {
                lang_run(&mut s, &rule(i));
            }
        }),
        TXNS,
    ));
    flush(&mut s);
    if let Some(l) = &lib {
        l.run(setup);
        txn[2] = Some(per(
            time(|| {
                for i in 0..TXNS {
                    l.run(&rule(i));
                }
            }),
            TXNS,
        ));
        flush(&mut s);
    }
    for (col, bin) in [(3, nfcrt.as_str()), (4, "nft")] {
        lang_run(&mut s, setup);
        txn[col] = Some(per(
            time(|| {
                for i in 0..PROC_TXNS {
                    process(bin, &rule(i).split(' ').collect::<Vec<_>>());
                }
            }),
            PROC_TXNS,
        ));
        flush(&mut s);
    }
    table.push(("single-rule transaction".into(), txn));

    table
}

/// Runs of the benchmark; the median of each measurement is reported.
const RUNS: usize = 3;

fn main() {
    let runs: Vec<_> = (0..RUNS).map(|_| run()).collect();
    // (libnftables is part of the nftables release `nft` comes from.)
    let version = Command::new("nft").arg("--version").output().unwrap();
    println!("{}", String::from_utf8_lossy(&version.stdout).trim());
    println!();
    println!(
        "| operation | crabtables (typed) | crabtables (`lang`) | libnftables | `nfcrt` | `nft` |"
    );
    println!("|---|---:|---:|---:|---:|---:|");
    for (row, (what, _)) in runs[0].iter().enumerate() {
        let cells: Vec<String> = (0..5)
            .map(|col| {
                let mut v: Vec<Duration> = runs.iter().filter_map(|r| r[row].1[col]).collect();
                v.sort_unstable();
                v.get(v.len() / 2).map_or("–".into(), |d| fmt(*d))
            })
            .collect();
        println!("| {what} | {} |", cells.join(" | "));
    }
}
