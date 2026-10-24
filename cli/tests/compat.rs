//! `nfcrt` must behave like `nft`: the same command sequences give the
//! same output, errors and exit status.
use std::process::Command;

fn netns() {
    // SAFETY: unshare has no memory safety preconditions.
    let r = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(r, 0, "unshare: {}", std::io::Error::last_os_error());
    for args in [
        &["link", "set", "lo", "up"][..],
        &["link", "add", "d0", "type", "dummy"],
        &["link", "add", "d1", "type", "dummy"],
        // Interface names used by the nftables wiki examples.
        &["link", "add", "eth0", "type", "dummy"],
        &["link", "add", "eth1", "type", "dummy"],
    ] {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }
}

/// Outputs of each command: (status, stdout, stderr).
type Outputs = Vec<(i32, String, String)>;

fn run_all(bin: &'static str, cmds: Vec<String>, files: Vec<(String, String)>) -> Outputs {
    std::thread::spawn(move || {
        netns();
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nfcrt-compat-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in &files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let mut out = Vec::new();
        for c in &cmds {
            let args = shell_words(c);
            let o = Command::new(bin)
                .args(&args)
                .current_dir(&dir)
                .output()
                .unwrap();
            out.push((
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
        out
    })
    .join()
    .unwrap()
}

/// Split a command line on spaces, honouring double quotes (kept, as nft
/// sees them when typed in a shell with single quotes around).
fn shell_words(s: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    v.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        v.push(cur);
    }
    v
}

fn compare(cmds: &[&str], files: &[(&str, &str)]) {
    let cmds: Vec<String> = cmds.iter().map(|s| s.to_string()).collect();
    let files: Vec<(String, String)> = files
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let want = run_all("nft", cmds.clone(), files.clone());
    let got = run_all(env!("CARGO_BIN_EXE_nfcrt"), cmds.clone(), files);
    // The JSON metainfo names the implementation.
    let norm = |o: &(i32, String, String)| {
        let mut out = o.1.clone();
        let tmp = |s: &str| {
            // Temporary directories differ.
            let mut r = String::new();
            let mut rest = s;
            while let Some(i) = rest.find("/nfcrt-compat-") {
                r.push_str(&rest[..i]);
                rest = rest[i..].trim_start_matches(|c: char| c != '/' || false);
                rest = &rest[1..];
                rest = rest.trim_start_matches(|c: char| c != '/');
                r.push_str("/DIR");
            }
            r.push_str(rest);
            r
        };
        while let Some(i) = out.find("{\"metainfo\": {") {
            let end = out[i..].find("}}").map_or(out.len(), |j| i + j + 2);
            out.replace_range(i..end, "META");
        }
        // `-e` reports the generation and the process.
        let out: String = out
            .lines()
            .filter(|l| !l.starts_with("# new generation"))
            .map(|l| format!("{l}\n"))
            .collect();
        // Expiry times run while the commands execute.
        let mut out2 = String::new();
        let mut rest = out.as_str();
        while let Some(i) = rest.find("expires") {
            out2.push_str(&rest[..i + 7]);
            rest = &rest[i + 7..];
            let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
            rest = &rest[end..];
        }
        out2.push_str(rest);
        // The kernel numbers anonymous chains with a global counter.
        let mut out3 = String::new();
        let mut rest = out2.as_str();
        while let Some(i) = rest.find("__chain") {
            out3.push_str(&rest[..i + 7]);
            rest = rest[i + 7..].trim_start_matches(|c: char| c.is_ascii_digit());
            out3.push('N');
        }
        out3.push_str(rest);
        let out2 = out3;
        // Elements of hash sets come from the kernel in random order.
        let mut lines: Vec<String> = out2.lines().map(str::to_owned).collect();
        let mut i = 0;
        while i < lines.len() {
            let j = (i..lines.len())
                .find(|&j| !lines[j].starts_with("\telement "))
                .unwrap_or(lines.len());
            lines[i..j].sort();
            i = j.max(i + 1);
        }
        let out2: String = lines.iter().map(|l| format!("{l}\n")).collect();
        // nft warns that it cannot express anonymous chains in JSON.
        let err: String = tmp(&o.2)
            .lines()
            .filter(|l| !l.starts_with("warning: stmt ops chain have no json callback"))
            .map(|l| format!("{l}\n"))
            .collect();
        (o.0, out2, err)
    };
    let mut failures = String::new();
    for (i, c) in cmds.iter().enumerate() {
        let (w, g) = (&norm(&want[i]), &norm(&got[i]));
        if w != g {
            failures.push_str(&format!("=== {c} (status {} / {})\n", w.0, g.0));
            for (name, a, b) in [("stdout", &w.1, &g.1), ("stderr", &w.2, &g.2)] {
                let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
                let mut n = 0;
                for i in 0..a.len().max(b.len()) {
                    let (x, y) = (a.get(i).copied(), b.get(i).copied());
                    if x != y && n < 8 {
                        failures.push_str(&format!(
                            "{name} line {i}:\n  nft:    {}\n  nfcrt:  {}\n",
                            x.unwrap_or("<none>"),
                            y.unwrap_or("<none>")
                        ));
                        n += 1;
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "differences:\n{failures}");
}

const RULESET: &str = "table inet f {
	counter c1 {
		packets 1 bytes 2
	}
	quota q1 {
		100 mbytes
	}
	set s {
		type ipv4_addr
		elements = { 1.1.1.1, 2.2.2.2 }
	}
	map m {
		type inet_service : verdict
		elements = { 22 : accept }
	}
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 22 counter accept
	}
	chain other {
		ip saddr @s drop
	}
}
table ip g {
	chain c {
		counter
	}
}
";

#[test]
fn listing() {
    compare(
        &[
            "-f ruleset.nft",
            "list ruleset",
            "list tables",
            "list tables ip",
            "list chains",
            "list sets",
            "list maps",
            "list counters",
            "list quotas",
            "list chain inet f input",
            "list set inet f s",
            "list map inet f m",
            "list counter inet f c1",
            "list table ip g",
            "list table g",
            "list ruleset ip",
            "list sets inet",
            "list counters table inet f",
            "-a list table inet f",
            "-t list ruleset",
            "-s list ruleset",
            "-n list ruleset",
            "list flowtables",
            "list chain inet f nope",
            "list table nope",
        ],
        &[("ruleset.nft", RULESET)],
    );
}

#[test]
fn commands() {
    compare(
        &[
            "add table ip t",
            "add chain ip t c { type filter hook input priority 0 ; }",
            "add rule ip t c tcp dport 22 accept",
            "insert rule ip t c udp dport 53 accept",
            "add rule ip t c counter comment 'x y'",
            "-a list ruleset",
            "add rule ip t c position 4 ip saddr 1.1.1.1 drop",
            "replace rule ip t c handle 3 tcp dport 23 accept",
            "delete rule ip t c handle 4",
            "-a list ruleset",
            "add set ip t s { type ipv4_addr; flags interval; }",
            "add element ip t s { 10.0.0.0/8, 192.168.1.1 }",
            "list set ip t s",
            "get element ip t s { 10.1.2.3 }",
            "delete element ip t s { 192.168.1.1 }",
            "list set ip t s",
            "flush set ip t s",
            "list set ip t s",
            "add map ip t m { type ipv4_addr : verdict; }",
            "add element ip t m { 1.2.3.4 : drop }",
            "add rule ip t c ip saddr vmap @m",
            "rename chain ip t c c2",
            "list chains",
            "flush chain ip t c2",
            "list table ip t",
            "add counter ip t cnt",
            "add quota ip t q { 10 mbytes }",
            "list counters",
            "reset counters",
            "delete counter ip t cnt",
            "flush table ip t",
            "list ruleset",
            "delete table ip t",
            "list ruleset",
            "-c add table ip x",
            "list ruleset",
            "flush ruleset",
            "list ruleset",
        ],
        &[],
    );
}

#[test]
fn errors() {
    compare(
        &[
            "add table ip t",
            "add chain ip t c",
            "add rule ip t nope accept",
            "add rule ip nope c accept",
            "delete table ip nope",
            "create table ip t",
            "add rule ip t c jump nowhere",
            "delete rule ip t c handle 99",
            "add rule ip t c foo",
            "-f bad.nft",
            "list ruleset",
        ],
        &[(
            "bad.nft",
            "table ip t {\n\tchain d {\n\t\tjump nowhere\n\t}\n}\n",
        )],
    );
}

const JSON_CMDS: &str = r#"{"nftables": [
{"add": {"table": {"family": "inet", "name": "j"}}},
{"add": {"chain": {"family": "inet", "table": "j", "name": "c", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}},
{"add": {"set": {"family": "inet", "table": "j", "name": "s", "type": "ipv4_addr", "flags": ["interval"], "elem": [{"prefix": {"addr": "10.0.0.0", "len": 8}}]}}},
{"add": {"rule": {"family": "inet", "table": "j", "chain": "c", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [22, 80]}}}, {"counter": null}, {"accept": null}]}}},
{"add": {"rule": {"family": "inet", "table": "j", "chain": "c", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@s"}}, {"drop": null}]}}},
{"add": {"element": {"family": "inet", "table": "j", "name": "s", "elem": ["192.168.1.1"]}}}
]}"#;

#[test]
fn json() {
    compare(
        &[
            "-f ruleset.nft",
            "-j list ruleset",
            "-j list tables",
            "-j list table inet f",
            "-j list chain inet f input",
            "-j list set inet f s",
            "-j list map inet f m",
            "-j list counters",
            "-j list chains",
            "-j list sets",
            "-j -s list ruleset",
            "-j -f cmds.json",
            "-j list table inet j",
            "list table inet j",
            "-j list ruleset",
        ],
        &[("ruleset.nft", RULESET), ("cmds.json", JSON_CMDS)],
    );
}

#[test]
fn corpora() {
    let files = [
        ("corpus.nft", include_str!("../../tests/data/corpus.nft")),
        ("corpus2.nft", include_str!("../../tests/data/corpus2.nft")),
        ("types.nft", include_str!("../../tests/data/types.nft")),
        ("objects.nft", include_str!("../../tests/data/objects.nft")),
        ("sets.nft", include_str!("../../tests/data/sets.nft")),
    ];
    for (name, _) in &files {
        let f = format!("-f {name}");
        let cmds = [
            f.as_str(),
            "-a list ruleset",
            "-n list ruleset",
            "-N list ruleset",
            "-S list ruleset",
            "-y list ruleset",
            "-p list ruleset",
            "-T list ruleset",
            "-u list ruleset",
            "-jn list ruleset",
            "-jS list ruleset",
            "-jNu list ruleset",
            "-j list ruleset",
            "-c -f ",
            "flush ruleset",
        ];
        let cmds: Vec<String> = cmds
            .iter()
            .map(|c| {
                if *c == "-c -f " {
                    format!("-c -f {name}")
                } else {
                    c.to_string()
                }
            })
            .collect();
        let cmds: Vec<&str> = cmds.iter().map(String::as_str).collect();
        compare(&cmds, &files);
    }
}

#[test]
fn debug_netlink_corpora() {
    let files = [
        ("corpus.nft", include_str!("../../tests/data/corpus.nft")),
        ("corpus2.nft", include_str!("../../tests/data/corpus2.nft")),
        ("types.nft", include_str!("../../tests/data/types.nft")),
        ("objects.nft", include_str!("../../tests/data/objects.nft")),
        ("sets.nft", include_str!("../../tests/data/sets.nft")),
        ("extra.nft", include_str!("../../tests/data/extra.nft")),
        ("wiki.nft", include_str!("../../tests/data/wiki.nft")),
    ];
    for (name, _) in &files {
        let f = format!("--debug=netlink -f {name}");
        let cmds = [f.as_str(), "--debug=netlink list ruleset", "flush ruleset"];
        compare(&cmds, &files);
    }
}

#[test]
fn includes() {
    compare(
        &[
            "-f missing.nft",
            "-f missing2.nft",
            "-f self.nft",
            "-f ib.nft",
            "include \"./bad.nft\"",
            "-f dirinc.nft",
            "-f sub/rel.nft",
            "-I sub -I dir -f search.nft",
            "-f wild.nft",
            "list ruleset",
        ],
        &[
            ("missing.nft", "include \"missing.nft\"\n"),
            (
                "missing2.nft",
                "add table ip m\ninclude \"./missing.nft.x\"\n",
            ),
            ("self.nft", "include \"./self.nft\"\n"),
            ("bad.nft", "add table ip q\nadd bogus\n"),
            ("ib.nft", "include \"./bad.nft\"\n"),
            ("dirinc.nft", "include \"./dir/\"\ninclude \"dir\"\n"),
            ("dir/b.nft", "add table ip b\n"),
            ("dir/.h.nft", "add table ip h\n"),
            ("dir/s.nft", "add table ip ds\n"),
            ("sub/rel.nft", "include \"o.nft\"\n"),
            ("sub/o.nft", "add table ip o\n"),
            ("sub/s.nft", "add table ip s\n"),
            ("search.nft", "include \"s.nft\"\ninclude \"b.nft\"\n"),
            (
                "wild.nft",
                "include \"./d?r/[a-c].nft\"\ninclude \"./*/o.nft\"\ninclude \"/nonexistent/*\"\n",
            ),
        ],
    );
}

#[test]
fn debug_netlink_commands() {
    compare(
        &[
            "-f ruleset.nft",
            "-d netlink list table inet f",
            "--debug netlink list chain inet f input",
            "--debug=netlink list set inet f s",
            "--debug=netlink list map inet f m",
            "--debug=netlink list counters",
            "--debug=netlink list tables",
            "--debug=netlink add element inet f s { 3.3.3.3, 4.4.4.4 }",
            "--debug=netlink delete element inet f s { 3.3.3.3 }",
            "--debug=netlink add set inet f t { type ipv4_addr; flags timeout; timeout 1m; }",
            "--debug=netlink insert rule inet f other position 0 counter",
            "--debug=netlink add counter inet f c2",
            "--debug=netlink add chain inet f c3",
            "--debug=netlink delete chain inet f c3",
            "--debug=netlink flush chain inet f other",
            "--debug=netlink add table ip x",
            "--debug=bogus list ruleset",
            "-c --debug=netlink add rule inet f other ip daddr 1.2.3.4 drop",
        ],
        &[("ruleset.nft", RULESET)],
    );
}

#[test]
fn echo_objects() {
    compare(
        &[
            "-e -f echo1.nft",
            "-ea add rule ip t c counter",
            "-e add element ip t s { 7.7.7.7 }",
            "-je add rule ip t c counter",
            "-je add set ip t s9 { type ipv4_addr; elements = { 1.2.3.4 }; }",
            "-je add chain ip t c9 { type filter hook output priority 0; }",
            "flush ruleset",
            "-ea -f echo2.nft",
            "-e add element inet t s { 2.0.0.0/8 . 80, 3.0.0.1 . 1 }",
            "flush ruleset",
            "-je -f echo1.nft",
            "flush ruleset",
            "-je -f echo2.nft",
        ],
        &[
            (
                "echo1.nft",
                "add table ip t\nadd table ip t2 { flags dormant; comment \"x\"; }\nadd chain ip t c { type filter hook input priority 0; policy drop; comment \"cc\"; }\nadd chain ip t r\nadd table netdev t3\nadd chain netdev t3 ing { type filter hook ingress device lo priority 0; }\nadd set ip t s { type ipv4_addr; flags interval,timeout; timeout 10s; size 100; elements = { 1.2.3.0/24, 5.5.5.5 } }\nadd element ip t s { 9.9.9.9 timeout 5s comment \"e\" }\nadd map ip t m { typeof ip saddr : verdict; }\nadd element ip t m { 1.1.1.1 : jump r }\nadd rule ip t c ip saddr { 1.1.1.1, 2.2.2.2 } counter accept comment \"rr\"\nadd rule ip t c ip saddr @s jump r\nadd counter ip t cnt { packets 5 bytes 6 }\nadd quota ip t q { 100 mbytes }\nadd limit ip t l { rate 10/second }\nadd ct helper ip t h { type \"ftp\" protocol tcp; }\nadd flowtable ip t f { hook ingress priority 0; devices = { lo }; }\nadd set ip t s3 { type ipv4_addr; }\n",
            ),
            (
                "echo2.nft",
                "add table inet t { comment \"tc\"; }\nadd ct timeout inet t to { protocol tcp; l3proto ip; policy = { established: 100, close: 4 }; }\nadd ct expectation inet t ex { protocol tcp; dport 5000; timeout 1h; size 12; l3proto ip; }\nadd synproxy inet t sp { mss 1460; wscale 7; timestamp sack-perm; }\nadd set inet t s { type ipv4_addr . inet_service; flags interval; counter; auto-merge; comment \"sc\"; policy memory; elements = { 1.0.0.0/8 . 22-25 } }\nadd map inet t m { typeof ip saddr : meta mark; elements = { 1.1.1.1 : 0x1 } }\nadd flowtable inet t f { hook ingress priority 10; devices = { lo }; counter; }\nadd chain inet t c { comment \"cc\"; }\nadd chain inet t b { type filter hook input priority -5; }\nadd counter inet t cn { comment \"x\"; packets 1 bytes 2; }\nadd quota inet t q { over 10 mbytes used 1 mbytes; }\nadd limit inet t l { rate over 10 mbytes/second burst 5 mbytes; }\nadd set inet t dyn { type ipv4_addr; flags dynamic,timeout; size 10; }\nadd element inet t dyn { 3.3.3.3 }\nadd rule inet t c ip saddr @dyn tcp dport { 22-25, 80 } ct state { new, established } counter\nadd map inet t vm { type inet_service : verdict; elements = { 22 : jump c, 80 : drop } }\n",
            ),
        ],
    );
}

#[test]
fn echo_define_include() {
    compare(
        &[
            "add table ip t",
            "-e add chain ip t c",
            "-e add rule ip t c tcp dport 22 accept",
            "-e -a add rule ip t c counter",
            "-D port=80 -f vars.nft",
            "-f inc.nft",
            "list ruleset",
        ],
        &[
            (
                "vars.nft",
                "define nets = { 10.0.0.0/8, 192.168.0.0/16 }\nadd rule ip t c ip saddr $nets tcp dport $port accept\n",
            ),
            (
                "inc.nft",
                "include \"vars2.nft\"\nadd rule ip t c ip daddr $x drop\n",
            ),
            ("vars2.nft", "define x = 1.2.3.4\n"),
        ],
    );
}

#[test]
fn syntax_errors() {
    compare(
        &[
            "add table ip t",
            "add chain ip t c",
            "add rule ip t c tcp dport",
            "add rule ip t c tcp dport 99999 accept",
            "add rule ip t c meta nosuch 1",
            "add rule ip t c counter packets",
            "add rule ip t c accept accept",
            // Implicit `add rule`.
            "add t c tcp dport 22 accept",
            "add ip t c counter",
            "insert ip t c counter",
            "add bogus",
            "add ip",
            "add table",
            "add table ip",
            "add table {",
            "delete table",
            "list table",
            "delete chain ip t",
            "list chain ip t",
            "delete rule ip t",
            "delete rule ip t c",
            "delete rule ip t c 5",
            "delete set ip t",
            "reset counter ip t",
            "destroy chain ip t",
            "list table ip",
            "monitor bogus",
            "monitor new bogus",
            "monitor destroy rules json",
            "monitor counters",
            "monitor new rules vm",
            "-f bad1.nft",
            "-f bad2.nft",
            "list ruleset",
        ],
        &[
            (
                "bad1.nft",
                "table ip t {\n\tchain c {\n\t\ttcp dport { 22, }\n\t}\n",
            ),
            (
                "bad2.nft",
                "table ip t {\n\tchain c {\n\t\tip daddr 300.1.1.1 drop\n\t}\n}\n",
            ),
        ],
    );
}

#[test]
fn reset_element() {
    compare(
        &[
            "add table ip t",
            "add set ip t s { type ipv4_addr ; counter ; elements = { 1.1.1.1 counter packets 5 bytes 10, 2.2.2.2 } }",
            "add set ip t i { type ipv4_addr ; flags interval ; counter ; elements = { 10.0.0.0/8 counter packets 3 bytes 4 } }",
            "add set ip t q { type ipv4_addr ; quota 10 mbytes ; elements = { 1.1.1.1 } }",
            "reset element ip t s { 1.1.1.1 }",
            "list set ip t s",
            "get element ip t s { 1.1.1.1, 2.2.2.2 }",
            "reset element ip t i { 10.1.2.3 }",
            "list set ip t i",
            "reset element ip t q { 1.1.1.1 }",
            "list set ip t q",
            "reset element ip t s { 9.9.9.9 }",
            "reset element ip t nope { 1.1.1.1 }",
            "reset element ip t s { 1.1.1.1, 2.2.2.2 }",
        ],
        &[],
    );
}

// ---------------------------------------------------------------------
// Every example of the nftables wiki's "Basic operation" and "Advanced
// data structures" pages (wiki.nftables.org), run through both tools.

#[test]
fn wiki_tables_chains_rules() {
    compare(
        &[
            // Configuring tables
            "add table ip filter",
            "list tables",
            "delete table ip foo",
            "flush table ip filter",
            // Configuring chains
            "add chain ip filter input { type filter hook input priority 0; }",
            "add chain ip filter output { type filter hook output priority 0; }",
            "add chain ip filter output { type filter hook output priority 0; policy accept; }",
            "add table netdev filter",
            "add chain netdev filter eth0_filter { type filter hook ingress device eth0 priority 0; }",
            "list ruleset",
            "-f prio.nft",
            "list table ip filter",
            // Simple rule management
            "add rule filter output ip daddr 8.8.8.8 counter",
            "add rule filter output tcp dport ssh counter",
            "list table filter",
            "list chain filter output",
            "-nn list table filter",
            "-n -a list table filter",
            "add rule filter output position 2 ip daddr 127.0.0.8 drop",
            "insert rule filter output position 2 ip daddr 127.0.0.8 drop",
            "-n -a list table filter",
            "delete rule filter output handle 3",
            "flush chain filter output",
            "flush table filter",
            "insert rule filter output ip daddr 192.168.1.1 counter",
            "-a list ruleset",
            "replace rule filter output handle 9 counter",
            "list ruleset",
            "delete chain ip filter input",
            "add rule filter input tcp dport ssh counter",
            "delete chain ip filter input",
            // Error reporting
            "add rule filter input tcp dport 1.1.1.1 counter drop",
            "add rule nosuch input tcp dport 1.1.1.1 counter drop",
            "add rule filter input tcp dport @nosuch",
            "add rule nosuch input tcp dport @nosuch",
            "add rule filter input tcp dport",
            // Building rules through expressions
            "add rule filter input tcp dport != 22",
            "add rule filter input tcp dport >= 1024",
            "add rule filter input tcp dport eq 22",
            "add rule filter input tcp dport ne 22",
            "add rule filter input tcp dport lt 22",
            "add rule filter input tcp dport gt 22",
            "add rule filter input tcp dport le 22",
            "add rule filter input tcp dport ge 22",
            "list chain filter input",
            // Operations at ruleset level
            "list ruleset arp",
            "list ruleset ip",
            "list ruleset ip6",
            "list ruleset bridge",
            "list ruleset inet",
            "list ruleset netdev",
            "--json list ruleset",
            "flush ruleset arp",
            "flush ruleset ip6",
            "flush ruleset bridge",
            "flush ruleset inet",
            "flush ruleset netdev",
            "list ruleset",
            "flush ruleset ip",
            "flush ruleset",
            "list ruleset",
        ],
        &[(
            "prio.nft",
            "table ip filter {
        # This chain is evaluated first due to priority
        chain services {
                type filter hook input priority 0; policy accept;

                # If matched, this rule will prevent any further evaluation
                tcp dport http drop

                # If matched, and despite the accept verdict, the packet proceeds to enter the chain below
                tcp dport ssh accept

                # Likewise for any packets that get this far and hit the default policy
        }

        # This chain is evaluated last due to priority
        chain input {
                type filter hook input priority 1; policy drop;
                # All ingress packets end up being dropped here!
        }
}
",
        )],
    );
}

#[test]
fn wiki_scripting() {
    compare(
        &[
            "-f comments.nft",
            "-f google.nft",
            "-f ntp.nft",
            "-f natformat.nft",
            "-f incl.nft",
            "-I incdir -f incl2.nft",
            "-f cdn.nft",
            "list ruleset",
            "-f backup.nft",
            "list ruleset",
            "-s list ruleset",
        ],
        &[
            (
                "comments.nft",
                "#!/usr/sbin/nft -f

#
# table declaration
#
add table filter

#
# chain declaration
#
add chain filter input { type filter hook input priority 0; policy drop; }

#
# rule declaration
#
add rule filter input ct state established,related counter accept
",
            ),
            (
                "google.nft",
                "#!/usr/sbin/nft -f

define google_dns = 8.8.8.8

add table filter
add chain filter input { type filter hook input priority 0; }
add rule filter input ip saddr $google_dns counter
",
            ),
            (
                "ntp.nft",
                "#!/usr/sbin/nft -f

define ntp_servers = { 84.77.40.132, 176.31.53.99, 81.19.96.148, 138.100.62.8 }

add table filter
add chain filter input { type filter hook input priority 0; }
add rule filter input ip saddr $ntp_servers counter
",
            ),
            (
                "natformat.nft",
                "#!/usr/sbin/nft -f

define ntp_servers = { 84.77.40.132, 176.31.53.99, 81.19.96.148, 138.100.62.8 }

#flush table nat
table ip nat {
	chain prerouting {
		type filter hook prerouting priority 0; policy accept;
                ip saddr $ntp_servers counter
	}

	chain postrouting {
		type filter hook postrouting priority 100; policy accept;
	}
}
",
            ),
            (
                "incl.nft",
                "include \"./parts/*.nft\"\ninclude \"./nothing/*\"\ninclude \"./parts/b.rules\"\n",
            ),
            ("parts/a.nft", "add table ip inc_a\n"),
            ("parts/c.nft", "add table ip inc_c\n"),
            ("parts/.hidden.nft", "add table ip hidden\n"),
            ("parts/b.rules", "add table ip inc_b\n"),
            ("incl2.nft", "include \"x.nft\"\n"),
            ("incdir/x.nft", "add table ip inc_x\n"),
            (
                "cdn.nft",
                "define SIMPLE_SET = { 192.168.1.1, 192.168.1.2 }

define CDN_EDGE = {
    192.168.1.1,
    192.168.1.2,
    192.168.1.3,
    10.0.0.0/8
}

define CDN_MONITORS = {
    192.168.1.10,
    192.168.1.20
}

define CDN = {
    $CDN_EDGE,
    $CDN_MONITORS
}

table inet cdn {
	chain c {
		# Allow HTTP(S) from approved IP ranges only
		tcp dport { http, https } ip saddr $CDN accept
		udp dport { http, https } ip saddr $CDN accept
		ip saddr $SIMPLE_SET drop
	}
}
",
            ),
            (
                "backup.nft",
                "flush ruleset\ntable ip b {\n\tchain c {\n\t\tcounter\n\t}\n}\n",
            ),
        ],
    );
}

#[test]
fn wiki_debug() {
    compare(
        &[
            "-f trace.nft",
            "add chain ip filter trace_chain { type filter hook prerouting priority -1; }",
            "add rule ip filter trace_chain meta nftrace set 1",
            "add rule ip filter trace_chain ip protocol tcp meta nftrace set 1",
            "add chain ip filter trace_chain2 { type filter hook prerouting priority -301; }",
            "list ruleset",
            "delete chain ip filter trace_chain2",
            "add table inet t",
            "add chain inet t c",
            "--debug=netlink add rule inet t c ip daddr 10.1.2.3 counter accept",
            "add table ip t",
            "add chain ip t c",
            "add rule ip t c tcp dport set tcp sport",
            "add rule ip t c ip dscp set 42",
            "list ruleset",
        ],
        &[(
            "trace.nft",
            "table ip filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related counter packets 2 bytes 292 accept
                ct state new tcp dport 22 counter packets 0 bytes 0 accept
        }
}
",
        )],
    );
}

#[test]
fn wiki_output_modifiers() {
    compare(
        &[
            "-f out.nft",
            "list ruleset",
            "-n list ruleset",
            "-nn list ruleset",
            "-N list ruleset",
            "-S list ruleset",
            "-y list ruleset",
            "-p list ruleset",
            "-T list ruleset",
            "-u list ruleset",
            "-nSy list ruleset",
            "-sta list ruleset",
            "-j list ruleset",
        ],
        &[(
            "out.nft",
            "table inet filter {
	set s {
		type inet_service
		elements = { 80, 443 }
	}

	chain input {
		type filter hook input priority filter; policy accept;
		counter packets 4447 bytes 1619415
		iif \"lo\" counter packets 337 bytes 25076 accept
		ct state established,related counter packets 44899 bytes 106405802 accept
		ip6 nexthdr ipv6-icmp icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } counter packets 1 bytes 72 accept
		tcp dport 22 drop
		ip saddr 127.0.0.1 drop
		meta skuid 0 accept
		ct expiration 1m accept
		ip protocol tcp accept
	}
}
",
        )],
    );
}

#[test]
fn wiki_intervals_concat_math() {
    compare(
        &[
            "add table ip filter",
            "add chain ip filter input",
            "add chain ip filter forward",
            "add chain ip filter chain-dmz",
            "add chain ip filter chain-desktop",
            "add rule filter input ip daddr 192.168.0.1-192.168.0.250 drop",
            "add rule filter input tcp ports 1-1024 drop",
            "add rule ip filter input ip saddr { 192.168.1.1-192.168.1.200, 192.168.2.1-192.168.2.200 } drop",
            "add rule ip filter forward ip daddr vmap { 192.168.1.1-192.168.1.200 : jump chain-dmz, 192.168.2.1-192.168.20.250 : jump chain-desktop }",
            "add rule ip filter input ip saddr . ip daddr . ip protocol { 1.1.1.1 . 2.2.2.2 . tcp, 1.1.1.1 . 3.3.3.3 . udp} counter accept",
            "add map filter whitelist { type ipv4_addr . inet_service : verdict ; }",
            "add rule filter input ip saddr . tcp dport vmap @whitelist",
            "add element filter whitelist { 1.2.3.4 . 22 : accept}",
            "add table ip nat",
            "add chain ip nat prerouting { type nat hook prerouting priority -100; }",
            "add rule ip nat prerouting dnat to ip saddr . tcp dport map { 1.1.1.1 . 80 : 192.168.1.100, 2.2.2.2 . 8888 : 192.168.1.101 }",
            "add rule filter input ip saddr and 255.255.255.0 . ip daddr and 255.255.255.0 vmap { 10.10.10.0 . 10.10.20.0 : accept }",
            "add map filter myMap { type ipv4_addr . ipv4_addr : verdict ; }",
            "add rule filter input ip saddr and 255.255.255.0 . ip saddr and 255.255.255.0 vmap @myMap",
            "add element filter myMap { 10.10.10.0 . 10.10.20.0 : accept }",
            "add rule filter forward iif . oif vmap { eth0 . eth1 : accept }",
            "-f concat.nft",
            "-f math.nft",
            "list ruleset",
            "-j list ruleset",
        ],
        &[
            (
                "concat.nft",
                "table inet fmytable {
	set myset {
		typeof ip daddr . tcp dport
		counter
		elements = { 1.1.1.4 . 22 counter packets 0 bytes 0,
			     1.1.1.5 . 23 counter packets 0 bytes 0,
			     1.1.1.6 . 24 counter packets 0 bytes 0 }
	}
}
table inet mytable {
    set myset {
        type ipv4_addr . ipv4_addr
        flags interval
        elements = { 192.168.0.0/16 . 172.16.0.0/25,
                     10.0.0.0/30 . 192.168.1.0/24,
        }
    }

    chain mychain {
        ip saddr . ip daddr @myset counter accept
    }
}
",
            ),
            (
                "math.nft",
                "table ip t {
	chain c {
		mark set numgen inc mod 4 offset 3
		mark set numgen random mod 50 offset 20
		mark set numgen inc mod 100
	}
}
table ip t2 {
	chain c {
		mark set jhash ip saddr mod 2
		mark set jhash ip saddr . tcp dport mod 2
		mark set jhash ip saddr . tcp dport . iiftype mod 2
	}
}
",
            ),
        ],
    );
}

#[test]
fn wiki_stateful_objects() {
    compare(
        &[
            "add table filter",
            "add counter filter https-traffic",
            "add quota filter https-quota 25 mbytes",
            "add chain filter output { type filter hook output priority 0 ; }",
            "add rule filter output tcp dport https counter name https-traffic",
            "add counter filter http-traffic",
            "add counter filter foo-counter",
            "add rule filter output counter name tcp dport map { https : \"https-traffic\", 80 : \"http-traffic\", 25 : \"foo-counter\", 50 : \"foo-counter\", 107 : \"foo-counter\" }",
            "add map filter ports { type inet_service : quota ; }",
            "add rule filter output quota name tcp dport map @ports",
            "add quota filter http-quota over 25 mbytes",
            "add quota filter ssh-quota 10 kbytes",
            "add element filter ports { 80 : \"http-quota\" }",
            "add element filter ports { 22 : \"ssh-quota\" }",
            "-f objs.nft",
            "list counter filter https-traffic",
            "list quota ip filter https-quota",
            "list quotas",
            "list counters",
            "list counters table inet named_counter_demo",
            "list quotas table ip filter",
            "list quota inet quota_demo q_over_http",
            "list quotas table inet quota_demo",
            "list limit inet limit_demo lim_400ppm",
            "list limits table inet limit_demo",
            "list limits",
            "list counter inet named_counter_demo cnt_http",
            "reset quota filter https-quota",
            "list quota filter https-quota",
            "reset counter inet named_counter_demo cnt_http",
            "reset counters table inet named_counter_demo",
            "reset quota inet quota_demo q_until_sip",
            "reset quotas table inet quota_demo",
            "reset quotas table filter",
            "reset counters",
            "reset quotas",
            "list ruleset",
            "-j list ruleset",
        ],
        &[(
            "objs.nft",
            "table inet foo {
   quota example { over 100 mbytes used 0 bytes }

   chain dropafterquota {
      type filter hook postrouting priority 0; policy accept;
      udp dport 5060 quota name \"example\" drop
   }

}
table ip counter_demo {
    chain IN {
        type filter hook input priority filter; policy drop;

        ip protocol tcp counter
        counter ip protocol tcp
    }
}
table inet named_counter_demo {

    counter cnt_http {
        comment \"count both http and https packets\"
    }

    counter cnt_smtp {
    }

    chain IN {
        type filter hook input priority filter; policy drop;

        tcp dport   25 counter name cnt_smtp
        tcp dport   80 counter name cnt_http
        tcp dport  443 counter name cnt_http
   }
}
define ipvoipbox=192.168.0.8

table ip filter {
    counter voip1 {
    }
    counter voip2 {
    }
    map voipcounters {
        type inet_service : counter
        elements = {
            5160 : \"voip1\",
            5161 : \"voip2\"
        }
    }
    chain FORWARD {
        #ip saddr $ipvoipbox udp dport 5160 counter name voip1 comment \"counting packets for SIP1\"
        ip saddr $ipvoipbox counter name udp sport map @voipcounters
        ip daddr $ipvoipbox counter name udp dport map @voipcounters
    }
 }
table inet anon_quota_demo {
    chain IN {
        type filter hook input priority filter; policy drop;

        udp dport 5060 quota until 100 mbytes accept
    }
}
table inet quota_demo {
   quota q_until_sip { until 100 mbytes used 0 bytes }
   quota q_over_http { over  500 mbytes ; comment \"cap http (but not https)\" ; }

   chain IN {
      type filter hook input priority filter; policy drop;

      udp dport 5060 quota name \"q_until_sip\" accept
      tcp dport 80 quota name \"q_over_http\" drop
      tcp dport { 80, 443 } accept
   }

}
table inet limit_demo {

   limit lim_400ppm { rate 400/minute ; comment \"use to limit incoming icmp\" ; }
   limit lim_1kbps  { rate over 1024 bytes/second burst 512 bytes ; comment \"use to limit incoming smtp\" ; }

   chain IN {
      type filter hook input priority filter; policy drop;

      meta l4proto icmp limit name \"lim_400ppm\" accept
      tcp dport 25 limit name \"lim_1kbps\" accept
   }
}
table inet connlimit_demo {
   chain IN {
      type filter hook input priority filter; policy drop;

      tcp dport 22 ct count 10 accept
   }
}
",
        )],
    );
}

#[test]
fn wiki_other_objects() {
    compare(
        &[
            "-f ct.nft",
            "-f synproxy.nft",
            "-f secmark.nft",
            "list ruleset",
            "-j list ruleset",
        ],
        &[
            (
                "ct.nft",
                "table inet stateful_ftp {

    # 1. ct helper stateful object
    ct helper ftp-standard {
        type \"ftp\" protocol tcp;
    }

    chain PRE {
        type filter hook prerouting priority filter;
        tcp dport 21 ct helper set \"ftp-standard\"
    }

    chain IN {
        type filter hook input priority filter; policy drop;
        tcp dport 21 ct state new,established accept
        ct helper \"ftp\" accept
        ct state related ip daddr 1.2.3.4 ct helper \"ftp\" tcp dport { 1024-65535 } accept
    }
}
table inet ct_timeout_demo {

    ct timeout agressive-tcp {
        l3proto ip;
        protocol tcp;
        policy = {established: 100, close_wait: 4, close: 4}
    }

    chain output {
        tcp dport 8888 ct timeout set \"agressive-tcp\"
    }
}
table ct_expect_demo {

    ct expectation e_pgsql {
        protocol tcp
        dport 5432
        timeout 1h
        size 12
        l3proto ip
    }

    chain input {
        type filter hook input priority filter;

        ct state new tcp dport 8888 ct expectation set \"e_pgsql\"
        ct state established,related counter accept
    }
}
",
            ),
            (
                "synproxy.nft",
                "table ip anon_synproxy_demo {

    chain PRE {
        type filter hook prerouting priority raw; policy accept;

        tcp dport 8888 tcp flags syn notrack
    }

    chain IN {
        type filter hook input priority filter; policy accept;

        tcp dport 8888 ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm
        ct state invalid drop
    }
}
table ip foo {

    synproxy https-synproxy {
        mss 1460
        wscale 7
        timestamp sack-perm
    }

    synproxy other-synproxy {
        mss 1460
        wscale 5
    }

    chain pre {
        type filter hook prerouting priority raw; policy accept;

        tcp dport 8888 tcp flags syn notrack
    }

    chain bar {
        type filter hook forward priority filter; policy accept;

        ct state invalid,untracked synproxy name ip saddr map {
            192.168.1.0/24 : \"https-synproxy\",
            192.168.2.0/24 : \"other-synproxy\",
        }
    }
}
",
            ),
            (
                "secmark.nft",
                "table inet secmark_map_demo {

    map secmapping {
        type inet_service : secmark
    }

    chain IN {
        type filter hook input priority filter;

        meta secmark set tcp dport map @secmapping
    }
}
",
            ),
        ],
    );
}

#[test]
fn wiki_sets_maps() {
    compare(
        &[
            "add table ip filter",
            "add chain ip filter input",
            "add chain ip filter output",
            "add rule ip filter output tcp dport { 22, 23 } counter",
            "add table ip6 filter",
            "add chain ip6 filter input",
            "add rule ip6 filter input tcp dport {telnet, http, https} accept",
            "add rule ip6 filter input icmpv6 type { nd-neighbor-solicit, echo-request, nd-router-advert, nd-neighbor-advert } accept",
            "add set ip filter blackhole { type ipv4_addr; comment \"drop all packets from these hosts\" ; }",
            "add element ip filter blackhole { 192.168.3.4 }",
            "add element ip filter blackhole { 192.168.1.4, 192.168.1.5 }",
            "add rule ip filter input ip saddr @blackhole drop",
            "add rule ip filter output ip daddr != @blackhole accept",
            "add set ip filter ports {type inet_service ; timeout 3h45s ;}",
            "add set ip filter flags_set {type ipv4_addr; flags constant, interval;}",
            "add set ip filter daddrs {type ipv4_addr ; flags timeout ; elements={192.168.1.1 timeout 10s, 192.168.1.2 timeout 30s} ;}",
            "add set ip filter saddrs {type ipv4_addr ; size 2 ;}",
            "-f sets.nft",
            "-f merge.nft",
            "-f nomerge.nft",
            "list set ip filter blackhole",
            "get element ip filter blackhole { 192.168.3.4 }",
            "get element ip filter blackhole { 1.1.1.1 }",
            "add table inet myfilter",
            "add set inet myfilter myset {type ipv4_addr; flags timeout; }",
            "add element inet myfilter myset {10.0.0.1 timeout 10s }",
            "list ruleset",
            "delete element inet myfilter myset { 10.0.0.1 }",
            "add element inet myfilter myset { 10.0.0.1 timeout 7s expires 5s }",
            "list set inet myfilter myset",
            "add table nat",
            "add chain nat prerouting { type nat hook prerouting priority -100 ; }",
            "add chain nat postrouting { type nat hook postrouting priority 100 ; }",
            "add rule ip nat prerouting dnat to tcp dport map { 80 : 192.168.1.100, 8888 : 192.168.1.101 }",
            "add map nat porttoip  { type inet_service: ipv4_addr; }",
            "add element nat porttoip { 80 : 192.168.1.100, 8888 : 192.168.1.101 }",
            "add rule ip nat postrouting snat to tcp dport map @porttoip",
            "add chain filter tcp-chain",
            "add chain filter udp-chain",
            "add chain filter icmp-chain",
            "add rule ip filter input ip protocol vmap { tcp : jump tcp-chain, udp : jump udp-chain , icmp : jump icmp-chain }",
            "add rule filter icmp-chain counter",
            "add rule filter tcp-chain counter",
            "add rule filter udp-chain counter",
            "add map filter mydict { type ipv4_addr : verdict; }",
            "add element filter mydict { 192.168.0.10 : drop, 192.168.0.11 : accept }",
            "add rule filter input ip saddr vmap @mydict",
            "add map filter allverdicts { type ipv4_addr : verdict; }",
            "add element filter allverdicts { 1.1.1.1 : accept, 1.1.1.2 : drop, 1.1.1.3 : queue, 1.1.1.4 : continue, 1.1.1.5 : return, 1.1.1.6 : jump tcp-chain, 1.1.1.7 : goto udp-chain }",
            "describe ip saddr",
            "describe tcp dport",
            "describe meta mark",
            "list ruleset",
            "-j list ruleset",
        ],
        &[
            (
                "sets.nft",
                "table inet mytable {
	set s1 {
		typeof osf name
		elements = { \"Linux\" }
	}
	set s2 {
		typeof vlan id
		elements = { 2, 3, 103 }
	}
	set s3 {
		typeof ip daddr
		elements = { 1.1.1.1 }
	}
	set s {
		typeof ip saddr
		counter
		elements = { 1.1.1.1 counter packets 0 bytes 0, 1.1.1.2 counter packets 0 bytes 0,
			     1.1.1.3 counter packets 0 bytes 0, 1.1.1.4 counter packets 0 bytes 0 }
	}
}
",
            ),
            (
                "merge.nft",
                "table inet mytable2 {
	set myset {
		typeof ip saddr
        flags interval
        auto-merge
		elements = { 10.0.0.1,
                     10.0.0.2,
                     10.0.0.3,
			         10.0.0.0/8,
        }
	}
}
",
            ),
            (
                "nomerge.nft",
                "table inet mytable3 {
	set myset {
		typeof ip saddr
        flags interval
		elements = { 10.0.0.0/8,
                     10.0.0.1 ,
        }
	}
}
",
            ),
        ],
    );
}

#[test]
fn wiki_dynamic_sets_meters_flowtables() {
    compare(
        &[
            "add table filter",
            "add chain filter input { type filter hook input priority 0; }",
            "add set filter myset { type inet_service; flags timeout,dynamic; }",
            "add rule filter input set update tcp dport timeout 60s @myset",
            "add set filter myset2 { type ipv4_addr; }",
            "add rule filter input set add ip saddr @myset2",
            "list ruleset",
            "flush ruleset",
            "-f meters.nft",
            "add table ip filter",
            "add chain ip filter INPUT",
            "add rule ip filter INPUT tcp dport 80 meter http1 { tcp dport . ip saddr limit rate over 200/second } counter drop",
            "add rule ip filter INPUT tcp dport 80 meter http2 { tcp dport . ip saddr timeout 3s limit rate over 200 kbytes/second burst 1 mbytes} counter drop",
            "add rule ip filter INPUT tcp dport 80 meter http3 { ip saddr and 255.255.255.0 limit rate 200/second } counter drop",
            "list ruleset",
            "list meters",
            "list meter ip filter http1",
            "-j list ruleset",
            "flush ruleset",
            "-f flowtable.nft",
            "list ruleset",
            "list flowtables",
            "list flowtable inet x f",
            "-j list ruleset",
        ],
        &[
            (
                "meters.nft",
                "table ip filter {
      set my_ssh_ratelimit {
             type ipv4_addr
             timeout 60s
             flags dynamic
      }

      chain input {
             type filter hook input priority 0; policy drop;

             ct state new tcp dport 22 update @my_ssh_ratelimit { ip saddr limit rate 3/minute } accept
      }
}
table ip filter2 {
      set my_ssh_ratelimit {
             type ipv4_addr . inet_service
             timeout 60s
             flags dynamic
      }

      chain input {
             type filter hook input priority 0; policy drop;

             ct state new update @my_ssh_ratelimit { ip saddr . tcp dport limit rate 3/minute } accept
      }
}
 table ip filter3 {
        set my_connlimit {
                type ipv4_addr
                size 65535
                flags dynamic
        }

        chain output {
                type filter hook output priority filter; policy accept;
                ct state new add @my_connlimit { ip saddr ct count over 20 } counter drop
        }
 }
",
            ),
            (
                "flowtable.nft",
                "define DEV_PRIVATE=eth0
define DEV_INTERNET=eth1

table inet x {

    flowtable f {
        hook ingress priority 0
        devices = { $DEV_PRIVATE, $DEV_INTERNET }
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # offload established HTTP connections
        tcp dport { 80, 443 } flow add @f counter packets 0 bytes 0

        # Allow traffic from established and related packets, drop invalid
        ct state vmap { established : accept, related : accept, invalid : drop }

        # connections from the internal net to the internet or to other
        # internal nets are allowed
        iifname $DEV_PRIVATE counter accept
    }
}
",
            ),
        ],
    );
}

/// Run a shell script in a new network namespace; its output.
fn script_in_netns(script: String) -> String {
    std::thread::spawn(move || {
        netns();
        let o = Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    })
    .join()
    .unwrap()
}

/// Trace lines with run-dependent values replaced, sorted and unique.
fn trace_lines(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out
        .lines()
        .map(|l| {
            let mut w: Vec<String> = l.split(' ').map(str::to_owned).collect();
            for i in 1..w.len() {
                if (w[i - 1] == "id"
                    && (w
                        .get(i.wrapping_sub(2))
                        .is_some_and(|x| x == "trace" || x == "ip")))
                    || (w[i - 1] == "packets" || w[i - 1] == "bytes")
                {
                    w[i] = "N".into();
                }
            }
            w.join(" ")
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// `monitor trace` prints traces like nft. The packets are sent by the
/// kernel after the commands that cause them returned (TCP
/// retransmissions of a closed socket, IPv6 neighbour discovery and MLD
/// after link up), while the monitor runs in the foreground.
#[test]
fn monitor_trace() {
    let setup = r#"
ip link add v0 address 02:00:00:00:00:01 type veth peer name v1 address 02:00:00:00:00:02
sysctl -qw net.ipv4.tcp_timestamps=0
nft -f - <<'NFT'
table inet t {
  chain sub { counter; meta mark set 0x7; }
  chain sub2 { ip6 nexthdr ipv6-icmp accept; }
  chain out { type filter hook output priority 0; meta nftrace set 1; jump sub; ip6 nexthdr 0 goto sub2; ip6 nexthdr ipv6-icmp goto sub2; }
  chain in { type filter hook input priority 0; tcp dport 5555 tcp flags & psh == psh counter drop; tcp sport 5555 tcp flags & rst == rst drop; }
}
table netdev n {
  chain ing { type filter hook ingress device v1 priority 0; meta nftrace set 1; }
}
NFT
python3 -I -c '
import socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 5555)); srv.listen(1)
c = socket.socket(); c.bind(("127.0.0.1", 40555)); c.connect(("127.0.0.1", 5555))
c.send(b"hello world")
'
ip link set v1 up
ip link set v0 up
ip addr add 224.0.0.5/32 dev v0 autojoin
"#;
    let run = |bin: &str| {
        trace_lines(&script_in_netns(format!(
            "{setup}\ntimeout 3 stdbuf -oL {bin} monitor trace"
        )))
    };
    let want = run("nft");
    // Some packets are sent at random times: retry for those missed.
    let mut got = Vec::new();
    for _ in 0..3 {
        got.extend(run(env!("CARGO_BIN_EXE_nfcrt")));
        got.sort();
        got.dedup();
        if want.iter().all(|l| got.contains(l)) {
            break;
        }
    }
    assert!(want.len() > 10, "too few traces: {want:?}");
    let missing: Vec<&String> = want.iter().filter(|l| !got.contains(l)).collect();
    // nfcrt may catch packets nft started too late for: those must look
    // like (have the fields of) lines nft printed.
    let shape = |l: &str| -> String {
        l.split(' ')
            .map(|w| {
                if w.chars()
                    .any(|c| c.is_ascii_digit() || c == ':' || c == '"')
                {
                    "V"
                } else {
                    w
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let shapes: Vec<String> = want.iter().map(|l| shape(l)).collect();
    let extra: Vec<&String> = got
        .iter()
        .filter(|l| !want.contains(l) && !shapes.contains(&shape(l)))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "only nft:\n{missing:#?}\nonly nfcrt:\n{extra:#?}"
    );
}

/// Ruleset change events print like nft's (`nft -e` output and the wiki's
/// `nft monitor` example). The events are collected while subscribed and
/// printed afterwards.
#[test]
fn monitor_events() {
    use crabtables::monitor::Monitor;
    let echo1 = include_str!("data/echo1.nft");
    // The text nft echoes for the file.
    let dir = std::env::temp_dir().join(format!("nfcrt-mon-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("echo1.nft");
    std::fs::write(&file, echo1).unwrap();
    let f = file.display().to_string();
    let want_echo = script_in_netns(format!("ip link set lo up; nft -e -f {f}"));
    let got = std::thread::spawn(move || {
        netns();
        let mut mon = Monitor::new().unwrap();
        let mut sock = crabtables::Socket::new().unwrap();
        let cache = sock.list_ruleset(crabtables::Family::Unspec).unwrap();
        let mut p =
            crabtables::lang::monitor::Printer::new(cache, crabtables::lang::Opts::default());
        let mut lines = Vec::new();
        let mut drain = |mon: &mut Monitor, lines: &mut Vec<String>| {
            for ev in mon.try_recv().unwrap() {
                lines.extend(p.event(&ev).into_iter().map(|l| l.text));
            }
            lines.extend(p.finish().into_iter().map(|l| l.text));
        };
        let nft = |args: &str| {
            let st = Command::new("nft")
                .args(shell_words(args))
                .status()
                .unwrap();
            assert!(st.success(), "nft {args}");
        };
        nft(&format!("-f {f}"));
        drain(&mut mon, &mut lines);
        nft("flush ruleset");
        drain(&mut mon, &mut lines);
        // The wiki example.
        for c in [
            "add table inet filter",
            "add chain inet filter forward",
            "add rule inet filter forward counter accept",
            "flush chain inet filter forward",
            "flush ruleset",
        ] {
            nft(c);
        }
        drain(&mut mon, &mut lines);
        lines
    })
    .join()
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let no_gen = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| !l.starts_with("# new generation"))
            .map(str::to_owned)
            .collect()
    };
    let got_text = got.join("\n");
    let got = no_gen(&got_text);
    let want = no_gen(&want_echo);
    assert_eq!(&got[..want.len()], &want[..], "adds like nft -e");
    // Then the deletions of flush ruleset (not checked in detail), and the
    // wiki's example.
    let wiki = [
        "add table inet filter",
        "add chain inet filter forward",
        "add rule inet filter forward counter packets 0 bytes 0 accept",
        "delete rule inet filter forward handle 2",
        "delete chain inet filter forward",
        "delete table inet filter",
    ];
    assert_eq!(&got[got.len() - wiki.len()..], &wiki[..]);
}

/// Every `nft` command in the wiki's "Basic operation" and "Advanced data
/// structures" pages, page by page (as typed in a shell).
#[test]
fn wiki_commands() {
    let text = include_str!("data/wiki_commands.txt");
    let mut pages: Vec<(&str, Vec<&str>)> = Vec::new();
    for l in text.lines() {
        match l.strip_prefix("== ") {
            Some(p) => pages.push((p, Vec::new())),
            None => pages.last_mut().unwrap().1.push(l),
        }
    }
    let norm = |s: String| -> String {
        s.lines()
            .map(|l| {
                if l.starts_with("# new generation") {
                    "# new generation".to_owned()
                } else if l.contains("\"release_name\"") || l.contains("\"version\"") {
                    "VERSION".to_owned()
                } else {
                    // Expiry times run while the commands execute.
                    let w: Vec<&str> = l.split(' ').collect();
                    let mut out = Vec::new();
                    for (i, x) in w.iter().enumerate() {
                        out.push(if i > 0 && w[i - 1] == "expires" {
                            "X"
                        } else {
                            x
                        });
                    }
                    out.join(" ")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut failures = String::new();
    for (page, cmds) in &pages {
        let run = |bin: &str| {
            // (Some commands write files.)
            let mut script = String::from(
                "cd \"$(mktemp -d)\"; ip link set lo up; for d in eth0 eth1 d0; do ip link add $d type dummy; done\n",
            );
            for c in cmds {
                script.push_str(&format!(
                    "echo '>>> {}'\n{bin} {c} 2>&1; echo \"rc=$?\"\n",
                    c.replace('\'', "")
                ));
            }
            norm(script_in_netns(script))
        };
        let (want, got) = (run("nft"), run(env!("CARGO_BIN_EXE_nfcrt")));
        if want != got {
            failures.push_str(&format!("=== {page}\n--- nft\n{want}\n--- nfcrt\n{got}\n"));
        }
    }
    assert!(failures.is_empty(), "{failures}");
}

/// Command line options are parsed like nft's (`getopt_long` and nft's
/// own checks): the same output, errors and exit status. Both run with
/// `nft` as program name.
#[test]
fn options() {
    let cases = include_str!("data/options.txt");
    let run = |bin: &str| {
        let mut script = String::from("cd /tmp\n");
        for a in cases.lines() {
            script.push_str(&format!(
                "echo '>>> {}'; (exec -a nft {bin} {a} </dev/null) 2>&1; echo \"rc=$?\"\n",
                a.replace('\'', "")
            ));
        }
        script_in_netns(script)
    };
    let (want, got) = (run("nft"), run(env!("CARGO_BIN_EXE_nfcrt")));
    let (want, got): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
    let diff: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| format!("nft:    {a}\nnfcrt:  {b}"))
        .collect();
    assert!(
        diff.is_empty() && want.len() == got.len(),
        "{}",
        diff.join("\n")
    );
}

/// `monitor` prints ruleset changes like `nft monitor`, both running at
/// the same time while the ruleset changes.
#[test]
fn monitor_cli() {
    let rs = env!("CARGO_BIN_EXE_nfcrt");
    let echo1 = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/echo1.nft");
    let modes = [
        "monitor",
        "-a monitor",
        "-j monitor",
        "-s monitor",
        "monitor new",
        "monitor ruleset",
        "monitor chains",
        "monitor new rules",
    ];
    let mut script = String::from(
        "ip link set lo up\ncd \"$(mktemp -d)\"\n\
         norm() { sed -E 's/by process [0-9]+ \\(.*\\)/by process/; s/expires [0-9a-z]+/expires X/g; s/\"expires\": [0-9]+/\"expires\": X/g' \"$1\"; }\n",
    );
    for m in modes {
        script.push_str(&format!(
            "timeout 2 stdbuf -oL nft {m} > a 2>&1 &\n\
             timeout 2 {rs} {m} > b 2>&1 &\n\
             sleep 0.5\n\
             nft -f {echo1}\n\
             nft add element ip t s {{ 7.7.7.7 }}\n\
             nft delete element ip t s {{ 7.7.7.7 }}\n\
             nft flush chain ip t c\n\
             nft delete set ip t s3\n\
             nft flush ruleset\n\
             wait\n\
             echo '=== {m}'\n\
             diff <(norm a) <(norm b) && echo same\n"
        ));
    }
    let out = script_in_netns(script);
    let bad: Vec<&str> = out
        .split("=== ")
        .filter(|s| !s.trim_end().ends_with("same") && !s.is_empty())
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("=== "));
}

/// Problems reported against similar tools (google/nftables #348, #140,
/// #126) and related nft behaviors: interval sets with and without
/// auto-merge, interface name wildcards, rule indexes.
#[test]
fn interval_sets_and_indexes() {
    compare(
        &[
            "add table inet t",
            "add chain inet t c",
            "add set inet t s4 { type ipv4_addr; flags interval; auto-merge; }",
            "add element inet t s4 { 10.0.0.0/8, 12.0.0.0/8 }",
            "--debug=netlink add element inet t s4 { 9.255.255.255-10.0.0.5, 11.0.0.0/8 }",
            "add element inet t s4 { 10.1.0.0/16 }",
            "add element inet t s4 { 20.0.0.0/8 }",
            "--debug=netlink delete element inet t s4 { 10.1.0.0/16 }",
            "delete element inet t s4 { 30.0.0.0/8 }",
            "--debug=netlink -f am.nft",
            "list set inet t s4",
            "add set inet t s6 { type ipv6_addr; flags interval; auto-merge; }",
            "add element inet t s6 { 2001:db8::/32 }",
            "add element inet t s6 { 2001:db8:1::/48, 2001:db9::/32 }",
            "list set inet t s6",
            "add set inet t n { type ipv4_addr; flags interval; }",
            "add element inet t n { 10.0.0.0/8 }",
            "add element inet t n { 10.0.0.0/8 }",
            "add element inet t n { 11.0.0.0/8 }",
            "add element inet t n { 10.5.0.0-11.0.0.4 }",
            "delete element inet t n { 10.0.0.0/16 }",
            "delete element inet t n { 10.0.0.0/8 }",
            "list set inet t n",
            "add set inet t x { type ipv4_addr; elements = { 1.2.3.0/24 }; }",
            "add set inet t y { type ipv4_addr; elements = { 1.2.3.0-1.2.3.4 }; }",
            "--debug=netlink add set inet t ifs { type ifname; flags interval; elements = { \"wlp*\", \"lo\", \"e*\" }; }",
            "add set inet t ifx { type ifname; elements = { \"wl*\" }; }",
            "-j list set inet t ifs",
            "add rule inet t c accept",
            "add rule inet t c drop",
            "add rule inet t c index 5 accept",
            "insert rule inet t c index 0 counter",
            "add rule inet t c index 1 counter",
            "add rule inet t nope index 0 accept",
            "-a list chain inet t c",
            "-a list sets",
            "-a list set inet t n",
            "-a list ruleset",
        ],
        &[(
            "am.nft",
            "add element inet t s4 { 40.0.0.0/8 }\nadd element inet t s4 { 40.1.0.0/16, 41.0.0.0/8 }\ndelete element inet t s4 { 40.2.0.0/16 }\n",
        )],
    );
}

/// Unclosed blocks, empty sets, definitions and -D values.
#[test]
fn blocks_sets_and_definitions() {
    compare(
        &[
            "add table inet t",
            "add chain inet t c",
            "add set inet t s { type ipv4_addr; elements = { 1.1.1.1 }; }",
            "delete element inet t s { }",
            "add element inet t s { }",
            "add set inet t s2 { type ipv4_addr; elements = { }; }",
            "add rule inet t c ip saddr { } accept",
            "add rule inet t c ip saddr vmap { }",
            "-f unclosed1.nft",
            "-f unclosed2.nft",
            "-f unclosed3.nft",
            "-f empty_define.nft",
            "-f redefine.nft",
            "-f define_eof.nft",
            "-f define_semicolon.nft",
            "-D x={ -D y=1 -c -f use_x.nft",
            "-D x=1.1.1.1 -D x=2.2.2.2 -c -f use_x.nft",
            "-D x={} -c -f use_x.nft",
            "-D x=1.1.1.1 -c -f use_x.nft",
            "list ruleset",
        ],
        &[
            ("unclosed1.nft", "table t { chain c {"),
            ("unclosed2.nft", "add rule inet t c jump {"),
            ("unclosed3.nft", "define x = { 1.1.1.1,\nflush ruleset\n"),
            (
                "empty_define.nft",
                "define e = { }\nadd rule inet t c ip saddr { $e, 1.1.1.1 }\nadd element inet t s $e\nadd rule inet t c ip saddr $e\n",
            ),
            (
                "redefine.nft",
                "define a = 1\ndefine a = 2\nadd tabel x\nadd tabel y\nredefine a = 3\nundefine a\ndefine a = 4\n",
            ),
            ("define_eof.nft", "define a = 2"),
            ("define_semicolon.nft", "define x = { 1.1.1.1;\n2.2.2.2 }\n"),
            ("use_x.nft", "add rule inet t c ip saddr $x\n"),
        ],
    );
}
