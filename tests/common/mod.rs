//! Test helpers. Every test runs in its own network namespace so that the
//! host firewall is never touched.
#![allow(dead_code)]

use std::process::Command;

/// Move the current thread into a fresh network namespace with `lo` up.
/// Subprocesses (nft) spawned from this thread inherit it.
pub fn netns() {
    // SAFETY: unshare has no memory safety preconditions.
    let r = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(
        r,
        0,
        "unshare(CLONE_NEWNET) failed (are we root?): {}",
        std::io::Error::last_os_error()
    );
    let st = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap();
    assert!(st.success());
}

/// Run nft with arguments, panicking on failure; returns stdout.
pub fn nft(args: &[&str]) -> String {
    let out = Command::new("nft").args(args).output().expect("run nft");
    assert!(
        out.status.success(),
        "nft {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Run nft, returning (success, stdout, stderr).
pub fn nft_try(args: &[&str]) -> (bool, String, String) {
    let out = Command::new("nft").args(args).output().expect("run nft");
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// Load an nft script.
pub fn nft_script(script: &str) {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "crabtables-test-{}-{:?}.nft",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, script).unwrap();
    let r = nft_try(&["-f", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert!(r.0, "nft -f failed:\n{}\nscript:\n{}", r.2, script);
}

/// `nft list ruleset` normalized: tabs replaced, trailing whitespace trimmed.
pub fn ruleset() -> String {
    normalize(&nft(&["list", "ruleset"]))
}

pub fn normalize(s: &str) -> String {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Assert that `haystack` (normalized) contains each line of `needle` (normalized), in order.
pub fn assert_contains_lines(haystack: &str, needle: &str) {
    let h = normalize(haystack);
    let mut pos = 0;
    for line in normalize(needle).lines() {
        match h[pos..].find(line) {
            Some(i) => pos += i + line.len(),
            None => panic!("expected line not found (in order): {line:?}\n--- in ---\n{h}"),
        }
    }
}

/// A thread living in its own network namespace, running closures on
/// request. Used to build multi-namespace topologies.
pub struct NetnsThread {
    tx: std::sync::mpsc::Sender<Box<dyn FnOnce() + Send>>,
    /// Thread id, usable as `ip link set DEV netns <tid>`.
    pub tid: i32,
}

impl NetnsThread {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Box<dyn FnOnce() + Send>>();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            netns();
            // SAFETY: gettid has no preconditions.
            tid_tx.send(unsafe { libc::gettid() }).unwrap();
            for job in rx {
                job();
            }
        });
        NetnsThread {
            tx,
            tid: tid_rx.recv().unwrap(),
        }
    }

    /// Run `f` in the namespace and return its result.
    pub fn run<R: Send + 'static>(&self, f: impl FnOnce() -> R + Send + 'static) -> R {
        let (tx, rx) = std::sync::mpsc::channel();
        self.tx
            .send(Box::new(move || {
                let _ = tx.send(f());
            }))
            .unwrap();
        rx.recv().expect("job panicked")
    }

    /// Run an `ip` command in the namespace.
    pub fn ip(&self, args: &str) {
        let args = args.to_owned();
        self.run(move || ip(&args));
    }
}

/// Run an `ip` command in the current namespace.
pub fn ip(args: &str) {
    let st = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .unwrap();
    assert!(st.success(), "ip {args}");
}

/// Router topology: the current namespace routes between a client
/// (10.1.0.2, via c0 = 10.1.0.1) and a server (10.2.0.2, via s0 = 10.2.0.1).
pub fn router_topology() -> (NetnsThread, NetnsThread) {
    netns();
    let client = NetnsThread::new();
    let server = NetnsThread::new();
    ip("link add c0 type veth peer name c1");
    ip(&format!("link set c1 netns {}", client.tid));
    ip("link add s0 type veth peer name s1");
    ip(&format!("link set s1 netns {}", server.tid));
    ip("addr add 10.1.0.1/24 dev c0");
    ip("addr add 10.2.0.1/24 dev s0");
    ip("link set c0 up");
    ip("link set s0 up");
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    client.ip("addr add 10.1.0.2/24 dev c1");
    client.ip("link set c1 up");
    client.ip("route add default via 10.1.0.1");
    server.ip("addr add 10.2.0.2/24 dev s1");
    server.ip("link set s1 up");
    server.ip("route add default via 10.2.0.1");
    (client, server)
}

/// Whether the running kernel is at least `major.minor`. Tests of newer
/// kernel features use this to skip on older kernels (e.g. in CI).
pub fn kernel_at_least(major: u32, minor: u32) -> bool {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut it = rel
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse::<u32>().ok());
    let v = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    let ok = v >= (major, minor);
    if !ok {
        eprintln!(
            "skipping: needs kernel {major}.{minor}, running {}",
            rel.trim()
        );
    }
    ok
}
