#![allow(dead_code)]
use std::process::Command;

pub fn netns() {
    // SAFETY: unshare has no memory safety preconditions.
    let r = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(r, 0, "unshare: {}", std::io::Error::last_os_error());
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
}

pub fn nft_try(args: &[&str]) -> (bool, String, String) {
    let out = Command::new("nft").args(args).output().expect("run nft");
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

pub fn nft(args: &[&str]) -> String {
    let (ok, out, err) = nft_try(args);
    assert!(ok, "nft {args:?}: {err}");
    out
}

pub fn nft_script(script: &str) {
    let path = std::env::temp_dir().join(format!(
        "crabtables-lang-{}-{:?}.nft",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, script).unwrap();
    let r = nft_try(&["-f", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert!(r.0, "nft -f failed: {}", r.2);
}

/// Replace time-dependent `expires` values.
pub fn strip_expires(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("expires ") {
        out.push_str(&rest[..i + 8]);
        rest = &rest[i + 8..];
        let end = rest.find([' ', ',', '}', '\n']).unwrap_or(rest.len());
        out.push('X');
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Compare two listings line by line; returns a readable diff.
pub fn diff(want: &str, got: &str) -> Option<String> {
    if want == got {
        return None;
    }
    let mut out = String::new();
    let w: Vec<&str> = want.lines().collect();
    let g: Vec<&str> = got.lines().collect();
    let mut n = 0;
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (
            w.get(i).copied().unwrap_or("<none>"),
            g.get(i).copied().unwrap_or("<none>"),
        );
        if a != b {
            out.push_str(&format!("line {i}:\n  nft:  {a}\n  ours: {b}\n"));
            n += 1;
            if n > 40 {
                break;
            }
        }
    }
    Some(out)
}
