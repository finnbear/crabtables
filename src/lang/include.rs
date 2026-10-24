//! `include` file resolution, as nft does it: relative names are searched
//! in the include paths and then in the directory of the including file;
//! names starting with `/`, `./` or `../` are used as they are. Names may
//! be glob patterns (`*`, `?`, `[...]`), matching in sorted order and
//! skipping hidden files and directories; a pattern matching nothing is
//! not an error.

use std::path::{Path, PathBuf};

/// Where includes are looked up.
#[derive(Debug, Clone)]
pub struct IncludeOpts {
    /// Search paths for relative names (nft's default is `/etc`, then the
    /// directories given with `-I`).
    pub paths: Vec<PathBuf>,
}

impl Default for IncludeOpts {
    fn default() -> Self {
        IncludeOpts {
            paths: vec![PathBuf::from("/etc")],
        }
    }
}

/// Maximum include nesting depth.
pub const MAX_DEPTH: usize = 16;

fn has_wildcard(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Does `name` match the glob `pat` (one path component)?
fn fnmatch(pat: &[u8], name: &[u8]) -> bool {
    // A leading dot must be matched explicitly.
    if name.first() == Some(&b'.') && pat.first() != Some(&b'.') {
        return false;
    }
    fn rec(p: &[u8], n: &[u8]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some(b'*') => (0..=n.len()).any(|i| rec(&p[1..], &n[i..])),
            Some(b'?') => !n.is_empty() && rec(&p[1..], &n[1..]),
            Some(b'[') => {
                let Some(c) = n.first() else { return false };
                let mut i = 1;
                let neg = matches!(p.get(1), Some(b'!' | b'^'));
                if neg {
                    i += 1;
                }
                let mut hit = false;
                let mut first = true;
                while i < p.len() && (first || p[i] != b']') {
                    first = false;
                    if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|&e| e != b']') {
                        if (p[i]..=p[i + 2]).contains(c) {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if p[i] == *c {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                if i >= p.len() {
                    // No closing bracket: a literal `[`.
                    return *c == b'[' && rec(&p[1..], &n[1..]);
                }
                hit != neg && rec(&p[i + 1..], &n[1..])
            }
            Some(&b) => n.first() == Some(&b) && rec(&p[1..], &n[1..]),
        }
    }
    rec(pat, name)
}

/// Expand a glob pattern into existing paths, sorted.
fn glob(pattern: &str) -> Vec<PathBuf> {
    let (mut cur, rest): (Vec<PathBuf>, &str) = match pattern.strip_prefix('/') {
        Some(r) => (vec![PathBuf::from("/")], r),
        None => (vec![PathBuf::new()], pattern),
    };
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let mut next = Vec::new();
        for base in &cur {
            if !has_wildcard(comp) {
                let p = base.join(comp);
                if (last && p.exists()) || p.is_dir() {
                    next.push(p);
                }
                continue;
            }
            let dir = if base.as_os_str().is_empty() {
                Path::new(".")
            } else {
                base.as_path()
            };
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut names: Vec<String> = rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| fnmatch(comp.as_bytes(), n.as_bytes()))
                .collect();
            names.sort_unstable();
            for n in names {
                let p = base.join(n);
                if last || p.is_dir() {
                    next.push(p);
                }
            }
        }
        cur = next;
    }
    if comps.is_empty() {
        return Vec::new();
    }
    cur.sort_unstable();
    cur
}

/// Files to include for `name`, from a file in `dir`. `None` means not
/// found (a name with wildcards matching nothing gives no files instead).
pub fn resolve(name: &str, dir: &Path, opts: &IncludeOpts) -> Option<Vec<PathBuf>> {
    let wild = has_wildcard(name);
    let search = !(name.starts_with('/') || name.starts_with("./") || name.starts_with("../"));
    let candidates: Vec<String> = if search {
        opts.paths
            .iter()
            .chain(std::iter::once(&dir.to_path_buf()))
            .map(|p| {
                if p.as_os_str().is_empty() {
                    name.to_owned()
                } else {
                    format!("{}/{name}", p.display())
                }
            })
            .collect()
    } else {
        vec![name.to_owned()]
    };
    for c in candidates {
        // Directories are not included.
        let files: Vec<PathBuf> = glob(&c).into_iter().filter(|p| !p.is_dir()).collect();
        let found_dir = !wild && Path::new(&c).is_dir();
        if !files.is_empty() {
            return Some(files);
        }
        if found_dir {
            return Some(Vec::new());
        }
    }
    wild.then(Vec::new)
}

#[cfg(test)]
mod tests {
    use super::fnmatch;

    #[test]
    fn patterns() {
        for (p, n, m) in [
            ("*.nft", "a.nft", true),
            ("*.nft", ".a.nft", false),
            (".*", ".a", true),
            ("[ab].nft", "b.nft", true),
            ("[!ab].nft", "b.nft", false),
            ("[a-c]?", "bz", true),
            ("p?rts", "parts", true),
            ("a*b*c", "aXXbYc", true),
            ("a*b*c", "aXXbY", false),
        ] {
            assert_eq!(fnmatch(p.as_bytes(), n.as_bytes()), m, "{p} {n}");
        }
    }
}
