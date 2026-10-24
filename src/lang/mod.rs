#![doc = include_str!("README.md")]
#![warn(missing_docs)]

pub mod ast;
pub mod compile;
pub mod datatype;
pub mod decompile;
pub mod describe;
mod error;
pub mod include;
#[cfg(feature = "lang_json")]
pub mod json;
mod lex;
pub mod list;
pub mod monitor;
pub mod netdebug;
pub mod parse;
pub mod print;
pub mod proto;
mod typeof_udata;

pub use error::{Error, Origin, Related, Result};
pub use print::Opts;

/// List a ruleset snapshot in the format of `nft list ruleset`.
pub fn list_ruleset(rs: &crate::Ruleset, opts: &Opts) -> String {
    print::tables(&decompile::ruleset(rs), opts)
}

/// The text of one rule (its statements), as `nft list` prints it.
pub fn rule_text(rs: &crate::Ruleset, r: &crate::Rule, opts: &Opts) -> String {
    print::rule(&decompile::one_rule(rs, r), r.family, opts)
}

/// `get element` / `reset element`: look up elements of a set (in the
/// snapshot `rs`) and print them as `nft` does, in the order asked.
#[allow(clippy::too_many_arguments)]
pub fn get_elements(
    sock: &mut crate::Socket,
    rs: &crate::Ruleset,
    reset: bool,
    family: crate::Family,
    table: &str,
    set: &str,
    elems: &[ast::Elem],
    opts: &Opts,
) -> Result<String> {
    let not_found = || Error::msg("Could not process rule: No such file or directory");
    let mut c = compile::Compiler::new();
    c.learn(rs);
    let (kset, kelems) = rs
        .sets
        .iter()
        .find(|(s, _)| s.family == family && s.table == table && s.name == set)
        .ok_or_else(not_found)?;
    let interval = kset.is_interval() && kset.field_lens.is_empty();
    let mut sorted: Vec<&crate::SetElem> = kelems.iter().collect();
    sorted.sort_unstable_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then(b.is_interval_end().cmp(&a.is_interval_end()))
    });
    let mut found = Vec::new();
    for e in elems {
        let keys = c.element_keys(family, table, set, std::slice::from_ref(e))?;
        let key = keys
            .first()
            .and_then(|k| k.key.clone())
            .ok_or_else(not_found)?;
        let matched: Vec<crate::SetElem> = if interval {
            // The interval containing the key: the last start at or below
            // it, unless an end marker comes first.
            let pos = sorted
                .iter()
                .rposition(|x| x.key.as_deref().is_some_and(|k| k <= key.as_slice()))
                .ok_or_else(not_found)?;
            let start = sorted[pos];
            if start.is_interval_end() {
                return Err(not_found());
            }
            let mut v = vec![start.clone()];
            if let Some(end) = sorted.get(pos + 1).filter(|x| x.is_interval_end()) {
                v.push((*end).clone());
            }
            v
        } else {
            let m: Vec<_> = kelems
                .iter()
                .filter(|x| x.key.as_deref() == Some(key.as_slice()))
                .cloned()
                .collect();
            if m.is_empty() {
                return Err(not_found());
            }
            m
        };
        let mut matched = matched;
        if reset {
            // Reset the element's counters and quotas; the kernel returns
            // their values from before the reset.
            let keys: Vec<crate::SetElem> = matched
                .iter()
                .filter(|x| !x.is_interval_end())
                .map(|x| crate::SetElem {
                    key: x.key.clone(),
                    key_end: x.key_end.clone(),
                    flags: x
                        .flags
                        .filter(|f| f & crate::sys::NFT_SET_ELEM_CATCHALL != 0),
                    ..Default::default()
                })
                .collect();
            let before = sock.get_elems_reset(family, table, set, &keys)?;
            for m in &mut matched {
                if let Some(b) = before
                    .iter()
                    .find(|b| b.key == m.key && !m.is_interval_end())
                {
                    m.exprs = b.exprs.clone();
                }
            }
        }
        let mut snap = rs.clone();
        for (s, e) in &mut snap.sets {
            if s.family == family && s.table == table && s.name == set {
                *e = matched.clone();
            }
        }
        for t in decompile::ruleset(&snap) {
            for it in t.items {
                if let ast::TableItem::Set(s) = it {
                    if t.family == family && t.name == table && s.name == set {
                        found.extend(s.elements.unwrap_or_default());
                    }
                }
            }
        }
    }
    let mut tables = decompile::ruleset(rs);
    tables.retain(|t| t.family == family && t.name == table);
    for t in &mut tables {
        t.items.retain_mut(|it| match it {
            ast::TableItem::Set(s) if s.name == set => {
                s.elements = Some(found.clone());
                // Only the elements are shown, not the set's statements.
                s.stmts.clear();
                s.comment = None;
                true
            }
            _ => false,
        });
        t.flags.clear();
        t.comment = None;
    }
    let opts = Opts {
        inline_elements: true,
        ..*opts
    };
    Ok(print::tables(&tables, &opts))
}
