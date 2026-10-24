//! `list` commands: select parts of a ruleset the way `nft list` does.

use crate::{Family, Ruleset};

use super::ast::*;
use super::error::{Error, Result};
use super::print::{self, Opts};

fn not_found(span: Span) -> Error {
    Error::at("No such file or directory", span)
}

fn family_matches(t: &Table, f: Option<Family>) -> bool {
    f.is_none_or(|f| t.family == f)
}

fn is_kind(item: &TableItem, k: ObjKind) -> bool {
    match (item, k) {
        (TableItem::Chain(_), ObjKind::Chain) => true,
        (TableItem::Set(s), ObjKind::Set) => !s.is_map,
        (TableItem::Set(s), ObjKind::Map) => s.is_map,
        (TableItem::Set(s), ObjKind::Meter) => s.flags.iter().any(|f| f == "dynamic"),
        (TableItem::Flowtable(_), ObjKind::Flowtable) => true,
        (TableItem::Obj(o), k) => {
            matches!(
                (&o.body, k),
                (ObjBody::Counter { .. }, ObjKind::Counter)
                    | (ObjBody::Quota(_), ObjKind::Quota)
                    | (ObjBody::Limit(_), ObjKind::Limit)
                    | (ObjBody::CtHelper { .. }, ObjKind::CtHelper)
                    | (ObjBody::CtTimeout { .. }, ObjKind::CtTimeout)
                    | (ObjBody::CtExpect { .. }, ObjKind::CtExpect)
                    | (ObjBody::Synproxy { .. }, ObjKind::Synproxy)
                    | (ObjBody::Secmark(_), ObjKind::Secmark)
            )
        }
        _ => false,
    }
}

fn item_name(item: &TableItem) -> &str {
    match item {
        TableItem::Chain(c) => &c.name,
        TableItem::Set(s) => &s.name,
        TableItem::Obj(o) => &o.name,
        TableItem::Flowtable(f) => &f.name,
    }
}

/// Run a `list` command against a ruleset snapshot.
pub fn list(
    rs: &Ruleset,
    kind: Option<ObjKind>,
    all: bool,
    target: &Target,
    opts: &Opts,
) -> Result<String> {
    let tables = super::decompile::ruleset(rs);
    Ok(print::tables(
        &select(tables, kind, all, target)?,
        &list_opts(kind, all, opts),
    ))
}

/// Printing options for a list command.
pub fn list_opts(kind: Option<ObjKind>, all: bool, opts: &Opts) -> Opts {
    let mut o = *opts;
    // Listings of all objects of a kind have no blank lines between them.
    if kind.is_some() && kind != Some(ObjKind::Table) && all {
        o.compact = true;
    }
    o
}

/// The tables (with the selected contents) a list command shows.
pub fn select(
    tables: Vec<Table>,
    kind: Option<ObjKind>,
    all: bool,
    target: &Target,
) -> Result<Vec<Table>> {
    let fam = target.family;
    let Some(k) = kind else {
        return Ok(tables
            .into_iter()
            .filter(|t| family_matches(t, fam))
            .collect());
    };
    if all {
        // A named table must exist.
        if let Some(name) = &target.table {
            if !tables
                .iter()
                .any(|t| family_matches(t, fam) && &t.name == name)
            {
                return Err(not_found(target.table_span));
            }
        }
        let mut out = Vec::new();
        for mut t in tables {
            if !family_matches(&t, fam) {
                continue;
            }
            if let Some(name) = &target.table {
                if &t.name != name {
                    continue;
                }
            }
            match k {
                ObjKind::Table => {
                    t.items.clear();
                    out.push(t);
                }
                ObjKind::Chain => {
                    t.items.retain(|i| is_kind(i, k));
                    for i in &mut t.items {
                        if let TableItem::Chain(c) = i {
                            c.rules.clear();
                        }
                    }
                    t.flags.clear();
                    t.handle = None;
                    t.comment = None;
                    out.push(t);
                }
                ObjKind::Set | ObjKind::Map | ObjKind::Flowtable | ObjKind::Meter => {
                    t.items.retain(|i| is_kind(i, k));
                    t.flags.clear();
                    t.handle = None;
                    t.comment = None;
                    out.push(t);
                }
                _ => {
                    t.items.retain(|i| is_kind(i, k));
                    t.flags.clear();
                    t.handle = None;
                    t.comment = None;
                    if !t.items.is_empty() {
                        out.push(t);
                    }
                }
            }
        }
        if target.table.is_some()
            && out.is_empty()
            && !matches!(
                k,
                ObjKind::Counter
                    | ObjKind::Quota
                    | ObjKind::Limit
                    | ObjKind::CtHelper
                    | ObjKind::CtTimeout
                    | ObjKind::CtExpect
                    | ObjKind::Synproxy
                    | ObjKind::Secmark
            )
        {
            return Err(not_found(target.table_span));
        }
        return Ok(out);
    }
    let fam = fam.unwrap_or(Family::Ipv4);
    let tname = target.table.as_deref().unwrap_or_default();
    let mut t = tables
        .into_iter()
        .find(|t| t.family == fam && t.name == tname)
        .ok_or_else(|| not_found(target.table_span))?;
    if k == ObjKind::Table {
        return Ok(vec![t]);
    }
    let name = target.name.as_deref().unwrap_or_default();
    t.items.retain(|i| is_kind(i, k) && item_name(i) == name);
    if t.items.is_empty() {
        return Err(not_found(target.name_span));
    }
    t.flags.clear();
    t.handle = None;
    t.comment = None;
    Ok(vec![t])
}

/// `list tables`: one line per table.
pub fn list_tables(rs: &Ruleset, family: Option<Family>, opts: &Opts) -> String {
    let mut out = String::new();
    for t in &rs.tables {
        if family.is_some_and(|f| f != t.family) {
            continue;
        }
        out.push_str(&format!("table {} {}", t.family, t.name));
        if opts.handles {
            if let Some(h) = t.handle {
                out.push_str(&format!(" # handle {h}"));
            }
        }
        out.push('\n');
    }
    out
}
