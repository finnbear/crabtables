//! Parser for nft scripts and commands.

use std::collections::HashMap;
use std::path::Path;

use crate::Family;

use super::ast::*;
use super::error::{Error, Origin, Result};
use super::include::{self, IncludeOpts};
use super::lex::{Tok, Token, lex};
use super::proto;

/// Parse a script (or a command line) into commands.
pub fn parse(input: &str) -> Result<Vec<Cmd>> {
    let mut p = Parser::new(input)?;
    p.script()
}

/// Parse a script, returning each command with its location.
pub fn parse_spanned(input: &str) -> Result<Vec<(Cmd, Span)>> {
    parse_source(input, &Source::default())
}

/// Where a script comes from, for its `include` statements.
#[derive(Debug, Clone)]
pub struct Source {
    /// Name in error messages (`<cmdline>`, `/dev/stdin` or the file name).
    pub name: String,
    /// Directory searched for relative includes (after the include paths).
    pub dir: std::path::PathBuf,
    /// Include search paths.
    pub include: IncludeOpts,
}

impl Default for Source {
    fn default() -> Self {
        Source {
            name: "<cmdline>".into(),
            dir: std::env::current_dir().unwrap_or_default(),
            include: IncludeOpts::default(),
        }
    }
}

/// Parse a script from `src` like nft, continuing after syntax errors:
/// the commands parsed (with their locations) and the errors (at most 10).
pub fn parse_source_all(input: &str, src: &Source) -> (Vec<(Cmd, Span)>, Vec<Error>) {
    let mut p = match Parser::new(input) {
        Ok(p) => p,
        Err(e) => return (Vec::new(), vec![e]),
    };
    p.src = std::rc::Rc::new(src.clone());
    p.text = input.into();
    p.recovering = true;
    let cmds = match p.script() {
        Ok(c) => c,
        Err(e) => {
            if e.msg != TOO_MANY {
                p.errors.push(e);
            }
            Vec::new()
        }
    };
    let spans = std::mem::take(&mut p.cmd_spans);
    let cmds = cmds
        .into_iter()
        .zip(spans.into_iter().chain(std::iter::repeat(Span::default())))
        .collect();
    (cmds, p.errors)
}

/// Parse a script from `src`, returning each command with its location
/// (commands from included files have none).
pub fn parse_source(input: &str, src: &Source) -> Result<Vec<(Cmd, Span)>> {
    let mut p = Parser::new(input)?;
    p.src = std::rc::Rc::new(src.clone());
    p.text = input.into();
    let cmds = p.script()?;
    let spans = std::mem::take(&mut p.cmd_spans);
    Ok(cmds
        .into_iter()
        .zip(spans.into_iter().chain(std::iter::repeat(Span::default())))
        .collect())
}

/// Parse a single rule's statements (as in `add rule ... <stmts>`).
pub fn parse_rule(input: &str) -> Result<Rule> {
    let mut p = Parser::new(input)?;
    let (r, _, _) = p.rule()?;
    Ok(r)
}

/// Parse an expression.
pub fn parse_expr(input: &str) -> Result<Expr> {
    let mut p = Parser::new(input)?;
    p.expr()
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
    len: usize,
    vars: HashMap<String, Vec<Token>>,
    /// Defines whose value is an empty set, `{ }`, with its span.
    empty_defs: HashMap<String, Span>,
    /// The last expansion of such a define: position of its `{` and the
    /// define's span.
    empty_def: Option<(usize, Span)>,
    /// Location of the last table name read by `table_ref`.
    tspan: Span,
    /// Locations of the commands parsed by `script`.
    cmd_spans: Vec<Span>,
    /// The input's origin (for includes).
    src: std::rc::Rc<Source>,
    /// The input (for locations of include statements).
    text: std::sync::Arc<str>,
    /// Include nesting depth.
    depth: usize,
    /// Continue after syntax errors (collecting them in `errors`).
    recovering: bool,
    /// Errors before this token are not reported (as bison, after a
    /// redefinition error, does not report one on the next line).
    quiet_until: usize,
    /// `quiet_until` once the current error is reported.
    quiet_next: usize,
    /// Syntax errors recovered from.
    errors: Vec<Error>,
}

/// Errors reported at most (as nft).
const MAX_ERRORS: usize = 10;
const TOO_MANY: &str = "too many errors";

fn family_of(w: &str) -> Option<Family> {
    Some(match w {
        "ip" => Family::Ipv4,
        "ip6" => Family::Ipv6,
        "inet" => Family::Inet,
        "arp" => Family::Arp,
        "bridge" => Family::Bridge,
        "netdev" => Family::Netdev,
        _ => return None,
    })
}

const VERBS: &[&str] = &[
    "add", "create", "insert", "replace", "delete", "destroy", "list", "flush", "reset", "rename",
    "get", "describe", "monitor",
];

const STMT_END: &[&str] = &[";", "}"];

/// Words that start statements (they may follow a protocol name used as a
/// value, as in `meta l4proto tcp accept`).
const STMT_KEYWORDS: &[&str] = &[
    "accept",
    "drop",
    "continue",
    "return",
    "jump",
    "goto",
    "queue",
    "counter",
    "log",
    "limit",
    "quota",
    "reject",
    "snat",
    "dnat",
    "masquerade",
    "redirect",
    "notrack",
    "dup",
    "fwd",
    "meta",
    "ct",
    "comment",
    "vmap",
    "map",
    "set",
    "synproxy",
    "flow",
    "tproxy",
    "add",
    "update",
    "delete",
    "last",
    "mark",
];

/// Words nft's scanner treats as keywords (named in syntax errors).
const KEYWORDS: &[&str] = &[
    "table",
    "chain",
    "rule",
    "set",
    "map",
    "element",
    "elements",
    "flowtable",
    "counter",
    "quota",
    "limit",
    "add",
    "create",
    "insert",
    "replace",
    "delete",
    "destroy",
    "list",
    "flush",
    "reset",
    "rename",
    "get",
    "describe",
    "ip",
    "ip6",
    "inet",
    "arp",
    "bridge",
    "netdev",
    "tcp",
    "udp",
    "udplite",
    "sctp",
    "dccp",
    "icmp",
    "icmpv6",
    "igmp",
    "ether",
    "vlan",
    "meta",
    "ct",
    "accept",
    "drop",
    "continue",
    "return",
    "jump",
    "goto",
    "queue",
    "log",
    "reject",
    "snat",
    "dnat",
    "masquerade",
    "redirect",
    "type",
    "typeof",
    "hook",
    "priority",
    "policy",
    "flags",
    "timeout",
    "comment",
    "define",
    "include",
    "th",
    "ah",
    "esp",
    "comp",
    "gre",
    "ruleset",
    "tables",
    "chains",
    "sets",
    "maps",
    "counters",
    "quotas",
    "handle",
    "position",
    "index",
    "to",
    "with",
    "mark",
    "saddr",
    "daddr",
    "sport",
    "dport",
    "protocol",
    "iifname",
    "oifname",
    "iif",
    "oif",
    "state",
    "vmap",
    "notrack",
    "dup",
    "fwd",
    "numgen",
    "jhash",
    "symhash",
    "fib",
    "rt",
    "socket",
    "osf",
    "synproxy",
    "secmark",
    "size",
    "auto-merge",
    "interval",
    "constant",
    "dynamic",
    "packets",
    "bytes",
    "over",
    "rate",
    "burst",
    "level",
    "prefix",
    "group",
    "device",
    "devices",
    "offload",
];

/// Record the location of the object declared by a command.
fn set_cmd_span(c: &mut Cmd, span: Span) {
    match c {
        Cmd::Table { table, .. } => table.span = span,
        Cmd::Chain { chain, .. } => chain.span = span,
        Cmd::Set { set, .. } => set.span = span,
        Cmd::Obj { obj, .. } => obj.span = span,
        Cmd::Flowtable { ft, .. } => ft.span = span,
        _ => {}
    }
}

impl Parser {
    fn new(input: &str) -> Result<Self> {
        Ok(Parser {
            tspan: Span::default(),
            cmd_spans: Vec::new(),
            src: Default::default(),
            text: "".into(),
            depth: 0,
            recovering: false,
            quiet_until: 0,
            quiet_next: 0,
            errors: Vec::new(),
            toks: lex(input)?,
            pos: 0,
            len: input.len(),
            vars: HashMap::new(),
            empty_defs: HashMap::new(),
            empty_def: None,
        })
    }

    // ------------------------------------------------------------ tokens

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.pos + n).map(|t| &t.tok)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn peek_word_at(&self, n: usize) -> Option<&str> {
        match self.peek_at(n) {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }

    fn span(&self) -> Span {
        self.toks.get(self.pos).map_or(
            Span {
                start: self.len,
                end: self.len,
            },
            |t| t.span,
        )
    }

    /// End of a command: nft's locations include the line terminator.
    fn cmd_end(&self) -> usize {
        match self.peek() {
            Some(Tok::Newline) => self.span().end,
            _ => self.prev_end(),
        }
    }

    /// Location of the token `n` positions ahead.
    fn span_at(&self, n: usize) -> Span {
        self.toks
            .get(self.pos + n)
            .map_or_else(|| self.span(), |t| t.span)
    }

    fn prev_end(&self) -> usize {
        self.pos
            .checked_sub(1)
            .and_then(|i| self.toks.get(i))
            .map_or(0, |t| t.span.end)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T> {
        Err(Error::at(msg, self.span()))
    }

    /// A syntax error in nft's wording: the unexpected token, and what
    /// was expected when that is a short list (as bison reports it).
    fn unexpected<T>(&self, what: &str) -> Result<T> {
        if let Some(Tok::Var(v)) = self.peek() {
            if !self.vars.contains_key(v) {
                // (Located at the name, after the `$`.)
                let sp = self.span();
                return Err(Error::at(
                    format!("unknown identifier '{v}'"),
                    Span {
                        start: sp.start + 1,
                        end: sp.end,
                    },
                ));
            }
        }
        let found = match self.peek() {
            None => "end of file".to_owned(),
            Some(Tok::Word(w)) if w.chars().all(|c| c.is_ascii_digit()) => "number".to_owned(),
            Some(Tok::Word(w)) if KEYWORDS.contains(&w.as_str()) => w.clone(),
            Some(Tok::Word(_)) => "string".to_owned(),
            Some(Tok::Str(_)) => "quoted string".to_owned(),
            Some(Tok::At(_)) => "'@'".to_owned(),
            Some(Tok::Var(_)) => "'$'".to_owned(),
            Some(Tok::Punct(p)) => match *p {
                // nft's names for its tokens.
                ";" => "semicolon".to_owned(),
                "," => "comma".to_owned(),
                ":" => "colon".to_owned(),
                "=" | "(" | ")" | "{" | "}" | "[" | "]" => format!("'{p}'"),
                p => p.to_owned(),
            },
            Some(Tok::Newline) => "newline".to_owned(),
        };
        // Expected alternatives are listed when nft lists them.
        if what.contains(" or ")
            || what.starts_with('\'')
            || what == "number"
            || what.starts_with("keyword ")
        {
            let what = what.strip_prefix("keyword ").unwrap_or(what);
            self.err(format!(
                "syntax error, unexpected {found}, expecting {what}"
            ))
        } else {
            self.err(format!("syntax error, unexpected {found}"))
        }
    }

    fn next(&mut self) -> Option<Tok> {
        // Variables expand to their definition.
        self.expand();
        let t = self.toks.get(self.pos).map(|t| t.tok.clone());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expand(&mut self) {
        if let Some(Tok::Var(v)) = self.peek().cloned() {
            if let Some(def) = self.vars.get(&v).cloned() {
                let span = self.span();
                if let Some(&d) = self.empty_defs.get(&v) {
                    self.empty_def = Some((self.pos, d));
                }
                self.toks.splice(
                    self.pos..=self.pos,
                    def.into_iter().map(|t| Token { tok: t.tok, span }),
                );
            }
        }
    }

    fn word(&mut self, what: &str) -> Result<String> {
        self.expand();
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => self.unexpected(what),
        }
    }

    fn string(&mut self, what: &str) -> Result<String> {
        self.expand();
        match self.peek() {
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            _ => self.unexpected(what),
        }
    }

    fn number<T: std::str::FromStr>(&mut self, what: &str) -> Result<T> {
        let span = self.span();
        self.expand();
        if !matches!(self.peek(), Some(Tok::Word(_))) {
            return self.unexpected("number");
        }
        let w = self.word(what)?;
        let n = if let Some(h) = w.strip_prefix("0x") {
            u64::from_str_radix(h, 16)
                .ok()
                .and_then(|v| v.to_string().parse().ok())
        } else {
            w.parse().ok()
        };
        n.ok_or_else(|| Error::at(format!("expected {what}, got `{w}`"), span))
    }

    fn eat_word(&mut self, w: &str) -> bool {
        self.expand();
        if self.peek_word() == Some(w) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, w: &str) -> Result<()> {
        if self.eat_word(w) {
            Ok(())
        } else {
            self.unexpected(&format!("`{w}`"))
        }
    }

    fn is_punct(&self, p: &str) -> bool {
        matches!(self.peek(), Some(Tok::Punct(x)) if *x == p)
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if self.is_punct(p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, p: &str) -> Result<()> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            self.unexpected(&format!("`{p}`"))
        }
    }

    fn skip_nl(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline)) {
            self.pos += 1;
        }
    }

    fn skip_seps(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline) | Some(Tok::Punct(";"))) {
            self.pos += 1;
        }
    }

    fn at_end(&self) -> bool {
        match self.peek() {
            None | Some(Tok::Newline) => true,
            Some(Tok::Punct(p)) => STMT_END.contains(p),
            _ => false,
        }
    }

    fn end_item(&mut self) -> Result<()> {
        if self.at_end() {
            self.eat_punct(";");
            Ok(())
        } else {
            self.unexpected("end of file or newline or semicolon")
        }
    }

    // ------------------------------------------------------------ script

    fn script(&mut self) -> Result<Vec<Cmd>> {
        let mut cmds = Vec::new();
        loop {
            match self.script_item(&mut cmds) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => self.recover(e)?,
            }
        }
        Ok(cmds)
    }

    /// Record a syntax error and skip to the next line (with recovery
    /// enabled; otherwise the error is returned).
    fn recover(&mut self, e: Error) -> Result<()> {
        if !self.recovering || e.msg == TOO_MANY {
            return Err(e);
        }
        // The end of the input is reported once (not by every open block).
        let eof = self.peek().is_none();
        if eof && self.errors.last().is_some_and(|l| l.span == e.span) {
            return Ok(());
        }
        if self.pos >= self.quiet_until {
            self.errors.push(e);
        }
        self.quiet_until = std::mem::take(&mut self.quiet_next);
        if self.errors.len() >= MAX_ERRORS {
            return Err(Error::msg(TOO_MANY));
        }
        while let Some(t) = self.peek() {
            let nl = matches!(t, Tok::Newline);
            self.pos += 1;
            if nl {
                break;
            }
        }
        Ok(())
    }

    /// One command (or definition) of a script; false at the end.
    fn script_item(&mut self, cmds: &mut Vec<Cmd>) -> Result<bool> {
        {
            self.skip_seps();
            let Some(tok) = self.peek().cloned() else {
                return Ok(false);
            };
            let Tok::Word(w) = tok else {
                return self.unexpected("command");
            };
            match w.as_str() {
                "define" | "redefine" => {
                    self.pos += 1;
                    let name_span = self.span();
                    let name = self.word("variable name")?;
                    self.expect_punct("=")?;
                    let start = self.pos;
                    let mut depth = 0i32;
                    while let Some(t) = self.peek() {
                        // A command keyword at the start of a line inside an
                        // open value ends it with an error, as in nft.
                        if depth > 0
                            && matches!(
                                self.toks.get(self.pos.wrapping_sub(1)).map(|t| &t.tok),
                                Some(Tok::Newline)
                            )
                            && matches!(t, Tok::Word(w) if VERBS.contains(&w.as_str()) || w == "table" || w == "define")
                        {
                            return self.unexpected("comma or '}'");
                        }
                        // (Neither is a semicolon inside one.)
                        if depth > 0 && *t == Tok::Punct(";") {
                            let open = self.toks[..self.pos]
                                .iter()
                                .rev()
                                .find(|t| t.tok != Tok::Newline)
                                .is_some_and(|t| t.tok == Tok::Punct("{"));
                            return self.unexpected(if open { "" } else { "comma or '}'" });
                        }
                        match t {
                            Tok::Punct("{") => depth += 1,
                            Tok::Punct("}") => depth -= 1,
                            Tok::Newline | Tok::Punct(";") if depth <= 0 => break,
                            _ => {}
                        }
                        self.pos += 1;
                    }
                    // A value left open at the end of the input.
                    if depth > 0 {
                        let open = matches!(
                            self.toks
                                .iter()
                                .rev()
                                .find(|t| t.tok != Tok::Newline)
                                .map(|t| &t.tok),
                            Some(Tok::Punct("{"))
                        );
                        return self.unexpected(if open { "" } else { "comma or '}'" });
                    }
                    if self.peek().is_none() {
                        return self.unexpected("newline or semicolon");
                    }
                    if w == "define" && self.vars.contains_key(&name) {
                        // The next line's errors are not reported.
                        let nl = |from: usize| {
                            (from..self.toks.len())
                                .find(|&i| self.toks[i].tok == Tok::Newline)
                                .unwrap_or(self.toks.len())
                        };
                        self.quiet_next = nl(nl(self.pos) + 1) + 1;
                        return Err(Error::at(
                            format!("redefinition of symbol '{name}'"),
                            name_span,
                        ));
                    }
                    let def = self.toks[start..self.pos].to_vec();
                    // An empty set is allowed here (it adds nothing to a
                    // set it is used in), as in nft.
                    let toks: Vec<_> = def.iter().filter(|t| t.tok != Tok::Newline).collect();
                    match toks[..] {
                        [a, b] if a.tok == Tok::Punct("{") && b.tok == Tok::Punct("}") => {
                            let span = Span {
                                start: a.span.start,
                                end: b.span.end,
                            };
                            self.empty_defs.insert(name.clone(), span);
                        }
                        _ => {
                            self.empty_defs.remove(&name);
                        }
                    }
                    self.vars.insert(name, def);
                }
                "undefine" => {
                    self.pos += 1;
                    let name = self.word("variable name")?;
                    self.empty_defs.remove(&name);
                    self.vars.remove(&name);
                }
                "include" => {
                    let start = self.span().start;
                    self.pos += 1;
                    let path = self.string("file name")?;
                    let span = Span {
                        start,
                        end: self.cmd_end(),
                    };
                    let here = Error::location(&self.text, &self.src.name, span);
                    if self.depth + 1 >= include::MAX_DEPTH {
                        return Err(Error::at(
                            format!(
                                "Include nested too deeply, max {} levels",
                                include::MAX_DEPTH
                            ),
                            span,
                        ));
                    }
                    let files = include::resolve(&path, &self.src.dir, &self.src.include)
                        .ok_or_else(|| Error::at(format!("File not found: {path}"), span))?;
                    for f in files {
                        let name = f.display().to_string();
                        let text = std::fs::read_to_string(&f).map_err(|e| {
                            Error::at(format!("Could not open file \"{name}\": {e}"), span)
                        })?;
                        let text: std::sync::Arc<str> = text.into();
                        let in_file = |mut e: Error| {
                            e.origin
                                .get_or_insert_with(|| {
                                    Box::new(Origin {
                                        file: name.clone(),
                                        text: text.clone(),
                                        included_from: Vec::new(),
                                    })
                                })
                                .included_from
                                .push(here.clone());
                            e
                        };
                        let mut sub = Parser::new(&text).map_err(in_file)?;
                        let dir = std::fs::canonicalize(&f)
                            .ok()
                            .and_then(|p| p.parent().map(Path::to_path_buf))
                            .unwrap_or_default();
                        sub.src = std::rc::Rc::new(Source {
                            name: name.clone(),
                            dir,
                            include: self.src.include.clone(),
                        });
                        sub.text = text.clone();
                        sub.depth = self.depth + 1;
                        sub.vars = std::mem::take(&mut self.vars);
                        let n = sub.script().map_err(in_file)?;
                        // Locations in included files are not tracked.
                        self.cmd_spans
                            .extend(std::iter::repeat_n(Span::default(), n.len()));
                        cmds.extend(n);
                        self.vars = sub.vars;
                    }
                }
                "table" => {
                    let start = self.span().start;
                    self.pos += 1;
                    let mut c = self.table_cmd(false)?;
                    let span = Span {
                        start,
                        end: self.cmd_end(),
                    };
                    set_cmd_span(&mut c, span);
                    cmds.push(c);
                    self.cmd_spans.push(span);
                }
                w if VERBS.contains(&w) => {
                    let start = self.span().start;
                    self.pos += 1;
                    let end_cmds = self.command(w)?;
                    let end = self.cmd_end();
                    for mut c in end_cmds {
                        let span = Span { start, end };
                        set_cmd_span(&mut c, span);
                        cmds.push(c);
                        self.cmd_spans.push(span);
                    }
                }
                // `add` may be omitted.
                _ => {
                    let start = self.span().start;
                    let end_cmds = self.command("add")?;
                    let end = self.cmd_end();
                    for mut c in end_cmds {
                        let span = Span { start, end };
                        set_cmd_span(&mut c, span);
                        cmds.push(c);
                        self.cmd_spans.push(span);
                    }
                }
            }
            // (A rule consumes its terminator.)
            let terminated = self.pos > 0
                && matches!(
                    self.toks.get(self.pos - 1).map(|t| &t.tok),
                    Some(Tok::Newline | Tok::Punct(";"))
                );
            if !terminated && !self.at_end() && self.peek().is_some() {
                return self.unexpected("end of file or newline or semicolon");
            }
        }
        Ok(true)
    }

    fn family(&mut self) -> Family {
        // `ip` etc. are always a family (as in nft, a table can be named
        // `ip` only when quoted).
        if let Some(Tok::Word(w)) = self.peek() {
            if let Some(f) = family_of(w) {
                self.pos += 1;
                return f;
            }
        }
        Family::Ipv4
    }

    fn opt_family(&mut self) -> Option<Family> {
        let f = self.peek_word().and_then(family_of)?;
        self.pos += 1;
        Some(f)
    }

    /// `[family] table`
    fn table_ref(&mut self) -> Result<(Family, String)> {
        let f = self.family();
        self.tspan = self.span();
        let t = self.word("string or last")?;
        Ok((f, t))
    }

    /// A name and its location.
    fn name(&mut self) -> Result<(String, Span)> {
        let span = self.span();
        Ok((self.word("string or last")?, span))
    }

    fn handle(&mut self) -> Result<Option<u64>> {
        if self.eat_word("handle") {
            Ok(Some(self.number("handle")?))
        } else {
            Ok(None)
        }
    }

    fn command(&mut self, verb: &str) -> Result<Vec<Cmd>> {
        let create = verb == "create";
        match verb {
            "add" | "create" => {
                // `add [family] table chain stmts...`: a rule.
                const KINDS: [&str; 13] = [
                    "table",
                    "chain",
                    "rule",
                    "set",
                    "map",
                    "element",
                    "flowtable",
                    "counter",
                    "quota",
                    "limit",
                    "synproxy",
                    "secmark",
                    "ct",
                ];
                if verb == "add"
                    && matches!(self.peek(), Some(Tok::Word(w)) if !KINDS.contains(&w.as_str()))
                {
                    return Ok(vec![self.rule_cmd(RuleOp::Add)?]);
                }
                let kind = self.word("object type")?;
                Ok(vec![match kind.as_str() {
                    "table" => self.table_cmd(create)?,
                    "chain" => {
                        let (family, table) = self.table_ref()?;
                        let table_span = self.tspan;
                        let (name, name_span) = self.name()?;
                        let mut chain = Chain {
                            name,
                            name_span,
                            ..Default::default()
                        };
                        if self.eat_punct("{") {
                            self.chain_body(&mut chain)?;
                        }
                        Cmd::Chain {
                            create,
                            family,
                            table,
                            table_span,
                            chain,
                        }
                    }
                    "rule" => self.rule_cmd(RuleOp::Add)?,
                    "set" | "map" => {
                        let (family, table) = self.table_ref()?;
                        let table_span = self.tspan;
                        let (name, name_span) = self.name()?;
                        let mut set = Set {
                            name,
                            name_span,
                            is_map: kind == "map",
                            ..Default::default()
                        };
                        self.expect_punct("{")?;
                        self.set_body(&mut set)?;
                        Cmd::Set {
                            create,
                            family,
                            table,
                            table_span,
                            set,
                        }
                    }
                    "element" => self.element_cmd(verb)?,
                    "flowtable" => {
                        let (family, table) = self.table_ref()?;
                        let table_span = self.tspan;
                        let (name, name_span) = self.name()?;
                        let mut ft = Flowtable {
                            name,
                            name_span,
                            ..Default::default()
                        };
                        if self.eat_punct("{") {
                            self.flowtable_body(&mut ft)?;
                        }
                        Cmd::Flowtable {
                            create,
                            family,
                            table,
                            table_span,
                            ft,
                        }
                    }
                    k => {
                        let kind = self.obj_kind(k)?;
                        let (family, table) = self.table_ref()?;
                        let table_span = self.tspan;
                        let (name, name_span) = self.name()?;
                        let mut obj = self.obj_decl(kind, name)?;
                        obj.name_span = name_span;
                        Cmd::Obj {
                            create,
                            family,
                            table,
                            table_span,
                            obj,
                        }
                    }
                }])
            }
            "insert" | "replace" => {
                if !self.eat_word("rule") {
                    return self.unexpected("keyword rule");
                }
                Ok(vec![self.rule_cmd(if verb == "insert" {
                    RuleOp::Insert
                } else {
                    RuleOp::Replace
                })?])
            }
            "delete" | "destroy" => {
                let destroy = verb == "destroy";
                let kind = self.word("object type")?;
                if kind == "element" {
                    return Ok(vec![self.element_cmd(verb)?]);
                }
                let k = self.kind_of(&kind)?;
                let target = self.target_of(k, true)?;
                Ok(vec![Cmd::Delete {
                    destroy,
                    kind: k,
                    target,
                }])
            }
            "list" => {
                let kind = self.word("object type")?;
                if kind == "ruleset" {
                    let family = self.opt_family();
                    return Ok(vec![Cmd::List {
                        kind: None,
                        all: true,
                        target: Target {
                            family,
                            ..Default::default()
                        },
                    }]);
                }
                let (k, all) = self.plural(&kind)?;
                let target = if all {
                    // `list sets [family]` or `list sets table [family] name`.
                    if k != ObjKind::Table && self.eat_word("table") {
                        let family = self.family();
                        let table_span = self.span();
                        let table = self.word("string or last")?;
                        Target {
                            family: Some(family),
                            table: Some(table),
                            table_span,
                            ..Default::default()
                        }
                    } else {
                        Target {
                            family: self.opt_family(),
                            ..Default::default()
                        }
                    }
                } else {
                    self.target(k)?
                };
                Ok(vec![Cmd::List {
                    kind: Some(k),
                    all,
                    target,
                }])
            }
            "flush" => {
                let kind = self.word("object type")?;
                if kind == "ruleset" {
                    let family = self.opt_family();
                    return Ok(vec![Cmd::Flush {
                        kind: None,
                        target: Target {
                            family,
                            ..Default::default()
                        },
                    }]);
                }
                let k = self.kind_of(&kind)?;
                let target = self.target(k)?;
                Ok(vec![Cmd::Flush {
                    kind: Some(k),
                    target,
                }])
            }
            "reset" => {
                let kind = self.word("object type")?;
                if kind == "element" {
                    return Ok(vec![self.element_cmd(verb)?]);
                }
                let (k, all) = self.plural(&kind)?;
                let target = if all {
                    let family = self.opt_family();
                    let mut t = Target {
                        family,
                        ..Default::default()
                    };
                    if k == ObjKind::Rule {
                        if let Some(w) = self.peek_word().map(str::to_owned) {
                            t.table_span = self.span();
                            self.pos += 1;
                            t.table = Some(w);
                            if let Some(c) = self.peek_word().map(str::to_owned) {
                                t.name_span = self.span();
                                self.pos += 1;
                                t.name = Some(c);
                            }
                        }
                    } else if self.eat_word("table") {
                        t.family = Some(self.family());
                        t.table_span = self.span();
                        t.table = Some(self.word("string or last")?);
                    }
                    t
                } else {
                    self.target(k)?
                };
                Ok(vec![Cmd::Reset {
                    kind: k,
                    all,
                    target,
                }])
            }
            "rename" => {
                self.expect_word("chain")?;
                let target = self.target(ObjKind::Chain)?;
                let new_name = self.word("new chain name")?;
                Ok(vec![Cmd::Rename { target, new_name }])
            }
            "describe" => {
                let e = self.primary()?;
                if !self.at_end() {
                    return self.unexpected("end of file or newline or semicolon");
                }
                Ok(vec![Cmd::Describe(e)])
            }
            "get" => {
                self.expect_word("element")?;
                Ok(vec![self.element_cmd("get")?])
            }
            "monitor" => {
                const OBJECTS: [&str; 7] = [
                    "tables", "chains", "sets", "rules", "elements", "ruleset", "trace",
                ];
                let mut event = None;
                if let Some(w) = self.peek_word() {
                    if !OBJECTS.contains(&w) && !matches!(w, "xml" | "json" | "vm") {
                        if VERBS.contains(&w) {
                            return self.unexpected("end of file or newline or semicolon");
                        }
                        if w != "new" {
                            return self.err(format!("invalid event {w}"));
                        }
                        event = Some(w.to_owned());
                        self.pos += 1;
                    }
                }
                let mut object = None;
                if let Some(w) = self.peek_word() {
                    if OBJECTS.contains(&w) {
                        object = Some(w.to_owned());
                        self.pos += 1;
                    }
                }
                let json = match self.peek_word() {
                    Some("json") => {
                        self.pos += 1;
                        true
                    }
                    Some("xml") => {
                        self.pos += 1;
                        false
                    }
                    Some("vm") => {
                        self.pos += 1;
                        if !self.eat_word("json") {
                            return self.unexpected("keyword json");
                        }
                        true
                    }
                    _ => false,
                };
                if !self.at_end() {
                    return self.unexpected("end of file or newline or semicolon");
                }
                Ok(vec![Cmd::Monitor {
                    event,
                    object,
                    json,
                }])
            }
            _ => self.err(format!("unsupported command `{verb}`")),
        }
    }

    fn kind_of(&mut self, w: &str) -> Result<ObjKind> {
        Ok(match w {
            "table" => ObjKind::Table,
            "chain" => ObjKind::Chain,
            "rule" => ObjKind::Rule,
            "set" => ObjKind::Set,
            "map" => ObjKind::Map,
            "element" => ObjKind::Element,
            "flowtable" => ObjKind::Flowtable,
            "meter" => ObjKind::Meter,
            w => self.obj_kind(w)?,
        })
    }

    fn obj_kind(&mut self, w: &str) -> Result<ObjKind> {
        Ok(match w {
            "counter" => ObjKind::Counter,
            "quota" => ObjKind::Quota,
            "limit" => ObjKind::Limit,
            "synproxy" => ObjKind::Synproxy,
            "secmark" => ObjKind::Secmark,
            "ct" => match self.word("ct object type")?.as_str() {
                "helper" => ObjKind::CtHelper,
                "timeout" => ObjKind::CtTimeout,
                "expectation" => ObjKind::CtExpect,
                _ => return self.err("expected helper, timeout or expectation"),
            },
            _ => return self.err(format!("syntax error, unexpected {w}")),
        })
    }

    /// Kind for `list`/`reset`, accepting plurals.
    fn plural(&mut self, w: &str) -> Result<(ObjKind, bool)> {
        Ok(match w {
            "tables" => (ObjKind::Table, true),
            "chains" => (ObjKind::Chain, true),
            "sets" => (ObjKind::Set, true),
            "maps" => (ObjKind::Map, true),
            "counters" => (ObjKind::Counter, true),
            "quotas" => (ObjKind::Quota, true),
            "limits" => (ObjKind::Limit, true),
            "flowtables" => (ObjKind::Flowtable, true),
            "meters" => (ObjKind::Meter, true),
            "synproxys" => (ObjKind::Synproxy, true),
            "secmarks" => (ObjKind::Secmark, true),
            "rules" => (ObjKind::Rule, true),
            "ct" => {
                let w2 = self.word("ct object type")?;
                match w2.as_str() {
                    "helpers" => (ObjKind::CtHelper, true),
                    "timeouts" => (ObjKind::CtTimeout, true),
                    "expectations" => (ObjKind::CtExpect, true),
                    "helper" => (ObjKind::CtHelper, false),
                    "timeout" => (ObjKind::CtTimeout, false),
                    "expectation" => (ObjKind::CtExpect, false),
                    _ => return self.err("expected ct helper(s), timeout(s) or expectation(s)"),
                }
            }
            w => (self.kind_of(w)?, false),
        })
    }

    /// The target of a delete / list / flush command.
    fn target(&mut self, k: ObjKind) -> Result<Target> {
        self.target_of(k, false)
    }

    /// `delete`/`destroy` targets may also be given by handle.
    fn target_of(&mut self, k: ObjKind, delete: bool) -> Result<Target> {
        let name = if delete {
            "handle or string or last"
        } else {
            "string or last"
        };
        let family = Some(self.family());
        let mut t = Target {
            family,
            ..Default::default()
        };
        if k == ObjKind::Table {
            if let Some(h) = self.handle()? {
                t.handle = Some(h);
                return Ok(t);
            }
            t.table_span = self.span();
            t.table = Some(self.word(name)?);
            return Ok(t);
        }
        t.table_span = self.span();
        t.table = Some(self.word("string or last")?);
        if self.peek_word() == Some("handle") {
            t.handle_span = self.span_at(1);
        }
        if let Some(h) = self.handle()? {
            t.handle = Some(h);
            return Ok(t);
        }
        if k == ObjKind::Rule && delete {
            t.name_span = self.span();
            t.name = Some(self.word("string or last")?);
            t.handle_span = self.span_at(1);
            if !self.eat_word("handle") {
                return self.unexpected("keyword handle");
            }
            t.handle = Some(self.number("handle")?);
            return Ok(t);
        }
        t.name_span = self.span();
        t.name = Some(self.word(name)?);
        if k == ObjKind::Rule || self.peek_word() == Some("handle") {
            t.handle_span = self.span_at(1);
            t.handle = self.handle()?;
        }
        Ok(t)
    }

    fn table_cmd(&mut self, create: bool) -> Result<Cmd> {
        let (family, name) = self.table_ref()?;
        let mut table = Table {
            family,
            name,
            name_span: self.tspan,
            ..Default::default()
        };
        if self.eat_punct("{") {
            self.table_body(&mut table)?;
        }
        Ok(Cmd::Table { create, table })
    }

    fn table_body(&mut self, t: &mut Table) -> Result<()> {
        loop {
            match self.table_item(t) {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(e) => {
                    // A missing `}` at the end of the input ends the block.
                    let eof = self.peek().is_none();
                    self.recover(e)?;
                    if eof {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// One item of a table block; false at its end.
    fn table_item(&mut self, t: &mut Table) -> Result<bool> {
        {
            self.skip_seps();
            if self.eat_punct("}") {
                return Ok(false);
            }
            let start = self.span().start;
            let w = self.word("table item")?;
            let n = t.items.len();
            match w.as_str() {
                "flags" => {
                    t.flags = self.word_list()?;
                    self.end_item()?;
                }
                "comment" => {
                    t.comment = Some(self.string("comment")?);
                    self.end_item()?;
                }
                "chain" => {
                    let (name, name_span) = self.name()?;
                    let mut c = Chain {
                        name,
                        name_span,
                        ..Default::default()
                    };
                    self.expect_punct("{")?;
                    self.chain_body(&mut c)?;
                    t.items.push(TableItem::Chain(c));
                }
                "set" | "map" => {
                    let (name, name_span) = self.name()?;
                    let mut s = Set {
                        name,
                        name_span,
                        is_map: w == "map",
                        ..Default::default()
                    };
                    self.expect_punct("{")?;
                    self.set_body(&mut s)?;
                    t.items.push(TableItem::Set(s));
                }
                "flowtable" => {
                    let (name, name_span) = self.name()?;
                    let mut f = Flowtable {
                        name,
                        name_span,
                        ..Default::default()
                    };
                    self.expect_punct("{")?;
                    self.flowtable_body(&mut f)?;
                    t.items.push(TableItem::Flowtable(f));
                }
                k => {
                    let kind = self.obj_kind(k)?;
                    let (name, name_span) = self.name()?;
                    let mut o = self.obj_decl(kind, name)?;
                    o.name_span = name_span;
                    t.items.push(TableItem::Obj(o));
                }
            }
            if t.items.len() > n {
                let span = Span {
                    start,
                    end: self.prev_end(),
                };
                match t.items.last_mut().unwrap() {
                    TableItem::Chain(c) => c.span = span,
                    TableItem::Set(s) => s.span = span,
                    TableItem::Obj(o) => o.span = span,
                    TableItem::Flowtable(f) => f.span = span,
                }
            }
        }
        Ok(true)
    }

    fn word_list(&mut self) -> Result<Vec<String>> {
        let mut v = vec![self.word("flag")?];
        while self.eat_punct(",") {
            v.push(self.word("flag")?);
        }
        Ok(v)
    }

    fn priority(&mut self) -> Result<Priority> {
        let span = self.span();
        let w = self.word("priority")?;
        if let Ok(n) = w.parse::<i32>() {
            return Ok(Priority {
                name: None,
                offset: n,
            });
        }
        if let Some(h) = w.strip_prefix("0x") {
            if let Ok(n) = i32::from_str_radix(h, 16) {
                return Ok(Priority {
                    name: None,
                    offset: n,
                });
            }
        }
        if !w.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(Error::at(format!("invalid priority `{w}`"), span));
        }
        let mut offset = 0;
        if self.eat_punct("+") {
            offset = self.number::<i32>("priority offset")?;
        } else if self.eat_punct("-") {
            offset = -self.number::<i32>("priority offset")?;
        } else if let Some(n) = self
            .peek_word()
            .and_then(|w| w.strip_prefix('-'))
            .and_then(|n| n.parse::<i32>().ok())
        {
            // `filter -5`
            self.pos += 1;
            offset = -n;
        }
        Ok(Priority {
            name: Some(w),
            offset,
        })
    }

    fn devices(&mut self) -> Result<Vec<String>> {
        let mut v = Vec::new();
        if self.eat_punct("=") || self.is_punct("{") {
            self.expect_punct("{")?;
            loop {
                self.skip_nl();
                if self.eat_punct("}") {
                    break;
                }
                v.push(self.string("device")?);
                self.skip_nl();
                self.eat_punct(",");
            }
        } else {
            v.push(self.string("device")?);
        }
        Ok(v)
    }

    fn chain_body(&mut self, c: &mut Chain) -> Result<()> {
        loop {
            self.skip_seps();
            if self.eat_punct("}") {
                return Ok(());
            }
            match self.peek_word() {
                Some("type") if matches!(self.peek_word_at(2), Some("hook")) => {
                    let start = self.span().start;
                    self.pos += 1;
                    let mut b = c.base.take().unwrap_or_default();
                    b.ty = self.word("chain type")?;
                    self.expect_word("hook")?;
                    b.hook = self.word("hook")?;
                    loop {
                        if self.eat_word("device") {
                            b.devices = vec![self.string("device")?];
                        } else if self.eat_word("devices") {
                            b.devices = self.devices()?;
                        } else if self.eat_word("priority") {
                            b.priority = self.priority()?;
                        } else {
                            break;
                        }
                    }
                    c.base = Some(b);
                    c.base_span = Span {
                        start,
                        end: self.prev_end(),
                    };
                    self.end_item()?;
                }
                Some("policy") => {
                    self.pos += 1;
                    let p = self.word("policy")?;
                    c.base.get_or_insert_with(Default::default).policy = Some(p);
                    self.end_item()?;
                }
                Some("comment")
                    if matches!(self.peek_at(1), Some(Tok::Str(_))) && self.stmt_ends_at(2) =>
                {
                    self.pos += 1;
                    c.comment = Some(self.string("comment")?);
                    self.end_item()?;
                }
                Some("devices") => {
                    self.pos += 1;
                    let d = self.devices()?;
                    c.base.get_or_insert_with(Default::default).devices = d;
                    self.end_item()?;
                }
                _ => match self.rule() {
                    Ok((r, _, _)) => c.rules.push(r),
                    Err(e) => {
                        let eof = self.peek().is_none();
                        self.recover(e)?;
                        if eof {
                            return Ok(());
                        }
                    }
                },
            }
        }
    }

    fn stmt_ends_at(&self, n: usize) -> bool {
        match self.peek_at(n) {
            None | Some(Tok::Newline) => true,
            Some(Tok::Punct(p)) => STMT_END.contains(p),
            _ => false,
        }
    }

    fn time(&mut self) -> Result<u64> {
        let span = self.span();
        let w = self.word("time")?;
        super::datatype::parse_duration(&w).map_err(|e| e.with_span(span))
    }

    fn type_names(&mut self) -> Result<Vec<String>> {
        let mut v = vec![self.type_name()?];
        while self.eat_punct(".") {
            v.push(self.type_name()?);
        }
        Ok(v)
    }

    /// A type name; `type a: b` (no space before the colon) splits the
    /// colon off.
    fn type_name(&mut self) -> Result<String> {
        let w = self.word("type")?;
        if let Some(t) = w.strip_suffix(':') {
            let span = self.toks[self.pos - 1].span;
            self.pos -= 1;
            self.toks[self.pos] = Token {
                tok: Tok::Word(t.to_owned()),
                span: Span {
                    start: span.start,
                    end: span.end - 1,
                },
            };
            self.toks.insert(
                self.pos + 1,
                Token {
                    tok: Tok::Punct(":"),
                    span: Span {
                        start: span.end - 1,
                        end: span.end,
                    },
                },
            );
            self.pos += 1;
            return Ok(t.to_owned());
        }
        Ok(w)
    }

    fn typeof_exprs(&mut self) -> Result<Vec<Expr>> {
        let mut v = vec![self.primary()?];
        while self.eat_punct(".") {
            v.push(self.primary()?);
        }
        Ok(v)
    }

    fn set_body(&mut self, s: &mut Set) -> Result<()> {
        loop {
            self.skip_seps();
            if self.eat_punct("}") {
                return Ok(());
            }
            let w = self.word("set attribute")?;
            match w.as_str() {
                "type" => {
                    s.key = Some(TypeSpec::Type(self.type_names()?));
                    if self.eat_punct(":") {
                        s.data_interval = self.eat_word("interval");
                        s.data = Some(TypeSpec::Type(self.type_names()?));
                    }
                }
                "typeof" => {
                    s.key = Some(TypeSpec::Typeof(self.typeof_exprs()?));
                    if self.eat_punct(":") {
                        s.data_interval = self.eat_word("interval");
                        let d = if self.peek_word() == Some("verdict") {
                            self.pos += 1;
                            TypeSpec::Type(vec!["verdict".into()])
                        } else {
                            TypeSpec::Typeof(self.typeof_exprs()?)
                        };
                        s.data = Some(d);
                    }
                }
                "flags" => s.flags.extend(self.word_list()?),
                "timeout" => s.timeout = Some(self.time()?),
                "gc-interval" => s.gc_interval = Some(self.time()?),
                "size" => s.size = Some(self.number("size")?),
                "policy" => s.policy = Some(self.word("policy")?),
                "auto-merge" => s.auto_merge = true,
                "comment" => s.comment = Some(self.string("comment")?),
                "elements" => {
                    self.expect_punct("=")?;
                    self.expect_punct("{")?;
                    s.elements = Some(self.elements()?);
                }
                "counter" | "quota" | "limit" | "last" | "ct" => {
                    self.pos -= 1;
                    // Several statements may share a line.
                    while matches!(
                        self.peek_word(),
                        Some("counter" | "quota" | "limit" | "last" | "ct")
                    ) {
                        let st = self.stmt()?;
                        s.stmts.push(st);
                    }
                }
                _ => {
                    self.pos -= 1;
                    return self.unexpected("set attribute");
                }
            }
            self.end_item()?;
        }
    }

    fn flowtable_body(&mut self, f: &mut Flowtable) -> Result<()> {
        loop {
            self.skip_seps();
            if self.eat_punct("}") {
                return Ok(());
            }
            let w = self.word("flowtable attribute")?;
            match w.as_str() {
                "hook" => {
                    f.hook = self.word("hook")?;
                    if self.eat_word("priority") {
                        f.priority = self.priority()?;
                    }
                }
                "devices" => f.devices = self.devices()?,
                "counter" => f.counter = true,
                "flags" => {
                    for fl in self.word_list()? {
                        if fl == "offload" {
                            f.offload = true;
                        }
                    }
                }
                _ => {
                    self.pos -= 1;
                    return self.unexpected("flowtable attribute");
                }
            }
            self.end_item()?;
        }
    }

    fn bytes_unit(&mut self) -> Result<u64> {
        let n: u64 = self.number("bytes")?;
        let unit = self.word("unit")?;
        Ok(n * match unit.as_str() {
            "bytes" => 1,
            "kbytes" => 1024,
            "mbytes" => 1024 * 1024,
            "gbytes" => 1024 * 1024 * 1024,
            _ => {
                return self.err(format!(
                    "Wrong unit format `{unit}`, expecting bytes, kbytes or mbytes"
                ));
            }
        })
    }

    fn quota_args(&mut self) -> Result<Quota> {
        let mut q = Quota::default();
        if self.eat_word("over") {
            q.over = true;
        } else {
            self.eat_word("until");
        }
        q.bytes = self.bytes_unit()?;
        if self.eat_word("used") {
            q.used = self.bytes_unit()?;
        }
        Ok(q)
    }

    fn limit_args(&mut self) -> Result<Limit> {
        self.expect_word("rate")?;
        let mut l = Limit {
            over: self.eat_word("over"),
            ..Default::default()
        };
        let span = self.span();
        let w = self.word("rate")?;
        let (rate, rest) = match w.split_once('/') {
            Some((r, per)) => (r.to_owned(), Some(per.to_owned())),
            None => (w, None),
        };
        l.rate = rate.parse().map_err(|_| Error::at("invalid rate", span))?;
        l.per = match rest {
            Some(p) => p,
            None => {
                // `10 kbytes/second` or `10 / second`.
                if self.eat_punct("/") {
                    self.word("time unit")?
                } else {
                    let u = self.word("rate unit")?;
                    let (unit, per) = u
                        .split_once('/')
                        .ok_or_else(|| Error::at("invalid rate unit", span))?;
                    l.rate_unit = Some(unit.to_owned());
                    per.to_owned()
                }
            }
        };
        if self.eat_word("burst") {
            l.burst = Some(self.number("burst")?);
            if let Some(u) = self.peek_word() {
                if matches!(u, "packets" | "bytes" | "kbytes" | "mbytes") {
                    l.burst_unit = Some(u.to_owned());
                    self.pos += 1;
                }
            }
        }
        Ok(l)
    }

    fn obj_decl(&mut self, kind: ObjKind, name: String) -> Result<Obj> {
        let mut comment = None;
        let mut body = match kind {
            ObjKind::Counter => ObjBody::Counter {
                packets: 0,
                bytes: 0,
            },
            ObjKind::Quota => ObjBody::Quota(Quota::default()),
            ObjKind::Limit => ObjBody::Limit(Limit::default()),
            ObjKind::CtHelper => ObjBody::CtHelper {
                helper: String::new(),
                protocol: String::new(),
                l3proto: None,
            },
            ObjKind::CtTimeout => ObjBody::CtTimeout {
                protocol: String::new(),
                l3proto: None,
                policy: Vec::new(),
            },
            ObjKind::CtExpect => ObjBody::CtExpect {
                protocol: String::new(),
                dport: 0,
                timeout: 0,
                size: 0,
                l3proto: None,
            },
            ObjKind::Synproxy => ObjBody::Synproxy {
                mss: 0,
                wscale: 0,
                flags: Vec::new(),
            },
            ObjKind::Secmark => ObjBody::Secmark(String::new()),
            _ => return self.err("unsupported object"),
        };
        if !self.eat_punct("{") {
            // `add quota t q 100 mbytes` style.
            match &mut body {
                ObjBody::Quota(q) if !self.at_end() => *q = self.quota_args()?,
                ObjBody::Limit(l) if !self.at_end() => *l = self.limit_args()?,
                _ => {}
            }
            return Ok(Obj {
                span: Span::default(),
                name_span: Span::default(),
                name,
                handle: None,
                comment,
                body,
            });
        }
        loop {
            self.skip_seps();
            if self.eat_punct("}") {
                break;
            }
            if self.eat_word("comment") {
                comment = Some(self.string("comment")?);
                self.end_item()?;
                continue;
            }
            match &mut body {
                ObjBody::Counter { packets, bytes } => {
                    self.expect_word("packets")?;
                    *packets = self.number("packets")?;
                    self.expect_word("bytes")?;
                    *bytes = self.number("bytes")?;
                }
                ObjBody::Quota(q) => *q = self.quota_args()?,
                ObjBody::Limit(l) => *l = self.limit_args()?,
                ObjBody::CtHelper {
                    helper,
                    protocol,
                    l3proto,
                } => match self.word("ct helper attribute")?.as_str() {
                    "type" => {
                        *helper = self.string("helper")?;
                        self.expect_word("protocol")?;
                        *protocol = self.word("protocol")?;
                    }
                    "l3proto" => *l3proto = Some(self.word("l3proto")?),
                    _ => return self.err("unexpected ct helper attribute"),
                },
                ObjBody::CtTimeout {
                    protocol,
                    l3proto,
                    policy,
                } => match self.word("ct timeout attribute")?.as_str() {
                    "protocol" => *protocol = self.word("protocol")?,
                    "l3proto" => *l3proto = Some(self.word("l3proto")?),
                    "policy" => {
                        self.expect_punct("=")?;
                        self.expect_punct("{")?;
                        loop {
                            self.skip_nl();
                            if self.eat_punct("}") {
                                break;
                            }
                            let state = self.word("state")?;
                            let state = match state.strip_suffix(':') {
                                Some(st) => st.to_owned(),
                                None => {
                                    self.expect_punct(":")?;
                                    state
                                }
                            };
                            let t = self.time()?;
                            policy.push((state, (t / 1000) as u32));
                            self.skip_nl();
                            self.eat_punct(",");
                        }
                    }
                    _ => return self.err("unexpected ct timeout attribute"),
                },
                ObjBody::CtExpect {
                    protocol,
                    dport,
                    timeout,
                    size,
                    l3proto,
                } => match self.word("ct expectation attribute")?.as_str() {
                    "protocol" => *protocol = self.word("protocol")?,
                    "dport" => *dport = self.number("port")?,
                    "timeout" => *timeout = self.time()?,
                    "size" => *size = self.number("size")?,
                    "l3proto" => *l3proto = Some(self.word("l3proto")?),
                    _ => return self.err("unexpected ct expectation attribute"),
                },
                ObjBody::Synproxy { mss, wscale, flags } => {
                    match self.word("synproxy attribute")?.as_str() {
                        "mss" => *mss = self.number("mss")?,
                        "wscale" => *wscale = self.number("wscale")?,
                        f @ ("timestamp" | "sack-perm") => {
                            flags.push(f.to_owned());
                            while let Some(f) = self
                                .peek_word()
                                .filter(|f| matches!(*f, "timestamp" | "sack-perm"))
                                .map(str::to_owned)
                            {
                                self.pos += 1;
                                flags.push(f);
                            }
                        }
                        _ => return self.err("unexpected synproxy attribute"),
                    }
                }
                ObjBody::Secmark(ctx) => *ctx = self.string("security context")?,
            }
            self.end_item()?;
        }
        Ok(Obj {
            span: Span::default(),
            name_span: Span::default(),
            name,
            handle: None,
            comment,
            body,
        })
    }

    fn element_cmd(&mut self, op: &str) -> Result<Cmd> {
        let (family, table) = self.table_ref()?;
        let table_span = self.tspan;
        let (set, set_span) = self.name()?;
        self.expand();
        self.expect_punct("{")?;
        let elems = self.elements()?;
        Ok(Cmd::Element {
            op: op.to_owned(),
            family,
            table,
            table_span,
            set,
            set_span,
            elems,
        })
    }

    fn rule_cmd(&mut self, op: RuleOp) -> Result<Cmd> {
        let (family, table) = self.table_ref()?;
        let table_span = self.tspan;
        let (chain, chain_span) = self.name()?;
        let mut pos_span = self.span_at(1);
        let pos = if self.eat_word("position") {
            Some(RulePos::Position(self.number("handle")?))
        } else if self.eat_word("handle") {
            Some(RulePos::Handle(self.number("handle")?))
        } else if self.peek_word() == Some("index") {
            // (Errors about an index point at `index N`.)
            let start = self.span().start;
            self.pos += 1;
            let i = self.number("index")?;
            pos_span = Span {
                start,
                end: self.prev_end(),
            };
            Some(RulePos::Index(i))
        } else {
            None
        };
        // A rule needs at least one statement.
        if self.at_end() {
            return self.unexpected("statement");
        }
        let (rule, span, stmt_spans) = self.rule()?;
        Ok(Cmd::Rule {
            op,
            family,
            table,
            table_span,
            chain,
            chain_span,
            pos_span,
            pos,
            rule,
            span,
            stmt_spans,
        })
    }

    // ------------------------------------------------------------ elements

    fn elements(&mut self) -> Result<Vec<Elem>> {
        let mut v = Vec::new();
        // (An empty list is an error, as in nft, except from a define.)
        let empty_def = matches!(self.empty_def, Some((p, _)) if p + 1 == self.pos);
        loop {
            self.skip_nl();
            if (empty_def || !v.is_empty()) && self.eat_punct("}") {
                return Ok(v);
            }
            let e = self.elem()?;
            match e {
                // A set variable inside a set contributes its elements.
                Elem {
                    key: Some(Expr::Set(inner)),
                    data: None,
                    ..
                } => v.extend(inner),
                e => v.push(e),
            }
            self.skip_nl();
            if !self.eat_punct(",") {
                self.skip_nl();
                if !self.eat_punct("}") {
                    return self.unexpected("comma or '}'");
                }
                return Ok(v);
            }
        }
    }

    fn elem(&mut self) -> Result<Elem> {
        let start = self.span().start;
        let mut e = Elem {
            key: if self.eat_punct("*") {
                Some(Expr::Wildcard)
            } else {
                Some(self.value_concat()?)
            },
            ..Default::default()
        };
        e.span = Span {
            start,
            end: self.prev_end(),
        };
        loop {
            match self.peek_word() {
                Some("timeout") => {
                    self.pos += 1;
                    e.timeout = Some(self.time()?);
                }
                Some("expires") => {
                    self.pos += 1;
                    e.expires = Some(self.time()?);
                }
                Some("comment") => {
                    self.pos += 1;
                    e.comment = Some(self.string("comment")?);
                }
                Some("counter" | "quota" | "limit" | "last") => {
                    let st = self.stmt()?;
                    e.stmts.push(st);
                }
                _ => break,
            }
        }
        if self.eat_punct(":") {
            e.data = Some(self.map_data()?);
        }
        Ok(e)
    }

    fn map_data(&mut self) -> Result<Expr> {
        if self.peek_word() == Some("queue") {
            return self.unexpected("value");
        }
        if let Some(v) = self.try_verdict()? {
            return Ok(Expr::Verdict(v));
        }
        self.value_concat()
    }

    fn try_verdict(&mut self) -> Result<Option<Verdict>> {
        Ok(Some(match self.peek_word() {
            Some("accept") => {
                self.pos += 1;
                Verdict::Accept
            }
            Some("drop") => {
                self.pos += 1;
                Verdict::Drop
            }
            Some("continue") => {
                self.pos += 1;
                Verdict::Continue
            }
            Some("return") => {
                self.pos += 1;
                Verdict::Return
            }
            Some("jump") | Some("goto") => {
                let goto = self.peek_word() == Some("goto");
                self.pos += 1;
                if self.eat_punct("{") {
                    let mut rules = Vec::new();
                    loop {
                        self.skip_seps();
                        if self.eat_punct("}") {
                            break;
                        }
                        rules.push(self.rule()?.0);
                    }
                    if goto {
                        Verdict::GotoBlock(rules)
                    } else {
                        Verdict::JumpBlock(rules)
                    }
                } else {
                    let c = self.word("chain name")?;
                    if goto {
                        Verdict::Goto(c)
                    } else {
                        Verdict::Jump(c)
                    }
                }
            }
            _ => return Ok(None),
        }))
    }

    // ------------------------------------------------------------ rules

    fn rule(&mut self) -> Result<(Rule, Span, Vec<Span>)> {
        // (A block left open at the end of the input.)
        if self.peek().is_none() {
            return self.unexpected("");
        }
        let start = self.span().start;
        let mut r = Rule::default();
        let mut spans = Vec::new();
        let mut terminal: Option<Span> = None;
        while !self.at_end() {
            // Command keywords start no statement.
            const NOT_STMTS: &[&str] = &[
                "ruleset",
                "table",
                "chain",
                "rule",
                "element",
                "elements",
                "flowtable",
                "tables",
                "chains",
                "sets",
                "maps",
                "list",
                "create",
                "insert",
                "replace",
                "destroy",
                "flush",
                "reset",
                "rename",
                "describe",
                "monitor",
                "hook",
                "priority",
                "policy",
                "typeof",
            ];
            let punct = matches!(self.peek(), Some(Tok::Punct(p)) if *p != "(");
            if self.peek_word().is_some_and(|w| NOT_STMTS.contains(&w)) || punct {
                return if r.stmts.is_empty() {
                    self.unexpected("statement")
                } else {
                    self.unexpected("end of file or newline or semicolon")
                };
            }
            if self.peek_word() == Some("comment")
                && matches!(self.peek_at(1), Some(Tok::Str(_) | Tok::Word(_)))
            {
                self.pos += 1;
                r.comment = Some(self.string("comment")?);
                if !self.at_end() {
                    return self.unexpected("end of file or newline or semicolon");
                }
                continue;
            }
            let s = self.span().start;
            let start_tok = self.pos;
            let st = self.stmt()?;
            // Errors about jumps and named objects point at the name.
            let s = if matches!(st, Stmt::Verdict(Verdict::Jump(_) | Verdict::Goto(_)))
                || matches!(
                    &st,
                    Stmt::Objref {
                        name: Expr::Value(_),
                        ..
                    }
                ) {
                self.toks[self.pos - 1].span.start
            } else {
                s
            };
            let sp = Span {
                start: s,
                end: self.prev_end(),
            };
            // Nothing can follow a verdict.
            if let Some(t) = terminal {
                let mut e = Error::at("Statement after terminal statement has no effect", sp);
                e.related = Some(super::error::Related::Span(t));
                return Err(e);
            }
            if matches!(&st, Stmt::Verdict(v) if !matches!(v, Verdict::Continue))
                || matches!(st, Stmt::Reject { .. })
            {
                terminal = Some(Span {
                    start: self.toks[start_tok].span.start,
                    end: sp.end,
                });
            }
            spans.push(sp);
            r.stmts.push(st);
        }
        let end = self.prev_end().max(start);
        r.span = Span { start, end };
        r.stmt_spans = spans.clone();
        // A `}` closes the enclosing block; leave it.
        if matches!(self.peek(), Some(Tok::Newline) | Some(Tok::Punct(";"))) {
            self.pos += 1;
        }
        Ok((r, Span { start, end }, spans))
    }

    fn stmt(&mut self) -> Result<Stmt> {
        self.expand();
        if let Some(v) = self.try_verdict()? {
            return Ok(Stmt::Verdict(v));
        }
        let Some(w) = self.peek_word().map(str::to_owned) else {
            return self.match_stmt();
        };
        match w.as_str() {
            "counter" => {
                self.pos += 1;
                if self.eat_word("name") {
                    let name = self.objref_name()?;
                    return Ok(Stmt::Objref {
                        kind: "counter".into(),
                        name,
                    });
                }
                let (mut p, mut b) = (None, None);
                if self.eat_word("packets") {
                    p = Some(self.number("packets")?);
                }
                if self.eat_word("bytes") {
                    b = Some(self.number("bytes")?);
                }
                Ok(Stmt::Counter {
                    packets: p,
                    bytes: b,
                })
            }
            "limit" => {
                self.pos += 1;
                if self.eat_word("name") {
                    return Ok(Stmt::Objref {
                        kind: "limit".into(),
                        name: self.objref_name()?,
                    });
                }
                Ok(Stmt::Limit(self.limit_args()?))
            }
            "quota" => {
                self.pos += 1;
                if self.eat_word("name") {
                    return Ok(Stmt::Objref {
                        kind: "quota".into(),
                        name: self.objref_name()?,
                    });
                }
                Ok(Stmt::Quota(self.quota_args()?))
            }
            "synproxy" if self.peek_word_at(1) == Some("name") => {
                self.pos += 2;
                Ok(Stmt::Objref {
                    kind: "synproxy".into(),
                    name: self.objref_name()?,
                })
            }
            "synproxy" => {
                self.pos += 1;
                let (mut mss, mut wscale, mut flags) = (None, None, Vec::new());
                loop {
                    match self.peek_word() {
                        Some("mss") => {
                            self.pos += 1;
                            mss = Some(self.number("mss")?);
                        }
                        Some("wscale") => {
                            self.pos += 1;
                            wscale = Some(self.number("wscale")?);
                        }
                        Some(f @ ("timestamp" | "sack-perm")) => {
                            flags.push(f.to_owned());
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                Ok(Stmt::Synproxy { mss, wscale, flags })
            }
            "log" => {
                self.pos += 1;
                let mut l = Log::default();
                loop {
                    match self.peek_word() {
                        Some("prefix") => {
                            self.pos += 1;
                            l.prefix = Some(self.string("prefix")?);
                        }
                        Some("group") => {
                            self.pos += 1;
                            l.group = Some(self.number("group")?);
                        }
                        Some("snaplen") => {
                            self.pos += 1;
                            l.snaplen = Some(self.number("snaplen")?);
                        }
                        Some("queue-threshold") => {
                            self.pos += 1;
                            l.qthreshold = Some(self.number("queue-threshold")?);
                        }
                        Some("level") => {
                            self.pos += 1;
                            l.level = Some(self.word("level")?);
                        }
                        Some("flags") => {
                            self.pos += 1;
                            let mut parts = Vec::new();
                            loop {
                                match self.peek_word() {
                                    Some("tcp") => {
                                        self.pos += 1;
                                        let mut v = vec![self.word("tcp log flag")?];
                                        while self.eat_punct(",") {
                                            v.push(self.word("tcp log flag")?);
                                        }
                                        parts.push(format!("tcp {}", v.join(",")));
                                    }
                                    Some("ip") => {
                                        self.pos += 1;
                                        self.expect_word("options")?;
                                        parts.push("ip options".into());
                                    }
                                    Some(f @ ("skuid" | "ether" | "all")) => {
                                        parts.push(f.to_owned());
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                                self.eat_punct(",");
                            }
                            // `flags` may be given several times.
                            let joined = parts.join(" ");
                            l.flags = Some(match l.flags.take() {
                                Some(prev) => format!("{prev} {joined}"),
                                None => joined,
                            });
                        }
                        _ => break,
                    }
                }
                Ok(Stmt::Log(l))
            }
            "ct" => match self.peek_word_at(1) {
                Some("count") => {
                    self.pos += 2;
                    let over = self.eat_word("over");
                    Ok(Stmt::Connlimit {
                        count: self.number("count")?,
                        over,
                    })
                }
                Some(k @ ("helper" | "timeout" | "expectation"))
                    if self.peek_word_at(2) == Some("set") =>
                {
                    let kind = format!("ct {k}");
                    self.pos += 3;
                    Ok(Stmt::Objref {
                        kind,
                        name: self.objref_name()?,
                    })
                }
                _ => self.match_stmt(),
            },
            "last" => {
                self.pos += 1;
                if self.eat_word("used") {
                    if self.eat_word("never") {
                        return Ok(Stmt::Last { used: None });
                    }
                    return Ok(Stmt::Last {
                        used: Some(self.time()?),
                    });
                }
                Ok(Stmt::Last { used: None })
            }
            "reject" => {
                self.pos += 1;
                if !self.eat_word("with") {
                    return Ok(Stmt::Reject {
                        with: None,
                        code: None,
                    });
                }
                let ty = self.word("reject type")?;
                if ty == "tcp" {
                    self.expect_word("reset")?;
                    return Ok(Stmt::Reject {
                        with: Some("tcp reset".into()),
                        code: None,
                    });
                }
                self.eat_word("type");
                let code = self.word("reject code")?;
                Ok(Stmt::Reject {
                    with: Some(ty),
                    code: Some(code),
                })
            }
            "snat" | "dnat" | "masquerade" | "redirect" => {
                self.pos += 1;
                let kind = match w.as_str() {
                    "snat" => NatKind::Snat,
                    "dnat" => NatKind::Dnat,
                    "masquerade" => NatKind::Masquerade,
                    _ => NatKind::Redirect,
                };
                let family = match self.peek_word() {
                    Some(f @ ("ip" | "ip6")) if matches!(kind, NatKind::Snat | NatKind::Dnat) => {
                        let f = f.to_owned();
                        self.pos += 1;
                        Some(f)
                    }
                    _ => None,
                };
                let (mut addr, mut port) = (None, None);
                if self.eat_word("to") {
                    let (a, p) = self.addr_port(family.as_deref() == Some("ip6"))?;
                    addr = a;
                    port = p;
                }
                let mut flags = Vec::new();
                while let Some(f) = self
                    .peek_word()
                    .filter(|f| matches!(*f, "random" | "fully-random" | "persistent" | "netmap"))
                    .map(str::to_owned)
                {
                    self.pos += 1;
                    flags.push(f);
                    self.eat_punct(",");
                }
                Ok(Stmt::Nat {
                    kind,
                    family,
                    addr,
                    port,
                    flags,
                })
            }
            "tproxy" => {
                self.pos += 1;
                let family = match self.peek_word() {
                    Some(f @ ("ip" | "ip6")) => {
                        let f = f.to_owned();
                        self.pos += 1;
                        Some(f)
                    }
                    _ => None,
                };
                self.expect_word("to")?;
                let (addr, port) = self.addr_port(family.as_deref() == Some("ip6"))?;
                Ok(Stmt::Tproxy { family, addr, port })
            }
            "queue" => {
                self.pos += 1;
                let mut flags = Vec::new();
                let mut num = None;
                loop {
                    match self.peek_word() {
                        Some("flags") => {
                            self.pos += 1;
                            flags = self.word_list()?;
                        }
                        Some(f @ ("bypass" | "fanout")) => {
                            flags.push(f.to_owned());
                            self.pos += 1;
                        }
                        Some("num") | Some("to") => {
                            self.pos += 1;
                            num = Some(self.expr()?);
                        }
                        _ => break,
                    }
                    self.eat_punct(",");
                }
                Ok(Stmt::Queue { flags, num })
            }
            "dup" => {
                self.pos += 1;
                self.expect_word("to")?;
                let first = self.expr()?;
                if self.eat_word("device") {
                    let dev = self.expr()?;
                    return Ok(Stmt::Dup {
                        addr: Some(first),
                        dev: Some(dev),
                    });
                }
                Ok(Stmt::Dup {
                    addr: Some(first),
                    dev: None,
                })
            }
            "fwd" => {
                self.pos += 1;
                let family = match self.peek_word() {
                    Some(f @ ("ip" | "ip6")) => {
                        let f = f.to_owned();
                        self.pos += 1;
                        Some(f)
                    }
                    _ => None,
                };
                self.expect_word("to")?;
                let first = self.expr()?;
                if self.eat_word("device") {
                    let dev = self.expr()?;
                    return Ok(Stmt::Fwd {
                        family,
                        addr: Some(first),
                        dev,
                    });
                }
                Ok(Stmt::Fwd {
                    family,
                    addr: None,
                    dev: first,
                })
            }
            "notrack" => {
                self.pos += 1;
                Ok(Stmt::Notrack)
            }
            "flow" => {
                self.pos += 1;
                if !self.eat_word("add") {
                    self.expect_word("offload")?;
                }
                match self.next() {
                    Some(Tok::At(n)) => Ok(Stmt::Flow(n)),
                    _ => self.err("expected @flowtable"),
                }
            }
            "meter" => {
                self.pos += 1;
                let name = self.word("meter name")?;
                let size = if self.eat_word("size") {
                    Some(self.number("size")?)
                } else {
                    None
                };
                self.expect_punct("{")?;
                let key = self.expr_concat()?;
                let (timeout, stmts) = self.set_stmt_args()?;
                self.expect_punct("}")?;
                Ok(Stmt::Meter {
                    name,
                    size,
                    key,
                    timeout,
                    stmts,
                })
            }
            // Old syntax: `set add|update <key> [timeout T] @set`.
            "set" if matches!(self.peek_word_at(1), Some("add" | "update")) => {
                self.pos += 1;
                let op = self.word("set operation")?;
                let key = self.expr_concat()?;
                let (timeout, stmts) = self.set_stmt_args()?;
                let set = match self.next() {
                    Some(Tok::At(n)) => n,
                    _ => {
                        self.pos -= 1;
                        return self.unexpected("'@'");
                    }
                };
                Ok(Stmt::SetUpdate {
                    op,
                    set,
                    key,
                    data: None,
                    timeout,
                    stmts,
                })
            }
            "add" | "update" | "delete" if matches!(self.peek_at(1), Some(Tok::At(_))) => {
                self.pos += 1;
                let Some(Tok::At(set)) = self.next() else {
                    unreachable!()
                };
                self.expect_punct("{")?;
                let key = self.expr_concat()?;
                let (timeout, stmts) = self.set_stmt_args()?;
                let data = if self.eat_punct(":") {
                    // (No verdicts.)
                    if self.peek_word().is_some_and(|w| {
                        matches!(
                            w,
                            "accept" | "drop" | "continue" | "return" | "jump" | "goto"
                        )
                    }) {
                        return self.unexpected("value");
                    }
                    Some(self.expr()?)
                } else {
                    None
                };
                self.expect_punct("}")?;
                Ok(Stmt::SetUpdate {
                    op: w,
                    set,
                    key,
                    data,
                    timeout,
                    stmts,
                })
            }
            "mark" | "priority" | "nftrace" if self.peek_word_at(1) == Some("set") => {
                // Deprecated unqualified meta statements.
                self.pos += 2;
                Ok(Stmt::MetaSet {
                    key: w,
                    value: self.expr()?,
                })
            }
            "xt" => {
                let start = self.pos;
                while !self.at_end() {
                    self.pos += 1;
                }
                let text: Vec<String> = self.toks[start..self.pos]
                    .iter()
                    .map(|t| format!("{:?}", t.tok))
                    .collect();
                Ok(Stmt::Opaque(text.join(" ")))
            }
            _ => self.match_stmt(),
        }
    }

    /// `[timeout T] [stmts...]` after the key of a set update.
    fn set_stmt_args(&mut self) -> Result<(Option<u64>, Vec<Stmt>)> {
        let mut timeout = None;
        let mut stmts = Vec::new();
        loop {
            match self.peek_word() {
                Some("timeout") => {
                    self.pos += 1;
                    timeout = Some(self.time()?);
                }
                Some("counter" | "limit" | "quota" | "ct" | "last") => stmts.push(self.stmt()?),
                _ => break,
            }
        }
        Ok((timeout, stmts))
    }

    fn objref_name(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(Expr::Value(super::ast::Value::Raw(format!("\"{s}\""))))
            }
            _ => self.expr(),
        }
    }

    /// `addr[:port]`, `:port`, `[v6addr]:port`, `addr map {...}`, ...
    fn addr_port(&mut self, v6: bool) -> Result<(Option<Expr>, Option<Expr>)> {
        // `to :1000-2000`
        if self.eat_punct(":") {
            return Ok((None, Some(self.expr()?)));
        }
        if let Some(w) = self.peek_word().map(str::to_owned) {
            if let Some(p) = w.strip_prefix(':') {
                self.pos += 1;
                return Ok((None, Some(Expr::raw(p))));
            }
            // `[addr]:port` / `addr:port` (not for plain v6 addresses).
            if let Some(rest) = w.strip_prefix('[') {
                if let Some((a, p)) = rest.split_once("]:") {
                    self.pos += 1;
                    return Ok((Some(Expr::raw(a)), Some(Expr::raw(p))));
                }
                if let Some(a) = rest.strip_suffix(']') {
                    self.pos += 1;
                    return Ok((Some(Expr::raw(a)), None));
                }
            }
            let colons = w.matches(':').count();
            if !v6 && colons == 1 && !w.contains("::") {
                let (a, p) = w.split_once(':').unwrap();
                self.pos += 1;
                let a = if a.is_empty() {
                    None
                } else {
                    Some(Expr::raw(a))
                };
                return Ok((a, Some(Expr::raw(p))));
            }
        }
        let a = self.expr()?;
        let port = if self.eat_punct(":") {
            Some(self.expr()?)
        } else {
            None
        };
        Ok((Some(a), port))
    }

    fn match_stmt(&mut self) -> Result<Stmt> {
        let left = self.expr()?;
        if self.eat_word("set") {
            let value = self.set_value()?;
            return Ok(match left {
                // `meta secmark set` refers to a secmark object.
                Expr::Meta(key) if key == "secmark" => Stmt::Objref {
                    kind: "secmark".into(),
                    name: match value {
                        Expr::Value(Value::Raw(s)) if !s.starts_with('"') => {
                            Expr::raw(format!("\"{s}\""))
                        }
                        v => v,
                    },
                },
                Expr::Meta(key) => Stmt::MetaSet { key, value },
                Expr::Ct { dir, key } => Stmt::CtSet { key, dir, value },
                target => Stmt::PayloadSet { target, value },
            });
        }
        if self.eat_word("vmap") {
            let map = self.rhs()?;
            return Ok(Stmt::Vmap { key: left, map });
        }
        let op = self.relop();
        if self.at_end() {
            return self.unexpected("value");
        }
        // Statement keywords are no values.
        const NOT_VALUES: &[&str] = &[
            "accept",
            "drop",
            "continue",
            "return",
            "jump",
            "goto",
            "counter",
            "log",
            "limit",
            "quota",
            "reject",
            "masquerade",
            "redirect",
            "notrack",
            "dup",
            "fwd",
            "comment",
            "vmap",
            "synproxy",
            "tproxy",
        ];
        if self.peek_word().is_some_and(|w| NOT_VALUES.contains(&w)) {
            return self.unexpected("value");
        }
        let right = self.rhs()?;
        // `x value / mask` is `x & mask == value`.
        if self.eat_punct("/") {
            let mask = self.rhs()?;
            return Ok(Stmt::Match {
                left: Expr::Binop(BinOp::And, Box::new(left), Box::new(mask)),
                op: if op == RelOp::Implicit { RelOp::Eq } else { op },
                right,
            });
        }
        Ok(Stmt::Match { left, op, right })
    }

    /// The value of a `... set <value>` statement: an expression or a
    /// value (list).
    fn set_value(&mut self) -> Result<Expr> {
        self.expand();
        if self.starts_expression() || self.is_punct("(") {
            return self.expr();
        }
        self.rhs()
    }

    fn relop(&mut self) -> RelOp {
        let op = match self.peek() {
            Some(Tok::Punct("==")) => RelOp::Eq,
            Some(Tok::Punct("!=")) => RelOp::Neq,
            Some(Tok::Punct("<")) => RelOp::Lt,
            Some(Tok::Punct(">")) => RelOp::Gt,
            Some(Tok::Punct("<=")) => RelOp::Lte,
            Some(Tok::Punct(">=")) => RelOp::Gte,
            Some(Tok::Word(w)) => match w.as_str() {
                "eq" => RelOp::Eq,
                "ne" => RelOp::Neq,
                "lt" => RelOp::Lt,
                "gt" => RelOp::Gt,
                "le" => RelOp::Lte,
                "ge" => RelOp::Gte,
                _ => return RelOp::Implicit,
            },
            _ => return RelOp::Implicit,
        };
        self.pos += 1;
        op
    }

    // ------------------------------------------------------------ expressions

    fn binop_of(&self) -> Option<BinOp> {
        match self.peek() {
            Some(Tok::Punct("&")) => Some(BinOp::And),
            Some(Tok::Punct("|")) => Some(BinOp::Or),
            Some(Tok::Punct("^")) => Some(BinOp::Xor),
            Some(Tok::Punct("<<")) => Some(BinOp::Lshift),
            Some(Tok::Punct(">>")) => Some(BinOp::Rshift),
            Some(Tok::Word(w)) => match w.as_str() {
                "and" => Some(BinOp::And),
                "or" => Some(BinOp::Or),
                "xor" => Some(BinOp::Xor),
                "lshift" => Some(BinOp::Lshift),
                "rshift" => Some(BinOp::Rshift),
                _ => None,
            },
            _ => None,
        }
    }

    /// A full expression: concatenation, bit operations, map lookup.
    fn expr(&mut self) -> Result<Expr> {
        let mut e = self.expr_concat()?;
        if self.eat_word("map") {
            let m = self.rhs()?;
            e = Expr::Map(Box::new(e), Box::new(m));
        }
        Ok(e)
    }

    fn operand(&mut self) -> Result<Expr> {
        if self.eat_punct("(") {
            let e = self.expr()?;
            self.expect_punct(")")?;
            return Ok(e);
        }
        self.primary()
    }

    /// A concatenation of expressions with bit operations, which bind
    /// tighter than `.` (`ip saddr & 255.255.255.0 . tcp dport`).
    fn expr_concat(&mut self) -> Result<Expr> {
        let first = self.binop_expr()?;
        if !self.is_punct(".") {
            return Ok(first);
        }
        let mut v = vec![first];
        while self.eat_punct(".") {
            v.push(self.binop_expr()?);
        }
        Ok(Expr::Concat(v))
    }

    fn binop_expr(&mut self) -> Result<Expr> {
        let mut e = self.primary()?;
        while let Some(op) = self.binop_of() {
            self.pos += 1;
            let r = self.operand()?;
            e = Expr::Binop(op, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    /// Right hand side of a match: values, lists, sets, references.
    fn rhs(&mut self) -> Result<Expr> {
        self.expand();
        let mut e = match self.peek() {
            Some(Tok::Punct("{")) => {
                self.pos += 1;
                let elems = self.elements()?;
                if elems.is_empty() {
                    let span = self.empty_def.map_or(self.span(), |(_, s)| s);
                    return Err(Error::at("Set is empty", span));
                }
                Expr::Set(elems)
            }
            Some(Tok::At(_)) => {
                let Some(Tok::At(n)) = self.next() else {
                    unreachable!()
                };
                Expr::SetRef(n)
            }
            _ => {
                let v = self.value_concat()?;
                if self.is_punct(",") {
                    let mut items = vec![v];
                    while self.eat_punct(",") {
                        items.push(self.value()?);
                    }
                    Expr::List(items)
                } else {
                    v
                }
            }
        };
        while let Some(op) = self.binop_of() {
            self.pos += 1;
            let r = self.operand()?;
            e = Expr::Binop(op, Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    /// A concatenation of values (`1.2.3.4 . 80`).
    fn value_concat(&mut self) -> Result<Expr> {
        let first = self.value()?;
        if !self.is_punct(".") {
            return Ok(first);
        }
        let mut v = vec![first];
        while self.eat_punct(".") {
            v.push(self.value()?);
        }
        Ok(Expr::Concat(v))
    }

    /// A single value (or a parenthesized expression).
    fn value(&mut self) -> Result<Expr> {
        self.expand();
        match self.peek().cloned() {
            Some(Tok::Punct("(")) => {
                self.pos += 1;
                let e = self.rhs()?;
                self.expect_punct(")")?;
                Ok(e)
            }
            Some(Tok::Punct("*")) => {
                self.pos += 1;
                Ok(Expr::Wildcard)
            }
            Some(Tok::Punct("{")) => {
                self.pos += 1;
                Ok(Expr::Set(self.elements()?))
            }
            Some(Tok::At(n)) => {
                self.pos += 1;
                Ok(Expr::SetRef(n))
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                let a = Expr::raw(format!("\"{s}\""));
                if self.is_punct("-") && matches!(self.peek_at(1), Some(Tok::Str(_))) {
                    self.pos += 1;
                    let b = self.value()?;
                    return Ok(Expr::Range(Box::new(a), Box::new(b)));
                }
                Ok(a)
            }
            Some(Tok::Word(_)) => {
                // Expressions are allowed as values (e.g. map data `meta mark`).
                if self.starts_expression() {
                    return self.primary();
                }
                let w = self.word("value")?;
                Ok(Expr::raw(w))
            }
            Some(Tok::Punct("-")) => {
                self.pos += 1;
                let w = self.word("value")?;
                Ok(Expr::raw(format!("-{w}")))
            }
            _ => self.unexpected("value"),
        }
    }

    fn starts_expression(&self) -> bool {
        let Some(w) = self.peek_word() else {
            return false;
        };
        let next = self.peek_word_at(1);
        match w {
            "meta" | "ct" | "numgen" | "jhash" | "symhash" | "fib" | "rt" | "socket" | "osf"
            | "ipsec" | "exthdr" => true,
            "iifname" | "oifname" | "iif" | "oif" | "iifgroup" | "oifgroup" => true,
            _ => proto::proto(w).is_some_and(|p| {
                next.is_some_and(|n| {
                    p.field(n).is_some() || matches!(n, "saddr" | "daddr" | "option" | "chunk")
                })
            }),
        }
    }

    /// A primary expression (left hand side of matches).
    fn primary(&mut self) -> Result<Expr> {
        self.expand();
        match self.peek().cloned() {
            Some(Tok::At(spec)) => {
                self.pos += 1;
                let parts: Vec<&str> = spec.split(',').collect();
                if parts.len() == 3 {
                    let n = |s: &str| {
                        s.parse::<u32>()
                            .map_err(|_| Error::msg(format!("invalid raw payload `@{spec}`")))
                    };
                    return Ok(Expr::Raw {
                        base: parts[0].to_owned(),
                        offset: n(parts[1])?,
                        len: n(parts[2])?,
                    });
                }
                Ok(Expr::SetRef(spec))
            }
            Some(Tok::Punct("(")) => {
                self.pos += 1;
                let e = self.expr()?;
                self.expect_punct(")")?;
                Ok(e)
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                self.primary_word(&w)
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Ok(Expr::raw(format!("\"{s}\"")))
            }
            _ => self.unexpected("expression"),
        }
    }

    fn primary_word(&mut self, w: &str) -> Result<Expr> {
        let ip6_ext = |n: &str| super::decompile::IP6_EXTHDRS.iter().any(|h| h.name == n);
        match w {
            "meta" => {
                let start = self.toks[self.pos - 1].span.start;
                let k = self.word("meta key")?;
                let k = match k.as_str() {
                    "secpath" => "ipsec".to_owned(),
                    _ => k,
                };
                if proto::meta(&k).is_none() {
                    let keys: Vec<&str> = proto::METAS.iter().map(|m| m.name).collect();
                    return Err(Error::at(
                        format!(
                            "syntax error, unexpected {k}, known keys are {}",
                            keys.join(", ")
                        ),
                        Span {
                            start,
                            end: self.prev_end(),
                        },
                    ));
                }
                Ok(Expr::Meta(k))
            }
            "iifname" | "oifname" | "iif" | "oif" | "iifgroup" | "oifgroup" | "iiftype"
            | "oiftype" | "skuid" | "skgid" | "nfproto" | "l4proto" | "rtclassid" | "pkttype"
            | "cpu" | "cgroup" | "ibrname" | "obrname" => Ok(Expr::Meta(w.to_owned())),
            "mark" if self.peek_word() != Some("set") => Ok(Expr::Meta("mark".into())),
            "ct" => {
                let mut dir = None;
                if let Some(d @ ("original" | "reply")) = self.peek_word() {
                    dir = Some(d.to_owned());
                    self.pos += 1;
                }
                let mut key = self.word("ct key")?;
                if matches!(key.as_str(), "ip" | "ip6") {
                    let f = self.word("ct address key")?;
                    key = format!("{key} {f}");
                }
                Ok(Expr::Ct { dir, key })
            }
            "exthdr" => {
                // `exthdr <name>` only tests for presence; fields are
                // written `<name> <field>`.
                let name = self.word("extension header")?;
                Ok(Expr::Exthdr {
                    desc: format!("exthdr {name}"),
                    field: None,
                    exists: true,
                })
            }
            n if ip6_ext(n)
                && self.peek_word().is_some_and(|f| f != "exists")
                && !matches!(n, "rt") =>
            {
                let field = self.word("field")?;
                Ok(Expr::Exthdr {
                    desc: n.to_owned(),
                    field: Some(field),
                    exists: false,
                })
            }
            "tcp" if self.peek_word() == Some("option") => self.option_expr("tcp option"),
            "ip" if self.peek_word() == Some("option") => self.option_expr("ip option"),
            "sctp" if self.peek_word() == Some("chunk") => self.option_expr("sctp chunk"),
            "fib" => {
                let mut flags = vec![self.word("fib flag")?];
                while self.eat_punct(".") {
                    flags.push(self.word("fib flag")?);
                }
                let result = self.word("fib result")?;
                Ok(Expr::Fib { flags, result })
            }
            "numgen" => {
                let mode = self.word("numgen mode")?;
                self.expect_word("mod")?;
                let modulus = self.number("modulus")?;
                let offset = if self.eat_word("offset") {
                    self.number("offset")?
                } else {
                    0
                };
                Ok(Expr::Numgen {
                    mode,
                    modulus,
                    offset,
                })
            }
            "jhash" | "symhash" => {
                let input = if w == "jhash" {
                    Some(Box::new(self.expr_concat()?))
                } else {
                    None
                };
                self.expect_word("mod")?;
                let modulus = self.number("modulus")?;
                let mut seed = None;
                let mut offset = 0;
                loop {
                    if self.eat_word("seed") {
                        seed = Some(self.number("seed")?);
                    } else if self.eat_word("offset") {
                        offset = self.number("offset")?;
                    } else {
                        break;
                    }
                }
                Ok(Expr::Hash {
                    input,
                    modulus,
                    seed,
                    offset,
                })
            }
            "osf" => {
                let mut ttl = None;
                if self.eat_word("ttl") {
                    ttl = Some(self.word("ttl mode")?);
                }
                let version = self.word("osf key")? == "version";
                Ok(Expr::Osf { ttl, version })
            }
            "socket" => {
                let key = self.word("socket key")?;
                let level = if self.eat_word("level") {
                    Some(self.number("level")?)
                } else {
                    None
                };
                Ok(Expr::Socket { key, level })
            }
            "rt" => {
                let mut k = self.word("rt key")?;
                if matches!(k.as_str(), "ip" | "ip6") {
                    let f = self.word("rt key")?;
                    k = format!("{k} {f}");
                }
                Ok(Expr::Rt(k))
            }
            "ipsec" => {
                let dir = self.word("ipsec direction")?;
                let mut spnum = 0;
                if self.eat_word("spnum") {
                    spnum = self.number("spnum")?;
                }
                let mut key = self.word("ipsec key")?;
                if matches!(key.as_str(), "ip" | "ip6") {
                    let f = self.word("ipsec key")?;
                    key = format!("{key} {f}");
                }
                Ok(Expr::Ipsec { dir, spnum, key })
            }
            p if proto::proto(p).is_some() && self.peek_word().is_some() => {
                let pr = proto::proto(p).unwrap();
                let mut f = self.peek_word().unwrap().to_owned();
                if pr.name == "arp" && matches!(f.as_str(), "saddr" | "daddr") {
                    self.pos += 1;
                    let kind = self.word("arp address type")?;
                    f = format!("{f} {kind}");
                } else if pr.field(&f).is_some() {
                    self.pos += 1;
                } else if !self.stmt_ends_at(0) && !STMT_KEYWORDS.contains(&f.as_str()) {
                    // `tcp ports`: not a field of the protocol.
                    return self.unexpected("field");
                } else {
                    return Ok(Expr::raw(w));
                }
                Ok(Expr::Payload {
                    proto: p.to_owned(),
                    field: f,
                })
            }
            _ => Ok(Expr::raw(w)),
        }
    }

    fn option_expr(&mut self, kind: &str) -> Result<Expr> {
        self.pos += 1; // `option` / `chunk`
        let name = self.word("option name")?;
        let desc = format!("{kind} {name}");
        match self.peek_word() {
            Some("exists") | Some("missing") => Ok(Expr::Exthdr {
                desc,
                field: None,
                exists: true,
            }),
            Some(f)
                if !self.stmt_ends_at(0)
                    && !matches!(
                        f,
                        "set" | "accept" | "drop" | "counter" | "vmap" | "map" | "eq" | "ne"
                    ) =>
            {
                let f = f.to_owned();
                self.pos += 1;
                Ok(Expr::Exthdr {
                    desc,
                    field: Some(f),
                    exists: false,
                })
            }
            _ => Ok(Expr::Exthdr {
                desc,
                field: None,
                exists: true,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_then_command() {
        for t in [
            "add rule ip t c accept\nadd table ip x\n",
            "add rule ip t c accept; add table ip x",
            "add t c counter\nadd table ip x",
        ] {
            assert_eq!(parse(t).unwrap().len(), 2, "{t}");
        }
    }

    #[test]
    fn commands() {
        let c = parse(
            "add rule inet t c tcp dport { 22, 80 } ct state new counter accept comment \"x\"",
        )
        .unwrap();
        let Cmd::Rule {
            family,
            table,
            chain,
            rule,
            stmt_spans,
            ..
        } = &c[0]
        else {
            panic!()
        };
        assert_eq!(
            (*family, table.as_str(), chain.as_str()),
            (Family::Inet, "t", "c")
        );
        assert_eq!(rule.stmts.len(), 4);
        assert_eq!(rule.comment.as_deref(), Some("x"));
        assert_eq!(stmt_spans.len(), 4);
        let c = parse("table ip t {\n chain c {\n  type filter hook input priority filter - 5; policy drop;\n  ip saddr 1.2.3.4 drop\n }\n set s { type ipv4_addr; flags interval; elements = { 10.0.0.0/8,\n 1.1.1.1 } }\n}\n").unwrap();
        let Cmd::Table { table, .. } = &c[0] else {
            panic!()
        };
        assert_eq!(table.items.len(), 2);
        let TableItem::Chain(ch) = &table.items[0] else {
            panic!()
        };
        let b = ch.base.as_ref().unwrap();
        assert_eq!(
            (b.hook.as_str(), b.priority.offset, b.policy.as_deref()),
            ("input", -5, Some("drop"))
        );
        assert_eq!(ch.rules.len(), 1);
        let c = parse("define ports = { 22, 80 }\nadd rule t c tcp dport $ports accept").unwrap();
        let Cmd::Rule { rule, .. } = &c[0] else {
            panic!()
        };
        assert!(matches!(&rule.stmts[0], Stmt::Match { right: Expr::Set(e), .. } if e.len() == 2));
        for s in [
            "list ruleset",
            "list table inet t",
            "flush chain ip t c",
            "delete rule inet t c handle 5",
            "add element inet t s { 1.2.3.4 timeout 10s, 5.6.7.8 }",
            "add map t m { type ipv4_addr : verdict; }",
            "add counter t c",
            "add quota t q { over 100 mbytes }",
            "list counters",
            "reset counters table t",
            "rename chain ip t c d",
            "add rule t c meta mark set ip saddr map { 1.1.1.1 : 0x1 }",
            "add rule t c tcp flags & (syn | ack) == syn",
            "add rule t c snat ip to 1.2.3.4-1.2.3.10:1000-2000 random,persistent",
            "add rule t c dnat ip6 to [::1]:80",
            "add rule t c update @m { ip saddr limit rate over 10/second burst 5 packets } drop",
            "add rule t c jump { counter; accept; }",
        ] {
            parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        }
    }
}
