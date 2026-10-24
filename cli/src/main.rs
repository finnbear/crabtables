//! `nfcrt`: an nft-compatible command line tool built on crabtables.

use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

use crabtables::lang::ast::{Cmd, ObjKind, RulePos, Span, Target};
use crabtables::lang::compile::{Compiler, OpSource};
use crabtables::lang::print::Opts;
use crabtables::lang::{Error, list, parse};
use crabtables::{Family, ObjType, Ruleset, Socket};

/// nft's help text (`{}` is the program name).
const USAGE: &str = "Usage: {} [ options ] [ cmds... ]

Options (general):
  -h, --help                      Show this help
  -v, --version                   Show version information
  -V                              Show extended version information

Options (ruleset input handling):
  -f, --file <filename>           Read input from <filename>
  -D, --define <name=value>       Define variable, e.g. --define foo=1.2.3.4
  -i, --interactive               Read input from interactive CLI
  -I, --includepath <directory>   Add <directory> to the paths searched for include files. Default is: /etc
  -c, --check                     Check commands validity without actually applying the changes.
  -o, --optimize                  Optimize ruleset

Options (ruleset list formatting):
  -a, --handle                    Output rule handle.
  -s, --stateless                 Omit stateful information of ruleset.
  -t, --terse                     Omit contents of sets.
  -S, --service                   Translate ports to service names as described in /etc/services.
  -N, --reversedns                Translate IP addresses to names.
  -u, --guid                      Print UID/GID as defined in /etc/passwd and /etc/group.
  -n, --numeric                   Print fully numerical output.
  -y, --numeric-priority          Print chain priority numerically.
  -p, --numeric-protocol          Print layer 4 protocols numerically.
  -T, --numeric-time              Print time values numerically.

Options (command output formatting):
  -e, --echo                      Echo what has been added, inserted or replaced.
  -j, --json                      Format output in JSON
  -d, --debug <level [,level...]> Specify debugging level (scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all)

";

/// The options: short name, long name, takes an argument (in nft's order).
const OPTIONS: &[(char, &str, bool)] = &[
    ('h', "help", false),
    ('v', "version", false),
    ('V', "", false),
    ('f', "file", true),
    ('D', "define", true),
    ('i', "interactive", false),
    ('I', "includepath", true),
    ('c', "check", false),
    ('o', "optimize", false),
    ('a', "handle", false),
    ('s', "stateless", false),
    ('t', "terse", false),
    ('S', "service", false),
    ('N', "reversedns", false),
    ('u', "guid", false),
    ('n', "numeric", false),
    ('y', "numeric-priority", false),
    ('p', "numeric-protocol", false),
    ('T', "numeric-time", false),
    ('e', "echo", false),
    ('j', "json", false),
    ('d', "debug", true),
];

#[derive(Default)]
struct Cli {
    file: Option<String>,
    defines: Vec<(String, String)>,
    interactive: bool,
    check: bool,
    json: bool,
    echo: bool,
    /// `--debug=netlink`: print the netlink objects.
    debug_netlink: bool,
    /// Include search paths (`-I`).
    include_paths: Vec<String>,
    opts: Opts,
    words: Vec<String>,
}

/// How parsing the arguments ended, other than with commands to run.
enum Exit {
    /// Done (`-h`, `-v`): success.
    Done,
    /// An error was reported: failure.
    Failed,
}

/// nft checks that no option follows the commands (before parsing the
/// options), up to the first word starting with `{`.
fn options_after_commands(argv: &[String]) -> bool {
    let (mut skip, mut command) = (false, false);
    let mut pos = 0;
    for i in 1..argv.len() {
        pos += argv[i - 1].len() + 1;
        let a = &argv[i];
        if a.starts_with('{') {
            break;
        } else if skip {
            skip = false;
        } else if a.starts_with('-') {
            if command {
                // (The message goes to stderr, the markers to stdout.)
                eprintln!("Error: syntax error, options must be specified before commands");
                for a in argv {
                    eprint!("{a} ");
                }
                print!("\n{:>4}{:>w$}\n", '^', "~~", w = pos - 2);
                return true;
            }
            skip = matches!(a.as_bytes().get(1), Some(b'd' | b'I' | b'f' | b'D'))
                || matches!(
                    a.as_str(),
                    "--debug" | "--includepath" | "--file" | "--define"
                );
        } else {
            command = true;
        }
    }
    false
}

/// Parse the arguments like nft (with `getopt_long`: clustered short
/// options, attached or separate values, unambiguous prefixes of long
/// options, `--`, options only before the commands).
fn parse_args(argv: &[String]) -> Result<Cli, Exit> {
    let prog = argv.first().map_or("nfcrt", String::as_str);
    if options_after_commands(argv) {
        return Err(Exit::Failed);
    }
    let fail = |msg: String| {
        eprintln!("{prog}: {msg}");
        Exit::Failed
    };
    let mut cli = Cli::default();
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        i += 1;
        // The options of this word, with their values (if given).
        let mut found: Vec<(char, Option<String>)> = Vec::new();
        if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (long, None),
            };
            let matches: Vec<&(char, &str, bool)> = OPTIONS
                .iter()
                .filter(|o| !o.1.is_empty() && o.1.starts_with(name))
                .collect();
            let opt = match matches.iter().find(|o| o.1 == name) {
                Some(o) => *o,
                None if matches.len() == 1 => matches[0],
                None if matches.is_empty() => {
                    return Err(fail(format!("unrecognized option '--{name}'")));
                }
                None => {
                    let p: Vec<String> = matches.iter().map(|o| format!("'--{}'", o.1)).collect();
                    return Err(fail(format!(
                        "option '--{name}' is ambiguous; possibilities: {}",
                        p.join(" ")
                    )));
                }
            };
            let value = match (opt.2, value) {
                (false, Some(_)) => {
                    return Err(fail(format!(
                        "option '--{}' doesn't allow an argument",
                        opt.1
                    )));
                }
                (true, None) => match argv.get(i) {
                    Some(v) => {
                        i += 1;
                        Some(v.clone())
                    }
                    None => return Err(fail(format!("option '--{}' requires an argument", opt.1))),
                },
                (_, v) => v,
            };
            found.push((opt.0, value));
        } else {
            for (off, c) in a[1..].char_indices() {
                let Some(opt) = OPTIONS.iter().find(|o| o.0 == c) else {
                    return Err(fail(format!("invalid option -- '{c}'")));
                };
                if !opt.2 {
                    found.push((c, None));
                    continue;
                }
                // The rest of the word, or the next one, is the value.
                let rest = &a[1 + off + c.len_utf8()..];
                let value = if !rest.is_empty() {
                    rest.to_owned()
                } else if let Some(v) = argv.get(i) {
                    i += 1;
                    v.clone()
                } else {
                    return Err(fail(format!("option requires an argument -- '{c}'")));
                };
                found.push((c, Some(value)));
                break;
            }
        }
        for (c, value) in found {
            let value = value.unwrap_or_default();
            match c {
                'h' => {
                    print!("{}", USAGE.replacen("{}", prog, 1));
                    return Err(Exit::Done);
                }
                'v' => {
                    println!("nfcrt v{} (nftables compatible)", env!("CARGO_PKG_VERSION"));
                    return Err(Exit::Done);
                }
                'V' => {
                    println!("nfcrt v{} (nftables compatible)", env!("CARGO_PKG_VERSION"));
                    println!("  cli:\t\tbasic\n  json:\t\tyes\n  minigmp:\tno\n  libxtables:\tno");
                    return Err(Exit::Done);
                }
                'f' => cli.file = Some(value),
                'D' => match value.split_once('=') {
                    Some((k, v)) => cli.defines.push((k.to_owned(), v.to_owned())),
                    None => {
                        eprintln!("Error: Failed to define variable '{value}'");
                        return Err(Exit::Failed);
                    }
                },
                'i' => cli.interactive = true,
                'I' => {
                    if std::fs::metadata(&value).is_ok() {
                        cli.include_paths.push(value);
                    } else {
                        eprintln!("Warning: Cannot include path '{value}'");
                    }
                }
                'c' => cli.check = true,
                'o' => {
                    eprintln!("Error: -o/--optimize is not supported by nfcrt");
                    return Err(Exit::Failed);
                }
                'a' => cli.opts.handles = true,
                's' => cli.opts.stateless = true,
                't' => cli.opts.terse = true,
                'S' => cli.opts.service = true,
                'N' => cli.opts.reverse_dns = true,
                'u' => cli.opts.guid = true,
                'n' => {
                    cli.opts.numeric = true;
                    cli.opts.numeric_proto = true;
                    cli.opts.numeric_prio = true;
                    cli.opts.numeric_time = true;
                }
                'y' => cli.opts.numeric_prio = true,
                'p' => cli.opts.numeric_proto = true,
                'T' => cli.opts.numeric_time = true,
                'e' => cli.echo = true,
                'j' => cli.json = true,
                'd' => {
                    for l in value.split(',') {
                        match l {
                            "netlink" | "all" => cli.debug_netlink = true,
                            "scanner" | "parser" | "eval" | "mnl" | "proto-ctx" | "segtree" => {}
                            _ => {
                                eprintln!("Error: invalid debug parameter `{l}'");
                                return Err(Exit::Failed);
                            }
                        }
                    }
                }
                _ => unreachable!("option table"),
            }
        }
    }
    cli.words = argv[i..].to_vec();
    if !cli.defines.is_empty() && cli.file.is_none() {
        eprintln!("Error: -D/--define can only be used with -f/--filename");
        return Err(Exit::Failed);
    }
    if cli.words.is_empty() && cli.file.is_none() && !cli.interactive {
        eprintln!("{prog}: no command specified");
        return Err(Exit::Failed);
    }
    Ok(cli)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let cli = match parse_args(&argv) {
        Ok(c) => c,
        Err(Exit::Done) => return ExitCode::SUCCESS,
        Err(Exit::Failed) => return ExitCode::FAILURE,
    };
    let mut sock = match Socket::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: unable to open netlink socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut prelude = String::new();
    for (k, v) in &cli.defines {
        // (As nft: one line, parsed before the input.)
        prelude.push_str(&format!("define {k}={v}; "));
    }
    // Commands take precedence over -f and -i.
    if cli.interactive && cli.words.is_empty() {
        return interactive(&cli, &mut sock, &prelude);
    }
    let (input, name) = if !cli.words.is_empty() {
        // Command line input ends like a line of a script.
        (format!("{}\n", cli.words.join(" ")), None)
    } else if let Some(f) = &cli.file {
        let text = if f == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map(|_| s)
        } else if std::fs::metadata(f).is_ok_and(|m| !m.is_file()) {
            eprint!("internal:0:0-0: Error: Not a regular file: \"{f}\"\n\n\n");
            return ExitCode::FAILURE;
        } else {
            std::fs::read_to_string(f)
        };
        match text {
            Ok(t) => (t, Some(f.clone())),
            Err(e) => {
                eprint!(
                    "internal:0:0-0: Error: Could not open file \"{f}\": {}\n\n\n",
                    strerror(&e)
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        return ExitCode::SUCCESS;
    };
    // Like C's stdio, output is buffered unless it goes to a terminal (so
    // that errors come first when both go to the same pipe).
    let stdout = std::io::stdout();
    let mut out: Box<dyn Write> = if std::io::IsTerminal::is_terminal(&stdout) {
        Box::new(stdout.lock())
    } else {
        Box::new(std::io::BufWriter::with_capacity(1 << 16, stdout.lock()))
    };
    let ok = run(&cli, &mut sock, &prelude, &input, name.as_deref(), &mut out);
    let _ = out.flush();
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn interactive(cli: &Cli, sock: &mut Socket, prelude: &str) -> ExitCode {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        // (Like nft, no prompt unless reading from a terminal.)
        if std::io::IsTerminal::is_terminal(&stdin) {
            print!("nft> ");
            let _ = std::io::stdout().flush();
        }
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let l = line.trim();
        if l == "quit" || l == "exit" {
            break;
        }
        if l.is_empty() {
            continue;
        }
        let out = std::io::stdout();
        run(cli, sock, prelude, &format!("{l}\n"), None, &mut out.lock());
    }
    ExitCode::SUCCESS
}

fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error") {
        Some(i) => s[..i].to_owned(),
        None => s,
    }
}

/// Print an error located in the input.
fn report(e: &Error, input: &str, file: Option<&str>) {
    eprint!("{}", e.render(input, file));
}

/// What evaluating and compiling `cmds` needs of the ruleset: tables,
/// chains and set definitions, and the rules of chains that commands
/// address by index.
fn definitions(sock: &mut Socket, cmds: &[(Cmd, Span)]) -> crabtables::Result<Ruleset> {
    Ok(definitions_fetched(sock, cmds)?.0)
}

/// [`definitions`], and the sets whose elements were fetched.
fn definitions_fetched(
    sock: &mut Socket,
    cmds: &[(Cmd, Span)],
) -> crabtables::Result<(Ruleset, Vec<usize>)> {
    let mut fetched = Vec::new();
    let sets = sock.list_sets(Family::Unspec, None)?;
    let mut rs = Ruleset {
        tables: sock.list_tables(Family::Unspec)?,
        chains: sock.list_chains(Family::Unspec, None)?,
        sets: sets.into_iter().map(|s| (s, Vec::new())).collect(),
        ..Ruleset::default()
    };
    for (c, _) in cmds {
        // Element changes to interval sets depend on the elements there.
        if let Cmd::Element {
            op,
            family,
            table,
            set,
            ..
        } = c
        {
            if matches!(op.as_str(), "add" | "delete") {
                if let Some(i) = rs.sets.iter().position(|(s, _)| {
                    s.family == *family && s.table == *table && s.name == *set && s.is_interval()
                }) {
                    if !fetched.contains(&i) {
                        rs.sets[i].1 = sock.list_elems(*family, table, set)?;
                        fetched.push(i);
                    }
                }
            }
        }
        if let Cmd::Rule {
            family,
            table,
            chain,
            pos: Some(RulePos::Index(_)),
            ..
        } = c
        {
            // (A missing chain is reported when compiling.)
            if let Ok(rules) = sock.list_rules(*family, Some(table), Some(chain)) {
                rs.rules.extend(rules);
            }
        }
    }
    Ok((rs, fetched))
}

/// Does nft read the ruleset for `c`? (Not for adding a table without
/// contents, flushes of tables or the ruleset, `describe`.)
fn needs_ruleset(c: &Cmd) -> bool {
    match c {
        Cmd::Table { table, .. } => {
            !(table.items.is_empty() && table.flags.is_empty() && table.comment.is_none())
        }
        Cmd::Flush { kind, .. } => !matches!(kind, None | Some(ObjKind::Table)),
        Cmd::Describe(_) => false,
        _ => true,
    }
}

/// Is `c` executed immediately (not part of a transaction)?
fn is_query(c: &Cmd) -> bool {
    matches!(
        c,
        Cmd::List { .. } | Cmd::Reset { .. } | Cmd::Describe(_) | Cmd::Monitor { .. }
    ) || matches!(c, Cmd::Element { op, .. } if op == "get" || op == "reset")
}

/// Parse and execute `input`. Returns false on error.
fn run(
    cli: &Cli,
    sock: &mut Socket,
    prelude: &str,
    input: &str,
    file: Option<&str>,
    out: &mut dyn Write,
) -> bool {
    // Variables defined with -D come first; spans are relative to the input.
    let full = format!("{prelude}{input}");
    // JSON input (`-j`): a JSON document instead of nft syntax.
    let (cmds, mut errors) = if cli.json && input.trim_start().starts_with('{') {
        match crabtables::lang::json::parse(input) {
            Ok(c) => (
                c.into_iter().map(|c| (c, Span::default())).collect(),
                Vec::new(),
            ),
            Err(e) => (Vec::new(), vec![e]),
        }
    } else {
        let mut include = crabtables::lang::include::IncludeOpts::default();
        include
            .paths
            .extend(cli.include_paths.iter().map(std::path::PathBuf::from));
        let cwd = std::env::current_dir().unwrap_or_default();
        let src = parse::Source {
            name: match file {
                None => "<cmdline>".into(),
                Some("-") => "/dev/stdin".into(),
                Some(f) => f.to_owned(),
            },
            dir: match file {
                Some(f) if f != "-" => std::fs::canonicalize(f)
                    .ok()
                    .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                    .unwrap_or(cwd),
                _ => cwd,
            },
            include,
        };
        parse::parse_source_all(&full, &src)
    };
    // Like nft, evaluate all commands before running any, and report all
    // errors (syntax errors first, at most 10).
    if !cmds.is_empty() {
        let mut c = Compiler::new();
        match definitions(sock, &cmds) {
            Ok(rs) => c.learn(&rs),
            // Without privileges, nft fails when it needs the ruleset;
            // other changes go to the kernel, which rejects them.
            Err(e) if e.errno() == Some(EPERM) => {
                if cmds.iter().any(|(c, _)| needs_ruleset(c)) {
                    eprintln!("Operation not permitted (you must be root)");
                    eprintln!(
                        "netlink: Error: cache initialization failed: Operation not permitted"
                    );
                    return false;
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return false;
            }
        }
        let suggest = cmds.iter().any(|(c, _)| !is_query(c));
        errors.extend(c.evaluate(&cmds, suggest));
    }
    if !errors.is_empty() {
        for e in errors.into_iter().take(10) {
            report_in(e, prelude, input, file);
        }
        return false;
    }
    let mut pending: Vec<&(Cmd, Span)> = Vec::new();
    for cs in &cmds {
        let c = &cs.0;
        if is_query(c) {
            if !transaction(cli, sock, &pending, prelude, input, file, out) {
                return false;
            }
            pending.clear();
            if let Err(e) = query(cli, sock, c, cs.1, out) {
                if e.source.as_ref().and_then(|s| s.errno()) == Some(EPERM) {
                    // (As nft, which needs the ruleset for queries.)
                    eprintln!("Operation not permitted (you must be root)");
                    eprintln!(
                        "netlink: Error: cache initialization failed: Operation not permitted"
                    );
                } else {
                    report_in(e, prelude, input, file);
                }
                return false;
            }
        } else {
            pending.push(cs);
        }
    }
    transaction(cli, sock, &pending, prelude, input, file, out)
}

/// Report an error located in `prelude` (the -D definitions, shown like
/// command line input, as nft) followed by `input`.
fn report_in(mut e: Error, prelude: &str, input: &str, file: Option<&str>) {
    let by = prelude.len();
    match &mut e.span {
        // Located in an included file.
        _ if e.origin.is_some() => report(&e, input, file),
        Some(s) if s.start < by => report(&e, prelude, None),
        Some(s) => {
            s.start -= by;
            s.end = s.end.saturating_sub(by);
            report(&e, input, file);
        }
        None => report(&e, input, file),
    }
}

/// Compile and commit (or check) batch commands.
fn transaction(
    cli: &Cli,
    sock: &mut Socket,
    cmds: &[&(Cmd, Span)],
    prelude: &str,
    input: &str,
    file: Option<&str>,
    out: &mut dyn Write,
) -> bool {
    if cmds.is_empty() {
        return true;
    }
    let owned: Vec<(Cmd, Span)> = cmds.iter().map(|c| (*c).clone()).collect();
    let mut c = Compiler::new();
    let cache;
    // The current ruleset resolves references (sets, chain handles) and
    // lets missing objects be reported as nft does.
    {
        match definitions_fetched(sock, &owned) {
            Ok((rs, fetched)) => {
                if cli.debug_netlink {
                    // (nft shows the elements it reads.)
                    for i in fetched {
                        let (set, elems) = &rs.sets[i];
                        let text = crabtables::lang::netdebug::set_elements(set, elems);
                        let _ = out.write_all(text.as_bytes());
                    }
                }
                c.learn(&rs);
                cache = rs;
            }
            Err(e) if e.errno() == Some(EPERM) => cache = Ruleset::default(),
            Err(e) => {
                eprintln!("Error: {e}");
                return false;
            }
        }
    }
    // With echo, the kernel reports the objects (with their handles).
    c.set_echo(cli.echo);
    if let Err(e) = c.compile_spanned(&owned) {
        report_in(e, prelude, input, file);
        return false;
    }
    let (batch, sources) = c.into_batch();
    if cli.debug_netlink {
        let _ = out.write_all(crabtables::lang::netdebug::batch(&batch).as_bytes());
    }
    let res = if cli.check {
        sock.check(&batch).map(|_| None)
    } else {
        sock.commit(&batch).map(Some)
    };
    match res {
        Ok(outcome) => {
            if cli.echo {
                if let Some(o) = outcome {
                    echo(cli, &o, cache, out);
                }
            }
            true
        }
        Err(e) => {
            match e.as_batch() {
                Some(b) if !b.errors.is_empty() => {
                    for m in &b.errors {
                        let src = m.index.and_then(|i| sources.get(i));
                        if let Some(c) = src
                            .and_then(|s| s.conflict.as_ref())
                            .filter(|_| matches!(m.errno, 17 | 95) /* EEXIST, EOPNOTSUPP */)
                        {
                            let e = Error::at(c.msg.clone(), c.span.unwrap_or_default());
                            report_in(e, prelude, input, file);
                            continue;
                        }
                        // A rejected batch (e.g. without privileges) is
                        // reported at the first command, as nft does.
                        let span = match src {
                            Some(s) => error_span(s, m),
                            None => sources.first().map_or_else(Span::default, |s| s.cmd_span),
                        };
                        let mut msg = format!(
                            "Could not process rule: {}",
                            strerror(&std::io::Error::from_raw_os_error(m.errno))
                        );
                        if let Some(x) = &m.message {
                            msg.push_str(&format!(" ({x})"));
                        }
                        let err = if span == Span::default() {
                            Error::msg(msg)
                        } else {
                            Error::at(msg, span)
                        };
                        report_in(err, prelude, input, file);
                    }
                }
                _ => eprintln!("Error: {e}"),
            }
            false
        }
    }
}

/// The input location that a kernel error refers to.
fn error_span(src: &OpSource, m: &crabtables::MessageError) -> Span {
    if let Some(loc) = &m.location {
        if let Some(i) = loc.expr_index {
            if let Some(s) = src.expr_spans.get(i) {
                return *s;
            }
        }
        if let Some(attr) = loc.attr_path.first() {
            if attr.ends_with("_TABLE") && src.table_span != Span::default() {
                return src.table_span;
            }
            if attr.ends_with("_HANDLE") && src.handle_span != Span::default() {
                return src.handle_span;
            }
            if attr.ends_with("_POSITION") && src.cmd_span != Span::default() {
                return src.cmd_span;
            }
            if (attr.ends_with("_NAME") || attr.ends_with("_CHAIN") || attr.ends_with("_SET"))
                && src.name_span != Span::default()
            {
                return src.name_span;
            }
        }
    }
    [src.span, src.name_span, src.table_span, src.cmd_span]
        .into_iter()
        .find(|s| *s != Span::default())
        .unwrap_or_default()
}

fn echo(cli: &Cli, o: &crabtables::BatchOutcome, cache: Ruleset, out: &mut dyn Write) {
    use crabtables::lang::monitor::{Kind, Printer};
    use crabtables::monitor::Event;
    let mut p = Printer::new(cache, cli.opts).with_json(cli.json);
    let mut lines = Vec::new();
    for (_, obj) in &o.echoes {
        lines.extend(p.event(&Event::New(obj.clone())));
    }
    lines.extend(p.finish());
    lines.retain(|l| l.kind != Kind::Generation);
    if cli.json {
        let items: Vec<String> = lines.into_iter().map(|l| l.text).collect();
        let _ = writeln!(out, "{{\"nftables\": [{}]}}", items.join(", "));
        return;
    }
    for l in lines {
        let _ = writeln!(out, "{}", l.text);
    }
    let comm = std::fs::read_to_string("/proc/self/comm").unwrap_or_default();
    let _ = writeln!(
        out,
        "# new generation {} by process {} ({})",
        o.genid,
        std::process::id(),
        comm.trim()
    );
}

/// Execute a list / reset / get command.
fn query(
    cli: &Cli,
    sock: &mut Socket,
    c: &Cmd,
    span: Span,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match c {
        Cmd::List { kind, all, target } => {
            if *kind == Some(ObjKind::Table) && *all {
                let rs = sock.list_ruleset(target.family.unwrap_or(Family::Unspec))?;
                let text = if cli.json {
                    crabtables::lang::json::list(&rs, *kind, *all, target, &cli.opts)?
                } else {
                    list::list_tables(&rs, target.family, &cli.opts)
                };
                let _ = out.write_all(text.as_bytes());
                return Ok(());
            }
            let rs = sock.list_ruleset(Family::Unspec)?;
            if cli.debug_netlink {
                let _ = out.write_all(debug_dump(&rs, *kind, target).as_bytes());
            }
            let text = if cli.json {
                crabtables::lang::json::list(&rs, *kind, *all, target, &cli.opts)?
            } else {
                list::list(&rs, *kind, *all, target, &cli.opts)?
            };
            let _ = out.write_all(text.as_bytes());
            Ok(())
        }
        Cmd::Reset { kind, all, target } => reset(cli, sock, *kind, *all, target, out),
        Cmd::Monitor {
            event,
            object,
            json,
        } => monitor(cli, sock, event.as_deref(), object.as_deref(), *json, out),
        Cmd::Describe(e) => {
            let text = crabtables::lang::describe::describe(e).map_err(|e| e.with_span(span))?;
            let _ = out.write_all(text.as_bytes());
            Ok(())
        }
        Cmd::Element {
            op,
            family,
            table,
            set,
            elems,
            table_span,
            set_span,
            ..
        } => {
            let rs = sock.list_ruleset(Family::Unspec)?;
            // A missing table or set is reported at its name.
            if !rs
                .tables
                .iter()
                .any(|t| t.family == *family && t.name == *table)
            {
                return Err(Error::at("No such file or directory", *table_span));
            }
            if !rs
                .sets
                .iter()
                .any(|(s, _)| s.family == *family && s.table == *table && s.name == *set)
            {
                return Err(Error::at("No such file or directory", *set_span));
            }
            let text = crabtables::lang::get_elements(
                sock,
                &rs,
                op == "reset",
                *family,
                table,
                set,
                elems,
                &cli.opts,
            )
            .map_err(|e| e.with_span(span))?;
            let _ = out.write_all(text.as_bytes());
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The objects nft fetches for a listing, as `--debug=netlink` prints them.
fn debug_dump(rs: &Ruleset, kind: Option<ObjKind>, t: &Target) -> String {
    let fam_ok = |f: Family| t.family.is_none_or(|x| x == f);
    let table_ok = |n: &str| t.table.as_deref().is_none_or(|x| x == n);
    let mut d = Ruleset {
        tables: rs.tables.clone(),
        ..Ruleset::default()
    };
    let (sets, rules) = match kind {
        None | Some(ObjKind::Table) => (true, true),
        Some(ObjKind::Chain) => (false, true),
        Some(ObjKind::Set | ObjKind::Map | ObjKind::Meter) => (true, false),
        _ => (false, false),
    };
    if sets {
        d.sets = rs
            .sets
            .iter()
            .filter(|(s, _)| fam_ok(s.family) && table_ok(&s.table))
            .filter(|(s, _)| {
                kind.is_none_or(|k| k == ObjKind::Table)
                    || t.name.as_deref().is_none_or(|n| n == s.name)
            })
            .cloned()
            .collect();
    }
    if rules {
        d.rules = rs
            .rules
            .iter()
            .filter(|r| fam_ok(r.family) && table_ok(&r.table))
            .filter(|r| {
                kind != Some(ObjKind::Chain) || t.name.as_deref().is_none_or(|n| n == r.chain)
            })
            .cloned()
            .collect();
    }
    crabtables::lang::netdebug::ruleset(&d)
}

/// `monitor`: print ruleset changes and/or packet traces until killed.
fn monitor(
    cli: &Cli,
    sock: &mut Socket,
    event: Option<&str>,
    object: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    use crabtables::lang::monitor::{Kind, Printer};
    use crabtables::monitor::{Event, Monitor};
    let trace = matches!(object, None | Some("trace"));
    let changes = object != Some("trace");
    let mut printer =
        Printer::new(sock.list_ruleset(Family::Unspec)?, cli.opts).with_json(json || cli.json);
    let mut mon = Monitor::with_groups(changes, trace)?;
    // What nft prints: with no filter everything (with the generations),
    // `new` events of the ruleset proper, `ruleset` also objects.
    let wanted = |k: Kind| match object {
        None if event.is_some() => matches!(
            k,
            Kind::Tables | Kind::Chains | Kind::Sets | Kind::Rules | Kind::Elements
        ),
        None => true,
        Some("ruleset") => !matches!(k, Kind::Flowtables | Kind::Generation | Kind::Trace),
        Some("tables") => k == Kind::Tables,
        Some("chains") => k == Kind::Chains,
        Some("sets") => k == Kind::Sets,
        Some("rules") => k == Kind::Rules,
        Some("elements") => k == Kind::Elements,
        Some("trace") => k == Kind::Trace,
        _ => false,
    };
    loop {
        let events = mon.recv()?;
        for ev in &events {
            if let Event::Overrun = ev {
                // Events were lost: start over from the current ruleset.
                printer = Printer::new(sock.list_ruleset(Family::Unspec)?, cli.opts)
                    .with_json(json || cli.json);
                continue;
            }
            for l in printer.event(ev) {
                let show = wanted(l.kind)
                    && (event.is_none() || l.new)
                    && !(l.kind == Kind::Generation && (json || cli.json));
                if show {
                    let _ = writeln!(out, "{}", l.text);
                }
            }
        }
        let _ = out.flush();
    }
}

const ENOENT: i32 = 2;
const EPERM: i32 = 1;

fn obj_type(k: ObjKind) -> Option<ObjType> {
    Some(match k {
        ObjKind::Counter => ObjType::Counter,
        ObjKind::Quota => ObjType::Quota,
        ObjKind::Limit => ObjType::Limit,
        ObjKind::CtHelper => ObjType::CtHelper,
        ObjKind::CtTimeout => ObjType::CtTimeout,
        ObjKind::CtExpect => ObjType::CtExpect,
        ObjKind::Synproxy => ObjType::Synproxy,
        ObjKind::Secmark => ObjType::Secmark,
        _ => return None,
    })
}

fn reset(
    cli: &Cli,
    sock: &mut Socket,
    kind: ObjKind,
    all: bool,
    target: &Target,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let family = target
        .family
        .unwrap_or(if all { Family::Unspec } else { Family::Ipv4 });
    let mut rs = sock.list_ruleset(Family::Unspec)?;
    // A named table (and object) must exist.
    if let Some(t) = &target.table {
        if !rs
            .tables
            .iter()
            .any(|x| &x.name == t && (family == Family::Unspec || x.family == family))
        {
            return Err(Error::at("No such file or directory", target.table_span));
        }
    }
    match kind {
        ObjKind::Rule => {
            if let (Some(t), Some(c)) = (&target.table, &target.name) {
                if !rs.chains.iter().any(|x| {
                    &x.table == t
                        && &x.name == c
                        && (family == Family::Unspec || x.family == family)
                }) {
                    return Err(Error::at("No such file or directory", target.name_span));
                }
            }
            // (Like nft, an interrupted dump is not reported.)
            let rules =
                sock.list_rules_reset(family, target.table.as_deref(), target.name.as_deref())?;
            rs.rules = rules.items;
            let text = list::list(&rs, None, true, target, &cli.opts)?;
            let _ = out.write_all(text.as_bytes());
        }
        k => {
            let ty = obj_type(k).ok_or_else(|| Error::msg("cannot reset this object type"))?;
            let objs = if all {
                sock.list_objs_reset(family, target.table.as_deref(), Some(ty))?
                    .items
            } else {
                match sock.reset_obj(
                    family,
                    target.table.as_deref().unwrap_or_default(),
                    target.name.as_deref().unwrap_or_default(),
                    ty,
                ) {
                    Ok(o) => vec![o],
                    // Like nft, a missing object is no error (nothing is
                    // listed).
                    Err(e) if e.errno() == Some(ENOENT) => return Ok(()),
                    Err(e) => return Err(Error::from(e).with_span(target.name_span)),
                }
            };
            // Show the values before the reset.
            for o in &mut rs.objs {
                if let Some(n) = objs
                    .iter()
                    .find(|x| x.family == o.family && x.table == o.table && x.name == o.name)
                {
                    *o = n.clone();
                }
            }
            let text = list::list(&rs, Some(k), all, target, &cli.opts)?;
            let _ = out.write_all(text.as_bytes());
        }
    }
    Ok(())
}
