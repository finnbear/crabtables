//! Tokenizer for the nft language.

use super::ast::Span;
use super::error::{Error, Result};

/// A token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A bare word: identifier, number, address, range, ... (`tcp`,
    /// `10.0.0.0/8`, `1000-2000`, `port-unreachable`, `10/second`).
    Word(String),
    /// A double quoted string (without the quotes).
    Str(String),
    /// `@name` or `@th,16,16`.
    At(String),
    /// `$name`.
    Var(String),
    /// Punctuation / operator.
    Punct(&'static str),
    /// End of line (statement separator in scripts).
    Newline,
}

/// A token with its location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The token.
    pub tok: Tok,
    /// Location.
    pub span: Span,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/' | '[' | ']' | '%' | '*')
}

/// A double quoted string at the start of `i`, with the escapes `\\`,
/// `\"` and `\n`. `None` if unterminated (or with another escape).
fn quoted(i: &str) -> Option<(&str, String)> {
    let mut out = String::new();
    let mut chars = i.strip_prefix('"')?.char_indices();
    while let Some((n, c)) = chars.next() {
        match c {
            '"' => return Some((&i[1 + n + 1..], out)),
            '\\' => out.push(match chars.next()?.1 {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                _ => return None,
            }),
            c => out.push(c),
        }
    }
    None
}

const PUNCTS: &[&str] = &[
    "==", "!=", "<=", ">=", "<<", ">>", "{", "}", "(", ")", ";", ",", "=", "<", ">", "&", "|", "^",
    "!", "-", "+", "*",
];

fn punct(i: &str) -> Option<(&str, &'static str)> {
    PUNCTS.iter().find_map(|p| Some((i.strip_prefix(p)?, *p)))
}

/// The longest non-empty prefix of `i` of characters matching `f`, and the
/// rest.
fn take_while1(i: &str, f: impl Fn(char) -> bool) -> Option<(&str, &str)> {
    let n = i.find(|c| !f(c)).unwrap_or(i.len());
    (n > 0).then(|| (&i[n..], &i[..n]))
}

fn word(i: &str) -> Option<(&str, &str)> {
    take_while1(i, is_word_char)
}

fn at_ref(i: &str) -> Option<(&str, &str)> {
    take_while1(i.strip_prefix('@')?, |c| is_word_char(c) || c == ',')
}

fn var(i: &str) -> Option<(&str, &str)> {
    take_while1(i.strip_prefix('$')?, |c| {
        c.is_ascii_alphanumeric() || c == '_'
    })
}

/// A comment, which runs to the end of the line.
fn comment(i: &str) -> Option<&str> {
    let c = i.strip_prefix('#')?;
    Some(&c[c.find('\n').unwrap_or(c.len())..])
}

/// Split `input` into tokens.
pub fn lex(input: &str) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut rest = input;
    loop {
        // Whitespace (except newlines) and line continuations.
        let trimmed = rest.trim_start_matches([' ', '\t', '\r']);
        let trimmed = trimmed.strip_prefix("\\\n").unwrap_or(trimmed);
        if trimmed.len() != rest.len() {
            rest = trimmed;
            continue;
        }
        if rest.is_empty() {
            break;
        }
        let start = input.len() - rest.len();
        let (r, tok) = if let Some(r) = rest.strip_prefix('\n') {
            (r, Tok::Newline)
        } else if let Some(r) = comment(rest) {
            // Comments run to the end of the line and produce no token.
            rest = r;
            continue;
        } else if rest.starts_with('"') {
            let (r, s) = quoted(rest).ok_or_else(|| {
                Error::at(
                    "unterminated string",
                    Span {
                        start,
                        end: input.len(),
                    },
                )
            })?;
            (r, Tok::Str(s))
        } else if let Some((r, w)) = at_ref(rest) {
            (r, Tok::At(w.to_owned()))
        } else if let Some((r, w)) = var(rest) {
            (r, Tok::Var(w.to_owned()))
        } else if let Some(t) = standalone(rest) {
            t
        } else if rest.starts_with('-') && !rest[1..].starts_with(|c: char| c.is_ascii_digit()) {
            // A leading `-` (as in `-a`) is a token of its own.
            (&rest[1..], Tok::Punct("-"))
        } else if let Some((r, w)) = word(rest) {
            let bracketed_ipv6 = w.starts_with('[')
                && w[1..].split(']').next().is_some_and(|a| {
                    a.contains(':')
                        && a.chars()
                            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
                });
            if w.starts_with('[') && !bracketed_ipv6 {
                // `[` is a token of its own (nft names it in errors).
                (&rest[1..], Tok::Punct("["))
            } else if w.len() > 1 && w.ends_with(':') && !w[..w.len() - 1].contains(':') {
                // `name:` is a name and a colon.
                (&rest[w.len() - 1..], Tok::Word(w[..w.len() - 1].to_owned()))
            } else {
                (r, Tok::Word(w.to_owned()))
            }
        } else if let Some((r, p)) = punct(rest) {
            (r, Tok::Punct(p))
        } else {
            let c = rest.chars().next().unwrap();
            return Err(Error::at(
                format!("syntax error, unexpected character `{c}`"),
                Span {
                    start,
                    end: start + c.len_utf8(),
                },
            ));
        };
        let end = input.len() - r.len();
        out.push(Token {
            tok,
            span: Span { start, end },
        });
        rest = r;
    }
    Ok(out)
}

/// Single characters that are operators only when standing alone: `.`
/// (concatenation), `:` (mapping), `-`, `+`, `*`, `/`.
fn standalone(i: &str) -> Option<(&str, Tok)> {
    let mut chars = i.chars();
    let c = chars.next()?;
    let next = chars.next();
    let alone = next.is_none_or(|n| !is_word_char(n));
    match c {
        '.' if alone => Some((&i[1..], Tok::Punct("."))),
        ':' if alone => Some((&i[1..], Tok::Punct(":"))),
        '-' if alone => Some((&i[1..], Tok::Punct("-"))),
        '+' if alone => Some((&i[1..], Tok::Punct("+"))),
        '*' if alone => Some((&i[1..], Tok::Punct("*"))),
        '/' if alone => Some((&i[1..], Tok::Punct("/"))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn tokens() {
        use Tok::*;
        let w = |s: &str| Word(s.to_owned());
        assert_eq!(
            words("ip saddr . tcp dport { 1.2.3.4 . 80-90 } accept # c\n"),
            vec![
                w("ip"),
                w("saddr"),
                Punct("."),
                w("tcp"),
                w("dport"),
                Punct("{"),
                w("1.2.3.4"),
                Punct("."),
                w("80-90"),
                Punct("}"),
                w("accept"),
                Newline
            ]
        );
        assert_eq!(
            words("@th,16,16 0x1234"),
            vec![At("th,16,16".into()), w("0x1234")]
        );
        assert_eq!(
            words("comment \"a \\\"b\\\"\""),
            vec![w("comment"), Str("a \"b\"".into())]
        );
        assert_eq!(
            words("tcp flags & (syn|ack) == syn"),
            vec![
                w("tcp"),
                w("flags"),
                Punct("&"),
                Punct("("),
                w("syn"),
                Punct("|"),
                w("ack"),
                Punct(")"),
                Punct("=="),
                w("syn")
            ]
        );
        assert_eq!(
            words("ct state established,related"),
            vec![
                w("ct"),
                w("state"),
                w("established"),
                Punct(","),
                w("related")
            ]
        );
        assert_eq!(
            words("priority filter - 5;"),
            vec![w("priority"), w("filter"), Punct("-"), w("5"), Punct(";")]
        );
        assert_eq!(
            words("1 : accept, * : drop"),
            vec![
                w("1"),
                Punct(":"),
                w("accept"),
                Punct(","),
                Punct("*"),
                Punct(":"),
                w("drop")
            ]
        );
        assert_eq!(
            words("dnat ip6 to [::2]:80 $x"),
            vec![w("dnat"), w("ip6"), w("to"), w("[::2]:80"), Var("x".into())]
        );
        assert_eq!(
            words("\"\" \"a\\nb\\\\\" #\n#x"),
            vec![Str("".into()), Str("a\nb\\".into()), Newline]
        );
        assert!(lex("\"abc").is_err());
        assert!(lex("\"a\\").is_err());
        assert!(lex("\"a\\t\"").is_err());
        // A non-ASCII character is an error located at it.
        let e = lex("a é").unwrap_err();
        assert_eq!(e.span, Some(Span { start: 2, end: 4 }));
    }
}
