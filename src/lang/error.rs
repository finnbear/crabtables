//! Errors.

use std::fmt;

use super::ast::Span;

/// A location related to an error's location (underlined with `~`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Related {
    /// This location.
    Span(Span),
    /// The start of the error's location up to this text (`ip saddr` of
    /// `ip saddr @set`).
    To(Box<str>),
    /// The whole location of the error (before narrowing it to `needle`).
    Whole,
}

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error, optionally pointing at a span of the input.
#[derive(Debug)]
pub struct Error {
    /// Message (without `Error: `).
    pub msg: String,
    /// Location in the input, if known.
    pub span: Option<Span>,
    /// The underlying kernel / socket error, if any.
    pub source: Option<Box<crate::Error>>,
    /// Text within the location that the error is about (e.g. a value):
    /// the location is narrowed to it when rendering.
    pub needle: Option<String>,
    /// A related location (underlined with `~`).
    pub related: Option<Related>,
    /// Times nft reports this error (some errors it reports twice).
    pub repeat: u8,
    /// For errors in an included file: the file (the location refers to
    /// it).
    pub origin: Option<Box<Origin>>,
}

/// An included file that an error is located in.
#[derive(Debug, Clone)]
pub struct Origin {
    /// File name.
    pub file: String,
    /// File contents.
    pub text: std::sync::Arc<str>,
    /// The include statements leading to the file, innermost first, as
    /// `file:line:col-col`.
    pub included_from: Vec<String>,
}

impl Error {
    /// An error with a message.
    pub fn msg(m: impl Into<String>) -> Self {
        Error {
            msg: m.into(),
            span: None,
            source: None,
            needle: None,
            related: None,
            repeat: 1,
            origin: None,
        }
    }

    /// An error with a message and location.
    pub fn at(m: impl Into<String>, span: Span) -> Self {
        Error {
            span: Some(span),
            ..Error::msg(m)
        }
    }

    /// An error about `text` (located within the location attached later).
    pub fn about(m: impl Into<String>, text: impl Into<String>) -> Self {
        Error {
            needle: Some(text.into()),
            ..Error::msg(m)
        }
    }

    /// Attach a location if none is set.
    pub fn with_span(mut self, span: Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span);
        }
        self
    }

    /// Format like nft: the message, then the offending input line with
    /// carets under the error location. `file` adds a
    /// `file:line:col-col: ` prefix (as for `nft -f`).
    pub fn render(&self, input: &str, file: Option<&str>) -> String {
        let mut out = String::new();
        let Some(o) = &self.origin else {
            return self.render_in(input, file);
        };
        for (i, l) in o.included_from.iter().enumerate() {
            out.push_str(if i == 0 {
                "In file included from "
            } else {
                "                 from "
            });
            out.push_str(l);
            out.push_str(":\n");
        }
        out.push_str(&self.render_in(&o.text, Some(&o.file)));
        out
    }

    /// `file:line:col-col` of a location in `input`.
    pub fn location(input: &str, file: &str, span: Span) -> String {
        let start = span.start.min(input.len());
        let line_start = input[..start].rfind('\n').map_or(0, |i| i + 1);
        let line_no = input[..line_start].matches('\n').count() + 1;
        format!(
            "{file}:{line_no}:{}-{}",
            start - line_start + 1,
            span.end.max(start + 1) - line_start
        )
    }

    fn render_in(&self, input: &str, file: Option<&str>) -> String {
        let Some(mut span) = self.span.filter(|s| s.start <= input.len()) else {
            return format!("Error: {}\n", self.msg);
        };
        let whole = Span {
            start: span.start,
            end: span.end.min(input.len()),
        };
        let related = match &self.related {
            None => None,
            Some(Related::Span(r)) => Some(*r),
            Some(Related::Whole) => Some(whole),
            Some(Related::To(t)) => input
                .get(whole.start..whole.end)
                .and_then(|x| x.find(&**t))
                .map(|i| Span {
                    start: whole.start,
                    end: whole.start + input[whole.start..whole.start + i].trim_end().len(),
                }),
        };
        if let Some(n) = &self.needle {
            let end = span.end.min(input.len());
            if let Some(i) = input.get(span.start..end).and_then(|t| t.find(n.as_str())) {
                span = Span {
                    start: span.start + i,
                    end: span.start + i + n.len(),
                };
            }
        }
        let line_start = input[..span.start].rfind('\n').map_or(0, |i| i + 1);
        let line_end = input[span.start..]
            .find('\n')
            .map_or(input.len(), |i| span.start + i);
        let line_no = input[..line_start].matches('\n').count() + 1;
        // A location may include the line terminator (one more caret).
        let end = span
            .end
            .clamp(span.start + 1, (line_end + 1).max(span.start + 1));
        let col = span.start - line_start;
        let prefix = file.map_or(String::new(), |f| {
            format!("{f}:{line_no}:{}-{}: ", col + 1, end - line_start)
        });
        // At the end of a file, nft shows the last line.
        let shown = if line_start == line_end && line_start == input.len() && line_start > 0 {
            let prev = input[..line_start - 1].rfind('\n').map_or(0, |i| i + 1);
            return format!(
                "{prefix}Error: {}\n{}\n^\n",
                self.msg,
                &input[prev..line_start - 1]
            );
        } else {
            &input[line_start..line_end]
        };
        // Markers by column: blanks (tabs kept), then `~` under the related
        // location's columns (taken on its own line, as nft does), then `^`.
        let mut marks: Vec<char> = shown
            .chars()
            .map(|c| if c == '\t' { '\t' } else { ' ' })
            .collect();
        let mut put = |from: usize, to: usize, c: char| {
            if marks.len() < to {
                marks.resize(to, ' ');
            }
            for m in &mut marks[from..to] {
                *m = c;
            }
        };
        if let Some(r) = related.filter(|r| r.end <= input.len() && r.start < r.end) {
            let rl = input[..r.start].rfind('\n').map_or(0, |i| i + 1);
            put(r.start - rl, r.end - rl, '~');
        }
        put(span.start - line_start, end - line_start, '^');
        let carets: String = marks.into_iter().collect();
        let carets = carets.trim_end();
        format!("{prefix}Error: {}\n{shown}\n{carets}\n", self.msg)
    }
}

impl Error {
    fn with_msg_from_source(mut self) -> Self {
        if let Some(e) = &self.source {
            self.msg = e.to_string();
        }
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        Error {
            source: Some(Box::new(e)),
            ..Error::msg(String::new())
        }
        .with_msg_from_source()
    }
}
