//! Error types.

use std::borrow::Cow;
use std::fmt;
use std::io;

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Any error produced by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A socket operation failed.
    Io(io::Error),
    /// The kernel rejected a (non-batch) request.
    Kernel(KernelError),
    /// The kernel rejected one or more messages of a batch; the whole batch
    /// was rolled back.
    Batch(BatchError),
    /// Received data could not be parsed.
    Malformed(Cow<'static, str>),
    /// An attribute or message exceeded the netlink length limits.
    TooLarge,
    /// A dump was interrupted by concurrent ruleset changes too many times.
    DumpInterrupted,
    /// The caller supplied invalid input.
    InvalidInput(Cow<'static, str>),
}

impl Error {
    pub(crate) fn malformed(s: &'static str) -> Self {
        Error::Malformed(Cow::Borrowed(s))
    }

    pub(crate) fn invalid(s: impl Into<Cow<'static, str>>) -> Self {
        Error::InvalidInput(s.into())
    }

    /// The (positive) errno of a kernel or socket error, if any. For batch
    /// errors this is the errno of the first failing message.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Io(e) => e.raw_os_error(),
            Error::Kernel(k) => Some(k.errno),
            Error::Batch(b) => b.errors.first().map(|e| e.errno),
            _ => None,
        }
    }

    /// Whether the error is `ENOENT` (object not found).
    pub fn is_not_found(&self) -> bool {
        self.errno() == Some(libc::ENOENT)
    }

    /// Whether the error is `EEXIST` (object exists).
    pub fn is_exists(&self) -> bool {
        self.errno() == Some(libc::EEXIST)
    }

    /// Whether a batch was rejected because the ruleset generation changed
    /// since [`Batch::with_genid`](crate::Batch::with_genid) (`ERESTART`).
    /// Re-read the ruleset and retry.
    pub fn is_generation_mismatch(&self) -> bool {
        self.errno() == Some(libc::ERESTART)
    }

    /// The batch error, if this is one.
    pub fn as_batch(&self) -> Option<&BatchError> {
        match self {
            Error::Batch(b) => Some(b),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "netlink socket error: {e}"),
            Error::Kernel(e) => e.fmt(f),
            Error::Batch(e) => e.fmt(f),
            Error::Malformed(s) => write!(f, "malformed netlink data: {s}"),
            Error::TooLarge => f.write_str("netlink attribute or message too large"),
            Error::DumpInterrupted => {
                f.write_str("dump repeatedly interrupted by concurrent ruleset changes")
            }
            Error::InvalidInput(s) => write!(f, "invalid input: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// An error returned by the kernel in response to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelError {
    /// Positive errno value.
    pub errno: i32,
    /// Extended ack message, if the kernel provided one.
    pub message: Option<String>,
}

impl KernelError {
    /// The errno as an [`io::Error`].
    pub fn io_error(&self) -> io::Error {
        io::Error::from_raw_os_error(self.errno)
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kernel error: {}", self.io_error())?;
        if let Some(m) = &self.message {
            write!(f, " ({m})")?;
        }
        Ok(())
    }
}

/// Failure of an atomic batch. No part of the batch was applied (unless
/// [`outcome_unknown`](Self::outcome_unknown) is set).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchError {
    /// Every message the kernel rejected, in batch order.
    pub errors: Vec<MessageError>,
    /// Whether some responses were lost because the socket receive buffer
    /// overflowed (`ENOBUFS`). If set, `errors` may be incomplete.
    pub responses_lost: bool,
    /// Responses were lost, none of them an error, and whether the batch
    /// was applied cannot be determined (it may have been).
    pub outcome_unknown: bool,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errors.as_slice() {
            [] if self.outcome_unknown => f.write_str("batch outcome unknown")?,
            [] => f.write_str("batch failed")?,
            [e] => e.fmt(f)?,
            [e, rest @ ..] => write!(f, "{e} (and {} more errors)", rest.len())?,
        }
        if self.responses_lost {
            f.write_str(" (some responses lost: receive buffer overflow)")?;
        }
        Ok(())
    }
}

impl std::error::Error for BatchError {}

/// Rejection of a single batch message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageError {
    /// Index of the failing operation, as returned by the [`Batch`]
    /// method that added it. `None` if the error concerns the batch framing
    /// itself (e.g. a generation id mismatch reported on the batch header).
    ///
    /// [`Batch`]: crate::Batch
    pub index: Option<usize>,
    /// Positive errno value.
    pub errno: i32,
    /// Extended ack message, if the kernel provided one.
    pub message: Option<String>,
    /// Human readable summary of the operation, e.g. `add rule inet filter input`.
    pub operation: String,
    /// The location within the message that the kernel blamed, if it
    /// reported one.
    pub location: Option<ErrorLocation>,
}

impl MessageError {
    /// The errno as an [`io::Error`].
    pub fn io_error(&self) -> io::Error {
        io::Error::from_raw_os_error(self.errno)
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.index {
            Some(i) => write!(
                f,
                "batch operation #{i} ({}) failed: {}",
                self.operation,
                self.io_error()
            )?,
            None => write!(f, "batch ({}) failed: {}", self.operation, self.io_error())?,
        }
        if let Some(m) = &self.message {
            write!(f, ": {m}")?;
        }
        if let Some(l) = &self.location {
            write!(f, " at {l}")?;
        }
        Ok(())
    }
}

/// The part of a batch message that the kernel identified as invalid
/// (decoded from the extended ack attribute offset).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ErrorLocation {
    /// Index of the rule (or set) expression containing the error.
    pub expr_index: Option<usize>,
    /// Name of that expression (e.g. `lookup`).
    pub expr_name: Option<String>,
    /// Index of the set element containing the error.
    pub elem_index: Option<usize>,
    /// Path of attribute names from the message top level down to the
    /// offending attribute, e.g. `["NFTA_RULE_EXPRESSIONS", "elem[2]", "NFTA_EXPR_DATA", "NFTA_LOOKUP_SET"]`.
    pub attr_path: Vec<String>,
    /// Whether the kernel reported a *missing* attribute (rather than an invalid one).
    pub missing: bool,
    /// Short description of the blamed expression or element, e.g.
    /// `jump nope`, `set blocklist` or `key 0a000001`.
    pub detail: Option<String>,
}

impl fmt::Display for ErrorLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        if let Some(i) = self.elem_index {
            write!(f, "element #{i}")?;
            sep = ", ";
        }
        if let Some(i) = self.expr_index {
            write!(f, "{sep}expression #{i}")?;
            if let Some(n) = &self.expr_name {
                write!(f, " `{n}`")?;
            }
            sep = ", ";
        }
        if let Some(d) = &self.detail {
            write!(f, " ({d})")?;
        }
        if !self.attr_path.is_empty() {
            let what = if self.missing {
                "missing attribute in "
            } else {
                ""
            };
            write!(f, "{sep}{what}{}", self.attr_path.join("/"))?;
        }
        Ok(())
    }
}
