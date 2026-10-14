//! Typed errors of acquisitions, conversions and verifications (D4).
//!
//! A refusal (a safety or preflight rule decided the operation must not
//! happen) is told apart from a failure by its [`ErrorKind`], never by the text
//! of its message. dfcore refusals arrive as [`dfcore::Refusal`] somewhere in an
//! `anyhow` chain and are recognised with [`dfcore::is_refusal`].

use crate::models::outcome::exit_code;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Why an operation ended without a report-worthy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// A safety or preflight rule refused the operation; nothing was written
    Refused,
    /// Invalid arguments or inconsistent options
    Usage,
    /// The operation could not run (tool missing, I/O error, ...)
    Failed,
    /// Stopped by the examiner or a signal
    Aborted,
}

impl ErrorKind {
    /// Process exit code: 3 refused, 2 usage, 4 failed, 8 aborted.
    pub fn exit_code(&self) -> i32 {
        match self {
            ErrorKind::Refused => exit_code::REFUSED,
            ErrorKind::Usage => exit_code::USAGE,
            ErrorKind::Failed => exit_code::FAILED,
            ErrorKind::Aborted => exit_code::ABORTED,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ErrorKind::Refused => "REFUSED",
            ErrorKind::Usage => "USAGE ERROR",
            ErrorKind::Failed => "FAILED",
            ErrorKind::Aborted => "ABORTED",
        }
    }
}

/// An error with its kind and the complete user-facing message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionError {
    pub kind: ErrorKind,
    pub message: String,
}

pub type AcquisitionResult<T> = Result<T, AcquisitionError>;

impl AcquisitionError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Refused, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Failed, message)
    }

    pub fn aborted(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Aborted, message)
    }

    pub fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    pub fn is_refusal(&self) -> bool {
        self.kind == ErrorKind::Refused
    }

    /// Prefix the message ("context: message"), keeping the kind.
    pub fn context(self, context: impl fmt::Display) -> Self {
        Self {
            kind: self.kind,
            message: format!("{}: {}", context, self.message),
        }
    }

    /// The audit-log outcome of a run that ended with this error.
    pub fn audit_outcome(&self) -> dfcore::audit::Outcome {
        match self.kind {
            ErrorKind::Refused => dfcore::audit::Outcome::Refused,
            _ => dfcore::audit::Outcome::Error,
        }
    }
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AcquisitionError {}

/// dfcore refusals anywhere in the chain become `Refused`; everything else
/// `Failed`. The message is the whole chain (`{:#}`).
impl From<anyhow::Error> for AcquisitionError {
    fn from(e: anyhow::Error) -> Self {
        let kind = if dfcore::is_refusal(&e) {
            ErrorKind::Refused
        } else {
            ErrorKind::Failed
        };
        Self::new(kind, format!("{e:#}"))
    }
}

impl From<dfcore::Refusal> for AcquisitionError {
    fn from(r: dfcore::Refusal) -> Self {
        Self::refused(r.0)
    }
}

impl From<std::io::Error> for AcquisitionError {
    fn from(e: std::io::Error) -> Self {
        Self::failed(e.to_string())
    }
}

/// Bridge for code that still reports errors as plain strings. A string
/// carries no kind, so it is a failure; refusals must be raised as
/// [`AcquisitionError::refused`] or [`dfcore::Refusal`].
impl From<String> for AcquisitionError {
    fn from(message: String) -> Self {
        Self::failed(message)
    }
}

impl From<&str> for AcquisitionError {
    fn from(message: &str) -> Self {
        Self::failed(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn exit_codes_per_kind() {
        assert_eq!(AcquisitionError::refused("x").exit_code(), 3);
        assert_eq!(AcquisitionError::usage("x").exit_code(), 2);
        assert_eq!(AcquisitionError::failed("x").exit_code(), 4);
        assert_eq!(AcquisitionError::aborted("x").exit_code(), 8);
    }

    #[test]
    fn dfcore_refusals_are_recognised_by_type_through_context() {
        let e = anyhow::Error::new(dfcore::Refusal("ABORT: /dev/sda is protected".into()))
            .context("preflight");
        let a = AcquisitionError::from(e);
        assert_eq!(a.kind, ErrorKind::Refused);
        assert_eq!(a.message, "preflight: ABORT: /dev/sda is protected");
        assert_eq!(a.audit_outcome(), dfcore::audit::Outcome::Refused);

        let r: anyhow::Result<()> = Err(dfcore::Refusal("no".into())).context("checking");
        assert!(AcquisitionError::from(r.unwrap_err()).is_refusal());
        assert!(AcquisitionError::from(dfcore::Refusal("x".into())).is_refusal());
    }

    #[test]
    fn refusal_words_in_ordinary_errors_do_not_make_refusals() {
        let a = AcquisitionError::from(anyhow::anyhow!("Refusing: Critical Safety Error, ABORT"));
        assert_eq!(a.kind, ErrorKind::Failed);
        assert_eq!(a.audit_outcome(), dfcore::audit::Outcome::Error);
        let s = AcquisitionError::from("Refusing to overwrite".to_string());
        assert_eq!(s.kind, ErrorKind::Failed);
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(AcquisitionError::from(io).kind, ErrorKind::Failed);
    }

    #[test]
    fn display_and_context_keep_kind() {
        let e = AcquisitionError::usage("RAW images cannot be split").context("--split 2G");
        assert_eq!(e.kind, ErrorKind::Usage);
        assert_eq!(e.to_string(), "--split 2G: RAW images cannot be split");
        let boxed: Box<dyn std::error::Error> = Box::new(e);
        assert_eq!(boxed.to_string(), "--split 2G: RAW images cannot be split");
    }
}
