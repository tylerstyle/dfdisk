//! The verdict of an acquisition and the facts it is derived from.
//!
//! [`classify`] is the only place a verdict is decided (P1): engines and the
//! session measure facts ([`AcquisitionFacts`]), never pick an [`Outcome`]
//! themselves. Exit codes are fixed by [`Outcome::exit_code`] and
//! [`exit_code`] and documented in the README, `--help` and the CHANGELOG.

use crate::models::config::EngineKind;
use crate::models::text::{format_iec, plural};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Process exit codes of dfdisk.
pub mod exit_code {
    /// Complete, no read errors, image digests match the acquisition digests
    pub const VERIFIED: i32 = 0;
    /// Bug or unexpected internal failure
    pub const INTERNAL_ERROR: i32 = 1;
    /// Invalid arguments or inconsistent options
    pub const USAGE: i32 = 2;
    /// Refused by a safety or preflight rule; nothing was written
    pub const REFUSED: i32 = 3;
    /// Could not run, or verification could not run or complete
    pub const FAILED: i32 = 4;
    /// A recomputed digest differs from the acquisition digest
    pub const MISMATCH: i32 = 5;
    /// Not all of the source was acquired
    pub const INCOMPLETE: i32 = 6;
    /// Full length written, unreadable sectors replaced by zeros
    pub const READ_ERRORS: i32 = 7;
    /// Stopped by the examiner or a signal
    pub const ABORTED: i32 = 8;
    /// Complete, but no independent comparison was possible
    pub const UNVERIFIED: i32 = 9;
}

/// What an acquisition (or conversion) achieved, in decreasing order of
/// confidence. Derived only by [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Complete, no substituted sectors, image re-read digests equal the
    /// acquisition digests
    Verified,
    /// Complete, no substituted sectors, but no independent comparison was
    /// possible (rescue without --verify-source)
    CompleteUnverified,
    /// Full length written, some ranges unreadable and replaced by zeros; the
    /// digests describe the substituted stream, not the original medium
    CompletedWithReadErrors,
    /// Not all of the source was acquired (stopped early, unread or untried
    /// ranges, source lost, destination full)
    Incomplete,
    /// A re-read digest differs from the acquisition digest
    Mismatch,
    /// Verification could not run or complete
    VerificationFailed,
    /// Stopped by the examiner or a signal
    Aborted,
}

impl Outcome {
    pub const ALL: [Outcome; 7] = [
        Outcome::Verified,
        Outcome::CompleteUnverified,
        Outcome::CompletedWithReadErrors,
        Outcome::Incomplete,
        Outcome::Mismatch,
        Outcome::VerificationFailed,
        Outcome::Aborted,
    ];

    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Verified => exit_code::VERIFIED,
            Outcome::CompleteUnverified => exit_code::UNVERIFIED,
            Outcome::CompletedWithReadErrors => exit_code::READ_ERRORS,
            Outcome::Incomplete => exit_code::INCOMPLETE,
            Outcome::Mismatch => exit_code::MISMATCH,
            Outcome::VerificationFailed => exit_code::FAILED,
            Outcome::Aborted => exit_code::ABORTED,
        }
    }

    /// Upper-case verdict for banners. Only `Verified` says "VERIFIED".
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Verified => "VERIFIED",
            Outcome::CompleteUnverified => "COMPLETE, NOT VERIFIED",
            Outcome::CompletedWithReadErrors => "COMPLETED WITH READ ERRORS",
            Outcome::Incomplete => "INCOMPLETE",
            Outcome::Mismatch => "HASH MISMATCH",
            Outcome::VerificationFailed => "VERIFICATION FAILED",
            Outcome::Aborted => "ABORTED",
        }
    }

    /// One sentence saying what the verdict means, independent of the engine.
    pub fn explanation(&self) -> &'static str {
        match self {
            Outcome::Verified => {
                "The whole source was acquired without read errors, and the digests recomputed from the written image match the digests computed while reading the source."
            }
            Outcome::CompleteUnverified => {
                "The whole source was acquired without read errors, but no independent comparison was possible, so the image digests are not confirmed by a second computation."
            }
            Outcome::CompletedWithReadErrors => {
                "The full length of the source was written, but some sectors could not be read and were replaced by zeros in the image; the digests describe the image including those substituted sectors, not the original medium."
            }
            Outcome::Incomplete => {
                "Not all of the source was acquired: the acquisition stopped early or some areas were never read, so the image and its digests cover only what was acquired."
            }
            Outcome::Mismatch => {
                "A digest recomputed from the image (or from a second read of the source) differs from the digest computed during acquisition: the image does not reproduce the acquired data, or the source changed or reads unstably."
            }
            Outcome::VerificationFailed => {
                "The acquisition finished, but its verification could not be run or completed, so the integrity of the image is not confirmed."
            }
            Outcome::Aborted => {
                "The acquisition was stopped by the examiner or by a signal before it finished; the image is partial and its digests cover only what was acquired."
            }
        }
    }

    /// [`explanation`](Self::explanation) in the terms of the engine that ran
    /// (R12): rescue verdicts name the ddrescue map areas and the remedy.
    pub fn explanation_for(&self, engine: EngineKind) -> &'static str {
        match (self, engine) {
            (Outcome::Incomplete, EngineKind::Rescue) => {
                "Not all of the source was acquired: the ddrescue map still lists areas that were not tried or not finished (untried, non-trimmed or non-scraped); run the rescue again on the same destination to resume and retry them, until then the image holds no source data for those areas."
            }
            (Outcome::CompletedWithReadErrors, EngineKind::Rescue) => {
                "The full length of the source was written, but ddrescue could not read some sectors even after retries (bad sectors in the map) and they are zeros in the image; the digests describe the image including those substituted sectors, not the original medium."
            }
            (Outcome::CompleteUnverified, EngineKind::Rescue) => {
                "ddrescue rescued every sector of the source, but it does not compute digests while reading, so the image digests are not confirmed against the source; acquire with --verify-source to compare them with a second read of the source."
            }
            (outcome, _) => outcome.explanation(),
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How the bytes of a [`ReadErrorRange`] are represented in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeKind {
    /// Unreadable; zero-filled in the image (the image has full length)
    Substituted,
    /// Not tried, or not present in the image: the acquisition is incomplete
    Unread,
}

impl RangeKind {
    pub fn label(&self) -> &'static str {
        match self {
            RangeKind::Substituted => "unreadable, zero-filled",
            RangeKind::Unread => "not read",
        }
    }
}

/// A byte range of the source that was not acquired as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadErrorRange {
    /// First byte, from the start of the source
    pub offset: u64,
    /// Length in bytes
    pub length: u64,
    pub kind: RangeKind,
}

impl ReadErrorRange {
    pub fn new(offset: u64, length: u64, kind: RangeKind) -> Self {
        Self {
            offset,
            length,
            kind,
        }
    }

    /// One past the last byte (saturating).
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    /// Sectors of `sector_size` bytes this range touches, partial sectors at
    /// either end included.
    pub fn sectors(&self, sector_size: u32) -> u64 {
        if self.length == 0 {
            return 0;
        }
        let s = u64::from(sector_size.max(1));
        self.end().div_ceil(s) - self.offset / s
    }
}

/// Every range of the source that is not in the image as read, with where the
/// list came from. Invariant kept by [`push`](Self::push),
/// [`merge`](Self::merge) and [`normalise`](Self::normalise): ranges are
/// sorted, non-empty, do not overlap, and adjacent ranges of the same kind are
/// merged. Where an `Unread` and a `Substituted` range overlap, the overlap is
/// `Unread` (the more conservative statement). Code that edits `ranges`
/// directly must call `normalise` afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReadErrorTable {
    /// Granularity the source reported errors in (logical sector size);
    /// 0 means unknown and counts as 512
    pub sector_size: u32,
    pub ranges: Vec<ReadErrorRange>,
    /// Where the list comes from, e.g. "ewfinfo -e", "ddrescue mapfile",
    /// "raw engine"; merged tables join their sources with " + "
    pub source: String,
}

impl ReadErrorTable {
    pub fn new(sector_size: u32, source: impl Into<String>) -> Self {
        Self {
            sector_size,
            ranges: Vec::new(),
            source: source.into(),
        }
    }

    /// Sector size used for counting (512 when unknown).
    pub fn effective_sector_size(&self) -> u32 {
        if self.sector_size == 0 {
            512
        } else {
            self.sector_size
        }
    }

    /// Add a range. Appending in ascending order is cheap; anything else
    /// re-normalises the table.
    pub fn push(&mut self, offset: u64, length: u64, kind: RangeKind) {
        if length == 0 {
            return;
        }
        let range = ReadErrorRange::new(offset, length, kind);
        match self.ranges.last_mut() {
            None => self.ranges.push(range),
            Some(last) if range.offset > last.end() => self.ranges.push(range),
            Some(last) if range.offset == last.end() && range.kind == last.kind => {
                last.length = range.end() - last.offset;
            }
            Some(last) if range.offset == last.end() => self.ranges.push(range),
            Some(_) => {
                self.ranges.push(range);
                self.normalise();
            }
        }
    }

    /// Add a range given in sectors of `sector_size`.
    pub fn push_sectors(&mut self, first_sector: u64, count: u64, kind: RangeKind) {
        let s = u64::from(self.effective_sector_size());
        self.push(
            first_sector.saturating_mul(s),
            count.saturating_mul(s),
            kind,
        );
    }

    /// Restore the invariant (see the type documentation).
    pub fn normalise(&mut self) {
        if self.is_normalised() {
            return;
        }
        // Sweep over range boundaries, counting how many ranges of each kind
        // cover the current position
        let mut events: Vec<(u64, i32, RangeKind)> = Vec::with_capacity(self.ranges.len() * 2);
        for r in self.ranges.iter().filter(|r| r.length > 0) {
            events.push((r.offset, 1, r.kind));
            events.push((r.end(), -1, r.kind));
        }
        events.sort_by_key(|e| e.0);

        let mut out: Vec<ReadErrorRange> = Vec::new();
        let (mut substituted, mut unread) = (0i64, 0i64);
        let mut i = 0;
        let mut prev_pos = 0u64;
        while i < events.len() {
            let pos = events[i].0;
            // The segment [prev_pos, pos) had the coverage counted so far
            let current = if unread > 0 {
                Some(RangeKind::Unread)
            } else if substituted > 0 {
                Some(RangeKind::Substituted)
            } else {
                None
            };
            if let Some(kind) = current {
                if pos > prev_pos {
                    match out.last_mut() {
                        Some(last) if last.end() == prev_pos && last.kind == kind => {
                            last.length = pos - last.offset;
                        }
                        _ => out.push(ReadErrorRange::new(prev_pos, pos - prev_pos, kind)),
                    }
                }
            }
            while i < events.len() && events[i].0 == pos {
                let (_, delta, kind) = events[i];
                match kind {
                    RangeKind::Substituted => substituted += i64::from(delta),
                    RangeKind::Unread => unread += i64::from(delta),
                }
                i += 1;
            }
            prev_pos = pos;
        }
        self.ranges = out;
    }

    fn is_normalised(&self) -> bool {
        self.ranges.iter().all(|r| r.length > 0)
            && self.ranges.windows(2).all(|w| {
                w[1].offset > w[0].end() || (w[1].offset == w[0].end() && w[1].kind != w[0].kind)
            })
    }

    /// Union with `other` (e.g. ranges parsed from ewfacquire's output and the
    /// list ewfinfo reads back from the image). The finer sector size wins.
    pub fn merge(&mut self, other: &ReadErrorTable) {
        self.sector_size = match (self.sector_size, other.sector_size) {
            (0, s) | (s, 0) => s,
            (a, b) => a.min(b),
        };
        if !other.source.is_empty() && self.source != other.source {
            self.source = if self.source.is_empty() {
                other.source.clone()
            } else {
                format!("{} + {}", self.source, other.source)
            };
        }
        self.ranges.extend(other.ranges.iter().copied());
        // Force a full sweep: the combined list may be unsorted or overlapping
        self.ranges.sort_by_key(|r| (r.offset, r.kind));
        self.normalise();
    }

    fn normalised(&self) -> std::borrow::Cow<'_, ReadErrorTable> {
        if self.is_normalised() {
            std::borrow::Cow::Borrowed(self)
        } else {
            let mut t = self.clone();
            t.normalise();
            std::borrow::Cow::Owned(t)
        }
    }

    fn bytes_of(&self, kind: RangeKind) -> u64 {
        self.normalised()
            .ranges
            .iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.length)
            .sum()
    }

    fn sectors_of(&self, kind: Option<RangeKind>) -> u64 {
        let s = self.effective_sector_size();
        self.normalised()
            .ranges
            .iter()
            .filter(|r| kind.is_none_or(|k| r.kind == k))
            .map(|r| r.sectors(s))
            .sum()
    }

    /// Bytes that are zeros in the image instead of source data.
    pub fn substituted_bytes(&self) -> u64 {
        self.bytes_of(RangeKind::Substituted)
    }

    /// Bytes of the source that were not acquired at all.
    pub fn unread_bytes(&self) -> u64 {
        self.bytes_of(RangeKind::Unread)
    }

    /// Sectors touched by any range.
    pub fn sectors(&self) -> u64 {
        self.sectors_of(None)
    }

    pub fn substituted_sectors(&self) -> u64 {
        self.sectors_of(Some(RangeKind::Substituted))
    }

    pub fn unread_sectors(&self) -> u64 {
        self.sectors_of(Some(RangeKind::Unread))
    }

    /// Number of ranges of `kind`.
    pub fn count(&self, kind: RangeKind) -> usize {
        self.normalised()
            .ranges
            .iter()
            .filter(|r| r.kind == kind)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.iter().all(|r| r.length == 0)
    }

    /// "128 sectors (64 KiB) in 2 ranges" for the ranges of `kind`, `None`
    /// when there are none.
    pub fn summary(&self, kind: RangeKind) -> Option<String> {
        let count = self.count(kind) as u64;
        if count == 0 {
            return None;
        }
        let sectors = self.sectors_of(Some(kind));
        Some(format!(
            "{} ({}) in {}",
            plural(sectors, "sector", "sectors"),
            format_iec(self.bytes_of(kind)),
            plural(count, "range", "ranges")
        ))
    }
}

/// Outcome of comparing digests, or why no comparison happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerificationResult {
    /// Every selected digest was recomputed and equals its counterpart
    Matched { method: String },
    /// At least one recomputed digest differs
    Mismatched { method: String, details: String },
    /// No independent comparison is possible for this acquisition
    NotPossible { reason: String },
    /// Verification was attempted but could not run or complete
    Failed { reason: String },
}

impl Default for VerificationResult {
    fn default() -> Self {
        VerificationResult::NotPossible {
            reason: "no verification was run".to_string(),
        }
    }
}

impl VerificationResult {
    pub fn is_matched(&self) -> bool {
        matches!(self, VerificationResult::Matched { .. })
    }

    /// Short status word for tables ("matched", "MISMATCH", ...).
    pub fn label(&self) -> &'static str {
        match self {
            VerificationResult::Matched { .. } => "matched",
            VerificationResult::Mismatched { .. } => "MISMATCH",
            VerificationResult::NotPossible { .. } => "not possible",
            VerificationResult::Failed { .. } => "FAILED",
        }
    }

    /// One line describing the result with its method, details or reason.
    pub fn describe(&self) -> String {
        match self {
            VerificationResult::Matched { method } => format!("matched ({method})"),
            VerificationResult::Mismatched { method, details } => {
                format!("MISMATCH ({method}): {details}")
            }
            VerificationResult::NotPossible { reason } => format!("not possible: {reason}"),
            VerificationResult::Failed { reason } => format!("FAILED: {reason}"),
        }
    }
}

/// Everything [`classify`] decides on, measured by the engines and the session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionFacts {
    /// Size of the source when the acquisition started
    pub expected_bytes: u64,
    /// Bytes of the source represented in the image (read or substituted)
    pub bytes_acquired: u64,
    pub read_errors: ReadErrorTable,
    /// Why the acquisition stopped before the end, e.g. "source lost at
    /// offset X", "destination full at offset X"
    pub stop_reason: Option<String>,
    /// Stopped by the examiner or a signal
    pub aborted: bool,
    pub verification: VerificationResult,
    /// The source vanished or is no longer the device that was selected
    pub identity_changed: bool,
}

/// A verdict with the facts that decided it, in one sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub outcome: Outcome,
    pub reason: String,
}

/// The verdict for `facts`. Rules, first match wins:
/// 1. aborted → `Aborted`
/// 2. identity changed → `Incomplete`
/// 3. bytes acquired < expected, unread ranges, or a stop reason → `Incomplete`
/// 4. `Mismatched` → `Mismatch`
/// 5. `Failed` → `VerificationFailed`
/// 6. substituted ranges → `CompletedWithReadErrors` (even if verification matched)
/// 7. `Matched` → `Verified`
/// 8. `NotPossible` → `CompleteUnverified`
pub fn classify(facts: &AcquisitionFacts) -> Outcome {
    classify_detailed(facts).outcome
}

/// [`classify`] with the reason for the verdict.
pub fn classify_detailed(facts: &AcquisitionFacts) -> Classification {
    let done = |outcome: Outcome, reason: String| Classification { outcome, reason };
    let acquired = format!(
        "{} of {} bytes acquired",
        facts.bytes_acquired, facts.expected_bytes
    );

    if facts.aborted {
        let mut reason = format!("stopped by the examiner or a signal; {acquired}");
        if let Some(stop) = &facts.stop_reason {
            reason.push_str(&format!(" ({stop})"));
        }
        return done(Outcome::Aborted, reason);
    }

    if facts.identity_changed {
        let mut reason =
            "the source device changed or disappeared during the acquisition".to_string();
        if let Some(stop) = &facts.stop_reason {
            reason.push_str(&format!(": {stop}"));
        }
        reason.push_str(&format!("; {acquired}"));
        return done(Outcome::Incomplete, reason);
    }

    let shortfall = facts.bytes_acquired < facts.expected_bytes;
    let unread = facts.read_errors.unread_bytes() > 0;
    if shortfall || unread || facts.stop_reason.is_some() {
        let mut parts = Vec::new();
        if let Some(stop) = &facts.stop_reason {
            parts.push(stop.clone());
        }
        if shortfall {
            parts.push(acquired);
        }
        if let Some(s) = facts.read_errors.summary(RangeKind::Unread) {
            parts.push(format!("{s} not read"));
        }
        return done(Outcome::Incomplete, parts.join("; "));
    }

    match &facts.verification {
        VerificationResult::Mismatched { method, details } => {
            return done(Outcome::Mismatch, format!("{method}: {details}"));
        }
        VerificationResult::Failed { reason } => {
            return done(Outcome::VerificationFailed, reason.clone());
        }
        _ => {}
    }

    if let Some(s) = facts.read_errors.summary(RangeKind::Substituted) {
        return done(
            Outcome::CompletedWithReadErrors,
            format!(
                "{s} unreadable and replaced by zeros; verification {}",
                facts.verification.describe()
            ),
        );
    }

    match &facts.verification {
        VerificationResult::Matched { method } => done(Outcome::Verified, method.clone()),
        VerificationResult::NotPossible { reason } => {
            done(Outcome::CompleteUnverified, reason.clone())
        }
        // Handled above
        VerificationResult::Mismatched { .. } | VerificationResult::Failed { .. } => {
            unreachable!("mismatch and failure are classified before")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched() -> VerificationResult {
        VerificationResult::Matched {
            method: "image re-read".into(),
        }
    }

    fn mismatched() -> VerificationResult {
        VerificationResult::Mismatched {
            method: "ewfverify".into(),
            details: "MD5 differs".into(),
        }
    }

    fn failed() -> VerificationResult {
        VerificationResult::Failed {
            reason: "ewfverify exited 1".into(),
        }
    }

    fn not_possible() -> VerificationResult {
        VerificationResult::NotPossible {
            reason: "ddrescue does not hash".into(),
        }
    }

    /// A complete, clean acquisition of 1 MiB with the given verification.
    fn complete(verification: VerificationResult) -> AcquisitionFacts {
        AcquisitionFacts {
            expected_bytes: 1 << 20,
            bytes_acquired: 1 << 20,
            read_errors: ReadErrorTable::new(512, "test"),
            stop_reason: None,
            aborted: false,
            verification,
            identity_changed: false,
        }
    }

    fn with_range(mut f: AcquisitionFacts, kind: RangeKind) -> AcquisitionFacts {
        f.read_errors.push(4096, 1024, kind);
        f
    }

    #[test]
    fn rule_1_aborted_wins_over_everything() {
        for v in [matched(), mismatched(), failed(), not_possible()] {
            let mut f = with_range(complete(v), RangeKind::Unread);
            f.aborted = true;
            f.identity_changed = true;
            f.bytes_acquired = 10;
            f.stop_reason = Some("x".into());
            assert_eq!(classify(&f), Outcome::Aborted);
        }
        let mut f = complete(matched());
        f.aborted = true;
        let c = classify_detailed(&f);
        assert_eq!(c.outcome, Outcome::Aborted);
        assert!(
            c.reason.contains("1048576 of 1048576 bytes"),
            "{}",
            c.reason
        );
    }

    #[test]
    fn rule_2_identity_change_is_incomplete_even_when_matched() {
        let mut f = complete(matched());
        f.identity_changed = true;
        f.stop_reason = Some("source lost at offset 512".into());
        let c = classify_detailed(&f);
        assert_eq!(c.outcome, Outcome::Incomplete);
        assert!(c.reason.contains("changed or disappeared"), "{}", c.reason);
        assert!(
            c.reason.contains("source lost at offset 512"),
            "{}",
            c.reason
        );
        // ... and beats a mismatch
        let mut f = complete(mismatched());
        f.identity_changed = true;
        assert_eq!(classify(&f), Outcome::Incomplete);
    }

    #[test]
    fn rule_3_shortfall_unread_or_stop_reason_is_incomplete() {
        for v in [matched(), mismatched(), failed(), not_possible()] {
            let mut short = complete(v.clone());
            short.bytes_acquired -= 512;
            let c = classify_detailed(&short);
            assert_eq!(c.outcome, Outcome::Incomplete);
            assert!(
                c.reason.contains("1048064 of 1048576 bytes"),
                "{}",
                c.reason
            );

            let unread = with_range(complete(v.clone()), RangeKind::Unread);
            let c = classify_detailed(&unread);
            assert_eq!(c.outcome, Outcome::Incomplete);
            assert!(c.reason.contains("2 sectors (1 KiB) in 1 range not read"));

            let mut stopped = complete(v);
            stopped.stop_reason = Some("destination full at offset 4096".into());
            let c = classify_detailed(&stopped);
            assert_eq!(c.outcome, Outcome::Incomplete);
            assert_eq!(c.reason, "destination full at offset 4096");
        }
    }

    #[test]
    fn rule_4_mismatch_beats_read_errors() {
        assert_eq!(classify(&complete(mismatched())), Outcome::Mismatch);
        let f = with_range(complete(mismatched()), RangeKind::Substituted);
        let c = classify_detailed(&f);
        assert_eq!(c.outcome, Outcome::Mismatch);
        assert_eq!(c.reason, "ewfverify: MD5 differs");
    }

    #[test]
    fn rule_5_failed_verification_beats_read_errors() {
        assert_eq!(classify(&complete(failed())), Outcome::VerificationFailed);
        let f = with_range(complete(failed()), RangeKind::Substituted);
        assert_eq!(classify(&f), Outcome::VerificationFailed);
    }

    #[test]
    fn rule_6_substituted_sectors_never_verify() {
        for v in [matched(), not_possible()] {
            let f = with_range(complete(v), RangeKind::Substituted);
            let c = classify_detailed(&f);
            assert_eq!(c.outcome, Outcome::CompletedWithReadErrors);
            assert!(
                c.reason
                    .starts_with("2 sectors (1 KiB) in 1 range unreadable and replaced by zeros"),
                "{}",
                c.reason
            );
        }
    }

    #[test]
    fn rule_7_matched_is_verified() {
        let c = classify_detailed(&complete(matched()));
        assert_eq!(c.outcome, Outcome::Verified);
        assert_eq!(c.reason, "image re-read");
    }

    #[test]
    fn rule_8_not_possible_is_complete_unverified() {
        assert_eq!(
            classify(&complete(not_possible())),
            Outcome::CompleteUnverified
        );
    }

    #[test]
    fn more_bytes_than_expected_is_not_a_shortfall() {
        let mut f = complete(matched());
        f.bytes_acquired += 1;
        assert_eq!(classify(&f), Outcome::Verified);
    }

    #[test]
    fn exit_codes_labels_and_explanations() {
        let codes: Vec<i32> = Outcome::ALL.iter().map(Outcome::exit_code).collect();
        assert_eq!(codes, [0, 9, 7, 6, 5, 4, 8]);
        let mut labels: Vec<&str> = Outcome::ALL.iter().map(Outcome::label).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), Outcome::ALL.len());
        for o in Outcome::ALL {
            for e in [EngineKind::Ewf, EngineKind::Raw, EngineKind::Rescue] {
                let text = o.explanation_for(e);
                assert!(text.ends_with('.'), "{text}");
                assert!(!text.contains("ALL HASHES MATCH"));
            }
            assert_eq!(o.to_string(), o.label());
        }
        // R12: rescue wording names the map areas, the remedy and substituted sectors
        let inc = Outcome::Incomplete.explanation_for(EngineKind::Rescue);
        assert!(inc.contains("untried") && inc.contains("run the rescue again"));
        let rd = Outcome::CompletedWithReadErrors.explanation_for(EngineKind::Rescue);
        assert!(rd.contains("substituted sectors"));
        assert!(Outcome::CompletedWithReadErrors
            .explanation()
            .contains("substituted sectors"));
        assert_eq!(
            Outcome::Verified.explanation_for(EngineKind::Rescue),
            Outcome::Verified.explanation()
        );
        assert_eq!(exit_code::REFUSED, 3);
        assert_eq!(exit_code::USAGE, 2);
        assert_eq!(exit_code::INTERNAL_ERROR, 1);
    }

    #[test]
    fn outcome_serialises_snake_case() {
        assert_eq!(
            serde_json::to_string(&Outcome::CompletedWithReadErrors).unwrap(),
            "\"completed_with_read_errors\""
        );
        let v = serde_json::to_value(mismatched()).unwrap();
        assert_eq!(v["status"], "mismatched");
        assert_eq!(v["details"], "MD5 differs");
    }

    fn table(ranges: &[(u64, u64, RangeKind)]) -> ReadErrorTable {
        let mut t = ReadErrorTable::new(512, "test");
        for &(o, l, k) in ranges {
            t.push(o, l, k);
        }
        t
    }

    fn spans(t: &ReadErrorTable) -> Vec<(u64, u64, RangeKind)> {
        t.ranges
            .iter()
            .map(|r| (r.offset, r.length, r.kind))
            .collect()
    }

    use RangeKind::{Substituted as S, Unread as U};

    #[test]
    fn adjacent_and_overlapping_ranges_of_one_kind_merge() {
        let t = table(&[(0, 512, S), (512, 512, S), (2048, 512, S)]);
        assert_eq!(spans(&t), [(0, 1024, S), (2048, 512, S)]);

        let t = table(&[(1024, 1024, S), (0, 1536, S)]);
        assert_eq!(spans(&t), [(0, 2048, S)]);

        // Contained range disappears
        let t = table(&[(0, 4096, U), (512, 512, U)]);
        assert_eq!(spans(&t), [(0, 4096, U)]);

        // Unsorted input with duplicates
        let t = table(&[(8192, 512, S), (0, 512, S), (8192, 512, S), (512, 512, S)]);
        assert_eq!(spans(&t), [(0, 1024, S), (8192, 512, S)]);
        assert_eq!(t.substituted_bytes(), 1536);
        assert_eq!(t.count(S), 2);
    }

    #[test]
    fn unread_wins_where_kinds_overlap() {
        let t = table(&[(0, 4096, S), (1024, 1024, U)]);
        assert_eq!(spans(&t), [(0, 1024, S), (1024, 1024, U), (2048, 2048, S)]);
        assert_eq!(t.substituted_bytes(), 3072);
        assert_eq!(t.unread_bytes(), 1024);

        let t = table(&[(1024, 1024, U), (0, 4096, S)]);
        assert_eq!(spans(&t), [(0, 1024, S), (1024, 1024, U), (2048, 2048, S)]);

        // Adjacent ranges of different kinds stay separate
        let t = table(&[(0, 512, S), (512, 512, U)]);
        assert_eq!(spans(&t), [(0, 512, S), (512, 512, U)]);
    }

    #[test]
    fn empty_ranges_are_dropped_and_huge_offsets_saturate() {
        let mut t = table(&[(100, 0, S)]);
        assert!(t.is_empty());
        assert!(t.ranges.is_empty());
        t.push(u64::MAX - 10, 100, U);
        assert_eq!(spans(&t), [(u64::MAX - 10, 100, U)]);
        assert_eq!(t.ranges[0].end(), u64::MAX);
        // Direct edits are repaired by normalise
        t.ranges.push(ReadErrorRange::new(0, 0, S));
        t.ranges.push(ReadErrorRange::new(0, 512, S));
        t.normalise();
        assert_eq!(spans(&t)[0], (0, 512, S));
    }

    #[test]
    fn sector_counts_include_partial_sectors() {
        let t = table(&[(0, 1024, S), (1536, 100, U), (4000, 200, S)]);
        // 2 + 1 + (sector 7 and 8) = 5
        assert_eq!(t.sectors(), 5);
        assert_eq!(t.substituted_sectors(), 4);
        assert_eq!(t.unread_sectors(), 1);
        let mut t4k = ReadErrorTable::new(4096, "x");
        t4k.push_sectors(2, 3, S);
        assert_eq!(spans(&t4k), [(8192, 12288, S)]);
        assert_eq!(t4k.sectors(), 3);
        // Unknown sector size counts in 512-byte sectors
        let mut unknown = ReadErrorTable::default();
        unknown.push(0, 4096, U);
        assert_eq!(unknown.sectors(), 8);
    }

    #[test]
    fn merging_tables_unions_ranges_and_sources() {
        let mut parsed = ReadErrorTable::new(4096, "ewfacquire output");
        parsed.push(0, 4096, S);
        parsed.push(65536, 4096, S);
        let mut stored = ReadErrorTable::new(512, "ewfinfo -e");
        stored.push(2048, 4096, S);
        stored.push(65536, 512, U);
        parsed.merge(&stored);
        assert_eq!(parsed.sector_size, 512);
        assert_eq!(parsed.source, "ewfacquire output + ewfinfo -e");
        assert_eq!(
            spans(&parsed),
            [(0, 6144, S), (65536, 512, U), (66048, 3584, S)]
        );
        // Merging the same source twice does not repeat it
        let copy = parsed.clone();
        parsed.merge(&copy);
        assert_eq!(parsed.source, "ewfacquire output + ewfinfo -e");
        assert_eq!(spans(&parsed), spans(&copy));
        // Merging into an empty table adopts the other's metadata
        let mut empty = ReadErrorTable::default();
        empty.merge(&stored);
        assert_eq!(empty.sector_size, 512);
        assert_eq!(empty.source, "ewfinfo -e");
    }

    #[test]
    fn summaries_state_sectors_size_and_ranges() {
        let t = table(&[(0, 32768, S), (1 << 20, 32768, S)]);
        assert_eq!(
            t.summary(S).as_deref(),
            Some("128 sectors (64 KiB) in 2 ranges")
        );
        assert_eq!(t.summary(U), None);
        let one = table(&[(0, 512, U)]);
        assert_eq!(
            one.summary(U).as_deref(),
            Some("1 sector (512 B) in 1 range")
        );
    }

    #[test]
    fn verification_result_texts() {
        assert_eq!(matched().describe(), "matched (image re-read)");
        assert!(mismatched().describe().starts_with("MISMATCH (ewfverify)"));
        assert!(failed().describe().starts_with("FAILED"));
        assert!(not_possible().describe().starts_with("not possible"));
        assert!(matched().is_matched());
        assert!(!VerificationResult::default().is_matched());
    }
}
