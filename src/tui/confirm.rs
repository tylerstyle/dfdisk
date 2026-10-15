//! The typed confirmation of the confirmation sheet (§16, R10): before an
//! acquisition or conversion starts, the examiner types the last 4
//! characters of the source's serial number (the full serial when it is
//! shorter), or the evidence number when the source has no serial. Trimmed,
//! case-insensitive. Nothing (no environment variable, no option) bypasses it.

/// What the examiner has to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmBasis {
    /// The end of the serial number
    Serial,
    /// The whole evidence number (no serial)
    EvidenceNumber,
}

/// The expected confirmation input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmTarget {
    pub basis: ConfirmBasis,
    expected: String,
    /// Characters to type (for the prompt): 4, fewer for a short serial
    pub length: usize,
}

fn normalise(s: &str) -> String {
    s.trim().to_lowercase()
}

impl ConfirmTarget {
    /// Target for a source with `serial` (as shown on the sheet) and the
    /// case's `evidence` number.
    pub fn new(serial: Option<&str>, evidence: &str) -> Self {
        match serial.map(str::trim).filter(|s| !s.is_empty()) {
            Some(serial) => {
                let chars: Vec<char> = serial.chars().collect();
                let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
                Self {
                    basis: ConfirmBasis::Serial,
                    length: tail.chars().count(),
                    expected: normalise(&tail),
                }
            }
            None => Self {
                basis: ConfirmBasis::EvidenceNumber,
                length: evidence.trim().chars().count(),
                expected: normalise(evidence),
            },
        }
    }

    /// Does `typed` confirm? Never for an empty expectation.
    pub fn matches(&self, typed: &str) -> bool {
        !self.expected.is_empty() && normalise(typed) == self.expected
    }

    /// The instruction shown above the input.
    pub fn prompt(&self) -> String {
        match self.basis {
            ConfirmBasis::Serial if self.length < 4 => format!(
                "Type the serial number of the source ({} characters) to start",
                self.length
            ),
            ConfirmBasis::Serial => {
                "Type the LAST 4 CHARACTERS of the source's serial number to start".into()
            }
            ConfirmBasis::EvidenceNumber => {
                "The source reports no serial number: type the EVIDENCE NUMBER to start".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_four_of_the_serial_trimmed_case_insensitive() {
        let t = ConfirmTarget::new(Some("  S3Z9NB0K123abc  "), "EV01");
        assert_eq!(t.basis, ConfirmBasis::Serial);
        assert!(t.matches("3abc"));
        assert!(t.matches(" 3ABC "));
        assert!(!t.matches("abc"));
        assert!(!t.matches("23abc"));
        assert!(!t.matches("EV01"));
        assert!(!t.matches(""));
    }

    #[test]
    fn short_serial_is_typed_in_full() {
        let t = ConfirmTarget::new(Some("X7"), "EV01");
        assert_eq!(t.length, 2);
        assert!(t.matches("x7"));
        assert!(!t.matches("7"));
        assert!(t.prompt().contains("2 characters"));
    }

    #[test]
    fn no_serial_means_the_evidence_number() {
        for serial in [None, Some(""), Some("   ")] {
            let t = ConfirmTarget::new(serial, " Cf-01 ");
            assert_eq!(t.basis, ConfirmBasis::EvidenceNumber);
            assert!(t.matches("cf-01"));
            assert!(!t.matches("01"));
        }
        // Nothing to type, nothing confirms
        assert!(!ConfirmTarget::new(None, "  ").matches(""));
    }

    #[test]
    fn multibyte_serial_tail_is_by_characters() {
        let t = ConfirmTarget::new(Some("ÄÖÜßéè"), "x");
        assert!(t.matches("üßéè"));
        assert!(t.matches("ÜßÉÈ"));
        assert!(!t.matches("ßéè"));
    }
}
