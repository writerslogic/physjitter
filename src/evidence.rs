//! Serializable evidence types for proof-of-process records.

use serde::{Deserialize, Serialize};

use crate::{Jitter, PhysHash};

/// Evidence of a jitter computation, serializable for storage/verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Evidence {
    /// Physics-bound evidence with hardware entropy.
    Phys {
        /// Hash of hardware entropy samples.
        phys_hash: PhysHash,
        /// Computed jitter delay in microseconds.
        jitter: Jitter,
        /// Timestamp of capture (Unix micros).
        timestamp_us: u64,
    },
    /// Pure HMAC-based evidence (economic security).
    Pure {
        /// Computed jitter delay in microseconds.
        jitter: Jitter,
        /// Timestamp of capture (Unix micros).
        timestamp_us: u64,
    },
}

impl Evidence {
    /// Create physics-bound evidence.
    pub fn phys(phys_hash: PhysHash, jitter: Jitter) -> Self {
        Self::Phys {
            phys_hash,
            jitter,
            timestamp_us: current_timestamp_us(),
        }
    }

    /// Create pure HMAC evidence.
    pub fn pure(jitter: Jitter) -> Self {
        Self::Pure {
            jitter,
            timestamp_us: current_timestamp_us(),
        }
    }

    /// Get the jitter value regardless of evidence type.
    pub fn jitter(&self) -> Jitter {
        match self {
            Evidence::Phys { jitter, .. } => *jitter,
            Evidence::Pure { jitter, .. } => *jitter,
        }
    }

    /// Check if this is physics-bound evidence.
    pub fn is_phys(&self) -> bool {
        matches!(self, Evidence::Phys { .. })
    }

    /// Get timestamp in microseconds.
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Evidence::Phys { timestamp_us, .. } => *timestamp_us,
            Evidence::Pure { timestamp_us, .. } => *timestamp_us,
        }
    }
}

/// Aggregated evidence for a session or document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    /// Version of evidence format.
    pub version: u8,
    /// Individual evidence records.
    pub records: Vec<Evidence>,
    /// Running hash of the chain (for integrity).
    pub chain_hash: PhysHash,
}

impl Default for EvidenceChain {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceChain {
    /// Create a new empty evidence chain.
    pub fn new() -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_hash: [0u8; 32],
        }
    }

    /// Append evidence and update chain hash.
    pub fn append(&mut self, evidence: Evidence) {
        use sha2::{Digest, Sha256};

        // Update chain hash
        let mut hasher = Sha256::new();
        hasher.update(&self.chain_hash);
        hasher.update(serde_json::to_vec(&evidence).unwrap_or_default());
        let result = hasher.finalize();
        self.chain_hash.copy_from_slice(&result);

        self.records.push(evidence);
    }

    /// Get count of physics-bound records.
    pub fn phys_count(&self) -> usize {
        self.records.iter().filter(|e| e.is_phys()).count()
    }

    /// Get count of pure HMAC records.
    pub fn pure_count(&self) -> usize {
        self.records.iter().filter(|e| !e.is_phys()).count()
    }

    /// Calculate physics coverage ratio (0.0 to 1.0).
    pub fn phys_ratio(&self) -> f64 {
        if self.records.is_empty() {
            0.0
        } else {
            self.phys_count() as f64 / self.records.len() as f64
        }
    }
}

/// Get current timestamp in microseconds.
fn current_timestamp_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_serialization() {
        let evidence = Evidence::phys([1u8; 32], 1500);
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.jitter(), parsed.jitter());
        assert!(parsed.is_phys());
    }

    #[test]
    fn test_evidence_chain() {
        let mut chain = EvidenceChain::new();
        assert_eq!(chain.records.len(), 0);

        chain.append(Evidence::phys([1u8; 32], 1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::phys([2u8; 32], 2000));

        assert_eq!(chain.records.len(), 3);
        assert_eq!(chain.phys_count(), 2);
        assert_eq!(chain.pure_count(), 1);
        assert!((chain.phys_ratio() - 0.666).abs() < 0.01);
    }
}
