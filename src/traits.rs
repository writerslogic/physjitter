//! Core traits for entropy sources and jitter engines.

use crate::{Error, Jitter, PhysHash};

/// Source of physical entropy from hardware or environment.
pub trait EntropySource {
    /// Collect entropy sample, mixing with provided inputs.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    /// Validate that a captured hash meets statistical requirements.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Engine that computes jitter delays from entropy.
pub trait JitterEngine {
    /// Compute jitter delay from secret, inputs, and entropy.
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
