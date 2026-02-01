//! Hardware-based entropy source using timing measurements.
//!
//! Provides physics-bound jitter using TSC (Time Stamp Counter) and
//! system timing variations for hardware-level entropy collection.

use sha2::{Digest, Sha256};

use crate::{EntropySource, Error, Jitter, JitterEngine, PhysHash};

/// Hardware entropy source using timing measurements.
///
/// Security model: Physics - entropy derived from hardware timing
/// variations that cannot be perfectly simulated.
#[derive(Debug, Clone, Default)]
pub struct PhysJitter {
    /// Minimum entropy bits required for valid sample.
    pub min_entropy_bits: u8,
}

impl PhysJitter {
    /// Create with custom entropy requirements.
    pub fn new(min_entropy_bits: u8) -> Self {
        Self { min_entropy_bits }
    }

    /// Capture raw timing samples from hardware.
    #[cfg(feature = "hardware")]
    fn capture_timing_samples(&self, count: usize) -> Vec<u64> {
        let mut samples = Vec::with_capacity(count);

        for _ in 0..count {
            // Read TSC if available
            #[cfg(target_arch = "x86_64")]
            {
                let tsc: u64;
                unsafe {
                    core::arch::x86_64::_mm_lfence();
                    tsc = core::arch::x86_64::_rdtsc();
                }
                samples.push(tsc);
            }

            #[cfg(target_arch = "aarch64")]
            {
                let cntvct: u64;
                unsafe {
                    core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
                }
                samples.push(cntvct);
            }

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                use std::time::Instant;
                let now = Instant::now();
                samples.push(now.elapsed().as_nanos() as u64);
            }
        }

        samples
    }

    /// Capture timing samples (fallback for non-hardware builds).
    #[cfg(not(feature = "hardware"))]
    fn capture_timing_samples(&self, count: usize) -> Vec<u64> {
        use std::time::Instant;

        let mut samples = Vec::with_capacity(count);
        let start = Instant::now();

        for _ in 0..count {
            samples.push(start.elapsed().as_nanos() as u64);
            // Small busy-wait to introduce timing variation
            std::hint::spin_loop();
        }

        samples
    }

    /// Estimate entropy bits from sample variance.
    fn estimate_entropy(&self, samples: &[u64]) -> u8 {
        if samples.len() < 2 {
            return 0;
        }

        // Calculate deltas between consecutive samples
        let deltas: Vec<i64> = samples
            .windows(2)
            .map(|w| (w[1] as i64).wrapping_sub(w[0] as i64))
            .collect();

        // Calculate variance of deltas
        let mean: f64 = deltas.iter().map(|&d| d as f64).sum::<f64>() / deltas.len() as f64;
        let variance: f64 = deltas
            .iter()
            .map(|&d| {
                let diff = d as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / deltas.len() as f64;

        // Estimate entropy bits (simplified)
        let std_dev = variance.sqrt();
        if std_dev < 1.0 {
            0
        } else {
            (std_dev.log2().ceil() as u8).min(64)
        }
    }
}

impl EntropySource for PhysJitter {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error> {
        // Capture timing samples
        let samples = self.capture_timing_samples(64);

        // Check minimum entropy
        let entropy_bits = self.estimate_entropy(&samples);
        if entropy_bits < self.min_entropy_bits {
            return Err(Error::InsufficientEntropy {
                required: self.min_entropy_bits,
                found: entropy_bits,
            });
        }

        // Hash samples with inputs
        let mut hasher = Sha256::new();
        for sample in &samples {
            hasher.update(sample.to_le_bytes());
        }
        hasher.update(inputs);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);

        Ok(hash)
    }

    fn validate(&self, _hash: PhysHash) -> bool {
        // For now, any hash that was successfully created is valid
        // Future: could store entropy estimate in hash metadata
        true
    }
}

impl JitterEngine for PhysJitter {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        mac.update(inputs);
        mac.update(&entropy);
        let result = mac.finalize().into_bytes();

        // Extract jitter value (500-3000μs range)
        let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
        500 + (hash_val % 2500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_collection() {
        let phys = PhysJitter::new(0); // No minimum for testing
        let result = phys.sample(b"test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_entropy_estimation() {
        let phys = PhysJitter::default();

        // Constant delta (linear) - variance of deltas is 0
        let constant_delta: Vec<u64> = (0..64).map(|i| 1000 + i * 100).collect();
        let low_entropy = phys.estimate_entropy(&constant_delta);

        // Varying deltas - variance of deltas is high
        let varying_delta: Vec<u64> = (0..64)
            .map(|i| 1000 + (i * i * 37 + i * 17) % 10000)
            .collect();
        let high_entropy = phys.estimate_entropy(&varying_delta);

        // Linear sequence should have low/zero entropy (constant deltas)
        // Varying sequence should have higher entropy
        assert!(
            high_entropy >= low_entropy,
            "Expected high_entropy ({}) >= low_entropy ({})",
            high_entropy,
            low_entropy
        );
    }
}
