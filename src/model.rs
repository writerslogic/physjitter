//! Statistical model for human typing validation.
//!
//! Based on the Aalto 136M keystroke dataset for baseline human
//! inter-key interval (IKI) distributions.

use serde::{Deserialize, Serialize};

use crate::Jitter;

/// Statistical model for validating jitter sequences against human typing patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanModel {
    /// Minimum inter-key interval in microseconds.
    pub iki_min_us: u32,
    /// Maximum reasonable inter-key interval in microseconds.
    pub iki_max_us: u32,
    /// Mean inter-key interval in microseconds (Aalto: ~200ms = 200,000μs).
    pub iki_mean_us: u32,
    /// Standard deviation of IKI in microseconds.
    pub iki_std_us: u32,
    /// Minimum sequence length for statistical validation.
    pub min_sequence_length: usize,
    /// Maximum allowed perfect-timing ratio (detects automation).
    pub max_perfect_ratio: f64,
}

impl Default for HumanModel {
    fn default() -> Self {
        // Based on Aalto 136M keystroke dataset analysis
        Self {
            iki_min_us: 30_000,       // 30ms minimum (very fast typist)
            iki_max_us: 2_000_000,    // 2s maximum (thinking pause)
            iki_mean_us: 200_000,     // 200ms mean
            iki_std_us: 80_000,       // 80ms std dev
            min_sequence_length: 20,  // Minimum keystrokes for validation
            max_perfect_ratio: 0.05,  // Max 5% can be "perfect" timing
        }
    }
}

/// Result of validating a jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the sequence appears human-generated.
    pub is_human: bool,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Detected anomalies.
    pub anomalies: Vec<Anomaly>,
    /// Statistics about the sequence.
    pub stats: SequenceStats,
}

/// Detected anomaly in jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Type of anomaly.
    pub kind: AnomalyKind,
    /// Position in sequence where anomaly was detected.
    pub position: usize,
    /// Additional context.
    pub detail: String,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Too many perfectly timed intervals.
    PerfectTiming,
    /// Interval outside human range.
    OutOfRange,
    /// Statistical distribution mismatch.
    DistributionMismatch,
    /// Repeating pattern detected.
    RepeatingPattern,
    /// Unnaturally low variance.
    LowVariance,
}

/// Statistics about a jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Number of samples.
    pub count: usize,
    /// Mean jitter value.
    pub mean: f64,
    /// Standard deviation.
    pub std_dev: f64,
    /// Minimum value.
    pub min: Jitter,
    /// Maximum value.
    pub max: Jitter,
}

impl HumanModel {
    /// Validate a sequence of jitter values against human typing patterns.
    pub fn validate(&self, jitters: &[Jitter]) -> ValidationResult {
        let mut anomalies = Vec::new();

        if jitters.len() < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::DistributionMismatch,
                    position: 0,
                    detail: format!(
                        "Sequence too short: {} < {}",
                        jitters.len(),
                        self.min_sequence_length
                    ),
                }],
                stats: self.compute_stats(jitters),
            };
        }

        let stats = self.compute_stats(jitters);

        // Check for low variance (automation signal)
        if stats.std_dev < 50.0 {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("Variance too low: std_dev={:.2}", stats.std_dev),
            });
        }

        // Check for perfect timing (exact same values)
        let perfect_count = self.count_perfect_timing(jitters);
        let perfect_ratio = perfect_count as f64 / jitters.len() as f64;
        if perfect_ratio > self.max_perfect_ratio {
            anomalies.push(Anomaly {
                kind: AnomalyKind::PerfectTiming,
                position: 0,
                detail: format!("Too many perfect timings: {:.1}%", perfect_ratio * 100.0),
            });
        }

        // Check for repeating patterns
        if let Some(pattern_len) = self.detect_repeating_pattern(jitters) {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating pattern of length {}", pattern_len),
            });
        }

        // Calculate confidence based on anomalies
        let base_confidence = 1.0 - (anomalies.len() as f64 * 0.25);
        let confidence = base_confidence.max(0.0).min(1.0);

        ValidationResult {
            is_human: anomalies.is_empty() && confidence > 0.5,
            confidence,
            anomalies,
            stats,
        }
    }

    /// Compute statistics for a jitter sequence.
    fn compute_stats(&self, jitters: &[Jitter]) -> SequenceStats {
        if jitters.is_empty() {
            return SequenceStats {
                count: 0,
                mean: 0.0,
                std_dev: 0.0,
                min: 0,
                max: 0,
            };
        }

        let count = jitters.len();
        let sum: u64 = jitters.iter().map(|&j| j as u64).sum();
        let mean = sum as f64 / count as f64;

        let variance: f64 = jitters
            .iter()
            .map(|&j| {
                let diff = j as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / count as f64;

        let std_dev = variance.sqrt();
        let min = *jitters.iter().min().unwrap_or(&0);
        let max = *jitters.iter().max().unwrap_or(&0);

        SequenceStats {
            count,
            mean,
            std_dev,
            min,
            max,
        }
    }

    /// Count consecutive identical values (perfect timing).
    fn count_perfect_timing(&self, jitters: &[Jitter]) -> usize {
        jitters
            .windows(2)
            .filter(|w| w[0] == w[1])
            .count()
    }

    /// Detect repeating patterns in jitter sequence.
    fn detect_repeating_pattern(&self, jitters: &[Jitter]) -> Option<usize> {
        if jitters.len() < 6 {
            return None;
        }

        // Check for patterns of length 2-5
        for pattern_len in 2..=5 {
            if jitters.len() < pattern_len * 3 {
                continue;
            }

            let pattern = &jitters[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for chunk in jitters.chunks(pattern_len) {
                if chunk.len() == pattern_len {
                    checks += 1;
                    if chunk == pattern {
                        matches += 1;
                    }
                }
            }

            // If >80% match the pattern, it's suspicious
            if checks > 2 && matches as f64 / checks as f64 > 0.8 {
                return Some(pattern_len);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_validation() {
        let model = HumanModel::default();

        // Simulate human-like jitter (varied values)
        let human_jitters: Vec<Jitter> = (0..50)
            .map(|i| 500 + ((i * 37) % 2500) as u32)
            .collect();

        let result = model.validate(&human_jitters);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_automation_detection() {
        let model = HumanModel::default();

        // Constant values (automation signal)
        let automated_jitters: Vec<Jitter> = vec![1000; 50];

        let result = model.validate(&automated_jitters);
        assert!(!result.is_human);
        assert!(result.anomalies.iter().any(|a| matches!(a.kind, AnomalyKind::LowVariance)));
    }

    #[test]
    fn test_repeating_pattern_detection() {
        let model = HumanModel::default();

        // Repeating pattern
        let pattern_jitters: Vec<Jitter> = (0..50)
            .map(|i| [1000, 1500, 2000][i % 3])
            .collect();

        let result = model.validate(&pattern_jitters);
        assert!(result.anomalies.iter().any(|a| matches!(a.kind, AnomalyKind::RepeatingPattern)));
    }
}
