# physjitter

Proof-of-process primitive using timing jitter for human authorship verification.

[![Crates.io](https://img.shields.io/crates/v/physjitter.svg)](https://crates.io/crates/physjitter)
[![Documentation](https://docs.rs/physjitter/badge.svg)](https://docs.rs/physjitter)
[![License](https://img.shields.io/crates/l/physjitter.svg)](LICENSE)

## Overview

`physjitter` provides cryptographic proof-of-process through timing jitter, enabling verification of human authorship in document creation. It creates tamper-evident records that prove content was typed by a human rather than generated or pasted.

## Features

- **Dual Security Models**: Economic (HMAC-based) and Physics (hardware entropy)
- **Automatic Fallback**: Uses hardware when available, falls back to HMAC in VMs
- **Human Validation**: Statistical model based on Aalto 136M keystroke dataset
- **Evidence Chain**: Serializable proof records for verification
- **Zero Dependencies on Unsafe**: Pure Rust implementation

## Installation

```toml
[dependencies]
physjitter = "0.1"
```

## Quick Start

```rust
use physjitter::{Session, Evidence};

// Create a session with your secret
let secret = [0u8; 32]; // Use proper key derivation in production
let mut session = Session::new(secret);

// Sample jitter for each keystroke
for keystroke in keystrokes {
    let jitter = session.sample(keystroke.as_bytes())?;

    // Apply jitter delay
    std::thread::sleep(std::time::Duration::from_micros(jitter as u64));
}

// Validate against human typing model
let result = session.validate();
println!("Human: {}, Confidence: {:.2}", result.is_human, result.confidence);

// Export evidence
let json = session.export_json()?;
```

## Architecture

### Traits

```rust
/// Source of physical entropy from hardware or environment.
pub trait EntropySource {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Engine that computes jitter delays from entropy.
pub trait JitterEngine {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
```

### Implementations

| Engine | Security Model | Requirements | Use Case |
|--------|---------------|--------------|----------|
| `PureJitter` | Economic | None | Universal fallback |
| `PhysJitter` | Physics | Hardware TSC | Native applications |
| `HybridEngine` | Both | Auto-detect | Production recommended |

## Security Models

### Economic Security (PureJitter)

Security relies on the economic cost of reproducing the exact input sequence. An attacker would need to retype content character-by-character with identical timing to reproduce the jitter chain.

```rust
let engine = PureJitter::new(500, 2500); // jmin=500μs, range=2500μs
let jitter = engine.compute_jitter(&secret, inputs, [0u8; 32]);
```

### Physics Security (PhysJitter)

Security relies on hardware entropy that cannot be perfectly simulated. Uses TSC (Time Stamp Counter) and timing variations unique to the physical device.

```rust
let phys = PhysJitter::new(8); // Require 8 bits minimum entropy
let entropy = phys.sample(inputs)?;
let jitter = phys.compute_jitter(&secret, inputs, entropy);
```

### Hybrid Security (HybridEngine)

Combines both models: uses physics when available, falls back to pure jitter in virtualized environments. Evidence records which mode was used.

```rust
let engine = HybridEngine::default();
let (jitter, evidence) = engine.sample(&secret, inputs)?;

match evidence {
    Evidence::Phys { .. } => println!("Hardware entropy used"),
    Evidence::Pure { .. } => println!("HMAC fallback used"),
}
```

## Human Validation

The `HumanModel` validates jitter sequences against statistical patterns derived from the Aalto 136M keystroke dataset:

```rust
let model = HumanModel::default();
let result = model.validate(&jitters);

if !result.is_human {
    for anomaly in result.anomalies {
        println!("Anomaly: {:?}", anomaly.kind);
    }
}
```

Detected anomalies include:
- **PerfectTiming**: Too many identical consecutive values
- **LowVariance**: Unnaturally consistent timing
- **RepeatingPattern**: Periodic patterns suggesting automation
- **OutOfRange**: Values outside human typing range

## Evidence Chain

Evidence is accumulated in an append-only chain with integrity protection:

```rust
let mut chain = EvidenceChain::new();
chain.append(Evidence::phys(entropy, jitter));
chain.append(Evidence::pure(jitter));

// Chain hash updated on each append
println!("Chain hash: {:?}", chain.chain_hash);
println!("Physics ratio: {:.1}%", chain.phys_ratio() * 100.0);
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | Core functionality |
| `hardware` | Enable TSC and hardware entropy collection |

## Performance

| Operation | Time |
|-----------|------|
| `PureJitter::compute_jitter` | ~200ns |
| `PhysJitter::sample` | ~10μs |
| `HumanModel::validate` (1000 samples) | ~50μs |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting PRs.

## Related Projects

- [witnessd](https://github.com/writerslogic/witnessd) - Cryptographic authorship witnessing for writers
