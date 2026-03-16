# Barzakh-521

**Geometric Chaos Engine — Cryptographic Key Generator over GF(2^521 - 1)**

A CSPRNG based on quadratic torsion and modular inversion over the
Mersenne prime field M521. Designed as a certified source of randomness
for key generation (AES, RSA, ECDSA, Ed25519).

**Author:** Abdelghaffour Khettany (Morocco)
**Patent:** OMPIC / PCT — Pending

## What is Barzakh-521?

Barzakh-521 is a **cryptographic key generator** (CSPRNG) — the component
that creates the random material used by encryption engines (AES, ChaCha20)
and stored in key vaults (HSM, Azure Key Vault).

It is NOT an encryption engine. It is NOT a key store.
It is the **certified source of randomness** that feeds both.

## Formula

    k = (a * x^2 + b) * (x - a)^(-1) + w   (mod 2^521 - 1)
    x <- W XOR k
    output = k >> 265  (top 256 bits)

## Security Certifications

| Test | Result | Details |
|------|--------|---------|
| PractRand | PASS 1 TB | 7 consecutive perfect passes (16 GB - 1 TB) |
| Z3 SMT | TIMEOUT 390s | 1-round attack, 2^1042 search space |
| Bitwuzla | TIMEOUT all | 1r (30/120/300s) + 2r (300s) |
| Bitwuzla + Z3 | BOTH FAIL | Neither solver recovers internal state |
| SAC | 50.00% +/- 0.36% | ChaCha20 / SHAKE256 level avalanche |

## Performance

| Mode | Throughput | Description |
|------|-----------|-------------|
| Single stream | ~1 MB/s | 1 core, Fermat inversion |
| Batch x8 | 7.54 MB/s | 1 core, Montgomery batch inversion |
| 4 cores | ~30 MB/s | Standard tier (AGPL v3) |

At 7.5 MB/s, generates 234,000+ AES-256 keys per second.

## Quick Start

    git clone https://github.com/AKhettany/barzakh-521.git
    cd barzakh-521
    cargo build --release
    cargo test --release
    cargo run --release --bin bench

## Usage

    use barzakh_521::{Barzakh521, Barzakh521Batch};

    // Single stream
    let mut rng = Barzakh521::new(b"your-secret-seed");
    let key: [u8; 32] = rng.next_u256();

    // Batch (8x faster)
    let mut batch = Barzakh521Batch::new(b"your-seed");
    let data: Vec<u8> = batch.next_batch(); // 256 bytes

    // Fill buffer
    let mut buf = vec![0u8; 1_000_000];
    batch.fill_bytes(&mut buf);

## PractRand

    cargo run --release --bin practrand 2>/dev/null | RNG_test stdin -tlmax 1TB
    cargo run --release --bin practrand_parallel 2>/dev/null | RNG_test stdin -tlmax 32TB

## SAC Test

    cargo run --release --bin test_sac

## Memory Safety

All internal state (field elements, seeds, intermediate buffers) is
automatically zeroed on drop using the zeroize crate. No key material
lingers in memory after the CSPRNG instance is destroyed.

## Editions

| Feature | Standard (AGPL v3) | Enterprise | Organization |
|---------|-------------------|------------|--------------|
| Price | Free | Commercial | Commercial |
| Max Cores | 4 | 16 | Unlimited |
| Domain Isolation | - | domain_id | domain_id |
| User Isolation | - | - | user_id |
| Memory Zeroization | Yes | Yes | Yes |
| Audit Hooks | - | - | Yes |

Enterprise/Organization: enterprise@barzakh521.com

## License

Standard: GNU AGPL v3 — see LICENSE
Commercial editions available on request.
Patent: OMPIC / PCT — Pending.
