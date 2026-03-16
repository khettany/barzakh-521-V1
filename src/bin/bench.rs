use std::time::Instant;
use barzakh_521::{F521, Barzakh521, Barzakh521Batch, BATCH_SIZE};

fn main() {
    println!("=== Barzakh-521 Benchmark ===\n");

    let a = F521::from_bytes_be(&[0x42; 66]);
    let n = 2000u64;
    let start = Instant::now();
    let mut r = a.clone();
    for _ in 0..n { r = r.inv_mod(); }
    let inv_time = start.elapsed();
    std::hint::black_box(&r);
    println!("Inversion: {:.0} ns/op", inv_time.as_nanos() as f64 / n as f64);

    let mut rng = Barzakh521::new(b"bench-seed");
    let blocks = 10_000u64;
    let start = Instant::now();
    for _ in 0..blocks { std::hint::black_box(rng.next_u256()); }
    let t = start.elapsed();
    println!("Single: {:.0} ns/block, {:.3} MB/s",
        t.as_nanos() as f64 / blocks as f64,
        (blocks * 32) as f64 / t.as_secs_f64() / 1e6);

    let mut rng_b = Barzakh521Batch::new(b"bench-seed");
    let start = Instant::now();
    for _ in 0..blocks { std::hint::black_box(rng_b.next_batch()); }
    let t = start.elapsed();
    let total = blocks * (BATCH_SIZE as u64) * 32;
    println!("Batch:  {:.0} ns/block, {:.3} MB/s",
        t.as_nanos() as f64 / (blocks as f64 * BATCH_SIZE as f64),
        total as f64 / t.as_secs_f64() / 1e6);
}
