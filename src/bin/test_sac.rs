use barzakh_521::Barzakh521;

fn main() {
    println!("=== Barzakh-521: SAC ===\n");
    let samples = 1u64 << 18;
    let output_bits = 256;
    let mut counts = vec![0u64; output_bits];
    let base_seed = b"sac-test-barzakh521-base-seed-v1";
    let positions: Vec<usize> = vec![
        0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 100, 127, 128, 200, 255,
    ];
    let mut worst_dev = 0.0f64;

    println!("  {:>6} | {:>8} {:>8} {:>8} | {:>7} | {}",
        "InBit", "Min%", "Avg%", "Max%", "Dev%", "Result");
    println!("  -------+---------------------------+---------+--------");

    for &bit_pos in &positions {
        for c in counts.iter_mut() { *c = 0; }
        for ctr in 0..samples {
            let mut s1 = Vec::from(&base_seed[..]);
            s1.extend_from_slice(&ctr.to_le_bytes());
            let mut s2 = s1.clone();
            let bi = bit_pos / 8;
            while s2.len() <= bi { s2.push(0); }
            s2[bi] ^= 1u8 << (bit_pos % 8);
            let o1 = Barzakh521::new(&s1).next_u256();
            let o2 = Barzakh521::new(&s2).next_u256();
            for byte in 0..32 {
                let diff = o1[byte] ^ o2[byte];
                for b in 0..8 {
                    if (diff >> b) & 1 == 1 { counts[byte * 8 + b] += 1; }
                }
            }
        }
        let (mut mn, mut mx, mut sm, mut md) = (100.0f64, 0.0f64, 0.0f64, 0.0f64);
        for ob in 0..output_bits {
            let p = counts[ob] as f64 / samples as f64 * 100.0;
            let d = (p - 50.0).abs();
            if p < mn { mn = p; }
            if p > mx { mx = p; }
            if d > md { md = d; }
            sm += p;
        }
        let avg = sm / output_bits as f64;
        if md > worst_dev { worst_dev = md; }
        let v = if md < 0.50 { "PASS" } else if md < 1.0 { "WARN" } else { "FAIL" };
        println!("  {:>6} | {:>7.3}% {:>7.3}% {:>7.3}% | {:>6.3}% | {}",
            bit_pos, mn, avg, mx, md, v);
    }
    println!("\n  SAC = 50.000% +/- {:.3}%", worst_dev);
    if worst_dev < 0.50 {
        println!("  VERDICT: PASS");
    } else if worst_dev < 1.0 {
        println!("  VERDICT: ACCEPTABLE");
    } else {
        println!("  VERDICT: FAIL");
    }
}
