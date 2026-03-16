use barzakh_521::*;

#[test]
fn test_full_pipeline() {
    let mut rng = Barzakh521::new(b"integration-test");
    let mut prev = rng.next_u256();
    for _ in 0..100 {
        let cur = rng.next_u256();
        assert_ne!(prev, cur, "Consecutive blocks must differ");
        prev = cur;
    }
}

#[test]
fn test_batch_inv_correctness_16() {
    let vals: Vec<F521> = (1u8..=16)
        .map(|b| F521::from_bytes_be(&[b; 66]))
        .collect();
    let invs = F521::batch_inv(&vals);
    for i in 0..vals.len() {
        assert_eq!(vals[i].mul_mod(&invs[i]), F521::ONE,
            "batch_inv[{}] failed", i);
    }
}

#[test]
fn test_fill_bytes_large() {
    let mut rng = Barzakh521Batch::new(b"fill-test-large");
    let mut buf = vec![0u8; 100_000];
    rng.fill_bytes(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));
    // Check not all the same
    let first = buf[0];
    assert!(buf.iter().any(|&b| b != first));
}
