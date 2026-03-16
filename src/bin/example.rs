use barzakh_521::{Barzakh521, Barzakh521Batch};

fn main() {
    println!("=== Barzakh-521 Examples ===\n");

    // Single stream
    println!("--- Single Stream ---");
    let mut rng = Barzakh521::new(b"my-secret-seed");
    for i in 0..5 {
        let block = rng.next_u256();
        print!("  Block {}: ", i);
        for b in &block[..8] { print!("{:02x}", b); }
        println!("...");
    }

    // Batch (8 streams, Montgomery trick)
    println!("\n--- Batch (8 streams, Montgomery) ---");
    let mut batch = Barzakh521Batch::new(b"batch-seed");
    let data = batch.next_batch();
    println!("  Generated {} bytes in 1 call", data.len());
    print!("  First 16 bytes: ");
    for b in &data[..16] { print!("{:02x}", b); }
    println!();

    // Fill arbitrary buffer
    println!("\n--- Fill Buffer ---");
    let mut buf = vec![0u8; 1000];
    batch.fill_bytes(&mut buf);
    println!("  Filled {} bytes", buf.len());
}
