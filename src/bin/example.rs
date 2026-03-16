use barzakh_521::{Barzakh521, Barzakh521Batch};

fn main() {
    println!("=== Barzakh-521 ===\n");

    let mut rng = Barzakh521::new(b"my-secret-seed");
    for i in 0..3 {
        let block = rng.next_u256();
        print!("Block {}: ", i);
        for b in &block[..8] { print!("{:02x}", b); }
        println!("...");
    }

    let mut batch = Barzakh521Batch::new(b"batch-seed");
    let data = batch.next_batch();
    println!("\nBatch: {} bytes", data.len());
}
