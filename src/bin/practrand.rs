use std::io::Write;
use barzakh_521::Barzakh521Batch;

fn main() {
    let mut rng = Barzakh521Batch::new(b"practrand-barzakh521-v1");
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::with_capacity(1 << 20, stdout.lock());
    loop {
        let block = rng.next_batch();
        if out.write_all(&block).is_err() { break; }
    }
}
