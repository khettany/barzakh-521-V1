use std::io::Write;
use std::sync::mpsc;
use std::thread;
use barzakh_521::{Barzakh521Batch, STANDARD_MAX_CORES};

fn main() {
    let num_threads = STANDARD_MAX_CORES;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(num_threads * 4);

    for tid in 0..num_threads {
        let tx = tx.clone();
        thread::spawn(move || {
            let seed = format!("barzakh521-parallel-{:02}", tid);
            let mut rng = Barzakh521Batch::new(seed.as_bytes());
            let buf_size = 256 * 1024;
            loop {
                let mut buf = vec![0u8; buf_size];
                rng.fill_bytes(&mut buf);
                if tx.send(buf).is_err() { break; }
            }
        });
    }
    drop(tx);

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::with_capacity(1 << 20, stdout.lock());
    for buf in rx {
        if out.write_all(&buf).is_err() { break; }
    }
}
