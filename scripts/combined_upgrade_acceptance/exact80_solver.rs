//! Bounded single-thread CPU nonce helper. No node, wallet, network, or authority.
//! Root compiles against its already-built sha2 rlib; no Cargo/build is run here.
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Instant};

fn decode<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "hex length");
    let mut bytes = [0; N];
    for (index, out) in bytes.iter_mut().enumerate() {
        *out = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex");
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let words: Vec<String> = std::env::args().skip(1).collect();
    assert!(words.len() == 8 && words.len() % 2 == 0, "four explicit option/value pairs required");
    let args: HashMap<_, _> = words.chunks_exact(2).map(|p| (p[0].as_str(), p[1].as_str())).collect();
    assert_eq!(args.len(), 4, "duplicate option");
    let mut header = decode::<80>(args["--header80"]);
    let target = decode::<32>(args["--target"]);
    let attempts: u64 = args["--max-attempts"].parse().expect("attempt count");
    let timeout_ms: u128 = args["--timeout-ms"].parse().expect("timeout");
    assert!(attempts > 0 && attempts <= (1u64 << 32) && timeout_ms > 0, "positive bounded search required");
    let started = Instant::now();
    for candidate in 0..attempts {
        if candidate % 4096 == 0 && started.elapsed().as_millis() >= timeout_ms {
            eprintln!("single-thread nonce time bound exhausted after {candidate} attempts");
            std::process::exit(2);
        }
        header[76..80].copy_from_slice(&(candidate as u32).to_le_bytes());
        let first = Sha256::digest(header);
        let mut hash: [u8; 32] = Sha256::digest(first).into();
        hash.reverse();
        if hash <= target {
            println!("{{\"nonce\":{candidate},\"attempts\":{},\"seconds\":{},\"header80\":\"{}\",\"work_hash\":\"0x{}\"}}",
                candidate + 1, started.elapsed().as_secs_f64(), hex(&header), hex(&hash));
            return;
        }
    }
    eprintln!("single-thread nonce attempt bound exhausted after {attempts} attempts");
    std::process::exit(2);
}
