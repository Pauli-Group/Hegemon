use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const WIDTH: usize = 12;
const D: u64 = 7;
const FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 22;
const SEED: [u8; 32] = *b"hegemon-tx-poseidon2-seed-2026!!";
const INTERNAL_MATRIX_DIAG: [u64; WIDTH] = [
    0xc3b6c08e23ba9300,
    0xd84b5de94a324fb6,
    0x0d0c371c5b35b84f,
    0x7964f570e7188037,
    0x5daf18bbd996604b,
    0x6743bc47b9595257,
    0x5528b9362c59bb70,
    0xac45e25b7127b68b,
    0xa2077d7dfbb606b5,
    0xf3faac6faee378ae,
    0x0c6388b51545e883,
    0xd27dbb6944917b60,
];

fn sample_goldilocks(rng: &mut ChaCha20Rng) -> u64 {
    loop {
        let value = rng.next_u64();
        if value < FIELD_ORDER {
            return value;
        }
    }
}

fn to_hex_u64(value: u64) -> String {
    format!("0x{value:016x}")
}

fn format_row(row: &[u64]) -> String {
    let values: Vec<String> = row.iter().map(|value| to_hex_u64(*value)).collect();
    format!("[{}]", values.join(", "))
}

fn format_rows(rows: &[Vec<u64>], indent: &str) -> String {
    let mut out = String::from("[");
    for row in rows {
        out.push('\n');
        out.push_str(indent);
        out.push_str(&format_row(row));
        out.push(',');
    }
    out.push('\n');
    out.push(']');
    out
}

fn sample_rows(rng: &mut ChaCha20Rng, rows: usize) -> Vec<Vec<u64>> {
    (0..rows)
        .map(|_| {
            (0..WIDTH)
                .map(|_| sample_goldilocks(rng))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let half_f = ROUNDS_F / 2;
    let initial = sample_rows(&mut rng, half_f);
    let terminal = sample_rows(&mut rng, half_f);
    let internal = (0..ROUNDS_P)
        .map(|_| sample_goldilocks(&mut rng))
        .collect::<Vec<_>>();

    println!("// Auto-generated Poseidon2 constants (ChaCha20 seed).\n//");
    println!("// Generation scheme:");
    println!("// - Field modulus: {FIELD_ORDER} (Goldilocks)");
    println!("// - Width: {WIDTH}");
    println!("// - S-box degree: {D}");
    println!("// - External rounds (full): {ROUNDS_F}");
    println!("// - Internal rounds (partial): {ROUNDS_P}");
    println!("// - Seed: {}", core::str::from_utf8(&SEED).unwrap());
    println!("//");
    println!(
        "use crate::constants::{{POSEIDON2_EXTERNAL_ROUNDS, \
         POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_WIDTH}};"
    );
    println!();
    println!(
        "pub const INTERNAL_MATRIX_DIAG: [u64; POSEIDON2_WIDTH] = {};",
        format_row(&INTERNAL_MATRIX_DIAG)
    );
    println!();
    println!(
        "pub const EXTERNAL_ROUND_CONSTANTS: \
         [[[u64; POSEIDON2_WIDTH]; POSEIDON2_EXTERNAL_ROUNDS]; 2] = ["
    );
    println!("    {},", format_rows(&initial, "    "));
    println!("    {},", format_rows(&terminal, "    "));
    println!("];\n");
    println!(
        "pub const INTERNAL_ROUND_CONSTANTS: [u64; POSEIDON2_INTERNAL_ROUNDS] = ["
    );
    for value in internal {
        println!("    {},", to_hex_u64(value));
    }
    println!("];\n");
}
