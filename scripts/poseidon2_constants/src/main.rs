use p3_field::PrimeField64;
use p3_goldilocks::{Goldilocks, MATRIX_DIAG_12_GOLDILOCKS};
use p3_poseidon2::{poseidon2_round_numbers_128, ExternalLayerConstants};
use rand::distr::StandardUniform;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const WIDTH: usize = 12;
const D: u64 = 7;
const SEED: [u8; 32] = *b"hegemon-tx-poseidon2-seed-2026!!";

fn to_hex_u64(value: u64) -> String {
    format!("0x{value:016x}")
}

fn format_row(row: &[u64]) -> String {
    let values: Vec<String> = row.iter().map(|v| to_hex_u64(*v)).collect();
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

fn main() {
    let (rounds_f, rounds_p) =
        poseidon2_round_numbers_128::<Goldilocks>(WIDTH, D).expect("round numbers");
    let mut rng = ChaCha20Rng::from_seed(SEED);
    let external = ExternalLayerConstants::<Goldilocks, WIDTH>::new_from_rng(rounds_f, &mut rng);
    let internal: Vec<Goldilocks> = rng
        .sample_iter(StandardUniform)
        .take(rounds_p)
        .collect();

    println!("// Auto-generated Poseidon2 constants (ChaCha20 seed).\n//");
    println!("// Generation scheme:");
    println!("// - Field modulus: {} (Goldilocks)", Goldilocks::ORDER_U64);
    println!("// - Width: {WIDTH}");
    println!("// - S-box degree: {D}");
    println!("// - External rounds (full): {rounds_f}");
    println!("// - Internal rounds (partial): {rounds_p}");
    println!("// - Seed: {}", core::str::from_utf8(&SEED).unwrap());
    println!("//");
    println!(
        "use crate::constants::{{POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_WIDTH}};"
    );
    println!();

    let diag: Vec<u64> = MATRIX_DIAG_12_GOLDILOCKS
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();
    println!("pub const INTERNAL_MATRIX_DIAG: [u64; POSEIDON2_WIDTH] = {};", format_row(&diag));
    println!();

    let initial = external
        .get_initial_constants()
        .iter()
        .map(|row| row.iter().map(|v| v.as_canonical_u64()).collect::<Vec<u64>>())
        .collect::<Vec<_>>();
    let terminal = external
        .get_terminal_constants()
        .iter()
        .map(|row| row.iter().map(|v| v.as_canonical_u64()).collect::<Vec<u64>>())
        .collect::<Vec<_>>();

    println!("pub const EXTERNAL_ROUND_CONSTANTS: [[[u64; POSEIDON2_WIDTH]; POSEIDON2_EXTERNAL_ROUNDS]; 2] = [");
    println!("    {},", format_rows(&initial, "    "));
    println!("    {},", format_rows(&terminal, "    "));
    println!("];\n");

    let internal_vals: Vec<u64> = internal.iter().map(|v| v.as_canonical_u64()).collect();
    println!("pub const INTERNAL_ROUND_CONSTANTS: [u64; POSEIDON2_INTERNAL_ROUNDS] = [");
    for value in internal_vals {
        println!("    {},", to_hex_u64(value));
    }
    println!("];\n");
}
