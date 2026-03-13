use core::marker::PhantomData;
use std::time::Instant;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::FriParameters;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

const TRACE_ROWS: usize = 1 << 13;
const TRACE_WIDTH: usize = 146;
const PUBLIC_VALUES: usize = 76;
const FIRST_ROW_PUBLIC_VALUES: usize = PUBLIC_VALUES - 2;
const LOG_BLOWUP: usize = 1;
const NUM_QUERIES: usize = 40;

type Val = Mersenne31;
type Challenge = BinomialExtensionField<Val, 3>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

struct ShapeAir;

impl<F> BaseAir<F> for ShapeAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilderWithPublicValues<F = Val>> Air<AB> for ShapeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.row_slice(0).expect("trace must have a current row");
        let next = main.row_slice(1).expect("trace must have a next row");
        let public_values = builder
            .public_values()
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();

        let mut when_first = builder.when_first_row();
        for idx in 0..FIRST_ROW_PUBLIC_VALUES {
            when_first.assert_eq(current[idx].clone(), public_values[idx].clone());
        }

        let mut when_transition = builder.when_transition();
        for col in 0..TRACE_WIDTH {
            let step = AB::Expr::from_u64((col + 1) as u64);
            when_transition.assert_eq(next[col].clone(), current[col].clone() + step);
        }

        let mut when_last = builder.when_last_row();
        when_last.assert_eq(
            current[TRACE_WIDTH - 2].clone(),
            public_values[PUBLIC_VALUES - 2].clone(),
        );
        when_last.assert_eq(
            current[TRACE_WIDTH - 1].clone(),
            public_values[PUBLIC_VALUES - 1].clone(),
        );
    }
}

fn generate_trace(public_values: &[Val]) -> RowMajorMatrix<Val> {
    let mut values = vec![Val::ZERO; TRACE_ROWS * TRACE_WIDTH];
    let width = TRACE_WIDTH;

    for col in 0..TRACE_WIDTH {
        values[col] = if col < FIRST_ROW_PUBLIC_VALUES {
            public_values[col]
        } else {
            Val::from_u64((col + 1) as u64)
        };
    }

    for row in 1..TRACE_ROWS {
        let prev = (row - 1) * width;
        let cur = row * width;
        for col in 0..TRACE_WIDTH {
            values[cur + col] = values[prev + col] + Val::from_u64((col + 1) as u64);
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn build_config() -> Config {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let pcs = Pcs {
        mmcs: val_mmcs,
        fri_params,
        _phantom: PhantomData,
    };
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    Config::new(pcs, challenger)
}

fn main() {
    let mut public_values = vec![Val::ZERO; PUBLIC_VALUES];
    for (idx, value) in public_values
        .iter_mut()
        .take(FIRST_ROW_PUBLIC_VALUES)
        .enumerate()
    {
        *value = Val::from_u64((idx as u64) + 11);
    }

    let trace = generate_trace(&public_values);
    let last_row = trace.height() - 1;
    public_values[PUBLIC_VALUES - 2] = trace.values[last_row * TRACE_WIDTH + TRACE_WIDTH - 2];
    public_values[PUBLIC_VALUES - 1] = trace.values[last_row * TRACE_WIDTH + TRACE_WIDTH - 1];
    let config = build_config();
    let air = ShapeAir;

    let prove_start = Instant::now();
    let proof = prove(&config, &air, trace, &public_values);
    let prove_ns = prove_start.elapsed().as_nanos();

    let proof_bytes = bincode::serialize(&proof)
        .expect("serialize circle proof")
        .len();

    let verify_start = Instant::now();
    verify(&config, &air, &proof, &public_values).expect("verify circle proof");
    let verify_ns = verify_start.elapsed().as_nanos();

    let report = serde_json::json!({
        "backend": "p3-circle-m31",
        "shape_proxy": true,
        "trace_rows": TRACE_ROWS,
        "trace_width": TRACE_WIDTH,
        "public_values": PUBLIC_VALUES,
        "log_blowup": LOG_BLOWUP,
        "num_queries": NUM_QUERIES,
        "proof_bytes": proof_bytes,
        "prove_ns": prove_ns,
        "verify_ns": verify_ns,
        "notes": "Synthetic width/rows/public-values proxy only. This is not an apples-to-apples port of Hegemon's transaction AIR or security profile."
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
}
