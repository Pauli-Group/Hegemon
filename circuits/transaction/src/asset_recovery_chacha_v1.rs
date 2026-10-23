//! RFC8439 ChaCha20 arithmetic/stream gadget, staged recovery feasibility only.
//!
//! This is raw ChaCha20, not an AEAD or KDF. The caller must constrain its key,
//! nonce, payload and authenticated ciphertext in the enclosing relation.
//! Words/bytes use little endian order. Inputs are range constrained; sums are
//! below 2^33 (far below Goldilocks), and discarding bit32 implements u32 wrap.
//! XOR of constrained bits stays Boolean algebraically; rotations permute bits.
//! No witness-dependent branch determines topology. Counter wrap is rejected.
//!
//! Compose `chacha20_xor` inside an existing `Scope`. For exact graph counts,
//! finish that scope and call `HtlcAdapter::from_graph(graph).geometry()`:
//! canonical_wires, rows, nonlinear_batches, linear_equations, private_inputs,
//! packing and degree are actual lowered counts, not a projected proof size.
//! Cached value variant: no repacking of addition operands, and low32 values
//! are computed by subtracting the constrained carry. XOR/rotate are fused.
//! The cache is computed, not an additional unconstrained witness input.
//! Tests below instantiate the actual evaluator and packed constraint checker.
#![forbid(unsafe_code)]

use crate::smallwood_htlc::circuit::{range, Word};
use hegemon_field::PrimeCharacteristicRing;

pub const RECOVERY_PAYLOAD_BYTES: usize = 240;
const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const ROUNDS: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

#[derive(Clone, Copy)]
struct U32 {
    bits: [Word; 32],
    // Exact integer value of bits, always in [0,2^32); not a free wire.
    value: Word,
}
fn pack(bits: &[Word]) -> Word {
    bits.iter()
        .enumerate()
        .fold(Word::ZERO, |v, (i, b)| v + *b * Word::from_u64(1u64 << i))
}
fn bitxor(a: Word, b: Word) -> Word {
    a + b - Word::TWO * a * b
}
impl U32 {
    fn constant(n: u32) -> Self {
        Self {
            bits: core::array::from_fn(|i| Word::from_u64(((n >> i) & 1) as u64)),
            value: Word::from_u64(n as u64),
        }
    }
    fn checked(w: Word) -> Self {
        Self {
            bits: range(w, 32).try_into().expect("32 constrained bits"),
            value: w,
        }
    }
    fn add(self, b: Self) -> Self {
        // Both operands are <2^32. Hence sum<2^33<p: range's field
        // recomposition is also an exact integer equality, without aliases.
        let sum = self.value + b.value;
        let bits = range(sum, 33);
        Self {
            bits: core::array::from_fn(|i| bits[i]),
            value: sum - bits[32] * Word::from_u64(1u64 << 32),
        }
    }
    fn xor_rol(self, b: Self, n: usize) -> Self {
        // Fuse XOR with its immediately following rotation. Packing the
        // unrotated intermediate would create a cache that no caller uses.
        let bits = core::array::from_fn(|i| {
            let source = (i + 32 - n) % 32;
            bitxor(self.bits[source], b.bits[source])
        });
        Self {
            value: pack(&bits),
            bits,
        }
    }
}
fn quarter(s: &mut [U32; 16], [a, b, c, d]: [usize; 4]) {
    s[a] = s[a].add(s[b]);
    s[d] = s[d].xor_rol(s[a], 16);
    s[c] = s[c].add(s[d]);
    s[b] = s[b].xor_rol(s[c], 12);
    s[a] = s[a].add(s[b]);
    s[d] = s[d].xor_rol(s[a], 8);
    s[c] = s[c].add(s[d]);
    s[b] = s[b].xor_rol(s[c], 7);
}
fn block(key: [U32; 8], nonce: [U32; 3], counter: U32) -> [U32; 16] {
    let initial = core::array::from_fn(|i| match i {
        0..=3 => U32::constant(SIGMA[i]),
        4..=11 => key[i - 4],
        12 => counter,
        _ => nonce[i - 13],
    });
    let mut s = initial;
    for _ in 0..10 {
        for indices in ROUNDS {
            quarter(&mut s, indices);
        }
    }
    core::array::from_fn(|i| s[i].add(initial[i]))
}
fn check_length(counter: u32, len: usize) -> Result<(), &'static str> {
    if len > RECOVERY_PAYLOAD_BYTES {
        return Err("recovery ChaCha payload exceeds240 bytes");
    }
    if len != 0 && counter.checked_add(((len - 1) / 64) as u32).is_none() {
        return Err("recovery ChaCha counter would wrap");
    }
    Ok(())
}

/// Key and nonce are LE u32 field words; payload/output are byte field words.
/// Length is public topology (0..=240); unused final block bytes are discarded.
pub(crate) fn chacha20_xor(
    key: [Word; 8],
    nonce: [Word; 3],
    initial_counter: u32,
    bytes: &[Word],
) -> Result<Vec<Word>, &'static str> {
    check_length(initial_counter, bytes.len())?;
    let key = key.map(U32::checked);
    let nonce = nonce.map(U32::checked);
    let mut result = Vec::with_capacity(bytes.len());
    for (index, chunk) in bytes.chunks(64).enumerate() {
        let stream = block(key, nonce, U32::constant(initial_counter + index as u32));
        for (i, byte) in chunk.iter().enumerate() {
            let input = range(*byte, 8);
            let bits: [Word; 8] = core::array::from_fn(|bit| {
                bitxor(input[bit], stream[i / 4].bits[(i % 4) * 8 + bit])
            });
            result.push(pack(&bits));
        }
    }
    Ok(result)
}

fn host_quarter(s: &mut [u32; 16], [a, b, c, d]: [usize; 4]) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}
fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}
/// Host reference, same RFC8439 block semantics; no key derivation/authentication.
pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let k = le_words::<8>(key);
    let n = le_words::<3>(nonce);
    let initial: [u32; 16] = core::array::from_fn(|i| match i {
        0..=3 => SIGMA[i],
        4..=11 => k[i - 4],
        12 => counter,
        _ => n[i - 13],
    });
    let mut s = initial;
    for _ in 0..10 {
        for indices in ROUNDS {
            host_quarter(&mut s, indices);
        }
    }
    let output: [[u8; 4]; 16] =
        core::array::from_fn(|i| s[i].wrapping_add(initial[i]).to_le_bytes());
    core::array::from_fn(|i| output[i / 4][i % 4])
}
/// Host stream reference; bounds match the recovery circuit exactly.
pub fn chacha20_xor_reference(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    check_length(counter, bytes.len())?;
    let mut result = Vec::with_capacity(bytes.len());
    for (i, chunk) in bytes.chunks(64).enumerate() {
        let stream = chacha20_block(key, nonce, counter + i as u32);
        result.extend(chunk.iter().zip(stream).map(|(a, b)| *a ^ b));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_htlc::circuit::{equal, input, HtlcAdapter, Scope};
    fn graph_case(key: [u8; 32], nonce: [u8; 12], message: &[u8], expected: &[u8]) {
        let scope = Scope::start();
        let k = core::array::from_fn(|_| input());
        let n = core::array::from_fn(|_| input());
        let m: Vec<_> = message.iter().map(|_| input()).collect();
        let output = chacha20_xor(k, n, 1, &m).unwrap();
        assert_eq!(output.len(), expected.len());
        for (wire, value) in output.iter().zip(expected) {
            equal(*wire, Word::from_u64(*value as u64));
        }
        let adapter = HtlcAdapter::from_graph(scope.finish());
        let mut inputs: Vec<_> = le_words::<8>(&key)
            .into_iter()
            .chain(le_words::<3>(&nonce))
            .map(u64::from)
            .collect();
        inputs.extend(message.iter().map(|v| *v as u64));
        let witness = adapter.evaluate(&inputs).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let actual: Vec<_> = output
            .iter()
            .map(|w| match w {
                Word::Constant(v) => *v as u8,
                Word::Wire(i) => witness[*i] as u8,
            })
            .collect();
        assert_eq!(actual, expected);
        eprintln!(
            "ChaCha bytes={} geometry={:?}",
            message.len(),
            adapter.geometry()
        );
        if !message.is_empty() {
            inputs[11] ^= 1;
            assert!(adapter
                .verify_packed_witness(&adapter.evaluate(&inputs).unwrap())
                .is_err());
            inputs[11] = 256;
            assert!(adapter
                .verify_packed_witness(&adapter.evaluate(&inputs).unwrap())
                .is_err());
        }
        inputs[0] = 1u64 << 32;
        assert!(adapter
            .verify_packed_witness(&adapter.evaluate(&inputs).unwrap())
            .is_err());
    }
    #[test]
    fn cached_values_match_constrained_bits_at_carries_and_rotations() {
        let scope = Scope::start();
        let a = U32::checked(input());
        let b = U32::checked(input());
        let sum = a.add(b);
        let rotated = sum.xor_rol(a, 7);
        equal(sum.value, pack(&sum.bits));
        equal(rotated.value, pack(&rotated.bits));
        let adapter = HtlcAdapter::from_graph(scope.finish());
        for (x, y) in [
            (0u32, 0u32),
            (u32::MAX, 1),
            (u32::MAX, u32::MAX),
            (0x80000000, 0x80000000),
            (0x12345678, 0x9abcdef0),
        ] {
            let witness = adapter.evaluate(&[x as u64, y as u64]).unwrap();
            adapter.verify_packed_witness(&witness).unwrap();
            let read = |word: Word| match word {
                Word::Constant(v) => v,
                Word::Wire(i) => witness[i],
            };
            assert_eq!(read(sum.value), x.wrapping_add(y) as u64);
            assert_eq!(
                read(rotated.value),
                (x.wrapping_add(y) ^ x).rotate_left(7) as u64
            );
        }
    }
    #[test]
    fn rfc8439_section_2_3_2_host_and_actual_graph() {
        // https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2
        let key = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let expected = hex::decode(concat!(
            "10f1e7e4d13b5915500fdd1fa32071c4",
            "c7d1f4c733c068030422aa9ac3d46c4e",
            "d2826446079faa0914c2d705d98b02a2",
            "b5129cd1de164eb9cbd083e8a2503c4e"
        ))
        .unwrap();
        assert_eq!(chacha20_block(&key, &nonce, 1).as_slice(), expected);
        graph_case(key, nonce, &[0; 64], &expected);
    }
    #[test]
    fn four_block_240_byte_graph_matches_host_and_rejects_mutations() {
        let key = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let nonce = [0x91; 12];
        let message: Vec<_> = (0..240).map(|i| (i * 19) as u8).collect();
        let expected = chacha20_xor_reference(&key, &nonce, 1, &message).unwrap();
        assert_eq!(
            chacha20_xor_reference(&key, &nonce, 1, &expected).unwrap(),
            message
        );
        graph_case(key, nonce, &message, &expected);
    }
    #[test]
    fn lengths_and_counter_are_fail_closed() {
        assert!(check_length(u32::MAX, 64).is_ok());
        assert!(check_length(u32::MAX, 65).is_err());
        assert!(check_length(u32::MAX - 3, 240).is_ok());
        assert!(check_length(u32::MAX - 2, 240).is_err());
        assert!(check_length(0, 241).is_err());
        assert!(check_length(u32::MAX, 0).is_ok());
    }
}
