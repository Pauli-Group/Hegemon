//! Minimal RPO-256 hash + random coin implementation for no_std verification.

use alloc::vec;
use alloc::vec::Vec;
use core::{convert::TryInto, ops::Range, slice};

use winter_crypto::{Digest as WinterDigest, ElementHasher, Hasher, RandomCoin, RandomCoinError};
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
use winterfell::math::{fields::f64::BaseElement, FieldElement, StarkField};

type Felt = BaseElement;

const STATE_WIDTH: usize = 12;
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;
const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;
const CAPACITY_RANGE: Range<usize> = 0..4;
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;
const NUM_ROUNDS: usize = 7;
const BINARY_CHUNK_SIZE: usize = 7;

// DIGEST
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RpoDigest([Felt; DIGEST_SIZE]);

impl RpoDigest {
    pub fn new(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    pub fn as_elements(&self) -> &[Felt] {
        &self.0
    }

    pub fn digests_as_elements(digests: &[Self]) -> &[Felt] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_SIZE;
        unsafe { slice::from_raw_parts(p as *const Felt, len) }
    }

    fn as_bytes_le(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());
        result
    }
}

impl WinterDigest for RpoDigest {
    fn as_bytes(&self) -> [u8; 32] {
        self.as_bytes_le()
    }
}

impl Default for RpoDigest {
    fn default() -> Self {
        Self([Felt::ZERO; DIGEST_SIZE])
    }
}

impl Serializable for RpoDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes_le());
    }
}

impl Deserializable for RpoDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let e1 = Felt::new(source.read_u64()?);
        let e2 = Felt::new(source.read_u64()?);
        let e3 = Felt::new(source.read_u64()?);
        let e4 = Felt::new(source.read_u64()?);
        Ok(Self([e1, e2, e3, e4]))
    }
}

impl From<[Felt; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl From<RpoDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: RpoDigest) -> Self {
        value.0
    }
}

// RPO HASH
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpo256();

impl Rpo256 {
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for round in 0..NUM_ROUNDS {
            Self::apply_round(state, round);
        }
    }

    #[inline(always)]
    fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        apply_mds(state);
        add_constants(state, &ARK1[round]);
        apply_sbox(state);

        apply_mds(state);
        add_constants(state, &ARK2[round]);
        apply_inv_sbox(state);
    }
}

impl Hasher for Rpo256 {
    type Digest = RpoDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        hash_bytes(bytes)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        merge(values)
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let elements = RpoDigest::digests_as_elements(values);
        hash_elements(elements)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        merge_with_int(seed, value)
    }
}

impl ElementHasher for Rpo256 {
    type BaseField = Felt;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        hash_elements(elements)
    }
}

// RANDOM COIN
// ================================================================================================

const RATE_START: usize = RATE_RANGE.start;
const RATE_END: usize = RATE_RANGE.end;
const HALF_RATE_WIDTH: usize = (RATE_RANGE.end - RATE_RANGE.start) / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpoRandomCoin {
    state: [Felt; STATE_WIDTH],
    current: usize,
}

impl RpoRandomCoin {
    pub fn from_digest(seed: RpoDigest) -> Self {
        let mut state = [Felt::ZERO; STATE_WIDTH];
        for i in 0..HALF_RATE_WIDTH {
            state[RATE_START + i] += seed.as_elements()[i];
        }
        Rpo256::apply_permutation(&mut state);
        Self {
            state,
            current: RATE_START,
        }
    }

    fn draw_basefield(&mut self) -> Felt {
        if self.current == RATE_END {
            Rpo256::apply_permutation(&mut self.state);
            self.current = RATE_START;
        }

        self.current += 1;
        self.state[self.current - 1]
    }
}

impl RandomCoin for RpoRandomCoin {
    type BaseField = Felt;
    type Hasher = Rpo256;

    fn new(seed: &[Self::BaseField]) -> Self {
        let digest = hash_elements(seed);
        Self::from_digest(digest)
    }

    fn reseed(&mut self, data: RpoDigest) {
        self.current = RATE_START;
        self.state[RATE_START] += data.as_elements()[0];
        self.state[RATE_START + 1] += data.as_elements()[1];
        self.state[RATE_START + 2] += data.as_elements()[2];
        self.state[RATE_START + 3] += data.as_elements()[3];
        Rpo256::apply_permutation(&mut self.state);
    }

    fn check_leading_zeros(&self, value: u64) -> u32 {
        let value = Felt::new(value);
        let mut state_tmp = self.state;
        state_tmp[RATE_START] += value;
        Rpo256::apply_permutation(&mut state_tmp);
        state_tmp[RATE_START].as_int().trailing_zeros()
    }

    fn draw<E: FieldElement<BaseField = Felt>>(&mut self) -> Result<E, RandomCoinError> {
        let ext_degree = E::EXTENSION_DEGREE;
        let mut result = vec![Felt::ZERO; ext_degree];
        for r in result.iter_mut().take(ext_degree) {
            *r = self.draw_basefield();
        }
        let result = E::slice_from_base_elements(&result);
        Ok(result[0])
    }

    fn draw_integers(
        &mut self,
        num_values: usize,
        domain_size: usize,
        nonce: u64,
    ) -> Result<Vec<usize>, RandomCoinError> {
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            num_values < domain_size,
            "number of values must be smaller than domain size"
        );

        let nonce = Felt::new(nonce);
        self.state[RATE_START] += nonce;
        Rpo256::apply_permutation(&mut self.state);

        self.current = RATE_START + 1;

        let v_mask = (domain_size - 1) as u64;

        let mut values = Vec::new();
        for _ in 0..1000 {
            let value = self.draw_basefield().as_int();
            let value = (value & v_mask) as usize;
            values.push(value);
            if values.len() == num_values {
                break;
            }
        }

        if values.len() < num_values {
            return Err(RandomCoinError::FailedToDrawIntegers(
                num_values,
                values.len(),
                1000,
            ));
        }

        Ok(values)
    }
}

// HASH HELPERS
// ================================================================================================

fn hash_elements<E: FieldElement<BaseField = Felt>>(elements: &[E]) -> RpoDigest {
    let elements = E::slice_as_base_elements(elements);

    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE.start] = Felt::new((elements.len() % RATE_WIDTH) as u64);

    let mut i = 0;
    for &element in elements.iter() {
        state[RATE_RANGE.start + i] = element;
        i += 1;
        if i.is_multiple_of(RATE_WIDTH) {
            Rpo256::apply_permutation(&mut state);
            i = 0;
        }
    }

    if i > 0 {
        while i != RATE_WIDTH {
            state[RATE_RANGE.start + i] = Felt::ZERO;
            i += 1;
        }
        Rpo256::apply_permutation(&mut state);
    }

    RpoDigest::new(state[DIGEST_RANGE].try_into().expect("digest length"))
}

fn hash_bytes(bytes: &[u8]) -> RpoDigest {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    let num_field_elem = if bytes.is_empty() {
        0
    } else {
        (bytes.len() + BINARY_CHUNK_SIZE - 1) / BINARY_CHUNK_SIZE
    };

    state[CAPACITY_RANGE.start] = Felt::new((RATE_WIDTH + (num_field_elem % RATE_WIDTH)) as u64);

    let mut buf = [0u8; 8];
    let mut current_chunk_idx = 0usize;
    let last_chunk_idx = if num_field_elem == 0 {
        current_chunk_idx
    } else {
        num_field_elem - 1
    };

    let rate_pos = bytes
        .chunks(BINARY_CHUNK_SIZE)
        .fold(0usize, |rate_pos, chunk| {
            if current_chunk_idx != last_chunk_idx {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }
            current_chunk_idx += 1;

            state[RATE_RANGE.start + rate_pos] = Felt::new(u64::from_le_bytes(buf));

            if rate_pos == RATE_WIDTH - 1 {
                Rpo256::apply_permutation(&mut state);
                0
            } else {
                rate_pos + 1
            }
        });

    if rate_pos != 0 {
        state[RATE_RANGE.start + rate_pos..RATE_RANGE.end].fill(Felt::ZERO);
        Rpo256::apply_permutation(&mut state);
    }

    RpoDigest::new(state[DIGEST_RANGE].try_into().expect("digest length"))
}

fn merge(values: &[RpoDigest; 2]) -> RpoDigest {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    for (i, v) in values
        .iter()
        .flat_map(|d| d.as_elements().iter())
        .enumerate()
    {
        state[RATE_RANGE.start + i] = *v;
    }

    Rpo256::apply_permutation(&mut state);
    RpoDigest::new(state[DIGEST_RANGE].try_into().expect("digest length"))
}

fn merge_with_int(seed: RpoDigest, value: u64) -> RpoDigest {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
    state[INPUT2_RANGE.start] = Felt::new(value);
    if value < Felt::MODULUS {
        state[CAPACITY_RANGE.start] = Felt::new(5);
    } else {
        state[INPUT2_RANGE.start + 1] = Felt::new(value / Felt::MODULUS);
        state[CAPACITY_RANGE.start] = Felt::new(6);
    }

    Rpo256::apply_permutation(&mut state);
    RpoDigest::new(state[DIGEST_RANGE].try_into().expect("digest length"))
}

// RESCUE PERMUTATION
// ================================================================================================

#[inline(always)]
fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
    state.iter_mut().for_each(|value| *value = value.exp7());
}

#[inline(always)]
fn apply_inv_sbox(state: &mut [Felt; STATE_WIDTH]) {
    let mut t1 = *state;
    t1.iter_mut().for_each(|t| *t = t.square());

    let mut t2 = t1;
    t2.iter_mut().for_each(|t| *t = t.square());

    let t3 = exp_acc::<Felt, STATE_WIDTH, 3>(t2, t2);
    let t4 = exp_acc::<Felt, STATE_WIDTH, 6>(t3, t3);
    let t5 = exp_acc::<Felt, STATE_WIDTH, 12>(t4, t4);
    let t6 = exp_acc::<Felt, STATE_WIDTH, 6>(t5, t3);
    let t7 = exp_acc::<Felt, STATE_WIDTH, 31>(t6, t6);

    for (i, s) in state.iter_mut().enumerate() {
        let a = (t7[i].square() * t6[i]).square().square();
        let b = t1[i] * t2[i] * *s;
        *s = a * b;
    }

    #[inline(always)]
    fn exp_acc<B: StarkField, const N: usize, const M: usize>(
        base: [B; N],
        tail: [B; N],
    ) -> [B; N] {
        let mut result = base;
        for _ in 0..M {
            result.iter_mut().for_each(|r| *r = r.square());
        }
        result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
        result
    }
}

#[inline(always)]
fn add_constants(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; STATE_WIDTH]) {
    state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
}

#[inline(always)]
fn apply_mds(state: &mut [Felt; STATE_WIDTH]) {
    let mut result = [Felt::ZERO; STATE_WIDTH];

    let mut state_l = [0u64; STATE_WIDTH];
    let mut state_h = [0u64; STATE_WIDTH];

    for r in 0..STATE_WIDTH {
        let s = state[r].inner();
        state_h[r] = s >> 32;
        state_l[r] = (s as u32) as u64;
    }

    let state_h = mds_multiply_freq(state_h);
    let state_l = mds_multiply_freq(state_l);

    for r in 0..STATE_WIDTH {
        let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
        let s_hi = (s >> 64) as u64;
        let s_lo = s as u64;
        let z = (s_hi << 32) - s_hi;
        let (res, over) = s_lo.overflowing_add(z);

        result[r] = Felt::from_mont(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64));
    }

    *state = result;
}

// MDS MULTIPLICATION (FREQUENCY DOMAIN)
// ================================================================================================

const MDS_FREQ_BLOCK_ONE: [i64; 3] = [16, 8, 16];
const MDS_FREQ_BLOCK_TWO: [(i64, i64); 3] = [(-1, 2), (-1, 1), (4, 8)];
const MDS_FREQ_BLOCK_THREE: [i64; 3] = [-8, 1, 1];

#[inline(always)]
const fn mds_multiply_freq(state: [u64; 12]) -> [u64; 12] {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11] = state;

    let (u0, u1, u2) = fft4_real([s0, s3, s6, s9]);
    let (u4, u5, u6) = fft4_real([s1, s4, s7, s10]);
    let (u8, u9, u10) = fft4_real([s2, s5, s8, s11]);

    let [v0, v4, v8] = block1([u0, u4, u8], MDS_FREQ_BLOCK_ONE);
    let [v1, v5, v9] = block2([u1, u5, u9], MDS_FREQ_BLOCK_TWO);
    let [v2, v6, v10] = block3([u2, u6, u10], MDS_FREQ_BLOCK_THREE);

    let [s0, s3, s6, s9] = ifft4_real((v0, v1, v2));
    let [s1, s4, s7, s10] = ifft4_real((v4, v5, v6));
    let [s2, s5, s8, s11] = ifft4_real((v8, v9, v10));

    [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11]
}

#[inline(always)]
const fn fft2_real(x: [u64; 2]) -> [i64; 2] {
    [(x[0] as i64 + x[1] as i64), (x[0] as i64 - x[1] as i64)]
}

#[inline(always)]
const fn ifft2_real(y: [i64; 2]) -> [u64; 2] {
    [(y[0] + y[1]) as u64, (y[0] - y[1]) as u64]
}

#[inline(always)]
const fn fft4_real(x: [u64; 4]) -> (i64, (i64, i64), i64) {
    let [z0, z2] = fft2_real([x[0], x[2]]);
    let [z1, z3] = fft2_real([x[1], x[3]]);
    let y0 = z0 + z1;
    let y1 = (z2, -z3);
    let y2 = z0 - z1;
    (y0, y1, y2)
}

#[inline(always)]
const fn ifft4_real(y: (i64, (i64, i64), i64)) -> [u64; 4] {
    let z0 = y.0 + y.2;
    let z1 = y.0 - y.2;
    let z2 = y.1 .0;
    let z3 = -y.1 .1;

    let [x0, x2] = ifft2_real([z0, z2]);
    let [x1, x3] = ifft2_real([z1, z3]);

    [x0, x1, x2, x3]
}

#[inline(always)]
const fn block1(x: [i64; 3], y: [i64; 3]) -> [i64; 3] {
    let [x0, x1, x2] = x;
    let [y0, y1, y2] = y;
    let z0 = x0 * y0 + x1 * y2 + x2 * y1;
    let z1 = x0 * y1 + x1 * y0 + x2 * y2;
    let z2 = x0 * y2 + x1 * y1 + x2 * y0;

    [z0, z1, z2]
}

#[inline(always)]
const fn block2(x: [(i64, i64); 3], y: [(i64, i64); 3]) -> [(i64, i64); 3] {
    let [(x0r, x0i), (x1r, x1i), (x2r, x2i)] = x;
    let [(y0r, y0i), (y1r, y1i), (y2r, y2i)] = y;
    let x0s = x0r + x0i;
    let x1s = x1r + x1i;
    let x2s = x2r + x2i;
    let y0s = y0r + y0i;
    let y1s = y1r + y1i;
    let y2s = y2r + y2i;

    let m0 = (x0r * y0r, x0i * y0i);
    let m1 = (x1r * y2r, x1i * y2i);
    let m2 = (x2r * y1r, x2i * y1i);
    let z0r = (m0.0 - m0.1) + (x1s * y2s - m1.0 - m1.1) + (x2s * y1s - m2.0 - m2.1);
    let z0i = (x0s * y0s - m0.0 - m0.1) + (-m1.0 + m1.1) + (-m2.0 + m2.1);
    let z0 = (z0r, z0i);

    let m0 = (x0r * y1r, x0i * y1i);
    let m1 = (x1r * y0r, x1i * y0i);
    let m2 = (x2r * y2r, x2i * y2i);
    let z1r = (m0.0 - m0.1) + (m1.0 - m1.1) + (x2s * y2s - m2.0 - m2.1);
    let z1i = (x0s * y1s - m0.0 - m0.1) + (x1s * y0s - m1.0 - m1.1) + (-m2.0 + m2.1);
    let z1 = (z1r, z1i);

    let m0 = (x0r * y2r, x0i * y2i);
    let m1 = (x1r * y1r, x1i * y1i);
    let m2 = (x2r * y0r, x2i * y0i);
    let z2r = (m0.0 - m0.1) + (m1.0 - m1.1) + (m2.0 - m2.1);
    let z2i = (x0s * y2s - m0.0 - m0.1) + (x1s * y1s - m1.0 - m1.1) + (x2s * y0s - m2.0 - m2.1);
    let z2 = (z2r, z2i);

    [z0, z1, z2]
}

#[inline(always)]
const fn block3(x: [i64; 3], y: [i64; 3]) -> [i64; 3] {
    let [x0, x1, x2] = x;
    let [y0, y1, y2] = y;
    let z0 = x0 * y0 - x1 * y2 - x2 * y1;
    let z1 = x0 * y1 + x1 * y0 - x2 * y2;
    let z2 = x0 * y2 + x1 * y1 + x2 * y0;

    [z0, z1, z2]
}

// ROUND CONSTANTS
// ================================================================================================

const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new(5789762306288267392),
        Felt::new(6522564764413701783),
        Felt::new(17809893479458208203),
        Felt::new(107145243989736508),
        Felt::new(6388978042437517382),
        Felt::new(15844067734406016715),
        Felt::new(9975000513555218239),
        Felt::new(3344984123768313364),
        Felt::new(9959189626657347191),
        Felt::new(12960773468763563665),
        Felt::new(9602914297752488475),
        Felt::new(16657542370200465908),
    ],
    [
        Felt::new(12987190162843096997),
        Felt::new(653957632802705281),
        Felt::new(4441654670647621225),
        Felt::new(4038207883745915761),
        Felt::new(5613464648874830118),
        Felt::new(13222989726778338773),
        Felt::new(3037761201230264149),
        Felt::new(16683759727265180203),
        Felt::new(8337364536491240715),
        Felt::new(3227397518293416448),
        Felt::new(8110510111539674682),
        Felt::new(2872078294163232137),
    ],
    [
        Felt::new(18072785500942327487),
        Felt::new(6200974112677013481),
        Felt::new(17682092219085884187),
        Felt::new(10599526828986756440),
        Felt::new(975003873302957338),
        Felt::new(8264241093196931281),
        Felt::new(10065763900435475170),
        Felt::new(2181131744534710197),
        Felt::new(6317303992309418647),
        Felt::new(1401440938888741532),
        Felt::new(8884468225181997494),
        Felt::new(13066900325715521532),
    ],
    [
        Felt::new(5674685213610121970),
        Felt::new(5759084860419474071),
        Felt::new(13943282657648897737),
        Felt::new(1352748651966375394),
        Felt::new(17110913224029905221),
        Felt::new(1003883795902368422),
        Felt::new(4141870621881018291),
        Felt::new(8121410972417424656),
        Felt::new(14300518605864919529),
        Felt::new(13712227150607670181),
        Felt::new(17021852944633065291),
        Felt::new(6252096473787587650),
    ],
    [
        Felt::new(4887609836208846458),
        Felt::new(3027115137917284492),
        Felt::new(9595098600469470675),
        Felt::new(10528569829048484079),
        Felt::new(7864689113198939815),
        Felt::new(17533723827845969040),
        Felt::new(5781638039037710951),
        Felt::new(17024078752430719006),
        Felt::new(109659393484013511),
        Felt::new(7158933660534805869),
        Felt::new(2955076958026921730),
        Felt::new(7433723648458773977),
    ],
    [
        Felt::new(16308865189192447297),
        Felt::new(11977192855656444890),
        Felt::new(12532242556065780287),
        Felt::new(14594890931430968898),
        Felt::new(7291784239689209784),
        Felt::new(5514718540551361949),
        Felt::new(10025733853830934803),
        Felt::new(7293794580341021693),
        Felt::new(6728552937464861756),
        Felt::new(6332385040983343262),
        Felt::new(13277683694236792804),
        Felt::new(2600778905124452676),
    ],
    [
        Felt::new(7123075680859040534),
        Felt::new(1034205548717903090),
        Felt::new(7717824418247931797),
        Felt::new(3019070937878604058),
        Felt::new(11403792746066867460),
        Felt::new(10280580802233112374),
        Felt::new(337153209462421218),
        Felt::new(13333398568519923717),
        Felt::new(3596153696935337464),
        Felt::new(8104208463525993784),
        Felt::new(14345062289456085693),
        Felt::new(17036731477169661256),
    ],
];

const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new(6077062762357204287),
        Felt::new(15277620170502011191),
        Felt::new(5358738125714196705),
        Felt::new(14233283787297595718),
        Felt::new(13792579614346651365),
        Felt::new(11614812331536767105),
        Felt::new(14871063686742261166),
        Felt::new(10148237148793043499),
        Felt::new(4457428952329675767),
        Felt::new(15590786458219172475),
        Felt::new(10063319113072092615),
        Felt::new(14200078843431360086),
    ],
    [
        Felt::new(6202948458916099932),
        Felt::new(17690140365333231091),
        Felt::new(3595001575307484651),
        Felt::new(373995945117666487),
        Felt::new(1235734395091296013),
        Felt::new(14172757457833931602),
        Felt::new(707573103686350224),
        Felt::new(15453217512188187135),
        Felt::new(219777875004506018),
        Felt::new(17876696346199469008),
        Felt::new(17731621626449383378),
        Felt::new(2897136237748376248),
    ],
    [
        Felt::new(8023374565629191455),
        Felt::new(15013690343205953430),
        Felt::new(4485500052507912973),
        Felt::new(12489737547229155153),
        Felt::new(9500452585969030576),
        Felt::new(2054001340201038870),
        Felt::new(12420704059284934186),
        Felt::new(355990932618543755),
        Felt::new(9071225051243523860),
        Felt::new(12766199826003448536),
        Felt::new(9045979173463556963),
        Felt::new(12934431667190679898),
    ],
    [
        Felt::new(18389244934624494276),
        Felt::new(16731736864863925227),
        Felt::new(4440209734760478192),
        Felt::new(17208448209698888938),
        Felt::new(8739495587021565984),
        Felt::new(17000774922218161967),
        Felt::new(13533282547195532087),
        Felt::new(525402848358706231),
        Felt::new(16987541523062161972),
        Felt::new(5466806524462797102),
        Felt::new(14512769585918244983),
        Felt::new(10973956031244051118),
    ],
    [
        Felt::new(6982293561042362913),
        Felt::new(14065426295947720331),
        Felt::new(16451845770444974180),
        Felt::new(7139138592091306727),
        Felt::new(9012006439959783127),
        Felt::new(14619614108529063361),
        Felt::new(1394813199588124371),
        Felt::new(4635111139507788575),
        Felt::new(16217473952264203365),
        Felt::new(10782018226466330683),
        Felt::new(6844229992533662050),
        Felt::new(7446486531695178711),
    ],
    [
        Felt::new(3736792340494631448),
        Felt::new(577852220195055341),
        Felt::new(6689998335515779805),
        Felt::new(13886063479078013492),
        Felt::new(14358505101923202168),
        Felt::new(7744142531772274164),
        Felt::new(16135070735728404443),
        Felt::new(12290902521256031137),
        Felt::new(12059913662657709804),
        Felt::new(16456018495793751911),
        Felt::new(4571485474751953524),
        Felt::new(17200392109565783176),
    ],
    [
        Felt::new(17130398059294018733),
        Felt::new(519782857322261988),
        Felt::new(9625384390925085478),
        Felt::new(1664893052631119222),
        Felt::new(7629576092524553570),
        Felt::new(3485239601103661425),
        Felt::new(9755891797164033838),
        Felt::new(15218148195153269027),
        Felt::new(16460604813734957368),
        Felt::new(9643968136937729763),
        Felt::new(3611348709641382851),
        Felt::new(18256379591337759196),
    ],
];

// MDS MATRIX
// ================================================================================================

#[allow(dead_code)]
const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = [
    [
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
    ],
    [
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
    ],
    [
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
    ],
    [
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
    ],
    [
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
    ],
    [
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
    ],
    [
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
    ],
    [
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
    ],
    [
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
    ],
    [
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
    ],
];

#[cfg(test)]
mod tests {
    use super::{Felt, Rpo256, RpoRandomCoin};
    use miden_crypto::hash::rpo::Rpo256 as MidenRpo256;
    use miden_crypto::rand::RpoRandomCoin as MidenRandomCoin;
    use winter_crypto::{Digest as WinterDigest, ElementHasher, Hasher, RandomCoin};
    use winterfell::math::StarkField;

    fn felts(values: &[u64]) -> Vec<Felt> {
        values.iter().copied().map(Felt::new).collect()
    }

    #[test]
    fn rpo_hash_elements_parity() {
        let elements = felts(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let ours = Rpo256::hash_elements(&elements);
        let theirs = MidenRpo256::hash_elements(&elements);
        assert_eq!(ours.as_bytes(), theirs.as_bytes());
    }

    #[test]
    fn rpo_hash_bytes_parity() {
        let bytes: Vec<u8> = (0u8..=63).collect();
        let ours = Rpo256::hash(&bytes);
        let theirs = MidenRpo256::hash(&bytes);
        assert_eq!(ours.as_bytes(), theirs.as_bytes());
    }

    #[test]
    fn rpo_merge_parity() {
        let left = felts(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let right = felts(&[9, 10, 11, 12, 13, 14, 15, 16]);

        let ours_left = Rpo256::hash_elements(&left);
        let ours_right = Rpo256::hash_elements(&right);
        let theirs_left = MidenRpo256::hash_elements(&left);
        let theirs_right = MidenRpo256::hash_elements(&right);

        let ours = Rpo256::merge(&[ours_left, ours_right]);
        let theirs = MidenRpo256::merge(&[theirs_left, theirs_right]);
        assert_eq!(ours.as_bytes(), theirs.as_bytes());
    }

    #[test]
    fn rpo_merge_with_int_parity() {
        let seed_elements = felts(&[42, 43, 44, 45]);
        let seed_ours = Rpo256::hash_elements(&seed_elements);
        let seed_theirs = MidenRpo256::hash_elements(&seed_elements);

        let small = 17u64;
        let large = Felt::MODULUS + 17;

        let ours_small = Rpo256::merge_with_int(seed_ours, small);
        let theirs_small = MidenRpo256::merge_with_int(seed_theirs, small);
        assert_eq!(ours_small.as_bytes(), theirs_small.as_bytes());

        let ours_large = Rpo256::merge_with_int(seed_ours, large);
        let theirs_large = MidenRpo256::merge_with_int(seed_theirs, large);
        assert_eq!(ours_large.as_bytes(), theirs_large.as_bytes());
    }

    #[test]
    fn rpo_random_coin_parity() {
        let seed = felts(&[3, 1, 4, 1]);
        let mut ours = <RpoRandomCoin as RandomCoin>::new(&seed);
        let mut theirs = <MidenRandomCoin as RandomCoin>::new(&seed);

        for _ in 0..16 {
            let ours_draw: Felt = ours.draw().expect("draw ours");
            let theirs_draw: Felt = theirs.draw().expect("draw theirs");
            assert_eq!(ours_draw, theirs_draw);
        }

        let ours_vals = ours.draw_integers(8, 32, 7).expect("draw integers ours");
        let theirs_vals = theirs
            .draw_integers(8, 32, 7)
            .expect("draw integers theirs");
        assert_eq!(ours_vals, theirs_vals);
    }
}
