//! Authenticated B128-coefficient-lane folding under genuine E384 challenges.
//!
//! This module is an executable commitment/opening kernel for the proposed
//! mixed-field backend.  It is deliberately narrower than a production PCS:
//! every binary fold layer is committed with a SHA-512 Merkle tree, Fiat--
//! Shamir challenges are genuine [`E384`] values, and sampled pair openings
//! authenticate all three [`B128`] coefficient lanes for every grouped oracle.
//! It does not implement a low-degree code, a hiding compiler, complete zero
//! knowledge, a QROM reduction, or production consensus admission.

use crate::{B128, E384};

/// Canonical proof magic and schema version.
pub const AUTHENTICATED_BASEFOLD_MAGIC: [u8; 8] = *b"HGE3BF01";
/// Current canonical wire version.
pub const AUTHENTICATED_BASEFOLD_VERSION: u16 = 1;
/// SHA-512 digest width.
pub const SHA512_BYTES: usize = 64;
/// Three coefficient lanes are always serialized low-to-high.
pub const COEFFICIENT_LANE_COUNT: u8 = 3;
/// Exact fixed header size.
pub const AUTHENTICATED_BASEFOLD_HEADER_BYTES: usize = 152;
/// Defensive source-prototype cap on the number of grouped oracles.
pub const MAX_GROUP_COUNT: usize = 64;
/// Defensive source-prototype cap on `log2` of the initial layer.
pub const MAX_LOG_VALUES: usize = 20;
/// Defensive source-prototype cap on repeated sampled queries.
pub const MAX_QUERY_COUNT: usize = 512;

const HASH_SUITE_ID_SHA512: u16 = 1;
const ZERO_FLAGS: u16 = 0;
const ZERO_RESERVED: [u8; 4] = [0; 4];

const PROFILE_DESCRIPTOR: &[u8] =
    b"hegemon.strict-mixed-field.authenticated-b128-lane-basefold.sha512.e384.v1\0";
const CONTEXT_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.authenticated-basefold.context.sha512.v1\0";
const LEAF_DOMAIN: &[u8] = b"hegemon.strict-mixed-field.authenticated-basefold.leaf.sha512.v1\0";
const NODE_DOMAIN: &[u8] = b"hegemon.strict-mixed-field.authenticated-basefold.node.sha512.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.authenticated-basefold.transcript.sha512.v1\0";
const CHALLENGE_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.authenticated-basefold.challenge.e384.sha512.v1\0";
const QUERY_DOMAIN: &[u8] = b"hegemon.strict-mixed-field.authenticated-basefold.query.sha512.v1\0";

/// Fail-closed parser, commitment, and fold errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedBasefoldError {
    /// At least one grouped oracle is required.
    EmptyGroups,
    /// The group cap prevents attacker-controlled allocations.
    TooManyGroups { actual: usize, maximum: usize },
    /// All grouped oracles must have the same non-empty power-of-two length.
    GroupLengthMismatch,
    /// The initial table length is outside the bounded canonical geometry.
    InvalidTableLength,
    /// The query count is nonzero and bounded by the declared cap.
    InvalidQueryCount { actual: usize, maximum: usize },
    /// A count or byte-length calculation overflowed.
    LengthOverflow,
    /// The proof ended before its canonical geometry was consumed.
    ProofTruncated,
    /// Exact decoding rejects any suffix.
    ProofTrailingBytes { remaining: usize },
    /// The wire does not carry the unique magic.
    InvalidMagic,
    /// Only version one is accepted.
    UnsupportedVersion { actual: u16 },
    /// Flags are reserved and must be zero.
    NonzeroFlags { actual: u16 },
    /// The field representation must be exactly three B128 lanes.
    InvalidLaneCount { actual: u8 },
    /// The commitment and transcript hash suite is fixed to full SHA-512.
    InvalidHashSuite { actual: u16 },
    /// Reserved header bytes must stay zero.
    NonzeroReserved,
    /// The hard-coded profile fingerprint differs.
    ProfileMismatch,
    /// The caller's public statement/domain context differs.
    ContextMismatch,
    /// A carried terminal value does not authenticate to the last root.
    TerminalAuthentication,
    /// One grouped pair/path does not authenticate to its declared layer root.
    OpeningAuthentication { query: usize, round: usize },
    /// An authenticated next-layer value is not the E384 affine fold of the
    /// authenticated child pair.
    FoldMismatch {
        query: usize,
        round: usize,
        group: usize,
    },
    /// Prover/verifier transcript scheduling diverged.
    TranscriptSchedule,
}

/// One SHA-512 digest used by commitments and the transcript.
pub type Sha512Digest = [u8; SHA512_BYTES];

/// Exact serializer-derived byte accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatedBasefoldSizeReport {
    /// Header bytes written by the canonical serializer.
    pub fixed_bytes: usize,
    /// Number of 16-byte B128 coefficient symbols written.
    pub b128_symbols: usize,
    /// Number of 64-byte layer roots written.
    pub merkle_roots: usize,
    /// Number of 64-byte authentication nodes written.
    pub merkle_auth_nodes: usize,
    /// Initial `log2` table size.
    pub log_values: usize,
    /// Number of grouped oracles authenticated by each leaf.
    pub group_count: usize,
    /// Number of transcript-derived query repetitions.
    pub query_count: usize,
}

impl AuthenticatedBasefoldSizeReport {
    /// Exact byte count for the fields emitted by the same writer.
    pub const fn serialized_bytes(self) -> usize {
        self.fixed_bytes
            + self.b128_symbols * B128::BYTE_SIZE
            + (self.merkle_roots + self.merkle_auth_nodes) * SHA512_BYTES
    }

    /// Closed form for the canonical grammar.
    ///
    /// For `n=log_values`, `g=group_count`, and `q=query_count`:
    ///
    /// `152 + 64(n+1) + 48g + q(96gn + 32n(n-1))`.
    pub fn formula_bytes(
        log_values: usize,
        group_count: usize,
        query_count: usize,
    ) -> Result<usize, AuthenticatedBasefoldError> {
        let root_bytes = (log_values + 1)
            .checked_mul(SHA512_BYTES)
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        let terminal_bytes = group_count
            .checked_mul(E384::BYTE_SIZE)
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        let opened_value_bytes = query_count
            .checked_mul(log_values)
            .and_then(|count| count.checked_mul(group_count))
            .and_then(|count| count.checked_mul(2 * E384::BYTE_SIZE))
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        let path_nodes_per_query = log_values
            .checked_mul(log_values.saturating_sub(1))
            .and_then(|count| count.checked_div(2))
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        let path_bytes = query_count
            .checked_mul(path_nodes_per_query)
            .and_then(|count| count.checked_mul(SHA512_BYTES))
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        AUTHENTICATED_BASEFOLD_HEADER_BYTES
            .checked_add(root_bytes)
            .and_then(|total| total.checked_add(terminal_bytes))
            .and_then(|total| total.checked_add(opened_value_bytes))
            .and_then(|total| total.checked_add(path_bytes))
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)
    }
}

/// One pair opening at one binary fold layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupedPairOpening {
    /// Left child values, one E384 value per grouped oracle, each serialized as
    /// three B128 coefficient lanes.
    pub left: Vec<E384>,
    /// Right child values in the same group order.
    pub right: Vec<E384>,
    /// Authentication siblings above the already-known left/right pair.  The
    /// pair's mutual sibling is reconstructed and is never serialized.
    pub authentication_tail: Vec<Sha512Digest>,
}

/// Canonical authenticated folding proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBasefoldProof {
    log_values: u8,
    group_count: u16,
    query_count: u16,
    profile_digest: Sha512Digest,
    context_digest: Sha512Digest,
    layer_roots: Vec<Sha512Digest>,
    terminal_values: Vec<E384>,
    query_openings: Vec<Vec<GroupedPairOpening>>,
}

impl AuthenticatedBasefoldProof {
    /// Initial table arity.
    pub const fn log_values(&self) -> usize {
        self.log_values as usize
    }

    /// Number of grouped B128 source oracles.
    pub const fn group_count(&self) -> usize {
        self.group_count as usize
    }

    /// Number of Fiat--Shamir query repetitions.
    pub const fn query_count(&self) -> usize {
        self.query_count as usize
    }

    /// Committed root for every fold layer, including the terminal singleton.
    pub fn layer_roots(&self) -> &[Sha512Digest] {
        &self.layer_roots
    }

    /// Terminal E384 values represented on wire as B128 coefficient lanes.
    pub fn terminal_values(&self) -> &[E384] {
        &self.terminal_values
    }

    /// Query-major, then round-major authenticated openings.
    pub fn query_openings(&self) -> &[Vec<GroupedPairOpening>] {
        &self.query_openings
    }

    fn validate_shape(&self) -> Result<(), AuthenticatedBasefoldError> {
        let log_values = self.log_values();
        let group_count = self.group_count();
        let query_count = self.query_count();
        validate_geometry(log_values, group_count, query_count)?;
        if self.profile_digest != profile_digest() {
            return Err(AuthenticatedBasefoldError::ProfileMismatch);
        }
        if self.layer_roots.len() != log_values + 1
            || self.terminal_values.len() != group_count
            || self.query_openings.len() != query_count
        {
            return Err(AuthenticatedBasefoldError::TranscriptSchedule);
        }
        for query in &self.query_openings {
            if query.len() != log_values {
                return Err(AuthenticatedBasefoldError::TranscriptSchedule);
            }
            for (round, opening) in query.iter().enumerate() {
                if opening.left.len() != group_count
                    || opening.right.len() != group_count
                    || opening.authentication_tail.len() != log_values - round - 1
                {
                    return Err(AuthenticatedBasefoldError::TranscriptSchedule);
                }
            }
        }
        Ok(())
    }

    /// Serialize exactly one canonical proof and return counters populated by
    /// the same write operations.
    pub fn encode_counted(
        &self,
    ) -> Result<(Vec<u8>, AuthenticatedBasefoldSizeReport), AuthenticatedBasefoldError> {
        self.validate_shape()?;
        let mut writer =
            ExactWriter::new(self.log_values(), self.group_count(), self.query_count());
        writer.write_fixed(&AUTHENTICATED_BASEFOLD_MAGIC);
        writer.write_fixed(&AUTHENTICATED_BASEFOLD_VERSION.to_le_bytes());
        writer.write_fixed(&ZERO_FLAGS.to_le_bytes());
        writer.write_fixed(&[self.log_values]);
        writer.write_fixed(&[COEFFICIENT_LANE_COUNT]);
        writer.write_fixed(&self.group_count.to_le_bytes());
        writer.write_fixed(&self.query_count.to_le_bytes());
        writer.write_fixed(&HASH_SUITE_ID_SHA512.to_le_bytes());
        writer.write_fixed(&self.profile_digest);
        writer.write_fixed(&self.context_digest);
        writer.write_fixed(&ZERO_RESERVED);
        debug_assert_eq!(
            writer.report.fixed_bytes,
            AUTHENTICATED_BASEFOLD_HEADER_BYTES
        );

        for root in &self.layer_roots {
            writer.write_root(root);
        }
        for &value in &self.terminal_values {
            writer.write_lane_value(value);
        }
        for query in &self.query_openings {
            for opening in query {
                for &value in &opening.left {
                    writer.write_lane_value(value);
                }
                for &value in &opening.right {
                    writer.write_lane_value(value);
                }
                for sibling in &opening.authentication_tail {
                    writer.write_auth_node(sibling);
                }
            }
        }
        writer.finish()
    }

    /// Exact canonical parser with bounded allocation and no ignored suffix.
    pub fn decode_exact(encoded: &[u8]) -> Result<Self, AuthenticatedBasefoldError> {
        let mut reader = ExactReader::new(encoded);
        if reader.read_array::<8>()? != AUTHENTICATED_BASEFOLD_MAGIC {
            return Err(AuthenticatedBasefoldError::InvalidMagic);
        }
        let version = u16::from_le_bytes(reader.read_array::<2>()?);
        if version != AUTHENTICATED_BASEFOLD_VERSION {
            return Err(AuthenticatedBasefoldError::UnsupportedVersion { actual: version });
        }
        let flags = u16::from_le_bytes(reader.read_array::<2>()?);
        if flags != ZERO_FLAGS {
            return Err(AuthenticatedBasefoldError::NonzeroFlags { actual: flags });
        }
        let log_values = reader.read_array::<1>()?[0] as usize;
        let lane_count = reader.read_array::<1>()?[0];
        if lane_count != COEFFICIENT_LANE_COUNT {
            return Err(AuthenticatedBasefoldError::InvalidLaneCount { actual: lane_count });
        }
        let group_count = u16::from_le_bytes(reader.read_array::<2>()?) as usize;
        let query_count = u16::from_le_bytes(reader.read_array::<2>()?) as usize;
        let hash_suite = u16::from_le_bytes(reader.read_array::<2>()?);
        if hash_suite != HASH_SUITE_ID_SHA512 {
            return Err(AuthenticatedBasefoldError::InvalidHashSuite { actual: hash_suite });
        }
        validate_geometry(log_values, group_count, query_count)?;

        let carried_profile = reader.read_array::<SHA512_BYTES>()?;
        if carried_profile != profile_digest() {
            return Err(AuthenticatedBasefoldError::ProfileMismatch);
        }
        let context_digest = reader.read_array::<SHA512_BYTES>()?;
        if reader.read_array::<4>()? != ZERO_RESERVED {
            return Err(AuthenticatedBasefoldError::NonzeroReserved);
        }

        let expected_len =
            AuthenticatedBasefoldSizeReport::formula_bytes(log_values, group_count, query_count)?;
        if encoded.len() < expected_len {
            return Err(AuthenticatedBasefoldError::ProofTruncated);
        }
        if encoded.len() > expected_len {
            return Err(AuthenticatedBasefoldError::ProofTrailingBytes {
                remaining: encoded.len() - expected_len,
            });
        }

        let mut layer_roots = Vec::with_capacity(log_values + 1);
        for _ in 0..=log_values {
            layer_roots.push(reader.read_array::<SHA512_BYTES>()?);
        }
        let mut terminal_values = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            terminal_values.push(reader.read_lane_value()?);
        }
        let mut query_openings = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            let mut rounds = Vec::with_capacity(log_values);
            for round in 0..log_values {
                let mut left = Vec::with_capacity(group_count);
                let mut right = Vec::with_capacity(group_count);
                for _ in 0..group_count {
                    left.push(reader.read_lane_value()?);
                }
                for _ in 0..group_count {
                    right.push(reader.read_lane_value()?);
                }
                let mut authentication_tail = Vec::with_capacity(log_values - round - 1);
                for _ in 0..(log_values - round - 1) {
                    authentication_tail.push(reader.read_array::<SHA512_BYTES>()?);
                }
                rounds.push(GroupedPairOpening {
                    left,
                    right,
                    authentication_tail,
                });
            }
            query_openings.push(rounds);
        }
        reader.finish()?;

        let proof = Self {
            log_values: log_values as u8,
            group_count: group_count as u16,
            query_count: query_count as u16,
            profile_digest: carried_profile,
            context_digest,
            layer_roots,
            terminal_values,
            query_openings,
        };
        proof.validate_shape()?;
        Ok(proof)
    }
}

/// Prover output retained for differential and transcript-order tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBasefoldProverOutput {
    /// Canonical proof object.
    pub proof: AuthenticatedBasefoldProof,
    /// One true E384 challenge per fold round.
    pub fold_challenges: Vec<E384>,
    /// Transcript-derived initial pair indexes, not serialized.
    pub query_indices: Vec<usize>,
    /// Full SHA-512 digest of the final transcript state.
    pub transcript_digest: Sha512Digest,
}

/// Successful verifier result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBasefoldVerification {
    /// Re-derived true E384 challenges.
    pub fold_challenges: Vec<E384>,
    /// Re-derived initial pair indexes.
    pub query_indices: Vec<usize>,
    /// Authenticated terminal E384 values, one per group.
    pub terminal_values: Vec<E384>,
    /// Full SHA-512 digest of the final transcript state.
    pub transcript_digest: Sha512Digest,
}

fn validate_geometry(
    log_values: usize,
    group_count: usize,
    query_count: usize,
) -> Result<(), AuthenticatedBasefoldError> {
    if log_values == 0 || log_values > MAX_LOG_VALUES {
        return Err(AuthenticatedBasefoldError::InvalidTableLength);
    }
    if group_count == 0 {
        return Err(AuthenticatedBasefoldError::EmptyGroups);
    }
    if group_count > MAX_GROUP_COUNT {
        return Err(AuthenticatedBasefoldError::TooManyGroups {
            actual: group_count,
            maximum: MAX_GROUP_COUNT,
        });
    }
    if query_count == 0 || query_count > MAX_QUERY_COUNT {
        return Err(AuthenticatedBasefoldError::InvalidQueryCount {
            actual: query_count,
            maximum: MAX_QUERY_COUNT,
        });
    }
    Ok(())
}

/// Full dependency-free SHA-512.
///
/// This is the conventional FIPS 180-4 hash, not SHAKE and not a truncated
/// substitute.  The KATs include empty input and `abc`.
pub fn sha512(input: &[u8]) -> Sha512Digest {
    const INITIAL: [u64; 8] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
        0x6c44_198c_4a47_5817,
    ];

    fn compress(state: &mut [u64; 8], block: &[u8]) {
        debug_assert_eq!(block.len(), 128);
        let mut words = [0u64; 80];
        for (index, chunk) in block.chunks_exact(8).enumerate() {
            words[index] = u64::from_be_bytes(chunk.try_into().expect("eight-byte SHA-512 word"));
        }
        for index in 16..80 {
            let x = words[index - 15];
            let y = words[index - 2];
            let sigma0 = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
            let sigma1 = y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6);
            words[index] = words[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(sigma1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for index in 0..80 {
            let big1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let bit_len = (input.len() as u128).wrapping_mul(8);
    let padding_zeroes = (112usize.wrapping_sub((input.len() + 1) % 128)) % 128;
    let total_len = input
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(padding_zeroes))
        .and_then(|length| length.checked_add(16))
        .expect("an in-memory slice cannot overflow the SHA-512 padding length");
    let mut padded = Vec::with_capacity(total_len);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(input.len() + 1 + padding_zeroes, 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());
    debug_assert_eq!(padded.len() % 128, 0);

    let mut state = INITIAL;
    for block in padded.chunks_exact(128) {
        compress(&mut state, block);
    }
    let mut output = [0u8; SHA512_BYTES];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn append_frame(buffer: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    buffer.push(tag);
    buffer.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buffer.extend_from_slice(payload);
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Sha512Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    preimage.extend_from_slice(payload);
    sha512(&preimage)
}

/// Profile fingerprint embedded in every proof header.
pub fn profile_digest() -> Sha512Digest {
    domain_hash(PROFILE_DESCRIPTOR, PROFILE_DESCRIPTOR)
}

/// Public-context fingerprint embedded in the wire and checked by the
/// verifier.  The context should contain the statement, network, action,
/// version, and relation identities supplied by the caller.
pub fn context_digest(context: &[u8]) -> Sha512Digest {
    domain_hash(CONTEXT_DOMAIN, context)
}

#[derive(Clone, Debug)]
struct Sha512E384Transcript {
    state: Vec<u8>,
    challenge_count: u64,
    query_count: u64,
}

impl Sha512E384Transcript {
    fn new(
        context_digest: Sha512Digest,
        log_values: usize,
        group_count: usize,
        query_count: usize,
    ) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(TRANSCRIPT_DOMAIN);
        append_frame(&mut state, 1, &profile_digest());
        append_frame(&mut state, 2, &context_digest);
        let mut geometry = Vec::with_capacity(24);
        geometry.extend_from_slice(&(log_values as u64).to_le_bytes());
        geometry.extend_from_slice(&(group_count as u64).to_le_bytes());
        geometry.extend_from_slice(&(query_count as u64).to_le_bytes());
        append_frame(&mut state, 3, &geometry);
        Self {
            state,
            challenge_count: 0,
            query_count: 0,
        }
    }

    fn observe_root(&mut self, layer: usize, width: usize, root: &Sha512Digest) {
        let mut payload = Vec::with_capacity(16 + SHA512_BYTES);
        payload.extend_from_slice(&(layer as u64).to_le_bytes());
        payload.extend_from_slice(&(width as u64).to_le_bytes());
        payload.extend_from_slice(root);
        append_frame(&mut self.state, 4, &payload);
    }

    fn sample_e384(&mut self, round: usize) -> Result<E384, AuthenticatedBasefoldError> {
        if self.challenge_count != round as u64 {
            return Err(AuthenticatedBasefoldError::TranscriptSchedule);
        }
        let mut request = Vec::with_capacity(16);
        request.extend_from_slice(&self.challenge_count.to_le_bytes());
        request.extend_from_slice(&(round as u64).to_le_bytes());
        let mut preimage = self.state.clone();
        preimage.extend_from_slice(CHALLENGE_DOMAIN);
        append_frame(&mut preimage, 5, &request);
        let digest = sha512(&preimage);
        let mut challenge_bytes = [0u8; E384::BYTE_SIZE];
        challenge_bytes.copy_from_slice(&digest[..E384::BYTE_SIZE]);
        append_frame(&mut self.state, 6, &digest);
        self.challenge_count += 1;
        Ok(E384::from_le_bytes(challenge_bytes))
    }

    fn sample_query(
        &mut self,
        pair_count: usize,
        ordinal: usize,
    ) -> Result<usize, AuthenticatedBasefoldError> {
        if pair_count == 0 || !pair_count.is_power_of_two() || self.query_count != ordinal as u64 {
            return Err(AuthenticatedBasefoldError::TranscriptSchedule);
        }
        let mut request = Vec::with_capacity(24);
        request.extend_from_slice(&self.query_count.to_le_bytes());
        request.extend_from_slice(&(ordinal as u64).to_le_bytes());
        request.extend_from_slice(&(pair_count as u64).to_le_bytes());
        let mut preimage = self.state.clone();
        preimage.extend_from_slice(QUERY_DOMAIN);
        append_frame(&mut preimage, 7, &request);
        let digest = sha512(&preimage);
        let sample = u64::from_le_bytes(digest[..8].try_into().expect("eight digest bytes"));
        let index = (sample as usize) & (pair_count - 1);
        let mut response = Vec::with_capacity(SHA512_BYTES + 8);
        response.extend_from_slice(&digest);
        response.extend_from_slice(&(index as u64).to_le_bytes());
        append_frame(&mut self.state, 8, &response);
        self.query_count += 1;
        Ok(index)
    }

    fn digest(&self) -> Sha512Digest {
        domain_hash(TRANSCRIPT_DOMAIN, &self.state)
    }
}

/// This source prototype has not earned a complete-zero-knowledge claim.
pub const COMPLETE_ZERO_KNOWLEDGE: bool = false;
/// This source prototype has not earned a composed post-quantum/QROM claim.
pub const COMPOSED_PQ128_QROM: bool = false;
/// This source prototype is not reachable from production verification.
pub const PRODUCTION_AUTHORIZED: bool = false;

fn grouped_leaf_hash(layer: usize, width: usize, index: usize, values: &[E384]) -> Sha512Digest {
    let mut payload = Vec::with_capacity(26 + values.len() * E384::BYTE_SIZE);
    payload.extend_from_slice(&(layer as u64).to_le_bytes());
    payload.extend_from_slice(&(width as u64).to_le_bytes());
    payload.extend_from_slice(&(index as u64).to_le_bytes());
    payload.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for value in values {
        for coefficient in value.coefficients() {
            payload.extend_from_slice(&coefficient.to_le_bytes());
        }
    }
    domain_hash(LEAF_DOMAIN, &payload)
}

fn merkle_node_hash(
    layer: usize,
    tree_level: usize,
    node_index: usize,
    left: &Sha512Digest,
    right: &Sha512Digest,
) -> Sha512Digest {
    let mut payload = Vec::with_capacity(24 + 2 * SHA512_BYTES);
    payload.extend_from_slice(&(layer as u64).to_le_bytes());
    payload.extend_from_slice(&(tree_level as u64).to_le_bytes());
    payload.extend_from_slice(&(node_index as u64).to_le_bytes());
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    domain_hash(NODE_DOMAIN, &payload)
}

#[derive(Clone, Debug)]
struct GroupedMerkleTree {
    layer: usize,
    width: usize,
    levels: Vec<Vec<Sha512Digest>>,
}

impl GroupedMerkleTree {
    fn build(layer: usize, groups: &[Vec<E384>]) -> Result<Self, AuthenticatedBasefoldError> {
        if groups.is_empty() {
            return Err(AuthenticatedBasefoldError::EmptyGroups);
        }
        let width = groups[0].len();
        if width == 0 || !width.is_power_of_two() || groups.iter().any(|group| group.len() != width)
        {
            return Err(AuthenticatedBasefoldError::GroupLengthMismatch);
        }
        let mut leaves = Vec::with_capacity(width);
        let mut values = Vec::with_capacity(groups.len());
        for index in 0..width {
            values.clear();
            values.extend(groups.iter().map(|group| group[index]));
            leaves.push(grouped_leaf_hash(layer, width, index, &values));
        }
        let mut levels = vec![leaves];
        let mut tree_level = 1usize;
        while levels.last().expect("leaf level exists").len() > 1 {
            let previous = levels.last().expect("previous level exists");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for (node_index, pair) in previous.chunks_exact(2).enumerate() {
                next.push(merkle_node_hash(
                    layer, tree_level, node_index, &pair[0], &pair[1],
                ));
            }
            levels.push(next);
            tree_level += 1;
        }
        Ok(Self {
            layer,
            width,
            levels,
        })
    }

    fn root(&self) -> Sha512Digest {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("a validated Merkle tree has a root")
    }

    fn pair_authentication_tail(
        &self,
        pair_index: usize,
    ) -> Result<Vec<Sha512Digest>, AuthenticatedBasefoldError> {
        if self.width < 2 || pair_index >= self.width / 2 {
            return Err(AuthenticatedBasefoldError::TranscriptSchedule);
        }
        let mut current_index = pair_index;
        let mut tail = Vec::with_capacity(self.levels.len().saturating_sub(2));
        // Level zero holds leaves.  The opened left/right pair reconstructs its
        // level-one node without transmitting their mutual sibling digest.
        for level in 1..self.levels.len() - 1 {
            let nodes = &self.levels[level];
            tail.push(nodes[current_index ^ 1]);
            current_index >>= 1;
        }
        Ok(tail)
    }
}

fn log2_power_of_two(length: usize) -> Result<usize, AuthenticatedBasefoldError> {
    if length < 2 || !length.is_power_of_two() {
        return Err(AuthenticatedBasefoldError::InvalidTableLength);
    }
    Ok(length.trailing_zeros() as usize)
}

fn group_values_at(groups: &[Vec<E384>], index: usize) -> Vec<E384> {
    groups.iter().map(|group| group[index]).collect()
}

fn fold_groups(groups: &[Vec<E384>], challenge: E384) -> Vec<Vec<E384>> {
    let one_minus = E384::ONE - challenge;
    groups
        .iter()
        .map(|group| {
            group
                .chunks_exact(2)
                .map(|pair| pair[0] * one_minus + pair[1] * challenge)
                .collect()
        })
        .collect()
}

/// Commit every fold layer and construct sampled grouped pair openings.
///
/// `groups[g][i]` is source oracle `g` at Boolean index `i`.  Source values
/// are lifted into E384's constant coefficient; every later layer is stored and
/// authenticated as all three B128 coefficients.  Query indexes are derived
/// after every layer root is transcript-bound and therefore cost zero bytes.
pub fn prove_authenticated_basefold(
    groups: &[Vec<B128>],
    query_count: usize,
    context: &[u8],
) -> Result<AuthenticatedBasefoldProverOutput, AuthenticatedBasefoldError> {
    if groups.is_empty() {
        return Err(AuthenticatedBasefoldError::EmptyGroups);
    }
    if groups.len() > MAX_GROUP_COUNT {
        return Err(AuthenticatedBasefoldError::TooManyGroups {
            actual: groups.len(),
            maximum: MAX_GROUP_COUNT,
        });
    }
    let value_count = groups[0].len();
    if groups.iter().any(|group| group.len() != value_count) {
        return Err(AuthenticatedBasefoldError::GroupLengthMismatch);
    }
    let log_values = log2_power_of_two(value_count)?;
    validate_geometry(log_values, groups.len(), query_count)?;

    let context_digest = context_digest(context);
    let mut transcript =
        Sha512E384Transcript::new(context_digest, log_values, groups.len(), query_count);
    let mut layer_tables = Vec::with_capacity(log_values + 1);
    layer_tables.push(
        groups
            .iter()
            .map(|group| group.iter().copied().map(E384::from_b128).collect())
            .collect::<Vec<Vec<E384>>>(),
    );
    let mut trees = Vec::with_capacity(log_values + 1);
    let mut layer_roots = Vec::with_capacity(log_values + 1);
    let mut fold_challenges = Vec::with_capacity(log_values);

    for layer in 0..=log_values {
        let table = &layer_tables[layer];
        let width = value_count >> layer;
        let tree = GroupedMerkleTree::build(layer, table)?;
        debug_assert_eq!(tree.layer, layer);
        debug_assert_eq!(tree.width, width);
        let root = tree.root();
        transcript.observe_root(layer, width, &root);
        trees.push(tree);
        layer_roots.push(root);
        if layer < log_values {
            let challenge = transcript.sample_e384(layer)?;
            fold_challenges.push(challenge);
            layer_tables.push(fold_groups(table, challenge));
        }
    }

    let mut query_indices = Vec::with_capacity(query_count);
    let mut query_openings = Vec::with_capacity(query_count);
    let initial_pair_count = value_count / 2;
    for query in 0..query_count {
        let initial_pair = transcript.sample_query(initial_pair_count, query)?;
        query_indices.push(initial_pair);
        let mut pair_index = initial_pair;
        let mut rounds = Vec::with_capacity(log_values);
        for round in 0..log_values {
            let table = &layer_tables[round];
            let left_index = pair_index * 2;
            rounds.push(GroupedPairOpening {
                left: group_values_at(table, left_index),
                right: group_values_at(table, left_index + 1),
                authentication_tail: trees[round].pair_authentication_tail(pair_index)?,
            });
            pair_index >>= 1;
        }
        query_openings.push(rounds);
    }

    let terminal_values = group_values_at(layer_tables.last().expect("terminal layer exists"), 0);
    let proof = AuthenticatedBasefoldProof {
        log_values: log_values as u8,
        group_count: groups.len() as u16,
        query_count: query_count as u16,
        profile_digest: profile_digest(),
        context_digest,
        layer_roots,
        terminal_values,
        query_openings,
    };
    proof.validate_shape()?;
    Ok(AuthenticatedBasefoldProverOutput {
        proof,
        fold_challenges,
        query_indices,
        transcript_digest: transcript.digest(),
    })
}

fn authenticate_pair(
    layer: usize,
    width: usize,
    pair_index: usize,
    opening: &GroupedPairOpening,
) -> Sha512Digest {
    let left_index = pair_index * 2;
    let left = grouped_leaf_hash(layer, width, left_index, &opening.left);
    let right = grouped_leaf_hash(layer, width, left_index + 1, &opening.right);
    let mut current = merkle_node_hash(layer, 1, pair_index, &left, &right);
    let mut current_index = pair_index;
    let mut tree_level = 1usize;
    for sibling in &opening.authentication_tail {
        let parent_index = current_index >> 1;
        current = if current_index & 1 == 0 {
            merkle_node_hash(layer, tree_level + 1, parent_index, &current, sibling)
        } else {
            merkle_node_hash(layer, tree_level + 1, parent_index, sibling, &current)
        };
        current_index = parent_index;
        tree_level += 1;
    }
    current
}

/// Verify one decoded authenticated folding proof against its exact public
/// context.  All roots are bound before challenges, all challenges and query
/// indexes are re-derived, each pair path is authenticated, and each selected
/// parent is checked in genuine E384 arithmetic.
pub fn verify_authenticated_basefold(
    proof: &AuthenticatedBasefoldProof,
    context: &[u8],
) -> Result<AuthenticatedBasefoldVerification, AuthenticatedBasefoldError> {
    proof.validate_shape()?;
    if proof.context_digest != context_digest(context) {
        return Err(AuthenticatedBasefoldError::ContextMismatch);
    }
    let log_values = proof.log_values();
    let group_count = proof.group_count();
    let query_count = proof.query_count();
    let value_count = 1usize << log_values;
    let mut transcript =
        Sha512E384Transcript::new(proof.context_digest, log_values, group_count, query_count);
    let mut fold_challenges = Vec::with_capacity(log_values);
    for layer in 0..=log_values {
        transcript.observe_root(layer, value_count >> layer, &proof.layer_roots[layer]);
        if layer < log_values {
            fold_challenges.push(transcript.sample_e384(layer)?);
        }
    }

    let terminal_root = grouped_leaf_hash(log_values, 1, 0, &proof.terminal_values);
    if terminal_root != proof.layer_roots[log_values] {
        return Err(AuthenticatedBasefoldError::TerminalAuthentication);
    }

    let mut query_indices = Vec::with_capacity(query_count);
    for query in 0..query_count {
        let mut pair_index = transcript.sample_query(value_count / 2, query)?;
        query_indices.push(pair_index);
        for round in 0..log_values {
            let opening = &proof.query_openings[query][round];
            let width = value_count >> round;
            let authenticated = authenticate_pair(round, width, pair_index, opening);
            if authenticated != proof.layer_roots[round] {
                return Err(AuthenticatedBasefoldError::OpeningAuthentication { query, round });
            }
            let one_minus = E384::ONE - fold_challenges[round];
            for group in 0..group_count {
                let folded =
                    opening.left[group] * one_minus + opening.right[group] * fold_challenges[round];
                let expected = if round + 1 == log_values {
                    proof.terminal_values[group]
                } else {
                    let next = &proof.query_openings[query][round + 1];
                    if pair_index & 1 == 0 {
                        next.left[group]
                    } else {
                        next.right[group]
                    }
                };
                if folded != expected {
                    return Err(AuthenticatedBasefoldError::FoldMismatch {
                        query,
                        round,
                        group,
                    });
                }
            }
            pair_index >>= 1;
        }
    }

    Ok(AuthenticatedBasefoldVerification {
        fold_challenges,
        query_indices,
        terminal_values: proof.terminal_values.clone(),
        transcript_digest: transcript.digest(),
    })
}

/// Exact-decode and verify one canonical proof byte string.
pub fn verify_authenticated_basefold_exact(
    encoded: &[u8],
    context: &[u8],
) -> Result<AuthenticatedBasefoldVerification, AuthenticatedBasefoldError> {
    let proof = AuthenticatedBasefoldProof::decode_exact(encoded)?;
    // Canonical re-encoding is an explicit verifier gate even though the fixed
    // grammar already admits no alternate integer or field encodings.
    let (canonical, _) = proof.encode_counted()?;
    if canonical != encoded {
        return Err(AuthenticatedBasefoldError::TranscriptSchedule);
    }
    verify_authenticated_basefold(&proof, context)
}

#[derive(Default)]
struct ExactWriter {
    bytes: Vec<u8>,
    report: AuthenticatedBasefoldSizeReport,
}

impl ExactWriter {
    fn new(log_values: usize, group_count: usize, query_count: usize) -> Self {
        Self {
            bytes: Vec::new(),
            report: AuthenticatedBasefoldSizeReport {
                log_values,
                group_count,
                query_count,
                ..AuthenticatedBasefoldSizeReport::default()
            },
        }
    }

    fn write_fixed(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        self.report.fixed_bytes += bytes.len();
    }

    fn write_root(&mut self, root: &Sha512Digest) {
        self.bytes.extend_from_slice(root);
        self.report.merkle_roots += 1;
    }

    fn write_lane_value(&mut self, value: E384) {
        for coefficient in value.coefficients() {
            self.bytes.extend_from_slice(&coefficient.to_le_bytes());
            self.report.b128_symbols += 1;
        }
    }

    fn write_auth_node(&mut self, node: &Sha512Digest) {
        self.bytes.extend_from_slice(node);
        self.report.merkle_auth_nodes += 1;
    }

    fn finish(
        self,
    ) -> Result<(Vec<u8>, AuthenticatedBasefoldSizeReport), AuthenticatedBasefoldError> {
        let formula = AuthenticatedBasefoldSizeReport::formula_bytes(
            self.report.log_values,
            self.report.group_count,
            self.report.query_count,
        )?;
        debug_assert_eq!(self.bytes.len(), self.report.serialized_bytes());
        debug_assert_eq!(self.bytes.len(), formula);
        if self.bytes.len() != self.report.serialized_bytes() || self.bytes.len() != formula {
            return Err(AuthenticatedBasefoldError::LengthOverflow);
        }
        Ok((self.bytes, self.report))
    }
}

struct ExactReader<'a> {
    encoded: &'a [u8],
    cursor: usize,
}

impl<'a> ExactReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, cursor: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], AuthenticatedBasefoldError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(AuthenticatedBasefoldError::LengthOverflow)?;
        let bytes = self
            .encoded
            .get(self.cursor..end)
            .ok_or(AuthenticatedBasefoldError::ProofTruncated)?;
        self.cursor = end;
        Ok(bytes.try_into().expect("exact reader requested N bytes"))
    }

    fn read_lane_value(&mut self) -> Result<E384, AuthenticatedBasefoldError> {
        let mut coefficients = [B128::ZERO; 3];
        for coefficient in &mut coefficients {
            *coefficient = B128::from_le_bytes(self.read_array::<{ B128::BYTE_SIZE }>()?);
        }
        Ok(E384::from_coefficients(coefficients))
    }

    fn finish(self) -> Result<(), AuthenticatedBasefoldError> {
        if self.cursor != self.encoded.len() {
            return Err(AuthenticatedBasefoldError::ProofTrailingBytes {
                remaining: self.encoded.len() - self.cursor,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"hegemon.e384.authenticated-basefold.kat.statement-network-v1";

    fn hex(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            encoded.push(ALPHABET[(byte >> 4) as usize] as char);
            encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    fn fixture_groups() -> [Vec<B128>; 2] {
        [
            (0u128..8).map(|value| B128::new(value + 1)).collect(),
            (0u128..8)
                .map(|value| B128::new((value + 1) << 64 | (7 - value)))
                .collect(),
        ]
    }

    fn fixture() -> (
        AuthenticatedBasefoldProverOutput,
        Vec<u8>,
        AuthenticatedBasefoldSizeReport,
    ) {
        let proved = prove_authenticated_basefold(&fixture_groups(), 3, CONTEXT).unwrap();
        let (encoded, report) = proved.proof.encode_counted().unwrap();
        (proved, encoded, report)
    }

    fn swap_equal_ranges(bytes: &mut [u8], first: usize, second: usize, length: usize) {
        for offset in 0..length {
            bytes.swap(first + offset, second + offset);
        }
    }

    #[test]
    fn sha512_matches_fips_kats() {
        assert_eq!(
            hex(&sha512(b"")),
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn grouped_authenticated_fold_roundtrips_and_rederives_transcript() {
        let (proved, encoded, report) = fixture();
        let verified = verify_authenticated_basefold_exact(&encoded, CONTEXT).unwrap();
        assert_eq!(verified.fold_challenges, proved.fold_challenges);
        assert_eq!(verified.query_indices, proved.query_indices);
        assert_eq!(verified.terminal_values, proved.proof.terminal_values());
        assert_eq!(verified.transcript_digest, proved.transcript_digest);
        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&encoded).unwrap(),
            proved.proof
        );
        assert!(!COMPLETE_ZERO_KNOWLEDGE);
        assert!(!COMPOSED_PQ128_QROM);
        assert!(!PRODUCTION_AUTHORIZED);
        assert_eq!(report.serialized_bytes(), encoded.len());
    }

    #[test]
    fn serializer_report_is_exact_and_matches_closed_form() {
        let (_, encoded, report) = fixture();
        assert_eq!(report.fixed_bytes, 152);
        assert_eq!(report.log_values, 3);
        assert_eq!(report.group_count, 2);
        assert_eq!(report.query_count, 3);
        assert_eq!(report.merkle_roots, 4);
        assert_eq!(report.merkle_auth_nodes, 9);
        assert_eq!(report.b128_symbols, 114);
        assert_eq!(encoded.len(), 2_808);
        assert_eq!(report.serialized_bytes(), 2_808);
        assert_eq!(
            AuthenticatedBasefoldSizeReport::formula_bytes(3, 2, 3),
            Ok(2_808)
        );
    }

    #[test]
    fn coefficient_lane_and_group_order_mutations_reject() {
        let (_, encoded, _) = fixture();
        // Header (152) + four roots (256) + two terminal values (96).
        let first_opening = 152 + 4 * 64 + 2 * 48;

        let mut coefficient = encoded.clone();
        coefficient[first_opening] ^= 1;
        assert!(matches!(
            verify_authenticated_basefold_exact(&coefficient, CONTEXT),
            Err(AuthenticatedBasefoldError::OpeningAuthentication { .. })
        ));

        let mut lane_order = encoded.clone();
        swap_equal_ranges(&mut lane_order, first_opening, first_opening + 16, 16);
        assert!(matches!(
            verify_authenticated_basefold_exact(&lane_order, CONTEXT),
            Err(AuthenticatedBasefoldError::OpeningAuthentication { .. })
        ));

        let mut group_order = encoded.clone();
        swap_equal_ranges(&mut group_order, first_opening, first_opening + 48, 48);
        assert!(matches!(
            verify_authenticated_basefold_exact(&group_order, CONTEXT),
            Err(AuthenticatedBasefoldError::OpeningAuthentication { .. })
        ));
    }

    #[test]
    fn root_order_and_cross_domain_mutations_reject() {
        let (_, encoded, _) = fixture();
        let mut root_order = encoded.clone();
        swap_equal_ranges(&mut root_order, 152, 152 + 64, 64);
        assert!(verify_authenticated_basefold_exact(&root_order, CONTEXT).is_err());

        assert_eq!(
            verify_authenticated_basefold_exact(&encoded, b"wrong network/action/domain"),
            Err(AuthenticatedBasefoldError::ContextMismatch)
        );

        let mut profile = encoded.clone();
        // The profile digest starts after the 20-byte scalar header prefix.
        profile[20] ^= 1;
        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&profile),
            Err(AuthenticatedBasefoldError::ProfileMismatch)
        );
    }

    #[test]
    fn exact_parser_rejects_lane_tag_reserved_truncation_and_suffix() {
        let (_, encoded, _) = fixture();
        let mut lane_count = encoded.clone();
        lane_count[13] = 2;
        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&lane_count),
            Err(AuthenticatedBasefoldError::InvalidLaneCount { actual: 2 })
        );

        let mut reserved = encoded.clone();
        reserved[AUTHENTICATED_BASEFOLD_HEADER_BYTES - 1] = 1;
        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&reserved),
            Err(AuthenticatedBasefoldError::NonzeroReserved)
        );

        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&encoded[..encoded.len() - 1]),
            Err(AuthenticatedBasefoldError::ProofTruncated)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            AuthenticatedBasefoldProof::decode_exact(&trailing),
            Err(AuthenticatedBasefoldError::ProofTrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn fold_link_rejects_even_if_a_mutated_layer_is_reauthenticated() {
        let (proved, _, _) = fixture();
        let mut proof = proved.proof;
        // Replace the selected value in the second layer and rebuild only that
        // layer's tree/root.  Authentication then succeeds for the mutated
        // layer, but the preceding E384 fold equation must still fail.
        let query = 0usize;
        let round = 1usize;
        proof.query_openings[query][round].left[0] += E384::ONE;
        let opening = &proof.query_openings[query][round];
        let pair_index = proved.query_indices[query] >> round;
        proof.layer_roots[round] = authenticate_pair(
            round,
            (1usize << proof.log_values()) >> round,
            pair_index,
            opening,
        );
        assert!(verify_authenticated_basefold(&proof, CONTEXT).is_err());
    }
}
