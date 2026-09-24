//! Inactive exact inline transport for the unallocated all-W64/HX512 action.
//!
//! This module assigns no magic, circuit, suite, backend, profile, family, or
//! action identifier.  A caller must supply the exact 186-byte identity prefix
//! expected at the start of the raw statement.  The only owned representation
//! is the original action byte string; decoding never normalizes or rebuilds
//! it.
//!
//! The wire grammar is:
//!
//! ```text
//! statement[983] || proof_len:u32be || proof[proof_len]
//!     || ciphertext[2147] for each active output in slot order
//! ```
//!
//! This transport is deliberately inactive.  It has no sidecar, aggregation,
//! receipt, or cache validity path.  Syntax preflight makes no validity claim;
//! the admitted action type additionally requires a caller-supplied,
//! fail-closed statement/ciphertext/proof verifier.

use alloc::vec::Vec;
use core::fmt;

pub const HX512_INLINE_IDENTITY_BYTES: usize = 186;
pub const HX512_INLINE_ROUTE_BYTES: usize = 26;
pub const HX512_INLINE_ROUTE_MAGIC_BYTES: usize = 8;
pub const HX512_INLINE_ACTIVITY_MASK_OFFSET: usize = HX512_INLINE_IDENTITY_BYTES;
pub const HX512_INLINE_STABLECOIN_PUBLIC_OFFSET: usize = 668;
pub const HX512_INLINE_STABLECOIN_PUBLIC_BYTES: usize = 315;
pub const HX512_INLINE_STATEMENT_BYTES: usize = 983;
pub const HX512_INLINE_PROOF_LENGTH_BYTES: usize = 4;
pub const HX512_INLINE_PREFIX_BYTES: usize =
    HX512_INLINE_STATEMENT_BYTES + HX512_INLINE_PROOF_LENGTH_BYTES;
pub const HX512_INLINE_CIPHERTEXT_BYTES: usize = 2_147;
pub const HX512_INLINE_MAX_OUTPUTS: usize = 2;
/// Mathematical proof-length ceiling imposed by the `u32` wire and maximum
/// two-output overhead.  It is retained for arithmetic tests only and is far
/// too large to be a safe implementation or consensus cap.
pub const HX512_INLINE_WIRE_MAX_PROOF_BYTES: u32 = u32::MAX
    - HX512_INLINE_PREFIX_BYTES as u32
    - (HX512_INLINE_CIPHERTEXT_BYTES * HX512_INLINE_MAX_OUTPUTS) as u32;
/// Hard implementation ceiling, independent of the smaller future measured
/// consensus cap.  This prevents a caller from turning the mathematical
/// four-gigabyte wire range into an allocation interface.
pub const HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES: u32 = 4 * 1024 * 1024;

const HX512_INLINE_OUTPUT_FLAG_BASE: u8 = 2;
const HX512_INLINE_HIGH_MASK_NIBBLE: u8 = 0xf0;

const HX512_INLINE_ROUTE_STATEMENT_GRAMMAR_OFFSET: usize = 8;
const HX512_INLINE_ROUTE_CIRCUIT_OFFSET: usize = 10;
const HX512_INLINE_ROUTE_CRYPTO_SUITE_OFFSET: usize = 12;
const HX512_INLINE_ROUTE_FAMILY_OFFSET: usize = 14;
const HX512_INLINE_ROUTE_ACTION_OFFSET: usize = 16;
const HX512_INLINE_ROUTE_BACKEND_OFFSET: usize = 18;
const HX512_INLINE_ROUTE_PROFILE_OFFSET: usize = 19;
const HX512_INLINE_ROUTE_DOMAIN_SET_OFFSET: usize = 20;
const HX512_INLINE_ROUTE_NETWORK_OFFSET: usize = 22;
const HX512_INLINE_CHAIN_ID_OFFSET: usize = HX512_INLINE_ROUTE_BYTES;
const HX512_INLINE_CHAIN_ID_BYTES: usize = 32;
const HX512_INLINE_GENESIS_ID_OFFSET: usize =
    HX512_INLINE_CHAIN_ID_OFFSET + HX512_INLINE_CHAIN_ID_BYTES;
const HX512_INLINE_GENESIS_ID_BYTES: usize = 64;
const HX512_INLINE_RULES_HASH_OFFSET: usize =
    HX512_INLINE_GENESIS_ID_OFFSET + HX512_INLINE_GENESIS_ID_BYTES;
const HX512_INLINE_RULES_HASH_BYTES: usize = 64;

// The inactive snapshot is defined only for the 315-byte V3 stablecoin public
// projection.  A future public-width change must use a fresh transport
// identity/module; it may not silently move this boundary.
const _: [(); HX512_INLINE_STATEMENT_BYTES] =
    [(); HX512_INLINE_STABLECOIN_PUBLIC_OFFSET + HX512_INLINE_STABLECOIN_PUBLIC_BYTES];
const _: [(); HX512_INLINE_IDENTITY_BYTES] =
    [(); HX512_INLINE_RULES_HASH_OFFSET + HX512_INLINE_RULES_HASH_BYTES];

/// Declarations, not feature switches.  No alternative object may contribute
/// to validity for this self-contained action.
pub const HX512_INLINE_PRODUCTION_ADMISSION_ENABLED: bool = false;
pub const HX512_INLINE_SIDECAR_VALIDITY_ALLOWED: bool = false;
pub const HX512_INLINE_AGGREGATE_VALIDITY_ALLOWED: bool = false;
pub const HX512_INLINE_RECEIPT_VALIDITY_ALLOWED: bool = false;
pub const HX512_INLINE_CACHE_VALIDITY_ALLOWED: bool = false;

/// Read-only projection of the still-unallocated route and chain identity.
///
/// This is a structural view of the first 186 statement bytes, not an
/// allocation or authorization.  It exists so wallet/RPC/native lifecycle
/// code can compare its outer route fields with the exact inner statement
/// bytes without maintaining a second identity grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512InlineIdentityProjection {
    pub magic: [u8; HX512_INLINE_ROUTE_MAGIC_BYTES],
    pub statement_grammar: u16,
    pub circuit_version: u16,
    pub crypto_suite: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub backend_id: u8,
    pub proof_profile: u8,
    pub domain_set: u16,
    pub network_id: u32,
    pub chain_id: [u8; HX512_INLINE_CHAIN_ID_BYTES],
    pub genesis_id: [u8; HX512_INLINE_GENESIS_ID_BYTES],
    pub rules_hash: [u8; HX512_INLINE_RULES_HASH_BYTES],
}

/// Project the fixed route/chain fields without assigning meaning or
/// authority to any value.  All integers use the relation grammar's canonical
/// big-endian encoding.
pub fn project_hx512_inline_identity(
    identity: &[u8; HX512_INLINE_IDENTITY_BYTES],
) -> Hx512InlineIdentityProjection {
    Hx512InlineIdentityProjection {
        magic: identity[..HX512_INLINE_ROUTE_MAGIC_BYTES]
            .try_into()
            .expect("the HX512 route magic has a fixed width"),
        statement_grammar: read_u16_be(identity, HX512_INLINE_ROUTE_STATEMENT_GRAMMAR_OFFSET),
        circuit_version: read_u16_be(identity, HX512_INLINE_ROUTE_CIRCUIT_OFFSET),
        crypto_suite: read_u16_be(identity, HX512_INLINE_ROUTE_CRYPTO_SUITE_OFFSET),
        family_id: read_u16_be(identity, HX512_INLINE_ROUTE_FAMILY_OFFSET),
        action_id: read_u16_be(identity, HX512_INLINE_ROUTE_ACTION_OFFSET),
        backend_id: identity[HX512_INLINE_ROUTE_BACKEND_OFFSET],
        proof_profile: identity[HX512_INLINE_ROUTE_PROFILE_OFFSET],
        domain_set: read_u16_be(identity, HX512_INLINE_ROUTE_DOMAIN_SET_OFFSET),
        network_id: read_u32_be(identity, HX512_INLINE_ROUTE_NETWORK_OFFSET),
        chain_id: identity[HX512_INLINE_CHAIN_ID_OFFSET
            ..HX512_INLINE_CHAIN_ID_OFFSET + HX512_INLINE_CHAIN_ID_BYTES]
            .try_into()
            .expect("the HX512 chain id has a fixed width"),
        genesis_id: identity[HX512_INLINE_GENESIS_ID_OFFSET
            ..HX512_INLINE_GENESIS_ID_OFFSET + HX512_INLINE_GENESIS_ID_BYTES]
            .try_into()
            .expect("the HX512 genesis id has a fixed width"),
        rules_hash: identity[HX512_INLINE_RULES_HASH_OFFSET
            ..HX512_INLINE_RULES_HASH_OFFSET + HX512_INLINE_RULES_HASH_BYTES]
            .try_into()
            .expect("the HX512 rules hash has a fixed width"),
    }
}

/// Caller-owned immutable transport authority.
///
/// The identity bytes include the prospective route, domain, network, chain,
/// genesis, and rules bindings.  This crate intentionally provides no value
/// for them.  The proof cap is likewise supplied by the future manifest rather
/// than allocated here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512InlineTransportContext<'a> {
    expected_identity: &'a [u8; HX512_INLINE_IDENTITY_BYTES],
    max_proof_bytes: u32,
}

impl<'a> Hx512InlineTransportContext<'a> {
    pub fn new(
        expected_identity: &'a [u8; HX512_INLINE_IDENTITY_BYTES],
        max_proof_bytes: u32,
        stablecoin_public_bytes: usize,
    ) -> Result<Self, Hx512InlineTransportError> {
        if stablecoin_public_bytes != HX512_INLINE_STABLECOIN_PUBLIC_BYTES {
            return Err(Hx512InlineTransportError::StablecoinPublicWidth {
                observed: stablecoin_public_bytes,
                expected: HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
            });
        }
        if max_proof_bytes == 0 || max_proof_bytes > HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES {
            return Err(Hx512InlineTransportError::InvalidProofCap(max_proof_bytes));
        }
        let context = Self {
            expected_identity,
            max_proof_bytes,
        };
        context.maximum_action_bytes()?;
        Ok(context)
    }

    pub const fn expected_identity(&self) -> &[u8; HX512_INLINE_IDENTITY_BYTES] {
        self.expected_identity
    }

    pub const fn max_proof_bytes(&self) -> usize {
        self.max_proof_bytes as usize
    }

    pub fn maximum_action_bytes(&self) -> Result<usize, Hx512InlineTransportError> {
        HX512_INLINE_PREFIX_BYTES
            .checked_add(self.max_proof_bytes())
            .and_then(|length| {
                HX512_INLINE_CIPHERTEXT_BYTES
                    .checked_mul(HX512_INLINE_MAX_OUTPUTS)
                    .and_then(|ciphertext_bytes| length.checked_add(ciphertext_bytes))
            })
            .ok_or(Hx512InlineTransportError::LengthOverflow)
    }
}

/// Mandatory admission boundary supplied by the relation/verifier owner.
///
/// There is intentionally no permissive/default implementation.  Returning
/// `false` rejects the action.  The statement hook must bind the complete
/// 983-byte public statement, the proof hook must run the exact production
/// verifier against that statement, and each ciphertext hook must bind the
/// exact active-slot ciphertext to that statement.
pub trait Hx512InlineAdmissionVerifier {
    fn validate_statement(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool;

    fn validate_proof(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES], proof: &[u8]) -> bool;

    fn validate_ciphertext(
        &self,
        output_slot: usize,
        statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
        ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
    ) -> bool;
}

/// Allocation-free result of validating the fixed 987-byte framing prefix.
///
/// This is syntax metadata only.  It is never evidence that the statement,
/// ciphertexts, or proof are valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512InlineFrameShape {
    proof_length: u32,
    output_count: u8,
    action_bytes: u32,
}

impl Hx512InlineFrameShape {
    pub const fn proof_length(self) -> u32 {
        self.proof_length
    }

    pub const fn output_count(self) -> u8 {
        self.output_count
    }

    pub const fn action_bytes(self) -> u32 {
        self.action_bytes
    }
}

/// One exact self-contained action admitted by the mandatory verifier.
///
/// No decoded fields or validity result are cached alongside the canonical
/// bytes.  This type cannot be obtained through syntax preflight alone.
#[derive(Debug, PartialEq, Eq)]
pub struct Hx512InlineAction {
    canonical_bytes: Vec<u8>,
}

impl Hx512InlineAction {
    pub fn from_parts<V: Hx512InlineAdmissionVerifier + ?Sized>(
        context: Hx512InlineTransportContext<'_>,
        statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
        proof: &[u8],
        ciphertexts: [Option<&[u8; HX512_INLINE_CIPHERTEXT_BYTES]>; HX512_INLINE_MAX_OUTPUTS],
        validator: &V,
    ) -> Result<Self, Hx512InlineTransportError> {
        if proof.is_empty() {
            return Err(Hx512InlineTransportError::EmptyProof);
        }
        if proof.len() > context.max_proof_bytes() {
            return Err(Hx512InlineTransportError::ProofTooLarge {
                observed: proof.len(),
                maximum: context.max_proof_bytes(),
            });
        }
        let proof_length =
            u32::try_from(proof.len()).map_err(|_| Hx512InlineTransportError::LengthOverflow)?;
        let activity_mask = validate_statement_transport(context, statement)?;

        let mut output_count = 0usize;
        for (slot, ciphertext) in ciphertexts.iter().enumerate() {
            let active = output_is_active(activity_mask, slot);
            match (active, ciphertext) {
                (true, Some(_)) => {
                    output_count = output_count
                        .checked_add(1)
                        .ok_or(Hx512InlineTransportError::LengthOverflow)?;
                }
                (true, None) => {
                    return Err(Hx512InlineTransportError::MissingCiphertext(slot));
                }
                (false, Some(_)) => {
                    return Err(Hx512InlineTransportError::UnexpectedCiphertext(slot));
                }
                (false, None) => {}
            }
        }

        let total_length = exact_action_length(proof.len(), output_count)?;
        if total_length > context.maximum_action_bytes()? {
            return Err(Hx512InlineTransportError::ActionTooLarge {
                observed: total_length,
                maximum: context.maximum_action_bytes()?,
            });
        }

        // All allocation-free option/mask/length/cap checks above precede
        // every caller-supplied semantic or cryptographic hook.
        if !validator.validate_statement(statement) {
            return Err(Hx512InlineTransportError::StatementRejected);
        }
        for (slot, ciphertext) in ciphertexts.iter().enumerate() {
            if let (true, Some(ciphertext)) = (output_is_active(activity_mask, slot), ciphertext) {
                if !validator.validate_ciphertext(slot, statement, ciphertext) {
                    return Err(Hx512InlineTransportError::CiphertextRejected(slot));
                }
            }
        }
        if !validator.validate_proof(statement, proof) {
            return Err(Hx512InlineTransportError::ProofRejected);
        }

        // Every cap, identity, shape, and semantic check above precedes this
        // action allocation.
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(total_length)
            .map_err(|_| Hx512InlineTransportError::AllocationFailed(total_length))?;
        canonical_bytes.extend_from_slice(statement);
        canonical_bytes.extend_from_slice(&proof_length.to_be_bytes());
        canonical_bytes.extend_from_slice(proof);
        for ciphertext in ciphertexts.into_iter().flatten() {
            canonical_bytes.extend_from_slice(ciphertext);
        }
        debug_assert_eq!(canonical_bytes.len(), total_length);
        Ok(Self { canonical_bytes })
    }

    pub fn admit_exact<V: Hx512InlineAdmissionVerifier + ?Sized>(
        context: Hx512InlineTransportContext<'_>,
        raw_action: &[u8],
        validator: &V,
    ) -> Result<Self, Hx512InlineTransportError> {
        validate_hx512_inline_action(context, raw_action, validator)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(raw_action.len())
            .map_err(|_| Hx512InlineTransportError::AllocationFailed(raw_action.len()))?;
        canonical_bytes.extend_from_slice(raw_action);
        Ok(Self { canonical_bytes })
    }

    /// Admit an already-owned canonical frame without a second full-frame
    /// allocation/copy.  Network/RPC framing must enforce the context cap
    /// before constructing the supplied vector.
    pub fn admit_owned<V: Hx512InlineAdmissionVerifier + ?Sized>(
        context: Hx512InlineTransportContext<'_>,
        raw_action: Vec<u8>,
        validator: &V,
    ) -> Result<Self, Hx512InlineTransportError> {
        validate_hx512_inline_action(context, &raw_action, validator)?;
        Ok(Self {
            canonical_bytes: raw_action,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Explicit fallible duplicate for the rare caller that genuinely needs
    /// two owned copies of a complete admitted action.
    pub fn try_clone(&self) -> Result<Self, Hx512InlineTransportError> {
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(self.canonical_bytes.len())
            .map_err(|_| Hx512InlineTransportError::AllocationFailed(self.canonical_bytes.len()))?;
        canonical_bytes.extend_from_slice(&self.canonical_bytes);
        Ok(Self { canonical_bytes })
    }

    pub fn statement(&self) -> &[u8; HX512_INLINE_STATEMENT_BYTES] {
        self.canonical_bytes[..HX512_INLINE_STATEMENT_BYTES]
            .try_into()
            .expect("validated HX512 action retains its fixed statement")
    }

    pub fn activity_mask(&self) -> u8 {
        self.canonical_bytes[HX512_INLINE_ACTIVITY_MASK_OFFSET]
    }

    pub fn proof(&self) -> &[u8] {
        let proof_length = read_proof_length(&self.canonical_bytes);
        &self.canonical_bytes[HX512_INLINE_PREFIX_BYTES..HX512_INLINE_PREFIX_BYTES + proof_length]
    }

    pub fn ciphertext(&self, output_slot: usize) -> Option<&[u8; HX512_INLINE_CIPHERTEXT_BYTES]> {
        if output_slot >= HX512_INLINE_MAX_OUTPUTS
            || !output_is_active(self.activity_mask(), output_slot)
        {
            return None;
        }
        let mut offset = HX512_INLINE_PREFIX_BYTES + self.proof().len();
        for slot in 0..HX512_INLINE_MAX_OUTPUTS {
            if !output_is_active(self.activity_mask(), slot) {
                continue;
            }
            if slot == output_slot {
                return Some(
                    self.canonical_bytes[offset..offset + HX512_INLINE_CIPHERTEXT_BYTES]
                        .try_into()
                        .expect("validated HX512 ciphertext keeps its fixed width"),
                );
            }
            offset += HX512_INLINE_CIPHERTEXT_BYTES;
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512InlineTransportStage {
    Wallet,
    Rpc,
    Relay,
    Mempool,
    Mining,
    Block,
    Restart,
    Sync,
    Reorg,
    FreshNode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512InlineTransportError {
    StablecoinPublicWidth {
        observed: usize,
        expected: usize,
    },
    InvalidProofCap(u32),
    ActionTooLarge {
        observed: usize,
        maximum: usize,
    },
    PrefixTooShort {
        observed: usize,
        minimum: usize,
    },
    IdentityMismatch {
        first_difference: usize,
    },
    NonCanonicalActivityMask(u8),
    EmptyProof,
    ProofTooLarge {
        observed: usize,
        maximum: usize,
    },
    LengthOverflow,
    AllocationFailed(usize),
    Truncated {
        declared: usize,
        observed: usize,
    },
    TrailingBytes {
        trailing: usize,
    },
    MissingCiphertext(usize),
    UnexpectedCiphertext(usize),
    StatementRejected,
    ProofRejected,
    CiphertextRejected(usize),
    StageMismatch {
        stage: Hx512InlineTransportStage,
        expected: usize,
        observed: usize,
        first_difference: Option<usize>,
    },
}

impl fmt::Display for Hx512InlineTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Hx512InlineTransportError {}

/// Allocation-free preflight for a fixed-width prefix already read by the
/// outer network/RPC/block framer.
///
/// Callers must first enforce `context.maximum_action_bytes()` on the outer
/// frame before buffering it.  This function then freezes the exact declared
/// action length without invoking semantic or cryptographic validation.
pub fn preflight_hx512_inline_prefix(
    context: Hx512InlineTransportContext<'_>,
    prefix: &[u8; HX512_INLINE_PREFIX_BYTES],
) -> Result<Hx512InlineFrameShape, Hx512InlineTransportError> {
    let statement: &[u8; HX512_INLINE_STATEMENT_BYTES] = prefix[..HX512_INLINE_STATEMENT_BYTES]
        .try_into()
        .expect("the HX512 preflight prefix has a fixed statement width");
    let activity_mask = validate_statement_transport(context, statement)?;
    let proof_length = read_proof_length(prefix);
    if proof_length == 0 {
        return Err(Hx512InlineTransportError::EmptyProof);
    }
    if proof_length > context.max_proof_bytes() {
        return Err(Hx512InlineTransportError::ProofTooLarge {
            observed: proof_length,
            maximum: context.max_proof_bytes(),
        });
    }
    let output_count = active_output_count(activity_mask);
    let action_bytes = exact_action_length(proof_length, output_count)?;
    let maximum = context.maximum_action_bytes()?;
    if action_bytes > maximum {
        return Err(Hx512InlineTransportError::ActionTooLarge {
            observed: action_bytes,
            maximum,
        });
    }
    Ok(Hx512InlineFrameShape {
        proof_length: u32::try_from(proof_length)
            .map_err(|_| Hx512InlineTransportError::LengthOverflow)?,
        output_count: u8::try_from(output_count)
            .map_err(|_| Hx512InlineTransportError::LengthOverflow)?,
        action_bytes: u32::try_from(action_bytes)
            .map_err(|_| Hx512InlineTransportError::LengthOverflow)?,
    })
}

/// Validate only identity, mask, cap, and exact framing, without allocating.
/// This function deliberately makes no statement/proof/ciphertext validity
/// claim.
pub fn validate_hx512_inline_syntax(
    context: Hx512InlineTransportContext<'_>,
    raw_action: &[u8],
) -> Result<Hx512InlineFrameShape, Hx512InlineTransportError> {
    let maximum = context.maximum_action_bytes()?;
    if raw_action.len() > maximum {
        return Err(Hx512InlineTransportError::ActionTooLarge {
            observed: raw_action.len(),
            maximum,
        });
    }
    if raw_action.len() < HX512_INLINE_PREFIX_BYTES {
        return Err(Hx512InlineTransportError::PrefixTooShort {
            observed: raw_action.len(),
            minimum: HX512_INLINE_PREFIX_BYTES,
        });
    }

    let prefix: &[u8; HX512_INLINE_PREFIX_BYTES] = raw_action[..HX512_INLINE_PREFIX_BYTES]
        .try_into()
        .expect("the fixed HX512 prefix length was checked");
    let shape = preflight_hx512_inline_prefix(context, prefix)?;
    let declared = shape.action_bytes() as usize;
    if raw_action.len() < declared {
        return Err(Hx512InlineTransportError::Truncated {
            declared,
            observed: raw_action.len(),
        });
    }
    if raw_action.len() > declared {
        return Err(Hx512InlineTransportError::TrailingBytes {
            trailing: raw_action.len() - declared,
        });
    }
    Ok(shape)
}

/// Validate the complete action without allocating or retaining a validity
/// cache.  Exact syntax is established before any expensive verifier hook.
pub fn validate_hx512_inline_action<V: Hx512InlineAdmissionVerifier + ?Sized>(
    context: Hx512InlineTransportContext<'_>,
    raw_action: &[u8],
    validator: &V,
) -> Result<(), Hx512InlineTransportError> {
    let shape = validate_hx512_inline_syntax(context, raw_action)?;
    let statement: &[u8; HX512_INLINE_STATEMENT_BYTES] = raw_action[..HX512_INLINE_STATEMENT_BYTES]
        .try_into()
        .expect("HX512 syntax validation established the statement width");
    let proof_length = shape.proof_length() as usize;
    let activity_mask = statement[HX512_INLINE_ACTIVITY_MASK_OFFSET];

    // Semantic and cryptographic checks run only after all cheap identity,
    // mask, cap, and exact-length checks have succeeded.
    if !validator.validate_statement(statement) {
        return Err(Hx512InlineTransportError::StatementRejected);
    }

    let mut ciphertext_offset = HX512_INLINE_PREFIX_BYTES + proof_length;
    for slot in 0..HX512_INLINE_MAX_OUTPUTS {
        if !output_is_active(activity_mask, slot) {
            continue;
        }
        let ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES] = raw_action
            [ciphertext_offset..ciphertext_offset + HX512_INLINE_CIPHERTEXT_BYTES]
            .try_into()
            .expect("the exact HX512 action length was checked");
        if !validator.validate_ciphertext(slot, statement, ciphertext) {
            return Err(Hx512InlineTransportError::CiphertextRejected(slot));
        }
        ciphertext_offset += HX512_INLINE_CIPHERTEXT_BYTES;
    }
    debug_assert_eq!(ciphertext_offset, shape.action_bytes() as usize);

    // The proof verifier is intentionally last: cheap exact semantic and
    // ciphertext rejection precedes the heavy cryptographic operation.
    let proof = &raw_action[HX512_INLINE_PREFIX_BYTES..HX512_INLINE_PREFIX_BYTES + proof_length];
    if !validator.validate_proof(statement, proof) {
        return Err(Hx512InlineTransportError::ProofRejected);
    }
    Ok(())
}

/// Diagnostic-only byte-for-byte lifecycle assertion.
///
/// This performs syntax checks but is never admission authority; every
/// consensus admission/re-admission site must invoke the exact proof verifier.
pub fn ensure_hx512_inline_stage_bytes(
    context: Hx512InlineTransportContext<'_>,
    canonical_action: &[u8],
    observed_action: &[u8],
    stage: Hx512InlineTransportStage,
) -> Result<(), Hx512InlineTransportError> {
    validate_hx512_inline_syntax(context, canonical_action)?;
    validate_hx512_inline_syntax(context, observed_action)?;
    if canonical_action == observed_action {
        return Ok(());
    }
    let first_difference = canonical_action
        .iter()
        .zip(observed_action)
        .position(|(expected, observed)| expected != observed)
        .or_else(|| {
            (canonical_action.len() != observed_action.len())
                .then_some(canonical_action.len().min(observed_action.len()))
        });
    Err(Hx512InlineTransportError::StageMismatch {
        stage,
        expected: canonical_action.len(),
        observed: observed_action.len(),
        first_difference,
    })
}

fn validate_statement_transport(
    context: Hx512InlineTransportContext<'_>,
    statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
) -> Result<u8, Hx512InlineTransportError> {
    if statement[..HX512_INLINE_IDENTITY_BYTES] != context.expected_identity()[..] {
        let first_difference = statement[..HX512_INLINE_IDENTITY_BYTES]
            .iter()
            .zip(context.expected_identity())
            .position(|(observed, expected)| observed != expected)
            .expect("unequal fixed-width HX512 identities differ somewhere");
        return Err(Hx512InlineTransportError::IdentityMismatch { first_difference });
    }
    let activity_mask = statement[HX512_INLINE_ACTIVITY_MASK_OFFSET];
    if activity_mask & HX512_INLINE_HIGH_MASK_NIBBLE != 0 {
        return Err(Hx512InlineTransportError::NonCanonicalActivityMask(
            activity_mask,
        ));
    }
    Ok(activity_mask)
}

fn exact_action_length(
    proof_length: usize,
    output_count: usize,
) -> Result<usize, Hx512InlineTransportError> {
    HX512_INLINE_CIPHERTEXT_BYTES
        .checked_mul(output_count)
        .and_then(|ciphertext_bytes| {
            HX512_INLINE_PREFIX_BYTES
                .checked_add(proof_length)?
                .checked_add(ciphertext_bytes)
        })
        .ok_or(Hx512InlineTransportError::LengthOverflow)
}

fn read_proof_length(raw_action: &[u8]) -> usize {
    u32::from_be_bytes(
        raw_action[HX512_INLINE_STATEMENT_BYTES..HX512_INLINE_PREFIX_BYTES]
            .try_into()
            .expect("the fixed HX512 prefix length was checked"),
    ) as usize
}

fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("the fixed HX512 identity width was checked"),
    )
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("the fixed HX512 identity width was checked"),
    )
}

fn output_is_active(activity_mask: u8, output_slot: usize) -> bool {
    output_slot < HX512_INLINE_MAX_OUTPUTS
        && activity_mask & (1u8 << (HX512_INLINE_OUTPUT_FLAG_BASE as usize + output_slot)) != 0
}

fn active_output_count(activity_mask: u8) -> usize {
    (0..HX512_INLINE_MAX_OUTPUTS)
        .filter(|slot| output_is_active(activity_mask, *slot))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ONLY_PROOF_CAP: u32 = 37;

    struct TestOnlyFixture {
        identity: [u8; HX512_INLINE_IDENTITY_BYTES],
        statement: [u8; HX512_INLINE_STATEMENT_BYTES],
        proof: Vec<u8>,
        ciphertexts: [[u8; HX512_INLINE_CIPHERTEXT_BYTES]; HX512_INLINE_MAX_OUTPUTS],
    }

    impl TestOnlyFixture {
        fn new(activity_mask: u8, proof_length: usize) -> Self {
            let mut identity = [0u8; HX512_INLINE_IDENTITY_BYTES];
            for (index, byte) in identity.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
            }
            let mut statement = [0u8; HX512_INLINE_STATEMENT_BYTES];
            for (index, byte) in statement.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(29).wrapping_add(11);
            }
            statement[..HX512_INLINE_IDENTITY_BYTES].copy_from_slice(&identity);
            statement[HX512_INLINE_ACTIVITY_MASK_OFFSET] = activity_mask;

            let proof = (0..proof_length)
                .map(|index| (index as u8).wrapping_mul(7).wrapping_add(5))
                .collect();
            let ciphertexts = core::array::from_fn(|slot| {
                let mut ciphertext = [0u8; HX512_INLINE_CIPHERTEXT_BYTES];
                for (index, byte) in ciphertext.iter_mut().enumerate() {
                    *byte = (index as u8)
                        .wrapping_mul(13)
                        .wrapping_add((slot as u8).wrapping_mul(71))
                        .wrapping_add(19);
                }
                ciphertext
            });
            Self {
                identity,
                statement,
                proof,
                ciphertexts,
            }
        }

        fn context(&self) -> Hx512InlineTransportContext<'_> {
            Hx512InlineTransportContext::new(
                &self.identity,
                TEST_ONLY_PROOF_CAP,
                HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
            )
            .unwrap()
        }

        fn raw(&self) -> Vec<u8> {
            let output_count =
                active_output_count(self.statement[HX512_INLINE_ACTIVITY_MASK_OFFSET]);
            let mut raw =
                Vec::with_capacity(exact_action_length(self.proof.len(), output_count).unwrap());
            raw.extend_from_slice(&self.statement);
            raw.extend_from_slice(&(self.proof.len() as u32).to_be_bytes());
            raw.extend_from_slice(&self.proof);
            for slot in 0..HX512_INLINE_MAX_OUTPUTS {
                if output_is_active(self.statement[HX512_INLINE_ACTIVITY_MASK_OFFSET], slot) {
                    raw.extend_from_slice(&self.ciphertexts[slot]);
                }
            }
            raw
        }

        fn ciphertext_refs(
            &self,
        ) -> [Option<&[u8; HX512_INLINE_CIPHERTEXT_BYTES]>; HX512_INLINE_MAX_OUTPUTS] {
            core::array::from_fn(|slot| {
                output_is_active(self.statement[HX512_INLINE_ACTIVITY_MASK_OFFSET], slot)
                    .then_some(&self.ciphertexts[slot])
            })
        }
    }

    struct TestOnlyValidator<'a>(&'a TestOnlyFixture);

    impl Hx512InlineAdmissionVerifier for TestOnlyValidator<'_> {
        fn validate_statement(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool {
            statement == &self.0.statement
        }

        fn validate_proof(
            &self,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            proof: &[u8],
        ) -> bool {
            statement == &self.0.statement && proof == self.0.proof
        }

        fn validate_ciphertext(
            &self,
            output_slot: usize,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
        ) -> bool {
            statement == &self.0.statement
                && self.0.ciphertexts.get(output_slot) == Some(ciphertext)
        }
    }

    struct PanicIfCalledValidator;

    impl Hx512InlineAdmissionVerifier for PanicIfCalledValidator {
        fn validate_statement(&self, _: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool {
            panic!("semantic validation ran before exact syntax rejection")
        }

        fn validate_proof(&self, _: &[u8; HX512_INLINE_STATEMENT_BYTES], _: &[u8]) -> bool {
            panic!("proof verification ran before exact syntax rejection")
        }

        fn validate_ciphertext(
            &self,
            _: usize,
            _: &[u8; HX512_INLINE_STATEMENT_BYTES],
            _: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
        ) -> bool {
            panic!("ciphertext validation ran before exact syntax rejection")
        }
    }

    #[test]
    fn every_low_mask_roundtrips_with_exact_formula_and_slot_order() {
        for activity_mask in 0u8..=0x0f {
            let fixture = TestOnlyFixture::new(activity_mask, 19);
            let validator = TestOnlyValidator(&fixture);
            let raw = fixture.raw();
            let output_count = active_output_count(activity_mask);
            assert_eq!(raw.len(), 987 + fixture.proof.len() + 2_147 * output_count);

            let parsed = Hx512InlineAction::admit_exact(fixture.context(), &raw, &validator)
                .expect("canonical test-only action must parse");
            assert_eq!(parsed.as_bytes(), raw);
            assert_eq!(parsed.statement(), &fixture.statement);
            assert_eq!(parsed.proof(), fixture.proof);
            let duplicate = parsed
                .try_clone()
                .expect("bounded test action clones fallibly");
            assert_eq!(duplicate.as_bytes(), raw);
            for slot in 0..HX512_INLINE_MAX_OUTPUTS {
                assert_eq!(
                    parsed.ciphertext(slot),
                    output_is_active(activity_mask, slot).then_some(&fixture.ciphertexts[slot])
                );
            }

            let built = Hx512InlineAction::from_parts(
                fixture.context(),
                &fixture.statement,
                &fixture.proof,
                fixture.ciphertext_refs(),
                &validator,
            )
            .expect("canonical test-only parts must encode");
            assert_eq!(built.into_bytes(), raw);
        }
    }

    #[test]
    fn proof_cap_minus_one_and_cap_pass_but_cap_plus_one_fails() {
        for proof_length in [
            (TEST_ONLY_PROOF_CAP - 1) as usize,
            TEST_ONLY_PROOF_CAP as usize,
        ] {
            let fixture = TestOnlyFixture::new(0, proof_length);
            let validator = TestOnlyValidator(&fixture);
            assert!(
                Hx512InlineAction::admit_exact(fixture.context(), &fixture.raw(), &validator)
                    .is_ok()
            );
        }

        let fixture = TestOnlyFixture::new(0, TEST_ONLY_PROOF_CAP as usize + 1);
        let validator = TestOnlyValidator(&fixture);
        assert_eq!(
            Hx512InlineAction::admit_exact(fixture.context(), &fixture.raw(), &validator),
            Err(Hx512InlineTransportError::ProofTooLarge {
                observed: TEST_ONLY_PROOF_CAP as usize + 1,
                maximum: TEST_ONLY_PROOF_CAP as usize,
            })
        );

        let fixture = TestOnlyFixture::new(0x0c, TEST_ONLY_PROOF_CAP as usize + 1);
        let validator = TestOnlyValidator(&fixture);
        assert!(matches!(
            Hx512InlineAction::admit_exact(fixture.context(), &fixture.raw(), &validator),
            Err(Hx512InlineTransportError::ActionTooLarge { .. })
        ));
    }

    #[test]
    fn unallocated_identity_projection_is_exact_and_big_endian() {
        let mut identity = [0u8; HX512_INLINE_IDENTITY_BYTES];
        identity[..8].copy_from_slice(b"HXTST001");
        identity[8..10].copy_from_slice(&0x0102u16.to_be_bytes());
        identity[10..12].copy_from_slice(&0x0304u16.to_be_bytes());
        identity[12..14].copy_from_slice(&0x0506u16.to_be_bytes());
        identity[14..16].copy_from_slice(&0x0708u16.to_be_bytes());
        identity[16..18].copy_from_slice(&0x090au16.to_be_bytes());
        identity[18] = 0x0b;
        identity[19] = 0x0c;
        identity[20..22].copy_from_slice(&0x0d0eu16.to_be_bytes());
        identity[22..26].copy_from_slice(&0x0f10_1112u32.to_be_bytes());
        identity[26..58].fill(0x31);
        identity[58..122].fill(0x32);
        identity[122..186].fill(0x33);

        let projected = project_hx512_inline_identity(&identity);
        assert_eq!(projected.magic, *b"HXTST001");
        assert_eq!(projected.statement_grammar, 0x0102);
        assert_eq!(projected.circuit_version, 0x0304);
        assert_eq!(projected.crypto_suite, 0x0506);
        assert_eq!(projected.family_id, 0x0708);
        assert_eq!(projected.action_id, 0x090a);
        assert_eq!(projected.backend_id, 0x0b);
        assert_eq!(projected.proof_profile, 0x0c);
        assert_eq!(projected.domain_set, 0x0d0e);
        assert_eq!(projected.network_id, 0x0f10_1112);
        assert_eq!(projected.chain_id, [0x31; 32]);
        assert_eq!(projected.genesis_id, [0x32; 64]);
        assert_eq!(projected.rules_hash, [0x33; 64]);
    }

    #[test]
    fn prefix_preflight_is_architecture_independent_and_syntax_only() {
        assert_eq!(HX512_INLINE_WIRE_MAX_PROOF_BYTES, 4_294_962_014);
        assert_eq!(HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES, 4_194_304);
        let fixture = TestOnlyFixture::new(0x0c, 19);
        let raw = fixture.raw();
        let prefix: &[u8; HX512_INLINE_PREFIX_BYTES] =
            raw[..HX512_INLINE_PREFIX_BYTES].try_into().unwrap();
        let shape = preflight_hx512_inline_prefix(fixture.context(), prefix).unwrap();
        assert_eq!(shape.proof_length(), 19);
        assert_eq!(shape.output_count(), 2);
        assert_eq!(shape.action_bytes() as usize, raw.len());

        let maximum_context = Hx512InlineTransportContext::new(
            &fixture.identity,
            HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES,
            HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
        )
        .unwrap();
        assert_eq!(maximum_context.maximum_action_bytes().unwrap(), 4_199_585);
        assert_eq!(
            Hx512InlineTransportContext::new(
                &fixture.identity,
                HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES + 1,
                HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
            ),
            Err(Hx512InlineTransportError::InvalidProofCap(
                HX512_INLINE_ABSOLUTE_MAX_PROOF_BYTES + 1
            ))
        );
    }

    #[test]
    fn malformed_lengths_reject_before_any_expensive_hook() {
        let fixture = TestOnlyFixture::new(0x0c, 19);
        let mut empty = fixture.raw();
        empty[HX512_INLINE_STATEMENT_BYTES..HX512_INLINE_PREFIX_BYTES]
            .copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &empty, &PanicIfCalledValidator,),
            Err(Hx512InlineTransportError::EmptyProof)
        );

        let mut trailing = fixture.raw();
        trailing.push(0);
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &trailing, &PanicIfCalledValidator,),
            Err(Hx512InlineTransportError::TrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn malformed_part_shapes_reject_before_any_expensive_hook() {
        let fixture = TestOnlyFixture::new(0x04, 19);
        assert_eq!(
            Hx512InlineAction::from_parts(
                fixture.context(),
                &fixture.statement,
                &fixture.proof,
                [None, None],
                &PanicIfCalledValidator,
            ),
            Err(Hx512InlineTransportError::MissingCiphertext(0))
        );
        assert_eq!(
            Hx512InlineAction::from_parts(
                fixture.context(),
                &fixture.statement,
                &fixture.proof,
                [Some(&fixture.ciphertexts[0]), Some(&fixture.ciphertexts[1]),],
                &PanicIfCalledValidator,
            ),
            Err(Hx512InlineTransportError::UnexpectedCiphertext(1))
        );
    }

    #[test]
    fn same_shape_proof_substitution_is_rejected_by_the_proof_verifier() {
        let fixture = TestOnlyFixture::new(0x0c, 29);
        let validator = TestOnlyValidator(&fixture);
        let mut counterfeit = fixture.raw();
        counterfeit[HX512_INLINE_PREFIX_BYTES] ^= 1;
        assert_eq!(
            validate_hx512_inline_syntax(fixture.context(), &counterfeit),
            validate_hx512_inline_syntax(fixture.context(), &fixture.raw())
        );
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &counterfeit, &validator),
            Err(Hx512InlineTransportError::ProofRejected)
        );
    }

    #[test]
    fn every_truncated_prefix_and_all_length_field_bit_mutations_fail() {
        let fixture = TestOnlyFixture::new(0x0c, 23);
        let validator = TestOnlyValidator(&fixture);
        let raw = fixture.raw();
        for prefix_length in 0..raw.len() {
            assert!(
                validate_hx512_inline_action(fixture.context(), &raw[..prefix_length], &validator)
                    .is_err(),
                "truncated prefix {prefix_length} unexpectedly passed"
            );
        }

        for byte_index in 0..HX512_INLINE_PROOF_LENGTH_BYTES {
            for bit in 0..8 {
                let mut mutated = raw.clone();
                mutated[HX512_INLINE_STATEMENT_BYTES + byte_index] ^= 1 << bit;
                assert!(
                    validate_hx512_inline_action(fixture.context(), &mutated, &validator).is_err(),
                    "proof-length byte {byte_index} bit {bit} unexpectedly passed"
                );
            }
        }

        let mut empty = raw;
        empty[HX512_INLINE_STATEMENT_BYTES..HX512_INLINE_PREFIX_BYTES]
            .copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &empty, &validator),
            Err(Hx512InlineTransportError::EmptyProof)
        );
    }

    #[test]
    fn trailing_bytes_and_every_mask_mutation_fail() {
        let fixture = TestOnlyFixture::new(0x05, 17);
        let validator = TestOnlyValidator(&fixture);
        let mut trailing = fixture.raw();
        trailing.push(0xa5);
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &trailing, &validator),
            Err(Hx512InlineTransportError::TrailingBytes { trailing: 1 })
        );

        let raw = fixture.raw();
        for high_nibble in 1u8..=0x0f {
            let mut mutated = raw.clone();
            mutated[HX512_INLINE_ACTIVITY_MASK_OFFSET] =
                (high_nibble << 4) | fixture.statement[HX512_INLINE_ACTIVITY_MASK_OFFSET];
            assert_eq!(
                validate_hx512_inline_action(fixture.context(), &mutated, &validator),
                Err(Hx512InlineTransportError::NonCanonicalActivityMask(
                    mutated[HX512_INLINE_ACTIVITY_MASK_OFFSET]
                ))
            );
        }

        for mutated_mask in 0u8..=u8::MAX {
            if mutated_mask == fixture.statement[HX512_INLINE_ACTIVITY_MASK_OFFSET] {
                continue;
            }
            let mut mutated = raw.clone();
            mutated[HX512_INLINE_ACTIVITY_MASK_OFFSET] = mutated_mask;
            assert!(
                validate_hx512_inline_action(fixture.context(), &mutated, &validator).is_err(),
                "activity-mask mutation {mutated_mask:#04x} unexpectedly passed"
            );
        }
    }

    #[test]
    fn every_ciphertext_byte_mutation_fails_closed() {
        let fixture = TestOnlyFixture::new(0x0c, 13);
        let validator = TestOnlyValidator(&fixture);
        let raw = fixture.raw();
        let first_ciphertext = HX512_INLINE_PREFIX_BYTES + fixture.proof.len();
        for slot in 0..HX512_INLINE_MAX_OUTPUTS {
            for byte_index in 0..HX512_INLINE_CIPHERTEXT_BYTES {
                let mut mutated = raw.clone();
                mutated[first_ciphertext + slot * HX512_INLINE_CIPHERTEXT_BYTES + byte_index] ^= 1;
                assert_eq!(
                    validate_hx512_inline_action(fixture.context(), &mutated, &validator),
                    Err(Hx512InlineTransportError::CiphertextRejected(slot)),
                    "ciphertext slot {slot} byte {byte_index} unexpectedly passed"
                );
            }
        }
    }

    #[test]
    fn identity_and_statement_validator_fail_closed() {
        let fixture = TestOnlyFixture::new(0x04, 11);
        let validator = TestOnlyValidator(&fixture);
        let raw = fixture.raw();

        for identity_index in [0, HX512_INLINE_IDENTITY_BYTES - 1] {
            let mut mutated = raw.clone();
            mutated[identity_index] ^= 1;
            assert_eq!(
                validate_hx512_inline_action(fixture.context(), &mutated, &validator),
                Err(Hx512InlineTransportError::IdentityMismatch {
                    first_difference: identity_index,
                })
            );
        }

        let mut mutated = raw;
        mutated[HX512_INLINE_ACTIVITY_MASK_OFFSET + 1] ^= 1;
        assert_eq!(
            validate_hx512_inline_action(fixture.context(), &mutated, &validator),
            Err(Hx512InlineTransportError::StatementRejected)
        );
    }

    #[test]
    fn every_stage_keeps_the_canonical_action_bytes_unchanged() {
        let fixture = TestOnlyFixture::new(0x0c, 29);
        let validator = TestOnlyValidator(&fixture);
        let canonical = fixture.raw();
        let stages = [
            Hx512InlineTransportStage::Wallet,
            Hx512InlineTransportStage::Rpc,
            Hx512InlineTransportStage::Relay,
            Hx512InlineTransportStage::Mempool,
            Hx512InlineTransportStage::Mining,
            Hx512InlineTransportStage::Block,
            Hx512InlineTransportStage::Restart,
            Hx512InlineTransportStage::Sync,
            Hx512InlineTransportStage::Reorg,
            Hx512InlineTransportStage::FreshNode,
        ];
        let mut observed = canonical.clone();
        for stage in stages {
            ensure_hx512_inline_stage_bytes(fixture.context(), &canonical, &observed, stage)
                .unwrap();
            observed = Hx512InlineAction::admit_exact(fixture.context(), &observed, &validator)
                .unwrap()
                .into_bytes();
            assert_eq!(observed, canonical);
        }

        observed[HX512_INLINE_PREFIX_BYTES] ^= 1;
        assert!(matches!(
            ensure_hx512_inline_stage_bytes(
                fixture.context(),
                &canonical,
                &observed,
                Hx512InlineTransportStage::FreshNode,
            ),
            Err(Hx512InlineTransportError::StageMismatch {
                stage: Hx512InlineTransportStage::FreshNode,
                first_difference: Some(HX512_INLINE_PREFIX_BYTES),
                ..
            })
        ));
    }

    #[test]
    fn missing_unexpected_ciphertexts_and_width_drift_fail() {
        let fixture = TestOnlyFixture::new(0x04, 7);
        let validator = TestOnlyValidator(&fixture);
        assert_eq!(
            Hx512InlineAction::from_parts(
                fixture.context(),
                &fixture.statement,
                &fixture.proof,
                [None, None],
                &validator,
            ),
            Err(Hx512InlineTransportError::MissingCiphertext(0))
        );
        assert_eq!(
            Hx512InlineAction::from_parts(
                fixture.context(),
                &fixture.statement,
                &fixture.proof,
                [Some(&fixture.ciphertexts[0]), Some(&fixture.ciphertexts[1])],
                &validator,
            ),
            Err(Hx512InlineTransportError::UnexpectedCiphertext(1))
        );
        assert_eq!(
            Hx512InlineTransportContext::new(
                &fixture.identity,
                TEST_ONLY_PROOF_CAP,
                HX512_INLINE_STABLECOIN_PUBLIC_BYTES + 1,
            ),
            Err(Hx512InlineTransportError::StablecoinPublicWidth {
                observed: HX512_INLINE_STABLECOIN_PUBLIC_BYTES + 1,
                expected: HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
            })
        );
        assert_eq!(
            Hx512InlineTransportContext::new(
                &fixture.identity,
                0,
                HX512_INLINE_STABLECOIN_PUBLIC_BYTES,
            ),
            Err(Hx512InlineTransportError::InvalidProofCap(0))
        );
    }

    #[test]
    fn inactive_self_contained_policy_is_explicit() {
        assert!(!HX512_INLINE_PRODUCTION_ADMISSION_ENABLED);
        assert!(!HX512_INLINE_SIDECAR_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_AGGREGATE_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_RECEIPT_VALIDITY_ALLOWED);
        assert!(!HX512_INLINE_CACHE_VALIDITY_ALLOWED);
    }
}
