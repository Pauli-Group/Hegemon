use super::*;
use crate::private_spend::circuit::{
    constrain_policy_secret, constrain_release_bytes, constrain_release_mode, PolicyWires,
};
use crate::smallwood_poseidon2_v8_hash_schedule::{
    SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN as NULLIFIER,
    SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN as SINGLE,
};
use crate::{
    smallwood_engine::SmallwoodArithmetization,
    smallwood_htlc::circuit::{
        boolean, equal, input, nonzero, range, select, HtlcAdapter, HtlcGeometry, Scope, Word,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::PrimeCharacteristicRing;
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG},
    poseidon2_width16::{poseidon2_width16_compress14_ring, poseidon2_width16_sponge_ring},
    stablecoin_poseidon2_v8::STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
};

fn c(value: u64) -> Word {
    Word::from_u64(value)
}
fn arr<const N: usize>() -> [Word; N] {
    core::array::from_fn(|_| input())
}
fn gate(active: Word, left: Word, right: Word) {
    equal(active * (left - right), Word::ZERO)
}
fn gates<const N: usize>(active: Word, left: [Word; N], right: [Word; N]) {
    for index in 0..N {
        gate(active, left[index], right[index]);
    }
}
fn pad(active: Word, words: &[Word]) {
    for &word in words {
        gate(Word::ONE - active, word, Word::ZERO);
    }
}
fn nz(active: Word, word: Word) {
    nonzero(Word::ONE - active + active * word);
}
fn hash(domain: u64, words: &[Word]) -> Result<DigestWords, TransactionCircuitError> {
    poseidon2_width16_sponge_ring(domain, words).map_err(|_| error("asset circuit hash shape"))
}
type DigestWords = [Word; 7];
fn key7(key: [Word; 5]) -> DigestWords {
    [
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        Word::ZERO,
        Word::ZERO,
    ]
}
fn owner(note: &[Word; 18]) -> DigestWords {
    [
        note[14], note[15], note[16], note[17], note[10], note[11], note[12],
    ]
}

struct InputWords {
    occupied: Word,
    legacy: Word,
    note: [Word; 18],
    position: Word,
    siblings: [DigestWords; 32],
    key: [Word; 5],
    dummy: [Word; 5],
}
impl InputWords {
    fn new() -> Self {
        Self {
            occupied: input(),
            legacy: input(),
            note: arr(),
            position: input(),
            siblings: core::array::from_fn(|_| arr()),
            key: arr(),
            dummy: arr(),
        }
    }
}
struct CredentialWords {
    index: Word,
    expires: Word,
    siblings: Vec<DigestWords>,
}

struct AssetPolicyWords {
    create: Word,
    spend: Word,
    input: PolicyWires,
    selected: [Word; 2],
    input_owner: DigestWords,
    output_owner: DigestWords,
}
impl AssetPolicyWords {
    fn new(p: &[Word; PUBLIC_WORDS], occupied: Word) -> Result<Self, TransactionCircuitError> {
        let create = input();
        let spend = input();
        let policy_input = PolicyWires::new();
        let policy_output = PolicyWires::new();
        let selected: [Word; 2] = arr();
        let secret: [Word; 256] = arr();
        boolean(create);
        boolean(spend);
        gate(spend, occupied, Word::ONE);
        let input_owner = policy_input.constrain_owner(spend, &p[..8], p[types::ASSET])?;
        let output_owner = policy_output.constrain_owner(create, &p[..8], p[types::ASSET])?;
        let (required, release) =
            policy_input.constrain_selection(spend, selected, p[types::HEIGHT]);
        constrain_policy_secret(required, secret);
        constrain_release_mode(
            p[types::SECRET_RELEASE],
            &p[types::RELEASED_SECRET..],
            release,
        );
        constrain_release_bytes(
            p[types::SECRET_RELEASE],
            &p[types::RELEASED_SECRET..],
            secret,
        );
        policy_input.constrain_hash(selected, crate::smallwood_htlc::sha(secret));
        Ok(Self {
            create,
            spend,
            input: policy_input,
            selected,
            input_owner,
            output_owner,
        })
    }
}

pub struct AssetSpendAdapter {
    inner: HtlcAdapter,
}
impl AssetSpendAdapter {
    pub fn from_public(public: &AssetSpendPublic) -> Result<Self, TransactionCircuitError> {
        public.validate_structure()?;
        let words = public.words();
        let depth = public.credential_depth;
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = arr();
        for &word in &p[..16] {
            range(word, 32);
        }
        range(p[types::HEIGHT], 48);
        // H+12 is below Goldilocks. Each always-active output constrains both
        // expiry and expiry-(H+12) to 48 bits below; hence H+12 <= expiry <2^48,
        // which also enforces no 48-bit wrap without a redundant range gadget.
        // Policy not_before checks intentionally continue to use H itself.
        let credential_horizon = p[types::HEIGHT] + c(ASSET_REFERENCE_WINDOW);
        range(p[types::ASSET], 32);
        nonzero(p[types::ASSET]);
        range(p[types::POLICY_VERSION], 32);
        equal(p[types::CREDENTIAL_DEPTH], c(u64::from(depth)));
        equal(p[types::FROZEN], Word::ZERO);
        boolean(p[types::MINT_ENABLED]);
        range(p[types::MAGNITUDE], 56);
        range(p[types::FEE], 56);
        for &word in &p[types::CIPHERTEXTS..types::POLICY_MODE] {
            range(word, 32);
        }

        equal(p[types::POLICY_MODE], c(u64::from(public.policy_mode)));
        if public.policy_mode == 0 {
            for &word in &p[types::SECRET_RELEASE..] {
                equal(word, Word::ZERO);
            }
        }
        let modes: [Word; 3] = arr();
        for &mode in &modes {
            boolean(mode);
        }
        let [transfer, mint, burn] = modes;
        equal(transfer + mint + burn, Word::ONE);
        equal(p[types::OPERATION], mint + c(2) * burn);
        gate(transfer, p[types::MAGNITUDE], Word::ZERO);
        nz(mint + burn, p[types::MAGNITUDE]);
        gate(mint, p[types::MINT_ENABLED], Word::ONE);

        let inputs: [InputWords; 2] = core::array::from_fn(|_| InputWords::new());
        let outputs: [[Word; 18]; 3] = core::array::from_fn(|_| arr());
        let authorities: [DigestWords; 3] = core::array::from_fn(|_| arr());
        let credentials: [CredentialWords; 3] = core::array::from_fn(|_| CredentialWords {
            index: input(),
            expires: input(),
            siblings: (0..depth).map(|_| arr()).collect(),
        });
        let issuer: DigestWords = arr();
        let issuer_nonzero: DigestWords = arr();
        let policies = if public.policy_mode == 1 {
            Some(AssetPolicyWords::new(&p, inputs[0].occupied)?)
        } else {
            None
        };
        let policy_spend = policies.as_ref().map_or(Word::ZERO, |policy| policy.spend);
        let policy_create = policies.as_ref().map_or(Word::ZERO, |policy| policy.create);

        equal(inputs[0].occupied, Word::ONE - mint);
        equal(inputs[0].legacy, Word::ZERO);
        equal(inputs[1].occupied, Word::ONE);
        let mut input_authorities = [[Word::ZERO; 7]; 2];
        for slot in 0..2 {
            let note = &inputs[slot];
            boolean(note.occupied);
            boolean(note.legacy);
            range(note.note[0], 56);
            if slot == 0 {
                gate(note.occupied, note.note[1], p[types::ASSET]);
            } else {
                equal(note.note[1], Word::ZERO);
            }
            pad(note.occupied, &note.note);
            pad(note.occupied, &[note.position]);
            for sibling in note.siblings {
                pad(note.occupied, &sibling);
            }
            pad(note.occupied, &note.key);
            pad(Word::ONE - note.occupied, &note.dummy);
            nz(note.occupied, note.key[0]);
            nz(Word::ONE - note.occupied, note.dummy[0]);
            let authority = hash(SINGLE, &key7(note.key))?;
            input_authorities[slot] = if slot == 0 {
                policies.as_ref().map_or(authority, |policy| {
                    core::array::from_fn(|index| {
                        select(policy.spend, authority[index], policy.input_owner[index])
                    })
                })
            } else {
                authority
            };
            let ordinary = hash(crate::private_spend::ORDINARY_OWNER_DOMAIN, &authority)?;
            gates(
                note.occupied
                    * if slot == 0 {
                        Word::ONE - policy_spend
                    } else {
                        Word::ONE
                    },
                owner(&note.note),
                core::array::from_fn(|index| {
                    select(note.legacy, ordinary[index], authority[index])
                }),
            );
            if slot == 0 {
                if let Some(policy) = &policies {
                    gates(policy.spend, owner(&note.note), policy.input_owner);
                    policy.input.constrain_authority(policy.selected, authority);
                }
            }
            let directions = range(note.position, 32);
            let mut root = hash(NOTE_DOMAIN_TAG, &note.note)?;
            for level in 0..32 {
                let sibling = note.siblings[level];
                let left = core::array::from_fn(|index| {
                    select(directions[level], root[index], sibling[index])
                });
                let right = core::array::from_fn(|index| {
                    select(directions[level], sibling[index], root[index])
                });
                root = poseidon2_width16_compress14_ring(MERKLE_DOMAIN_TAG, &left, &right);
            }
            gates(
                note.occupied,
                root,
                p[types::NOTE_ROOT..types::NOTE_ROOT + 7]
                    .try_into()
                    .unwrap(),
            );
            let nullifier_key = if slot == 0 {
                policies.as_ref().map_or(note.key, |policy| {
                    let shared = policy.input.nullifier_key();
                    core::array::from_fn(|index| {
                        select(policy.spend, note.key[index], shared[index])
                    })
                })
            } else {
                note.key
            };
            let mut preimage = key7(nullifier_key).to_vec();
            preimage.push(note.position);
            preimage.extend_from_slice(&note.note[6..10]);
            let real = hash(NULLIFIER, &preimage)?;
            let mut dummy_words = p[..8].to_vec();
            dummy_words.extend(note.dummy);
            let dummy = hash(DUMMY_NULLIFIER_DOMAIN, &dummy_words)?;
            gates::<7>(
                Word::ONE,
                core::array::from_fn(|index| select(note.occupied, dummy[index], real[index])),
                p[types::NULLIFIERS + 7 * slot..types::NULLIFIERS + 7 * (slot + 1)]
                    .try_into()
                    .unwrap(),
            );
        }
        for slot in 0..3 {
            let note = outputs[slot];
            range(note[0], 56);
            equal(
                note[1],
                if slot < 2 {
                    p[types::ASSET]
                } else {
                    Word::ZERO
                },
            );
            let ordinary_output = if slot == 0 {
                Word::ONE - policy_create
            } else {
                Word::ONE
            };
            pad(ordinary_output, &authorities[slot]);
            gates(
                ordinary_output,
                owner(&note),
                hash(
                    crate::private_spend::ORDINARY_OWNER_DOMAIN,
                    &authorities[slot],
                )?,
            );
            if slot == 0 {
                if let Some(policy) = &policies {
                    gates(policy.create, owner(&note), policy.output_owner);
                }
            }
            gates(
                Word::ONE,
                hash(NOTE_DOMAIN_TAG, &note)?,
                p[types::COMMITMENTS + 7 * slot..types::COMMITMENTS + 7 * (slot + 1)]
                    .try_into()
                    .unwrap(),
            );
        }
        // Each term is at most56 bits; either side is below2^58 and hence below
        // Goldilocks. These field equations therefore express integer balances.
        equal(
            inputs[0].note[0] + mint * p[types::MAGNITUDE],
            outputs[0][0] + outputs[1][0] + burn * p[types::MAGNITUDE],
        );
        equal(inputs[1].note[0], outputs[2][0] + p[types::FEE]);

        // Mint has no holder input. Both asset outputs always require a leaf,
        // even when their value is zero or they return change to the sender.
        for slot in 0..3 {
            let active = if slot == 0 {
                Word::ONE - mint
            } else {
                Word::ONE
            };
            let credential = &credentials[slot];
            pad(active, &[credential.index, credential.expires]);
            for sibling in &credential.siblings {
                pad(active, sibling);
            }
            let directions = range(credential.index, depth);
            range(credential.expires, 48);
            // For active slots, a negative difference is a Goldilocks residue
            // above 2^48; the range proof therefore enforces expiry >= H+12.
            range(active * (credential.expires - credential_horizon), 48);
            let (recipient, authority) = if slot == 0 {
                (&inputs[0].note[2..6], input_authorities[0])
            } else {
                let output_slot = slot - 1;
                let authority = if output_slot == 0 {
                    policies.as_ref().map_or(authorities[0], |policy| {
                        core::array::from_fn(|index| {
                            select(
                                policy.create,
                                authorities[0][index],
                                policy.output_owner[index],
                            )
                        })
                    })
                } else {
                    authorities[output_slot]
                };
                (&outputs[output_slot][2..6], authority)
            };
            let mut leaf_words = vec![p[types::ASSET], p[types::POLICY_VERSION]];
            leaf_words.extend_from_slice(recipient);
            leaf_words.extend(authority);
            leaf_words.push(credential.expires);
            let mut root = hash(CREDENTIAL_LEAF_DOMAIN, &leaf_words)?;
            for (level, sibling) in credential.siblings.iter().enumerate() {
                let left = core::array::from_fn(|index| {
                    select(directions[level], root[index], sibling[index])
                });
                let right = core::array::from_fn(|index| {
                    select(directions[level], sibling[index], root[index])
                });
                root = poseidon2_width16_compress14_ring(
                    CREDENTIAL_NODE_DOMAIN + level as u64,
                    &left,
                    &right,
                );
            }
            gates(
                active,
                root,
                p[types::CREDENTIAL_ROOT..types::CREDENTIAL_ROOT + 7]
                    .try_into()
                    .unwrap(),
            );
        }
        pad(mint, &issuer);
        for &bit in &issuer_nonzero {
            boolean(bit);
        }
        equal(issuer_nonzero.iter().copied().sum(), mint);
        nz(
            mint,
            issuer
                .iter()
                .zip(issuer_nonzero)
                .map(|(word, bit)| *word * bit)
                .sum(),
        );
        let issuer_binding = [
            p[types::ASSET],
            p[types::POLICY_VERSION],
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
        ];
        gates(
            mint,
            poseidon2_width16_compress14_ring(
                STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
                &issuer,
                &issuer_binding,
            ),
            p[types::ISSUER..types::ISSUER + 7].try_into().unwrap(),
        );

        let mut inner = HtlcAdapter::from_graph(scope.finish());
        for (wire, value) in p.iter().copied().zip(words) {
            inner.bind_public(wire, value);
        }
        // The existing independent source-lowering certificate targets the
        // native relation. It is deliberately not claimed for this asset graph.
        Ok(Self { inner })
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        self.inner.geometry()
    }
    pub fn lower(
        &self,
        public: &AssetSpendPublic,
        witness: &AssetSpendWitness,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        let mut inputs = public.words().to_vec();
        inputs.extend(witness.words(public)?);
        self.inner.evaluate(&inputs)
    }
    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(witness)
    }
}
pub fn compile(
    public: &AssetSpendPublic,
    witness: &AssetSpendWitness,
) -> Result<(AssetSpendAdapter, Vec<u64>), TransactionCircuitError> {
    let adapter = AssetSpendAdapter::from_public(public)?;
    let packed = adapter.lower(public, witness)?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
impl SmallwoodConstraintAdapter for AssetSpendAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64AssetSpendSha512Smze
    }
    fn row_count(&self) -> usize {
        self.inner.row_count()
    }
    fn packing_factor(&self) -> usize {
        64
    }
    fn constraint_degree(&self) -> usize {
        2
    }
    fn linear_constraint_count(&self) -> usize {
        self.inner.linear_constraint_count()
    }
    fn constraint_count(&self) -> usize {
        self.inner.constraint_count()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        self.inner.linear_constraint_offsets()
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        self.inner.linear_constraint_indices()
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.inner.linear_constraint_coefficients()
    }
    fn linear_targets(&self) -> &[u64] {
        self.inner.linear_targets()
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        point: u64,
        rows: &'a [u64],
        auxiliary: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        self.inner.nonlinear_eval_view(point, rows, auxiliary)
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        self.inner.compute_constraints_u64(view, out)
    }
}
