use super::*;
use crate::smallwood_engine::SmallwoodArithmetization;
use crate::smallwood_htlc::circuit::{
    boolean, equal, input, nonzero, range, record_poseidon2, select, sha256_compact, HtlcAdapter,
    HtlcGeometry, PrivateSpendArithmeticRoles, Scope, Word,
};
use crate::smallwood_poseidon2_v8_hash_schedule::{
    SMALLWOOD_POSEIDON2_V8_AUTH_MODE_BIND_DOMAIN as MODE_BIND,
    SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN as VALUE_LOCK,
    SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN as NULLIFIER,
    SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN as SINGLE,
};
use crate::smallwood_poseidon2_v8_types::SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN as POLICY;
use crate::smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView};
use hegemon_field::PrimeCharacteristicRing;
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG},
    poseidon2_width16::{
        poseidon2_width16_compress14_with_permutation_ring,
        poseidon2_width16_sponge_with_permutation_ring,
    },
};
fn poseidon2_width16_compress14_ring(
    domain: u64,
    left: &[Word; 7],
    right: &[Word; 7],
) -> [Word; 7] {
    poseidon2_width16_compress14_with_permutation_ring(domain, left, right, |state| {
        *state = record_poseidon2(*state);
    })
}
fn hash(domain: u64, w: &[Word]) -> Result<[Word; 7], TransactionCircuitError> {
    poseidon2_width16_sponge_with_permutation_ring(domain, w, |state| {
        *state = record_poseidon2(*state);
    })
    .map_err(|_| error("private spend hash shape"))
}
/// Fixed six-permutation schedule. The caller constrains selector to a bit.
/// At selector=0 this is the exact44-word treasury policy sponge; at1 it is
/// the exact48-word bounded input-policy sponge. Both modes keep private
/// topology, domains, encoded lengths and final-block delimiters intact.
fn shared_input_policy_root<R: PrimeCharacteristicRing>(
    selector: R,
    treasury_words: &[R; 44],
    policy_words: &[R; 48],
    mut permute: impl FnMut(&mut [R; 16]),
) -> [R; 7] {
    use transaction_core::poseidon2_width16::{
        POSEIDON2_WIDTH16_SPONGE_MODE_MARKER, POSEIDON2_WIDTH16_SUITE_MARKER,
    };
    let choose = |a: R, b: R| a + selector * (b - a);
    let mut state = [R::ZERO; 16];
    state[8] = choose(
        R::from_u64(POLICY),
        R::from_u64(transaction_core::bounded_policy::POLICY_DOMAIN),
    );
    state[9] = choose(R::from_u64(44), R::from_u64(48));
    state[10] = R::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
    state[15] = R::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
    for block in 0..6 {
        for lane in 0..8 {
            let index = block * 8 + lane;
            let treasury = if index < 44 {
                treasury_words[index]
            } else {
                R::ZERO
            };
            state[lane] += choose(treasury, policy_words[index]);
        }
        if block == 5 {
            state[11] += R::ONE;
        }
        permute(&mut state);
    }
    state[..7].try_into().ok().expect("fixed seven-word digest")
}

fn c(v: u64) -> Word {
    Word::from_u64(v)
}
fn gate(g: Word, a: Word, b: Word) {
    equal(g * (a - b), Word::ZERO)
}
fn gates<const N: usize>(g: Word, a: [Word; N], b: [Word; N]) {
    for i in 0..N {
        gate(g, a[i], b[i]);
    }
}
fn nz(g: Word, x: Word) {
    nonzero(Word::ONE - g + g * x)
}
fn pad(g: Word, words: &[Word]) {
    for &w in words {
        gate(Word::ONE - g, w, Word::ZERO)
    }
}
fn owner(n: &[Word; 18]) -> [Word; 7] {
    [n[14], n[15], n[16], n[17], n[10], n[11], n[12]]
}
fn key7(k: [Word; 5]) -> [Word; 7] {
    [k[0], k[1], k[2], k[3], k[4], Word::ZERO, Word::ZERO]
}
fn bound(k: [Word; 5], d: [Word; 7]) -> [Word; 7] {
    poseidon2_width16_compress14_ring(MODE_BIND, &key7(k), &d)
}
fn ordinary(d: [Word; 7]) -> Result<[Word; 7], TransactionCircuitError> {
    hash(ORDINARY_OWNER_DOMAIN, &d)
}
fn arr<const N: usize>() -> [Word; N] {
    core::array::from_fn(|_| input())
}
struct In {
    occupied: Word,
    legacy: Word,
    note: [Word; 18],
    position: Word,
    siblings: [[Word; 7]; 32],
    key: [Word; 5],
    dummy: [Word; 5],
}
impl In {
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

struct BranchWires {
    enabled: Word,
    authority: [Word; 7],
    not_before: Word,
    hash_required: Word,
    hashlock: [Word; 8],
    release_secret: Word,
    nonzero_limb: [Word; 7],
}
impl BranchWires {
    fn new() -> Self {
        Self {
            enabled: input(),
            authority: arr(),
            not_before: input(),
            hash_required: input(),
            hashlock: arr(),
            release_secret: input(),
            nonzero_limb: arr(),
        }
    }
    fn words(&self) -> Vec<Word> {
        let mut w = vec![self.enabled];
        w.extend(self.authority);
        w.extend([self.not_before, self.hash_required]);
        w.extend(self.hashlock);
        w.push(self.release_secret);
        w
    }
}
pub(crate) struct PolicyWires {
    key: [Word; 5],
    branches: [BranchWires; 2],
}
impl PolicyWires {
    pub(crate) fn new() -> Self {
        Self {
            key: arr(),
            branches: core::array::from_fn(|_| BranchWires::new()),
        }
    }
    pub(crate) fn constrain_owner(
        &self,
        active: Word,
        chain: &[Word],
        asset: Word,
    ) -> Result<[Word; 7], TransactionCircuitError> {
        use transaction_core::bounded_policy::{OWNER_DOMAIN, POLICY_DOMAIN};
        let words = self.constrain_descriptor(active, chain, asset)?;
        Ok(poseidon2_width16_compress14_ring(
            OWNER_DOMAIN,
            &key7(self.key),
            &hash(POLICY_DOMAIN, &words)?,
        ))
    }
    /// Keep every descriptor/range predicate independently of hash sharing.
    fn constrain_descriptor(
        &self,
        active: Word,
        chain: &[Word],
        asset: Word,
    ) -> Result<Vec<Word>, TransactionCircuitError> {
        use transaction_core::bounded_policy::VERSION;
        pad(active, &self.key);
        nz(active, self.key[0]);
        gate(active, self.branches[0].enabled, Word::ONE);
        let mut words = chain.to_vec();
        words.extend([asset, c(VERSION)]); // exact asset and shared policy version
        for b in &self.branches {
            let descriptor = b.words();
            pad(active, &descriptor);
            boolean(b.enabled);
            boolean(b.hash_required);
            boolean(b.release_secret);
            pad(b.enabled, &descriptor[1..]);
            range(b.not_before, 48);
            for &word in &b.hashlock {
                range(word, 32);
            }
            pad(b.hash_required, &b.hashlock);
            gate(b.release_secret, b.hash_required, Word::ONE);
            for &bit in &b.nonzero_limb {
                boolean(bit);
            }
            equal(b.nonzero_limb.iter().copied().sum(), b.enabled);
            let chosen: Word = (0..7).map(|i| b.nonzero_limb[i] * b.authority[i]).sum();
            nz(b.enabled, chosen);
            words.extend(descriptor);
        }
        Ok(words)
    }

    pub(crate) fn nullifier_key(&self) -> [Word; 5] {
        self.key
    }
    /// The same two-branch selector, maturity and hash/disclosure predicates
    /// used by the native relation. Asset callers supply the authenticated height.
    pub(crate) fn constrain_selection(
        &self,
        spend: Word,
        selected: [Word; 2],
        height: Word,
    ) -> (Word, Word) {
        for &bit in &selected {
            boolean(bit);
        }
        equal(selected.iter().copied().sum(), spend);
        let mut hash_required = Word::ZERO;
        let mut release = Word::ZERO;
        for i in 0..2 {
            let b = &self.branches[i];
            gate(selected[i], b.enabled, Word::ONE);
            range(selected[i] * (height - b.not_before), 48);
            hash_required = hash_required + selected[i] * b.hash_required;
            release = release + selected[i] * b.release_secret;
        }
        (hash_required, release)
    }
    pub(crate) fn constrain_authority(&self, selected: [Word; 2], who: [Word; 7]) {
        for branch in 0..2 {
            gates(selected[branch], who, self.branches[branch].authority);
        }
    }
    pub(crate) fn constrain_hash(&self, selected: [Word; 2], digest: [Word; 8]) {
        for i in 0..2 {
            gates(
                selected[i] * self.branches[i].hash_required,
                digest,
                self.branches[i].hashlock,
            );
        }
    }
}

pub(crate) fn constrain_policy_secret(required: Word, secret: [Word; 256]) {
    pad(required, &secret);
    for &bit in &secret {
        boolean(bit);
    }
}
pub(crate) fn constrain_release_mode(flag: Word, released: &[Word], expected: Word) {
    boolean(flag);
    pad(flag, released);
    equal(flag, expected);
}
pub(crate) fn constrain_release_bytes(flag: Word, released: &[Word], secret: [Word; 256]) {
    assert_eq!(released.len(), 8);
    for i in 0..8 {
        let mut word = Word::ZERO;
        for bit in 0..32 {
            word = word + secret[32 * i + bit] * c(1u64 << bit);
        }
        gate(flag, released[i], word);
    }
}

pub struct PrivateSpendAdapter {
    inner: HtlcAdapter,
}
impl PrivateSpendAdapter {
    pub fn from_public(public: &PrivateSpendPublic) -> Result<Self, TransactionCircuitError> {
        let words = public.words();
        if words
            .iter()
            .any(|x| *x >= hegemon_field::GOLDILOCKS_MODULUS)
            || public.chain_id == [0; 32]
            || public.reference_parent_height >= (1 << 48)
            || public.fee >= (1 << 56)
            || public.nullifiers[0] == public.nullifiers[1]
            || public.secret_release > 1
            || (public.secret_release == 0 && public.released_secret != [0; 32])
        {
            return Err(error("private spend public shape"));
        }
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = arr();
        for &w in &p[..16] {
            range(w, 32);
        }
        range(p[16], 48);
        range(p[24], 56);
        for &w in &p[53..] {
            range(w, 32);
        }
        let modes: [Word; 6] = arr();
        for &s in &modes {
            boolean(s)
        }
        let mut selector_prefix = [Word::ZERO; 7];
        for i in 0..6 {
            selector_prefix[i + 1] = selector_prefix[i] + modes[i];
        }
        equal(selector_prefix[6], Word::ONE);
        let [ordinary_mode, approval, final_mode, lock, claim, refund] = modes;
        let treasury = approval + final_mode;
        let htlc = lock + claim + refund;
        let unlocked = claim + refund;
        let ins: [In; 2] = core::array::from_fn(|_| In::new());
        let outs: [[Word; 18]; 2] = core::array::from_fn(|_| arr());
        let recipients: [[Word; 7]; 2] = core::array::from_fn(|_| arr());
        let tk: [Word; 5] = arr();
        let tags: [[Word; 7]; 3] = core::array::from_fn(|_| arr());
        let nonzero_limb: [[Word; 7]; 3] = core::array::from_fn(|_| arr());
        let distinct_limb: [[Word; 7]; 3] = core::array::from_fn(|_| arr());
        let approved: [Word; 3] = arr();
        let signer: [Word; 3] = arr();
        let intent: [Word; INTENT_WORDS] = arr();
        let hk: [Word; 5] = arr();
        let hashlock: [Word; 8] = arr();
        let ca: [Word; 7] = arr();
        let ra: [Word; 7] = arr();
        let cr: [Word; 4] = arr();
        let rr: [Word; 4] = arr();
        let timeout = input();
        let secret: [Word; 256] = arr();
        let htlc_release = input();
        let policy_create = input();
        let policy_spend = input();
        let policy_input = PolicyWires::new();
        let policy_output = PolicyWires::new();
        let policy_selected: [Word; 2] = arr();
        let policy_secret: [Word; 256] = arr();
        boolean(htlc_release);
        pad(htlc, &[htlc_release]);
        boolean(policy_create);
        boolean(policy_spend);
        gate(policy_create, ordinary_mode, Word::ONE);
        gate(policy_spend, ordinary_mode, Word::ONE);
        // The private modes are one-hot: treasury and policy_spend cannot
        // coexist. Preserve both descriptor constraints but share their six
        // sponge permutations. Inactive root consumers stay gated below.
        gate(treasury, policy_spend, Word::ZERO);
        let mut treasury_policy = vec![c(2), c(3)];
        for tag in tags {
            treasury_policy.extend(tag);
        }
        treasury_policy.extend([Word::ZERO; 21]);
        let input_descriptor =
            policy_input.constrain_descriptor(policy_spend, &p[..8], Word::ZERO)?;
        let treasury_policy: [Word; 44] = treasury_policy
            .try_into()
            .map_err(|_| error("treasury policy shape"))?;
        let input_descriptor: [Word; 48] = input_descriptor
            .try_into()
            .map_err(|_| error("bounded policy descriptor shape"))?;
        let root =
            shared_input_policy_root(policy_spend, &treasury_policy, &input_descriptor, |state| {
                *state = record_poseidon2(*state);
            });
        let input_policy_owner = poseidon2_width16_compress14_ring(
            transaction_core::bounded_policy::OWNER_DOMAIN,
            &key7(policy_input.key),
            &root,
        );
        let output_policy_owner =
            policy_output.constrain_owner(policy_create, &p[..8], Word::ZERO)?;
        let (policy_hash_required, policy_release) =
            policy_input.constrain_selection(policy_spend, policy_selected, p[16]);
        constrain_policy_secret(policy_hash_required, policy_secret);
        constrain_release_mode(p[77], &p[78..86], claim * htlc_release + policy_release);
        // Modes are disjoint: reuse one SHA256 evaluation for HTLC and policy.
        let common_secret: [Word; 256] = core::array::from_fn(|i| secret[i] + policy_secret[i]);
        constrain_release_bytes(p[77], &p[78..86], common_secret);
        pad(treasury, &tk);
        for t in tags {
            pad(treasury, &t)
        }
        pad(treasury, &approved);
        pad(approval, &signer);
        pad(treasury, &intent);
        pad(htlc, &hk);
        pad(htlc, &hashlock);
        pad(htlc, &ca);
        pad(htlc, &ra);
        pad(htlc, &cr);
        pad(htlc, &rr);
        pad(htlc, &[timeout]);
        pad(claim, &secret);
        for &b in &secret {
            boolean(b)
        }
        for &w in &hashlock {
            range(w, 32);
        }
        range(timeout, 48);
        nz(treasury, tk[0]);
        nz(htlc, hk[0]);
        let mut pair = 0;
        for i in 0..3 {
            boolean(approved[i]);
            boolean(signer[i]);
            for &b in &nonzero_limb[i] {
                boolean(b);
            }
            equal(nonzero_limb[i].iter().copied().sum(), treasury);
            let selected: Word = (0..7).map(|j| nonzero_limb[i][j] * tags[i][j]).sum();
            nz(treasury, selected);
            for j in 0..i {
                for &b in &distinct_limb[pair] {
                    boolean(b);
                }
                equal(distinct_limb[pair].iter().copied().sum(), treasury);
                let selected: Word = (0..7)
                    .map(|k| distinct_limb[pair][k] * (tags[i][k] - tags[j][k]))
                    .sum();
                nz(treasury, selected);
                pair += 1;
            }
        }
        gate(approval, signer.iter().copied().sum(), Word::ONE);
        let count: Word = approved.iter().copied().sum();
        let next: [Word; 3] = core::array::from_fn(|i| approved[i] + signer[i]);
        for i in 0..3 {
            gate(approval, approved[i] * signer[i], Word::ZERO);
        }
        let intent_digest = hash(INTENT_DOMAIN, &intent)?;
        let accumulator = |bits: [Word; 3]| -> Result<[Word; 7], TransactionCircuitError> {
            let mut w = root.to_vec();
            w.extend(intent_digest);
            w.extend([c(2), c(3), bits.iter().copied().sum()]);
            w.extend(bits);
            w.extend([Word::ZERO; 3]);
            Ok(bound(tk, hash(ACCUMULATOR_DOMAIN, &w)?))
        };
        let acc = accumulator(approved)?;
        let next_acc = accumulator(next)?;
        let value_owner = bound(
            tk,
            poseidon2_width16_compress14_ring(VALUE_LOCK, &root, &[Word::ZERO; 7]),
        );
        gate(approval * (Word::ONE - ins[0].occupied), count, Word::ZERO);
        nz(approval * ins[0].occupied, count);
        gate(approval, ins[1].occupied, Word::ONE);
        gate(final_mode, ins[0].occupied, Word::ONE);
        gate(final_mode, ins[1].occupied, Word::ONE);
        range(final_mode * (count - c(2)), 1);
        let mut actual_intent = p[..8].to_vec();
        actual_intent.push(p[24]);
        actual_intent.extend_from_slice(&p[25..32]);
        actual_intent.extend_from_slice(&p[39..77]);
        for i in 0..INTENT_WORDS {
            gate(final_mode, intent[i], actual_intent[i]);
        }
        // Intent byte words are canonical even during private approval construction.
        for &w in &intent[..8] {
            range(w, 32);
        }
        range(intent[8], 56);
        for &w in &intent[30..] {
            range(w, 32);
        }
        let mut hp = p[..8].to_vec();
        hp.extend(hashlock);
        hp.extend(ca);
        hp.extend(ra);
        hp.extend(cr);
        hp.extend(rr);
        hp.push(timeout);
        let htlc_policy_digest = hash(HTLC_POLICY_DOMAIN, &hp)?;
        let private_locked =
            poseidon2_width16_compress14_ring(HTLC_OWNER_DOMAIN, &key7(hk), &htlc_policy_digest);
        let releasing_locked = poseidon2_width16_compress14_ring(
            HTLC_RELEASE_OWNER_DOMAIN,
            &key7(hk),
            &htlc_policy_digest,
        );
        let locked: [Word; 7] =
            core::array::from_fn(|i| select(htlc_release, private_locked[i], releasing_locked[i]));
        let digest = sha256_compact(common_secret);
        gates(claim, digest, hashlock);
        policy_input.constrain_hash(policy_selected, digest);
        gate(policy_spend, ins[0].occupied, Word::ONE);
        // Integer bounds are below p/2; no modular-wrap witness can satisfy these ranges.
        let lock_difference = timeout - p[16];
        let lock_shifted = lock_difference - c(14);
        let lock_slack = lock * lock_shifted;
        range(lock_slack, 48);
        let refund_difference = p[16] - timeout;
        let refund_slack = refund * refund_difference;
        range(refund_slack, 48);
        gate(lock + unlocked, ins[0].occupied, Word::ONE);
        let mut values = [Word::ZERO; 2];
        for i in 0..2 {
            let n = &ins[i];
            boolean(n.occupied);
            boolean(n.legacy);
            range(n.note[0], 56);
            equal(n.note[1], Word::ZERO);
            values[i] = n.note[0];
            pad(n.occupied, &n.note);
            pad(n.occupied, &[n.position]);
            for s in n.siblings {
                pad(n.occupied, &s)
            }
            pad(Word::ONE - n.occupied, &n.dummy);
            nz(Word::ONE - n.occupied, n.dummy[0]);
            let ord = if i == 0 {
                ordinary_mode - policy_spend + lock
            } else {
                ordinary_mode + approval + lock + unlocked
            };
            let ord_active = ord * n.occupied;
            let credential_use = ord_active
                + if i == 0 {
                    unlocked + policy_spend
                } else {
                    Word::ZERO
                };
            pad(credential_use, &n.key);
            pad(ord_active, &[n.legacy]);
            nz(credential_use, n.key[0]);
            let who = hash(SINGLE, &key7(n.key))?;
            let new_owner = ordinary(who)?;
            gates(
                ord_active,
                owner(&n.note),
                core::array::from_fn(|j| select(n.legacy, new_owner[j], who[j])),
            );
            if i == 0 {
                gates(claim, who, ca);
                gates(refund, who, ra);
                gates(approval * n.occupied, owner(&n.note), acc);
                gates(final_mode, owner(&n.note), value_owner);
                gates(unlocked, owner(&n.note), locked);
                gates(policy_spend, owner(&n.note), input_policy_owner);
                policy_input.constrain_authority(policy_selected, who);
                gate(approval, n.note[0], Word::ZERO);
            } else {
                gates(final_mode, owner(&n.note), acc);
                gate(final_mode, n.note[0], Word::ZERO);
                for j in 0..3 {
                    gates(approval * signer[j], who, tags[j]);
                }
            }
            let directions = range(n.position, 32);
            let mut mr = hash(NOTE_DOMAIN_TAG, &n.note)?;
            for level in 0..32 {
                let sibling = n.siblings[level];
                let left = core::array::from_fn(|j| select(directions[level], mr[j], sibling[j]));
                let right = core::array::from_fn(|j| select(directions[level], sibling[j], mr[j]));
                mr = poseidon2_width16_compress14_ring(MERKLE_DOMAIN_TAG, &left, &right);
            }
            gates(n.occupied, mr, p[17..24].try_into().unwrap());
            let policy_use = if i == 0 { treasury } else { final_mode };
            let hash_use = if i == 0 { unlocked } else { Word::ZERO };
            let selected: [Word; 5] = core::array::from_fn(|j| {
                ord * n.key[j]
                    + policy_use * tk[j]
                    + hash_use * hk[j]
                    + if i == 0 {
                        policy_spend * policy_input.key[j]
                    } else {
                        Word::ZERO
                    }
            });
            let mut pre = key7(selected).to_vec();
            pre.push(n.position);
            pre.extend_from_slice(&n.note[6..10]);
            let real = hash(NULLIFIER, &pre)?;
            let mut dp = p[..8].to_vec();
            dp.extend(n.dummy);
            let dummy = hash(DUMMY_NULLIFIER_DOMAIN, &dp)?;
            gates::<7>(
                Word::ONE,
                core::array::from_fn(|j| select(n.occupied, dummy[j], real[j])),
                p[25 + 7 * i..32 + 7 * i].try_into().unwrap(),
            );
        }
        for i in 0..2 {
            range(outs[i][0], 56);
            equal(outs[i][1], Word::ZERO);
            let normal = if i == 0 {
                Word::ONE - approval - lock - policy_create
            } else {
                Word::ONE
            };
            pad(normal, &recipients[i]);
            gates(normal, owner(&outs[i]), ordinary(recipients[i])?);
            if i == 0 {
                gates(approval, owner(&outs[0]), next_acc);
                gate(approval, outs[0][0], Word::ZERO);
                gates(lock, owner(&outs[0]), locked);
                gates(policy_create, owner(&outs[0]), output_policy_owner);
                for j in 0..4 {
                    gate(claim, outs[0][2 + j], cr[j]);
                    gate(refund, outs[0][2 + j], rr[j]);
                }
                gates(claim, recipients[0], ca);
                gates(refund, recipients[0], ra);
            }
            gates(
                Word::ONE,
                hash(NOTE_DOMAIN_TAG, &outs[i])?,
                p[39 + 7 * i..46 + 7 * i].try_into().unwrap(),
            );
        }
        let balance_left = values[0] + values[1];
        let balance_first = outs[0][0] + outs[1][0];
        let balance_right = balance_first + p[24];
        equal(balance_left, balance_right);
        // Locked value is delivered in full. Input1 funds fee/change; changing
        // the locked value allocation requires a new reviewed relation version.
        gate(unlocked, outs[0][0], values[0]);
        let arithmetic_roles = PrivateSpendArithmeticRoles {
            public: p[..77].try_into().unwrap(),
            modes,
            selector_prefix,
            values: [values[0], values[1], outs[0][0], outs[1][0], p[24]],
            balance: [balance_left, balance_first, balance_right],
            timeout,
            lock_steps: [lock_difference, lock_shifted, lock_slack],
            refund_steps: [refund_difference, refund_slack],
            intent,
            unlocked,
        };
        let mut inner = HtlcAdapter::from_graph_with_public_bindings(scope.finish(), &words);
        inner.require_private_spend_packed_poseidon_schedule()?;
        inner.require_private_spend_compact_sha_schedule()?;
        for (wire, target) in p.iter().copied().zip(words) {
            inner.bind_public(wire, target);
        }
        inner
            .check_source_lowering(&p, &words)
            .map_err(|_| error("private spend source lowering certificate mismatch"))?;
        inner
            .check_arithmetic_roles(&arithmetic_roles)
            .map_err(|_| error("private spend arithmetic topology mismatch"))?;
        Ok(Self { inner })
    }
    #[cfg(test)]
    pub(crate) fn adversarial_probe_indices(&self) -> Vec<usize> {
        self.inner.adversarial_probe_indices()
    }
    #[cfg(test)]
    pub(crate) fn lowering_census(&self) -> Vec<(&'static str, usize)> {
        self.inner.lowering_census()
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        self.inner.geometry()
    }
    pub fn verify_packed_witness(&self, packed: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(packed)
    }
    pub fn lower(
        &self,
        p: &PrivateSpendPublic,
        w: &PrivateSpendWitness,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        let mut inputs = p.words().to_vec();
        inputs.extend(w.words()?);
        self.inner.evaluate(&inputs)
    }
}
pub fn compile(
    p: &PrivateSpendPublic,
    w: &PrivateSpendWitness,
) -> Result<(PrivateSpendAdapter, Vec<u64>), TransactionCircuitError> {
    let a = PrivateSpendAdapter::from_public(p)?;
    let packed = a.lower(p, w)?;
    a.verify_packed_witness(&packed)?;
    Ok((a, packed))
}
impl SmallwoodConstraintAdapter for PrivateSpendAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64NativePrivateSpendSha512Smzd
    }
    fn row_count(&self) -> usize {
        self.inner.row_count()
    }
    fn packing_factor(&self) -> usize {
        64
    }
    fn constraint_degree(&self) -> usize {
        self.inner.constraint_degree()
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
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        self.inner
            .nonlinear_eval_view(eval_point, row_scalars, auxiliary_words)
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        self.inner.compute_constraints_u64(view, out)
    }
}

#[cfg(test)]
mod shared_policy_root_tests {
    use super::*;
    use transaction_core::poseidon2_width16::{
        poseidon2_width16_permutation_ring, poseidon2_width16_sponge_ring, Felt,
    };

    #[test]
    fn shared_policy_root_matches_both_native_sponges_with_fixed_geometry() {
        for seed in 0..16u64 {
            let treasury = core::array::from_fn(|i| Felt::from_u64(seed * 47 + i as u64));
            let policy = core::array::from_fn(|i| Felt::from_u64(seed * 53 + i as u64));
            for selected in 0..2u64 {
                let mut calls = 0;
                let got = shared_input_policy_root(
                    Felt::from_u64(selected),
                    &treasury,
                    &policy,
                    |state| {
                        calls += 1;
                        poseidon2_width16_permutation_ring(state);
                    },
                );
                let expected = if selected == 0 {
                    poseidon2_width16_sponge_ring(POLICY, &treasury).unwrap()
                } else {
                    poseidon2_width16_sponge_ring(
                        transaction_core::bounded_policy::POLICY_DOMAIN,
                        &policy,
                    )
                    .unwrap()
                };
                assert_eq!(got, expected);
                assert_eq!(calls, 6);
            }
        }
    }

    #[test]
    fn shared_policy_root_binds_domain_length_and_last_selected_word() {
        let treasury = core::array::from_fn(|i| Felt::from_u64(i as u64 + 1));
        let policy = core::array::from_fn(|i| Felt::from_u64(i as u64 + 101));
        for selected in 0..2u64 {
            let baseline = shared_input_policy_root(
                Felt::from_u64(selected),
                &treasury,
                &policy,
                poseidon2_width16_permutation_ring,
            );
            for capacity_lane in [8, 9] {
                let mut first = true;
                let mutated = shared_input_policy_root(
                    Felt::from_u64(selected),
                    &treasury,
                    &policy,
                    |state| {
                        if first {
                            state[capacity_lane] += Felt::ONE;
                            first = false;
                        }
                        poseidon2_width16_permutation_ring(state);
                    },
                );
                assert_ne!(baseline, mutated);
            }
            let mut changed_treasury = treasury;
            let mut changed_policy = policy;
            if selected == 0 {
                changed_treasury[43] += Felt::ONE;
            } else {
                changed_policy[47] += Felt::ONE;
            }
            assert_ne!(
                baseline,
                shared_input_policy_root(
                    Felt::from_u64(selected),
                    &changed_treasury,
                    &changed_policy,
                    poseidon2_width16_permutation_ring
                )
            );
            // Unselected descriptor values cannot influence the chosen digest.
            if selected == 0 {
                changed_treasury = treasury;
                changed_policy[0] += Felt::ONE;
            } else {
                changed_policy = policy;
                changed_treasury[0] += Felt::ONE;
            }
            assert_eq!(
                baseline,
                shared_input_policy_root(
                    Felt::from_u64(selected),
                    &changed_treasury,
                    &changed_policy,
                    poseidon2_width16_permutation_ring
                )
            );
        }
    }
}
