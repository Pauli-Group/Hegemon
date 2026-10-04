# Full SHAKE256 transaction-relation scalar oracle

This isolated crate specifies the proposed full two-input/two-output SHAKE256
relation before an M4 circuit is allowed onto the proof-size frontier. It is not
reachable from consensus and it is not, by itself, proof-system, zero-knowledge,
post-quantum, or formal-verification evidence.

## Exact public grammar

`encode_canonical_statement` and `decode_canonical_statement` define one fixed
853-byte grammar. Integers are big-endian. It contains, in order:

1. `HGF4ST02`, grammar version 2, two input flags, and two output flags;
2. the 56-byte anchor, two nullifiers, two commitments, and two ciphertext
   hashes;
3. four asset slots, fee, and signed value balance;
4. the complete stablecoin tuple: enable bit, asset, policy version, signed
   issuance, policy hash, oracle commitment, and attestation commitment;
5. a 56-byte `bal.tag1` commitment derived from the exact slot/delta fields; and
6. circuit, crypto, family, action, backend, proof profile, chain, genesis, and
   rules bindings.

The decoder requires exactly 853 bytes, rejects non-binary flags and negative
zero, and consumes the complete input. The only non-test relation entry point,
`verify_relation_with_expected_activation`, then compares the entire
activation/network tuple to an authoritative caller value. Production
admission cannot call the weaker profile-only check and must never use a
statement as its own expected network identity.

The active SmallWood relation exposes 78 field elements because its hashes use
six 64-bit limbs. The SHAKE candidate carries the analogous public categories,
but its 56-byte digests require seven limbs, so the analogous relation surface is 88
words before the additional activation/network bytes. Calling this an exact
SmallWood differential would be false until a field-by-field adapter is
implemented and tested.

## Deliberate differences from active SmallWood

- All proposed cryptographic roles are explicitly framed SHAKE256 roles; no
  Poseidon or SmallWood hash is reused. The fixed KATs were independently
  calculated with Python `hashlib.shake_256`.
- `note.cm3` commits a private covenanted note kind: `Ordinary`, `Accumulator`,
  or `ValueLock`. Single-key transfers may consume and create only ordinary
  notes. `AccumulatorInit` creates a zero-approval, zero-value native
  accumulator; `ValueLockCreation` creates a value-lock bound to a policy and
  future intent; Approval and Final consume/produce only their exact kinds.
  This deliberately breaks wire compatibility with active SmallWood to close
  its special-note provenance hole. A typed M4 circuit and ledger-refinement
  proof are required before the fork can be admitted.
- Digests are 56 bytes and spend keys are 48 bytes. Active SmallWood uses
  48-byte hash encodings, 32-byte spend keys, and 32-byte note authorization
  keys.
- Each active single-key input has its own spend key. Active SmallWood currently
  derives the legacy single-key lane from one transaction-level `sk_spend`.
- Nullifier keys follow the selected authorization mode: ordinary spend-key,
  current-accumulator, or value-lock material. Unused per-input spend-key bytes
  are required to be zero so they cannot select alternate nullifiers or remain
  unconstrained witness baggage.
- Every 112-byte key derivation includes `auth.nf1` in its framed input and
  defines bytes 0 through 55 as the note authorization key and bytes 56 through
  111 as its nullifier key. The ordering is therefore transcript data, not an
  implementation comment. Two active inputs must also have distinct public
  nullifiers, so one note cannot be counted twice in a transaction.
- Approval mode advances the intent already stored in the accumulator; it does
  not equate that intent to the approval transaction itself. Equating it would
  be circular because output zero is authorized by the next accumulator digest.
  Final-threshold mode does bind the stored intent to the exact final statement.
  Accumulator intents must be nonzero. The intent frame includes the statement
  magic and grammar version, and intentionally omits only the anchor and
  nullifiers.
- Active signer tags are nonzero, unique 56-byte values in creator-chosen,
  policy-root-bound slots followed by zero padding. The policy is an ordered
  vector, not an unordered set; avoiding a redundant lexicographic comparator
  keeps the binary circuit smaller without creating a serialization ambiguity.
- Accumulator notes are canonical zero-value native-asset state tokens. Approval
  mode enforces that shape for both the current input and next output; final
  mode enforces it for the accumulator input. This is a proof constraint, not a
  wallet-side assumption, so an accumulator authorization key cannot be used to
  smuggle value through a state transition.
- Final mode requires the raw next-accumulator witness to be zero, then derives
  the effective next state by preserving policy metadata and clearing approvals.
  This is a stricter witness-canonicality rule than merely deriving the effective
  state while ignoring raw next-state bytes.
- Stablecoin policy, oracle, and attestation digests are public commitments.
  Their external authorization is not invented inside this transaction
  relation; an independent stablecoin-policy verifier and acceptance certificate
  remain mandatory.
- Family, action, backend, proof profile, and complete network identity are in
  the canonical statement instead of relying only on circuit/crypto values plus
  an out-of-band manifest.
- The balance tag is an explicit 56-byte V5/Delta public field, recomputed from
  the bound fee, zero value balance, slot assets, and stablecoin issuance. The
  active 48-byte tag and all 48-byte action/state identities are incompatible;
  an atomic 56-byte wire/state/manifest migration is required. Truncation or
  field reduction is forbidden.
- The target fixed-slot V5/Delta transfer route admits only masks with at least
  one input and at least one output, requires public `value_balance = 0`, and
  requires enabled stablecoin issuance to be nonzero. The exhaustive mask test
  therefore accepts 9 of 16 masks and rejects the remaining 7. The deployed
  48-byte compact-list adapter is prefix-only and is not parity evidence for
  gap masks; V5/Delta requires explicit ordered flags and fixed 2x56 slots.
- Fixture refresh recomputes active derived values but never erases or
  normalizes inactive private payloads. This keeps negative fixtures invalid
  instead of silently repairing them before verification.

## Lean finite-vector bridge

`formal/lean/Hegemon/FullShakeRelation/GenerateFullShakeRelationVectors.lean`
deterministically generates
`testdata/formal_core_vectors/full_shake_relation.json`. The isolated
integration test `tests/lean_full_shake_relation_vectors.rs` uses a small
dependency-free JSON parser to recompute the Lean activity, typed-state,
balance, and stablecoin decisions, then exercises the actual scalar verifier
for all 16 masks and every named typed authorization/lineage case. Once the
disk admission gate permits focused builds, run:

    cd formal/lean
    lake exe gen_full_shake_relation_vectors
    cd ../..
    cargo test --manifest-path circuits/standalone-full-shake256-relation-prototype/Cargo.toml \
      --test lean_full_shake_relation_vectors

The committed file must be byte-identical to generator output. This is a
finite differential gate, not a proof that arbitrary Rust inputs refine Lean
or that the M4 circuit refines the scalar oracle.

## Frontier status

The production frontier remains empty. Admission additionally requires a
complete M4 realization, scalar/circuit differential evidence, exact proof
parsing, complete zero-knowledge evidence, strict composed PQ128 evidence, and
formal/refinement certificates accepted by the sealed frontier gate.
