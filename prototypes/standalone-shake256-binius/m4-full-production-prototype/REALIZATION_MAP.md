# M4 full-transfer realization map

Status: implemented source, not yet compiled or proved because the disk gate is
closed. The production frontier is empty. No zero-knowledge result, PQ128
composition, formal certificate, or production refinement is implied by this
source.

The scalar oracle is
`circuits/standalone-full-shake256-relation-prototype/src/lib.rs`. M4 must be a
literal realization of that oracle plus the outer admission obligations listed
at the end. Active SmallWood is useful as a semantic reference, but the typed
note lineage below is an intentional security fork and therefore cannot be
called a SmallWood differential.

## Canonical public statement

The only accepted byte grammar is `HGF4ST02`, grammar version 2, exactly 853
bytes. Ranges are half-open.

| Bytes | Meaning |
|---:|---|
| 0..8 | magic `HGF4ST02` |
| 8..10 | grammar version, big-endian `u16` |
| 10..12 | input flags 0 and 1 |
| 12..14 | output flags 0 and 1 |
| 14..70 | Merkle anchor |
| 70..126 | nullifier 0 |
| 126..182 | nullifier 1 |
| 182..238 | output commitment 0 |
| 238..294 | output commitment 1 |
| 294..350 | ciphertext hash 0 |
| 350..406 | ciphertext hash 1 |
| 406..438 | four big-endian `u64` asset IDs |
| 438..446 | fee, big-endian `u64` |
| 446..447 | value-balance sign |
| 447..455 | value-balance magnitude, big-endian `u64` |
| 455..456 | stablecoin enabled |
| 456..464 | stablecoin asset, big-endian `u64` |
| 464..468 | stablecoin policy version, big-endian `u32` |
| 468..469 | stablecoin issuance sign |
| 469..477 | stablecoin issuance magnitude, big-endian `u64` |
| 477..533 | stablecoin policy hash |
| 533..589 | stablecoin oracle commitment |
| 589..645 | stablecoin attestation commitment |
| 645..701 | V5/Delta balance tag |
| 701..703 | circuit version, big-endian `u16` |
| 703..705 | crypto suite, big-endian `u16` |
| 705..707 | family ID, big-endian `u16` |
| 707..709 | action ID, big-endian `u16` |
| 709..717 | backend ID |
| 717..725 | proof-profile ID |
| 725..757 | chain ID |
| 757..805 | genesis block ID |
| 805..853 | rules hash |

The statement transport is exactly 107 words. Word `i` is the raw eight
statement bytes interpreted with `u64::from_le_bytes`; this preserves byte order
in digest lanes. The circuit now loads aligned or two-word-spanning digest and
integer fields directly from that packed transport, extracts only the seven
individual flag/sign bytes, and converts big-endian integers with the same
`swap_bytes` operation. Magic, grammar version, and the entire authoritative
activation suffix are compared with exact full- or partial-word masks. The
final word is formed from bytes 848..853 followed by three zero bytes, so its
high 24 bits must be zero. There is no alternate field-element decoder,
modular reduction, short form, or trailing input.

The composed verifier appends seven raw public words containing the 56-byte
`intent.1` digest it derives from the exact decoded statement. Total M4 public
input is therefore 114 words. These seven words are not action-wire bytes and
are never caller-selected: raw M4 verification stays private, while the only
accepted packer consumes `FullProofBinding::m4_public_transport()`, whose exact
912 bytes contain the 853-byte statement, three zero alignment bytes, and the
56-byte derived intent. `bal.tag1` is
likewise recomputed by the authoritative action adapter before M4 verification.
Moving these two public-only hashes out of the circuit removes seven Keccak-f
calls without changing the accepted witness relation.

The only concrete upstream verifier adapter is an explicitly unsupported
negative control behind the nondefault `prototype-weak` feature. It is
compile-forbidden when debug assertions are disabled, uses the pinned
transparent 96-bit/SHA-256/B128 profile, and cannot authorize the statement's
`pq128v1` profile. Default and release builds expose no accepting full-proof
verifier. It also deliberately does not implement the production-shaped
`FullProofVerifier` trait. The negative control instead accepts a distinct,
non-authorizing prover binding, uses the exact transport, observes the
byte-identical FullProofBinding-v3 preamble in prover and verifier, calls
`VerifierM4`, and requires transcript finalization so it can test the proof
mechanics once the disk gate opens without entering action composition.

The verifier supplies the authoritative 152 activation/network bytes at
701..853. The circuit/verifier pair compares every byte. Comparing the decoded
statement to itself is forbidden.

## Private word layout

Every private transport word is eight original bytes interpreted little-endian
so SHAKE frames see the original byte order. Numeric fields are serialized in
canonical big-endian form and converted with `swap_bytes` before integer gates.
Boolean words and the mode word serialize as big-endian `u64` values and must
have all high bits zero after conversion. There are 671 private words after
adding the four committed note-kind words.

Each input occupies 261 words:

| Input 0 | Input 1 | Count | Meaning |
|---:|---:|---:|---|
| 0..6 | 261..267 | 6 | spend key |
| 6 | 267 | 1 | note kind: Ordinary=0, Accumulator=1, ValueLock=2 |
| 7 | 268 | 1 | note value |
| 8 | 269 | 1 | note asset |
| 9..13 | 270..274 | 4 | recipient key |
| 13..19 | 274..280 | 6 | rho |
| 19..25 | 280..286 | 6 | randomness |
| 25..32 | 286..293 | 7 | note authorization key |
| 32 | 293 | 1 | Merkle position |
| 33..257 | 294..518 | 224 | 32 siblings, seven words each |
| 257..261 | 518..522 | 4 | balance-slot selectors |

Each output occupies 30 words:

| Output 0 | Output 1 | Count | Meaning |
|---:|---:|---:|---|
| 522 | 552 | 1 | note kind |
| 523 | 553 | 1 | note value |
| 524 | 554 | 1 | note asset |
| 525..529 | 555..559 | 4 | recipient key |
| 529..535 | 559..565 | 6 | rho |
| 535..541 | 565..571 | 6 | randomness |
| 541..548 | 571..578 | 7 | note authorization key |
| 548..552 | 578..582 | 4 | balance-slot selectors |

Authorization occupies the remaining 89 words:

| Words | Count | Meaning |
|---:|---:|---|
| 582 | 1 | mode: Single=0, Init=1, Approval=2, LockCreation=3, Final=4 |
| 583..590 | 7 | current policy root |
| 590..597 | 7 | current intent |
| 597 | 1 | current threshold |
| 598 | 1 | current signer count |
| 599 | 1 | current approval count |
| 600..606 | 6 | current approval bits |
| 606..613 | 7 | next policy root |
| 613..620 | 7 | next intent |
| 620 | 1 | next threshold |
| 621 | 1 | next signer count |
| 622 | 1 | next approval count |
| 623..629 | 6 | next approval bits |
| 629..671 | 42 | six signer tags, seven words each |

Activity is not duplicated privately; the four public flags gate these fixed
slots. Inactive input payloads (all 261 words) and inactive output payloads
(all 30 words) are exactly zero. Their public nullifier or
commitment/ciphertext words are also zero.

## SHAKE256 calls

Every frame is `HEG-F4V1 || role[8] || field_count[1] ||` repeated
`field_len_be_u16 || field`. SHAKE256 uses the FIPS 202 `0x1f` suffix and final
`0x80` pad bit at the 136-byte rate. Digest bytes are never reduced. All
112-byte KDFs include the eight-byte field `auth.nf1`; bytes 0..56 are the note
authorization key and bytes 56..112 are the nullifier key.

| Role | Frame bytes | Output | Keccak-f calls | Fixed instances |
|---|---:|---:|---:|---:|
| `note.cm3` | 232 | 56 | 2 | 4 |
| `nullif.2` | 135 | 56 | 1 | 2 |
| `merk.nd2` | 133 | 56 | 1 | 64 |
| `sp.keys2` | 77 | 112 | 1 | 2 |
| `policy.1` | 385 | 56 | 3 | 1 |
| `accum.01` | 181 | 112 | 2 | 2 |
| `val.lock` | 143 | 112 | 2 | 1 |
| `bal.tag1` | 100 | 56 | external | adapter recomputes |
| `intent.1` | 704 | 56 | external | composed verifier derives 7 words |

The fixed universal geometry is 83 Keccak-f calls. The policy hash is shared
because every permitted transition constrains current/next policy metadata to
the same canonical policy where both exist. Final's previously sketched
effective-next hash was removed because its output was discarded; the current
metadata and approval-clearing semantics remain constrained without spending
two observationally dead Keccak-f calls. Both membership paths retain all 32
hashes: sharing the final compression would reject hypothetical distinct
SHAKE preimages with the same root and would therefore narrow the scalar
relation. A claimed active-row count must be
emitted by the implemented circuit; Pay1x2 counts or proof sizes must not be
mapped onto this geometry.

The applied source patch chain at SHA-256
`f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b`
also caches numeric note values/selectors, replaces the Merkle mask/delta cone
with one MSB select plus XOR recovery of the other child, uses the exact
five-mode one-hot partition to remove redundant SHAKE-frame mux gates, and
validates one selected policy structure while preserving both approval-state
lanes. Its allocation-free counters tighten the conservative syntactic
hidden-word upper from 65,336 to 60,788, or at most 30,394 active B128 symbols,
leaving at least 2,374 symbols in an n15 tail. This is not a compiled-size result: the upstream
compiler runs CSE/fusion/DCE and may realize a different delta. Typecheck,
compiled statistics, and scalar/M4 differential execution remain mandatory
before citing an actual constraint or proof-byte reduction.

## Constraint realization

1. **Decode and action binding.** Constrain magic, grammar, the final 24 zero
   padding bits, every flag/sign as a bit, every numeric width, and the exact
   authoritative activation tuple. Target V5/Delta admission accepts exactly
   the 9 masks having at least one input and one output. It also constrains
   `value_balance` sign and magnitude to zero.
2. **Kinds and ranges.** Each active note kind is in `{0,1,2}`. Values, fee,
   value-balance magnitude, and issuance magnitude have their top three bits
   zero. Input positions have their top 32 bits zero. Asset words are compared
   as raw unsigned 64-bit integers, not reduced field elements.
3. **Asset slots.** Slot 0 is native zero. Nonpadding slots are canonical,
   exclude the reserved reduced-padding alias, and strictly increase. Raw
   `u64::MAX` padding is a suffix. Each active note has four boolean selectors
   summing to one; inactive selectors are zero; the selected nonpadding asset
   equals the note asset.
4. **Commitments and membership.** `note.cm3` hashes kind, value, asset,
   recipient, rho, randomness, and authorization key in that order. Each active
   input commitment is nonzero and follows its 32 direction bits/siblings to
   the public anchor. Each active output commitment is nonzero and equals its
   public commitment. Active ciphertext hashes are nonzero and public; the
   encryption preimage is outside this relation.
5. **Nullifiers.** The mode resolves each input to the spend, accumulator, or
   value-lock nullifier half. Active nullifiers are nonzero and equal their
   public values. If both inputs are active, their public nullifiers differ.
6. **Canonical policy.** Non-single policies have `1 <= threshold <=
   signer_count <= 6`, `approval_count <= signer_count`, nonzero intent, and
   exactly `approval_count` approval bits. Active 56-byte signer tags are
   nonzero and unique in creator-chosen, policy-root-bound slots; inactive tags
   and approval bits are zero. `policy.1` equals the opening's policy root.
7. **Single.** Current/next openings and all tags are zero. Every active input
   and output is Ordinary. Each input uses its own spend-key auth/NF halves.
8. **AccumulatorInit.** At least one Ordinary input and output 0 are active;
   output 0 is a zero-value native Accumulator and output 1, if active, is
   Ordinary. Current is zero. Next is a valid policy opening with zero approval
   count/bits. Output 0 authorization equals the next accumulator auth half.
9. **Approval.** Both inputs and output 0 are active. Input 0/output 0 are
   zero-value native Accumulators, input 1 and optional output 1 are Ordinary,
   and input-0 spend-key bytes are zero. Current/next metadata match, next count
   is current plus one, the input-1 spend-derived tag is exactly one active
   member not previously approved, and only that bit changes. Input 0 uses the
   current accumulator halves; output 0 uses the next accumulator auth half.
10. **ValueLockCreation.** At least one Ordinary input and output 0 are active;
    output 0 is ValueLock and optional output 1 is Ordinary. Next is zero.
    Current is a valid zero-approval policy descriptor. Output 0 authorization
    equals `val.lock(policy_root, future_intent)`'s auth half.
11. **Final.** Both inputs are active. Input 0 is ValueLock, input 1 is a
    zero-value native Accumulator, all active outputs are Ordinary, both raw
    input spend keys and raw next opening are zero. Current is valid, has count
    at least threshold, and its intent equals the seven verifier-derived
    `intent.1` public words over magic/version,
    flags, output commitments, ciphertext hashes, slots, fee, zero value
    balance, stablecoin tuple, derived balance tag, and activation.
    Anchor/nullifiers are the only
    omitted statement fields. Input auth/NF halves come from value-lock and
    current accumulator respectively. Effective-next semantics preserve the
    current policy/intent/threshold/signer-count metadata and clear approvals;
    no unused effective-next digest is computed.
12. **Balance.** Use carry-constrained integer arithmetic, not binary-field
    addition, for the two 61-bit input/output values per slot. Padding deltas
    are zero. Native `inputs - outputs = fee` because the active action binds
    zero value balance. Enabled stablecoin uses its signed issuance delta;
    every other nonnative delta is zero. Disabled stablecoin fields are all
    zero. Enabled stablecoin has a canonical nonnative slotted asset, nonzero
    policy version, nonzero issuance magnitude, and nonzero policy/oracle/
    attestation digests. The action adapter recomputes `bal.tag1` from fee,
    signed value balance, four raw slot assets, and signed stablecoin issuance
    and requires equality with public bytes 645..701 before invoking M4.

## Required evidence before any frontier point

- Fixed scalar KATs for every SHAKE role and every note kind.
- Positive and single-field negative vectors for all 16 masks, five auth modes,
  every kind transition, stablecoin fields, slots, carries, activation bytes,
  short/trailing grammar, and the fake-threshold lineage exploit.
- Scalar/M4 differential equality for every accepted vector and identical
  rejection for every negative vector.
- An outer-admission refinement showing only verified-output commitments enter
  accepted note-tree roots, accepted roots are checked before proof acceptance,
  nullifiers are globally fresh, stablecoin policy commitments are authorized,
  and the family/action/version/network tuple selects this exact circuit.
- An atomic V5/Delta action/state/manifest/receipt adapter with explicit two
  flags and fixed ordered 2x56-byte NF/commitment/ciphertext slots. The deployed
  prefix-only 48-byte compact-list projection is incompatible; no digest may be
  truncated or reduced, and every one of the 16 slot masks needs an injective
  adapter mutation vector.
- Exact proof parsing with complete consumption, complete ZK evidence, strict
  composed PQ128 evidence, and independent formal/refinement certificates.

Until every item is sealed by the production-frontier gate, accepted frontier
points remain empty regardless of proof size.
