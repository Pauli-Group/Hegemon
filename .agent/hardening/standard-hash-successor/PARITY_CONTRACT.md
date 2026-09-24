# HX448C01 scalar-to-M4 source parity contract

Status: diagnostic oracle only. `production=false`, tournament `winner=None`,
and no statement, proof, envelope, transcript, network, or consensus identity is
allocated. M4 may copy this byte/role schedule only under a new candidate
namespace; it must not reinterpret any HGF6/SWV6 artifact.

## Candidate statement codec

- Exact width: 893 bytes. Exact public projection: 128 little-endian limbs of
  seven bytes each; the last limb contains the final four bytes and four zero
  high bytes.
- Magic `0..8`: ASCII `HX448C01`.
- Grammar `8..10`: `u16be(1)`.
- Fields: input flags `10..12`; output flags `12..14`; anchor `14..70`;
  nullifiers `70..182`; commitments `182..294`; ciphertext hashes `294..406`;
  ciphertext sizes `406..414`; four balance assets `414..446`; fee `446..454`;
  value-balance sign `454`, magnitude `455..463`; stablecoin enabled `463`,
  asset `464..472`, policy version `472..476`, issuance sign `476`, magnitude
  `477..485`, policy hash `485..541`, oracle `541..597`, attestation `597..653`;
  balance tag `653..709`; circuit/suite/family/action `709..717`; network
  `717..721`; backend `721`; proof profile `722`; domain set `723..725`; chain
  `725..781`; genesis `781..837`; rules `837..893`.
- Integers are big-endian. Flags/signs are exactly zero or one. Negative zero
  is rejected. The verifier supplies the expected activation and exact equality
  is required. Circuit, suite, family, action, backend, proof-profile, and
  domain-set values and each 56-byte chain/genesis/rules binding must be
  nonzero; network ID is equality-bound but may be zero. This explicit-nonzero
  rule is part of the diagnostic candidate grammar, not an inherited claim
  about an already allocated production route. The historical V6 route is
  rejected even if carried under the fresh magic.
- Decoder rejects `HGF6ST02`, `HGF6HR02`, `HGR6RM02`, and `HGV6PB02` before
  interpreting any field, and canonical re-encoding must reproduce all 893
  bytes. It never calls the HGF6 encoder or decoder.

## Canonical application frame grammar

Every physical hash input is:

    profile[8] || role[8] || field_count:u8
      || (field_len:u16be || field_bytes)[field_count]

The diagnostic profile is ASCII `HX448C01`. Field order and field boundaries
are semantic; concatenations with a different field split are different
messages. The profile, role, count, lengths, fixed lane bytes, and dummy bytes
are constants. Each remaining byte has one typed source:
`CandidateStatement`, `PrivateWitness`, or `InternalDigest`.

The fixed equal-length lane tags are ASCII `lane.A01` and `lane.B01`. Their
distinctness is mandatory for both spend and authorization lanes.

## Exact 83-call schedule and frames

| Calls | Role bytes | Calls | Exact frame | Ordered fields |
| --- | --- | ---: | ---: | --- |
| 0..3 | `nt.b4481` | 4 | 232 | kind:1, value:u64be, asset:u64be, recipient:32, rho:48, randomness:48, auth key:56 |
| 4..5 | `nf.b4481` | 2 | 135 | resolved nullifier key:56, position:u64be, rho:48 |
| 6..69 | `mk.s4481` | 64 | 133 | left:56, right:56; position bit selects current digest versus private sibling; calls 6..37 are input 0 levels 0..31 and 38..69 input 1 levels 0..31 |
| 70..71 | `sk.b44a1` | 2 | 77 | `lane.A01`, private spend seed:48 |
| 72..73 | `sk.b44b1` | 2 | 77 | `lane.B01`, private spend seed:48 |
| 74 | `pl.b4481` | 1 | 385 | threshold:u64be, signer count:u64be, six signer tags of 56 bytes |
| 75..76 | `au.b44a1` | 2 | 136/143/181 | lane-A authorization slot 0 then slot 1; exact arms below |
| 77..78 | `au.b44b1` | 2 | 136/143/181 | lane-B authorization slot 0 then slot 1; exact arms below |
| 79 | `in.s4481` | 1 | 744 | one 725-byte statement field: statement bytes `0..14` followed by `182..893` |
| 80 | `bl.s4481` | 1 | 100 | fee:8, value sign:1, value magnitude:8, four assets:32, stable enabled:1, stable asset:8, issuance sign:1, issuance magnitude:8 |
| 81..82 | `ct.s4481` | 2 | 2,182 | proof profile:1, domain set:u16be, output slot:1, fixed length:u32be(2147), ciphertext:2147 |

Physical call meanings are fixed: notes are input 0, input 1, output 0,
output 1; nullifier/spend calls are input 0 then input 1; ciphertext calls are
output 0 then output 1. Inactive calls remain physical calls over the unique
zero witness encoding. Call 74 is the private accumulator-authorization policy
hash; it does not derive or authorize the public stablecoin policy hash.

## Fixed five-arm authorization programs

Selector order is exactly SingleKey, AccumulatorInit, ApprovalStep,
ValueLockCreation, FinalThresholdSpend. Both lanes and both slots allocate all
five arms.

- Dummy frame, 136 bytes: one 117-byte constant field; byte 0 is slot, byte 1
  is lane, remaining bytes are zero.
- Accumulator frame, 181 bytes: lane tag:8, policy root:56, intent:56,
  threshold:u64be, signer count:u64be, approval count:u64be, approved flags:6.
- Value-lock frame, 143 bytes: lane tag:8, current policy root:56, current
  intent:56.
- Slot 0 arms: dummy, next accumulator, current accumulator, value lock,
  current accumulator. Exact lengths `[136,181,181,143,181]`.
- Slot 1 arms: dummy, dummy, next accumulator, dummy, value lock. Exact lengths
  `[136,136,181,136,143]`.

For BLAKE, every arm is zero-padded to two 128-byte blocks. Before compression,
the one-hot mux selects all 2,048 block bits, both 128-bit counters
`[128, frame_len]`, and both final flags `[false,true]`. Exactly two
compressions execute per physical authorization call. The RFC 7693 parameter
word is unkeyed fanout/depth 1 with digest length 56 (`0x01010038`); there is no
key, salt, or personalization.

For split SHA3, every arm receives FIPS 202 SHA3 padding (`0x06`, final
`0x80`) at rate 72 and is extended to a fixed three-block pipeline. Dummy and
value-lock arms terminate after permutation 2; accumulator arms terminate
after permutation 3. A final one-hot mux selects the correct 448 digest bits.

## Primitive profiles and exact core ledger

- Collision roles `mk.s4481`, `in.s4481`, `bl.s4481`, `ct.s4481` always use
  FIPS 202 SHAKE256, rate 136, suffix `0x1f`, 56 output bytes: 68 calls and 105
  Keccak-f permutations.
- BLAKE finalist: every other role uses unkeyed RFC 7693 BLAKE2b-448: 15 calls
  and 28 compressions. Per-family compressions are note 8, nullifier 4, spend
  4, policy 4, authorization 8.
- Split-SHA3 finalist: every other role uses a separate FIPS 202 SHA3-512 call,
  rate 72, suffix `0x06`, truncated to its first 56 bytes: 15 calls and 46
  permutations. Per-family permutations are note 16, nullifier 4, spend 8,
  policy 6, authorization 12.
- Pinned M4 raw-AND projection: BLAKE finalist 79,128 words; split SHA3
  90,600 words, an 11,472-word BLAKE advantage. The 28 BLAKE compressions also
  emit 10,752 rotation-linear Shift constraints separately (`28 * 384`);
  `rotr` emits no AND. Each of the 16,128 BLAKE additions emits one additional
  linear constraint as well as its AND. Raw AND counts are not a winner because
  mux/counter/final metadata, total linear constraints, DCE, and proof bytes are
  not included.
- Exact scalar diagnostic constraints for the four canonical authorization
  calls: BLAKE 813,624; split SHA3 1,497,512. These are parity diagnostics only,
  not native-Binius counts.

## Admission and release boundary

The algebraic relation does not add nonzero requirements for input note
commitments, ciphertext digests, accumulator intents, or signer tags. The
composed parser/admission boundary separately requires active public nullifiers
and active public output commitments to be nonzero.

Stablecoin algebra and external policy authorization are distinct gates.
Enabled stablecoin metadata may be zero inside the transaction relation because
the source algebra admits it; disabled metadata must be uniquely all zero. The
active native consensus boundary nevertheless authorizes an enabled binding
against the protocol manifest: policy known/active/live, exact asset,
policy-hash/version, oracle and attestation commitment equality, undisputed
attestation, fresh oracle, nonzero issuance, and issuance within the manifest
limit. The active fields are 48-byte values; policy identity is a domain-framed
native-output RFC 7693 BLAKE2b-384 digest, while oracle and attestation values
are opaque manifest commitments with no derivation algorithm in this contract.
The active policy preimage is the exact 61-byte SCALE encoding of
`(asset:u32, oracle_feed:u32, attestation_id:u64,
min_collateral_ratio_ppm:u128, max_mint_per_epoch:u128,
oracle_max_age:u64, policy_version:u32, active:bool)` (fixed integers little
endian). Its exact hash transcript is
`"hegemon.blake2b-384.frame-v1" || u64le(35) ||
"hegemon.kernel.stablecoin-policy.v2" || u64le(61) || preimage`, evaluated as
BLAKE2b with its native 48-byte digest parameter.

This diagnostic candidate carries three 56-byte stablecoin values. They have no
48-to-56 conversion authority and are intentionally opaque/fail-closed until a
fresh versioned manifest/action grammar either defines conventional hash domains
and canonical preimages or retains an explicit external validity gate. Padding,
truncating, or reusing the active 48-byte identity is forbidden.

The minimum 56-byte successor is an atomic version change, not an adapter: a
new manifest entry and shielded-action binding carry native `[u8;56]` fields; a
fresh domain-framed native-output BLAKE2b-448 policy digest hashes the same exact
61-byte tuple; the 893-byte statement carries those bytes unchanged; admission
compares exact 56-byte values; and the verifier-selected route and freshly
computed rules binding commit to the new manifest type, hash frame/domain, and
action grammar. Oracle/attestation require either separately versioned
conventional-hash preimage grammars or the explicit external-manifest gate
above. No production domain string, route, or rules identity is allocated by
`HX448C01`, so this minimum successor remains a release blocker rather than an
implemented authority.

No M4 artifact matches this contract unless it binds every source bit and
digest bit, emits the exact core ledger above, passes KAT/mutation/all-mask/
all-mode tests, and retains `production=false`, `winner=None`, and an
unallocated consensus identity.
