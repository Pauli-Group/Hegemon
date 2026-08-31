# Conventional secret-role hash successor screen

Status: bounded architecture evidence only.  This note does not select, name, or authorize a
production profile.  The existing profile-3/domain-set-2 `HGF6HR02` rate-72 `SHAKE512` proposal is
rejected because FIPS 202 and RustCrypto define SHAKE128 and SHAKE256, not a rate-72 SHAKE512 XOF.

## Compared constructions

The fixed public/collision roles remain standard FIPS 202 SHAKE256-448: 64 Merkle calls, one
intent call, one balance call, and two ciphertext calls, for 68 primitive invocations and exactly
105 Keccak-f[1600] permutations.  The measured Boolean compiler inventory for those calls is
13,022,694 scalar constraints.

The all-standard SHA3 option uses FIPS 202 SHA3-512, truncated to 56 bytes.  Every former 112-byte
KDF output becomes two SHA3-512 calls with distinct registry-owned role tags.  The full schedule is
83 primitive invocations and 151 Keccak permutations: 105 collision-role SHAKE256 permutations and
46 secret-role SHA3-512 permutations.  The executable shared-Keccak geometry screen gives
18,697,090 scalar constraints, or 292,143 rows after one global ceiling division by the SmallWood
packing factor 64.  This excludes authorization mux, source equalities, output equalities, and all
non-hash relation constraints.

The smaller standard option uses RFC 7693 BLAKE2b with digest length 56.  Note and policy roles are
unkeyed and personalized.  Spend-key, nullifier, and authorization derivations use RFC keyed mode.
Each former 112-byte output becomes two BLAKE2b-448 calls with distinct 16-byte personalization
values.  The proposed, unfrozen schedule is 83 primitive invocations and 137 primitive cores: 105
SHAKE256 permutations plus 32 BLAKE2b compressions.  Using placeholder personalizations solely to
make constant-folded gate accounting executable, the secret-role traces contain 3,178,341 scalar
constraints.  Together with the collision roles this is 16,201,035 constraints, or 253,142 globally
packed rows.  It is 39,001 rows (13.35 percent) below the SHA3 option before mux and binding rows.
These are compiler-geometry measurements, not proof bytes or a production-frontier point.

The exact BLAKE2b compression schedule is:

- four 232-byte note commitments: 8 unkeyed compressions;
- two keyed nullifiers, each with a 56-byte key and 77-byte message: 4 compressions;
- two spend inputs times two independently personalized halves, each with a 48-byte key and
  27-byte message: 8 compressions;
- one 385-byte unkeyed policy commitment: 4 compressions;
- two authorization slots times two independently personalized halves, each with a 56-byte key
  and a maximum 123-byte accumulator message: 8 compressions.

## Retained executable evidence

`circuits/transaction/src/smallwood_blake2b384.rs` now supports arbitrary RFC digest widths,
unkeyed personalization, and keyed personalization.  Keyed mode constrains the output-length and
key-length parameter bytes, the 16-byte personalization, the padded 128-byte key block, the exact
`t` counter, final-block flag, every key/message bit, and every output bit.  Its dependency-light
test binary passed 12 of 12 tests.  Two independent Python `hashlib.blake2b` cross-checks matched:

    keyed BLAKE2b-448
    key = 48 bytes of 0x11
    message = "keyed payload"
    personalization = "HEG-test-half-01"
    digest = 17717a8ead79718ab6442b2d10d6c3e830fd668463ad566d98ce618e11e8ca9427ab891da9de2f4527b654d6f8272a4d12b0f17064150724

    unkeyed personalized BLAKE2b-448
    message = "abc"
    personalization = "HEG-test-half-01"
    digest = 8c29074f8df3b4b2f567956895713f9518067375b619660a7fdba17671653ead99dd3ba56c47473651fafdf6f4c4cfaa4ef95d9da5d42b3b

The test command was a direct `rustc --test` build linked to already present dependency rlibs; no
Cargo, Lake, proof generation, or heavy build ran while free disk was below the 28 GiB gate.

## Blockers before selection

No profile should be rotated from this screen alone.  A production design must fix the exact key
source for each keyed role and prove its entropy/non-exposure premise; define fresh role and
personalization bytes for both halves; lower the five-mode authorization mux with exact selected
message length and counter semantics; bind every key, message, parameter, personalization, and
output bit; and obtain a composed multi-user QROM accounting for keyed PRF, preimage, collision,
PCS, IOP, Fiat-Shamir, transcript, grinding, and all union terms.  The full relation compiler must
then measure the resulting adapter rows and SmallWood proof bytes.  At roughly 253 thousand hash
rows before the non-hash relation, the SmallWood wire-size lower bound may already lose the
architecture tournament; this screen does not assume it remains the winner.
