# HX512 semantic-suite source certificate

Verdict: `blake2b512_rfc` is the smallest source-static candidate in this
screen, at 29,510,157 projected Boolean-R1CS rows and 213 BLAKE2b
compressions across 90 physical in-relation calls.  The distinct
SHA-512/SHAKE256-512 control is 36,868,145 rows, 37 SHA-512 compressions, and
183 SHAKE256 permutations.  These are macro-source counts, not compiled
geometry or proof measurements.  Production is false and proof bytes are
null.

## One canonical composite domain schedule

The 83 frozen transaction calls use the fresh `HX512B01` counted frame:

    profile[8] || role[8] || field_count:u8 ||
    repeated(field_len:u16be || field_bytes)

The selected suite adopts, byte-for-byte, the smaller frozen all-W64 manifest
authority from `manifest-authority-closure`; the discarded generic HX512
authority frame is never accepted.  Identity hashes use the BLAKE2b
parameter personalization

    HGMAIDV2 || role:u8 || 0x02 || 0x40 || 0x0000000000

where roles 1, 2, and 3 are policy, oracle, and attestation.  Their raw
preimages are respectively the exact 61-byte policy tuple, the 54-byte oracle
header plus 1..4096 payload bytes, and the 58-byte attestation header plus
1..4096 payload bytes.

Manifest hashes use

    HGMAROOT || role:u8 || 0x02 || 0x40 || 0x04 || level:u8 || 0x000000

over an exact 216-byte `present || row215` leaf (role 2), exact 128-byte
`left64 || right64` nodes (role 3, levels 0..3), and exact 72-byte
`parent_height:u64le || manifest_root64` snapshot (role 4).  Policy, leaf,
four path nodes, and snapshot cost 1+2+4+1 = 8 compressions.  The
SHAKE control absorbs `HX512H01 || personalization16 || u16be(raw_len) || raw`;
it is a separate suite identity and cannot be substituted into a BLAKE proof.

The statement's `domain_set=0x5127` freezes both the HX512B01 core registry
and the HGMA authority registry.  Network, action, circuit, suite, backend,
proof profile, chain, genesis, and rules identifiers remain separate exact
statement fields.  The snapshot does not authenticate its own parent state:
the native verifier must source canonical-parent root and height and compare
them exactly before proof verification.  The exact inactive-native verifier
context is `manifest_root64 || parent_height:u64le`; it is not
`state_snapshot64 || height`.  The statement separately carries the derived
snapshot as `state_root`.

## Exact surface

The prospective statement is 1,141 bytes (163 seven-byte limbs, or 143
eight-byte words plus three zero pad bytes).  Authenticated verifier context
is 72 bytes.  Public transport is 152 eight-byte words, seven fewer than the
frozen HX448C02 statement plus its old state seam.

Private transport is 11,000 bytes / 1,375 words: transaction base 6,216;
two padded ciphertexts 4,304; manifest membership 480.  Membership is
`index:u32le || row215 || sibling64[4] || zero[5]`, with 475 semantic bytes.
The 215-byte row, all offsets, canonical ordering, cap 16, source grammars,
all 16 activity masks, all five authorization modes, and stablecoin gates are
retained in `suite_report.json`.  `policy_version` is any canonical `u32`,
including zero; the native V2 codec and verifier impose no nonzero predicate.

The transaction base carries `current_policy_master64` at byte 6,088 and
`next_policy_master64` at byte 6,152.  The policy call selects next only for
accumulator initialization and current otherwise.  Slot order is `0A,0B,1A,1B`:
single-key selects four dummy arms and zeros both masters; initialization uses
next for slot 0 and zeros current; approval uses current for slot 0 and next
for slot 1 while enforcing `current=next`; value-lock creation uses current
for slot 0 and zeros next; final spend uses current for both slots and zeros
next.  Active masters are 64-byte witnesses, but the relation cannot certify
uniform sampling.

The authorization BLAKE mux contributes exactly 80,456 rows: 73,728 for four
calls times three selected 128-byte blocks; 4,608 for three selected 64-bit
counters; 72 for three selected final flags; and 2,048 for four 512-bit
two-versus-three-compression state selections.

Policy-master constraints contribute 2,560 rows: 1,024 for the already-counted
single-key zero surface, 512 for the already-counted inactive master, 512 to
widen selected-policy opening selection to include its master, and 512 for
approval current/next continuity.  The last two are the exact 1,024-row
correction; there is no padding and no extra hash call.

The six authority non-bitness groups contribute exactly 11,592 rows:
186 transport/canonicality, 1,088 selected-row/statement equality, 512 policy
output equality, 5,696 path/root reconstruction, 1,934 lifecycle/oracle/cap,
and 2,176 snapshot/verifier-context equality.  This broader full-relation
closure includes the frozen authority-local 6,237-row surface plus its exact
statement, lifecycle, disabled-branch, snapshot, and context bindings; it has
no padding.  The 5,696-row group already contains 512 rows requiring the
depth-four recomputed root to equal the statement manifest root.  Correcting
the context equality to statement manifest root versus verifier-context
manifest root therefore changes no row count.  The first group includes
exactly 21 constraints forcing the upper
seven bits of each 8-bit `retired_present`, `active`, and
`attestation_disputed` witness byte to zero; source bitness alone does not make
those bytes canonical.  The earlier unsupported 14,616 estimate and the
intermediate 11,571 count are retired.

## Security boundary

`security_ledgers.json` intentionally has two ledgers.  The theorem-only
ledger leaves the deployed-hash QROM reductions unbounded and fails closed.
The conditional ledger sets `Q=2^64`, assigns a nonzero `2^-160` concrete
hash-as-QRO assumption per primitive, and includes prefix multi-user/history,
physical-call preimage, collision, grinding, RNG, mask/mode, and proof-history
terms.  Every listed non-null term and their sum are strictly below `2^-128`;
the semantic slice is about 154.913 bits.  The full proof result is still null
because PCS, IOP, Fiat-Shamir, complete-ZK, selective-opening, refinement, and
release terms are absent.

Semantic width is not the proof salt.  With at least 33,555,190 320-bit field
elements, the BCS rate-one floor is `p >= 10,737,660,800` bits.  The loss
`p*2^(-lambda/4+2)` gives only about 92.68 bits at lambda 512; aligned 648
still fails, and aligned 656 only clears this optimistic floor.  Actual code
lengths increase `p`.

## Reproduce the source-only certificate

These commands do not build a proof or invoke Cargo:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-semantic-suite/hx512_suite.py --write
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-semantic-suite/hx512_suite.py --check
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/hx512-semantic-suite -p 'test_*.py' -v

The checker pins the frozen HX448C02 scalar/M4 sources, odd-field compiler and
manifest, the adopted manifest-authority source, and the inactive native V2
module/checker/tests that define the public context boundary.  Six standard
primitive KATs and ten selected/control authority KATs are executable.  The retained 56
mutation labels and direct unit mutations keep every production capability
fail closed.
