# HX448C02 scalar-to-M4 source parity certificate

This directory certifies an exact source mapping for the test-only `HX448C02` grammar-two
transaction diagnostic. A checker pass means that the pinned scalar, M4, native-admission, codec,
primitive, and dependency bytes still match the machine-readable inventory; all 83 typed hash
calls and every enumerated non-hash semantic family have named scalar and M4 source counterparts;
and every execution or production authority flag remains false.

It does **not** mean that a compiled M4 aggregate accepted an honest witness, rejected a mutation,
or shares the intended wires after compiler lowering. The scalar implementation performs many
transaction and stablecoin checks as Rust host predicates. Those predicates are not retroactively
M4 constraints. `certificate.json` therefore keeps a separate `missing_executed_graph` with exact
nonzero denominators and zero executed counts for call frames, hash outputs, Merkle chains, public
digest bindings, authorization arms, codec bytes, semantic edges, stablecoin cases, and mutation
classes.

## Frozen relation surface

- Fresh identity: `HX448C02`, big-endian grammar `2`; retired `HX448C01` is a required negative.
- Public statement: 869 bytes, packed as 125 scalar seven-byte limbs or 109 M4 eight-byte words.
  The final scalar limb has one payload byte and seven zero high bytes. M4 word 108 has five
  payload bytes and its high 24 bits constrained to zero.
- Post-quantum diagnostic digests remain 56 bytes. The live stablecoin policy hash, oracle
  commitment, and attestation commitment are exactly 48 bytes each and map directly to six M4
  words each. No padding, truncation, or 48/56-byte conversion is permitted.
- Hash program: 83 typed physical calls. Call 74 remains the private accumulator-authorization
  policy hash. It is not the stablecoin policy hash.
- Shape corpus: five authorization modes over all 16 two-input/two-output masks, partitioned into
  exactly 33 accepted and 47 rejected pairs per profile.
- Intent call 79 hashes a 720-byte frame whose sole 701-byte payload is statement bytes `0..14`
  followed by bytes `182..869`.

## Stablecoin claim boundary

For an enabled binding, scalar diagnostic admission retains an entire `ProtocolManifest` snapshot
plus a current height and mirrors native admission's existential search: an entry is plausible when
its asset id **or** its kernel-derived policy hash matches, and any plausible entry satisfying all
ordered predicates authorizes the diagnostic. Disabled bindings remain uniquely zero and ignore an
ambient manifest. The manifest snapshot and height are external host facts. They are neither
authenticated to consensus state by this diagnostic nor compiled into the aggregate M4 relation.

The kernel policy identity is independently rederived from the exact 61-byte fixed-width SCALE
tuple with RFC 7693 BLAKE2b-384. The three 384-bit live authorities are compatibility evidence only:
their generic quantum collision screen is exactly 128 bits, leaving no positive strict composed
margin and no concrete QROM bridge for opaque oracle or attestation commitments. Consequently
`strict_stablecoin_pq_margin=false` and `production_authorized=false`. Any production successor
needs fresh wider bindings rederived from authoritative policy/oracle/attestation preimages; it may
not manufacture width by padding or truncating the live 48-byte values.

## Lightweight validation

While the 28-GiB compile gate is closed, run only:

```sh
python3 .agent/hardening/scalar-m4-parity-certificate/check_certificate.py --json
python3 .agent/hardening/scalar-m4-parity-certificate/test_check_certificate.py
python3 prototypes/standalone-shake256-binius/m4-full-blake448-e384-candidate/check_source.py
git diff --check -- .agent/hardening/scalar-m4-parity-certificate
```

The Binius logical root is a symlink into a local temporary tree. The checker binds all 688 files
with the candidate's canonical tree SHA-512 and individually pins the four files absorbed by the
Rust `source_digest()`, but the dependency is not retained or self-contained. That limitation is
part of the certificate, not hidden by its hash.

Once at least 28 GiB is actually free, `corpus.json` supplies the exact ignored Rust commands for
compiled scalar/M4 differential execution. Those runs can fill the zero execution counters only
with retained artifacts and transcripts. They still cannot select a winner, allocate a consensus
identity, establish complete zero knowledge or composed PQ128/QROM security, or grant production
authority.
