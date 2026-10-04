# Aurora all-W64 PQ128 screen

Status: **valid negative/conditional screen; fail closed**. Aurora is not the
tournament leader, `proof_bytes` is null, and every architecture and production
gate is false.

## Verdict

Aurora remains a serious theorem-level challenger because its zero-knowledge
claim is real whole-view zero knowledge, not witness obfuscation. Definition
4.4 requires identical distributions for every bounded-query verifier, uses a
straightline simulator, and explicitly permits queries during the interaction.
Theorem 9.2 gives a binary-field R1CS IOP with perfect zero knowledge against
`b` queries.

That positive result does not close the requested NIZK:

- no exact characteristic-two full Hegemon R1CS exists;
- no inspected source proves round-by-round soundness for the complete Aurora
  IOP;
- the modified-BCS finite-QROM theorem therefore does not apply concretely;
- the current source-projection BCS privacy floor rules out every 512-bit
  digest even before the missing composition terms are charged;
- pinned libiop has no canonical binary/non-algebraic proof serializer or
  parser and no SHA-512/SHAKE backend;
- proof parameters, physical proof-hash calls, proof bytes, verifier
  refinement, and consensus binding are all absent.

## Exact Aurora theorem boundary

For binary-field R1CS with `m` constraints and `n` variables, Theorem 9.2
requires

    2*max(m,n+1)+2*b <= rho*|L|

and prints the total IOP oracle length

    p_symbols = (4+2*lambda_i+(lambda_i_prime*lambda_i_FRI)/3)*|L|.

It gives

    epsilon_i = ((m+1)/|F|)^lambda_i
              + (|L|/|F|)^lambda_i_prime
              + epsilon_i_FRI(F,L)^lambda_i_FRI

    epsilon_q = epsilon_q_FRI(L,rho,delta)^lambda_q_FRI

    delta = min((1-2*rho)/2,(1-rho)/3,1-rho).

For the proven FRI bound, the bases are `3|L|/|F|` and
`1-min(delta,(1-3rho-2^eta/sqrt(|L|))/4)`. Setting `b>=q_pi` gives the
honest-verifier query allowance. The theorem leaves the round count and query
complexity in big-O form; this package leaves their constants and every
selected parameter null.

The printed `p_symbols` equation is retained exactly as an uninstantiated core
expression. It is not compressed BCS proof bytes and is not a lower or upper
bound on the canonical Hegemon wire.

## Complete-ZK digest-width no-go

BCS16 Lemma 7.5 gives the exact statistical privacy loss

    z'(x,lambda) = z(x) + p_bits*2^(-lambda/4+2),

where `p_bits` is total IOP proof length in bits. For Aurora's perfect IOP ZK,
`z=0` when the exact premises hold.

The upstream all-W64 input is red-team rejected as an executable relation: its
`m=29,509,133` is an anonymous source-static macro projection, not sparse
binary matrices. Subsequent macro edits target the V2 context but do not supply
accepted sparse-matrix or native-parent refinement. The following is therefore
only a conditional screen for an adapter retaining at least that many rows.

Meaningful proven-FRI query soundness needs `rho<1/2`. Theorem 9.2 then forces
`|L|>4m`, hence power-of-two `|L|>=2^27`. A disjoint affine `L` and nonempty
`H` require a binary field of at least 28 bits. Even using the minimum
coefficient four in the printed oracle-length expression gives

    p_bits >= 4 * 2^27 * 28 = 15,032,385,536.

At `lambda=512`, the direct privacy term has at most
`126-log2(p)=92.192645077943` security bits. Lambda 656 is the first
multiple-of-four and byte-aligned output that passes this floor term alone.

Pinned libiop exposes only GF(2^64), GF(2^128), GF(2^192), and GF(2^256).
Their theorem-compatible multiple-of-four floor-only minima are 664, 668, 668,
and 672 bits; the byte-aligned minima are 664, 672, 672, and 672 bits. Thus
SHA-512 and BLAKE2b-512 are insufficient even for the smallest supported field
under this projection. A longer SHAKE output is not a certificate: exact
`p_bits`, the actual required lambda, capacity/domain separation, a backend,
and a concrete QROM bridge remain null.

These IOP-length floors are used only for the BCS privacy theorem. They are not
proof-byte claims because the BCS Merkle layer commits to, rather than carries,
the full oracle strings.

## Whole-protocol QROM soundness gap

CMS19 Theorem 8.6 requires round-by-round soundness of the complete underlying
IOP and gives the shape

    O(T^2*epsilon_RBR + T^3/2^lambda)

for an attacker making at most `T-O(q log ell)` QRO queries. The big-O constant
and augmented-query constant are not exposed, so both remain null.

The 2023 FRI analysis proves RBR results for FRI, batched FRI, and a stated
delta-correlated class including Plonk-like protocols. It does not identify
Aurora. The generalized-special-soundness paper supplies an implication to
generalized RBR soundness, but no inspected result proves Aurora's algebraic
core satisfies that premise. Preon Conjectures 4.7, 4.11, and 4.12 explicitly
leave the Aurora state-restoration/RBR knowledge chain conjectural.

CMS Appendix B gives a generic fallback `mu^(1/(k+1))` from ordinary soundness
`mu` for a `k`-round IOP. Aurora supplies only `k=O(log|L|)` here, and no full
parameter profile fixes `mu`; the fallback is therefore symbolic, not a finite
retained security term. FRI component RBR is never promoted to whole-Aurora
RBR.

## Exact relation boundary

The source-static all-W64 schedule does cover 16 activity masks, five
authorization modes, stablecoin/manifest families, 90 relation-level
BLAKE2b-512 calls, and 213 compressions. Its statement, verifier context, and
private transport are 1,141, 72, and 11,000 bytes.

An attempted characteristic-two macro expansion reports `m=37,364,095`,
`n=21,531,353`, `l=9,704`, and `nnz=156,526,483`. Its Aurora padding projection
is `H1=2^26`, `H2=2^25`, and `k'=16,383` public inputs, obtained by injecting
6,679 canonical public zeros and shifting all private/derived indices by the
same amount. These numbers are retained only as an unfrozen macro projection:
the typed IR never froze and no verified IR-to-binary-sparse lowering or
concrete `A/B/C` coordinates exist. They are not used for the BCS privacy floor,
proof parameters, or bytes.

The decisive missing items are a frozen typed IR and mutation-residual
certificate; materialized canonical `A/B/C` rows tying all 90 semantic calls
and seven V2 authority compressions to coordinates; sparse-matrix rejection of
the four former host predicates; scalar/source-macro-to-binary refinement; a
selected `GF(2^s)` and irreducible polynomial with adequate dimension; proof of
libiop's shifted-domain disjointness; and refinement from
`manifest_root64||parent_height` to authenticated native parent state. The
frozen odd-field matrices cannot be reinterpreted in characteristic two.

## Pinned implementation boundary

The inspected official MIT-licensed libiop revision is
`a2ed2ec2f3e85f29b6035951553b02cb737c817a`. Its static Aurora include closure
is 113 files, 18,818 lines, and 783,493 bytes before libff, libfqfft,
libsodium, and C++/system dependencies. It was not built or linked. It is useful
research code, not a production wire:

- its README says final transcript serialization is missing;
- binary-field or non-algebraic serialization/deserialization prints
  “not implemented”;
- the logical size counter omits query positions and all codec framing;
- only BLAKE2b and Poseidon are wired; SHA-512 and SHAKE are absent;
- BLAKE2b output is `2*security_parameter` bits but is capped at 512 bits;
- field elements are hashed as raw in-memory objects and canonical encoding is
  unresolved;
- profiler support is GF64/128/192/256 and defaults to heuristic FRI;
- the code adds proof-of-work and selectively salts rounds without an exact
  theorem/refinement for this profile.

Consequently, the exact proof-backend Merkle, hashchain, salt, squeeze,
proof-of-work, SHA-512, and SHAKE call counts all remain null. The 90/213
semantic relation counts do not fill those fields.

## Composition and comparison

The canonical certificate lists separate PCS, IOP, Fiat-Shamir, hash,
grinding/RNG, and union terms. Every value is null, never silently zero. The
overall advantage and composed security bits are null.

The CFW26 105-oracle carrier remains theorem-ineligible: its printed endpoint
`st2=(0,1,0,...)` reads coefficient one rather than evaluating at one, so the
honest polynomial `s=X^2-X` fails; repairs also need `st2=pow(1)` and explicit
`row_M(M,alpha)`. ProveKit remains ineligible because witness hiding is
disabled and its transcript/MMCS surface is 256-bit. Historical Aurora
40–130 KiB results are neither the same relation nor a strict-QROM profile and
are excluded from ranking.

## Claim boundary

`certificate.json` is a canonical negative/conditional architecture receipt.
It proves no exact relation, proof, byte bound, complete NIZK, composed PQ128
security, parser, verifier refinement, consensus lifecycle, or production
authority. All of those gates remain false.
