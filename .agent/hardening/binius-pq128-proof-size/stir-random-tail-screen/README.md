# STIR screen for the random-tail candidate

Status: source-only wire and theorem audit. It is not a PCS, a STIR port, a
zero-knowledge proof, or a strict-security result.

This screen replaces the random-padding experiment's optimistic `5q+2` field
message placeholder with the actual recursive shape of STIR. It pins the
authors' reference source at commit
`51064ebd45667dae3b499539f4476ba6d8527610` and uses the published/reference
factor-four fold and factor-two domain shrink. The canonical row uses the
paper's provable `s=1` OOD setting and a theorem-implied query lower bound: it
keeps `lambda+1` and the initial `sqrt(1.05*rho)` term but drops every positive
`eta` correction. Actual proven parameters can only be larger. The pinned Rust
prototype's `SoundnessType::Provable` helper instead uses `ceil(2*lambda/r)`
and hard-wires two OOD samples; those source fields are not promoted as the
paper's sufficient parameter setting. The screen then prices the requested
transport: one shared initial B128 commitment, two independently sampled E256
branches, four values per leaf, SHAKE256-448 or SHAKE256-512 digests, every
later root/opening/authentication path, the final
polynomial, a 64-byte fixed-profile parser header, the 1,920-byte local char-2
kernel, and the 128-byte fused ring switch.

The source references are:

- paper: <https://eprint.iacr.org/2024/390>;
- reference source: <https://github.com/WizardOfMenlo/stir/tree/51064ebd45667dae3b499539f4476ba6d8527610>;
- author parameter note: <https://gfenzi.io/blurbs/stir-parameters/>.

The canonical row omits the reference Rust prototype's `ans_polynomial` and
`shake_polynomial` because a size-minimal verifier can reconstruct both from
the already-opened values and OOD answers. The report separately prices those
serialized prototype fields. Neither row borrows the paper's reported
benchmark sizes.

The screen also uses STIR Remark 5.3's disjoint-domain optimization, which
removes every hole-fill oracle and its consistency openings. This is the
smallest published transcript shape; retaining hole fills only makes the no-go
larger.

The authoritative strict transport row uses 64-byte SHAKE256-512 proof roots
and nodes. It prices the direct classical BCS Lemma 3.4 salt screen separately
for every tree. For `n` power-of-two leaves, the lemma's privacy exponent gives
`salt_bytes = 130 + log2(n)` at a 128-bit target: 148 bytes at `n=2^18` and
147 bytes at `n=2^17`. A separate 32-byte-salt row is retained only as an
explicitly unproved compactness sensitivity, while the 56-byte SHAKE256-448 row
is legacy/non-strict.

Even the per-tree salt charge does not instantiate the direct theorem. Its one
parameter `lambda` must be both the digest output width and half the salt width.
The required `lambda` is 592 bits at `n=2^18`, while the strict digest is 512
bits. The common-parameter gate therefore remains false, as do the adaptive and
QROM simulator gates.

"Four symbols" always means four physical B128 symbols. An E256 value occupies
two such coefficient lanes, so a later STIR fold fibre of four E256 values
opens two physical leaves per branch query. The screen never packs four E256
values into one nominal four-symbol leaf.

## Hard theorem boundary

Published STIR folds over smooth multiplicative domains. The reference source
requires `FftField + PrimeField`, constructs radix-two multiplicative FFT
domains, and uses roots of unity, division by the fold size, and the power map
fibres. B128 and E256 have characteristic two; their multiplicative groups have
odd order and therefore no nontrivial power-of-two subgroup. The proposed
nonzero additive B128 coset is not an instantiation of that theorem. An
additive-FFT STIR analogue would need new folding, quotient/degree-correction,
distance, correlated-agreement, and extraction proofs.

The mixed-field seam is also not automatic. Once a B128 word is folded by an
E256 challenge, the next oracle is E256-valued. The screen therefore charges
two independent wide trees after the shared initial tree. Neither the paper nor
the reference source proves extraction for this B128-committed/E256-folded,
two-branch construction. Domain-separated challenges do not prove that two
132-bit errors multiply under one adversarial shared commitment.

## Zero-knowledge boundary

STIR is an IOPP, not a zero-knowledge compiler. Random high coefficients can
perfectly hide a *fixed* full-rank collection of linear views, but the Merkle
roots determine the Fiat-Shamir challenges and query schedule. STIR additionally
reveals OOD samples, later-oracle openings, and the final polynomial. Those
views are included in the conservative rank-capacity counter, but a post-hoc
rank count is not an adaptive simulator. Fresh per-leaf salts do not establish
BCS zero knowledge by themselves, especially in the QROM. A qualifying result
still needs an adaptive salted-BCS simulator, abort conditioning, a complete
observation matrix from the compiled relation, and a composed QROM proof.

## Run

From the repository root, without creating bytecode or allocating an oracle:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/stir-random-tail-screen/stir_screen.py \
      --check --report

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/stir-random-tail-screen/test_stir_screen.py \
      -v

Every security and authority flag remains false even if a hypothetical byte
row is below the cap.

## Exact no-go

For the authoritative SHAKE256-512/148-byte-salt transport, exhaustive search
over inverse rates `1/16` and `1/32` and every reachable factor-four stopping
degree finds:

- the smallest complete worst-case canonical transcript is the rate-`1/32`,
  two-round, stopping-degree-`2048` row with branch queries `(54,45)`: `403,392`
  bytes, exceeding `124,068` by `279,324` bytes; and
- the smallest authentication-free floor is the rate-`1/32`, three-round,
  stopping-degree-`512` row. Even after deleting **every** Merkle authentication
  node, its roots, opened values and salts, OOD replies, final E256 polynomial,
  parser header, char-2 kernel, and ring switch total `128,456` bytes, exceeding
  the raw cap by `4,388` bytes.

The second result is independent of canonical-path geometry. The full report
records its exact byte total and deficit. The 32-byte-salt SHAKE256-512 and
56-byte-hash rows are smaller sensitivity controls but remain over the cap and
are not strict profiles.
