# Frozen n15 two-branch wire report

This is an exact serializer skeleton, not an implemented proof, strict-security
claim, or frontier point. It fixes the following paper-valid parameters:

```text
original polynomial       15 B128 variables
degree-two ring switch    14 E256 variables
inverse-rate log R        3
fold arity theta          2 (theta divides 14)
queries                   160 independently sampled indices per branch
field / digest / salt     32 / 64 / 32 bytes
initial tree depth        14 + 3 + 1 - 2 = 16
later tree depths         14, 12, 10, 8, 6, 4
```

`theta=2` is intentional. The papers' benchmark value `theta=4` does not
divide the 14-variable packed polynomial; using it here would require the
paper's unstated remainder-round generalization.

## Shared immutable input commitment

The two branches keep independent, domain-separated 160-index lists. The
prover concatenates them into one 320-index opening call against the one input
root; it does not replace them by one shared 160-index list.

The pinned Merkle format selects cap height 9 for 320 indices and cap height 8
for 160 indices. With depth 16:

```text
one 320-index authentication
  ((16 - 9) * 320 + 2^9) * 64                  = 176,128

two 160-index authentications
  2 * ((16 - 8) * 160 + 2^8) * 64             = 196,608

four E256 values per opening
  320 * 4 * 32                                  = 40,960

BCS leaf salts
  320 * 32                                      = 10,240

one shared root                                 =     64
shared-input total                              = 227,392
two openings with one shared root               = 247,872
two entirely separate commitments               = 247,936
```

The common-layer serialization saves exactly 20,480 bytes versus two opening
records, and sharing the root saves another 64 bytes versus two commitments.
It does not reduce the 320 opened value records or 320 salts in the pinned
grammar.

The shared original commitment must contain enough Diamond high-coefficient
randomness for the complete union: `2 * 160 * 2^2 = 1,280` E256 coefficients.
One-branch padding of 640 coefficients is insufficient. Since 1,280 is below
`2^14`, the already-required extra domain bit has enough capacity.

## Complete declared-wire skeleton

Each branch additionally has one independent blind initial tree, six
challenge-dependent fold trees, and the following clear algebraic messages:

```text
branch blind initial tree                       = 123,968
branch six later trees                          = 347,520
s_hat (2), 14 sumcheck rounds (2 each),
blind evaluation (1), final (c0,c1) (2)         =   1,056
```

Therefore the full two-branch skeleton under this exact layout is:

```text
shared input + 2 * branch-local wire            = 1,172,480 bytes
same root but two input opening records          = 1,192,960 bytes
serialization saving                             =    20,480 bytes
```

These totals extend the pinned repeated-opening grammar with one BCS salt per
opened leaf. Repeated sampled indices remain repeated records, as in pinned
`send_openings`; no collision-dependent compression is assumed.

## Independence boundary

Sharing the root and serializing the union in one opening does not change the
two random experiments. The verifier retains both branch labels and both
independently sampled index lists, and checks every occurrence against the
same binding root. Natural cross-branch collisions may be represented once
only if the transcript also carries an unambiguous multiplicity/index map;
that is a lossless encoding, not shared randomness.

Intentionally reusing the same 160 query indices in both branches is not
admitted. It leaves the FRI/proximity miss event at one-set strength rather
than giving the product of two independent miss probabilities. All blind
trees, fold roots, challenges, algebraic messages, and terminal claims remain
branch-local. A theorem would be needed before co-committing those values.
