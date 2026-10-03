# Calculated decoded rows to the current PIOP candidate

Date: 2026-09-07. This is a source-derived finite-experiment result, not an
accepted-byte extractor, a raw Fiat–Shamir theorem, or production authority.

## Result

`SmallWoodV8Smz9DecodedPolynomialSource.lean` constructs the actual PIOP
candidate from an arbitrary calculated DECS polynomial object. No honest
prover coins, polynomial-degree receipt, relation-validity premise, or
post-batching witness selection is supplied.

The construction evaluates the 140 decoded row polynomials at original
head positions 20 through 387, reverses the 70-by-736 source stack, and uses
the resulting cells as column coefficients. Taking those coefficients and
restacking recovers every original head exactly. All 736 column polynomials
have degree at most 69.

The first 686 columns are the witness polynomials. The five nonlinear masks
use the source shifts `0,64,128,192,256,320,384,419`, giving degree at most
488 even for arbitrary decoded columns. The five linear masks use shifts
0 and 63, giving degree at most 132. These are the actual shortened final
shifts, not an assumed cancellation between honest masking coins.

The calculated packed witness is its 686-by-64 row-major evaluation at the
canonical packing points, with canonical natural representatives. Both its
length/field bounds and its exact field-evaluation correspondence are proved.

## Actual unbatched source system

The PIOP candidate uses all 830 current nonlinear roots and every retained
normalized CSR row from `CurrentPublicContext`. It uses the actual common
width `max 830 retainedRows`, with zero padding of the shorter family.
Each linear polynomial is constructed from that row's exact dense public
coefficients and canonical packing Lagrange polynomials. The degree bounds
are discharged by construction, before any gamma matrix is given.

Full satisfaction of this generated candidate implies every actual nonlinear
root vanishes on the calculated packed lanes and every retained normalized
CSR equation holds on that same packed witness. Consequently, failure of
this explicit unbatched source relation has finite PIOP acceptance probability
at most `p^-5 + epsilon3`, for any matrix-dependent response selected before
the fresh admissible six-point tuple.

## Remaining boundary

This is not yet a theorem that arbitrary accepted proof bytes produce this
candidate or satisfy its opening equations. It does not by itself prove the
converse from normalized field equations to complete interpreter acceptance,
including public compiler guards and impossible-empty-row normalization.
Those bindings, the unrestricted MCA budget, actual raw challenge sampling,
coherent extraction, semantic adequacy, and full quantum composition remain
separate obligations. No runtime or proof format was changed.

## Verification

The complete 303-line module passed the following warm strict command at
approximately 17:49 UTC on 2026-09-07:

    cd formal/crypto
    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9DecodedPolynomialSource.lean

The coordinator will add principal roots to the integrated axiom audit only
after caching this frozen source. No new axiom, executable proof bypass, or
placeholder is permitted. Original generated program files and wire vectors
remain unchanged.
