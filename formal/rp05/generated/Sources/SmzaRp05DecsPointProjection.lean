import SmzaRp05PcsWireProjection

/-!
# Existing-proof DECS leaf indexes to field evaluation points

This is the deterministic disjoint-coset branch of
`decs_field_evaluation_points`. The 38 leaf indexes are produced by the
DECS-opening sampler from the existing PCS fields; neither the coset shift nor
the resulting field points is a serialized proof field. This file is source
only and is not a checked end-to-end verifier.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05DecsPointProjection

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PcsWireProjection

set_option autoImplicit false

def domainSize : Nat := 2 ^ 23
def searchLimit : Nat := 2 ^ 12

/-- The source's Goldilocks two-adic generator raised to `2^(32-23)`. -/
def radix2Root : Goldilocks := (0x185629dcda58878c : Goldilocks) ^ (2 ^ 9)

/-- Source predicate: the shifted subgroup must avoid every coordinate in
`0 .. interpolationCount`. Zero is automatically outside a nonzero coset. -/
def disjointCandidate (interpolationCount shift : Nat) : Bool :=
  decide (shift ≠ 0) &&
    decide (shift < SmzaRp05ExecutableChallengeStage.modulus) &&
    (List.range interpolationCount).all (fun point =>
      decide (point = 0 ∨
        (((point : Goldilocks) * (shift : Goldilocks)⁻¹) ^ domainSize ≠ 1)))

/-- The first admissible shift in the source's 4096-candidate bounded search.
Failure remains failure; no arbitrary shift is supplied by the caller. -/
def disjointCosetShift (interpolationCount : Nat) : Option Goldilocks := do
  if interpolationCount = 0 ∨ interpolationCount > domainSize then none else pure ()
  let candidate ← ((List.range searchLimit).map (interpolationCount + ·)).find?
    (disjointCandidate interpolationCount)
  pure (candidate : Goldilocks)

/-- Exact RP05 disjoint-coset point formula, rejecting out-of-domain leaves. -/
def fieldPoint (interpolationCount leafIndex : Nat) : Option Goldilocks := do
  if leafIndex ≥ domainSize then none else pure ()
  let shift ← disjointCosetShift interpolationCount
  pure (shift * radix2Root ^ leafIndex)

def fieldPoints (interpolationCount : Nat) (indexes : List Nat) :
    Option (List Goldilocks) :=
  indexes.mapM (fieldPoint interpolationCount)

/-- Compose the existing opening sampler with the deterministic field-point
projection. The sampled indexes, not caller-supplied point values, select the
LVCS evaluation coordinates. -/
def openingPointProgram (pending : Bool) (hPiop : V8SmzaOracleParser.RawDigest)
    (fields : DecodedPcsFields) (evalPoints : List Goldilocks)
    (rowScalars : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount : Nat) : Option (Program (List Goldilocks)) := do
  let sampler ← decsOpeningFromPcsFields pending hPiop fields evalPoints rowScalars
    packingFactor widths deltas beta lvcsCols tailCount
  pure (sampler.bind fun indexes =>
    .done (fieldPoints (lvcsCols + tailCount) indexes))

/-- Retain the sampled leaf indexes alongside their derived field points;
Merkle authentication uses the indexes, whereas LVCS uses the field points. -/
def openingIndexPointProgram (pending : Bool)
    (hPiop : V8SmzaOracleParser.RawDigest) (fields : DecodedPcsFields)
    (evalPoints : List Goldilocks)
    (rowScalars : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount : Nat) :
    Option (Program (List Nat × List Goldilocks)) := do
  let sampler ← decsOpeningFromPcsFields pending hPiop fields evalPoints rowScalars
    packingFactor widths deltas beta lvcsCols tailCount
  pure (sampler.bind fun indexes =>
    .done ((fieldPoints (lvcsCols + tailCount) indexes).map
      (fun points => (indexes, points))))

end HegemonCrypto.SmallWood.SmzaRp05DecsPointProjection
