import SmzaRp05ExecutableChallengeStage
import HegemonCrypto.SmallWoodTranscript

/-!
# Current RP05 PCS proof-field projection

This is the wire-to-mathematics prefix of PCS reconstruction. It adds no
serialized fields: it decodes the existing `PcsProof` matrices
`partial_evals`, `rcombi_tails`, and `subset_evals` into canonical field words.
The opening points and row scalars remain verifier inputs to this component.
It computes combination heads from the decoded partials and feeds those heads
and decoded tails to the DECS-opening hash. LVCS rows and the final PCS/PIOP
transcript are not reconstructed here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection

open SmzaRp05ExecutableChallengeStage (FieldWord canonicalWord)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open HegemonCrypto.CanonicalBytes
open scoped BigOperators

set_option autoImplicit false

abbrev FieldMatrix := List (List FieldWord)

/-- Decode one serialized field-word list, rejecting every noncanonical word. -/
def decodeFieldWords : List Nat → Option (List FieldWord)
  | [] => some []
  | word :: rest => do
      let decoded ← canonicalWord word
      let tail ← decodeFieldWords rest
      pure (decoded :: tail)

/-- Decode an existing row-major PCS matrix without changing its wire order. -/
def decodeFieldMatrix : List (List Nat) → Option FieldMatrix
  | [] => some []
  | row :: rest => do
      let decodedRow ← decodeFieldWords row
      let decodedRest ← decodeFieldMatrix rest
      pure (decodedRow :: decodedRest)

/-- Exact existing PCS wire payloads used by `pcs_recompute_transcript`.
The DECS payload remains separately decoded by its existing proof grammar. -/
structure DecodedPcsFields where
  partialEvals : FieldMatrix
  rcombiTails : FieldMatrix
  subsetEvals : FieldMatrix
deriving DecidableEq

/-- Source-shaped projection from the three matrices of `PcsProof`. -/
def decodePcsFields (partialEvals rcombiTails subsetEvals : List (List Nat)) :
    Option DecodedPcsFields := do
  let partialEvals ← decodeFieldMatrix partialEvals
  let rcombiTails ← decodeFieldMatrix rcombiTails
  let subsetEvals ← decodeFieldMatrix subsetEvals
  pure ⟨partialEvals, rcombiTails, subsetEvals⟩

/-- The verifier obtains these scalars from the existing
`opened_witness.RowScalars` variant, not from a new PCS witness/certificate. -/
structure DecodedMiddleWire where
  pcs : DecodedPcsFields
  rowScalars : FieldMatrix
deriving DecidableEq

def decodeMiddleWire (partialEvals rcombiTails subsetEvals
    openedRowScalars : List (List Nat)) : Option DecodedMiddleWire := do
  let pcs ← decodePcsFields partialEvals rcombiTails subsetEvals
  let rowScalars ← decodeFieldMatrix openedRowScalars
  pure ⟨pcs, rowScalars⟩

/-- One genuine decoder equation: a serialized first word is admitted exactly
when its canonical field conversion succeeds, after which the tail is decoded
in source order. -/
theorem decodeFieldWords_cons (word : Nat) (rest : List Nat) :
    decodeFieldWords (word :: rest) = (do
      let decoded ← canonicalWord word
      let tail ← decodeFieldWords rest
      pure (decoded :: tail)) := rfl

/-- Exact composition order of the three extant PCS wire matrices. -/
theorem decodePcsFields_steps
    (partialEvals rcombiTails subsetEvals : List (List Nat)) :
    decodePcsFields partialEvals rcombiTails subsetEvals = (do
      let partialRows ← decodeFieldMatrix partialEvals
      let tails ← decodeFieldMatrix rcombiTails
      let subset ← decodeFieldMatrix subsetEvals
      pure ⟨partialRows, tails, subset⟩) := rfl

/-- The first coefficient of one unstacked combination polynomial.  This is
the head equation in `pcs_reconstruct_combi_heads`: the row scalar minus each
decoded partial evaluation times its protocol power. Source `r_to_mu` starts
at `evalPoint` and applies the half-open Rust loop `1..packingFactor`, giving
`evalPoint ^ packingFactor`; each nonfinal power is advanced before use. -/
def reconstructHeadZero (evalPoint : Goldilocks) (packingFactor delta : Nat)
    (rowScalar : Goldilocks) (partials : List Goldilocks) : Goldilocks :=
  rowScalar - ∑ index ∈ Finset.range partials.length,
    partials.getD index 0 * evalPoint ^ (index * packingFactor +
      (if index + 1 = partials.length then packingFactor - delta else packingFactor))

/-- Source equation for the head at a given PCS evaluation point. -/
theorem reconstructHeadZero_eq_sub_weighted_partials
    (evalPoint : Goldilocks) (packingFactor delta : Nat)
    (rowScalar : Goldilocks) (partials : List Goldilocks) :
    reconstructHeadZero evalPoint packingFactor delta rowScalar partials =
      rowScalar - ∑ index ∈ Finset.range partials.length,
        partials.getD index 0 * evalPoint ^ (index * packingFactor +
          (if index + 1 = partials.length then packingFactor - delta else packingFactor)) := rfl

/-- One-partial specialization of the verifier's head-zero recurrence. -/
theorem reconstructHeadZero_single_partial
    (evalPoint : Goldilocks) (packingFactor delta : Nat)
    (rowScalar partialValue : Goldilocks) :
    reconstructHeadZero evalPoint packingFactor delta rowScalar [partialValue] =
      rowScalar - partialValue * evalPoint ^ (packingFactor - delta) := by
  simp [reconstructHeadZero]

/-- With two decoded partials, the first is weighted by `x^p` and the last
by `x^(2p-delta)`, exactly following the source's update-before-use loop. -/
theorem reconstructHeadZero_two_partials
    (evalPoint : Goldilocks) (packingFactor delta : Nat)
    (rowScalar first second : Goldilocks) :
    reconstructHeadZero evalPoint packingFactor delta rowScalar [first, second] =
      rowScalar - (first * evalPoint ^ packingFactor +
        second * evalPoint ^ (packingFactor + (packingFactor - delta))) := by
  simp [reconstructHeadZero, Finset.sum_range_succ]

/-- Traverse one source row in configured polynomial order. Width `w` consumes
`w-1` entries from the flattened `partial_evals` row. Malformed widths,
insufficient partials, excess trailing partials, and invalid deltas reject. -/
def reconstructUnstackedRow (evalPoint : Goldilocks) (packingFactor : Nat) :
    List Nat → List Nat → List Goldilocks → List Goldilocks → Option (List Goldilocks)
  | [], [], [], [] => some []
  | width :: widths, delta :: deltas, scalar :: scalars, partials =>
      if width = 0 ∨ delta > packingFactor then none
      else
        let count := width - 1
        let current := partials.take count
        if current.length ≠ count then none
        else do
          let rest ← reconstructUnstackedRow evalPoint packingFactor
            widths deltas scalars (partials.drop count)
          pure (reconstructHeadZero evalPoint packingFactor delta scalar current ::
            current ++ rest)
  | _, _, _, _ => none

/-- On a single configured polynomial, successful traversal exposes the
computed row-scalar-minus-weighted-partials head as its first output. -/
theorem reconstructed_single_polynomial_head
    (evalPoint : Goldilocks) (packingFactor width delta : Nat)
    (scalar : Goldilocks) (partials : List Goldilocks)
    (length_eq : partials.length = width - 1)
    (validWidth : width ≠ 0) (validDelta : delta ≤ packingFactor) :
    reconstructUnstackedRow evalPoint packingFactor [width] [delta] [scalar] partials =
      some (reconstructHeadZero evalPoint packingFactor delta scalar partials :: partials) := by
  have taken : partials.take (width - 1) = partials := by
    rw [← length_eq]
    exact List.take_length (l := partials)
  have dropped : partials.drop (width - 1) = [] := by
    rw [← length_eq]
    simp
  simp [reconstructUnstackedRow, validWidth, validDelta, length_eq, taken, dropped]

/-- Chunk one unstacked row into the source's beta consecutive head blocks,
zero-padding the last block to `lvcsCols`. -/
def paddedChunk (lvcsCols offset : Nat) (unstacked : List Goldilocks) :
    List Goldilocks :=
  let chunk := (unstacked.drop offset).take lvcsCols
  chunk ++ List.replicate (lvcsCols - chunk.length) 0

def chunkHeads (beta lvcsCols : Nat) (unstacked : List Goldilocks) :
    List (List Goldilocks) :=
  (List.range beta).map fun index => paddedChunk lvcsCols (index * lvcsCols) unstacked

/-- The source takes each `beta × lvcsCols` block from the unstacked vector. -/
def reconstructedCombiHeads (beta lvcsCols : Nat) (unstacked : List Goldilocks) :
    List (List Goldilocks) :=
  chunkHeads beta lvcsCols unstacked

def fieldWordsToGoldilocks (words : List FieldWord) : List Goldilocks :=
  words.map fun word => word.val

/-- Reconstruct one opening-evaluation row directly from the decoded PCS
partial-evaluation matrix and the row-scalar matrix. The point and fixed
protocol shape are verifier inputs, not precomputed head values. -/
def reconstructDecodedPcsRow (fields : DecodedPcsFields)
    (evalPoints : List Goldilocks) (rowScalars : List (List FieldWord))
    (evaluationIndex : Nat) (packingFactor : Nat)
    (widths deltas : List Nat) : Option (List Goldilocks) :=
  match evalPoints[evaluationIndex]?, rowScalars[evaluationIndex]?,
      fields.partialEvals[evaluationIndex]? with
  | some point, some scalars, some partials =>
      reconstructUnstackedRow point packingFactor widths deltas
        (fieldWordsToGoldilocks scalars) (fieldWordsToGoldilocks partials)
  | _, _, _ => none

/-- The source's `j * beta + i` output order is the beta consecutive chunks
of each successfully reconstructed unstacked evaluation row. -/
def reconstructedHeadsForRow (fields : DecodedPcsFields)
    (evalPoints : List Goldilocks) (rowScalars : List (List FieldWord))
    (evaluationIndex : Nat) (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols : Nat) : Option (List (List Goldilocks)) := do
  if beta = 0 ∨ lvcsCols = 0 then none else pure ()
  let row ← reconstructDecodedPcsRow fields evalPoints rowScalars evaluationIndex
    packingFactor widths deltas
  pure (reconstructedCombiHeads beta lvcsCols row)

/-- Compute every head in source `j * beta + i` order. Exact matrix heights
reject excess or missing proof rows before a transcript can be formed. -/
def reconstructedHeadsAll (fields : DecodedPcsFields)
    (evalPoints : List Goldilocks) (rowScalars : List (List FieldWord))
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols : Nat) : Option (List (List Goldilocks)) := do
  if rowScalars.length ≠ evalPoints.length ∨
      fields.partialEvals.length ≠ evalPoints.length then none else pure ()
  let rows ← (List.range evalPoints.length).mapM fun index =>
    reconstructedHeadsForRow fields evalPoints rowScalars index
      packingFactor widths deltas beta lvcsCols
  pure rows.flatten

/-- Strictly zip the configured number of combination heads and DECS-opening
tails. Every row must have its source-configured width; malformed dimensions
reject rather than silently defaulting as a list lookup would. -/
def openingRowsWords : Nat → Nat → Nat → List (List Goldilocks) →
    List (List FieldWord) → Option (List Nat)
  | 0, _, _, [], [] => some []
  | count + 1, cols, tailCount, head :: heads, tail :: tails =>
      if head.length ≠ cols ∨ tail.length ≠ tailCount then none
      else do
        let rest ← openingRowsWords count cols tailCount heads tails
        pure ((head.map fun word => word.val) ++
          (tail.map fun word => word.val) ++ rest)
  | _, _, _, _, _ => none

/-- For one configured combination, its head words precede its tail words. -/
theorem openingRowsWords_one (cols tailCount : Nat)
    (head : List Goldilocks) (tail : List FieldWord) (headShape : head.length = cols)
    (tailShape : tail.length = tailCount) :
    openingRowsWords 1 cols tailCount [head] [tail] =
      some (head.map (fun word => word.val) ++ tail.map (fun word => word.val)) := by
  simp [openingRowsWords, headShape, tailShape]

/-- Rust `hash_challenge_opening_decs` input words: the eight LE words of
`h_piop`, then each combination head immediately followed by its matching tail. -/
def decsOpeningWords (hPiop : RawDigest) (count cols tailCount : Nat)
    (heads : List (List Goldilocks)) (tails : List (List FieldWord)) : Option (List Nat) := do
  let rows ← openingRowsWords count cols tailCount heads tails
  pure (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows)

/-- Exact transcript word ordering before the DECS-opening domain frame. -/
theorem decsOpeningWords_order (hPiop : RawDigest) (count cols tailCount : Nat)
    (heads : List (List Goldilocks)) (tails : List (List FieldWord)) :
    decsOpeningWords hPiop count cols tailCount heads tails =
      (openingRowsWords count cols tailCount heads tails).map
        (fun rows => SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows) := by
  cases rows : openingRowsWords count cols tailCount heads tails with
  | none => simp [decsOpeningWords, rows]
  | some values => simp [decsOpeningWords, rows]

def decsOpeningInput (hPiop : RawDigest) (count cols tailCount : Nat)
    (heads : List (List Goldilocks)) (tails : List (List FieldWord)) : Option RawInput := do
  let words ← decsOpeningWords hPiop count cols tailCount heads tails
  pure (V8SmzaOracleParser.framedInput SmallWoodTranscript.decsOpeningDomain
    (words.flatMap (encodeLE 8)))

/-- Hash the computed head/tail transcript through the abstract verifier's
actual oracle program, then run the existing capped opening sampler. The
opening digest is obtained from `Program.ask`; it is not a caller argument. -/
def decsOpeningQueryProgram (pending : Bool) (hPiop : RawDigest)
    (count cols tailCount : Nat) (heads : List (List Goldilocks))
    (tails : List (List FieldWord)) :
    Option (Program (List Nat)) := do
  let input ← decsOpeningInput hPiop count cols tailCount heads tails
  pure ((SmzaRp05ExecutableMerkleVerifier.ask input).bind fun openingDigest =>
    SmzaRp05ExecutableChallengeStage.queryProgram pending openingDigest)

/-- No caller-supplied combination heads: all opening words now come from the
decoded existing PCS matrices, public configuration, and computed row scalars. -/
def decsOpeningFromPcsFields (pending : Bool) (hPiop : RawDigest)
    (fields : DecodedPcsFields) (evalPoints : List Goldilocks)
    (rowScalars : List (List FieldWord)) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount : Nat) :
    Option (Program (List Nat)) := do
  let heads ← reconstructedHeadsAll fields evalPoints rowScalars
    packingFactor widths deltas beta lvcsCols
  decsOpeningQueryProgram pending hPiop (evalPoints.length * beta)
    lvcsCols tailCount heads fields.rcombiTails

/-- Wire-facing entry: there is no separately supplied head, tail, or scalar
matrix. The existing proof's four row-major matrices are decoded first. -/
def decsOpeningFromWire (pending : Bool) (hPiop : RawDigest)
    (partialEvals rcombiTails subsetEvals openedRowScalars : List (List Nat))
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount : Nat) :
    Option (Program (List Nat)) := do
  let wire ← decodeMiddleWire partialEvals rcombiTails subsetEvals openedRowScalars
  decsOpeningFromPcsFields pending hPiop wire.pcs evalPoints wire.rowScalars
    packingFactor widths deltas beta lvcsCols tailCount

/-- The first reconstructed head is the first `lvcsCols` entries of the
unstacked vector, with source-compatible zero padding. -/
theorem first_chunk_heads (lvcsCols : Nat) (unstacked : List Goldilocks) :
    (chunkHeads 1 lvcsCols unstacked).head? =
      some (paddedChunk lvcsCols 0 unstacked) := by
  simp [chunkHeads, paddedChunk]

end HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection
