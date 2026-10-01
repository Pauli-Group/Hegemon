import SmzaRp05ExecutablePcsClosureStages
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-!
# Source opening fields projected from the current decoded proof

This module gives the source-shaped view of the exact 40 partial-evaluation
words in each decoded PCS opening row: five nonlinear groups of seven words,
then five linear words.  The row scalars are the same decoded `opened_witness`
field used by the execution's PIOP suffix.  These are projections, not fresh
opening values or caller-supplied relation evidence.

The remaining (separate) algebraic obligation is to prove that the successful
736-entry `reconstructUnstackedRow` result, chunked into the two PCS heads,
equals `reconstructedColumnEvaluations` for these projected fields.  This
module deliberately does not claim that equation until its list/chunk
readback is proved.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningView

open HegemonCrypto.SmallWood (Goldilocks)
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator

set_option autoImplicit false

private def zeroFieldWord : SmzaRp05ExecutableChallengeStage.FieldWord :=
  ⟨0, by decide⟩

/-- Read a canonical decoded PCS partial word in its original row-major
serialization order.  Successful fixed-shape reconstruction guards make the
fallback unreachable for the indices used by the opening view. -/
def decodedPartialWord (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (opening index : Nat) :
    SmzaRp05ExecutableChallengeStage.FieldWord :=
  ((pcs.partialEvals.getD opening []).getD index zeroFieldWord)

/-- The source PCS view is exactly the first 35 values (five 7-column
nonlinear rows) and final five values (five linear rows) of each 40-word
`partial_evals` opening row. -/
def sourcePcsViewOfDecoded (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields) :
    HegemonCrypto.SmallWood.V8Smz9EagerPrivacy.SourcePcsView Goldilocks :=
  (fun polynomial opening column =>
    (decodedPartialWord pcs opening.val (7 * polynomial.val + column.val)).val,
   fun polynomial opening =>
    (decodedPartialWord pcs opening.val (35 + polynomial.val)).val)

@[simp] theorem sourcePcsViewOfDecoded_nonlinear
    (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (polynomial : Fin 5) (opening : Fin 6)
    (column : Fin 7) :
    (sourcePcsViewOfDecoded pcs).1 polynomial opening column =
      (decodedPartialWord pcs opening.val (7 * polynomial.val + column.val)).val := rfl

@[simp] theorem sourcePcsViewOfDecoded_linear
    (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (polynomial : Fin 5) (opening : Fin 6) :
    (sourcePcsViewOfDecoded pcs).2 polynomial opening =
      (decodedPartialWord pcs opening.val (35 + polynomial.val)).val := rfl

/-- The source simulator's flattened 40-entry partial-evaluation row reads
back the canonical decoded PCS row without reordering either region. -/
theorem source_partial_nonlinear_readback
    (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields) (opening : Fin 6)
    (polynomial : Fin 5) (column : Fin 7) :
    sourcePartialEvaluations (sourcePcsViewOfDecoded pcs) opening
        (Fin.castAdd 5 (finProdFinEquiv (polynomial, column))) =
      (decodedPartialWord pcs opening.val (7 * polynomial.val + column.val)).val := by
  rw [source_partial_nonlinear_index]
  rfl

theorem source_partial_linear_readback
    (pcs : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (opening : Fin 6) (polynomial : Fin 5) :
    sourcePartialEvaluations (sourcePcsViewOfDecoded pcs) opening
        (Fin.natAdd 35 polynomial) =
      (decodedPartialWord pcs opening.val (35 + polynomial.val)).val := by
  rw [source_partial_linear_index]
  rfl

/-- The actual current PIOP decoder supplies the source witness and masks;
their split is the verifier's 686/5/5 layout, not a new sample. -/
def sourceWitnessOfDecoded
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    V8Smz9ZeroKnowledge.WitnessOpeningView Goldilocks :=
  SmzaRp05ExecutableReconstruction.witness piop

def sourceMasksOfDecoded
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    HegemonCrypto.SmallWood.V8Smz9EagerSimulator.MaskOpeningValues Goldilocks :=
  SmzaRp05ExecutableReconstruction.masks piop

/-! A generic factorization of the configured row traversal follows. It
preserves the exact source row list and the unconsumed partial suffix, so
successive applications can expose the 686 + 5 + 5 protocol regions without
proving a separate, assumed row certificate. -/

/-- Run `n` consecutive source polynomials of one width/delta, retaining the
remaining partial-evaluation suffix for the next configured region. -/
def reconstructRepeated (point : Goldilocks) (packingFactor width delta : Nat) :
    List Goldilocks → List Goldilocks → Option (List Goldilocks × List Goldilocks)
  | [], partials => some ([], partials)
  | scalar :: scalars, partials =>
      if width = 0 ∨ delta > packingFactor then none else
        let count := width - 1
        let current := partials.take count
        if current.length ≠ count then none else do
          let (rest, remaining) ← reconstructRepeated point packingFactor width delta
            scalars (partials.drop count)
          pure (SmzaRp05PcsWireProjection.reconstructHeadZero point packingFactor
            delta scalar current ::
            current ++ rest, remaining)

private theorem take_partial_row_is_short_iff
    (partials : List Goldilocks) (width : Nat) (widthPositive : 0 < width) :
    (partials.take (width - 1)).length ≠ width - 1 ↔
      partials.length + 1 < width := by
  simp only [List.length_take]
  omega

/-- Width-one witness cells consume no PCS partials and are copied verbatim. -/
theorem reconstructRepeated_singleton_witness
    (point : Goldilocks) (rows partials : List Goldilocks) :
    reconstructRepeated point 64 1 0 rows partials = some (rows, partials) := by
  induction rows with
  | nil => rfl
  | cons scalar rows ih =>
      simp [reconstructRepeated, SmzaRp05PcsWireProjection.reconstructHeadZero, ih]

/-- Exact list-result factorization of the executable row traversal for a
fixed-width region. The only side condition says how many source scalar rows
are in this region; the option result and all consumed/dropped partial words
are calculated by the executable recursion itself. -/
theorem reconstructUnstackedRow_repeat
    (point : Goldilocks) (packingFactor width delta n : Nat)
    (widths deltas : List Nat) (scalars followingScalars partials : List Goldilocks)
    (scalarLength : scalars.length = n) :
  SmzaRp05PcsWireProjection.reconstructUnstackedRow point packingFactor
        (List.replicate n width ++ widths) (List.replicate n delta ++ deltas)
        (scalars ++ followingScalars) partials =
      (reconstructRepeated point packingFactor width delta scalars partials).bind
        (fun result =>
          (SmzaRp05PcsWireProjection.reconstructUnstackedRow
            point packingFactor widths deltas
            followingScalars result.2).map (fun suffix => result.1 ++ suffix)) := by
  induction n generalizing scalars partials with
  | zero =>
      have scalarsNil : scalars = [] := List.eq_nil_of_length_eq_zero scalarLength
      subst scalars
      simp [reconstructRepeated]
  | succ n ih =>
      cases scalars with
      | nil => simp at scalarLength
      | cons scalar scalars =>
          have tailLength : scalars.length = n := by simp at scalarLength; omega
          simp only [List.replicate_succ]
          by_cases bad : width = 0 ∨ delta > packingFactor
          · simp [SmzaRp05PcsWireProjection.reconstructUnstackedRow,
              reconstructRepeated, bad]
          · have widthNonzero : width ≠ 0 := by
              intro h
              exact bad (Or.inl h)
            have widthPositive : 0 < width := by omega
            have shortIff := take_partial_row_is_short_iff partials width widthPositive
            by_cases short : (partials.take (width - 1)).length ≠ width - 1
            · have tooShort : partials.length + 1 < width := shortIff.mp short
              simp [SmzaRp05PcsWireProjection.reconstructUnstackedRow,
                reconstructRepeated, bad, tooShort]
            · have enough : ¬ partials.length + 1 < width := by
                intro tooShort
                exact short (shortIff.mpr tooShort)
              simp [SmzaRp05PcsWireProjection.reconstructUnstackedRow,
                bad, enough]
              have recursiveIH := ih scalars (partials.drop (width - 1)) tailLength
              rw [recursiveIH]
              cases regional : reconstructRepeated point packingFactor width delta
                  scalars (partials.drop (width - 1)) with
              | none =>
                  simp [reconstructRepeated, bad, enough, regional]
              | some pair =>
                  cases suffix : SmzaRp05PcsWireProjection.reconstructUnstackedRow
                      point packingFactor widths deltas followingScalars pair.2 with
                  | none =>
                      simp [reconstructRepeated, bad, enough, regional, suffix]
                  | some rest =>
                      simp [reconstructRepeated, bad, enough,
                        regional, suffix, List.append_assoc]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningView
