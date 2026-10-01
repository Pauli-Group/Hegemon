import SmzaRp05ExecutablePcsClosureStages

/-! Successful configured PCS reconstruction consumes exactly its partial
words. This derives the 40-word row shape from the executable guards, not
from a caller-supplied shape certificate. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsPartialLength

open SmzaRp05PcsWireProjection (reconstructUnstackedRow)

set_option autoImplicit false

theorem successful_reconstruction_partial_length
    (point : Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (scalars partials output : List Goldilocks)
    (success : reconstructUnstackedRow point packingFactor widths deltas
      scalars partials = some output) :
    partials.length = (widths.map (fun width => width - 1)).sum := by
  induction widths generalizing deltas scalars partials output with
  | nil =>
      cases deltas <;> cases scalars <;> cases partials <;>
        simp_all [reconstructUnstackedRow]
  | cons width widths ih =>
      cases deltas with
      | nil => simp [reconstructUnstackedRow] at success
      | cons delta deltas =>
          cases scalars with
          | nil => simp [reconstructUnstackedRow] at success
          | cons scalar scalars =>
              by_cases bad : width = 0 ∨ delta > packingFactor
              · simp [reconstructUnstackedRow, bad] at success
              · by_cases short : (partials.take (width - 1)).length ≠ width - 1
                · simp only [reconstructUnstackedRow, if_neg bad, if_pos short] at success
                  cases success
                · have enough : width - 1 ≤ partials.length := by
                    have exactLength := not_not.mp short
                    simp only [List.length_take] at exactLength
                    omega
                  cases remaining : reconstructUnstackedRow point packingFactor
                      widths deltas scalars (partials.drop (width - 1)) with
                  | none =>
                      simp only [reconstructUnstackedRow, if_neg bad, if_neg short,
                        remaining, Option.bind_eq_bind, Option.bind_none] at success
                      cases success
                  | some rest =>
                      have tailLength := ih deltas scalars
                        (partials.drop (width - 1)) rest remaining
                      simp only [List.length_drop] at tailLength
                      simp only [List.map_cons, List.sum_cons]
                      omega

theorem successful_current_reconstruction_has_forty_partials
    (point : Goldilocks) (scalars partials output : List Goldilocks)
    (success : reconstructUnstackedRow point 64
      SmzaRp05ExecutablePcsClosure.widths SmzaRp05ExecutablePcsClosure.deltas
      scalars partials = some output) :
    partials.length = 40 := by
  have length := successful_reconstruction_partial_length point 64
    SmzaRp05ExecutablePcsClosure.widths SmzaRp05ExecutablePcsClosure.deltas
    scalars partials output success
  simp only [SmzaRp05ExecutablePcsClosure.widths, List.map_append,
    List.map_replicate, List.sum_append, List.sum_replicate] at length
  norm_num at length
  exact length

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsPartialLength
