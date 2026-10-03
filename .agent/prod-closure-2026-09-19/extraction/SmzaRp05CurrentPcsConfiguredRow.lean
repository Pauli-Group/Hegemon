import SmzaRp05CurrentPcsOpeningView

/-!
# Exact configured-row decomposition for current RP05 PCS reconstruction

This specializes the executable traversal factorization to the source's
686 singleton witness rows, five width-8 nonlinear rows (delta 29), and five
width-2 linear rows (delta 1). It is an equation about the actual list
program, with the final empty-width branch preserving its exact trailing-
partial rejection behavior.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsConfiguredRow

open HegemonCrypto.SmallWood
open SmzaRp05PcsWireProjection
open HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningView

set_option autoImplicit false

/-- The result of running the three protocol regions in their source order.
Each region's values and residual partial suffix are produced by the same
list recursion as `reconstructUnstackedRow`. -/
def configuredRowResult (point : Goldilocks)
    (witnessRows nonlinearRows linearRows partials : List Goldilocks) :
    Option (List Goldilocks) :=
  (reconstructRepeated point 64 1 0 witnessRows partials).bind fun witnessResult =>
    (reconstructRepeated point 64 8 29 nonlinearRows witnessResult.2).bind
      fun nonlinearResult =>
        (reconstructRepeated point 64 2 1 linearRows nonlinearResult.2).bind
          fun linearResult =>
            if linearResult.2 = [] then
              some (witnessResult.1 ++ nonlinearResult.1 ++ linearResult.1)
            else none

/-- With the exact 686/5/5 split of opened scalars, the verifier's configured
row traversal is exactly the concatenation of the three fixed-width source
regions. This is the list-result equation needed before identifying each
region with its source witness, masks, and PCS partial values. -/
theorem reconstruct_configured_row_decomposes
    (point : Goldilocks)
    (witnessRows nonlinearRows linearRows partials : List Goldilocks)
    (witnessLength : witnessRows.length = 686)
    (nonlinearLength : nonlinearRows.length = 5)
    (linearLength : linearRows.length = 5) :
    reconstructUnstackedRow point 64
      HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosure.widths
      HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosure.deltas
      (witnessRows ++ nonlinearRows ++ linearRows) partials =
        configuredRowResult point witnessRows nonlinearRows linearRows partials := by
  change reconstructUnstackedRow point 64
      (List.replicate 686 1 ++ List.replicate 5 8 ++ List.replicate 5 2)
      (List.replicate 686 0 ++ List.replicate 5 29 ++ List.replicate 5 1)
      (witnessRows ++ nonlinearRows ++ linearRows) partials = _
  simp only [List.append_assoc]
  have witnessSplit := reconstructUnstackedRow_repeat point 64 1 0 686
    (List.replicate 5 8 ++ List.replicate 5 2)
    (List.replicate 5 29 ++ List.replicate 5 1)
    witnessRows (nonlinearRows ++ linearRows) partials witnessLength
  have nonlinearSplit (remaining : List Goldilocks) :=
    reconstructUnstackedRow_repeat point 64 8 29 5
      (List.replicate 5 2) (List.replicate 5 1)
      nonlinearRows linearRows remaining nonlinearLength
  have linearSplit (remaining : List Goldilocks) :
      reconstructUnstackedRow point 64
          (List.replicate 5 2) (List.replicate 5 1) linearRows remaining =
        (reconstructRepeated point 64 2 1 linearRows remaining).bind
          (fun result =>
            (reconstructUnstackedRow point 64 [] [] [] result.2).map
              (fun suffix => result.1 ++ suffix)) := by
    simpa only [List.append_nil] using
      (reconstructUnstackedRow_repeat point 64 2 1 5
        [] [] linearRows [] remaining linearLength)
  rw [witnessSplit]
  simp_rw [nonlinearSplit]
  simp_rw [linearSplit]
  unfold configuredRowResult
  cases hWitness : reconstructRepeated point 64 1 0 witnessRows partials with
  | none => simp only [Option.bind_none]
  | some witnessResult =>
      cases hNonlinear : reconstructRepeated point 64 8 29 nonlinearRows witnessResult.2 with
      | none => simp only [Option.bind_some, hNonlinear, Option.map_none, Option.bind_none]
      | some nonlinearResult =>
          cases hLinear : reconstructRepeated point 64 2 1 linearRows nonlinearResult.2 with
          | none => simp only [Option.bind_some, hNonlinear, hLinear,
              Option.map_none, Option.bind_none]
          | some linearResult =>
              simp only [Option.bind_some, hNonlinear, hLinear]
              have terminal (rest : List Goldilocks) :
                  reconstructUnstackedRow point 64 [] [] [] rest =
                    (if rest = [] then some [] else none) := by
                cases rest <;> rfl
              rw [terminal]
              by_cases empty : linearResult.2 = []
              · simp only [if_pos empty, Option.map_some,
                  List.append_nil, List.append_assoc]
              · simp only [if_neg empty, Option.map_none]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsConfiguredRow
