import SmzaRp04TracePrefixes
import SmzaRp04RawDecsReadback

/-! The verifier reconstructs the DECS heads from the opened witness, masks
and partial PCS scalars. Interpolating the hashed heads and tails therefore
supplies the head-binding equation; it is not a witness-validity assumption. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawHeadReadback

open Polynomial SmzaRp04TracePrefixes SmzaRp04RawDecsReadback
open SmzaRp04ChronologicalAlgebra SmzaQ38LvcsOpening
open SmzaQ38OracleExtraction SmzaQ38OpeningFieldReadback
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewFinalInput

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSimpArgs false

def reconstructedWireEvaluations (points : Fin 6 → Goldilocks)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks) (tails : Fin 12 → Fin 38 → Goldilocks) :
    WireEvaluations := fun row coordinate =>
  let combination : Fin 6 × Fin 2 := finProdFinEquiv.symm row
  if head : coordinate.val < 368 then
    reconstructedColumnEvaluations points witness masks partials combination.1
      (columnIndex combination.2 ⟨coordinate.val, head⟩)
  else tails row ⟨coordinate.val - 368, by omega⟩

theorem query_polynomial_head_reads_wire_head
    (commitmentPrefix : Prefix) (evaluations : WireEvaluations)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (claimedPolynomials (queryCoefficients
      ⟨.decs, decsPayload commitmentPrefix evaluations⟩) (opening, block)).eval
        (lvcsDataPoint column) =
      evaluations (finProdFinEquiv (opening, block)) ⟨column.val, by omega⟩ := by
  let node : Fin 406 := ⟨38 + column.val, by omega⟩
  have readback := query_polynomial_reads_rotated_heads_and_tails
    ⟨.decs, decsPayload commitmentPrefix evaluations⟩ (opening, block) node
  have point : toGoldilocks node.val = lvcsDataPoint column := by rfl
  rw [point] at readback
  rw [readback]
  change toGoldilocks (V8SmzaOracleParser.wordAt
    (decsPayload commitmentPrefix evaluations)
      (8 + (opening.val * 2 + block.val) * 406 + (node.val + 368) % 406)) = _
  rw [raw_decs_rotated_evaluation_readback]
  apply congrArg (evaluations (finProdFinEquiv (opening, block)))
  apply Fin.ext
  change (38 + column.val + 368) % 406 = column.val
  omega

theorem reconstructed_decs_heads_supply_head_binding
    (commitmentPrefix : Prefix) (points : Fin 6 → Goldilocks)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks) (tails : Fin 12 → Fin 38 → Goldilocks) :
    ClaimedHeadsReconstructed points
      (claimedPolynomials (queryCoefficients ⟨.decs, decsPayload commitmentPrefix
        (reconstructedWireEvaluations points witness masks partials tails)⟩))
      witness masks partials := by
  intro opening block column
  rw [query_polynomial_head_reads_wire_head]
  have head : column.val < 368 := column.isLt
  simp only [reconstructedWireEvaluations, Equiv.symm_apply_apply,
    dif_pos head]
  rfl

end
end HegemonCrypto.SmallWood.SmzaRp04RawHeadReadback
