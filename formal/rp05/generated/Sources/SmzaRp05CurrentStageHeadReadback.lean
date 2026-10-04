import SmzaRp05CurrentTwelveCalculated
import SmzaRp05ExecutablePcsClosureLvcsAlgebraInterpolation

/-! # Current query polynomial readback to the actual PCS heads

At source index `38 + column`, the current 406-node polynomial reads exactly
the corresponding head coordinate. This is the algebraic bridge from the
same-run twelve polynomial identities to the head values used in the DECS
opening relation; vector dimensions come from the successful PCS stage.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentStageHeadReadback

open Polynomial
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (widths deltas)
open SmzaRp05CurrentTwelveCalculated
open SmzaRp05LvcsWireProjection (rotateLeft)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.SmallWood (Goldilocks)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

private theorem rotate_left_head_getD
    (head tail : List Goldilocks)
    (headLength : head.length = 368) (tailLength : tail.length = 38)
    (column : Fin 368) :
    (rotateLeft (head ++ tail) 368).getD (38 + column.val) 0 =
      head.getD column.val 0 := by
  have fullLength : (head ++ tail).length = 406 := by
    simp [headLength, tailLength]
  have rotation : rotateLeft (head ++ tail) 368 = tail ++ head := by
    unfold rotateLeft
    rw [fullLength, Nat.mod_eq_of_lt (by omega : 368 < 406)]
    simp [headLength]
  rw [rotation]
  rw [List.getD_eq_getElem _ _ (by simp [headLength, tailLength]; omega)]
  rw [List.getElem_append_right (by simp [tailLength])]
  simp only [tailLength, Nat.add_sub_cancel_left]
  rw [List.getD_eq_getElem _ _ (by simpa only [headLength] using column.isLt)]

/-- The polynomial evaluator returns the concrete source `heads` word on the
368-column portion of the rotated 406-vector. The successful opening-input
guard supplies exactly the 368-head and 38-tail dimensions used here. -/
theorem current_stage_query_polynomial_reads_head
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (currentQueryPolynomial stages.heads (currentStageTails wire) opening block).eval
        ((38 + column.val : Nat) : Goldilocks) =
      (stages.heads.getD (2 * opening.val + block.val) []).getD column.val 0 := by
  have shape := pcs_stages_query_vector_well_formed stages
  have rowBound : 2 * opening.val + block.val < 12 := by
    have openingBound := opening.isLt
    have blockBound := block.isLt
    omega
  have headLength := shape.2.2.1 (2 * opening.val + block.val) rowBound
  have tailLength := shape.2.2.2 (2 * opening.val + block.val) rowBound
  have rotatedRead :
      (currentQueryValues stages.heads (currentStageTails wire) opening block).getD
          (38 + column.val) 0 =
        (stages.heads.getD (2 * opening.val + block.val) []).getD column.val 0 := by
    unfold currentQueryValues
    exact rotate_left_head_getD
      (stages.heads.getD (2 * opening.val + block.val) [])
      ((currentStageTails wire).getD (2 * opening.val + block.val) [])
      headLength tailLength column
  let node : Fin 406 := ⟨38 + column.val, by have h := column.isLt; omega⟩
  have atNode := Lagrange.eval_interpolate_at_node
    (s := (Finset.univ : Finset (Fin 406))) (i := node)
    (v := fun index : Fin 406 => (index.val : Goldilocks))
    (fun index : Fin 406 =>
      (currentQueryValues stages.heads (currentStageTails wire) opening block).getD
        index.val 0)
    (SmzaRp04TracePrefixes.consecutive_point_injective.injOn)
    (Finset.mem_univ node)
  calc
    (currentQueryPolynomial stages.heads (currentStageTails wire) opening block).eval
        ((38 + column.val : Nat) : Goldilocks) =
      (currentQueryValues stages.heads (currentStageTails wire) opening block).getD
        node.val 0 := by
          simpa [currentQueryPolynomial, node] using atNode
    _ = (stages.heads.getD (2 * opening.val + block.val) []).getD column.val 0 :=
      rotatedRead

/-- The `PcsStages.heads` value used by `currentQueryPolynomial` is not an
independent vector: it is the exact result of the decoded PCS matrices and
source reconstruction parameters in `reconstructedHeadsAll`. -/
theorem pcs_stages_heads_are_reconstructed_heads
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) :
    SmzaRp05LvcsWireProjection.reconstructAllHeads wire.pcs points wire.rowScalars
      64 widths deltas 2 368 = some stages.heads := by
  obtain ⟨rowHeads, rowHeadsBuilt, _rowCount, _equations⟩ :=
    SmzaRp05ExecutablePcsClosureLvcsAlgebra.reconstructed_rows_twelve_block_equations
      wire.pcs points stages.decsPoints pointCount wire.rowScalars widths deltas
      stages.rows stages.rowsBuilt
  have heights : wire.rowScalars.length = points.length ∧
      wire.pcs.partialEvals.length = points.length := by
    have guardFalse : ¬ (wire.rowScalars.length ≠ points.length ∨
        wire.pcs.partialEvals.length ≠ points.length) := by
      intro bad
      have headsBuilt := stages.headsBuilt
      simp [SmzaRp05PcsWireProjection.reconstructedHeadsAll, bad] at headsBuilt
    exact ⟨by omega, by omega⟩
  have sameHeads := reconstructed_head_aggregators_agree wire.pcs points
    wire.rowScalars 64 widths deltas 2 368 heights.1 heights.2
  have headEq : rowHeads = stages.heads := by
    have outputEq := Option.some.inj
      (rowHeadsBuilt.symm.trans (sameHeads.trans stages.headsBuilt))
    exact outputEq
  simpa [headEq] using rowHeadsBuilt

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentStageHeadReadback
