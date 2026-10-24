import HegemonCrypto.NativePrivateSpendQ58CurrentScalarStageReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedPcsFacts
import HegemonCrypto.NativePrivateSpendQ58CurrentLvcsEventJoin

/-! Reverse current PCS scalar/chunk bridge. The polynomial equality arm is
an intermediate result of the current LVCS discrepancy event split, not an
acceptance premise. Every head/tail/row scalar used below comes from the same
successful PCS execution and decodeWire result. SOURCE ONLY: no kernel or
adaptive accepted-invalid bound is asserted by this file. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarEventBridge

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire DecodedFields decodeWire Opening points PcsOutput pcsProgram
   openedWitness openedNonlinearMask openedLinearMask)
namespace CM
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end CM
end E
namespace P
export NativePrivateSpendQ58CurrentAcceptedPcsFacts (pcs_execution_has_actual_facts)
end P
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation
  (Decoded columnPolynomial witness nonlinearColumn linearColumn nonlinearMask linearMask)
end D
namespace L
export NativePrivateSpendQ58CurrentLvcsEventJoin
  (actualCombinationPolynomial combinationPolynomial combination_head_is_current_column_opening)
end L
namespace S
export NativePrivateSpendQ58CurrentScalarStageReadback (current_heads_are_computed_columns)
end S
namespace RF
export NativePrivateSpendQ58CurrentScalarRowFactorization
  (emittedColumns nonlinearColumnIndex linearColumnIndex current_witness_scalar_recombines
   current_nonlinear_scalar_recombines current_linear_scalar_recombines)
end RF
open Polynomial
open SmzaRp05PcsWireProjection (fieldWordsToGoldilocks)
open SmzaRp05ExecutablePcsClosureLvcsAlgebra (consecutivePolynomial)
open SmzaRp05LvcsWireProjection (rotateLeft)
open SmzaRp05ExecutableMerkleVerifier (Oracle Program)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

/-- Actual current rejection guards derive head and tail dimensions. -/
theorem pcs_execution_has_head_tail_shapes
    (ns : E.CM.Namespace) (pending : Bool) (wire : E.Wire)
    (decoded : E.DecodedFields) (opening : E.Opening) (oracle : Oracle)
    (output : E.PcsOutput)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    output.heads.length = 12 ∧ decoded.pcs.rcombiTails.length = 12 ∧
      (∀ index, index < 12 → (output.heads.getD index []).length = 13115) ∧
      (∀ index, index < 12 →
        ((decoded.pcs.rcombiTails.map fieldWordsToGoldilocks).getD index []).length = 58) := by
  obtain ⟨_, _, _, headsBuilt, _⟩ :=
    P.pcs_execution_has_actual_facts ns pending wire decoded opening oracle output executed
  have pass : ¬ (output.heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
      output.heads.any (fun row => decide (row.length ≠ 13115)) ∨
      decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58))) := by
    intro bad
    simp only [E.pcsProgram, headsBuilt, if_pos bad, Program.eval] at executed
    cases executed
  have headsLength : output.heads.length = 12 := by omega
  have tailsLength : decoded.pcs.rcombiTails.length = 12 := by omega
  have headsEach : ∀ row, row ∈ output.heads → row.length = 13115 := by
    intro row member
    by_contra bad
    have anyBad : output.heads.any (fun entry => decide (entry.length ≠ 13115)) = true :=
      List.any_eq_true.mpr ⟨row, member, by simp only [decide_eq_true_eq]; exact bad⟩
    exact pass (Or.inr (Or.inr (Or.inl anyBad)))
  have tailsEach : ∀ row, row ∈ decoded.pcs.rcombiTails → row.length = 58 := by
    intro row member
    by_contra bad
    have anyBad : decoded.pcs.rcombiTails.any (fun entry => decide (entry.length ≠ 58)) = true :=
      List.any_eq_true.mpr ⟨row, member, by simp only [decide_eq_true_eq]; exact bad⟩
    exact pass (Or.inr (Or.inr (Or.inr anyBad)))
  refine ⟨headsLength, tailsLength, ?_, ?_⟩
  · intro index bound
    rw [List.getD_eq_getElem output.heads [] (by omega)]
    exact headsEach _ (List.mem_iff_getElem.mpr ⟨index, by omega, rfl⟩)
  · intro index bound
    have mapped : (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks).getD index [] =
        fieldWordsToGoldilocks (decoded.pcs.rcombiTails.getD index []) := by
      simpa only [fieldWordsToGoldilocks, List.map_nil] using
        (List.getD_map decoded.pcs.rcombiTails [] fieldWordsToGoldilocks (n := index))
    rw [mapped, List.getD_eq_getElem decoded.pcs.rcombiTails [] (by omega)]
    simpa only [fieldWordsToGoldilocks, List.length_map] using
      tailsEach _ (List.mem_iff_getElem.mpr ⟨index, by omega, rfl⟩)

private theorem current_node_injective :
    Function.Injective (fun index : Fin 13173 => (index.val : Goldilocks)) := by
  intro left right same
  apply Fin.ext
  have leftBound : left.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := left.isLt.trans (by decide)
  have rightBound : right.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := right.isLt.trans (by decide)
  have naturalSame := congrArg fromGoldilocks same
  change fromGoldilocks (toGoldilocks left.val) = fromGoldilocks (toGoldilocks right.val) at naturalSame
  simpa only [fromGoldilocks_toGoldilocks, Hegemon.Transaction.SmallWoodProductionConstraintRefinement.fieldValue,
    Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] using naturalSame

/-- The actual head/tail interpolant at node58+head reads that very head.
This uses the current58 tail and13115 head dimensions, not the old406 vector. -/
theorem current_combination_reads_actual_head
    (fields : SmzaRp05PcsWireProjection.DecodedPcsFields)
    (heads : List (List Goldilocks)) (coordinate : Fin 6) (block : Fin 2)
    (head : Fin 13115)
    (headShape : (heads.getD (2 * coordinate.val + block.val) []).length = 13115)
    (tailShape : ((fields.rcombiTails.map fieldWordsToGoldilocks).getD
      (2 * coordinate.val + block.val) []).length = 58) :
    (L.actualCombinationPolynomial fields heads (coordinate, block)).eval
        ((58 + head.val : Nat) : Goldilocks) =
      (heads.getD (2 * coordinate.val + block.val) []).getD head.val 0 := by
  let rowHeads := heads.getD (2 * coordinate.val + block.val) []
  let rowTails := (fields.rcombiTails.map fieldWordsToGoldilocks).getD
    (2 * coordinate.val + block.val) []
  have rotated : rotateLeft (rowHeads ++ rowTails) 13115 = rowTails ++ rowHeads := by
    unfold rotateLeft
    rw [List.length_append, headShape, tailShape, Nat.mod_eq_of_lt (by decide : 13115 < 13173)]
    change (rowHeads ++ rowTails).drop 13115 ++ (rowHeads ++ rowTails).take 13115 =
      rowTails ++ rowHeads
    rw [List.drop_left' headShape, List.take_left' headShape]
  have count : (rowTails ++ rowHeads).length = 13173 := by
    rw [List.length_append, tailShape, headShape]
  let index : Fin 13173 := ⟨58 + head.val, by omega⟩
  have nodesInjective : Function.Injective
      (fun index : Fin (rowTails ++ rowHeads).length => (index.val : Goldilocks)) := by
    rw [count]
    exact current_node_injective
  let actualIndex : Fin (rowTails ++ rowHeads).length := ⟨index.val, by rw [count]; exact index.isLt⟩
  have read := Lagrange.eval_interpolate_at_node
    (fun index : Fin (rowTails ++ rowHeads).length => (rowTails ++ rowHeads).getD index.val 0)
    nodesInjective.injOn (Finset.mem_univ actualIndex)
  change (consecutivePolynomial (rowTails ++ rowHeads)).eval ((58 + head.val : Nat) : Goldilocks) =
    (rowTails ++ rowHeads).getD (58 + head.val) 0 at read
  unfold L.actualCombinationPolynomial
  rw [rotated, read, List.getD_append_right rowTails rowHeads 0 _ (by rw [tailShape]; omega)]
  rw [tailShape, Nat.add_sub_cancel_left]

/-- Outside the actual LVCS discrepancy arm, the derived interpolant
identities bind every current column opening to the same decoded PCS scalars. -/
theorem current_polynomial_identity_binds_columns
    (ns : E.CM.Namespace) (pending : Bool) (wire : E.Wire)
    (decoded : E.DecodedFields) (opening : E.Opening) (oracle : Oracle)
    (output : E.PcsOutput) (source : D.Decoded)
    (decodedWire : E.decodeWire wire = some decoded)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (identities : ∀ combination,
      L.actualCombinationPolynomial decoded.pcs output.heads combination =
        L.combinationPolynomial source opening combination) :
    ∀ coordinate : Fin 6, ∃ partials : Fin 10 → Goldilocks,
      ∀ column : Fin 26230,
        (D.columnPolynomial source column).eval (E.points opening coordinate) =
          RF.emittedColumns (E.points opening coordinate)
            (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
            partials column := by
  obtain ⟨_, _, _, headsBuilt, _⟩ :=
    P.pcs_execution_has_actual_facts ns pending wire decoded opening oracle output executed
  obtain ⟨_headCount, _tailCount, headShape, tailShape⟩ :=
    pcs_execution_has_head_tail_shapes ns pending wire decoded opening oracle output executed
  intro coordinate
  obtain ⟨partials, actualColumns⟩ :=
    S.current_heads_are_computed_columns wire decoded opening decodedWire output.heads headsBuilt coordinate
  refine ⟨partials, ?_⟩
  intro column
  obtain ⟨pair, rfl⟩ := (finProdFinEquiv : Fin 2 × Fin 13115 ≃ Fin 26230).surjective column
  have bound : 2 * coordinate.val + pair.1.val < 12 := by
    have hc := coordinate.isLt
    have hb := pair.1.isLt
    omega
  have actualHead := current_combination_reads_actual_head decoded.pcs output.heads
    coordinate pair.1 pair.2 (headShape _ bound) (tailShape _ bound)
  have same := congrArg (fun polynomial : Goldilocks[X] =>
    polynomial.eval ((58 + pair.2.val : Nat) : Goldilocks))
      (identities (coordinate, pair.1))
  rw [actualHead, L.combination_head_is_current_column_opening] at same
  exact same.symm.trans (actualColumns pair.1 pair.2)

/-- No scalar certificate is an input. Actual decode/PCS success and the
current LVCS equality arm derive all three PIOP scalar families. -/
theorem current_same_execution_scalar_agreement
    (ns : E.CM.Namespace) (pending : Bool) (wire : E.Wire)
    (decoded : E.DecodedFields) (opening : E.Opening) (oracle : Oracle)
    (output : E.PcsOutput) (source : D.Decoded)
    (decodedWire : E.decodeWire wire = some decoded)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (identities : ∀ combination,
      L.actualCombinationPolynomial decoded.pcs output.heads combination =
        L.combinationPolynomial source opening combination) :
    (∀ coordinate : Fin 6, ∀ row : NativePrivateSpendQ58CurrentPublicOpening.Row,
      E.openedWitness decoded.piop coordinate row =
        (D.witness source row).eval (E.points opening coordinate)) ∧
    (∀ coordinate : Fin 6, ∀ row : Fin 5,
      E.openedNonlinearMask decoded.piop coordinate row =
        (D.nonlinearMask source row).eval (E.points opening coordinate)) ∧
    (∀ coordinate : Fin 6, ∀ row : Fin 5,
      E.openedLinearMask decoded.piop coordinate row =
        (D.linearMask source row).eval (E.points opening coordinate)) := by
  have columns := current_polynomial_identity_binds_columns ns pending wire decoded opening
    oracle output source decodedWire executed identities
  refine ⟨?_, ?_, ?_⟩
  · intro coordinate row
    obtain ⟨partials, each⟩ := columns coordinate
    change (decoded.piop.rowScalars coordinate (Fin.castAdd 10 row)).val =
      (D.columnPolynomial source (Fin.castAdd 20 row)).eval (E.points opening coordinate)
    rw [each]
    exact (RF.current_witness_scalar_recombines (E.points opening coordinate)
      (fun index : Fin 26220 => ((decoded.piop.rowScalars coordinate index).val : Goldilocks))
      partials row).symm
  · intro coordinate row
    obtain ⟨partials, each⟩ := columns coordinate
    have columnIndex (part : Fin 2) :
        (⟨26210 + 2 * row.val + part.val, by have := row.isLt; have := part.isLt; omega⟩ : Fin 26230) =
          RF.nonlinearColumnIndex row part := by
      apply Fin.ext
      change 26210 + 2 * row.val + part.val = 26210 + (part.val + 2 * row.val)
      omega
    unfold D.nonlinearMask D.nonlinearColumn
    simp only [eval_add, eval_mul, eval_pow, eval_X, columnIndex, each]
    have scalar := RF.current_nonlinear_scalar_recombines (E.points opening coordinate)
      (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials row
    exact scalar.symm
  · intro coordinate row
    obtain ⟨partials, each⟩ := columns coordinate
    have columnIndex (part : Fin 2) :
        (⟨26220 + 2 * row.val + part.val, by have := row.isLt; have := part.isLt; omega⟩ : Fin 26230) =
          RF.linearColumnIndex row part := by
      apply Fin.ext
      change 26220 + 2 * row.val + part.val = 26210 + (10 + (part.val + 2 * row.val))
      omega
    unfold D.linearMask D.linearColumn
    simp only [eval_add, eval_mul, eval_pow, eval_X, columnIndex, each]
    have scalar := RF.current_linear_scalar_recombines (E.points opening coordinate)
      (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials row
    convert scalar.symm using 1
    apply congrArg (fun index : Fin 26220 =>
      ((decoded.piop.rowScalars coordinate index).val : Goldilocks))
    apply Fin.ext
    change 26215 + row.val = 26210 + (5 + row.val)
    omega

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarEventBridge
