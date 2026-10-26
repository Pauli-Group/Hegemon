import HegemonCrypto.NativePrivateSpendQ58CurrentPiopEvents
import HegemonCrypto.NativePrivateSpendQ58CurrentPiopRestoration

private def g3_build50_progress (phase : String) : IO Unit := do -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  match ← IO.getEnv "HEGEMON_G3_SCALAR_PROGRESS_PATH" with -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  | some path => IO.FS.withFile (System.FilePath.mk path) IO.FS.Mode.append (fun handle => do handle.putStrLn phase; handle.flush) -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  | none => pure () -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
elab "g3_build50_entry " phase:str : command => Lean.Elab.Command.liftIO (g3_build50_progress phase.getString) -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
elab "g3_build50_checked " id:ident : command => do -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  let names ← Lean.Elab.Command.liftCoreM (Lean.Elab.realizeGlobalConstWithInfos id) -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  let env ← Lean.getEnv -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
  for name in names do -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
    match env.toKernelEnv.find? name with -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
    | some (.thmInfo _) => Lean.Elab.Command.liftIO (g3_build50_progress ("PHASE SC50_CHECKED " ++ id.getId.toString)) -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
    | _ => Lean.throwError "SC50 checked kernel environment does not contain a theorem" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
/-! Current nonlinear/CSR scalar readout to literal PIOP discrepancy zeros.
These intermediate scalar equalities must be derived from the current PCS
chunk inverse; they are not the final ordinary acceptance premise.
No packed-source validity or desired relation certificate is used. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarChecks
open Polynomial V8Smz9PiopSoundness V8Smz9PiopOpeningRecovery
open NativePrivateSpendQ58CurrentPublicOpening (Relation Row Check Batch packing csrWeights)
open scoped Classical BigOperators
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Opening points PiopFields openedWitness openedNonlinearMask openedLinearMask
   nonlinearScalar linearScalar evaluation)
end E
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation
  (Decoded witness nonlinear linear nonlinearMask linearMask candidate)
end D
namespace R
export NativePrivateSpendQ58CurrentPiopRestoration
  (response nonlinear_discrepancy_evaluation linear_discrepancy_evaluation packing_divisor_nonzero)
end R

g3_build50_entry "PHASE SC50_ENTRY scalar_add_sub_cancel" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem scalar_add_sub_cancel {G : Type*} [AddGroup G]
    (a b : G) : (a + b - b) - a = 0 := by
  rw [add_sub_cancel_right, sub_self]

g3_build50_checked scalar_add_sub_cancel -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY scalar_trace_cancel" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem scalar_trace_cancel {G : Type*} [AddGroup G]
    (t m b s o : G)
    (trace : t = s + o) (mask : o = m) (batch : s = b) :
    t - m - b = 0 := by
  rw [trace, mask, batch]
  exact scalar_add_sub_cancel (G := G) b m

g3_build50_checked scalar_trace_cancel -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY scalar_quotient_trace_cancel" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem scalar_quotient_trace_cancel {G : Type*} [Field G]
    (v t m b s o : G) (nonzero : v ≠ 0)
    (trace : t = s / v + o) (mask : o = m) (batch : s = b) :
    v * (t - m) - b = 0 := by
  rw [trace, mask, batch, add_sub_cancel_right, mul_div_cancel₀ b nonzero, sub_self]

g3_build50_checked scalar_quotient_trace_cancel -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY packing_divisor_bridge" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem packing_divisor_bridge (point : Goldilocks) :
    (Interactive.packingVanishing Finset.univ
      V8Smz9AdaptiveFiniteAccounting.packingPoint).eval point =
      (packingVanishing packing).eval point := rfl

g3_build50_checked packing_divisor_bridge -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY current_nonlinear_scalar_is_polynomial_readout" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
theorem current_nonlinear_scalar_is_polynomial_readout
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded) (opening : E.Opening)
    (proof : E.PiopFields)
    (witnessReadout : ∀ coordinate row,
      E.openedWitness proof coordinate row = (D.witness source row).eval (E.points opening coordinate))
    (coordinate : Fin 6) (check : Check) :
    E.nonlinearScalar relation (E.openedWitness proof coordinate) check =
      (D.nonlinear relation source check).eval (E.points opening coordinate) := by
  by_cases bound : check.val < 5210
  · simp only [E.nonlinearScalar, D.nonlinear, dif_pos bound, eval_sub, eval_mul,
      witnessReadout]
  · simp [E.nonlinearScalar, D.nonlinear, bound]

g3_build50_checked current_nonlinear_scalar_is_polynomial_readout -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY current_linear_scalar_is_polynomial_readout" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
theorem current_linear_scalar_is_polynomial_readout
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded) (opening : E.Opening)
    (proof : E.PiopFields)
    (witnessReadout : ∀ coordinate row,
      E.openedWitness proof coordinate row = (D.witness source row).eval (E.points opening coordinate))
    (coordinate : Fin 6) (check : Check) :
    E.linearScalar relation (E.openedWitness proof coordinate) (E.points opening coordinate) check =
      (D.linear relation source check).eval (E.points opening coordinate) := by
  have same : E.openedWitness proof coordinate =
      fun row => (D.witness source row).eval (E.points opening coordinate) := by
    funext row
    exact witnessReadout coordinate row
  rw [same]
  unfold E.linearScalar D.linear
  with_reducible
    exact (source_linear_unmasked_evaluation (F := Goldilocks) (Rows := Row)
      (csrWeights (relation.csr check)) (sourcePackingLagrange packing)
      (D.witness source) (E.points opening coordinate)).symm

g3_build50_checked current_linear_scalar_is_polynomial_readout -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY nonlinear_batch_readout" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem nonlinear_batch_readout
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (witnessReadout : ∀ coordinate row,
      E.openedWitness proof coordinate row = (D.witness source row).eval (E.points opening coordinate)) :
    ∀ row coordinate,
    (∑ check, matrix row check *
      E.nonlinearScalar relation (E.openedWitness proof coordinate) check) =
    (PiopExtraction.nonlinearBatch (D.candidate relation source).system
      (matrix row)).eval (E.points opening coordinate) := by
  intro row coordinate
  simp only [PiopExtraction.nonlinearBatch, Interactive.batch,
    V8Smz9PiopSoundness.Candidate.system, D.candidate, eval_finsetSum, eval_mul, eval_C]
  apply Finset.sum_congr rfl
  intro check _
  rw [current_nonlinear_scalar_is_polynomial_readout relation source opening proof witnessReadout]

g3_build50_checked nonlinear_batch_readout -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY linear_batch_readout_generic" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem linear_batch_readout_generic
    {F Node : Type*} [Field F] {width : Nat}
    (system : Interactive.System (F := F) (Node := Node)
      (Nonlinear := Fin width) (Linear := Fin width))
    (coefficients values : Fin width → F) (point : F)
    (readout : ∀ check, values check = (system.linearPolynomial check).eval point) :
    (∑ check, coefficients check * values check) =
      (PiopExtraction.linearBatch system coefficients).eval point := by
  have same : (∑ check, coefficients check * values check) =
      ∑ check, coefficients check * (system.linearPolynomial check).eval point :=
    Finset.sum_congr rfl (fun check _ =>
      congrArg (fun value : F => coefficients check * value) (readout check))
  exact same.trans
    (V8Smz9PiopOpeningRecovery.nonlinear_batch_eval
      coefficients system.linearPolynomial point).symm

g3_build50_checked linear_batch_readout_generic -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY candidate_system_linear_family" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem candidate_system_linear_family {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width) :
    candidate.system.linearPolynomial = candidate.linear :=
  Eq.refl candidate.linear

g3_build50_checked candidate_system_linear_family -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY decoded_candidate_linear_family" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem decoded_candidate_linear_family
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (source : D.Decoded) :
    (D.candidate relation source).linear = D.linear relation source := by
  with_reducible
    unfold D.candidate
    exact Eq.refl (D.linear relation source)

g3_build50_checked decoded_candidate_linear_family -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY candidate_linear_polynomial_projection" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem candidate_linear_polynomial_projection
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (source : D.Decoded) (check : Check) :
    (D.candidate relation source).system.linearPolynomial check =
      D.linear relation source check :=
  congrFun ((candidate_system_linear_family (D.candidate relation source)).trans
    (decoded_candidate_linear_family relation source)) check

g3_build50_checked candidate_linear_polynomial_projection -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY linear_batch_readout" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
private theorem linear_batch_readout
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (witnessReadout : ∀ coordinate row,
      E.openedWitness proof coordinate row = (D.witness source row).eval (E.points opening coordinate)) :
    ∀ row coordinate,
    (∑ check, matrix row check *
      E.linearScalar relation (E.openedWitness proof coordinate) (E.points opening coordinate) check) =
    (PiopExtraction.linearBatch (D.candidate relation source).system
      (matrix row)).eval (E.points opening coordinate) := by
  intro row coordinate
  with_reducible
    exact linear_batch_readout_generic (F := Goldilocks) (Node := Fin 64)
      (width := 1344594) (D.candidate relation source).system (matrix row)
      (E.linearScalar relation (E.openedWitness proof coordinate) (E.points opening coordinate))
      (E.points opening coordinate)
      (fun check =>
        (current_linear_scalar_is_polynomial_readout relation source opening proof
          witnessReadout coordinate check).trans
          ((congrArg (fun polynomial : Goldilocks[X] =>
            polynomial.eval (E.points opening coordinate))
            (candidate_linear_polynomial_projection relation source check)).symm))

g3_build50_checked linear_batch_readout -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
g3_build50_entry "PHASE SC50_ENTRY current_opened_scalars_derive_piop_checks" -- G3_SCALAR_CHECKS_BUILD_PROGRESS50
theorem current_opened_scalars_derive_piop_checks
    (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (witnessReadout : ∀ coordinate row,
      E.openedWitness proof coordinate row = (D.witness source row).eval (E.points opening coordinate))
    (nonlinearReadout : ∀ coordinate row,
      E.openedNonlinearMask proof coordinate row =
        (D.nonlinearMask source row).eval (E.points opening coordinate))
    (linearReadout : ∀ coordinate row,
      E.openedLinearMask proof coordinate row =
        (D.linearMask source row).eval (E.points opening coordinate)) :
    NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks (D.candidate relation source)
      matrix (R.response relation matrix opening proof) opening := by
  intro row coordinate
  constructor
  · have traceRead :
        (E.evaluation relation matrix opening proof).nonlinear row coordinate =
          (∑ check, matrix row check *
            E.nonlinearScalar relation (E.openedWitness proof coordinate) check) /
            (Interactive.packingVanishing Finset.univ
              V8Smz9AdaptiveFiniteAccounting.packingPoint).eval (E.points opening coordinate) +
            E.openedNonlinearMask proof coordinate row :=
      (show (E.evaluation relation matrix opening proof).nonlinear row coordinate =
        (∑ check, matrix row check *
          E.nonlinearScalar relation (E.openedWitness proof coordinate) check) /
          (packingVanishing packing).eval (E.points opening coordinate) +
          E.openedNonlinearMask proof coordinate row from rfl).trans
        (congrArg (fun divisor : Goldilocks =>
          (∑ check, matrix row check *
            E.nonlinearScalar relation (E.openedWitness proof coordinate) check) / divisor +
            E.openedNonlinearMask proof coordinate row)
          (packing_divisor_bridge (E.points opening coordinate)).symm)
    have maskProjection :
        (D.candidate relation source).nonlinearMask row = D.nonlinearMask source row := rfl
    have maskRead :
        E.openedNonlinearMask proof coordinate row =
          ((D.candidate relation source).nonlinearMask row).eval (E.points opening coordinate) :=
      (nonlinearReadout coordinate row).trans
        ((congrArg (fun polynomial : Goldilocks[X] =>
          polynomial.eval (E.points opening coordinate)) maskProjection).symm)
    have divisorNonzero :
        ((Interactive.packingVanishing Finset.univ
          V8Smz9AdaptiveFiniteAccounting.packingPoint).eval (E.points opening coordinate)) ≠ 0 :=
      fun zero => (R.packing_divisor_nonzero opening coordinate)
        ((packing_divisor_bridge (E.points opening coordinate)).symm.trans zero)
    with_reducible
      exact (R.nonlinear_discrepancy_evaluation relation source matrix opening proof
        row coordinate).trans
        (scalar_quotient_trace_cancel (G := Goldilocks)
          ((Interactive.packingVanishing Finset.univ
            V8Smz9AdaptiveFiniteAccounting.packingPoint).eval (E.points opening coordinate))
          ((E.evaluation relation matrix opening proof).nonlinear row coordinate)
          (((D.candidate relation source).nonlinearMask row).eval (E.points opening coordinate))
          ((PiopExtraction.nonlinearBatch (D.candidate relation source).system
            (matrix row)).eval (E.points opening coordinate))
          (∑ check, matrix row check *
            E.nonlinearScalar relation (E.openedWitness proof coordinate) check)
          (E.openedNonlinearMask proof coordinate row)
          divisorNonzero
          traceRead maskRead
          (nonlinear_batch_readout relation source matrix opening proof witnessReadout
            row coordinate))
  · have traceRead :
        (E.evaluation relation matrix opening proof).linear row coordinate =
          (∑ check, matrix row check *
            E.linearScalar relation (E.openedWitness proof coordinate)
              (E.points opening coordinate) check) +
            E.openedLinearMask proof coordinate row := rfl
    have maskProjection :
        (D.candidate relation source).linearMask row = D.linearMask source row := rfl
    have maskRead :
        E.openedLinearMask proof coordinate row =
          ((D.candidate relation source).linearMask row).eval (E.points opening coordinate) :=
      (linearReadout coordinate row).trans
        ((congrArg (fun polynomial : Goldilocks[X] =>
          polynomial.eval (E.points opening coordinate)) maskProjection).symm)
    with_reducible
      exact (R.linear_discrepancy_evaluation relation source matrix opening proof
        row coordinate).trans
        (scalar_trace_cancel (G := Goldilocks)
          ((E.evaluation relation matrix opening proof).linear row coordinate)
          (((D.candidate relation source).linearMask row).eval (E.points opening coordinate))
          ((PiopExtraction.linearBatch (D.candidate relation source).system
            (matrix row)).eval (E.points opening coordinate))
          (∑ check, matrix row check *
            E.linearScalar relation (E.openedWitness proof coordinate)
              (E.points opening coordinate) check)
          (E.openedLinearMask proof coordinate row)
          traceRead maskRead
          (linear_batch_readout relation source matrix opening proof witnessReadout
            row coordinate))
g3_build50_checked current_opened_scalars_derive_piop_checks -- G3_SCALAR_CHECKS_BUILD_PROGRESS50

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarChecks
