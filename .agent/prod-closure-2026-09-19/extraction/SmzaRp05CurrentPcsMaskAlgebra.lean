import SmzaRp05PcsWireProjection
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-! The actual PCS head-zero recurrence uses exactly the mask reconstruction
powers in the relation's opening view. No additional transmitted data is used. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsMaskAlgebra

open SmzaRp05PcsWireProjection (reconstructHeadZero)
open V8Smz9EagerPrivacy (sourceRecoveredNonlinearFirstColumn)
open V8Smz9EagerSimulator (reconstructNonlinearColumns reconstructLinearColumns)

set_option autoImplicit false
set_option maxRecDepth 10000

theorem nonlinear_head_zero_is_source_reconstruction
    (point scalar : Goldilocks) (partials : Fin 7 → Goldilocks) :
    reconstructHeadZero point 64 29 scalar (List.ofFn partials) =
      sourceRecoveredNonlinearFirstColumn point scalar partials := by
  simp [reconstructHeadZero, sourceRecoveredNonlinearFirstColumn,
    Finset.sum_range_succ, List.ofFn_succ]
  ring

theorem nonlinear_column_list_is_source_reconstruction
    (point scalar : Goldilocks) (partials : Fin 7 → Goldilocks) :
    reconstructHeadZero point 64 29 scalar (List.ofFn partials) :: List.ofFn partials =
      List.ofFn (reconstructNonlinearColumns point scalar partials) := by
  rw [nonlinear_head_zero_is_source_reconstruction]
  simp [reconstructNonlinearColumns, List.ofFn_succ]

theorem linear_column_list_is_source_reconstruction
    (point scalar partialValue : Goldilocks) :
    [reconstructHeadZero point 64 1 scalar [partialValue], partialValue] =
      List.ofFn (reconstructLinearColumns point scalar partialValue) := by
  simp [SmzaRp05PcsWireProjection.reconstructHeadZero_single_partial,
    reconstructLinearColumns, List.ofFn_succ, mul_comm]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsMaskAlgebra
