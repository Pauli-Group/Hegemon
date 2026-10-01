import SmzaRp04RawMcaSampling
import SmzaRp05CurrentAcceptedQuerySupport
import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout
import HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness
import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler

/-! The current DECS sampler emits five row-major rows of 140 field words.
This decoder preserves that wire order and only changes the output coordinate
view to the `Fin 140 → Fin 5` convention used by the coefficient predicates.
The historical RP04 decoder remains unchanged. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDecsMatrixSampling

open SmzaRp05CurrentAcceptedQuerySupport (Coefficients)
open V8Smz9CappedRawSampler (FieldOutput sourceFieldSize RawByteBlock)
open V8Smz9RuntimeRandomness (idealFieldCoinEquivGoldilocks)
open V8Smz9RuntimeFieldLayout (matrixEquiv)
open SmzaRp04RawRoleSampling (rawFieldSample totalEquivDecoder selectedRawBlocks)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9CoherentVectorMerkle (VectorOutput)

set_option autoImplicit false
noncomputable section

def currentDecsMatrixFieldEquiv :
    FieldOutput sourceFieldSize (140 * 5) ≃ Coefficients :=
  ((Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks).trans
      (matrixEquiv 5 140 Goldilocks)).trans
    (Equiv.piComm (fun (_ : Fin 5) (_ : Fin 140) => Goldilocks))

theorem current_decs_matrix_field_equiv_apply
    (fields : FieldOutput sourceFieldSize (140 * 5))
    (column : Fin 140) (row : Fin 5) :
    currentDecsMatrixFieldEquiv fields column row =
      idealFieldCoinEquivGoldilocks (fields
        ((finProdFinEquiv : Fin 5 × Fin 140 ≃ Fin (5 * 140)) (row, column))) := by
  simp only [currentDecsMatrixFieldEquiv, Equiv.trans_apply,
    Equiv.piComm_apply, Function.swap]
  rw [HegemonCrypto.SmallWood.V8Smz9RuntimeFieldLayout.matrix_equiv_apply]
  rfl

def currentRawDecsMatrixOutput
    (raw : Fin (digestCallCap (140 * 5)) → RawByteBlock) : Option Coefficients :=
  (rawFieldSample (digestCallCap (140 * 5)) (140 * 5) raw).bind
    (totalEquivDecoder currentDecsMatrixFieldEquiv)

def currentActualDecsMatrixOutput {Counter : Type*}
    (select : Fin (digestCallCap (140 * 5)) ↪ Counter)
    (vector : VectorOutput Counter) : Option Coefficients :=
  currentRawDecsMatrixOutput (selectedRawBlocks select vector)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentDecsMatrixSampling
