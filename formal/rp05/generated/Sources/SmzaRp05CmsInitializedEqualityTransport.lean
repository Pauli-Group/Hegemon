import HegemonCrypto.CmsOracleSimulation
import SmzaRp05CmsEventEqualityTransport

/-! Transport of the initialized CMS register state over equality of input
types. The second register vector is always derived by casting the first;
no independently supplied register/state equality is assumed.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CmsInitializedEqualityTransport

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.SmzaRp05CmsEventEqualityTransport

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Input₁ Input₂ Output Phase Workspace : Type}
variable [fintypeInput₁ : Fintype Input₁] [decEqInput₁ : DecidableEq Input₁]
variable [fintypeInput₂ : Fintype Input₂] [decEqInput₂ : DecidableEq Input₂]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Register-basis types are dependent only on the input carrier. -/
theorem registerBasisTypeEq (sameInput : Input₁ = Input₂) :
    RegisterBasis (Input := Input₁) (Phase := Phase) (Workspace := Workspace) =
      RegisterBasis (Input := Input₂) (Phase := Phase) (Workspace := Workspace) :=
  congrArg (fun input => RegisterBasis (Input := input)
    (Phase := Phase) (Workspace := Workspace)) sameInput

/-- Register amplitude-vector types follow the same input equality. -/
theorem registerStateTypeEq (sameInput : Input₁ = Input₂) :
    (RegisterBasis (Input := Input₁) (Phase := Phase) (Workspace := Workspace) → ℂ) =
      (RegisterBasis (Input := Input₂) (Phase := Phase) (Workspace := Workspace) → ℂ) :=
  congrArg (fun registers => registers → ℂ) (registerBasisTypeEq sameInput)

/-- Cast a register vector to the equal input carrier. This is the derived
second register function used by the initialized-state transport below. -/
def castRegisterState (sameInput : Input₁ = Input₂)
    (registers : RegisterBasis (Input := Input₁) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    RegisterBasis (Input := Input₂) (Phase := Phase) (Workspace := Workspace) → ℂ :=
  cast (registerStateTypeEq sameInput) registers

/-- The empty-support partial-random-oracle initialization commutes with the
input equality when its register function is the cast of the original one. -/
theorem partialRandomOracleState_cast_empty (sameInput : Input₁ = Input₂)
    (registers : RegisterBasis (Input := Input₁) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    cast (stateTypeEq sameInput)
        (partialRandomOracleState (Output := Output) ∅ registers) =
      partialRandomOracleState (Output := Output) ∅
        (castRegisterState sameInput registers) := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- Equality transport of the initialized state preserves its squared norm;
the target register vector is definitionally the cast of the source vector. -/
theorem partialRandomOracleState_normSquared_cast_empty
    (sameInput : Input₁ = Input₂)
    (registers : RegisterBasis (Input := Input₁) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    normSquared
        (partialRandomOracleState (Output := Output) ∅
          (castRegisterState sameInput registers)) =
      normSquared (partialRandomOracleState (Output := Output) ∅ registers) := by
  rw [← partialRandomOracleState_cast_empty sameInput registers]
  exact normSquared_cast_input sameInput
    (partialRandomOracleState (Output := Output) ∅ registers)

end
end HegemonCrypto.SmallWood.SmzaRp05CmsInitializedEqualityTransport
