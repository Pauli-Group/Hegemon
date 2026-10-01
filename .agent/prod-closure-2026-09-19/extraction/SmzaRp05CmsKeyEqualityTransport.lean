import SmzaRp05CurrentJointObserverKeys
import SmzaRp05CurrentJointExtractionPrograms
import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05PhysicalAcceptedReplayLite

/-! Equality transports for the finite grouped-key carrier.  These are
ordinary dependent casts along an already-proved key-type equality; there is
no zero extension or assumption that two independently prepared states agree.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05PhysicalAcceptedReplayLite

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Input₁ Input₂ Counter BaseWork : Type}
variable [fintypeInput₁ : Fintype Input₁] [decEqInput₁ : DecidableEq Input₁]
variable [fintypeInput₂ : Fintype Input₂] [decEqInput₂ : DecidableEq Input₂]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev OrdinaryOutput (Counter : Type) :=
  SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)

abbrev OrdinaryWorkspace (Counter BaseWork : Type) :=
  SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)

abbrev OrdinaryCmsState (Input Counter BaseWork : Type)
    [Fintype Input] [DecidableEq Input]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork] :=
  State Input (OrdinaryOutput Counter) (OrdinaryOutput Counter)
    (OrdinaryWorkspace Counter BaseWork)

/-- The ordinary-prefix syntax depends on its finite key type through its
database-independent gate constructors. Equality of the key types therefore
transports the entire syntax exactly. -/
theorem ordinaryPrefixTypeEq {cap start finish queries : Nat}
    (sameInput : Input₁ = Input₂) :
    OrdinaryPrefix (Key := Input₁) (Counter := Counter) (BaseWork := BaseWork)
      (cap := cap) start finish queries =
    OrdinaryPrefix (Key := Input₂) (Counter := Counter) (BaseWork := BaseWork)
      (cap := cap) start finish queries := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- The corresponding CMS state family is transported by the same input
equality. -/
theorem cmsStateTypeEq (sameInput : Input₁ = Input₂) :
    OrdinaryCmsState Input₁ Counter BaseWork =
      OrdinaryCmsState Input₂ Counter BaseWork := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- Squared norm is invariant under the CMS state cast induced by an input
type equality. The finite basis sum is handled at the abstract function-space
level, avoiding expansion of the compressed database basis. -/
theorem normSquared_cast_input (sameInput : Input₁ = Input₂)
    (state : OrdinaryCmsState Input₁ Counter BaseWork) :
    normSquared (cast (cmsStateTypeEq (Counter := Counter) (BaseWork := BaseWork)
      sameInput) state) = normSquared state := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- Ordinary execution commutes with key-type transport, including the
database-independent contraction operators embedded in the prefix. -/
theorem ordinaryRun_cast (sameInput : Input₁ = Input₂)
    {cap start finish queries : Nat}
    (program : OrdinaryPrefix (Key := Input₁) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) start finish queries)
    (state : OrdinaryCmsState Input₁ Counter BaseWork) :
    cast (cmsStateTypeEq (Counter := Counter) (BaseWork := BaseWork) sameInput)
        (ordinaryRun program state) =
      ordinaryRun
        (cast (ordinaryPrefixTypeEq (Counter := Counter) (BaseWork := BaseWork)
          (cap := cap) sameInput) program)
        (cast (cmsStateTypeEq (Counter := Counter) (BaseWork := BaseWork)
          sameInput) state) := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  rfl

/-- Naturalness of the physical transcript interpreter under an input-type
equality. The branch is shared (its type depends on the program and decoder,
not on the key type); only each encoded query is transported. -/
theorem physicalRun_cast_input
    {Output Phase Work Result : Type}
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (sameInput : Input₁ = Input₂)
    (encode₁ : V8SmzaOracleParser.RawInput → Input₁)
    (encode₂ : V8SmzaOracleParser.RawInput → Input₂)
    (sameEncode : ∀ raw, encode₂ raw = cast sameInput (encode₁ raw))
    (decode : V8SmzaOracleParser.RawInput → Output → V8SmzaOracleParser.RawDigest)
    (program : SmzaRp05ExecutableMerkleVerifier.Program Result)
    (branch : Branches decode program)
    (state : State Input₁ Output Phase Work) :
    cast (congrArg (fun input => State input Output Phase Work) sameInput)
        (physicalRun encode₁ decode program branch state) =
      physicalRun encode₂ decode program branch
        (cast (congrArg (fun input => State input Output Phase Work) sameInput) state) := by
  cases sameInput
  have sameFintype : fintypeInput₁ = fintypeInput₂ := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqInput₁ = decEqInput₂ := Subsingleton.elim _ _
  cases sameDecEq
  have sameEncode' : encode₂ = encode₁ := funext sameEncode
  cases sameEncode'
  rfl

end
end HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport
