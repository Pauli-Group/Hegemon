import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentJointRetainedProofs
import SmzaRp05CurrentFiniteGroupedProgram

/-! # Exact program identities for the two-target extraction route

These are only program equalities.  The second-target verifier is the actual
joint chronology once, while the first-target unit observer is the same joint
followed by the first producer/verifier prefix as a proof-only suffix.  No
independent-run, selector, coverage, or mass premise is introduced. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentJointAcceptedExecution
  (firstAcceptedVerifierProgram secondProducerAfterFirst
    secondAcceptedVerifierProgram program_bind_assoc)
open SmzaRp05CurrentJointRetainedProofs (terminalUnitPrefixReplayObserver)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

/-- The second accepted target is one actual joint execution, expressed as
the ordinary accepted-mass endpoint's producer followed by target₂'s verifier.
-/
theorem actualProgram_secondTarget_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂ =
    secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
  rfl

/-- The first-target endpoint producer is the completed joint followed by the
first proof producer.  Associating the final verifier inward yields exactly
the unit-valued whole-prefix terminal observer. -/
theorem actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁ =
    terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
  unfold actualProgram terminalUnitPrefixReplayObserver firstAcceptedVerifierProgram
  exact program_bind_assoc
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
    (fun _ => producer₁)
    (fun wire₁ => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)

/-- Key universes used by dependent selectors/registers transport along the
first-target program identity. -/
theorem firstTarget_key_eq_terminalUnitPrefixReplayObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁) =
    Key (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  exact congrArg Key
    (actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver producer₁ producer₂
      ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)

/-- The second-target Key universe likewise is the actual joint Key universe;
all downstream dependent structures can use this equality directly. -/
theorem secondTarget_key_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Key (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂) =
    Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  exact congrArg Key
    (actualProgram_secondTarget_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms
