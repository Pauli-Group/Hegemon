import SmzaRp05CurrentSourceBlockReplay
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentFullOrRoleXViewCoverage
import SmzaRp05ActualAcceptedAuthorizationEndpoint

/-! # Source-replay envelopes from the actual designated selector

The finite ledger's source replay receives this selector's output, not an
independently chosen accepted relation witness. Missing extraction remains
an explicit `none` entry and therefore the replay's indexed failure outcome.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedRunEnvelope

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05ConditionedExecution (XKey)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector)
open SmzaRp05ActualAcceptedAuthorizationEndpoint
  (designatedWitnessOfFullSuccessSelector)
open SmzaRp05CurrentSourceBlockReplay (CurrentRunEnvelope)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl
  HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.SmzaRp05Components.program
  HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport.rustV8SemanticPrimitives
  SmzaQ38Recovery.packedFromRows
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage.currentAcceptedXViewFullSuccessSelector

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
variable (producer : Program ExistingProofFieldView)
variable (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
variable (pending : Bool) (nonce : Fin (2 ^ 32)) (fallback : RawDigest)
variable (typed : V8PublicStatement)
variable (parsed : parseCurrentPublicStatement? statement = some typed)
variable (fuel : Nat)
variable (ctx : Context (Key := Key (actualProgram producer ns statement pending nonce))
  (Counter := GroupCounter) (BaseWork := BaseWork))
variable (branch : Branches groupedDecode (actualProgram producer ns statement pending nonce))
variable (view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter))

/-- Package only the designated decoder output on a successful selector arm.
The producer, branch, namespace, statement and raw nonchallenge view stay fixed
through the construction. No witness is a constructor argument. -/
def selectedRunEnvelope : Option CurrentRunEnvelope :=
  if selected : currentAcceptedXViewFullSuccessSelector producer ns statement pending
      nonce fallback typed fuel ctx branch view then
    some {
      preamble := statement
      typedStatement := typed
      run := designatedWitnessOfFullSuccessSelector producer ns statement pending nonce
        fallback typed parsed fuel ctx branch view selected
    }
  else none

/-- The replay's missing-envelope arm is precisely failure of the actual
current full-success selector, not a separate guard or resampled experiment. -/
theorem selectedRunEnvelope_eq_none_iff :
    selectedRunEnvelope producer ns statement pending nonce fallback typed parsed fuel
      ctx branch view = none ↔
      ¬ currentAcceptedXViewFullSuccessSelector producer ns statement pending nonce
        fallback typed fuel ctx branch view := by
  classical
  unfold selectedRunEnvelope
  by_cases selected : currentAcceptedXViewFullSuccessSelector producer ns statement pending
      nonce fallback typed fuel ctx branch view
  · simp only [dif_pos selected, Option.some_ne_none, false_iff]
    exact not_not_intro selected
  · rw [dif_neg selected]
    exact ⟨fun _ => selected, fun _ => rfl⟩

/-- A successful envelope preserves the typed statement actually parsed for
this stage. These are data equalities, not supplied acceptance conclusions. -/
theorem selectedRunEnvelope_statement
    (envelope : CurrentRunEnvelope)
    (produced : selectedRunEnvelope producer ns statement pending nonce fallback typed
      parsed fuel ctx branch view = some envelope) :
    envelope.preamble = statement ∧ envelope.typedStatement = typed := by
  classical
  unfold selectedRunEnvelope at produced
  split_ifs at produced with selected
  · cases Option.some.inj produced
    exact ⟨rfl, rfl⟩

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedRunEnvelope
