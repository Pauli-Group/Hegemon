import SmzaRp05CurrentSelectedRunEnvelope
import SmzaRp05CurrentFullOrRoleXViewCoverage

/-! # Chronological actual-selector stage list

This carrier stores only verifier inputs. Each optional envelope is computed
by the designated full-success selector; absent extraction is preserved as
`none` for the native block replay to report at its exact transaction index.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedStageList

open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedRunEnvelope
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05ConditionedExecution (XKey)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentSourceBlockReplay (CurrentRunEnvelope)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Program" => SmzaRp05ExecutableMerkleVerifier.Program

set_option autoImplicit false

noncomputable section

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- One transaction stage before extraction. The dependent verifier branch and
view are retained exactly so the designated selector runs without accepting
a caller-built relation/source witness. -/
structure CurrentSelectedStage where
  producer : Program ExistingProofFieldView
  ns : Namespace
  statement : Statement
  pending : Bool
  nonce : Fin (2 ^ 32)
  fallback : RawDigest
  typed : V8PublicStatement
  parsed : parseCurrentPublicStatement? statement = some typed
  fuel : Nat
  ctx : Context (Key := Key (actualProgram producer ns statement pending nonce))
    (Counter := GroupCounter) (BaseWork := BaseWork)
  branch : Branches groupedDecode (actualProgram producer ns statement pending nonce)
  view : XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput GroupCounter)

def CurrentSelectedStage.envelope (stage : CurrentSelectedStage (BaseWork := BaseWork)) :
    Option CurrentRunEnvelope :=
  selectedRunEnvelope stage.producer stage.ns stage.statement stage.pending
    stage.nonce stage.fallback stage.typed stage.parsed stage.fuel stage.ctx
    stage.branch stage.view

/-- Missing extraction is exactly failure of the actual full-success
selector. -/
theorem CurrentSelectedStage.envelope_eq_none_iff
    (stage : CurrentSelectedStage (BaseWork := BaseWork)) :
    stage.envelope = none ↔
      ¬ currentAcceptedXViewFullSuccessSelector stage.producer stage.ns
        stage.statement stage.pending stage.nonce stage.fallback stage.typed
        stage.fuel stage.ctx stage.branch stage.view := by
  simpa [CurrentSelectedStage.envelope] using
    selectedRunEnvelope_eq_none_iff stage.producer stage.ns stage.statement
      stage.pending stage.nonce stage.fallback stage.typed stage.parsed stage.fuel
      stage.ctx stage.branch stage.view

/-- A present envelope retains the stage's parsed public statement/preamble. -/
theorem CurrentSelectedStage.envelope_statement
    (stage : CurrentSelectedStage (BaseWork := BaseWork)) (envelope : CurrentRunEnvelope)
    (selected : stage.envelope = some envelope) :
    envelope.preamble = stage.statement ∧ envelope.typedStatement = stage.typed := by
  apply selectedRunEnvelope_statement stage.producer stage.ns stage.statement
    stage.pending stage.nonce stage.fallback stage.typed stage.parsed stage.fuel
    stage.ctx stage.branch stage.view envelope
  simpa only [CurrentSelectedStage.envelope] using selected

/-- Stage order and missing-selector positions are retained by the list map. -/
def selectedTransactions (stages : List (CurrentSelectedStage (BaseWork := BaseWork))) :
    List (Option CurrentRunEnvelope) := stages.map CurrentSelectedStage.envelope

omit [Fintype BaseWork] [DecidableEq BaseWork] in
theorem selectedTransactions_length
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork))) :
    (selectedTransactions stages).length = stages.length := by
  simp [selectedTransactions]

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedStageList
