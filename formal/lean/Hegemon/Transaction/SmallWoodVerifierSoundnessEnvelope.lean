import Hegemon.Transaction.AirBalanceBoundary
import Hegemon.Transaction.ProofSystemBoundary
import Hegemon.Transaction.SmallWoodBalanceBoundary
import Hegemon.Transaction.SmallWoodCandidateWrapperAdmission
import Hegemon.Transaction.SmallWoodSpendAuthorization
import Hegemon.Transaction.SmallWoodTranscriptBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodVerifierSoundnessEnvelope

open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

structure CandidateWrapperAdmissionFacts
    (input : SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput) :
    Prop where
  accepted : SmallWoodCandidateWrapperAdmission.wrapperAccepts input = true
  selectedCanonicalNonempty :
    (SmallWoodCandidateWrapperAdmission.canonicalWrapperAdmits
        input.current = true
      ∧ input.current.arkProofBytesPresent = true)
      ∨ (SmallWoodCandidateWrapperAdmission.canonicalWrapperAdmits
          input.current = false
        ∧ SmallWoodCandidateWrapperAdmission.canonicalWrapperAdmits
          input.legacy = true
        ∧ input.legacy.arkProofBytesPresent = true)

structure SmallWoodVerifierEnvelopeFacts
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : PublicInputBinding.PublicFields)
    (serializedFields : PublicInputBinding.SerializedFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot)
    (candidateWrapper :
      SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput)
    (transcriptSurface :
      SmallWoodTranscriptBinding.TranscriptSurface)
    (authSurface :
      SmallWoodSpendAuthorization.ActiveAuthLinkSurface)
    (inputSpendSurface :
      SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface)
    (outputSurface :
      SmallWoodSpendAuthorization.ActiveOutputBindingSurface)
    (smallwoodBalanceSurface :
      SmallWoodBalanceBoundary.BalanceSurface)
    (airBalanceSurface :
      AirBalanceBoundary.AirBalanceFinalRowSurface) : Prop where
  canonicalBoundaryFacts :
    CanonicalDeployedVerifierBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  noTheftBoundaryFacts :
    CanonicalProofSystemNoTheftBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  spendBoundaryFacts :
    CanonicalDeployedVerifierSpendBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
  balancePublicBoundaryFacts :
    CanonicalDeployedVerifierBalancePublicBoundaryFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      balanceWitness
      slots
  candidateWrapperFacts :
    CandidateWrapperAdmissionFacts candidateWrapper
  transcriptFacts :
    SmallWoodTranscriptBinding.SmallwoodTranscriptBindingFacts
      transcriptSurface
  activeAuthFacts :
    authSurface.active = true ->
      SmallWoodSpendAuthorization.ActiveAuthLinkFacts authSurface
  inputSpendFacts :
    SmallWoodSpendAuthorization.ActiveInputSpendBoundaryFacts
      inputSpendSurface
  outputFacts :
    SmallWoodSpendAuthorization.ActiveOutputBindingFacts outputSurface
  smallwoodBalanceFacts :
    SmallWoodBalanceBoundary.SmallWoodBalanceBoundaryFacts
      smallwoodBalanceSurface
  airFinalRowFacts :
    AirBalanceBoundary.AirBalanceFinalRowFacts airBalanceSurface
  spendAndBalanceFacts :
    balanceSlots balanceWitness = some slots
      ∧ validBalance balanceWitness = true
      ∧ transactionSpendAuthorized shape merkleRoot spendWitnesses = true
  nativeDeltaAuthorized :
    slotDelta nativeAsset slots = nativeExpected balanceWitness
  publicAuthorizedDeltas :
    ∀ {assetId : Nat},
      slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId
  smallwoodNativeDeltaAuthorized :
    SmallWoodBalanceBoundary.nativeDelta smallwoodBalanceSurface =
      Int.ofNat smallwoodBalanceSurface.fee -
        SmallWoodBalanceBoundary.signedMagnitude
          smallwoodBalanceSurface.valueBalanceSign
          smallwoodBalanceSurface.valueBalanceMagnitude
  airNativeDeltaAuthorized :
    AirBalanceBoundary.slotDelta airBalanceSurface 0 =
      airBalanceSurface.fee -
        AirBalanceBoundary.signedMagnitude
          airBalanceSurface.valueBalanceSign
          airBalanceSurface.valueBalanceMagnitude

theorem accepted_candidate_wrapper_exposes_admission_facts
    {input : SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    (accepted :
      SmallWoodCandidateWrapperAdmission.wrapperAccepts input = true) :
    CandidateWrapperAdmissionFacts input := by
  exact
    {
      accepted := accepted,
      selectedCanonicalNonempty :=
        (SmallWoodCandidateWrapperAdmission.wrapper_accepts_iff_selected_canonical_nonempty
          (input := input)).mp accepted
    }

theorem accepted_smallwood_surfaces_with_split_soundness_imply_verifier_envelope
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {candidateWrapper :
      SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {transcriptSurface :
      SmallWoodTranscriptBinding.TranscriptSurface}
    {authSurface :
      SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      AirBalanceBoundary.AirBalanceFinalRowSurface}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses)
    (balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        balanceWitness
        slots)
    (candidateAccepted :
      SmallWoodCandidateWrapperAdmission.wrapperAccepts
        candidateWrapper = true)
    (transcriptAccepted :
      SmallWoodTranscriptBinding.acceptedSmallwoodTranscriptBinding
        transcriptSurface)
    (authAccepted :
      SmallWoodSpendAuthorization.activeAuthLinkAccepted
        authSurface = true)
    (inputAccepted :
      SmallWoodSpendAuthorization.activeInputSpendBoundaryAccepted
        inputSpendSurface = true)
    (outputAccepted :
      SmallWoodSpendAuthorization.activeOutputBindingAccepted
        outputSurface = true)
    (smallwoodBalanceAccepted :
      SmallWoodBalanceBoundary.AcceptedSmallWoodBalanceConstraints
        smallwoodBalanceSurface)
    (airBalanceAccepted :
      AirBalanceBoundary.AcceptedAirBalanceFinalRowConstraints
        airBalanceSurface) :
    SmallWoodVerifierEnvelopeFacts
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
      candidateWrapper
      transcriptSurface
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface := by
  have spendFacts :=
    spend_soundness_canonical_surface_implies_spend_boundary_facts
      surface
      spendSound
  have balancePublicFacts :=
    balance_public_soundness_canonical_surface_implies_balance_public_boundary_facts
      surface
      balanceSound
  have canonicalFacts :=
    canonical_split_boundary_facts_imply_full_boundary_facts
      spendFacts
      balancePublicFacts
  exact
    {
      canonicalBoundaryFacts := canonicalFacts,
      noTheftBoundaryFacts :=
        deployed_soundness_parts_canonical_surface_implies_no_theft_boundary_facts
          surface
          spendSound
          balanceSound,
      spendBoundaryFacts := spendFacts,
      balancePublicBoundaryFacts := balancePublicFacts,
      candidateWrapperFacts :=
        accepted_candidate_wrapper_exposes_admission_facts
          candidateAccepted,
      transcriptFacts :=
        SmallWoodTranscriptBinding.accepted_smallwood_transcript_binding_implies_statement_boundary_facts
          transcriptAccepted,
      activeAuthFacts := by
        intro active
        exact
          SmallWoodSpendAuthorization.active_auth_link_constraints_imply_goldilocks_auth_link
            authAccepted
            active,
      inputSpendFacts :=
        SmallWoodSpendAuthorization.accepted_smallwood_spend_constraints_imply_active_input_spend_boundary
          inputAccepted,
      outputFacts :=
        SmallWoodSpendAuthorization.accepted_smallwood_output_constraints_imply_active_output_binding_boundary
          outputAccepted,
      smallwoodBalanceFacts :=
        SmallWoodBalanceBoundary.accepted_smallwood_balance_constraints_expose_boundary_facts
          smallwoodBalanceAccepted,
      airFinalRowFacts :=
        AirBalanceBoundary.accepted_air_balance_final_row_exposes_boundary_facts
          airBalanceAccepted,
      spendAndBalanceFacts :=
        canonical_boundary_facts_expose_spend_and_balance canonicalFacts,
      nativeDeltaAuthorized :=
        canonical_boundary_facts_native_delta canonicalFacts,
      publicAuthorizedDeltas := by
        intro assetId
        exact
          canonical_balance_public_boundary_facts_authorized_public_delta_value
            balancePublicFacts,
      smallwoodNativeDeltaAuthorized :=
        SmallWoodBalanceBoundary.accepted_smallwood_balance_constraints_authorize_native_delta
          smallwoodBalanceAccepted,
      airNativeDeltaAuthorized :=
        AirBalanceBoundary.accepted_air_balance_final_row_native_delta
          airBalanceAccepted
    }

theorem smallwood_verifier_envelope_exposes_no_theft_and_public_conservation
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {candidateWrapper :
      SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {transcriptSurface :
      SmallWoodTranscriptBinding.TranscriptSurface}
    {authSurface :
      SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      AirBalanceBoundary.AirBalanceFinalRowSurface}
    (facts :
      SmallWoodVerifierEnvelopeFacts
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots
        candidateWrapper
        transcriptSurface
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface) :
    transactionSpendAuthorized shape merkleRoot spendWitnesses = true
      ∧ (∀ {assetId : Nat},
        slotDelta assetId slots =
          publicAuthorizedAssetDeltaValue publicFields assetId)
      ∧ slotDelta nativeAsset slots = nativeExpected balanceWitness :=
  ⟨facts.spendAndBalanceFacts.right.right,
    facts.publicAuthorizedDeltas,
    facts.nativeDeltaAuthorized⟩

end SmallWoodVerifierSoundnessEnvelope
end Transaction
end Hegemon
