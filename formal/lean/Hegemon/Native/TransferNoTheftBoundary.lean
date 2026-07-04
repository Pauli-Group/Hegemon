import Hegemon.Native.BlockActionValidation
import Hegemon.Native.TxLeafCanonicalSurface

namespace Hegemon
namespace Native
namespace TransferNoTheftBoundary

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TransferStateAdmission
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

def singletonTransferPayloadAction
    (payload : TransferPayloadInput)
    (transferKey : Nat) : ValidationAction :=
  {
    validTransferAction transferKey with
    payloadValid := transferPayloadAccepts payload
  }

def singletonTransferPayloadValidation
    (payload : TransferPayloadInput)
    (transferKey : Nat) : BlockActionValidationInput :=
  {
    actionCountMatches := true,
    actionHashesMatch := true,
    actionHashesUnique := true,
    consumedBridgeReplays := [],
    actions := [singletonTransferPayloadAction payload transferKey]
  }

theorem singleton_transfer_payload_validation_accepts
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    (payloadAccepted : transferPayloadAccepts payload = true) :
    evaluateBlockActionValidation
        (singletonTransferPayloadValidation payload transferKey) =
      Except.ok
        { validatedActionCount := 1,
          importedBridgeReplayCount := 0,
          lastTransferKey := some transferKey } := by
  simp [
    singletonTransferPayloadValidation,
    singletonTransferPayloadAction,
    evaluateBlockActionValidation,
    evaluateActionsFrom,
    hashInput,
    evaluateAdmissionRejection,
    evaluateScopeAdmission,
    evaluateTransferState,
    transferOrderExtends,
    validTransferAction,
    validTransfer,
    validBridge,
    validTransferState,
    payloadAccepted
  ]

def ActiveInputNoTheftFullBinding
    (payload : TransferPayloadInput)
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness) :
    Prop :=
  Hegemon.Transaction.SpendAuthorization.InputSpendFacts
      merkleRoot
      publicNullifier
      witness
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      shape.inputFlags
      shape.nullifiers
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ TransferPayloadBindingFacts payload
    ∧ payload.bindingHashMatches = true
    ∧ payload.proofBindingHashMatchesKey = true
    ∧ payload.feeMatches = true
    ∧ proofWrapperPreconditions wrapper = true
    ∧ acceptedProofWrapperSurface wrapper
    ∧ Hegemon.Transaction.PublicInputBinding.validBinding
      publicFields
      serializedFields = true
    ∧ Hegemon.Transaction.StatementHash.statementPreimage
      statementFields = some statementBytes
    ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
      bindingFields = some bindingBytes
    ∧ statementFields.merkleRootSeed = merkleRoot
    ∧ bindingFields.anchorSeed = merkleRoot
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      bound.inputFlags
      statementFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      bound.inputFlags
      bindingFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ TxLeafActionBindingFacts input
    ∧ input.nullifiersMatch = true
    ∧ input.inputCountMatches = true
    ∧ input.feeMatches = true
    ∧ input.receiptStatementHashMatches = true
    ∧ input.publicInputsDigestMatches = true
    ∧ input.proofDigestMatches = true
    ∧ input.proofBackendMatches = true
    ∧ input.ciphertextPayloadHashesMatch = true

structure ValidatedTransferPayloadNoTheftBoundaryFacts
    (payload : TransferPayloadInput)
    (transferKey : Nat)
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness) :
    Prop where
  payloadBlockValidationAccepted :
    evaluateBlockActionValidation
        (singletonTransferPayloadValidation payload transferKey) =
      Except.ok
        { validatedActionCount := 1,
          importedBridgeReplayCount := 0,
          lastTransferKey := some transferKey }
  payloadRejectionPrecedesTransferOrder :
    evaluateBlockActionValidation transferPayloadPrecedesOrderValidation =
      Except.error BlockActionReject.transferPayloadInvalid
  transferOrderRejectionPrecedesState :
    evaluateBlockActionValidation transferOrderPrecedesStateValidation =
      Except.error BlockActionReject.transferOrderInvalid
  noTheftFullBinding :
    ActiveInputNoTheftFullBinding
      payload
      input
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
      index
      activeFlag
      publicNullifier
      witness

def InputSlotAuthorizationFullBinding
    (payload : TransferPayloadInput)
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness) :
    Prop :=
  Hegemon.Transaction.SpendAuthorization.InputSlotAuthorizationFacts
      merkleRoot
      activeFlag
      publicNullifier
      witness
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      shape.inputFlags
      shape.nullifiers
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ TransferPayloadBindingFacts payload
    ∧ payload.bindingHashMatches = true
    ∧ payload.proofBindingHashMatchesKey = true
    ∧ payload.feeMatches = true
    ∧ proofWrapperPreconditions wrapper = true
    ∧ acceptedProofWrapperSurface wrapper
    ∧ Hegemon.Transaction.PublicInputBinding.validBinding
      publicFields
      serializedFields = true
    ∧ Hegemon.Transaction.StatementHash.statementPreimage
      statementFields = some statementBytes
    ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
      bindingFields = some bindingBytes
    ∧ statementFields.merkleRootSeed = merkleRoot
    ∧ bindingFields.anchorSeed = merkleRoot
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      bound.inputFlags
      statementFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
      bound.inputFlags
      bindingFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
    ∧ TxLeafActionBindingFacts input
    ∧ input.nullifiersMatch = true
    ∧ input.inputCountMatches = true
    ∧ input.feeMatches = true
    ∧ input.receiptStatementHashMatches = true
    ∧ input.publicInputsDigestMatches = true
    ∧ input.proofDigestMatches = true
    ∧ input.proofBackendMatches = true
    ∧ input.ciphertextPayloadHashesMatch = true

structure ValidatedTransferPayloadInputSlotAuthorizationBoundaryFacts
    (payload : TransferPayloadInput)
    (transferKey : Nat)
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness) :
    Prop where
  payloadBlockValidationAccepted :
    evaluateBlockActionValidation
        (singletonTransferPayloadValidation payload transferKey) =
      Except.ok
        { validatedActionCount := 1,
          importedBridgeReplayCount := 0,
          lastTransferKey := some transferKey }
  payloadRejectionPrecedesTransferOrder :
    evaluateBlockActionValidation transferPayloadPrecedesOrderValidation =
      Except.error BlockActionReject.transferPayloadInvalid
  transferOrderRejectionPrecedesState :
    evaluateBlockActionValidation transferOrderPrecedesStateValidation =
      Except.error BlockActionReject.transferOrderInvalid
  inputSlotFullBinding :
    InputSlotAuthorizationFullBinding
      payload
      input
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
      index
      activeFlag
      publicNullifier
      witness

theorem validated_transfer_payload_active_input_no_theft_full_binding
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    ValidatedTransferPayloadNoTheftBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have nativeFacts :=
    proof_keyed_transfer_payload_canonical_artifact_boundary_facts
      (payload := payload)
      (input := input)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (balanceWitness := balanceWitness)
      (slots := slots)
      (assetId := assetId)
      payloadAccepted
      bindingAccepted
      surface
      sound
  have noTheft :=
    proof_keyed_transfer_payload_active_input_no_theft_full_binding
      nativeFacts
      slot
      active
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      noTheftFullBinding :=
        ⟨noTheft.left, slot, noTheft.right⟩ }

theorem validated_transfer_payload_input_slot_authorization_full_binding
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    ValidatedTransferPayloadInputSlotAuthorizationBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have nativeFacts :=
    proof_keyed_transfer_payload_canonical_artifact_boundary_facts
      (payload := payload)
      (input := input)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (balanceWitness := balanceWitness)
      (slots := slots)
      (assetId := assetId)
      payloadAccepted
      bindingAccepted
      surface
      sound
  have inputSlot :=
    proof_keyed_transfer_payload_input_slot_authorization_full_binding
      nativeFacts
      slot
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      inputSlotFullBinding :=
        ⟨inputSlot.left, slot, inputSlot.right⟩ }

theorem validated_transfer_payload_active_input_no_theft_full_binding_from_spend_soundness
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    ValidatedTransferPayloadNoTheftBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have spendFacts :=
    canonical_statement_spend_soundness_active_input_bound_to_statement
      surface
      spendSound
      slot
      active
  have payloadBinding :=
    transfer_payload_accepts_implies_binding_facts payloadAccepted
  have txLeafFacts :=
    tx_leaf_action_accepts_implies_binding_facts bindingAccepted
  have wrapperPreconditions :
      proofWrapperPreconditions wrapper = true :=
    (accepts_iff_proof_wrapper_preconditions (input := wrapper)).mp
      surface.accepted
  have wrapperSurface :
      acceptedProofWrapperSurface wrapper :=
    proofWrapperAccepts_implies_statement_surface surface.accepted
  have publicBindingValid :
      Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true := by
    simp [
      Hegemon.Transaction.PublicInputBinding.validBinding,
      surface.publicBinding
    ]
  rcases spendFacts with
    ⟨inputSpendFacts, statementRoot, bindingRoot, statementSlot,
      bindingSlot⟩
  rcases payloadBinding with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      noTheftFullBinding :=
        ⟨inputSpendFacts,
          slot,
          ⟨payloadBindingHash, proofBindingHash, payloadFee⟩,
          payloadBindingHash,
          proofBindingHash,
          payloadFee,
          wrapperPreconditions,
          wrapperSurface,
          publicBindingValid,
          surface.statementPreimage,
          surface.bindingMessage,
          statementRoot,
          bindingRoot,
          statementSlot,
          bindingSlot,
          ⟨hNullifiers,
            hCommitments,
            hCiphertextHashes,
            hInputCount,
            hOutputCount,
            hVersion,
            hFee,
            hStablecoinPayload,
            hBalanceTag,
            hReceiptStatementHash,
            hPublicInputsDigest,
            hProofDigest,
            hProofBackend,
            hCiphertextPayloadHashes⟩,
          hNullifiers,
          hInputCount,
          hFee,
          hReceiptStatementHash,
          hPublicInputsDigest,
          hProofDigest,
          hProofBackend,
          hCiphertextPayloadHashes⟩ }

theorem validated_transfer_payload_input_slot_authorization_full_binding_from_spend_soundness
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    ValidatedTransferPayloadInputSlotAuthorizationBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have inputSlotFacts :=
    canonical_statement_spend_soundness_input_slot_bound_to_statement
      surface
      spendSound
      slot
  have payloadBinding :=
    transfer_payload_accepts_implies_binding_facts payloadAccepted
  have txLeafFacts :=
    tx_leaf_action_accepts_implies_binding_facts bindingAccepted
  have wrapperPreconditions :
      proofWrapperPreconditions wrapper = true :=
    (accepts_iff_proof_wrapper_preconditions (input := wrapper)).mp
      surface.accepted
  have wrapperSurface :
      acceptedProofWrapperSurface wrapper :=
    proofWrapperAccepts_implies_statement_surface surface.accepted
  have publicBindingValid :
      Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true := by
    simp [
      Hegemon.Transaction.PublicInputBinding.validBinding,
      surface.publicBinding
    ]
  rcases inputSlotFacts with
    ⟨authorizationFacts, statementRoot, bindingRoot, statementSlot,
      bindingSlot⟩
  rcases payloadBinding with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      inputSlotFullBinding :=
        ⟨authorizationFacts,
          slot,
          ⟨payloadBindingHash, proofBindingHash, payloadFee⟩,
          payloadBindingHash,
          proofBindingHash,
          payloadFee,
          wrapperPreconditions,
          wrapperSurface,
          publicBindingValid,
          surface.statementPreimage,
          surface.bindingMessage,
          statementRoot,
          bindingRoot,
          statementSlot,
          bindingSlot,
          ⟨hNullifiers,
            hCommitments,
            hCiphertextHashes,
            hInputCount,
            hOutputCount,
            hVersion,
            hFee,
            hStablecoinPayload,
            hBalanceTag,
            hReceiptStatementHash,
            hPublicInputsDigest,
            hProofDigest,
            hProofBackend,
            hCiphertextPayloadHashes⟩,
          hNullifiers,
          hInputCount,
          hFee,
          hReceiptStatementHash,
          hPublicInputsDigest,
          hProofDigest,
          hProofBackend,
          hCiphertextPayloadHashes⟩ }

theorem validated_transfer_payload_active_input_no_theft_full_binding_from_spend_boundary_facts
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
    (spendFacts :
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
        spendWitnesses)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    ValidatedTransferPayloadNoTheftBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have slotsAuthorized :=
    Hegemon.Transaction.SpendAuthorization.transactionSpendAuthorized_implies_slots_authorized
      spendFacts.spendAuthorized
  have inputSpendFacts :=
    Hegemon.Transaction.SpendAuthorization.authorizeInputSlots_active_input_facts_at
      slot
      active
      slotsAuthorized
  have slotFacts :=
    canonical_spend_boundary_facts_input_slot_bound_to_statement
      spendFacts
      slot
  have payloadBinding :=
    transfer_payload_accepts_implies_binding_facts payloadAccepted
  have txLeafFacts :=
    tx_leaf_action_accepts_implies_binding_facts bindingAccepted
  rcases slotFacts with
    ⟨_authorizationFacts, statementRoot, bindingRoot, statementSlot,
      bindingSlot⟩
  rcases payloadBinding with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      noTheftFullBinding :=
        ⟨inputSpendFacts,
          slot,
          ⟨payloadBindingHash, proofBindingHash, payloadFee⟩,
          payloadBindingHash,
          proofBindingHash,
          payloadFee,
          spendFacts.wrapperPreconditions,
          spendFacts.wrapperSurface,
          (by
            simp [
              Hegemon.Transaction.PublicInputBinding.validBinding,
              spendFacts.publicBindingExact
            ]),
          spendFacts.statementPreimage,
          spendFacts.bindingMessage,
          statementRoot,
          bindingRoot,
          statementSlot,
          bindingSlot,
          ⟨hNullifiers,
            hCommitments,
            hCiphertextHashes,
            hInputCount,
            hOutputCount,
            hVersion,
            hFee,
            hStablecoinPayload,
            hBalanceTag,
            hReceiptStatementHash,
            hPublicInputsDigest,
            hProofDigest,
            hProofBackend,
            hCiphertextPayloadHashes⟩,
          hNullifiers,
          hInputCount,
          hFee,
          hReceiptStatementHash,
          hPublicInputsDigest,
          hProofDigest,
          hProofBackend,
          hCiphertextPayloadHashes⟩ }

theorem validated_transfer_payload_input_slot_authorization_full_binding_from_spend_boundary_facts
    {payload : TransferPayloadInput}
    {transferKey : Nat}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
    (spendFacts :
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
        spendWitnesses)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    ValidatedTransferPayloadInputSlotAuthorizationBoundaryFacts
      payload
      transferKey
      input
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
      index
      activeFlag
      publicNullifier
      witness := by
  have inputSlotFacts :=
    canonical_spend_boundary_facts_input_slot_bound_to_statement
      spendFacts
      slot
  have payloadBinding :=
    transfer_payload_accepts_implies_binding_facts payloadAccepted
  have txLeafFacts :=
    tx_leaf_action_accepts_implies_binding_facts bindingAccepted
  rcases inputSlotFacts with
    ⟨authorizationFacts, statementRoot, bindingRoot, statementSlot,
      bindingSlot⟩
  rcases payloadBinding with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { payloadBlockValidationAccepted :=
        singleton_transfer_payload_validation_accepts payloadAccepted
      payloadRejectionPrecedesTransferOrder :=
        transfer_payload_precedes_order
      transferOrderRejectionPrecedesState :=
        transfer_order_precedes_state
      inputSlotFullBinding :=
        ⟨authorizationFacts,
          slot,
          ⟨payloadBindingHash, proofBindingHash, payloadFee⟩,
          payloadBindingHash,
          proofBindingHash,
          payloadFee,
          spendFacts.wrapperPreconditions,
          spendFacts.wrapperSurface,
          (by
            simp [
              Hegemon.Transaction.PublicInputBinding.validBinding,
              spendFacts.publicBindingExact
            ]),
          spendFacts.statementPreimage,
          spendFacts.bindingMessage,
          statementRoot,
          bindingRoot,
          statementSlot,
          bindingSlot,
          ⟨hNullifiers,
            hCommitments,
            hCiphertextHashes,
            hInputCount,
            hOutputCount,
            hVersion,
            hFee,
            hStablecoinPayload,
            hBalanceTag,
            hReceiptStatementHash,
            hPublicInputsDigest,
            hProofDigest,
            hProofBackend,
            hCiphertextPayloadHashes⟩,
          hNullifiers,
          hInputCount,
          hFee,
          hReceiptStatementHash,
          hPublicInputsDigest,
          hProofDigest,
          hProofBackend,
          hCiphertextPayloadHashes⟩ }

end TransferNoTheftBoundary
end Native
end Hegemon
