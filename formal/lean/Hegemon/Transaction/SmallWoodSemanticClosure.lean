import Hegemon.Transaction.AcceptedTransactionSoundness

namespace Hegemon
namespace Transaction
namespace SmallWoodSemanticClosure

open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

structure SmallWoodInputConstraintRow where
  noteCommitmentRow : Digest
  authorizationKeyRow : Digest
  nullifierRow : Digest
  merkleRootRow : Digest
deriving DecidableEq, Repr

structure SmallWoodActiveInputConstraintFacts
    (merkleRoot publicNullifier : Digest)
    (witness : InputSpendWitness)
    (row : SmallWoodInputConstraintRow) : Prop where
  noteCommitmentComputed :
    row.noteCommitmentRow = noteCommitmentFromWitness witness
  noteCommitmentBound :
    row.noteCommitmentRow = witness.noteCommitment
  authorizationKeyComputed :
    row.authorizationKeyRow =
      authorizationPublicKeyFromSecret witness.spendSecret
  authorizationKeyBound :
    row.authorizationKeyRow = witness.authorizationPublicKey
  nullifierComputed :
    row.nullifierRow = nullifierFromWitness witness
  nullifierBound :
    row.nullifierRow = publicNullifier
  publicNullifierNonzero : publicNullifier ≠ 0
  merkleRootBound :
    row.merkleRootRow = merkleRoot
  merklePathAccepted :
    verifyPathWithDepth
      mockMerkleNode
      witness.merkleDepth
      witness.noteCommitment
      witness.notePosition
      witness.merkleSiblings
      row.merkleRootRow = true

def SmallWoodInputConstraintRowSatisfied
    (merkleRoot : Digest)
    (activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness)
    (row : SmallWoodInputConstraintRow) : Prop :=
  (activeFlag = 0
      ∧ publicNullifier = 0
      ∧ row.nullifierRow = 0)
    ∨ (activeFlag = 1
      ∧ SmallWoodActiveInputConstraintFacts
        merkleRoot
        publicNullifier
        witness
        row)

inductive SmallWoodInputConstraintsSatisfied
    (merkleRoot : Digest) :
    List Nat ->
      List Digest ->
      List InputSpendWitness ->
      List SmallWoodInputConstraintRow ->
      Prop where
  | nil : SmallWoodInputConstraintsSatisfied merkleRoot [] [] [] []
  | cons
      {activeFlag : Nat}
      {activeFlags : List Nat}
      {publicNullifier : Digest}
      {publicNullifiers : List Digest}
      {witness : InputSpendWitness}
      {witnesses : List InputSpendWitness}
      {row : SmallWoodInputConstraintRow}
      {rows : List SmallWoodInputConstraintRow}
      (head :
        SmallWoodInputConstraintRowSatisfied
          merkleRoot
          activeFlag
          publicNullifier
          witness
          row)
      (tail :
        SmallWoodInputConstraintsSatisfied
          merkleRoot
          activeFlags
          publicNullifiers
          witnesses
          rows) :
      SmallWoodInputConstraintsSatisfied
        merkleRoot
        (activeFlag :: activeFlags)
        (publicNullifier :: publicNullifiers)
        (witness :: witnesses)
        (row :: rows)

theorem active_input_constraint_facts_imply_authorized
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    {row : SmallWoodInputConstraintRow}
    (facts :
      SmallWoodActiveInputConstraintFacts
        merkleRoot
        publicNullifier
        witness
        row) :
    authorizedInputWitness merkleRoot publicNullifier witness = true := by
  have noteCommitment :
      noteCommitmentFromWitness witness = witness.noteCommitment :=
    facts.noteCommitmentComputed.symm.trans facts.noteCommitmentBound
  have authorizationKey :
      authorizationPublicKeyFromSecret witness.spendSecret =
        witness.authorizationPublicKey :=
    facts.authorizationKeyComputed.symm.trans facts.authorizationKeyBound
  have nullifier :
      nullifierFromWitness witness = publicNullifier :=
    facts.nullifierComputed.symm.trans facts.nullifierBound
  have merklePath :
      verifyPathWithDepth
        mockMerkleNode
        witness.merkleDepth
        witness.noteCommitment
        witness.notePosition
        witness.merkleSiblings
        merkleRoot = true := by
    rw [<- facts.merkleRootBound]
    exact facts.merklePathAccepted
  simp [authorizedInputWitness, SpendAuthorization.natEq,
    noteCommitment, authorizationKey, nullifier, merklePath]

theorem input_constraints_imply_slots_authorized
    {merkleRoot : Digest}
    {activeFlags : List Nat}
    {publicNullifiers : List Digest}
    {witnesses : List InputSpendWitness}
    {rows : List SmallWoodInputConstraintRow}
    (satisfied :
      SmallWoodInputConstraintsSatisfied
        merkleRoot
        activeFlags
        publicNullifiers
        witnesses
        rows) :
    authorizeInputSlots
      merkleRoot
      activeFlags
      publicNullifiers
      witnesses = true := by
  induction satisfied with
  | nil => rfl
  | cons head _ inductionHypothesis =>
      rcases head with inactive | active
      · rcases inactive with ⟨activeFlag, publicNullifier, _⟩
        simp [authorizeInputSlots, activeFlag, publicNullifier,
          SpendAuthorization.natEq, inductionHypothesis]
      · rcases active with ⟨activeFlag, facts⟩
        have headAuthorized :=
          active_input_constraint_facts_imply_authorized facts
        simp [authorizeInputSlots, activeFlag, headAuthorized,
          inductionHypothesis]

theorem input_constraints_imply_public_inputs_valid
    {merkleRoot : Digest}
    {activeFlags : List Nat}
    {publicNullifiers : List Digest}
    {witnesses : List InputSpendWitness}
    {rows : List SmallWoodInputConstraintRow}
    (satisfied :
      SmallWoodInputConstraintsSatisfied
        merkleRoot
        activeFlags
        publicNullifiers
        witnesses
        rows) :
    allInputsValid activeFlags publicNullifiers = true := by
  induction satisfied with
  | nil => rfl
  | cons head _ inductionHypothesis =>
      rcases head with inactive | active
      · rcases inactive with ⟨activeFlag, publicNullifier, _⟩
        simp [allInputsValid, validInputSlot, isBoolFlag, isZeroDigest,
          activeFlag, publicNullifier, inductionHypothesis]
      · rcases active with ⟨activeFlag, facts⟩
        simp [allInputsValid, validInputSlot, isBoolFlag, isZeroDigest,
          activeFlag, facts.publicNullifierNonzero, inductionHypothesis]

structure SmallWoodOutputConstraintRow where
  noteOpeningCommitment : Digest
  noteCommitmentRow : Digest
  ciphertextHashRow : Digest
deriving DecidableEq, Repr

structure SmallWoodOutputWitness where
  value : Nat
  assetId : Nat
  recipientKey : Digest
  authorizationPublicKey : Digest
  rho : Nat
  noteRandomness : Nat
  noteCommitment : Digest
deriving DecidableEq, Repr

def noteCommitmentFromOutputWitness
    (witness : SmallWoodOutputWitness) : Digest :=
  (witness.value * 1315423911
    + witness.assetId * 2654435761
    + witness.recipientKey * 97531
    + witness.authorizationPublicKey * 314159
    + witness.rho * 271828
    + witness.noteRandomness * 65537
    + 97) % SpendAuthorization.authDigestMod

def inputNoteSummary (witness : InputSpendWitness) : NoteSummary :=
  { assetId := witness.assetId, value := witness.value }

def outputNoteSummary (witness : SmallWoodOutputWitness) : NoteSummary :=
  { assetId := witness.assetId, value := witness.value }

def activeInputNoteSummaries : List Nat -> List InputSpendWitness -> List NoteSummary
  | activeFlag :: activeFlags, witness :: witnesses =>
      if activeFlag = 1 then
        inputNoteSummary witness :: activeInputNoteSummaries activeFlags witnesses
      else
        activeInputNoteSummaries activeFlags witnesses
  | _, _ => []

def activeOutputNoteSummaries :
    List Nat -> List SmallWoodOutputWitness -> List NoteSummary
  | activeFlag :: activeFlags, witness :: witnesses =>
      if activeFlag = 1 then
        outputNoteSummary witness :: activeOutputNoteSummaries activeFlags witnesses
      else
        activeOutputNoteSummaries activeFlags witnesses
  | _, _ => []

def SmallWoodOutputConstraintRowSatisfied
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest)
    (witness : SmallWoodOutputWitness)
    (row : SmallWoodOutputConstraintRow) : Prop :=
  (activeFlag = 0
      ∧ publicCommitment = 0
      ∧ publicCiphertextHash = 0)
    ∨ (activeFlag = 1
      ∧ publicCommitment ≠ 0
      ∧ row.noteOpeningCommitment = noteCommitmentFromOutputWitness witness
      ∧ row.noteOpeningCommitment = witness.noteCommitment
      ∧ row.noteCommitmentRow = row.noteOpeningCommitment
      ∧ row.noteCommitmentRow = publicCommitment
      ∧ row.ciphertextHashRow = publicCiphertextHash)

inductive SmallWoodOutputConstraintsSatisfied :
      List Nat ->
      List Digest ->
      List Digest ->
      List SmallWoodOutputWitness ->
      List SmallWoodOutputConstraintRow ->
      Prop where
  | nil : SmallWoodOutputConstraintsSatisfied [] [] [] [] []
  | cons
      {activeFlag : Nat}
      {activeFlags : List Nat}
      {publicCommitment publicCiphertextHash : Digest}
      {publicCommitments publicCiphertextHashes : List Digest}
      {witness : SmallWoodOutputWitness}
      {witnesses : List SmallWoodOutputWitness}
      {row : SmallWoodOutputConstraintRow}
      {rows : List SmallWoodOutputConstraintRow}
      (head :
        SmallWoodOutputConstraintRowSatisfied
          activeFlag
          publicCommitment
          publicCiphertextHash
          witness
          row)
      (tail :
        SmallWoodOutputConstraintsSatisfied
          activeFlags
          publicCommitments
          publicCiphertextHashes
          witnesses
          rows) :
      SmallWoodOutputConstraintsSatisfied
        (activeFlag :: activeFlags)
        (publicCommitment :: publicCommitments)
        (publicCiphertextHash :: publicCiphertextHashes)
        (witness :: witnesses)
        (row :: rows)

theorem output_constraints_imply_slots_valid
    {activeFlags : List Nat}
    {publicCommitments publicCiphertextHashes : List Digest}
    {witnesses : List SmallWoodOutputWitness}
    {rows : List SmallWoodOutputConstraintRow}
    (satisfied :
      SmallWoodOutputConstraintsSatisfied
        activeFlags
        publicCommitments
        publicCiphertextHashes
        witnesses
        rows) :
    allOutputsValid
      activeFlags
      publicCommitments
      publicCiphertextHashes = true := by
  induction satisfied with
  | nil => rfl
  | cons head _ inductionHypothesis =>
      rcases head with inactive | active
      · rcases inactive with
          ⟨activeFlag, publicCommitment, publicCiphertextHash⟩
        simp [allOutputsValid, validOutputSlot, isBoolFlag, isZeroDigest,
          activeFlag, publicCommitment, publicCiphertextHash,
          inductionHypothesis]
      · rcases active with
          ⟨activeFlag, publicCommitment, _, _, _, _, _, _⟩
        simp [allOutputsValid, validOutputSlot, isBoolFlag, isZeroDigest,
          activeFlag, publicCommitment, inductionHypothesis]

theorem active_output_constraint_binds_note_opening
    {activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {witness : SmallWoodOutputWitness}
    {row : SmallWoodOutputConstraintRow}
    (satisfied :
      SmallWoodOutputConstraintRowSatisfied
        activeFlag
        publicCommitment
        publicCiphertextHash
        witness
        row)
    (active : activeFlag = 1) :
    publicCommitment = row.noteOpeningCommitment := by
  rcases satisfied with inactive | activeFacts
  · rw [inactive.left] at active
    cases active
  · exact activeFacts.2.2.2.2.2.1.symm.trans activeFacts.2.2.2.2.1

theorem active_output_constraint_recomputes_note_commitment
    {activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {witness : SmallWoodOutputWitness}
    {row : SmallWoodOutputConstraintRow}
    (satisfied :
      SmallWoodOutputConstraintRowSatisfied
        activeFlag
        publicCommitment
        publicCiphertextHash
        witness
        row)
    (active : activeFlag = 1) :
    noteCommitmentFromOutputWitness witness = witness.noteCommitment := by
  rcases satisfied with inactive | activeFacts
  · rw [inactive.left] at active
    cases active
  · exact activeFacts.2.2.1.symm.trans activeFacts.2.2.2.1

structure SmallWoodBalanceConstraintsSatisfied
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  slotsMaterialized : balanceSlots balanceWitness = some slots
  nativeConservation :
    Transaction.intEq
      (slotDelta Transaction.nativeAsset slots)
      (nativeExpected balanceWitness) = true
  stablecoinConservation :
    stablecoinRules balanceWitness.stablecoin slots = true

theorem balance_constraints_imply_valid_balance
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodBalanceConstraintsSatisfied balanceWitness slots) :
    validBalance balanceWitness = true := by
  unfold validBalance
  rw [satisfied.slotsMaterialized]
  simp [satisfied.nativeConservation, satisfied.stablecoinConservation]

def smallwoodPublicShapeCoreValid (shape : PublicInputShape) : Bool :=
  shape.inputFlags.length = maxInputs
    && shape.outputFlags.length = maxOutputs
    && shape.nullifiers.length = maxInputs
    && shape.commitments.length = maxOutputs
    && shape.ciphertextHashes.length = maxOutputs
    && shape.balanceSlotAssets.length = PublicInputs.balanceSlotCount
    && balanceSlotsOrdered shape.balanceSlotAssets
    && (nonZeroExists shape.nullifiers || nonZeroExists shape.commitments)
    && isBoolFlag shape.valueBalanceSign
    && isBoolFlag shape.stablecoinEnabled
    && isBoolFlag shape.stablecoinIssuanceSign
    && (shape.stablecoinEnabled = 0 || stablecoinAssetPresent shape)

structure SmallWoodSemanticConstraintsSatisfied
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (inputRows : List SmallWoodInputConstraintRow)
    (outputWitnesses : List SmallWoodOutputWitness)
    (outputRows : List SmallWoodOutputConstraintRow)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  publicShapeCoreValid : smallwoodPublicShapeCoreValid shape = true
  inputConstraints :
    SmallWoodInputConstraintsSatisfied
      merkleRoot
      shape.inputFlags
      shape.nullifiers
      spendWitnesses
      inputRows
  outputConstraints :
    SmallWoodOutputConstraintsSatisfied
      shape.outputFlags
      shape.commitments
      shape.ciphertextHashes
      outputWitnesses
      outputRows
  balanceInputsBound :
    balanceWitness.inputs =
      activeInputNoteSummaries shape.inputFlags spendWitnesses
  balanceOutputsBound :
    balanceWitness.outputs =
      activeOutputNoteSummaries shape.outputFlags outputWitnesses
  balanceConstraints :
    SmallWoodBalanceConstraintsSatisfied balanceWitness slots
  balanceSlotAssetsBound :
    slots.map (fun slot => slot.assetId) = shape.balanceSlotAssets

theorem balance_input_summary_mismatch_rejects
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (mismatch :
      balanceWitness.inputs ≠
        activeInputNoteSummaries shape.inputFlags spendWitnesses) :
    ¬ SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputWitnesses
      outputRows
      balanceWitness
      slots := by
  intro satisfied
  exact mismatch satisfied.balanceInputsBound

theorem balance_output_summary_mismatch_rejects
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (mismatch :
      balanceWitness.outputs ≠
        activeOutputNoteSummaries shape.outputFlags outputWitnesses) :
    ¬ SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputWitnesses
      outputRows
      balanceWitness
      slots := by
  intro satisfied
  exact mismatch satisfied.balanceOutputsBound

theorem balance_slot_asset_mismatch_rejects
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (mismatch :
      slots.map (fun slot => slot.assetId) ≠ shape.balanceSlotAssets) :
    ¬ SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputWitnesses
      outputRows
      balanceWitness
      slots := by
  intro satisfied
  exact mismatch satisfied.balanceSlotAssetsBound

theorem semantic_constraints_imply_public_shape_valid
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots) :
    validPublicInputShape shape = true := by
  have inputsValid :=
    input_constraints_imply_public_inputs_valid satisfied.inputConstraints
  have outputsValid :=
    output_constraints_imply_slots_valid satisfied.outputConstraints
  have coreValid := satisfied.publicShapeCoreValid
  unfold smallwoodPublicShapeCoreValid at coreValid
  unfold validPublicInputShape
  simp at coreValid
  simp [coreValid, inputsValid, outputsValid]

def SmallWoodExactConstraintExtractionAssumption
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (inputRows : List SmallWoodInputConstraintRow)
    (outputWitnesses : List SmallWoodOutputWitness)
    (outputRows : List SmallWoodOutputConstraintRow)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  proofWrapperAccepts wrapper = true ->
    SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputWitnesses
      outputRows
      balanceWitness
      slots

theorem semantic_constraints_imply_spend_authorized
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots) :
    transactionSpendAuthorized shape merkleRoot spendWitnesses = true := by
  unfold transactionSpendAuthorized
  simp [semantic_constraints_imply_public_shape_valid satisfied,
    input_constraints_imply_slots_authorized satisfied.inputConstraints]

theorem accepted_proof_and_semantic_constraints_imply_transaction_relation
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (accepted : proofWrapperAccepts wrapper = true)
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots) :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots := by
  exact
    ⟨accepted,
      proofWrapperAccepts_implies_statement_surface accepted,
      satisfied.balanceConstraints.slotsMaterialized,
      balance_constraints_imply_valid_balance satisfied.balanceConstraints,
      semantic_constraints_imply_public_shape_valid satisfied,
      input_constraints_imply_slots_authorized satisfied.inputConstraints⟩

theorem accepted_proof_with_exact_constraint_extraction_implies_relation
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (accepted : proofWrapperAccepts wrapper = true)
    (extraction :
      SmallWoodExactConstraintExtractionAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots) :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots :=
  accepted_proof_and_semantic_constraints_imply_transaction_relation
    accepted
    (extraction accepted)

theorem semantic_constraints_imply_output_slots_valid
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputWitnesses : List SmallWoodOutputWitness}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
        outputWitnesses
        outputRows
        balanceWitness
        slots) :
    allOutputsValid
      shape.outputFlags
      shape.commitments
      shape.ciphertextHashes = true :=
  output_constraints_imply_slots_valid satisfied.outputConstraints

end SmallWoodSemanticClosure
end Transaction
end Hegemon
