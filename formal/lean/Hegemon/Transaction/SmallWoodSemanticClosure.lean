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

def SmallWoodOutputConstraintRowSatisfied
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest)
  (row : SmallWoodOutputConstraintRow) : Prop :=
  (activeFlag = 0
      ∧ publicCommitment = 0
      ∧ publicCiphertextHash = 0)
    ∨ (activeFlag = 1
      ∧ publicCommitment ≠ 0
      ∧ row.noteCommitmentRow = row.noteOpeningCommitment
      ∧ row.noteCommitmentRow = publicCommitment
      ∧ row.ciphertextHashRow = publicCiphertextHash)

inductive SmallWoodOutputConstraintsSatisfied :
    List Nat ->
      List Digest ->
      List Digest ->
      List SmallWoodOutputConstraintRow ->
      Prop where
  | nil : SmallWoodOutputConstraintsSatisfied [] [] [] []
  | cons
      {activeFlag : Nat}
      {activeFlags : List Nat}
      {publicCommitment publicCiphertextHash : Digest}
      {publicCommitments publicCiphertextHashes : List Digest}
      {row : SmallWoodOutputConstraintRow}
      {rows : List SmallWoodOutputConstraintRow}
      (head :
        SmallWoodOutputConstraintRowSatisfied
          activeFlag
          publicCommitment
          publicCiphertextHash
          row)
      (tail :
        SmallWoodOutputConstraintsSatisfied
          activeFlags
          publicCommitments
          publicCiphertextHashes
          rows) :
      SmallWoodOutputConstraintsSatisfied
        (activeFlag :: activeFlags)
        (publicCommitment :: publicCommitments)
        (publicCiphertextHash :: publicCiphertextHashes)
        (row :: rows)

theorem output_constraints_imply_slots_valid
    {activeFlags : List Nat}
    {publicCommitments publicCiphertextHashes : List Digest}
    {rows : List SmallWoodOutputConstraintRow}
    (satisfied :
      SmallWoodOutputConstraintsSatisfied
        activeFlags
        publicCommitments
        publicCiphertextHashes
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
          ⟨activeFlag, publicCommitment, _, _, _⟩
        simp [allOutputsValid, validOutputSlot, isBoolFlag, isZeroDigest,
          activeFlag, publicCommitment, inductionHypothesis]

theorem active_output_constraint_binds_note_opening
    {activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {row : SmallWoodOutputConstraintRow}
    (satisfied :
      SmallWoodOutputConstraintRowSatisfied
        activeFlag
        publicCommitment
        publicCiphertextHash
        row)
    (active : activeFlag = 1) :
    publicCommitment = row.noteOpeningCommitment := by
  rcases satisfied with inactive | activeFacts
  · rw [inactive.left] at active
    cases active
  · exact activeFacts.2.2.2.1.symm.trans activeFacts.2.2.1

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
      outputRows
  balanceConstraints :
    SmallWoodBalanceConstraintsSatisfied balanceWitness slots

theorem semantic_constraints_imply_public_shape_valid
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
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
    (outputRows : List SmallWoodOutputConstraintRow)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  proofWrapperAccepts wrapper = true ->
    SmallWoodSemanticConstraintsSatisfied
      shape
      merkleRoot
      spendWitnesses
      inputRows
      outputRows
      balanceWitness
      slots

theorem semantic_constraints_imply_spend_authorized
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {inputRows : List SmallWoodInputConstraintRow}
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
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
    {outputRows : List SmallWoodOutputConstraintRow}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (satisfied :
      SmallWoodSemanticConstraintsSatisfied
        shape
        merkleRoot
        spendWitnesses
        inputRows
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
