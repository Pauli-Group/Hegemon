import Hegemon.Transaction.SmallWoodSemanticClosure
import Hegemon.Transaction.NoteCommitmentInputs
import Hegemon.Transaction.PublicInputBinding
import Hegemon.Transaction.SmallWoodProductionSemanticSpec
import Hegemon.Transaction.StatementHash
import Hegemon.Transaction.SmallWoodKnowledgeSoundnessReduction

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

namespace Hegemon
namespace Transaction
namespace SmallWoodProductionConstraintRefinement

open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SmallWoodSemanticClosure
open Hegemon.Transaction.SpendAuthorization
open Hegemon.Transaction.SmallWoodKnowledgeSoundnessReduction

def activePublicFieldRanges : List PublicFieldRange :=
  [ { name := "input_flags", start := 0, stop := 2 },
    { name := "output_flags", start := 2, stop := 4 },
    { name := "nullifiers", start := 4, stop := 16 },
    { name := "commitments", start := 16, stop := 28 },
    { name := "ciphertext_hashes", start := 28, stop := 40 },
    { name := "fee", start := 40, stop := 41 },
    { name := "value_balance_sign", start := 41, stop := 42 },
    { name := "value_balance_magnitude", start := 42, stop := 43 },
    { name := "merkle_root", start := 43, stop := 49 },
    { name := "balance_slot_assets", start := 49, stop := 53 },
    { name := "stablecoin_enabled", start := 53, stop := 54 },
    { name := "stablecoin_asset", start := 54, stop := 55 },
    { name := "stablecoin_policy_version", start := 55, stop := 56 },
    { name := "stablecoin_issuance_sign", start := 56, stop := 57 },
    { name := "stablecoin_issuance_magnitude", start := 57, stop := 58 },
    { name := "stablecoin_policy_hash", start := 58, stop := 64 },
    { name := "stablecoin_oracle_commitment", start := 64, stop := 70 },
    { name := "stablecoin_attestation_commitment", start := 70, stop := 76 },
    { name := "circuit_version", start := 76, stop := 77 },
    { name := "crypto_suite", start := 77, stop := 78 } ]

def PublicFieldRange.indices (range : PublicFieldRange) : List Nat :=
  (List.range (range.stop - range.start)).map (range.start + ·)

def activePublicFieldIndices : List Nat :=
  activePublicFieldRanges.flatMap PublicFieldRange.indices

theorem active_public_field_map_covers_every_deployed_index_exactly_once :
    activePublicFieldIndices = List.range 78 := by
  decide

inductive ConstraintFixture where
  | active
  | stablecoin
deriving DecidableEq, Repr

def expectedConstraintMap : ConstraintFixture -> ProductionConstraintMap
  | .active => activeConstraintMap
  | .stablecoin => stablecoinConstraintMap

def expectedConstraintTableDigest : ConstraintFixture -> List Nat
  | .active => activeConstraintTableDigest
  | .stablecoin => stablecoinConstraintTableDigest

structure ProductionConstraintArtifact where
  map : ProductionConstraintMap
  exactTableDigest : List Nat
deriving DecidableEq, Repr

def expectedConstraintArtifact (fixture : ConstraintFixture) :
    ProductionConstraintArtifact :=
  { map := expectedConstraintMap fixture
    exactTableDigest := expectedConstraintTableDigest fixture }

def productionConstraintMapAccepts
    (fixture : ConstraintFixture)
    (candidate : ProductionConstraintMap) : Bool :=
  candidate = expectedConstraintMap fixture

def productionConstraintArtifactAccepts
    (fixture : ConstraintFixture)
    (candidate : ProductionConstraintArtifact) : Bool :=
  candidate = expectedConstraintArtifact fixture

def omittedFieldMap : ProductionConstraintMap :=
  { activeConstraintMap with publicFieldRanges := activePublicFieldRanges.tail }

def reorderedFieldMap : ProductionConstraintMap :=
  { activeConstraintMap with
    publicFieldRanges :=
      { name := "output_flags", start := 2, stop := 4 }
        :: { name := "input_flags", start := 0, stop := 2 }
        :: activePublicFieldRanges.drop 2 }

def substitutedFieldMap : ProductionConstraintMap :=
  { activeConstraintMap with
    publicFieldRanges :=
      { name := "substituted", start := 0, stop := 2 } :: activePublicFieldRanges.tail }

def duplicatedFieldMap : ProductionConstraintMap :=
  { activeConstraintMap with
    publicFieldRanges :=
      { name := "input_flags", start := 0, stop := 2 } :: activePublicFieldRanges }

def wrappedFieldMap : ProductionConstraintMap :=
  { activeConstraintMap with
    publicFieldRanges :=
      activePublicFieldRanges.dropLast ++
        [{ name := "crypto_suite", start := 77, stop := 79 }] }

def truncatedLinearTermCoefficientsMap : ProductionConstraintMap :=
  { activeConstraintMap with
    linearTermCoefficients := activeConstraintMap.linearTermCoefficients.dropLast }

def truncatedDigestArtifact : ProductionConstraintArtifact :=
  { map := activeConstraintMap
    exactTableDigest := activeConstraintTableDigest.dropLast }

def mismatchedConstraintCountMap : ProductionConstraintMap :=
  { activeConstraintMap with
    linearConstraintCount := activeConstraintMap.linearConstraintCount - 1 }

def mismatchedTableDigestArtifact : ProductionConstraintArtifact :=
  { map := activeConstraintMap
    exactTableDigest := 0 :: activeConstraintTableDigest.tail }

def substitutedNonlinearExpressionMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearExpressions :=
      ProductionConstraintExpression.constExpr 1 ::
        activeConstraintMap.nonlinearExpressions.tail }

def reorderedNonlinearRootMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearConstraintRoots :=
      activeConstraintMap.nonlinearConstraintRoots.reverse }

def mismatchedNonlinearProgramDigestMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearProgramDigest := 0 :: activeConstraintMap.nonlinearProgramDigest.tail }

def zeroLinearTableMap : ProductionConstraintMap :=
  { activeConstraintMap with
    linearConstraintCount := 0
    linearTermCount := 0
    linearTermOffsets := [0]
    linearTermIndices := []
    linearTermCoefficients := []
    linearTargets := [] }

def stalePublicValueMap : ProductionConstraintMap :=
  { activeConstraintMap with
    publicValues := activeConstraintMap.publicValues.set 40
      (fieldAdd (activeConstraintMap.publicValues.getD 40 0) 1) }

theorem active_constraint_map_accepts :
    productionConstraintMapAccepts .active activeConstraintMap = true := by
  native_decide

theorem stablecoin_constraint_map_accepts :
    productionConstraintMapAccepts .stablecoin stablecoinConstraintMap = true := by
  native_decide

theorem active_constraint_artifact_accepts :
    productionConstraintArtifactAccepts .active
      { map := activeConstraintMap
        exactTableDigest := activeConstraintTableDigest } = true := by
  native_decide

theorem stablecoin_constraint_artifact_accepts :
    productionConstraintArtifactAccepts .stablecoin
      { map := stablecoinConstraintMap
        exactTableDigest := stablecoinConstraintTableDigest } = true := by
  native_decide

theorem omitted_field_map_rejects :
    productionConstraintMapAccepts .active omittedFieldMap = false := by
  native_decide

theorem reordered_field_map_rejects :
    productionConstraintMapAccepts .active reorderedFieldMap = false := by
  native_decide

theorem substituted_field_map_rejects :
    productionConstraintMapAccepts .active substitutedFieldMap = false := by
  native_decide

theorem duplicated_field_map_rejects :
    productionConstraintMapAccepts .active duplicatedFieldMap = false := by
  native_decide

theorem wrapped_field_map_rejects :
    productionConstraintMapAccepts .active wrappedFieldMap = false := by
  native_decide

theorem truncated_linear_term_coefficients_rejects :
    productionConstraintMapAccepts .active truncatedLinearTermCoefficientsMap = false := by
  native_decide

theorem truncated_table_digest_rejects :
    productionConstraintArtifactAccepts .active truncatedDigestArtifact = false := by
  native_decide

theorem mismatched_constraint_count_rejects :
    productionConstraintMapAccepts .active mismatchedConstraintCountMap = false := by
  native_decide

theorem mismatched_table_digest_rejects :
    productionConstraintArtifactAccepts .active mismatchedTableDigestArtifact = false := by
  native_decide

theorem substituted_nonlinear_expression_rejects :
    productionConstraintMapAccepts .active substitutedNonlinearExpressionMap = false := by
  native_decide

theorem reordered_nonlinear_root_rejects :
    productionConstraintMapAccepts .active reorderedNonlinearRootMap = false := by
  native_decide

theorem mismatched_nonlinear_program_digest_rejects :
    productionConstraintMapAccepts .active mismatchedNonlinearProgramDigestMap = false := by
  native_decide

inductive ProductionConstraintFamily where
  | mapIdentity
  | publicShape
  | inputActiveFlag
  | inputInactivePadding
  | inputNoteCommitment
  | inputAuthorizationKey
  | inputNullifier
  | inputPublicBinding
  | inputMerkleGeometry
  | inputMerklePath
  | outputActiveFlag
  | outputInactivePadding
  | outputNoteCommitment
  | outputPublicBinding
  | outputCiphertextBinding
  | noteHashGeometry
  | balanceInputBinding
  | balanceOutputBinding
  | balanceSlotMaterialization
  | nativeConservation
  | stablecoinConservation
  | balanceSlotAssets
deriving DecidableEq, Repr

def productionConstraintFamilies : List ProductionConstraintFamily :=
  [ .mapIdentity, .publicShape, .inputActiveFlag, .inputInactivePadding,
    .inputNoteCommitment, .inputAuthorizationKey, .inputNullifier,
    .inputPublicBinding, .inputMerkleGeometry, .inputMerklePath,
    .outputActiveFlag, .outputInactivePadding, .outputNoteCommitment,
    .outputPublicBinding, .outputCiphertextBinding, .noteHashGeometry, .balanceInputBinding,
    .balanceOutputBinding, .balanceSlotMaterialization, .nativeConservation,
    .stablecoinConservation, .balanceSlotAssets ]

theorem production_constraint_family_map_is_complete :
    productionConstraintFamilies.length = 22 := by
  decide

structure ProductionConstraintCheck where
  family : ProductionConstraintFamily
  accepted : Bool
deriving DecidableEq, Repr

def productionConstraintCheck
    (family : ProductionConstraintFamily)
    (accepted : Bool) : ProductionConstraintCheck :=
  { family, accepted }

def productionConstraintChecksPass (checks : List ProductionConstraintCheck) : Bool :=
  checks.all (fun check => check.accepted)

def ProductionInputRowExecuted
    (merkleRoot : Digest)
    (activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness)
    (row : SmallWoodInputConstraintRow) : Prop :=
  (activeFlag = 0 ∧ publicNullifier = 0 ∧ row.nullifierRow = 0)
    ∨ (activeFlag = 1
      ∧ row.noteCommitmentRow = noteCommitmentFromWitness witness
      ∧ row.noteCommitmentRow = witness.noteCommitment
      ∧ row.authorizationKeyRow =
          authorizationPublicKeyFromSecret witness.spendSecret
      ∧ row.authorizationKeyRow = witness.authorizationPublicKey
      ∧ row.nullifierRow = nullifierFromWitness witness
      ∧ row.nullifierRow = publicNullifier
      ∧ publicNullifier ≠ 0
      ∧ row.merkleRootRow = merkleRoot
      ∧ witness.merkleDepth = 32
      ∧ witness.merkleSiblings.length = 32
      ∧ witness.notePosition < 2 ^ 32
      ∧ verifyPathWithDepth
          mockMerkleNode
          witness.merkleDepth
          witness.noteCommitment
          witness.notePosition
          witness.merkleSiblings
          row.merkleRootRow = true)

def productionInputRowChecks
    (merkleRoot : Digest)
    (activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness)
    (row : SmallWoodInputConstraintRow) : List ProductionConstraintCheck :=
  if activeFlag = 0 then
    [ productionConstraintCheck .inputActiveFlag (decide (activeFlag = 0)),
      productionConstraintCheck .inputInactivePadding (decide (publicNullifier = 0)),
      productionConstraintCheck .inputInactivePadding (decide (row.nullifierRow = 0)) ]
  else
    [ productionConstraintCheck .inputActiveFlag (decide (activeFlag = 1)),
      productionConstraintCheck .inputNoteCommitment
        (decide (row.noteCommitmentRow = noteCommitmentFromWitness witness)),
      productionConstraintCheck .inputNoteCommitment
        (decide (row.noteCommitmentRow = witness.noteCommitment)),
      productionConstraintCheck .inputAuthorizationKey
        (decide (row.authorizationKeyRow =
          authorizationPublicKeyFromSecret witness.spendSecret)),
      productionConstraintCheck .inputAuthorizationKey
        (decide (row.authorizationKeyRow = witness.authorizationPublicKey)),
      productionConstraintCheck .inputNullifier
        (decide (row.nullifierRow = nullifierFromWitness witness)),
      productionConstraintCheck .inputPublicBinding
        (decide (row.nullifierRow = publicNullifier)),
      productionConstraintCheck .inputNullifier (decide (publicNullifier ≠ 0)),
      productionConstraintCheck .inputPublicBinding
        (decide (row.merkleRootRow = merkleRoot)),
      productionConstraintCheck .inputMerkleGeometry
        (decide (witness.merkleDepth = 32)),
      productionConstraintCheck .inputMerkleGeometry
        (decide (witness.merkleSiblings.length = 32)),
      productionConstraintCheck .inputMerkleGeometry
        (decide (witness.notePosition < 2 ^ 32)),
      productionConstraintCheck .inputMerklePath
        (verifyPathWithDepth mockMerkleNode witness.merkleDepth witness.noteCommitment
          witness.notePosition witness.merkleSiblings row.merkleRootRow) ]

def productionInputRowExecutes
    (merkleRoot : Digest)
    (activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness)
    (row : SmallWoodInputConstraintRow) : Bool :=
  productionConstraintChecksPass
    (productionInputRowChecks merkleRoot activeFlag publicNullifier witness row)

theorem production_input_row_checks_refine_semantic_row
    {merkleRoot : Digest} {activeFlag : Nat} {publicNullifier : Digest}
    {witness : InputSpendWitness} {row : SmallWoodInputConstraintRow}
    (executed :
      productionInputRowExecutes merkleRoot activeFlag publicNullifier witness row = true) :
    ProductionInputRowExecuted merkleRoot activeFlag publicNullifier witness row := by
  by_cases inactive : activeFlag = 0
  · simpa [productionInputRowExecutes, productionInputRowChecks,
      productionConstraintChecksPass, productionConstraintCheck,
      ProductionInputRowExecuted, inactive] using executed
  · simpa [productionInputRowExecutes, productionInputRowChecks,
      productionConstraintChecksPass, productionConstraintCheck,
      ProductionInputRowExecuted, inactive] using executed

def productionInputRowsExecute
    (merkleRoot : Digest) :
    List Nat -> List Digest -> List InputSpendWitness ->
      List SmallWoodInputConstraintRow -> Bool
  | [], [], [], [] => true
  | flag :: flags, nullifier :: nullifiers, witness :: witnesses, row :: rows =>
      productionInputRowExecutes merkleRoot flag nullifier witness row
        && productionInputRowsExecute merkleRoot flags nullifiers witnesses rows
  | _, _, _, _ => false

theorem production_input_rows_refine_semantic_rows
    {merkleRoot : Digest} {flags : List Nat} {nullifiers : List Digest}
    {witnesses : List InputSpendWitness} {rows : List SmallWoodInputConstraintRow}
    (executed : productionInputRowsExecute merkleRoot flags nullifiers witnesses rows = true) :
    SmallWoodInputConstraintsSatisfied merkleRoot flags nullifiers witnesses rows := by
  induction flags generalizing nullifiers witnesses rows with
  | nil =>
      cases nullifiers <;> cases witnesses <;> cases rows <;>
        simp [productionInputRowsExecute] at executed
      exact .nil
  | cons flag flags inductionHypothesis =>
      cases nullifiers with
      | nil => simp [productionInputRowsExecute] at executed
      | cons nullifier nullifiers =>
        cases witnesses with
        | nil => simp [productionInputRowsExecute] at executed
        | cons witness witnesses =>
          cases rows with
          | nil => simp [productionInputRowsExecute] at executed
          | cons row rows =>
            simp only [productionInputRowsExecute, Bool.and_eq_true] at executed
            have head : ProductionInputRowExecuted merkleRoot flag nullifier witness row := by
              exact production_input_row_checks_refine_semantic_row executed.1
            have tail := inductionHypothesis executed.2
            apply SmallWoodInputConstraintsSatisfied.cons
            · rcases head with inactive | active
              · exact Or.inl inactive
              · refine Or.inr ⟨active.1, ?_⟩
                exact
                  { noteCommitmentComputed := active.2.1
                    noteCommitmentBound := active.2.2.1
                    authorizationKeyComputed := active.2.2.2.1
                    authorizationKeyBound := active.2.2.2.2.1
                    nullifierComputed := active.2.2.2.2.2.1
                    nullifierBound := active.2.2.2.2.2.2.1
                    publicNullifierNonzero := active.2.2.2.2.2.2.2.1
                    merkleRootBound := active.2.2.2.2.2.2.2.2.1
                    deployedMerkleDepth := active.2.2.2.2.2.2.2.2.2.1
                    deployedMerkleSiblingCount := active.2.2.2.2.2.2.2.2.2.2.1
                    canonicalNotePosition := active.2.2.2.2.2.2.2.2.2.2.2.1
                    merklePathAccepted := active.2.2.2.2.2.2.2.2.2.2.2.2 }
            · exact tail

structure ProductionNoteOpening where
  value : Nat
  assetId : Nat
  recipientKey : Digest
  authorizationPublicKey : Digest
  rho : Nat
  noteRandomness : Nat
deriving DecidableEq, Repr

def productionNoteOpeningFromOutputWitness
    (witness : SmallWoodOutputWitness) : ProductionNoteOpening :=
  { value := witness.value
    assetId := witness.assetId
    recipientKey := witness.recipientKey
    authorizationPublicKey := witness.authorizationPublicKey
    rho := witness.rho
    noteRandomness := witness.noteRandomness }

structure ProductionNoteHashSpec where
  domainTag : Nat
  preimageWordCount : Nat
  poseidonWidth : Nat
  poseidonRate : Nat
  outputLimbCount : Nat

def deployedProductionNoteHashSpecAccepts (spec : ProductionNoteHashSpec) : Bool :=
  decide (spec.domainTag = 1
    ∧ spec.preimageWordCount = 18
    ∧ spec.poseidonWidth = 12
    ∧ spec.poseidonRate = 6
    ∧ spec.outputLimbCount = 6)

def productionWords4 (value : Nat) : List Nat :=
  [ ((value / 2 ^ 192) % 2 ^ 64) % 18446744069414584321,
    ((value / 2 ^ 128) % 2 ^ 64) % 18446744069414584321,
    ((value / 2 ^ 64) % 2 ^ 64) % 18446744069414584321,
    (value % 2 ^ 64) % 18446744069414584321 ]

def productionNotePreimage (opening : ProductionNoteOpening) : List Nat :=
  [fieldValue opening.value, fieldValue opening.assetId]
    ++ productionWords4 opening.recipientKey
    ++ productionWords4 opening.rho
    ++ productionWords4 opening.noteRandomness
    ++ productionWords4 opening.authorizationPublicKey

theorem production_note_preimage_has_exact_deployed_word_count
    (opening : ProductionNoteOpening) :
    (productionNotePreimage opening).length = 18 := by
  simp [productionNotePreimage, productionWords4]

opaque productionPoseidon2Sponge : Nat -> List Nat -> Digest

def productionNoteHash (opening : ProductionNoteOpening) : Digest :=
  productionPoseidon2Sponge 1 (productionNotePreimage opening)

def ProductionHashCollisionResistance (spec : ProductionNoteHashSpec) : Prop :=
  deployedProductionNoteHashSpecAccepts spec = true
    ∧ ∀ left right,
      productionNoteHash left = productionNoteHash right ->
        productionNotePreimage left = productionNotePreimage right

structure ProductionValueAssetCanonical (opening : ProductionNoteOpening) : Prop where
  valueBelowFieldModulus : opening.value < goldilocksModulus
  assetBelowFieldModulus : opening.assetId < goldilocksModulus

theorem canonical_note_preimage_equality_binds_value_and_asset
    {left right : ProductionNoteOpening}
    (leftCanonical : ProductionValueAssetCanonical left)
    (rightCanonical : ProductionValueAssetCanonical right)
    (inputsEqual : productionNotePreimage left = productionNotePreimage right) :
    left.value = right.value ∧ left.assetId = right.assetId := by
  have firstEqual := congrArg List.head? inputsEqual
  have secondEqual := congrArg (fun values => values.tail.head?) inputsEqual
  constructor
  · simpa [productionNotePreimage, fieldValue,
      Nat.mod_eq_of_lt leftCanonical.valueBelowFieldModulus,
      Nat.mod_eq_of_lt rightCanonical.valueBelowFieldModulus] using firstEqual
  · simpa [productionNotePreimage, fieldValue,
      Nat.mod_eq_of_lt leftCanonical.assetBelowFieldModulus,
      Nat.mod_eq_of_lt rightCanonical.assetBelowFieldModulus] using secondEqual

def ProductionCanonicalOutputCommitmentBinding
    (spec : ProductionNoteHashSpec) : Prop :=
  deployedProductionNoteHashSpecAccepts spec = true
    ∧ forall publicCommitment left right,
      ProductionValueAssetCanonical left ->
      ProductionValueAssetCanonical right ->
      productionNoteHash left = publicCommitment ->
      productionNoteHash right = publicCommitment ->
      left.value = right.value ∧ left.assetId = right.assetId

theorem production_hash_collision_resistance_binds_canonical_output_value_and_asset
    {spec : ProductionNoteHashSpec}
    (collisionResistance : ProductionHashCollisionResistance spec) :
    ProductionCanonicalOutputCommitmentBinding spec := by
  refine ⟨collisionResistance.1, ?_⟩
  intro publicCommitment left right leftCanonical rightCanonical
    leftCommitment rightCommitment
  apply canonical_note_preimage_equality_binds_value_and_asset
    leftCanonical rightCanonical
  exact collisionResistance.2 left right
    (leftCommitment.trans rightCommitment.symm)

def zeroProductionNoteOpening : ProductionNoteOpening :=
  { value := 0
    assetId := 0
    recipientKey := 0
    authorizationPublicKey := 0
    rho := 0
    noteRandomness := 0 }

def fieldModulusAliasProductionNoteOpening : ProductionNoteOpening :=
  { zeroProductionNoteOpening with noteRandomness := 18446744069414584321 }

theorem raw_note_openings_can_alias_after_canonical_field_encoding :
    fieldModulusAliasProductionNoteOpening ≠ zeroProductionNoteOpening
      ∧ productionNotePreimage fieldModulusAliasProductionNoteOpening =
        productionNotePreimage zeroProductionNoteOpening := by
  native_decide

def ProductionOutputRowExecuted
    (_noteHashSpec : ProductionNoteHashSpec)
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest)
    (witness : SmallWoodOutputWitness)
    (row : SmallWoodOutputConstraintRow) : Prop :=
  (activeFlag = 0 ∧ publicCommitment = 0 ∧ publicCiphertextHash = 0)
    ∨ (activeFlag = 1
      ∧ publicCommitment ≠ 0
      ∧ row.noteOpeningCommitment =
        productionNoteHash (productionNoteOpeningFromOutputWitness witness)
      ∧ row.noteOpeningCommitment = witness.noteCommitment
      ∧ row.noteCommitmentRow = row.noteOpeningCommitment
      ∧ row.noteCommitmentRow = publicCommitment
      ∧ row.ciphertextHashRow = publicCiphertextHash)

def productionOutputRowChecks
    (_noteHashSpec : ProductionNoteHashSpec)
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest)
    (witness : SmallWoodOutputWitness)
    (row : SmallWoodOutputConstraintRow) : List ProductionConstraintCheck :=
  if activeFlag = 0 then
    [ productionConstraintCheck .outputActiveFlag (decide (activeFlag = 0)),
      productionConstraintCheck .outputInactivePadding (decide (publicCommitment = 0)),
      productionConstraintCheck .outputInactivePadding (decide (publicCiphertextHash = 0)) ]
  else
    [ productionConstraintCheck .outputActiveFlag (decide (activeFlag = 1)),
      productionConstraintCheck .outputPublicBinding (decide (publicCommitment ≠ 0)),
      productionConstraintCheck .outputNoteCommitment
        (decide (row.noteOpeningCommitment =
          productionNoteHash (productionNoteOpeningFromOutputWitness witness))),
      productionConstraintCheck .outputNoteCommitment
        (decide (row.noteOpeningCommitment = witness.noteCommitment)),
      productionConstraintCheck .outputNoteCommitment
        (decide (row.noteCommitmentRow = row.noteOpeningCommitment)),
      productionConstraintCheck .outputPublicBinding
        (decide (row.noteCommitmentRow = publicCommitment)),
      productionConstraintCheck .outputCiphertextBinding
        (decide (row.ciphertextHashRow = publicCiphertextHash)) ]

def productionOutputRowExecutes
    (noteHashSpec : ProductionNoteHashSpec)
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest)
    (witness : SmallWoodOutputWitness)
    (row : SmallWoodOutputConstraintRow) : Bool :=
  productionConstraintChecksPass
    (productionOutputRowChecks noteHashSpec activeFlag publicCommitment publicCiphertextHash
      witness row)

theorem production_output_row_checks_refine_semantic_row
    {noteHashSpec : ProductionNoteHashSpec}
    {activeFlag : Nat} {publicCommitment publicCiphertextHash : Digest}
    {witness : SmallWoodOutputWitness} {row : SmallWoodOutputConstraintRow}
    (executed :
      productionOutputRowExecutes noteHashSpec activeFlag publicCommitment publicCiphertextHash
        witness row = true) :
    ProductionOutputRowExecuted noteHashSpec activeFlag publicCommitment publicCiphertextHash
      witness row := by
  by_cases inactive : activeFlag = 0
  · simpa [productionOutputRowExecutes, productionOutputRowChecks,
      productionConstraintChecksPass, productionConstraintCheck,
      ProductionOutputRowExecuted, inactive] using executed
  · simpa [productionOutputRowExecutes, productionOutputRowChecks,
      productionConstraintChecksPass, productionConstraintCheck,
      ProductionOutputRowExecuted, inactive] using executed

def productionOutputRowsExecute :
    ProductionNoteHashSpec -> List Nat -> List Digest -> List Digest -> List SmallWoodOutputWitness ->
      List SmallWoodOutputConstraintRow -> Bool
  | _, [], [], [], [], [] => true
  | noteHashSpec, flag :: flags, commitment :: commitments, ciphertextHash :: ciphertextHashes,
      witness :: witnesses, row :: rows =>
      productionOutputRowExecutes noteHashSpec flag commitment ciphertextHash witness row
        && productionOutputRowsExecute noteHashSpec flags commitments ciphertextHashes witnesses rows
  | _, _, _, _, _, _ => false

theorem production_output_rows_refine_semantic_rows
    {noteHashSpec : ProductionNoteHashSpec}
    {flags : List Nat} {commitments ciphertextHashes : List Digest}
    {witnesses : List SmallWoodOutputWitness} {rows : List SmallWoodOutputConstraintRow}
    (executed :
      productionOutputRowsExecute noteHashSpec flags commitments ciphertextHashes witnesses rows =
        true) :
    SmallWoodOutputConstraintsSatisfied flags commitments ciphertextHashes witnesses rows := by
  induction flags generalizing commitments ciphertextHashes witnesses rows with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases witnesses <;> cases rows <;>
        simp [productionOutputRowsExecute] at executed
      exact .nil
  | cons flag flags inductionHypothesis =>
      cases commitments with
      | nil => simp [productionOutputRowsExecute] at executed
      | cons commitment commitments =>
        cases ciphertextHashes with
        | nil => simp [productionOutputRowsExecute] at executed
        | cons ciphertextHash ciphertextHashes =>
          cases witnesses with
          | nil => simp [productionOutputRowsExecute] at executed
          | cons witness witnesses =>
            cases rows with
            | nil => simp [productionOutputRowsExecute] at executed
            | cons row rows =>
              simp only [productionOutputRowsExecute, Bool.and_eq_true] at executed
              have head :
                  ProductionOutputRowExecuted noteHashSpec flag commitment ciphertextHash witness
                    row := by
                exact production_output_row_checks_refine_semantic_row executed.1
              have semanticHead :
                  SmallWoodOutputConstraintRowSatisfied flag commitment ciphertextHash witness row :=
                by
                  rcases head with inactive | active
                  · exact Or.inl inactive
                  · exact Or.inr
                      ⟨active.1, active.2.1, active.2.2.2.1,
                        active.2.2.2.2.1, active.2.2.2.2.2.1,
                        active.2.2.2.2.2.2⟩
              exact SmallWoodOutputConstraintsSatisfied.cons semanticHead
                (inductionHypothesis executed.2)

def NonlinearConstraintFamilySpan.indices
    (span : NonlinearConstraintFamilySpan) : List Nat :=
  (List.range span.count).map (span.start + ·)

def productionNonlinearConstraintFamilyIndices : List Nat :=
  productionNonlinearConstraintFamilySpans.flatMap
    NonlinearConstraintFamilySpan.indices

theorem production_nonlinear_constraint_families_cover_every_root_exactly_once :
    productionNonlinearConstraintFamilyIndices = List.range 1722 := by
  native_decide

structure ProductionLinearConstraintSpec where
  termIndices : List Nat
  termCoefficients : List Nat
  target : Nat
deriving DecidableEq, Repr

def productionLinearConstraintSpecAt
    (map : ProductionConstraintMap)
    (constraint : Nat) : ProductionLinearConstraintSpec :=
  let start := map.linearTermOffsets.getD constraint 0
  let stop := map.linearTermOffsets.getD (constraint + 1) start
  { termIndices := (map.linearTermIndices.drop start).take (stop - start)
    termCoefficients := (map.linearTermCoefficients.drop start).take (stop - start)
    target := fieldValue (map.linearTargets.getD constraint 0) }

def productionLinearConstraintSpecs
    (map : ProductionConstraintMap) : List ProductionLinearConstraintSpec :=
  (List.range map.linearConstraintCount).map
    (productionLinearConstraintSpecAt map)

def productionPackedWitnessIndex
    (map : ProductionConstraintMap)
    (row lane : Nat) : Nat :=
  row * map.lppcPackingFactor + lane

def productionOutputCommitmentPermutation
    (output chunk : Nat) : Nat :=
  137 + output * 3 + chunk

def productionOutputCommitmentLane
    (map : ProductionConstraintMap)
    (output chunk : Nat) : Nat :=
  productionOutputCommitmentPermutation output chunk % map.lppcPackingFactor

def productionOutputCommitmentPoseidonRow
    (map : ProductionConstraintMap)
    (output chunk step limb : Nat) : Nat :=
  415 +
    ((productionOutputCommitmentPermutation output chunk / map.lppcPackingFactor) * 31 + step) *
      12 + limb

def productionOutputCommitmentPoseidonIndex
    (map : ProductionConstraintMap)
    (output chunk step limb : Nat) : Nat :=
  productionPackedWitnessIndex map
    (productionOutputCommitmentPoseidonRow map output chunk step limb)
    (productionOutputCommitmentLane map output chunk)

def productionOutputSecretIndex
    (map : ProductionConstraintMap)
    (output chunk rowOffset : Nat) : Nat :=
  productionPackedWitnessIndex map (68 + output * 12 + rowOffset)
    (productionOutputCommitmentLane map output chunk)

def productionOutputHashInitialBindingSpecs
    (map : ProductionConstraintMap)
    (output : Nat) : List ProductionLinearConstraintSpec :=
  [ { termIndices :=
        [productionOutputCommitmentPoseidonIndex map output 0 0 0,
          productionOutputSecretIndex map output 0 0]
      termCoefficients := [1, goldilocksModulus - 1]
      target := 1 },
    { termIndices :=
        [productionOutputCommitmentPoseidonIndex map output 0 0 1,
          productionOutputSecretIndex map output 0 1]
      termCoefficients := [1, goldilocksModulus - 1]
      target := 0 } ]

def productionOutputHashFreshFrameBindingSpecs
    (map : ProductionConstraintMap)
    (output : Nat) : List ProductionLinearConstraintSpec :=
  (List.range 6).map fun relativeLimb =>
    let limb := 6 + relativeLimb
    { termIndices := [productionOutputCommitmentPoseidonIndex map output 0 0 limb]
      termCoefficients := [1]
      target := if limb = 11 then 1 else 0 }

def productionOutputHashContinuationBindingSpecs
    (map : ProductionConstraintMap)
    (output previousChunk : Nat) : List ProductionLinearConstraintSpec :=
  (List.range 6).map fun relativeLimb =>
    let limb := 6 + relativeLimb
    { termIndices :=
        [productionOutputCommitmentPoseidonIndex map output (previousChunk + 1) 0 limb,
          productionOutputCommitmentPoseidonIndex map output previousChunk 30 limb]
      termCoefficients := [1, goldilocksModulus - 1]
      target := 0 }

def productionOutputHashAuthorizationKeyBindingSpecs
    (map : ProductionConstraintMap)
    (output : Nat) : List ProductionLinearConstraintSpec :=
  (List.range 4).map fun limb =>
    { termIndices :=
        [productionOutputCommitmentPoseidonIndex map output 2 0 (2 + limb),
          productionOutputCommitmentPoseidonIndex map output 1 30 (2 + limb),
          productionOutputSecretIndex map output 2 (8 + limb)]
      termCoefficients := [1, goldilocksModulus - 1, goldilocksModulus - 1]
      target := 0 }

def productionOutputHashDigestBindingSpecs
    (map : ProductionConstraintMap)
    (output : Nat) : List ProductionLinearConstraintSpec :=
  (List.range 6).map fun limb =>
    { termIndices :=
        [productionOutputCommitmentPoseidonIndex map output 2 30 limb]
      termCoefficients := [1]
      target := publicValueAt map.publicValues (16 + output * 6 + limb) }

def productionOutputHashRequiredLinearSpecs
    (map : ProductionConstraintMap)
    (output : Nat) : List ProductionLinearConstraintSpec :=
  productionOutputHashInitialBindingSpecs map output
    ++ productionOutputHashFreshFrameBindingSpecs map output
    ++ productionOutputHashContinuationBindingSpecs map output 0
    ++ productionOutputHashContinuationBindingSpecs map output 1
    ++ productionOutputHashAuthorizationKeyBindingSpecs map output
    ++ productionOutputHashDigestBindingSpecs map output

theorem production_output_hash_required_linear_spec_count_is_exact
    (map : ProductionConstraintMap)
    (output : Nat) :
    (productionOutputHashRequiredLinearSpecs map output).length = 30 := by
  simp [productionOutputHashRequiredLinearSpecs,
    productionOutputHashInitialBindingSpecs,
    productionOutputHashFreshFrameBindingSpecs,
    productionOutputHashContinuationBindingSpecs,
    productionOutputHashAuthorizationKeyBindingSpecs,
    productionOutputHashDigestBindingSpecs]

def productionInputCommitmentPermutation
    (input chunk : Nat) : Nat :=
  1 + input * 68 + chunk

def productionInputCommitmentLane
    (map : ProductionConstraintMap)
    (input chunk : Nat) : Nat :=
  productionInputCommitmentPermutation input chunk % map.lppcPackingFactor

def productionInputCommitmentPoseidonRow
    (map : ProductionConstraintMap)
    (input chunk step limb : Nat) : Nat :=
  415 +
    ((productionInputCommitmentPermutation input chunk / map.lppcPackingFactor) * 31 + step) *
      12 + limb

def productionInputCommitmentPoseidonIndex
    (map : ProductionConstraintMap)
    (input chunk step limb : Nat) : Nat :=
  productionPackedWitnessIndex map
    (productionInputCommitmentPoseidonRow map input chunk step limb)
    (productionInputCommitmentLane map input chunk)

def productionInputSecretIndex
    (map : ProductionConstraintMap)
    (input rowOffset : Nat) : Nat :=
  productionPackedWitnessIndex map (input * 34 + rowOffset)
    (productionInputCommitmentLane map input 0)

def productionInputHashRequiredLinearSpecs
    (map : ProductionConstraintMap)
    (input : Nat) : List ProductionLinearConstraintSpec :=
  [ { termIndices :=
        [productionInputCommitmentPoseidonIndex map input 0 0 0,
          productionInputSecretIndex map input 0]
      termCoefficients := [1, goldilocksModulus - 1]
      target := 1 },
    { termIndices :=
        [productionInputCommitmentPoseidonIndex map input 0 0 1,
          productionInputSecretIndex map input 1]
      termCoefficients := [1, goldilocksModulus - 1]
      target := 0 } ]

theorem production_input_hash_required_linear_spec_count_is_exact
    (map : ProductionConstraintMap)
    (input : Nat) :
    (productionInputHashRequiredLinearSpecs map input).length = 2 := by
  simp [productionInputHashRequiredLinearSpecs]

def productionInputValueRow (input : Nat) : Nat :=
  input * 34

def productionOutputValueRow (output : Nat) : Nat :=
  68 + output * 12

def productionValueRangeBaseRow : Nat := 92

def productionRangeLimbCount : Nat := 21

def productionRangeLimbBits : Nat := 3

def productionRangeLimbCoefficient (limb : Nat) : Nat :=
  2 ^ (limb * productionRangeLimbBits)

def productionInputValueRangeRow (input limb : Nat) : Nat :=
  productionValueRangeBaseRow + input * productionRangeLimbCount + limb

def productionOutputValueRangeRow (output limb : Nat) : Nat :=
  productionValueRangeBaseRow + (2 + output) * productionRangeLimbCount + limb

def productionPublicValueRangeRow (rangeSlot limb : Nat) : Nat :=
  productionValueRangeBaseRow + (4 + rangeSlot) * productionRangeLimbCount + limb

def productionWitnessValueReconstructionSpec
    (map : ProductionConstraintMap)
    (valueRow : Nat)
    (rangeRow : Nat → Nat) : ProductionLinearConstraintSpec :=
  { termIndices :=
      productionPackedWitnessIndex map valueRow 0 ::
        (List.range productionRangeLimbCount).map fun limb =>
          productionPackedWitnessIndex map (rangeRow limb) 0
    termCoefficients :=
      1 :: (List.range productionRangeLimbCount).map fun limb =>
        goldilocksModulus - productionRangeLimbCoefficient limb
    target := 0 }

def productionInputValueReconstructionSpec
    (map : ProductionConstraintMap)
    (input : Nat) : ProductionLinearConstraintSpec :=
  productionWitnessValueReconstructionSpec map
    (productionInputValueRow input) (productionInputValueRangeRow input)

def productionOutputValueReconstructionSpec
    (map : ProductionConstraintMap)
    (output : Nat) : ProductionLinearConstraintSpec :=
  productionWitnessValueReconstructionSpec map
    (productionOutputValueRow output) (productionOutputValueRangeRow output)

def productionPublicValueReconstructionSpec
    (map : ProductionConstraintMap)
    (rangeSlot publicValueIndex : Nat) : ProductionLinearConstraintSpec :=
  { termIndices := (List.range productionRangeLimbCount).map fun limb =>
      productionPackedWitnessIndex map (productionPublicValueRangeRow rangeSlot limb) 0
    termCoefficients := (List.range productionRangeLimbCount).map
      productionRangeLimbCoefficient
    target := publicValueAt map.publicValues publicValueIndex }

def productionMonetaryReconstructionRequiredLinearSpecs
    (map : ProductionConstraintMap) : List ProductionLinearConstraintSpec :=
  (List.range 2).map (productionInputValueReconstructionSpec map)
    ++ (List.range 2).map (productionOutputValueReconstructionSpec map)
    ++ [ productionPublicValueReconstructionSpec map 0 40,
         productionPublicValueReconstructionSpec map 1 42,
         productionPublicValueReconstructionSpec map 2 57 ]

theorem production_monetary_reconstruction_required_linear_spec_count_is_exact
    (map : ProductionConstraintMap) :
    (productionMonetaryReconstructionRequiredLinearSpecs map).length = 7 := by
  simp [productionMonetaryReconstructionRequiredLinearSpecs]

def productionActivityMask (map : ProductionConstraintMap) : Nat :=
  publicValueAt map.publicValues 0
    + 2 * publicValueAt map.publicValues 1
    + 4 * publicValueAt map.publicValues 2
    + 8 * publicValueAt map.publicValues 3

def productionOutputHashBindingConstraintIndices
    (map : ProductionConstraintMap)
    (output : Nat) : List Nat :=
  (productionOutputHashBindingConstraintIndicesByActivityMask.getD
    (productionActivityMask map) []).getD output []

def productionOutputHashRequiredLinearSpecsPresentB
    (map : ProductionConstraintMap)
    (output : Nat) : Bool :=
  let indices := productionOutputHashBindingConstraintIndices map output
  let required := productionOutputHashRequiredLinearSpecs map output
  decide (indices.length = required.length)
    && (List.range required.length).all fun binding =>
      let constraint := indices.getD binding 0
      decide (constraint < map.linearConstraintCount)
        && decide (productionLinearConstraintSpecAt map constraint =
          required.getD binding { termIndices := [], termCoefficients := [], target := 0 })

def productionOutputHashLinearBindingsBoundB
    (map : ProductionConstraintMap) : Bool :=
  decide (map.lppcRowCount = 1531 ∧ map.lppcPackingFactor = 64)
    && (List.range 2).all fun output =>
      if publicValueAt map.publicValues (2 + output) = 1 then
        productionOutputHashRequiredLinearSpecsPresentB map output
      else
        true

def productionInputHashBindingConstraintIndices
    (map : ProductionConstraintMap)
    (input : Nat) : List Nat :=
  (productionInputHashBindingConstraintIndicesByActivityMask.getD
    (productionActivityMask map) []).getD input []

def productionInputHashRequiredLinearSpecsPresentB
    (map : ProductionConstraintMap)
    (input : Nat) : Bool :=
  let indices := productionInputHashBindingConstraintIndices map input
  let required := productionInputHashRequiredLinearSpecs map input
  decide (indices.length = required.length)
    && (List.range required.length).all fun binding =>
      let constraint := indices.getD binding 0
      decide (constraint < map.linearConstraintCount)
        && decide (productionLinearConstraintSpecAt map constraint =
          required.getD binding { termIndices := [], termCoefficients := [], target := 0 })

def productionInputHashLinearBindingsBoundB
    (map : ProductionConstraintMap) : Bool :=
  decide (map.lppcRowCount = 1531 ∧ map.lppcPackingFactor = 64)
    && (List.range 2).all fun input =>
      if publicValueAt map.publicValues input = 1 then
        productionInputHashRequiredLinearSpecsPresentB map input
      else
        true

def productionMonetaryReconstructionConstraintIndices
    (map : ProductionConstraintMap) : List Nat :=
  productionMonetaryReconstructionConstraintIndicesByActivityMask.getD
    (productionActivityMask map) []

def productionMonetaryReconstructionBindingsBoundB
    (map : ProductionConstraintMap) : Bool :=
  let indices := productionMonetaryReconstructionConstraintIndices map
  let required := productionMonetaryReconstructionRequiredLinearSpecs map
  decide (map.lppcRowCount = 1531 ∧ map.lppcPackingFactor = 64)
    && decide (indices.length = required.length)
    && (List.range required.length).all fun binding =>
      let constraint := indices.getD binding 0
      decide (constraint < map.linearConstraintCount)
        && decide (productionLinearConstraintSpecAt map constraint =
          required.getD binding { termIndices := [], termCoefficients := [], target := 0 })

def productionCounterfeitCriticalLinearBindingsBoundB
    (map : ProductionConstraintMap) : Bool :=
  productionOutputHashLinearBindingsBoundB map
    && productionInputHashLinearBindingsBoundB map
    && productionMonetaryReconstructionBindingsBoundB map

def productionConstraintMapBoundB (map : ProductionConstraintMap) : Bool :=
  canonicalProductionPublicValuesB map.publicValues
    && decide (productionConstraintMapForCanonicalValues?
      productionConstraintMapTemplates map.publicValues = some map)
    && map.sparseTableWellFormedB
    && decide (map.nonlinearExpressions = productionNonlinearExpressions)
    && decide (map.nonlinearConstraintRoots = productionNonlinearConstraintRoots)
    && productionCounterfeitCriticalLinearBindingsBoundB map
    && productionSemanticProgramBoundB map

def ProductionConstraintMapBound (map : ProductionConstraintMap) : Prop :=
  productionConstraintMapBoundB map = true

theorem active_production_constraint_map_is_bound :
    productionConstraintMapBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_constraint_map_is_bound :
    productionConstraintMapBoundB stablecoinConstraintMap = true := by
  native_decide

theorem active_production_output_hash_linear_bindings_are_bound :
    productionOutputHashLinearBindingsBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_output_hash_linear_bindings_are_bound :
    productionOutputHashLinearBindingsBoundB stablecoinConstraintMap = true := by
  native_decide

theorem active_production_input_hash_linear_bindings_are_bound :
    productionInputHashLinearBindingsBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_input_hash_linear_bindings_are_bound :
    productionInputHashLinearBindingsBoundB stablecoinConstraintMap = true := by
  native_decide

theorem active_production_monetary_reconstruction_bindings_are_bound :
    productionMonetaryReconstructionBindingsBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_monetary_reconstruction_bindings_are_bound :
    productionMonetaryReconstructionBindingsBoundB stablecoinConstraintMap = true := by
  native_decide

theorem active_production_counterfeit_critical_linear_bindings_are_bound :
    productionCounterfeitCriticalLinearBindingsBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_counterfeit_critical_linear_bindings_are_bound :
    productionCounterfeitCriticalLinearBindingsBoundB stablecoinConstraintMap = true := by
  native_decide

def substitutedOutputHashValueBindingMap : ProductionConstraintMap :=
  let constraint :=
    (productionOutputHashBindingConstraintIndices activeConstraintMap 0).getD 0 0
  { activeConstraintMap with
    linearTargets := activeConstraintMap.linearTargets.set constraint 2 }

theorem substituted_output_hash_value_binding_rejects :
    productionOutputHashLinearBindingsBoundB substitutedOutputHashValueBindingMap = false := by
  native_decide

def substitutedInputHashValueBindingMap : ProductionConstraintMap :=
  let constraint :=
    (productionInputHashBindingConstraintIndices activeConstraintMap 0).getD 0 0
  { activeConstraintMap with
    linearTargets := activeConstraintMap.linearTargets.set constraint 2 }

theorem substituted_input_hash_value_binding_rejects :
    productionInputHashLinearBindingsBoundB substitutedInputHashValueBindingMap = false := by
  native_decide

def substitutedMonetaryReconstructionBindingMap : ProductionConstraintMap :=
  let constraint :=
    (productionMonetaryReconstructionConstraintIndices activeConstraintMap).getD 0 0
  { activeConstraintMap with
    linearTargets := activeConstraintMap.linearTargets.set constraint 1 }

theorem substituted_monetary_reconstruction_binding_rejects :
    productionMonetaryReconstructionBindingsBoundB
      substitutedMonetaryReconstructionBindingMap = false := by
  native_decide

theorem substituted_nonlinear_expression_is_not_production_bound :
    productionConstraintMapBoundB substitutedNonlinearExpressionMap = false := by
  native_decide

theorem reordered_nonlinear_root_is_not_production_bound :
    productionConstraintMapBoundB reorderedNonlinearRootMap = false := by
  native_decide

theorem mismatched_nonlinear_digest_is_not_production_bound :
    productionConstraintMapBoundB mismatchedNonlinearProgramDigestMap = false := by
  native_decide

theorem zero_linear_table_is_not_production_bound :
    productionConstraintMapBoundB zeroLinearTableMap = false := by
  native_decide

theorem stale_public_value_map_is_not_production_bound :
    productionConstraintMapBoundB stalePublicValueMap = false := by
  native_decide

def productionActivityPatternPublicValues (mask : Nat) : List Nat :=
  [ mask % 2, (mask / 2) % 2, (mask / 4) % 2, (mask / 8) % 2 ]
    ++ List.replicate 45 0
    ++ [0, productionBalanceSlotPadding, productionBalanceSlotPadding,
      productionBalanceSlotPadding]
    ++ List.replicate 23 0 ++ [3, 2]

def productionPublicValuesWithBalanceSlots (slots : List Nat) : List Nat :=
  List.replicate 49 0 ++ slots ++ List.replicate 23 0 ++ [3, 2]

theorem canonical_production_balance_slots_accept_native_and_padding_suffix :
    canonicalProductionPublicValuesB
      (productionPublicValuesWithBalanceSlots
        [0, productionBalanceSlotPadding, productionBalanceSlotPadding,
          productionBalanceSlotPadding]) = true := by
  native_decide

theorem canonical_production_balance_slots_reject_duplicate_non_native_assets :
    canonicalProductionPublicValuesB
      (productionPublicValuesWithBalanceSlots
        [0, 4242, 4242, productionBalanceSlotPadding]) = false := by
  native_decide

theorem canonical_production_balance_slots_reject_unordered_non_native_assets :
    canonicalProductionPublicValuesB
      (productionPublicValuesWithBalanceSlots
        [0, 4243, 4242, productionBalanceSlotPadding]) = false := by
  native_decide

theorem canonical_production_balance_slots_reject_padding_holes :
    canonicalProductionPublicValuesB
      (productionPublicValuesWithBalanceSlots
        [0, productionBalanceSlotPadding, 4242, productionBalanceSlotPadding]) = false := by
  native_decide

def productionActivityPatternMapsAdversariallyBoundB : Bool :=
  (List.range 16).all fun mask =>
    let publicValues := productionActivityPatternPublicValues mask
    match productionConstraintMapForCanonicalValues?
        productionConstraintMapTemplates publicValues with
    | none => false
    | some exactMap =>
        let zeroLinear :=
          { exactMap with
            linearConstraintCount := 0
            linearTermCount := 0
            linearTermOffsets := [0]
            linearTermIndices := []
            linearTermCoefficients := []
            linearTargets := [] }
        let stalePublicValues :=
          { exactMap with publicValues := exactMap.publicValues.set 40 1 }
        productionConstraintMapBoundB exactMap
          && !productionConstraintMapBoundB zeroLinear
          && !productionConstraintMapBoundB stalePublicValues

theorem every_activity_pattern_uses_one_exact_adversarially_bound_production_map :
    productionActivityPatternMapsAdversariallyBoundB = true := by
  native_decide

def productionDigestFelts (seed : Nat) : List Nat :=
  (List.range 6).map fun limb =>
    fieldValue <| NoteCommitmentInputs.beBytesToNat
      ((StatementHash.digestBytes seed).drop (limb * 8) |>.take 8)

def productionPaddedDigestFelts (count : Nat) (seeds : List Nat) : List Nat :=
  (seeds.take count).flatMap productionDigestFelts
    ++ List.replicate ((count - seeds.length) * 6) 0

def productionVerifierPublicValues
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields) : List Nat :=
  bound.inputFlags.map fieldValue
    ++ bound.outputFlags.map fieldValue
    ++ productionPaddedDigestFelts 2 statementFields.nullifierSeeds
    ++ productionPaddedDigestFelts 2 statementFields.commitmentSeeds
    ++ productionPaddedDigestFelts 2 statementFields.ciphertextHashSeeds
    ++ [ fieldValue bound.fee,
         fieldValue bound.valueBalanceSign,
         fieldValue bound.valueBalanceMagnitude ]
    ++ productionDigestFelts bound.merkleRoot
    ++ bound.balanceSlotAssets.map fieldValue
    ++ [ fieldValue bound.stablecoinEnabled,
         fieldValue bound.stablecoinAsset,
         fieldValue bound.stablecoinPolicyVersion,
         fieldValue bound.stablecoinIssuanceSign,
         fieldValue bound.stablecoinIssuanceMagnitude ]
    ++ productionDigestFelts bound.stablecoinPolicyHash
    ++ productionDigestFelts bound.stablecoinOracleCommitment
    ++ productionDigestFelts bound.stablecoinAttestationCommitment
    ++ [ fieldValue statementFields.circuitVersion,
         fieldValue statementFields.cryptoSuite ]

def ProductionConstraintMapBoundToCanonicalStatement
    (map : ProductionConstraintMap)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields) : Prop :=
  ProductionConstraintMapBound map
    ∧ map.publicValues = productionVerifierPublicValues bound statementFields

def productionExpressionEvalAt
    (expressions : List ProductionConstraintExpression)
    (publicValues witnessRows : List Nat) : Nat → Nat → Nat
  | 0, _ => 0
  | fuel + 1, index =>
      match expressions.getD index (.constExpr 0) with
      | .constExpr value => fieldValue value
      | .publicExpr publicIndex => publicValueAt publicValues publicIndex
      | .witnessExpr witnessIndex => fieldValue (witnessRows.getD witnessIndex 0)
      | .slotInverseExpr slot => fieldInverse (slotDenominator publicValues slot)
      | .stableSelectorExpr bit =>
          fieldValue ((stableSelectorSlot publicValues / (2 ^ bit)) % 2)
      | .addExpr left right =>
          fieldAdd
            (productionExpressionEvalAt expressions publicValues witnessRows fuel left)
            (productionExpressionEvalAt expressions publicValues witnessRows fuel right)
      | .subExpr left right =>
          fieldSub
            (productionExpressionEvalAt expressions publicValues witnessRows fuel left)
            (productionExpressionEvalAt expressions publicValues witnessRows fuel right)
      | .mulExpr left right =>
          fieldMul
            (productionExpressionEvalAt expressions publicValues witnessRows fuel left)
            (productionExpressionEvalAt expressions publicValues witnessRows fuel right)
      | .negExpr value =>
          fieldNeg
            (productionExpressionEvalAt expressions publicValues witnessRows fuel value)

def evalExpressionProgramFrom
    (publicValues witnessRows : List Nat)
    (initial : Array Nat)
    (expressions : List ProductionConstraintExpression) : Array Nat :=
  expressions.foldl
    (fun values expression =>
      values.push (expression.eval publicValues witnessRows values)) initial

theorem eval_expression_program_from_size
    (publicValues witnessRows : List Nat)
    (initial : Array Nat)
    (expressions : List ProductionConstraintExpression) :
    (evalExpressionProgramFrom publicValues witnessRows initial expressions).size =
      initial.size + expressions.length := by
  induction expressions generalizing initial with
  | nil => simp [evalExpressionProgramFrom]
  | cons expression expressions inductionHypothesis =>
      simp only [evalExpressionProgramFrom, List.foldl_cons]
      change
        (evalExpressionProgramFrom publicValues witnessRows
          (initial.push (expression.eval publicValues witnessRows initial))
          expressions).size = _
      rw [inductionHypothesis]
      simp
      omega

theorem eval_expression_program_from_preserves
    (publicValues witnessRows : List Nat)
    (initial : Array Nat)
    (expressions : List ProductionConstraintExpression)
    (index : Nat)
    (indexBound : index < initial.size) :
    (evalExpressionProgramFrom publicValues witnessRows initial expressions)[index]'(by
      rw [eval_expression_program_from_size]
      omega) = initial[index] := by
  induction expressions generalizing initial with
  | nil => rfl
  | cons expression expressions inductionHypothesis =>
      simp only [evalExpressionProgramFrom, List.foldl_cons]
      let pushed := initial.push (expression.eval publicValues witnessRows initial)
      have pushedBound : index < pushed.size := by
        simp [pushed]
        omega
      have finalBound :
          index <
            (evalExpressionProgramFrom publicValues witnessRows pushed expressions).size := by
        rw [eval_expression_program_from_size]
        omega
      change
        (evalExpressionProgramFrom publicValues witnessRows pushed expressions)[index]'finalBound = _
      rw [inductionHypothesis pushed pushedBound]
      exact Array.getElem_push_lt indexBound

theorem eval_expression_program_size
    (publicValues witnessRows : List Nat)
    (expressions : List ProductionConstraintExpression) :
    (evalExpressionProgram publicValues witnessRows expressions).size = expressions.length := by
  simpa [evalExpressionProgram, evalExpressionProgramFrom] using
    eval_expression_program_from_size publicValues witnessRows #[] expressions

theorem eval_expression_program_preserves_prefix
    (publicValues witnessRows : List Nat)
    (headExpressions tailExpressions : List ProductionConstraintExpression)
    (index : Nat)
    (indexBound : index < headExpressions.length) :
    (evalExpressionProgram publicValues witnessRows
      (headExpressions ++ tailExpressions))[index]'(by
      rw [eval_expression_program_size]
      simp
      omega) =
      (evalExpressionProgram publicValues witnessRows headExpressions)[index]'(by
        rw [eval_expression_program_size]
        exact indexBound) := by
  simp only [evalExpressionProgram, List.foldl_append]
  apply eval_expression_program_from_preserves

theorem eval_expression_program_getD_preserves_prefix
    (publicValues witnessRows : List Nat)
    (headExpressions tailExpressions : List ProductionConstraintExpression)
    (index fallback : Nat)
    (indexBound : index < headExpressions.length) :
    (evalExpressionProgram publicValues witnessRows
      (headExpressions ++ tailExpressions)).getD index fallback =
      (evalExpressionProgram publicValues witnessRows headExpressions).getD index fallback := by
  have fullBound :
      index < (evalExpressionProgram publicValues witnessRows
        (headExpressions ++ tailExpressions)).size := by
    rw [eval_expression_program_size]
    simp
    omega
  have headBound :
      index < (evalExpressionProgram publicValues witnessRows headExpressions).size := by
    rw [eval_expression_program_size]
    exact indexBound
  simp only [Array.getD, fullBound, headBound, dite_true]
  exact eval_expression_program_preserves_prefix
    publicValues witnessRows headExpressions tailExpressions index indexBound

theorem eval_expression_program_equation
    (publicValues witnessRows : List Nat)
    (expressions : List ProductionConstraintExpression)
    (index : Nat)
    (indexBound : index < expressions.length)
    (referencesBound :
      (expressions[index].references).all
        (fun reference => decide (reference < index)) = true) :
    let values := evalExpressionProgram publicValues witnessRows expressions
    values[index]'(by
      dsimp [values]
      rw [eval_expression_program_size]
      exact indexBound) =
      expressions[index].eval publicValues witnessRows values := by
  let headExpressions := expressions.take index
  let selectedExpression := expressions[index]
  let tailExpressions := expressions.drop (index + 1)
  have indexLe : index ≤ expressions.length := Nat.le_of_lt indexBound
  have headLength : headExpressions.length = index := by
    simp [headExpressions, List.length_take_of_le indexLe]
  have selectedPrefix :
      expressions.take (index + 1) = headExpressions ++ [selectedExpression] := by
    simp [headExpressions, selectedExpression]
  have split :
      expressions = headExpressions ++ selectedExpression :: tailExpressions := by
    rw [← List.take_append_drop (index + 1) expressions, selectedPrefix]
    simp [tailExpressions]
  have produced :
      (evalExpressionProgram publicValues witnessRows expressions).getD index 0 =
        selectedExpression.eval publicValues witnessRows
          (evalExpressionProgram publicValues witnessRows headExpressions) := by
    rw [split]
    have prefixBound : index < (headExpressions ++ [selectedExpression]).length := by
      simp [headLength]
    have regroup :
        headExpressions ++ selectedExpression :: tailExpressions =
          (headExpressions ++ [selectedExpression]) ++ tailExpressions := by
      simp
    rw [regroup]
    rw [eval_expression_program_getD_preserves_prefix
      publicValues witnessRows (headExpressions ++ [selectedExpression]) tailExpressions
      index 0 prefixBound]
    simp only [evalExpressionProgram, List.foldl_append, List.foldl_cons, List.foldl_nil]
    change
      (evalExpressionProgramFrom publicValues witnessRows
        (evalExpressionProgram publicValues witnessRows headExpressions)
        [selectedExpression]).getD index 0 = _
    simp only [evalExpressionProgramFrom, List.foldl_cons, List.foldl_nil]
    have atEnd :
        index = (evalExpressionProgram publicValues witnessRows headExpressions).size := by
      rw [eval_expression_program_size, headLength]
    rw [atEnd]
    simp [Array.getD, evalExpressionProgram]
  have preserveReference
      (reference : Nat)
      (referenceBound : reference < index) :
      (evalExpressionProgram publicValues witnessRows expressions).getD reference 0 =
        (evalExpressionProgram publicValues witnessRows headExpressions).getD reference 0 := by
    rw [split]
    apply eval_expression_program_getD_preserves_prefix
    simpa [headLength] using referenceBound
  have semanticEquation :
      (evalExpressionProgram publicValues witnessRows expressions).getD index 0 =
        selectedExpression.eval publicValues witnessRows
          (evalExpressionProgram publicValues witnessRows expressions) := by
    have selectedReferencesBound :
        selectedExpression.references.all
          (fun reference => decide (reference < index)) = true := by
      simpa [selectedExpression] using referencesBound
    rw [produced]
    cases expressionCase : selectedExpression with
    | constExpr | publicExpr | witnessExpr | slotInverseExpr | stableSelectorExpr =>
        simp only [ProductionConstraintExpression.eval]
    | addExpr left right | subExpr left right | mulExpr left right =>
        have bounds := selectedReferencesBound
        simp [expressionCase, ProductionConstraintExpression.references] at bounds
        simp only [ProductionConstraintExpression.eval]
        rw [← preserveReference left bounds.1,
          ← preserveReference right bounds.2]
    | negExpr value =>
        have bound := selectedReferencesBound
        simp [expressionCase, ProductionConstraintExpression.references] at bound
        simp only [ProductionConstraintExpression.eval]
        rw [← preserveReference value bound]
  dsimp only
  have valuesBound :
      index < (evalExpressionProgram publicValues witnessRows expressions).size := by
    rw [eval_expression_program_size]
    exact indexBound
  simpa [selectedExpression, Array.getD, valuesBound] using semanticEquation

def ProductionExpressionReferencesBound
    (expressions : List ProductionConstraintExpression) : Prop :=
  forall (index : Nat) (indexBound : index < expressions.length),
    forall reference, reference ∈ expressions[index].references → reference < index

def productionExpressionReferencesBoundB
    (expressions : List ProductionConstraintExpression) : Bool :=
  (List.range expressions.length).all fun index =>
    (expressions.getD index (.constExpr 0)).references.all fun reference =>
      decide (reference < index)

theorem production_expression_references_bound_of_check
    {expressions : List ProductionConstraintExpression}
    (checked : productionExpressionReferencesBoundB expressions = true) :
    ProductionExpressionReferencesBound expressions := by
  intro index indexBound reference membership
  have indexChecked := (List.all_eq_true.mp checked) index
    (List.mem_range.mpr indexBound)
  have referencesChecked := (List.all_eq_true.mp indexChecked) reference
  have selected : expressions.getD index (.constExpr 0) = expressions[index] := by
    simp [List.getD, indexBound]
  rw [selected] at referencesChecked
  exact of_decide_eq_true (referencesChecked membership)

theorem production_nonlinear_expression_references_are_strictly_backward :
    ProductionExpressionReferencesBound productionNonlinearExpressions := by
  apply production_expression_references_bound_of_check
  native_decide

theorem eval_expression_program_eq_recursive
    (publicValues witnessRows : List Nat)
    (expressions : List ProductionConstraintExpression)
    (referencesBound : ProductionExpressionReferencesBound expressions)
    (index : Nat)
    (indexBound : index < expressions.length)
    (fuel : Nat)
    (fuelBound : index < fuel) :
    (evalExpressionProgram publicValues witnessRows expressions).getD index 0 =
      productionExpressionEvalAt expressions publicValues witnessRows fuel index := by
  induction index using Nat.strongRecOn generalizing fuel with
  | ind index inductionHypothesis =>
      have selectedReferencesBound :
          expressions[index].references.all
            (fun reference => decide (reference < index)) = true := by
        rw [List.all_eq_true]
        intro reference membership
        exact decide_eq_true (referencesBound index indexBound reference membership)
      have equation := eval_expression_program_equation
        publicValues witnessRows expressions index indexBound selectedReferencesBound
      have valuesBound :
          index < (evalExpressionProgram publicValues witnessRows expressions).size := by
        rw [eval_expression_program_size]
        exact indexBound
      have equationGetD :
          (evalExpressionProgram publicValues witnessRows expressions).getD index 0 =
            expressions[index].eval publicValues witnessRows
              (evalExpressionProgram publicValues witnessRows expressions) := by
        simpa [Array.getD, valuesBound] using equation
      cases fuel with
      | zero => omega
      | succ remainingFuel =>
          rw [equationGetD]
          cases expressionCase : expressions[index] with
          | constExpr | publicExpr | witnessExpr | slotInverseExpr | stableSelectorExpr =>
              simp [productionExpressionEvalAt, List.getD, indexBound, expressionCase,
                ProductionConstraintExpression.eval]
          | addExpr left right | subExpr left right | mulExpr left right =>
              have leftBound : left < index := by
                apply referencesBound index indexBound left
                simp [expressionCase, ProductionConstraintExpression.references]
              have rightBound : right < index := by
                apply referencesBound index indexBound right
                simp [expressionCase, ProductionConstraintExpression.references]
              have leftInRange : left < expressions.length := Nat.lt_trans leftBound indexBound
              have rightInRange : right < expressions.length := Nat.lt_trans rightBound indexBound
              have leftFuel : left < remainingFuel := by omega
              have rightFuel : right < remainingFuel := by omega
              simp only [ProductionConstraintExpression.eval, productionExpressionEvalAt]
              rw [inductionHypothesis left leftBound leftInRange remainingFuel leftFuel,
                inductionHypothesis right rightBound rightInRange remainingFuel rightFuel]
              simp [List.getD, indexBound, expressionCase]
          | negExpr value =>
              have valueBound : value < index := by
                apply referencesBound index indexBound value
                simp [expressionCase, ProductionConstraintExpression.references]
              have valueInRange : value < expressions.length :=
                Nat.lt_trans valueBound indexBound
              have valueFuel : value < remainingFuel := by omega
              simp only [ProductionConstraintExpression.eval, productionExpressionEvalAt]
              rw [inductionHypothesis value valueBound valueInRange remainingFuel valueFuel]
              simp [List.getD, indexBound, expressionCase]

inductive ProductionConstraintExpressionTree where
  | constant (value : Nat)
  | publicValue (index : Nat)
  | witnessRow (index : Nat)
  | slotInverse (slot : Nat)
  | stableSelector (bit : Nat)
  | add (left right : ProductionConstraintExpressionTree)
  | sub (left right : ProductionConstraintExpressionTree)
  | mul (left right : ProductionConstraintExpressionTree)
  | neg (value : ProductionConstraintExpressionTree)
deriving DecidableEq, Repr

def ProductionConstraintExpressionTree.eval
    (publicValues witnessRows : List Nat) : ProductionConstraintExpressionTree → Nat
  | .constant value => fieldValue value
  | .publicValue index => publicValueAt publicValues index
  | .witnessRow index => fieldValue (witnessRows.getD index 0)
  | .slotInverse slot => fieldInverse (slotDenominator publicValues slot)
  | .stableSelector bit =>
      fieldValue ((stableSelectorSlot publicValues / (2 ^ bit)) % 2)
  | .add left right =>
      fieldAdd (left.eval publicValues witnessRows) (right.eval publicValues witnessRows)
  | .sub left right =>
      fieldSub (left.eval publicValues witnessRows) (right.eval publicValues witnessRows)
  | .mul left right =>
      fieldMul (left.eval publicValues witnessRows) (right.eval publicValues witnessRows)
  | .neg value => fieldNeg (value.eval publicValues witnessRows)

def expandProductionExpressionTree
    (expressions : List ProductionConstraintExpression) :
    Nat → Nat → ProductionConstraintExpressionTree
  | 0, _ => .constant 0
  | fuel + 1, index =>
      match expressions.getD index (.constExpr 0) with
      | .constExpr value => .constant value
      | .publicExpr publicIndex => .publicValue publicIndex
      | .witnessExpr witnessIndex => .witnessRow witnessIndex
      | .slotInverseExpr slot => .slotInverse slot
      | .stableSelectorExpr bit => .stableSelector bit
      | .addExpr left right =>
          .add (expandProductionExpressionTree expressions fuel left)
            (expandProductionExpressionTree expressions fuel right)
      | .subExpr left right =>
          .sub (expandProductionExpressionTree expressions fuel left)
            (expandProductionExpressionTree expressions fuel right)
      | .mulExpr left right =>
          .mul (expandProductionExpressionTree expressions fuel left)
            (expandProductionExpressionTree expressions fuel right)
      | .negExpr value => .neg (expandProductionExpressionTree expressions fuel value)

theorem recursive_expression_eval_eq_expanded_tree
    (expressions : List ProductionConstraintExpression)
    (publicValues witnessRows : List Nat)
    (fuel index : Nat) :
    productionExpressionEvalAt expressions publicValues witnessRows fuel index =
      (expandProductionExpressionTree expressions fuel index).eval
        publicValues witnessRows := by
  induction fuel generalizing index with
  | zero => rfl
  | succ fuel inductionHypothesis =>
      simp only [productionExpressionEvalAt, expandProductionExpressionTree]
      cases expressions.getD index (.constExpr 0) <;>
        simp [ProductionConstraintExpressionTree.eval, inductionHypothesis]

def productionConcreteConstraintValue
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane constraint : Nat) : Nat :=
  productionExpressionEvalAt productionNonlinearExpressions
    map.publicValues (witnessLaneRows map witnessValues lane)
    productionNonlinearExpressions.length
    (productionNonlinearConstraintRoots.getD constraint 0)

def productionNonlinearRootsBoundB : Bool :=
  productionNonlinearConstraintRoots.all fun root =>
    decide (root < productionNonlinearExpressions.length)

theorem production_nonlinear_roots_are_in_expression_program :
    forall constraint, constraint < productionNonlinearConstraintRoots.length →
      productionNonlinearConstraintRoots.getD constraint 0 <
        productionNonlinearExpressions.length := by
  intro constraint constraintBound
  have checked := (List.all_eq_true.mp (show productionNonlinearRootsBoundB = true by
    native_decide))
    (productionNonlinearConstraintRoots[constraint]'constraintBound)
    (List.getElem_mem constraintBound)
  simpa [List.getD, constraintBound] using of_decide_eq_true checked

theorem production_constraint_map_bound_uses_static_nonlinear_program
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    map.nonlinearExpressions = productionNonlinearExpressions
      ∧ map.nonlinearConstraintRoots = productionNonlinearConstraintRoots := by
  simp only [ProductionConstraintMapBound, productionConstraintMapBoundB,
    Bool.and_eq_true] at mapBound
  exact
    ⟨of_decide_eq_true mapBound.1.1.1.2,
      of_decide_eq_true mapBound.1.1.2⟩

theorem production_nonlinear_equation_has_concrete_tree_meaning
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    {lane constraint : Nat}
    (mapBound : ProductionConstraintMapBound map)
    (constraintBound : constraint < productionNonlinearConstraintRoots.length)
    (equation : nonlinearConstraintEquation map witnessValues lane constraint) :
    productionConcreteConstraintValue map witnessValues lane constraint = 0 := by
  rcases production_constraint_map_bound_uses_static_nonlinear_program mapBound with
    ⟨expressions, roots⟩
  have rootBound :
      productionNonlinearConstraintRoots.getD constraint 0 <
        productionNonlinearExpressions.length :=
    production_nonlinear_roots_are_in_expression_program constraint constraintBound
  have recursive := eval_expression_program_eq_recursive
    map.publicValues (witnessLaneRows map witnessValues lane)
    productionNonlinearExpressions
    production_nonlinear_expression_references_are_strictly_backward
    (productionNonlinearConstraintRoots.getD constraint 0) rootBound
    productionNonlinearExpressions.length rootBound
  have evaluatedSize :
      (evalExpressionProgram map.publicValues (witnessLaneRows map witnessValues lane)
        productionNonlinearExpressions).size = productionNonlinearExpressions.length :=
    eval_expression_program_size _ _ _
  have rootArrayBound :
      productionNonlinearConstraintRoots.getD constraint 0 <
        (evalExpressionProgram map.publicValues (witnessLaneRows map witnessValues lane)
          productionNonlinearExpressions).size := by
    rw [evaluatedSize]
    exact rootBound
  have fallbackIrrelevant :
      (evalExpressionProgram map.publicValues (witnessLaneRows map witnessValues lane)
        productionNonlinearExpressions).getD
          (productionNonlinearConstraintRoots.getD constraint 0) 1 =
        (evalExpressionProgram map.publicValues (witnessLaneRows map witnessValues lane)
          productionNonlinearExpressions).getD
            (productionNonlinearConstraintRoots.getD constraint 0) 0 := by
    simp only [Array.getD]
    rw [dif_pos rootArrayBound, dif_pos rootArrayBound]
  unfold nonlinearConstraintEquation nonlinearConstraintValue at equation
  rw [expressions, roots, fallbackIrrelevant, recursive] at equation
  simpa [productionConcreteConstraintValue] using equation

def productionBalanceTreeDifference
    (asset : ProductionConstraintExpressionTree)
    (slot : Nat) : ProductionConstraintExpressionTree :=
  .sub asset (.publicValue (49 + slot))

def productionBalanceTreeMembershipWeight
    (asset : ProductionConstraintExpressionTree)
    (slot : Nat) : ProductionConstraintExpressionTree :=
  let difference := fun other => productionBalanceTreeDifference asset other
  let numerator := match slot with
    | 0 => .mul (difference 3) (.mul (difference 1) (difference 2))
    | 1 => .mul (difference 3) (.mul (difference 0) (difference 2))
    | 2 => .mul (.mul (difference 0) (difference 1)) (difference 3)
    | _ => .mul (.mul (difference 0) (difference 1)) (difference 2)
  .mul (.slotInverse slot) numerator

def productionBalanceTreeContribution
    (flagIndex valueRow assetRow slot : Nat) : ProductionConstraintExpressionTree :=
  .mul (productionBalanceTreeMembershipWeight (.witnessRow assetRow) slot)
    (.mul (.publicValue flagIndex) (.witnessRow valueRow))

def productionBalanceTreeSigned
    (signIndex magnitudeIndex : Nat) : ProductionConstraintExpressionTree :=
  .sub (.publicValue magnitudeIndex)
    (.mul (.publicValue magnitudeIndex)
      (.add (.publicValue signIndex) (.publicValue signIndex)))

def productionBalanceTreeSelectedWeight
    (slot : Nat) : ProductionConstraintExpressionTree :=
  let bit0 : ProductionConstraintExpressionTree := .stableSelector 0
  let bit1 : ProductionConstraintExpressionTree := .stableSelector 1
  let inverse0 : ProductionConstraintExpressionTree := .sub (.constant 1) bit0
  let inverse1 : ProductionConstraintExpressionTree := .sub (.constant 1) bit1
  match slot with
  | 0 => .mul inverse0 inverse1
  | 1 => .mul bit0 inverse1
  | 2 => .mul bit1 inverse0
  | _ => .mul bit0 bit1

def productionBalanceDeltaTree (slot : Nat) : ProductionConstraintExpressionTree :=
  let input0 := productionBalanceTreeContribution 0 0 1 slot
  let input1 := productionBalanceTreeContribution 1 34 35 slot
  let output0 := productionBalanceTreeContribution 2 68 69 slot
  let output1 := productionBalanceTreeContribution 3 80 81 slot
  .sub (.sub (.add input0 input1) output0) output1

def productionBalanceExpectedTree (slot : Nat) : ProductionConstraintExpressionTree :=
  if slot = 0 then
    .sub (.publicValue 40) (productionBalanceTreeSigned 41 42)
  else
    .mul (productionBalanceTreeSigned 56 57)
      (.mul (.publicValue 53) (productionBalanceTreeSelectedWeight slot))

def productionBalanceResidualTree (slot : Nat) : ProductionConstraintExpressionTree :=
  .sub (productionBalanceDeltaTree slot) (productionBalanceExpectedTree slot)

theorem production_balance_roots_are_exact_concrete_formulas :
    (List.range 4).map (fun slot =>
      expandProductionExpressionTree productionNonlinearExpressions
        productionNonlinearExpressions.length
        (productionNonlinearConstraintRoots.getD (117 + slot) 0)) =
      (List.range 4).map productionBalanceResidualTree := by
  native_decide

def productionBalanceDelta
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane slot : Nat) : Nat :=
  (productionBalanceDeltaTree slot).eval map.publicValues
    (witnessLaneRows map witnessValues lane)

def productionBalanceExpected
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane slot : Nat) : Nat :=
  (productionBalanceExpectedTree slot).eval map.publicValues
    (witnessLaneRows map witnessValues lane)

theorem production_balance_residual_tree_is_direct_delta
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane slot : Nat)
    (_slotBound : slot < 4) :
    (productionBalanceResidualTree slot).eval map.publicValues
        (witnessLaneRows map witnessValues lane) =
      fieldSub (productionBalanceDelta map witnessValues lane slot)
        (productionBalanceExpected map witnessValues lane slot) := by
  rfl

structure ProductionMaterializedBalanceSlotConserved
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane slot : Nat) : Prop where
  slotIndexBound : slot < 4
  materializedAssetIsPublicSlot :
    slotAsset map.publicValues slot = publicValueAt map.publicValues (49 + slot)
  exactConservation :
    fieldSub (productionBalanceDelta map witnessValues lane slot)
      (productionBalanceExpected map witnessValues lane slot) = 0

structure ProductionConcreteBalanceConservation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  everyLaneAndMaterializedSlot :
    forall lane, lane < map.lppcPackingFactor →
      forall slot, slot < 4 →
        ProductionMaterializedBalanceSlotConserved map witnessValues lane slot
  nativeConservation :
    forall lane, lane < map.lppcPackingFactor →
      fieldSub (productionBalanceDelta map witnessValues lane 0)
        (productionBalanceExpected map witnessValues lane 0) = 0
  everyNonNativeSlotConserved :
    forall lane, lane < map.lppcPackingFactor →
      forall slot, slot ∈ [1, 2, 3] →
        fieldSub (productionBalanceDelta map witnessValues lane slot)
          (productionBalanceExpected map witnessValues lane slot) = 0

def ProductionConcreteConstraintSpanSatisfied
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (span : NonlinearConstraintFamilySpan) : Prop :=
  forall lane, lane < map.lppcPackingFactor →
    forall relativeConstraint, relativeConstraint < span.count →
      productionConcreteConstraintValue map witnessValues lane
        (span.start + relativeConstraint) = 0

structure ProductionConcreteSpendAuthorization
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  everyInputSpendTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues inputConstraintSpan
  everyAuthorizationTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues authorizationConstraintSpan
  everyHashTransitionTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues poseidonConstraintSpan

structure ProductionConcreteOutputValidity
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  everyOutputTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues outputConstraintSpan
  everyValueRangeTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues valueRangeConstraintSpan
  everyHashTransitionTree :
    ProductionConcreteConstraintSpanSatisfied map witnessValues poseidonConstraintSpan
  exactLinearBindings :
    forall constraint, constraint < map.linearConstraintCount →
      linearConstraintEquation map witnessValues constraint

structure ProductionConcreteSemanticConsequences
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  canonicalPublicShapeTrees :
    ProductionConcreteConstraintSpanSatisfied map witnessValues publicShapeConstraintSpan
  totalSpendAuthorization : ProductionConcreteSpendAuthorization map witnessValues
  totalOutputValidity : ProductionConcreteOutputValidity map witnessValues
  materializedBalanceConservation :
    ProductionConcreteBalanceConservation map witnessValues

theorem production_nonlinear_root_count_is_exact :
    productionNonlinearConstraintRoots.length = 1722 := by
  rfl

theorem production_equations_give_concrete_span
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (nonlinearConstraintCount : map.nonlinearConstraintCount = 1722)
    (equations :
      forall lane, lane < map.lppcPackingFactor →
        forall constraint, constraint < map.nonlinearConstraintCount →
          nonlinearConstraintEquation map witnessValues lane constraint)
    (span : NonlinearConstraintFamilySpan)
    (spanBound : span.start + span.count ≤ 1722) :
    ProductionConcreteConstraintSpanSatisfied map witnessValues span := by
  intro lane laneBound relativeConstraint relativeBound
  apply production_nonlinear_equation_has_concrete_tree_meaning mapBound
  · rw [production_nonlinear_root_count_is_exact]
    omega
  · apply equations lane laneBound
    rw [nonlinearConstraintCount]
    omega

theorem production_balance_root_is_exact_concrete_formula
    (slot : Nat)
    (slotBound : slot < 4) :
    expandProductionExpressionTree productionNonlinearExpressions
      productionNonlinearExpressions.length
      (productionNonlinearConstraintRoots.getD (117 + slot) 0) =
        productionBalanceResidualTree slot := by
  have slotCases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by omega
  rcases slotCases with rfl | rfl | rfl | rfl <;> native_decide

theorem production_balance_equations_give_concrete_conservation
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (nonlinearConstraintCount : map.nonlinearConstraintCount = 1722)
    (equations :
      forall lane, lane < map.lppcPackingFactor →
        forall constraint, constraint < map.nonlinearConstraintCount →
          nonlinearConstraintEquation map witnessValues lane constraint) :
    ProductionConcreteBalanceConservation map witnessValues := by
  have conserved
      (lane : Nat)
      (laneBound : lane < map.lppcPackingFactor)
      (slot : Nat)
      (slotBound : slot < 4) :
      fieldSub (productionBalanceDelta map witnessValues lane slot)
        (productionBalanceExpected map witnessValues lane slot) = 0 := by
    have equation := equations lane laneBound (117 + slot) (by
      rw [nonlinearConstraintCount]
      omega)
    have concrete := production_nonlinear_equation_has_concrete_tree_meaning
      mapBound (constraint := 117 + slot) (by
        rw [production_nonlinear_root_count_is_exact]
        omega) equation
    unfold productionConcreteConstraintValue at concrete
    rw [recursive_expression_eval_eq_expanded_tree,
      production_balance_root_is_exact_concrete_formula slot slotBound,
      production_balance_residual_tree_is_direct_delta map witnessValues lane slot slotBound]
      at concrete
    exact concrete
  refine
    { everyLaneAndMaterializedSlot := ?_
      nativeConservation := ?_
      everyNonNativeSlotConserved := ?_ }
  · intro lane laneBound slot slotBound
    exact
      { slotIndexBound := slotBound
        materializedAssetIsPublicSlot := rfl
        exactConservation := conserved lane laneBound slot slotBound }
  · intro lane laneBound
    exact conserved lane laneBound 0 (by decide)
  · intro lane laneBound slot membership
    have slotCases : slot = 1 ∨ slot = 2 ∨ slot = 3 := by
      simpa using membership
    rcases slotCases with rfl | rfl | rfl
    · exact conserved lane laneBound 1 (by decide)
    · exact conserved lane laneBound 2 (by decide)
    · exact conserved lane laneBound 3 (by decide)

def productionOutputValue
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane output : Nat) : Nat :=
  fieldValue ((witnessLaneRows map witnessValues lane).getD (68 + output * 12) 0)

def productionOutputAsset
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane output : Nat) : Nat :=
  fieldValue ((witnessLaneRows map witnessValues lane).getD (69 + output * 12) 0)

def productionOutputCommitmentFelts
    (map : ProductionConstraintMap)
    (output : Nat) : List Nat :=
  (List.range 6).map fun limb =>
    publicValueAt map.publicValues (16 + output * 6 + limb)

def productionOutputHashTraceValue
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output chunk step limb : Nat) : Nat :=
  fieldValue (witnessValues.getD
    (productionOutputCommitmentPoseidonIndex map output chunk step limb) 0)

def productionOutputHashPreimage
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : List Nat :=
  [ productionOutputValue map witnessValues
      (productionOutputCommitmentLane map output 0) output,
    productionOutputAsset map witnessValues
      (productionOutputCommitmentLane map output 0) output ]
    ++ (List.range 4).map (fun limb =>
      productionOutputHashTraceValue map witnessValues output 0 0 (2 + limb))
    ++ (List.range 6).map (fun limb =>
      fieldSub
        (productionOutputHashTraceValue map witnessValues output 1 0 limb)
        (productionOutputHashTraceValue map witnessValues output 0 30 limb))
    ++ (List.range 6).map (fun limb =>
      fieldSub
        (productionOutputHashTraceValue map witnessValues output 2 0 limb)
        (productionOutputHashTraceValue map witnessValues output 1 30 limb))

theorem production_output_hash_preimage_has_exact_deployed_word_count
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) :
    (productionOutputHashPreimage map witnessValues output).length = 18 := by
  simp [productionOutputHashPreimage]

def zeroProductionLinearConstraintSpec : ProductionLinearConstraintSpec :=
  { termIndices := [], termCoefficients := [], target := 0 }

def ProductionLinearConstraintSpecExecuted
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (spec : ProductionLinearConstraintSpec) : Prop :=
  exists constraintIndex,
    constraintIndex < map.linearConstraintCount
      ∧ productionLinearConstraintSpecAt map constraintIndex = spec
      ∧ linearConstraintEquation map witnessValues constraintIndex

def ProductionNonlinearFamilyEquations
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (span : NonlinearConstraintFamilySpan) : Prop :=
  forall lane, lane < map.lppcPackingFactor ->
    forall relativeConstraint, relativeConstraint < span.count ->
      nonlinearConstraintEquation map witnessValues lane
        (span.start + relativeConstraint)

theorem production_counterfeit_critical_linear_bindings_are_map_bound
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    productionCounterfeitCriticalLinearBindingsBoundB map = true := by
  simp only [ProductionConstraintMapBound, productionConstraintMapBoundB,
    Bool.and_eq_true] at mapBound
  exact mapBound.1.2

theorem production_output_hash_linear_bindings_are_map_bound
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    productionOutputHashLinearBindingsBoundB map = true := by
  have critical := production_counterfeit_critical_linear_bindings_are_map_bound mapBound
  simp only [productionCounterfeitCriticalLinearBindingsBoundB,
    Bool.and_eq_true] at critical
  exact critical.1.1

theorem production_input_hash_linear_bindings_are_map_bound
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    productionInputHashLinearBindingsBoundB map = true := by
  have critical := production_counterfeit_critical_linear_bindings_are_map_bound mapBound
  simp only [productionCounterfeitCriticalLinearBindingsBoundB,
    Bool.and_eq_true] at critical
  exact critical.1.2

theorem production_monetary_reconstruction_bindings_are_map_bound
    {map : ProductionConstraintMap}
    (mapBound : ProductionConstraintMapBound map) :
    productionMonetaryReconstructionBindingsBoundB map = true := by
  have critical := production_counterfeit_critical_linear_bindings_are_map_bound mapBound
  simp only [productionCounterfeitCriticalLinearBindingsBoundB,
    Bool.and_eq_true] at critical
  exact critical.2

theorem production_output_hash_required_linear_binding_executes
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (linearEquations :
      forall constraint, constraint < map.linearConstraintCount →
        linearConstraintEquation map witnessValues constraint)
    (output binding : Nat)
    (outputBound : output < 2)
    (active : publicValueAt map.publicValues (2 + output) = 1)
    (bindingBound : binding < (productionOutputHashRequiredLinearSpecs map output).length) :
    ProductionLinearConstraintSpecExecuted map witnessValues
      ((productionOutputHashRequiredLinearSpecs map output).getD binding
        zeroProductionLinearConstraintSpec) := by
  have checked := production_output_hash_linear_bindings_are_map_bound mapBound
  simp only [productionOutputHashLinearBindingsBoundB, Bool.and_eq_true] at checked
  have outputChecked := (List.all_eq_true.mp checked.2) output
    (List.mem_range.mpr outputBound)
  rw [if_pos active] at outputChecked
  simp only [productionOutputHashRequiredLinearSpecsPresentB,
    Bool.and_eq_true] at outputChecked
  have bindingChecked := (List.all_eq_true.mp outputChecked.2) binding
    (List.mem_range.mpr bindingBound)
  simp only [Bool.and_eq_true] at bindingChecked
  let constraint := (productionOutputHashBindingConstraintIndices map output).getD binding 0
  have constraintBound : constraint < map.linearConstraintCount :=
    of_decide_eq_true bindingChecked.1
  exact ⟨constraint, constraintBound, of_decide_eq_true bindingChecked.2,
    linearEquations constraint constraintBound⟩

theorem production_input_hash_required_linear_binding_executes
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (linearEquations :
      forall constraint, constraint < map.linearConstraintCount →
        linearConstraintEquation map witnessValues constraint)
    (input binding : Nat)
    (inputBound : input < 2)
    (active : publicValueAt map.publicValues input = 1)
    (bindingBound : binding < (productionInputHashRequiredLinearSpecs map input).length) :
    ProductionLinearConstraintSpecExecuted map witnessValues
      ((productionInputHashRequiredLinearSpecs map input).getD binding
        zeroProductionLinearConstraintSpec) := by
  have checked := production_input_hash_linear_bindings_are_map_bound mapBound
  simp only [productionInputHashLinearBindingsBoundB, Bool.and_eq_true] at checked
  have inputChecked := (List.all_eq_true.mp checked.2) input
    (List.mem_range.mpr inputBound)
  rw [if_pos active] at inputChecked
  simp only [productionInputHashRequiredLinearSpecsPresentB,
    Bool.and_eq_true] at inputChecked
  have bindingChecked := (List.all_eq_true.mp inputChecked.2) binding
    (List.mem_range.mpr bindingBound)
  simp only [Bool.and_eq_true] at bindingChecked
  let constraint := (productionInputHashBindingConstraintIndices map input).getD binding 0
  have constraintBound : constraint < map.linearConstraintCount :=
    of_decide_eq_true bindingChecked.1
  exact ⟨constraint, constraintBound, of_decide_eq_true bindingChecked.2,
    linearEquations constraint constraintBound⟩

theorem production_monetary_reconstruction_required_linear_binding_executes
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (linearEquations :
      forall constraint, constraint < map.linearConstraintCount →
        linearConstraintEquation map witnessValues constraint)
    (binding : Nat)
    (bindingBound :
      binding < (productionMonetaryReconstructionRequiredLinearSpecs map).length) :
    ProductionLinearConstraintSpecExecuted map witnessValues
      ((productionMonetaryReconstructionRequiredLinearSpecs map).getD binding
        zeroProductionLinearConstraintSpec) := by
  have checked := production_monetary_reconstruction_bindings_are_map_bound mapBound
  simp only [productionMonetaryReconstructionBindingsBoundB,
    Bool.and_eq_true] at checked
  have bindingChecked := (List.all_eq_true.mp checked.2) binding
    (List.mem_range.mpr bindingBound)
  simp only [Bool.and_eq_true] at bindingChecked
  let constraint := (productionMonetaryReconstructionConstraintIndices map).getD binding 0
  have constraintBound : constraint < map.linearConstraintCount :=
    of_decide_eq_true bindingChecked.1
  exact ⟨constraint, constraintBound, of_decide_eq_true bindingChecked.2,
    linearEquations constraint constraintBound⟩

structure ProductionAcceptedOutputHashImage
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (output : Nat) : Prop where
  mapBound : ProductionConstraintMapBound map
  outputIndexBound : output < 2
  outputActive : publicValueAt map.publicValues (2 + output) = 1
  exactOutputEquations :
    ProductionNonlinearFamilyEquations map witnessValues outputConstraintSpan
  exactValueRangeEquations :
    ProductionNonlinearFamilyEquations map witnessValues valueRangeConstraintSpan
  exactHashTransitionEquations :
    ProductionNonlinearFamilyEquations map witnessValues poseidonConstraintSpan
  exactRequiredLinearBindings :
    forall binding,
      binding < (productionOutputHashRequiredLinearSpecs map output).length →
        ProductionLinearConstraintSpecExecuted map witnessValues
          ((productionOutputHashRequiredLinearSpecs map output).getD binding
            zeroProductionLinearConstraintSpec)

def ProductionPoseidon2HashCollisionResistance
    (spec : ProductionNoteHashSpec) : Prop :=
  deployedProductionNoteHashSpecAccepts spec = true
    ∧ forall map leftWitness rightWitness output,
      ProductionAcceptedOutputHashImage map leftWitness output →
      ProductionAcceptedOutputHashImage map rightWitness output →
      productionOutputHashPreimage map leftWitness output =
        productionOutputHashPreimage map rightWitness output

theorem production_output_hash_preimage_equality_binds_value_and_asset
    {map : ProductionConstraintMap}
    {leftWitness rightWitness : List Nat}
    {output : Nat}
    (preimagesEqual :
      productionOutputHashPreimage map leftWitness output =
        productionOutputHashPreimage map rightWitness output) :
    productionOutputValue map leftWitness
        (productionOutputCommitmentLane map output 0) output =
          productionOutputValue map rightWitness
            (productionOutputCommitmentLane map output 0) output
      ∧ productionOutputAsset map leftWitness
        (productionOutputCommitmentLane map output 0) output =
          productionOutputAsset map rightWitness
            (productionOutputCommitmentLane map output 0) output := by
  have firstEqual := congrArg List.head? preimagesEqual
  have secondEqual := congrArg (fun values => values.tail.head?) preimagesEqual
  constructor
  · simpa [productionOutputHashPreimage] using firstEqual
  · simpa [productionOutputHashPreimage] using secondEqual

theorem production_poseidon2_collision_resistance_binds_accepted_output_value_and_asset
    {spec : ProductionNoteHashSpec}
    (collisionResistance : ProductionPoseidon2HashCollisionResistance spec)
    {map : ProductionConstraintMap}
    {leftWitness rightWitness : List Nat}
    {output : Nat}
    (leftImage : ProductionAcceptedOutputHashImage map leftWitness output)
    (rightImage : ProductionAcceptedOutputHashImage map rightWitness output) :
    productionOutputValue map leftWitness
        (productionOutputCommitmentLane map output 0) output =
          productionOutputValue map rightWitness
            (productionOutputCommitmentLane map output 0) output
      ∧ productionOutputAsset map leftWitness
        (productionOutputCommitmentLane map output 0) output =
          productionOutputAsset map rightWitness
            (productionOutputCommitmentLane map output 0) output := by
  apply production_output_hash_preimage_equality_binds_value_and_asset
  exact collisionResistance.2 map leftWitness rightWitness output leftImage rightImage

def ProductionLinearConstraintEquations
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop :=
  forall constraint, constraint < map.linearConstraintCount ->
    linearConstraintEquation map witnessValues constraint

structure ProductionSpendAuthorizationConstraintRelation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  independentSemanticProgram : productionSemanticProgramBoundB map = true
  linearBindings : ProductionLinearConstraintEquations map witnessValues
  inputSpendEquations :
    ProductionNonlinearFamilyEquations map witnessValues inputConstraintSpan
  authorizationEquations :
    ProductionNonlinearFamilyEquations map witnessValues authorizationConstraintSpan
  poseidonTransitionEquations :
    ProductionNonlinearFamilyEquations map witnessValues poseidonConstraintSpan

structure ProductionOutputValidityConstraintRelation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  independentSemanticProgram : productionSemanticProgramBoundB map = true
  linearBindings : ProductionLinearConstraintEquations map witnessValues
  outputValidityEquations :
    ProductionNonlinearFamilyEquations map witnessValues outputConstraintSpan
  valueRangeEquations :
    ProductionNonlinearFamilyEquations map witnessValues valueRangeConstraintSpan
  poseidonTransitionEquations :
    ProductionNonlinearFamilyEquations map witnessValues poseidonConstraintSpan

structure ProductionBalanceConservationConstraintRelation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  independentSemanticProgram : productionSemanticProgramBoundB map = true
  linearBindings : ProductionLinearConstraintEquations map witnessValues
  stablecoinEquations :
    ProductionNonlinearFamilyEquations map witnessValues stablecoinConstraintSpan
  balanceEquations :
    ProductionNonlinearFamilyEquations map witnessValues balanceConstraintSpan
  valueRangeEquations :
    ProductionNonlinearFamilyEquations map witnessValues valueRangeConstraintSpan

theorem production_concrete_output_yields_accepted_hash_image
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound map)
    (outputValidity : ProductionOutputValidityConstraintRelation map witnessValues)
    (output : Nat)
    (outputBound : output < 2)
    (active : publicValueAt map.publicValues (2 + output) = 1) :
    ProductionAcceptedOutputHashImage map witnessValues output :=
  { mapBound
    outputIndexBound := outputBound
    outputActive := active
    exactOutputEquations := outputValidity.outputValidityEquations
    exactValueRangeEquations := outputValidity.valueRangeEquations
    exactHashTransitionEquations := outputValidity.poseidonTransitionEquations
    exactRequiredLinearBindings := fun binding bindingBound =>
      production_output_hash_required_linear_binding_executes mapBound
        outputValidity.linearBindings output binding outputBound active bindingBound }

structure ProductionSmallWoodSemanticConstraintsSatisfied
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop where
  mapBound : ProductionConstraintMapBound map
  independentSemanticProgram : productionSemanticProgramBoundB map = true
  exactConstraintEvaluation :
    ExactProductionConstraintMapEvaluates map witnessValues
  sparseTableWellFormed : map.sparseTableWellFormed
  witnessLength : witnessValues.length = map.lppcRowCount * map.lppcPackingFactor
  nonlinearConstraintCount : map.nonlinearConstraintCount = 1722
  linearConstraintEquations :
    ProductionLinearConstraintEquations map witnessValues
  counterfeitCriticalLinearBindings :
    productionCounterfeitCriticalLinearBindingsBoundB map = true
  inputHashBindings :
    forall input binding,
      input < 2 ->
      publicValueAt map.publicValues input = 1 ->
      binding < (productionInputHashRequiredLinearSpecs map input).length ->
      ProductionLinearConstraintSpecExecuted map witnessValues
        ((productionInputHashRequiredLinearSpecs map input).getD binding
          zeroProductionLinearConstraintSpec)
  monetaryReconstructionBindings :
    forall binding,
      binding < (productionMonetaryReconstructionRequiredLinearSpecs map).length ->
      ProductionLinearConstraintSpecExecuted map witnessValues
        ((productionMonetaryReconstructionRequiredLinearSpecs map).getD binding
          zeroProductionLinearConstraintSpec)
  nonlinearConstraintEquations :
    forall lane, lane < map.lppcPackingFactor ->
      forall constraint, constraint < map.nonlinearConstraintCount ->
        nonlinearConstraintEquation map witnessValues lane constraint
  publicShapeEquations :
    ProductionNonlinearFamilyEquations map witnessValues publicShapeConstraintSpan
  spendAuthorization :
    ProductionSpendAuthorizationConstraintRelation map witnessValues
  outputValidity :
    ProductionOutputValidityConstraintRelation map witnessValues
  balanceConservation :
    ProductionBalanceConservationConstraintRelation map witnessValues

theorem production_nonlinear_equations_include_family
    {map : ProductionConstraintMap}
    {witnessValues : List Nat}
    (equations :
      forall lane, lane < map.lppcPackingFactor ->
        forall constraint, constraint < map.nonlinearConstraintCount ->
          nonlinearConstraintEquation map witnessValues lane constraint)
    (span : NonlinearConstraintFamilySpan)
    (spanBound : span.start + span.count <= map.nonlinearConstraintCount) :
    ProductionNonlinearFamilyEquations map witnessValues span := by
  intro lane laneBound relativeConstraint relativeBound
  exact equations lane laneBound
    (span.start + relativeConstraint) (by omega)

theorem production_smallwood_air_rows_are_implementation_equivalent
    {exactMap : ProductionConstraintMap}
    {witnessValues : List Nat}
    (mapBound : ProductionConstraintMapBound exactMap)
    (satisfied : ExactProductionConstraintMapEvaluates exactMap witnessValues) :
    ProductionSmallWoodSemanticConstraintsSatisfied exactMap witnessValues := by
  have independentSemanticProgram : productionSemanticProgramBoundB exactMap = true := by
    simp only [ProductionConstraintMapBound, productionConstraintMapBoundB,
      Bool.and_eq_true] at mapBound
    exact mapBound.2
  have exactConstraintEvaluation := satisfied
  simp only [ExactProductionConstraintMapEvaluates,
    exactProductionConstraintMapEvaluatesB, Bool.and_eq_true] at satisfied
  obtain ⟨satisfied, nonlinearRows⟩ := satisfied
  obtain ⟨satisfied, linearRows⟩ := satisfied
  obtain ⟨mapWellFormed, witnessLengthDecision⟩ := satisfied
  have witnessLength :
      witnessValues.length = exactMap.lppcRowCount * exactMap.lppcPackingFactor :=
    of_decide_eq_true witnessLengthDecision
  simp only [nonlinearProgramEvaluatesB, Bool.and_eq_true] at nonlinearRows
  obtain ⟨nonlinearCountDecision, nonlinearLanes⟩ := nonlinearRows
  have nonlinearConstraintCount : exactMap.nonlinearConstraintCount = 1722 :=
    of_decide_eq_true nonlinearCountDecision
  have linearConstraintEquations :
      forall constraint, constraint < exactMap.linearConstraintCount ->
        linearConstraintEquation exactMap witnessValues constraint := by
    intro constraint constraintBound
    have evaluated := (List.all_eq_true.mp linearRows) constraint
      (List.mem_range.mpr constraintBound)
    have equation :
        linearConstraintValue exactMap witnessValues constraint =
          fieldValue (exactMap.linearTargets.getD constraint 0) :=
      of_decide_eq_true evaluated
    exact equation
  have nonlinearConstraintEquations :
      forall lane, lane < exactMap.lppcPackingFactor ->
        forall constraint, constraint < exactMap.nonlinearConstraintCount ->
          nonlinearConstraintEquation exactMap witnessValues lane constraint := by
    intro lane laneBound constraint constraintBound
    have laneEvaluated := (List.all_eq_true.mp nonlinearLanes) lane
      (List.mem_range.mpr laneBound)
    have allConstraints :
        (List.range exactMap.nonlinearConstraintCount).all
          (fun index => nonlinearConstraintEvaluatesB exactMap witnessValues lane index) = true := by
      simpa [nonlinearLaneEvaluatesB] using laneEvaluated
    have evaluated := (List.all_eq_true.mp allConstraints) constraint
      (List.mem_range.mpr constraintBound)
    have equation :
        nonlinearConstraintValue exactMap witnessValues lane constraint = 0 :=
      of_decide_eq_true evaluated
    exact equation
  have familyEquations
      (span : NonlinearConstraintFamilySpan)
      (spanBound : span.start + span.count <= 1722) :
      ProductionNonlinearFamilyEquations exactMap witnessValues span := by
    apply production_nonlinear_equations_include_family
      nonlinearConstraintEquations span
    simpa [nonlinearConstraintCount] using spanBound
  have publicShapeEquations := familyEquations publicShapeConstraintSpan (by decide)
  have inputSpendEquations := familyEquations inputConstraintSpan (by decide)
  have outputValidityEquations := familyEquations outputConstraintSpan (by decide)
  have stablecoinEquations := familyEquations stablecoinConstraintSpan (by decide)
  have balanceEquations := familyEquations balanceConstraintSpan (by decide)
  have valueRangeEquations := familyEquations valueRangeConstraintSpan (by decide)
  have authorizationEquations := familyEquations authorizationConstraintSpan (by decide)
  have poseidonTransitionEquations := familyEquations poseidonConstraintSpan (by decide)
  exact
    { mapBound
      independentSemanticProgram
      exactConstraintEvaluation
      sparseTableWellFormed := mapWellFormed
      witnessLength
      nonlinearConstraintCount
      linearConstraintEquations
      counterfeitCriticalLinearBindings :=
        production_counterfeit_critical_linear_bindings_are_map_bound mapBound
      inputHashBindings := fun input binding inputBound active bindingBound =>
        production_input_hash_required_linear_binding_executes mapBound
          linearConstraintEquations input binding inputBound active bindingBound
      monetaryReconstructionBindings := fun binding bindingBound =>
        production_monetary_reconstruction_required_linear_binding_executes mapBound
          linearConstraintEquations binding bindingBound
      nonlinearConstraintEquations
      publicShapeEquations
      spendAuthorization :=
        { independentSemanticProgram
          linearBindings := linearConstraintEquations
          inputSpendEquations
          authorizationEquations
          poseidonTransitionEquations }
      outputValidity :=
        { independentSemanticProgram
          linearBindings := linearConstraintEquations
          outputValidityEquations
          valueRangeEquations
          poseidonTransitionEquations }
      balanceConservation :=
        { independentSemanticProgram
          linearBindings := linearConstraintEquations
          stablecoinEquations
          balanceEquations
          valueRangeEquations } }

structure ProductionSmallWoodProofVerifier where
  accepts : List Byte → List Byte → Digest → ProofWrapperInput → Bool

structure DeployedSmallWoodProtocolStatement where
  exactMap : ProductionConstraintMap
  serializedPublicInputBytes : List Byte
  verifierProfile : Digest
  wrapper : ProofWrapperInput

def deployedSmallWoodProtocolStatement
    (exactMap : ProductionConstraintMap)
    (serializedPublicInputBytes : List Byte)
    (verifierProfile : Digest)
    (wrapper : ProofWrapperInput) : DeployedSmallWoodProtocolStatement :=
  { exactMap
    serializedPublicInputBytes
    verifierProfile
    wrapper }

abbrev DeployedSmallWoodProtocolModel :=
  ProtocolModel
    DeployedSmallWoodProtocolStatement
    (List Byte)
    (List Byte)
    (List Nat)
    (List Nat)
    (List Nat)

abbrev DeployedSmallWoodPrimitiveFailures :=
  PrimitiveFailurePredicates DeployedSmallWoodProtocolStatement (List Byte)

structure DeployedSmallWoodKnowledgeSoundnessReduction
    (verifier : ProductionSmallWoodProofVerifier)
    (exactMap : ProductionConstraintMap)
    (proofBytes serializedPublicInputBytes : List Byte)
    (verifierProfile : Digest)
    (wrapper : ProofWrapperInput) : Type where
  model : DeployedSmallWoodProtocolModel
  primitiveFailures : DeployedSmallWoodPrimitiveFailures
  protocolReduction : KnowledgeSoundnessReduction model primitiveFailures
  productionVerifierImplementationMismatch : Prop
  productionAcceptanceRefinesProtocol :
    verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true →
      model.verifies
          (deployedSmallWoodProtocolStatement exactMap serializedPublicInputBytes
            verifierProfile wrapper)
          proofBytes = true
        ∨ productionVerifierImplementationMismatch
  protocolRelationRefinesExactMap :
    ∀ witnessValues,
      model.relation
          (deployedSmallWoodProtocolStatement exactMap serializedPublicInputBytes
            verifierProfile wrapper)
          witnessValues →
        ExactProductionConstraintMapEvaluates exactMap witnessValues

def DeployedSmallWoodSoundnessFailure
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (reduction :
      DeployedSmallWoodKnowledgeSoundnessReduction verifier exactMap proofBytes
        serializedPublicInputBytes verifierProfile wrapper) : Prop :=
  reduction.productionVerifierImplementationMismatch
    ∨ ProtocolSoundnessFailure reduction.primitiveFailures
        (deployedSmallWoodProtocolStatement exactMap serializedPublicInputBytes
          verifierProfile wrapper)
        proofBytes

structure DeployedSmallWoodKnowledgeSoundnessEvidence
    (verifier : ProductionSmallWoodProofVerifier)
    (exactMap : ProductionConstraintMap)
    (proofBytes serializedPublicInputBytes : List Byte)
    (verifierProfile : Digest)
    (wrapper : ProofWrapperInput) : Type where
  reduction :
    DeployedSmallWoodKnowledgeSoundnessReduction verifier exactMap proofBytes
      serializedPublicInputBytes verifierProfile wrapper
  noNamedSoundnessFailure : ¬ DeployedSmallWoodSoundnessFailure reduction

theorem accepted_smallwood_proof_yields_exact_witness_or_named_failure
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (accepted :
      verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true)
    (reduction :
      DeployedSmallWoodKnowledgeSoundnessReduction verifier exactMap proofBytes
        serializedPublicInputBytes verifierProfile wrapper) :
    (exists witnessValues,
        ExactProductionConstraintMapEvaluates exactMap witnessValues)
      ∨ DeployedSmallWoodSoundnessFailure reduction := by
  rcases reduction.productionAcceptanceRefinesProtocol accepted with
    protocolAccepted | implementationMismatch
  · rcases accepted_protocol_yields_witness_or_named_failure
      reduction.protocolReduction protocolAccepted with witness | protocolFailure
    · obtain ⟨witnessValues, _, relation⟩ := witness
      exact Or.inl ⟨witnessValues,
        reduction.protocolRelationRefinesExactMap witnessValues relation⟩
    · exact Or.inr (Or.inr protocolFailure)
  · exact Or.inr (Or.inl implementationMismatch)

theorem accepted_smallwood_proof_yields_exact_witness_outside_named_failures
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (accepted :
      verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true)
    (evidence :
      DeployedSmallWoodKnowledgeSoundnessEvidence verifier exactMap proofBytes
        serializedPublicInputBytes verifierProfile wrapper) :
    exists witnessValues,
      ExactProductionConstraintMapEvaluates exactMap witnessValues := by
  rcases accepted_smallwood_proof_yields_exact_witness_or_named_failure
      accepted evidence.reduction with witness | failure
  · exact witness
  · exact False.elim (evidence.noNamedSoundnessFailure failure)

theorem accepted_smallwood_proof_yields_exact_semantic_constraints
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (accepted :
      verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true)
    (mapBound : ProductionConstraintMapBound exactMap)
    (knowledgeSoundness :
      DeployedSmallWoodKnowledgeSoundnessEvidence verifier exactMap proofBytes
        serializedPublicInputBytes verifierProfile wrapper) :
    exists witnessValues,
      ProductionSmallWoodSemanticConstraintsSatisfied exactMap witnessValues := by
  obtain ⟨witnessValues, exactRows⟩ :=
    accepted_smallwood_proof_yields_exact_witness_outside_named_failures
      accepted knowledgeSoundness
  exact ⟨witnessValues,
    production_smallwood_air_rows_are_implementation_equivalent mapBound exactRows⟩

structure ProductionAcceptedTransactionRelation
    (verifier : ProductionSmallWoodProofVerifier)
    (exactMap : ProductionConstraintMap)
    (canonicalPublicValues : List Nat)
    (proofBytes serializedPublicInputBytes : List Byte)
    (verifierProfile : Digest)
    (wrapper : ProofWrapperInput) : Prop where
  wrapperAccepted : proofWrapperAccepts wrapper = true
  exactProofArtifactAccepted :
    verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true
  constraintMapBound : ProductionConstraintMapBound exactMap
  canonicalPublicValuesBound : exactMap.publicValues = canonicalPublicValues
  exactSemanticConstraints :
    exists witnessValues,
      ProductionSmallWoodSemanticConstraintsSatisfied exactMap witnessValues

theorem accepted_smallwood_proof_yields_transaction_relation
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {canonicalPublicValues : List Nat}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (wrapperAccepted : proofWrapperAccepts wrapper = true)
    (artifactAccepted :
      verifier.accepts proofBytes serializedPublicInputBytes verifierProfile wrapper = true)
    (mapBound : ProductionConstraintMapBound exactMap)
    (publicValuesBound : exactMap.publicValues = canonicalPublicValues)
    (knowledgeSoundness :
      DeployedSmallWoodKnowledgeSoundnessEvidence verifier exactMap proofBytes
        serializedPublicInputBytes verifierProfile wrapper) :
    ProductionAcceptedTransactionRelation verifier exactMap canonicalPublicValues
      proofBytes serializedPublicInputBytes verifierProfile wrapper :=
  { wrapperAccepted
    exactProofArtifactAccepted := artifactAccepted
    constraintMapBound := mapBound
    canonicalPublicValuesBound := publicValuesBound
    exactSemanticConstraints :=
      accepted_smallwood_proof_yields_exact_semantic_constraints
        artifactAccepted mapBound knowledgeSoundness }

theorem production_accepted_transaction_relation_exposes_same_witness_semantics
    {verifier : ProductionSmallWoodProofVerifier}
    {exactMap : ProductionConstraintMap}
    {canonicalPublicValues : List Nat}
    {proofBytes serializedPublicInputBytes : List Byte}
    {verifierProfile : Digest}
    {wrapper : ProofWrapperInput}
    (relation :
      ProductionAcceptedTransactionRelation verifier exactMap canonicalPublicValues
        proofBytes serializedPublicInputBytes verifierProfile wrapper) :
    exists witnessValues,
      ExactProductionConstraintMapEvaluates exactMap witnessValues
        ∧ ProductionSpendAuthorizationConstraintRelation exactMap witnessValues
        ∧ ProductionOutputValidityConstraintRelation exactMap witnessValues
        ∧ ProductionBalanceConservationConstraintRelation exactMap witnessValues := by
  obtain ⟨witnessValues, semanticConstraints⟩ := relation.exactSemanticConstraints
  exact
    ⟨witnessValues, semanticConstraints.exactConstraintEvaluation,
      semanticConstraints.spendAuthorization,
      semanticConstraints.outputValidity,
      semanticConstraints.balanceConservation⟩

theorem production_output_row_hash_binding_rejects_opening_substitution
    {noteHashSpec : ProductionNoteHashSpec}
    (collisionResistance : ProductionHashCollisionResistance noteHashSpec)
    {publicCommitment publicCiphertextHash : Digest}
    {witness : SmallWoodOutputWitness} {row : SmallWoodOutputConstraintRow}
    (executed :
      ProductionOutputRowExecuted noteHashSpec 1 publicCommitment publicCiphertextHash witness row)
    {substituted : ProductionNoteOpening}
    (substitutedCommitment : productionNoteHash substituted = publicCommitment) :
    productionNotePreimage substituted =
      productionNotePreimage (productionNoteOpeningFromOutputWitness witness) := by
  rcases executed with inactive | active
  · omega
  · have witnessCommitment :
        productionNoteHash (productionNoteOpeningFromOutputWitness witness) =
          publicCommitment :=
      active.2.2.1.symm.trans
        (active.2.2.2.2.1.symm.trans active.2.2.2.2.2.1)
    exact collisionResistance.2 substituted
      (productionNoteOpeningFromOutputWitness witness)
      (substitutedCommitment.trans witnessCommitment.symm)

theorem production_output_row_hash_binding_preserves_canonical_value_and_asset
    {noteHashSpec : ProductionNoteHashSpec}
    (collisionResistance : ProductionHashCollisionResistance noteHashSpec)
    {publicCommitment publicCiphertextHash : Digest}
    {witness : SmallWoodOutputWitness} {row : SmallWoodOutputConstraintRow}
    (executed :
      ProductionOutputRowExecuted noteHashSpec 1 publicCommitment publicCiphertextHash witness row)
    {substituted : ProductionNoteOpening}
    (substitutedCanonical : ProductionValueAssetCanonical substituted)
    (witnessCanonical :
      ProductionValueAssetCanonical (productionNoteOpeningFromOutputWitness witness))
    (substitutedCommitment : productionNoteHash substituted = publicCommitment) :
    substituted.value = witness.value ∧ substituted.assetId = witness.assetId := by
  exact canonical_note_preimage_equality_binds_value_and_asset
    substitutedCanonical witnessCanonical
    (production_output_row_hash_binding_rejects_opening_substitution
      collisionResistance executed substitutedCommitment)

def ProductionOutputOpeningsBound
    (noteHashSpec : ProductionNoteHashSpec) :
    List Nat -> List Digest -> List SmallWoodOutputWitness -> Prop
  | [], [], [] => True
  | flag :: flags, commitment :: commitments, witness :: witnesses =>
      (flag = 1 ->
        productionNoteHash (productionNoteOpeningFromOutputWitness witness) = commitment)
        ∧ ProductionOutputOpeningsBound noteHashSpec flags commitments witnesses
  | _, _, _ => False

theorem production_output_rows_bind_every_active_opening
    {noteHashSpec : ProductionNoteHashSpec}
    {flags : List Nat} {commitments ciphertextHashes : List Digest}
    {witnesses : List SmallWoodOutputWitness} {rows : List SmallWoodOutputConstraintRow}
    (executed :
      productionOutputRowsExecute noteHashSpec flags commitments ciphertextHashes witnesses rows =
        true) :
    ProductionOutputOpeningsBound noteHashSpec flags commitments witnesses := by
  induction flags generalizing commitments ciphertextHashes witnesses rows with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases witnesses <;> cases rows <;>
        simp [productionOutputRowsExecute, ProductionOutputOpeningsBound] at executed ⊢
  | cons flag flags inductionHypothesis =>
      cases commitments with
      | nil => simp [productionOutputRowsExecute] at executed
      | cons commitment commitments =>
        cases ciphertextHashes with
        | nil => simp [productionOutputRowsExecute] at executed
        | cons ciphertextHash ciphertextHashes =>
          cases witnesses with
          | nil => simp [productionOutputRowsExecute] at executed
          | cons witness witnesses =>
            cases rows with
            | nil => simp [productionOutputRowsExecute] at executed
            | cons row rows =>
              simp only [productionOutputRowsExecute, Bool.and_eq_true] at executed
              have head := production_output_row_checks_refine_semantic_row executed.1
              refine ⟨?_, inductionHypothesis executed.2⟩
              intro activeFlag
              rcases head with inactive | active
              · omega
              · exact active.2.2.1.symm.trans
                  (active.2.2.2.2.1.symm.trans active.2.2.2.2.2.1)

def ProductionOutputOpeningsUnique
    (noteHashSpec : ProductionNoteHashSpec) :
    List Nat -> List Digest -> List SmallWoodOutputWitness -> Prop
  | [], [], [] => True
  | flag :: flags, commitment :: commitments, witness :: witnesses =>
      (flag = 1 -> forall substituted,
        productionNoteHash substituted = commitment ->
          productionNotePreimage substituted =
            productionNotePreimage (productionNoteOpeningFromOutputWitness witness))
        ∧ ProductionOutputOpeningsUnique noteHashSpec flags commitments witnesses
  | _, _, _ => False

theorem production_output_opening_bindings_are_unique
    {noteHashSpec : ProductionNoteHashSpec}
    (collisionResistance : ProductionHashCollisionResistance noteHashSpec)
    {flags : List Nat} {commitments : List Digest}
    {witnesses : List SmallWoodOutputWitness}
    (bound : ProductionOutputOpeningsBound noteHashSpec flags commitments witnesses) :
    ProductionOutputOpeningsUnique noteHashSpec flags commitments witnesses := by
  induction flags generalizing commitments witnesses with
  | nil =>
      cases commitments <;> cases witnesses <;>
        simp [ProductionOutputOpeningsBound, ProductionOutputOpeningsUnique] at bound ⊢
  | cons flag flags inductionHypothesis =>
      cases commitments with
      | nil => simp [ProductionOutputOpeningsBound] at bound
      | cons commitment commitments =>
        cases witnesses with
        | nil => simp [ProductionOutputOpeningsBound] at bound
        | cons witness witnesses =>
          refine ⟨?_, inductionHypothesis bound.2⟩
          intro activeFlag substituted substitutedCommitment
          exact collisionResistance.2 substituted
            (productionNoteOpeningFromOutputWitness witness)
            (substitutedCommitment.trans (bound.1 activeFlag).symm)

end SmallWoodProductionConstraintRefinement
end Transaction
end Hegemon
