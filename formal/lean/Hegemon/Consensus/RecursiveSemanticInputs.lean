namespace Hegemon
namespace Consensus
namespace RecursiveSemanticInputs

inductive SemanticReject where
  | emptyBlock
  | excessiveNullifiers
  | zeroNullifier
  | missingNonzeroNullifier
  | duplicateNullifier
  | daEncoding
deriving DecidableEq, Repr

structure SemanticDerivationInput where
  txCount : Nat
  nullifierCountsWithinMax : Bool
  hasZeroNullifier : Bool
  hasAnyNonzeroNullifier : Bool
  hasDuplicateNonzeroNullifier : Bool
  daEncodingValid : Bool
deriving DecidableEq, Repr

structure SemanticSourceFields where
  expectedCommitment : Nat
  parentRoot : Nat
  expectedTreeRoot : Nat
  parentKernelRoot : Nat
  expectedKernelRoot : Nat
  nullifierRoot : Nat
  daRoot : Nat
  messageRoot : Nat
  parentTreeCommitment : Nat
  expectedTreeCommitment : Nat
deriving DecidableEq, Repr

structure RecursiveSemanticFields where
  txStatementsCommitment : Nat
  startShieldedRoot : Nat
  endShieldedRoot : Nat
  startKernelRoot : Nat
  endKernelRoot : Nat
  nullifierRoot : Nat
  daRoot : Nat
  messageRoot : Nat
  startTreeCommitment : Nat
  endTreeCommitment : Nat
deriving DecidableEq, Repr

def evaluateSemanticRejection (input : SemanticDerivationInput) : Option SemanticReject :=
  if input.txCount = 0 then
    some SemanticReject.emptyBlock
  else if input.nullifierCountsWithinMax = false then
    some SemanticReject.excessiveNullifiers
  else if input.hasZeroNullifier then
    some SemanticReject.zeroNullifier
  else if input.hasAnyNonzeroNullifier = false then
    some SemanticReject.missingNonzeroNullifier
  else if input.hasDuplicateNonzeroNullifier then
    some SemanticReject.duplicateNullifier
  else if input.daEncodingValid = false then
    some SemanticReject.daEncoding
  else
    none

def semanticPreconditions (input : SemanticDerivationInput) : Bool :=
  input.txCount ≠ 0
    && input.nullifierCountsWithinMax
    && !input.hasZeroNullifier
    && input.hasAnyNonzeroNullifier
    && !input.hasDuplicateNonzeroNullifier
    && input.daEncodingValid

def semanticAccepts (input : SemanticDerivationInput) : Bool :=
  evaluateSemanticRejection input = none

def deriveSemanticFields
    (input : SemanticDerivationInput)
    (source : SemanticSourceFields) :
    Option RecursiveSemanticFields :=
  if semanticAccepts input then
    some {
      txStatementsCommitment := source.expectedCommitment,
      startShieldedRoot := source.parentRoot,
      endShieldedRoot := source.expectedTreeRoot,
      startKernelRoot := source.parentKernelRoot,
      endKernelRoot := source.expectedKernelRoot,
      nullifierRoot := source.nullifierRoot,
      daRoot := source.daRoot,
      messageRoot := source.messageRoot,
      startTreeCommitment := source.parentTreeCommitment,
      endTreeCommitment := source.expectedTreeCommitment
    }
  else
    none

theorem semantic_accepts_iff_preconditions (input : SemanticDerivationInput) :
    semanticAccepts input = semanticPreconditions input := by
  cases input with
  | mk txCount nullifierCountsWithinMax hasZeroNullifier hasAnyNonzeroNullifier
      hasDuplicateNonzeroNullifier daEncodingValid =>
      unfold semanticAccepts semanticPreconditions evaluateSemanticRejection
      cases txCount <;> cases nullifierCountsWithinMax <;> cases hasZeroNullifier <;>
        cases hasAnyNonzeroNullifier <;> cases hasDuplicateNonzeroNullifier <;>
        cases daEncodingValid <;> simp

def validInput : SemanticDerivationInput :=
  {
    txCount := 2,
    nullifierCountsWithinMax := true,
    hasZeroNullifier := false,
    hasAnyNonzeroNullifier := true,
    hasDuplicateNonzeroNullifier := false,
    daEncodingValid := true
  }

def sampleSource : SemanticSourceFields :=
  {
    expectedCommitment := 16,
    parentRoot := 32,
    expectedTreeRoot := 33,
    parentKernelRoot := 48,
    expectedKernelRoot := 49,
    nullifierRoot := 64,
    daRoot := 80,
    messageRoot := 96,
    parentTreeCommitment := 112,
    expectedTreeCommitment := 113
  }

theorem valid_semantic_derivation_accepts :
    evaluateSemanticRejection validInput = none := by
  native_decide

theorem empty_block_rejects :
    evaluateSemanticRejection { validInput with txCount := 0 } =
      some SemanticReject.emptyBlock := by
  native_decide

theorem excessive_nullifiers_rejects :
    evaluateSemanticRejection { validInput with nullifierCountsWithinMax := false } =
      some SemanticReject.excessiveNullifiers := by
  native_decide

theorem zero_nullifier_rejects :
    evaluateSemanticRejection { validInput with hasZeroNullifier := true } =
      some SemanticReject.zeroNullifier := by
  native_decide

theorem missing_nonzero_nullifier_rejects :
    evaluateSemanticRejection { validInput with hasAnyNonzeroNullifier := false } =
      some SemanticReject.missingNonzeroNullifier := by
  native_decide

theorem duplicate_nullifier_rejects :
    evaluateSemanticRejection { validInput with hasDuplicateNonzeroNullifier := true } =
      some SemanticReject.duplicateNullifier := by
  native_decide

theorem da_encoding_rejects :
    evaluateSemanticRejection { validInput with daEncodingValid := false } =
      some SemanticReject.daEncoding := by
  native_decide

theorem valid_semantic_fields_match_sources
    (input : SemanticDerivationInput)
    (source : SemanticSourceFields)
    (h : semanticAccepts input = true) :
    deriveSemanticFields input source =
      some {
        txStatementsCommitment := source.expectedCommitment,
        startShieldedRoot := source.parentRoot,
        endShieldedRoot := source.expectedTreeRoot,
        startKernelRoot := source.parentKernelRoot,
        endKernelRoot := source.expectedKernelRoot,
        nullifierRoot := source.nullifierRoot,
        daRoot := source.daRoot,
        messageRoot := source.messageRoot,
        startTreeCommitment := source.parentTreeCommitment,
        endTreeCommitment := source.expectedTreeCommitment
      } := by
  simp [deriveSemanticFields, h]

theorem rejection_precedes_da_encoding :
    evaluateSemanticRejection
        { validInput with
          hasDuplicateNonzeroNullifier := true,
          daEncodingValid := false
        } =
      some SemanticReject.duplicateNullifier := by
  native_decide

end RecursiveSemanticInputs
end Consensus
end Hegemon
