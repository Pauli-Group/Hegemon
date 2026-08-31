namespace Hegemon
namespace Native
namespace CanonicalReorgPersistenceAdmission

inductive SuppliedBlockRecordStatus where
  | knownExact
  | missing
deriving DecidableEq, Repr

inductive SuppliedBlockRecordClassificationReject where
  | knownRecordMismatch
deriving DecidableEq, Repr

structure SuppliedBlockRecordClassificationInput where
  storedRecordPresent : Bool
  storedRecordExact : Bool
deriving DecidableEq, Repr

def evaluateSuppliedBlockRecordClassification
    (input : SuppliedBlockRecordClassificationInput) :
    Except SuppliedBlockRecordClassificationReject SuppliedBlockRecordStatus :=
  if input.storedRecordPresent = false then
    .ok SuppliedBlockRecordStatus.missing
  else if input.storedRecordExact = false then
    .error SuppliedBlockRecordClassificationReject.knownRecordMismatch
  else
    .ok SuppliedBlockRecordStatus.knownExact

theorem absent_record_classifies_missing :
    evaluateSuppliedBlockRecordClassification
      { storedRecordPresent := false, storedRecordExact := false } =
        .ok SuppliedBlockRecordStatus.missing := by
  rfl

theorem exact_stored_record_classifies_known_exact :
    evaluateSuppliedBlockRecordClassification
      { storedRecordPresent := true, storedRecordExact := true } =
        .ok SuppliedBlockRecordStatus.knownExact := by
  rfl

theorem mismatched_stored_record_rejects :
    evaluateSuppliedBlockRecordClassification
      { storedRecordPresent := true, storedRecordExact := false } =
        .error SuppliedBlockRecordClassificationReject.knownRecordMismatch := by
  rfl

theorem accepted_known_status_requires_exact_stored_record
    {input : SuppliedBlockRecordClassificationInput}
    (accepted : evaluateSuppliedBlockRecordClassification input =
      .ok SuppliedBlockRecordStatus.knownExact) :
    input.storedRecordPresent = true ∧ input.storedRecordExact = true := by
  cases input with
  | mk storedRecordPresent storedRecordExact =>
      cases storedRecordPresent <;> cases storedRecordExact <;>
        simp [evaluateSuppliedBlockRecordClassification] at accepted ⊢

inductive CanonicalReorgPersistenceReject where
  | knownCountExceedsReplacement
  | classifiedMissingCountMismatch
  | suppliedMissingCountMismatch
  | connectedExactKnownRowsMissing
  | suffixNotFullyValidated
  | noncanonicalBatchWriteCountMismatch
  | noncanonicalBatchNotDurable
  | durableRecordsMismatchReplacement
  | canonicalTransactionWritesBlockRecords
deriving DecidableEq, Repr

structure CanonicalReorgPersistenceInput where
  replacementBlockCount : Nat
  knownBlockCount : Nat
  classifiedMissingBlockCount : Nat
  suppliedMissingBlockCount : Nat
  connectedExactKnownRows : Bool
  suffixFullyValidated : Bool
  noncanonicalBatchBlockRecordWrites : Nat
  noncanonicalBatchDurabilityFlushed : Bool
  durableRecordsMatchReplacement : Bool
  canonicalTransactionBlockRecordWrites : Nat
deriving DecidableEq, Repr

def orderedPersistenceChecks (input : CanonicalReorgPersistenceInput) :
    List (Bool × CanonicalReorgPersistenceReject) :=
  [
    (decide (input.knownBlockCount ≤ input.replacementBlockCount),
      CanonicalReorgPersistenceReject.knownCountExceedsReplacement),
    (decide (input.classifiedMissingBlockCount =
      input.replacementBlockCount - input.knownBlockCount),
      CanonicalReorgPersistenceReject.classifiedMissingCountMismatch),
    (decide (input.suppliedMissingBlockCount =
      input.classifiedMissingBlockCount),
      CanonicalReorgPersistenceReject.suppliedMissingCountMismatch),
    (input.connectedExactKnownRows,
      CanonicalReorgPersistenceReject.connectedExactKnownRowsMissing),
    (input.suffixFullyValidated,
      CanonicalReorgPersistenceReject.suffixNotFullyValidated),
    (decide (input.noncanonicalBatchBlockRecordWrites =
      input.suppliedMissingBlockCount),
      CanonicalReorgPersistenceReject.noncanonicalBatchWriteCountMismatch),
    (input.noncanonicalBatchDurabilityFlushed,
      CanonicalReorgPersistenceReject.noncanonicalBatchNotDurable),
    (input.durableRecordsMatchReplacement,
      CanonicalReorgPersistenceReject.durableRecordsMismatchReplacement),
    (decide (input.canonicalTransactionBlockRecordWrites = 0),
      CanonicalReorgPersistenceReject.canonicalTransactionWritesBlockRecords)
  ]

def firstPersistenceReject :
    List (Bool × CanonicalReorgPersistenceReject) ->
      Option CanonicalReorgPersistenceReject
  | [] => none
  | (ok, rejection) :: rest =>
      if ok then firstPersistenceReject rest else some rejection

def allPersistenceChecks :
    List (Bool × CanonicalReorgPersistenceReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allPersistenceChecks rest

theorem first_persistence_reject_none_iff_all_checks
    {checks : List (Bool × CanonicalReorgPersistenceReject)} :
    firstPersistenceReject checks = none ↔
      allPersistenceChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstPersistenceReject, allPersistenceChecks]
  | cons head rest ih =>
      cases head with
      | mk ok rejection =>
          cases ok <;>
            simp [firstPersistenceReject, allPersistenceChecks, ih]

def evaluateCanonicalReorgPersistenceRejection
    (input : CanonicalReorgPersistenceInput) :
    Option CanonicalReorgPersistenceReject :=
  firstPersistenceReject (orderedPersistenceChecks input)

def canonicalReorgPersistenceAccepts
    (input : CanonicalReorgPersistenceInput) : Bool :=
  evaluateCanonicalReorgPersistenceRejection input = none

def canonicalReorgPersistencePreconditions
    (input : CanonicalReorgPersistenceInput) : Bool :=
  allPersistenceChecks (orderedPersistenceChecks input)

theorem accepts_iff_canonical_reorg_persistence_preconditions
    {input : CanonicalReorgPersistenceInput} :
    canonicalReorgPersistenceAccepts input = true ↔
      canonicalReorgPersistencePreconditions input = true := by
  unfold canonicalReorgPersistenceAccepts
  unfold canonicalReorgPersistencePreconditions
  unfold evaluateCanonicalReorgPersistenceRejection
  simpa using
    (first_persistence_reject_none_iff_all_checks
      (checks := orderedPersistenceChecks input))

def valid : CanonicalReorgPersistenceInput :=
  {
    replacementBlockCount := 4,
    knownBlockCount := 2,
    classifiedMissingBlockCount := 2,
    suppliedMissingBlockCount := 2,
    connectedExactKnownRows := true,
    suffixFullyValidated := true,
    noncanonicalBatchBlockRecordWrites := 2,
    noncanonicalBatchDurabilityFlushed := true,
    durableRecordsMatchReplacement := true,
    canonicalTransactionBlockRecordWrites := 0
  }

theorem valid_accepts :
    evaluateCanonicalReorgPersistenceRejection valid = none := by
  decide

theorem valid_all_known_accepts :
    evaluateCanonicalReorgPersistenceRejection
      { valid with
        knownBlockCount := 4,
        classifiedMissingBlockCount := 0,
        suppliedMissingBlockCount := 0,
        noncanonicalBatchBlockRecordWrites := 0 } = none := by
  decide

theorem known_count_exceeds_replacement_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with knownBlockCount := 5 } =
        some CanonicalReorgPersistenceReject.knownCountExceedsReplacement := by
  decide

theorem classified_missing_count_mismatch_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with classifiedMissingBlockCount := 1 } =
        some CanonicalReorgPersistenceReject.classifiedMissingCountMismatch := by
  decide

theorem supplied_missing_count_mismatch_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with suppliedMissingBlockCount := 1 } =
        some CanonicalReorgPersistenceReject.suppliedMissingCountMismatch := by
  decide

theorem connected_exact_known_rows_missing_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with connectedExactKnownRows := false } =
        some CanonicalReorgPersistenceReject.connectedExactKnownRowsMissing := by
  decide

theorem unvalidated_suffix_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with suffixFullyValidated := false } =
        some CanonicalReorgPersistenceReject.suffixNotFullyValidated := by
  decide

theorem noncanonical_batch_write_count_mismatch_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with noncanonicalBatchBlockRecordWrites := 1 } =
        some CanonicalReorgPersistenceReject.noncanonicalBatchWriteCountMismatch := by
  decide

theorem noncanonical_batch_not_durable_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with noncanonicalBatchDurabilityFlushed := false } =
        some CanonicalReorgPersistenceReject.noncanonicalBatchNotDurable := by
  decide

theorem durable_records_mismatch_replacement_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with durableRecordsMatchReplacement := false } =
        some CanonicalReorgPersistenceReject.durableRecordsMismatchReplacement := by
  decide

theorem canonical_transaction_block_record_write_rejects :
    evaluateCanonicalReorgPersistenceRejection
      { valid with canonicalTransactionBlockRecordWrites := 1 } =
        some CanonicalReorgPersistenceReject.canonicalTransactionWritesBlockRecords := by
  decide

theorem structural_counts_precede_validation_and_storage :
    evaluateCanonicalReorgPersistenceRejection
      { valid with
        classifiedMissingBlockCount := 1,
        connectedExactKnownRows := false,
        noncanonicalBatchDurabilityFlushed := false } =
        some CanonicalReorgPersistenceReject.classifiedMissingCountMismatch := by
  decide

theorem validation_precedes_storage_durability :
    evaluateCanonicalReorgPersistenceRejection
      { valid with
        suffixFullyValidated := false,
        noncanonicalBatchDurabilityFlushed := false } =
        some CanonicalReorgPersistenceReject.suffixNotFullyValidated := by
  decide

theorem accepted_persistence_has_exact_prestorage_and_zero_canonical_record_writes
    {input : CanonicalReorgPersistenceInput}
    (accepted : canonicalReorgPersistenceAccepts input = true) :
    input.knownBlockCount ≤ input.replacementBlockCount
      ∧ input.classifiedMissingBlockCount =
          input.replacementBlockCount - input.knownBlockCount
      ∧ input.suppliedMissingBlockCount = input.classifiedMissingBlockCount
      ∧ input.connectedExactKnownRows = true
      ∧ input.suffixFullyValidated = true
      ∧ input.noncanonicalBatchBlockRecordWrites =
          input.suppliedMissingBlockCount
      ∧ input.noncanonicalBatchDurabilityFlushed = true
      ∧ input.durableRecordsMatchReplacement = true
      ∧ input.canonicalTransactionBlockRecordWrites = 0 := by
  have preconditions :=
    (accepts_iff_canonical_reorg_persistence_preconditions).mp accepted
  simpa [canonicalReorgPersistencePreconditions, orderedPersistenceChecks,
    allPersistenceChecks] using preconditions

end CanonicalReorgPersistenceAdmission
end Native
end Hegemon
