namespace Hegemon
namespace Native
namespace StorageDurabilityAdmission

inductive StorageDurabilityReject where
  | transactionRejected
  | durabilityFlushFailed
deriving DecidableEq, Repr

structure StorageDurabilityInput where
  transactionAccepted : Bool
  durabilityFlushed : Bool
deriving DecidableEq, Repr

def evaluateStorageDurabilityRejection
    (input : StorageDurabilityInput) : Option StorageDurabilityReject :=
  if input.transactionAccepted = false then
    some StorageDurabilityReject.transactionRejected
  else if input.durabilityFlushed = false then
    some StorageDurabilityReject.durabilityFlushFailed
  else
    none

def storageDurabilityAccepts (input : StorageDurabilityInput) : Bool :=
  evaluateStorageDurabilityRejection input = none

def storageDurabilityPreconditions (input : StorageDurabilityInput) : Bool :=
  input.transactionAccepted && input.durabilityFlushed

theorem accepts_iff_storage_durability_preconditions
    {input : StorageDurabilityInput} :
    storageDurabilityAccepts input = true ↔
      storageDurabilityPreconditions input = true := by
  cases input with
  | mk transactionAccepted durabilityFlushed =>
      cases transactionAccepted <;>
        cases durabilityFlushed <;>
        simp [
          storageDurabilityAccepts,
          storageDurabilityPreconditions,
          evaluateStorageDurabilityRejection
        ]

theorem transaction_rejection_precedes_durability_flush :
    evaluateStorageDurabilityRejection
      { transactionAccepted := false, durabilityFlushed := false } =
      some StorageDurabilityReject.transactionRejected := by
  rfl

theorem durability_flush_failure_rejects :
    evaluateStorageDurabilityRejection
      { transactionAccepted := true, durabilityFlushed := false } =
      some StorageDurabilityReject.durabilityFlushFailed := by
  rfl

def valid : StorageDurabilityInput :=
  {
    transactionAccepted := true,
    durabilityFlushed := true
  }

theorem valid_accepts :
    evaluateStorageDurabilityRejection valid = none := by
  rfl

end StorageDurabilityAdmission
end Native
end Hegemon
