namespace Hegemon
namespace Native
namespace StorageDurabilityAdmission

inductive StorageDurabilityReject where
  | unsupportedOperation
  | transactionRejected
  | durabilityFlushFailed
deriving DecidableEq, Repr

structure StorageDurabilityInput where
  operationSupported : Bool
  transactionAccepted : Bool
  durabilityFlushed : Bool
deriving DecidableEq, Repr

def evaluateStorageDurabilityRejection
    (input : StorageDurabilityInput) : Option StorageDurabilityReject :=
  if input.operationSupported = false then
    some StorageDurabilityReject.unsupportedOperation
  else if input.transactionAccepted = false then
    some StorageDurabilityReject.transactionRejected
  else if input.durabilityFlushed = false then
    some StorageDurabilityReject.durabilityFlushFailed
  else
    none

def storageDurabilityAccepts (input : StorageDurabilityInput) : Bool :=
  evaluateStorageDurabilityRejection input = none

def storageDurabilityPreconditions (input : StorageDurabilityInput) : Bool :=
  input.operationSupported && input.transactionAccepted && input.durabilityFlushed

theorem accepts_iff_storage_durability_preconditions
    {input : StorageDurabilityInput} :
    storageDurabilityAccepts input = true ↔
      storageDurabilityPreconditions input = true := by
  cases input with
  | mk operationSupported transactionAccepted durabilityFlushed =>
      cases operationSupported <;>
      cases transactionAccepted <;>
        cases durabilityFlushed <;>
        simp [
          storageDurabilityAccepts,
          storageDurabilityPreconditions,
          evaluateStorageDurabilityRejection
        ]

theorem unsupported_operation_precedes_transaction_rejection :
    evaluateStorageDurabilityRejection
      {
        operationSupported := false,
        transactionAccepted := false,
        durabilityFlushed := false
      } =
      some StorageDurabilityReject.unsupportedOperation := by
  rfl

theorem transaction_rejection_precedes_durability_flush :
    evaluateStorageDurabilityRejection
      {
        operationSupported := true,
        transactionAccepted := false,
        durabilityFlushed := false
      } =
      some StorageDurabilityReject.transactionRejected := by
  rfl

theorem durability_flush_failure_rejects :
    evaluateStorageDurabilityRejection
      {
        operationSupported := true,
        transactionAccepted := true,
        durabilityFlushed := false
      } =
      some StorageDurabilityReject.durabilityFlushFailed := by
  rfl

def valid : StorageDurabilityInput :=
  {
    operationSupported := true,
    transactionAccepted := true,
    durabilityFlushed := true
  }

theorem valid_accepts :
    evaluateStorageDurabilityRejection valid = none := by
  rfl

end StorageDurabilityAdmission
end Native
end Hegemon
