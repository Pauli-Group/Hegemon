namespace Hegemon
namespace Release
namespace PqBinaryPolicy

inductive PqBinaryReject where
  | sourceForbidden
  | dependencyForbidden
  | binaryForbidden
deriving DecidableEq, Repr

structure PqBinaryAuditInput where
  sourceScanClean : Bool
  dependencyScanClean : Bool
  binaryScanClean : Bool
deriving DecidableEq, Repr

def evaluatePqBinaryAudit
    (input : PqBinaryAuditInput) : Except PqBinaryReject Unit :=
  if input.sourceScanClean = false then
    Except.error PqBinaryReject.sourceForbidden
  else if input.dependencyScanClean = false then
    Except.error PqBinaryReject.dependencyForbidden
  else if input.binaryScanClean = false then
    Except.error PqBinaryReject.binaryForbidden
  else
    Except.ok ()

def pqBinaryAuditAccepts (input : PqBinaryAuditInput) : Bool :=
  match evaluatePqBinaryAudit input with
  | Except.ok _ => true
  | Except.error _ => false

def pqBinaryAuditRejection (input : PqBinaryAuditInput) : Option PqBinaryReject :=
  match evaluatePqBinaryAudit input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def pqBinaryAllScansClean (input : PqBinaryAuditInput) : Bool :=
  input.sourceScanClean && input.dependencyScanClean && input.binaryScanClean

theorem accepts_iff_all_scans_clean (input : PqBinaryAuditInput) :
    pqBinaryAuditAccepts input = pqBinaryAllScansClean input := by
  cases input with
  | mk sourceScanClean dependencyScanClean binaryScanClean =>
      unfold pqBinaryAuditAccepts pqBinaryAllScansClean evaluatePqBinaryAudit
      cases sourceScanClean <;> cases dependencyScanClean <;> cases binaryScanClean <;> rfl

def allScansClean : PqBinaryAuditInput :=
  {
    sourceScanClean := true,
    dependencyScanClean := true,
    binaryScanClean := true
  }

def sourceForbidden : PqBinaryAuditInput :=
  {
    sourceScanClean := false,
    dependencyScanClean := true,
    binaryScanClean := true
  }

def dependencyForbidden : PqBinaryAuditInput :=
  {
    sourceScanClean := true,
    dependencyScanClean := false,
    binaryScanClean := true
  }

def binaryForbidden : PqBinaryAuditInput :=
  {
    sourceScanClean := true,
    dependencyScanClean := true,
    binaryScanClean := false
  }

theorem all_scans_clean_accepts :
    evaluatePqBinaryAudit allScansClean = Except.ok () := by
  rfl

theorem source_forbidden_rejects
    {input : PqBinaryAuditInput}
    (source : input.sourceScanClean = false) :
    evaluatePqBinaryAudit input =
      Except.error PqBinaryReject.sourceForbidden := by
  unfold evaluatePqBinaryAudit
  simp [source]

theorem dependency_forbidden_rejects_after_source_clean
    {input : PqBinaryAuditInput}
    (source : input.sourceScanClean = true)
    (dependency : input.dependencyScanClean = false) :
    evaluatePqBinaryAudit input =
      Except.error PqBinaryReject.dependencyForbidden := by
  unfold evaluatePqBinaryAudit
  simp [source, dependency]

theorem binary_forbidden_rejects_after_source_dependency_clean
    {input : PqBinaryAuditInput}
    (source : input.sourceScanClean = true)
    (dependency : input.dependencyScanClean = true)
    (binary : input.binaryScanClean = false) :
    evaluatePqBinaryAudit input =
      Except.error PqBinaryReject.binaryForbidden := by
  unfold evaluatePqBinaryAudit
  simp [source, dependency, binary]

theorem source_rejection_precedes_dependency_and_binary :
    evaluatePqBinaryAudit {
      sourceScanClean := false,
      dependencyScanClean := false,
      binaryScanClean := false
    } = Except.error PqBinaryReject.sourceForbidden := by
  rfl

end PqBinaryPolicy
end Release
end Hegemon
