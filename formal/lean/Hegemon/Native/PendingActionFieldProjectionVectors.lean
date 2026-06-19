import Hegemon.Native.PendingActionByteReplayRowCountBinding

namespace Hegemon
namespace Native
namespace PendingActionFieldProjectionVectors

structure ProjectionActionSpec where
  fixtureName : String
  commitmentCount : Nat
  nullifierCount : Nat
  ciphertextCount : Nat
  hasBridgeReplay : Bool
deriving DecidableEq, Repr

structure ProjectionRowRef where
  actionIndex : Nat
  offset : Nat
  commitmentIndex : Nat
deriving DecidableEq, Repr

structure ProjectionRows where
  commitmentRows : List ProjectionRowRef
  nullifierRows : List ProjectionRowRef
  bridgeReplayRows : List Nat
  ciphertextIndexRows : List ProjectionRowRef
  ciphertextArchiveRows : List ProjectionRowRef
deriving DecidableEq, Repr

def emptyRows : ProjectionRows :=
  {
    commitmentRows := [],
    nullifierRows := [],
    bridgeReplayRows := [],
    ciphertextIndexRows := [],
    ciphertextArchiveRows := []
  }

def rowRefs (actionIndex start count : Nat) : List ProjectionRowRef :=
  (List.range count).map
    (fun offset =>
      {
        actionIndex := actionIndex,
        offset := offset,
        commitmentIndex := start + offset
      })

def appendRows
    (rows : ProjectionRows)
    (actionIndex start : Nat)
    (action : ProjectionActionSpec) : ProjectionRows :=
  let commitmentRows := rowRefs actionIndex start action.commitmentCount
  let nullifierRows := rowRefs actionIndex 0 action.nullifierCount
  let ciphertextRows := rowRefs actionIndex start action.ciphertextCount
  {
    commitmentRows := rows.commitmentRows ++ commitmentRows,
    nullifierRows := rows.nullifierRows ++ nullifierRows,
    bridgeReplayRows :=
      rows.bridgeReplayRows ++
        (if action.hasBridgeReplay then [actionIndex] else []),
    ciphertextIndexRows := rows.ciphertextIndexRows ++ ciphertextRows,
    ciphertextArchiveRows := rows.ciphertextArchiveRows ++ ciphertextRows
  }

def projectRowsFrom :
    Nat -> Nat -> ProjectionRows -> List ProjectionActionSpec -> ProjectionRows
  | _actionIndex, _start, rows, [] => rows
  | actionIndex, start, rows, action :: rest =>
      projectRowsFrom
        (actionIndex + 1)
        (start + action.commitmentCount)
        (appendRows rows actionIndex start action)
        rest

def projectRows (actions : List ProjectionActionSpec) : ProjectionRows :=
  projectRowsFrom 0 0 emptyRows actions

structure ProjectionCase where
  name : String
  actions : List ProjectionActionSpec
  expectedRows : ProjectionRows
deriving DecidableEq, Repr

def projectionCaseAccepts (case : ProjectionCase) : Bool :=
  decide (case.expectedRows = projectRows case.actions)

theorem generated_projection_case_accepts
    (name : String)
    (actions : List ProjectionActionSpec) :
    projectionCaseAccepts
      {
        name := name,
        actions := actions,
        expectedRows := projectRows actions
      } = true := by
  simp [projectionCaseAccepts]

def sidecarTransferFixture (name : String) : ProjectionActionSpec :=
  {
    fixtureName := name,
    commitmentCount := 1,
    nullifierCount := 1,
    ciphertextCount := 1,
    hasBridgeReplay := false
  }

def outboundBridgeFixture (name : String) : ProjectionActionSpec :=
  {
    fixtureName := name,
    commitmentCount := 0,
    nullifierCount := 0,
    ciphertextCount := 0,
    hasBridgeReplay := false
  }

def inboundBridgeFixture (name : String) : ProjectionActionSpec :=
  {
    fixtureName := name,
    commitmentCount := 0,
    nullifierCount := 0,
    ciphertextCount := 0,
    hasBridgeReplay := true
  }

def candidateArtifactFixture (name : String) : ProjectionActionSpec :=
  {
    fixtureName := name,
    commitmentCount := 0,
    nullifierCount := 0,
    ciphertextCount := 0,
    hasBridgeReplay := false
  }

def sidecarOnlyActions : List ProjectionActionSpec :=
  [sidecarTransferFixture "sidecar-a"]

def mixedCanonicalActions : List ProjectionActionSpec :=
  [
    sidecarTransferFixture "sidecar-a",
    outboundBridgeFixture "outbound-a",
    inboundBridgeFixture "inbound-a",
    candidateArtifactFixture "candidate-a"
  ]

def bridgeFirstActions : List ProjectionActionSpec :=
  [
    inboundBridgeFixture "inbound-a",
    sidecarTransferFixture "sidecar-a"
  ]

def twoSidecarActions : List ProjectionActionSpec :=
  [
    sidecarTransferFixture "sidecar-a",
    sidecarTransferFixture "sidecar-b"
  ]

def projectionCase (name : String) (actions : List ProjectionActionSpec) :
    ProjectionCase :=
  {
    name := name,
    actions := actions,
    expectedRows := projectRows actions
  }

def sidecarOnlyCase : ProjectionCase :=
  projectionCase "sidecar-only" sidecarOnlyActions

def mixedCanonicalCase : ProjectionCase :=
  projectionCase "mixed-canonical-order" mixedCanonicalActions

def bridgeFirstCase : ProjectionCase :=
  projectionCase "bridge-first-order" bridgeFirstActions

def twoSidecarCase : ProjectionCase :=
  projectionCase "two-sidecar-cumulative-indexes" twoSidecarActions

theorem sidecar_only_case_accepts :
    projectionCaseAccepts sidecarOnlyCase = true := by
  rfl

theorem mixed_canonical_case_accepts :
    projectionCaseAccepts mixedCanonicalCase = true := by
  rfl

theorem bridge_first_case_accepts :
    projectionCaseAccepts bridgeFirstCase = true := by
  rfl

theorem two_sidecar_case_accepts :
    projectionCaseAccepts twoSidecarCase = true := by
  rfl

end PendingActionFieldProjectionVectors
end Native
end Hegemon
