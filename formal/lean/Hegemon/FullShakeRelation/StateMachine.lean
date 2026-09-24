import Hegemon.FullShakeRelation.Core

namespace Hegemon
namespace FullShakeRelation

inductive NoteKind where
  | ordinary
  | accumulator
  | valueLock
deriving DecidableEq, Repr

inductive AuthMode where
  | singleKey
  | accumulatorInit
  | approvalStep
  | valueLockCreation
  | finalThresholdSpend
deriving DecidableEq, Repr

structure NoteSlot where
  active : Bool
  kind : NoteKind
  value : Nat
  assetId : Nat
deriving DecidableEq, Repr

def inactiveNote : NoteSlot :=
  { active := false, kind := .ordinary, value := 0, assetId := 0 }

def activeKind (note : NoteSlot) (kind : NoteKind) : Bool :=
  !note.active || note.kind == kind

def activeKinds (notes : Slot2 NoteSlot) (kind : NoteKind) : Bool :=
  activeKind notes.first kind && activeKind notes.second kind

def optionalSecondOrdinary (notes : Slot2 NoteSlot) : Bool :=
  activeKind notes.second .ordinary

def zeroNativeAccumulator (note : NoteSlot) : Bool :=
  note.active
    && note.kind == .accumulator
    && note.value == 0
    && note.assetId == nativeAssetId

structure AccumulatorState where
  policyRoot : Digest
  intentDigest : Digest
  threshold : Nat
  signerCount : Nat
  approvalCount : Nat
  approvedSlots : List Bool
deriving DecidableEq, Repr

def zeroAccumulator : AccumulatorState :=
  { policyRoot := 0,
    intentDigest := 0,
    threshold := 0,
    signerCount := 0,
    approvalCount := 0,
    approvedSlots := [false, false, false, false, false, false] }

def approvedCount (state : AccumulatorState) : Nat :=
  state.approvedSlots.count true

def accumulatorWellFormed (state : AccumulatorState) : Bool :=
  state.approvedSlots.length == maxSigners
    && state.policyRoot != 0
    && state.intentDigest != 0
    && 1 <= state.signerCount
    && state.signerCount <= maxSigners
    && 1 <= state.threshold
    && state.threshold <= state.signerCount
    && state.approvalCount <= state.signerCount
    && state.approvalCount == approvedCount state

def sameLineage (current next : AccumulatorState) : Bool :=
  current.policyRoot == next.policyRoot
    && current.intentDigest == next.intentDigest
    && current.threshold == next.threshold
    && current.signerCount == next.signerCount

def allZeroDigests (digests : List Digest) : Bool :=
  digests.length == maxSigners && digests.all (fun digest => digest == 0)

def orderedSignerPolicyAccepted
    (state : AccumulatorState)
    (signerTags : List Digest)
    (policyRootHashMatches : Bool) : Bool :=
  signerTags.length == maxSigners
    && (signerTags.take state.signerCount).all (fun digest => digest != 0)
    && decide (signerTags.take state.signerCount).Nodup
    && (signerTags.drop state.signerCount).all (fun digest => digest == 0)
    && policyRootHashMatches

def setApprovedAt : Nat -> List Bool -> List Bool
  | _, [] => []
  | 0, _ :: rest => true :: rest
  | index + 1, head :: rest => head :: setApprovedAt index rest

structure AuthSurface where
  mode : AuthMode
  inputs : Slot2 NoteSlot
  outputs : Slot2 NoteSlot
  current : AccumulatorState
  next : AccumulatorState
  signerTags : List Digest
  derivedSignerTag : Digest
  chosenSignerSlot : Nat
  policyRootHashMatches : Bool
  statementIntent : Digest
deriving DecidableEq, Repr

def approvalTransitionAccepted (surface : AuthSurface) : Bool :=
  surface.chosenSignerSlot < surface.current.signerCount
    && surface.signerTags[surface.chosenSignerSlot]? == some surface.derivedSignerTag
    && surface.current.approvedSlots[surface.chosenSignerSlot]? == some false
    && surface.next.approvedSlots ==
      setApprovedAt surface.chosenSignerSlot surface.current.approvedSlots

def inputFlags (surface : AuthSurface) : Slot2 Bool :=
  surface.inputs.map NoteSlot.active

def outputFlags (surface : AuthSurface) : Slot2 Bool :=
  surface.outputs.map NoteSlot.active

def authActivity (surface : AuthSurface) : ActivityFlags :=
  { inputs := inputFlags surface, outputs := outputFlags surface }

def zeroApprovals (state : AccumulatorState) : Bool :=
  state.approvalCount == 0 && state.approvedSlots.all (fun bit => !bit)

def authModeAccepted (surface : AuthSurface) : Bool :=
  activityAccepted (authActivity surface)
    && match surface.mode with
      | .singleKey =>
          surface.current == zeroAccumulator
            && surface.next == zeroAccumulator
            && allZeroDigests surface.signerTags
            && activeKinds surface.inputs .ordinary
            && activeKinds surface.outputs .ordinary
      | .accumulatorInit =>
          surface.inputs.anyBy (fun note => note.active)
            && surface.outputs.first.active
            && activeKinds surface.inputs .ordinary
            && zeroNativeAccumulator surface.outputs.first
            && optionalSecondOrdinary surface.outputs
            && surface.current == zeroAccumulator
            && accumulatorWellFormed surface.next
            && zeroApprovals surface.next
            && orderedSignerPolicyAccepted
              surface.next surface.signerTags surface.policyRootHashMatches
      | .approvalStep =>
          surface.inputs.first.active
            && surface.inputs.second.active
            && zeroNativeAccumulator surface.inputs.first
            && surface.inputs.second.kind == .ordinary
            && zeroNativeAccumulator surface.outputs.first
            && optionalSecondOrdinary surface.outputs
            && accumulatorWellFormed surface.current
            && accumulatorWellFormed surface.next
            && sameLineage surface.current surface.next
            && surface.next.approvalCount == surface.current.approvalCount + 1
            && approvalTransitionAccepted surface
            && orderedSignerPolicyAccepted
              surface.current surface.signerTags surface.policyRootHashMatches
      | .valueLockCreation =>
          surface.inputs.anyBy (fun note => note.active)
            && surface.outputs.first.active
            && activeKinds surface.inputs .ordinary
            && surface.outputs.first.kind == .valueLock
            && optionalSecondOrdinary surface.outputs
            && surface.next == zeroAccumulator
            && accumulatorWellFormed surface.current
            && zeroApprovals surface.current
            && orderedSignerPolicyAccepted
              surface.current surface.signerTags surface.policyRootHashMatches
      | .finalThresholdSpend =>
          surface.inputs.first.active
            && surface.inputs.second.active
            && surface.inputs.first.kind == .valueLock
            && zeroNativeAccumulator surface.inputs.second
            && activeKinds surface.outputs .ordinary
            && surface.next == zeroAccumulator
            && accumulatorWellFormed surface.current
            && surface.current.intentDigest == surface.statementIntent
            && surface.current.threshold <= surface.current.approvalCount
            && orderedSignerPolicyAccepted
              surface.current surface.signerTags surface.policyRootHashMatches

theorem accepted_single_key_cannot_create_accumulator
    {surface : AuthSurface}
    (mode : surface.mode = .singleKey)
    (accepted : authModeAccepted surface = true)
    (output0Active : surface.outputs.first.active = true) :
    surface.outputs.first.kind = .ordinary := by
  simp_all [authModeAccepted, activeKinds, activeKind]

theorem accepted_single_key_cannot_create_value_lock
    {surface : AuthSurface}
    (mode : surface.mode = .singleKey)
    (accepted : authModeAccepted surface = true)
    (output0Active : surface.outputs.first.active = true) :
    surface.outputs.first.kind != .valueLock := by
  have ordinary :=
    accepted_single_key_cannot_create_accumulator mode accepted output0Active
  simp [ordinary]

theorem accepted_accumulator_init_has_zero_approvals
    {surface : AuthSurface}
    (mode : surface.mode = .accumulatorInit)
    (accepted : authModeAccepted surface = true) :
    surface.next.approvalCount = 0 := by
  simp_all [authModeAccepted, zeroApprovals]

theorem accepted_approval_preserves_lineage_and_increments_once
    {surface : AuthSurface}
    (mode : surface.mode = .approvalStep)
    (accepted : authModeAccepted surface = true) :
    sameLineage surface.current surface.next = true
      ∧ surface.next.approvalCount = surface.current.approvalCount + 1 := by
  simp_all [authModeAccepted]

theorem accepted_final_spend_reaches_threshold
    {surface : AuthSurface}
    (mode : surface.mode = .finalThresholdSpend)
    (accepted : authModeAccepted surface = true) :
    surface.current.threshold <= surface.current.approvalCount := by
  simp_all [authModeAccepted]

def validAccumulator : AccumulatorState :=
  { policyRoot := 11,
    intentDigest := 12,
    threshold := 1,
    signerCount := 1,
    approvalCount := 0,
    approvedSlots := [false, false, false, false, false, false] }

def ordinaryInput : NoteSlot :=
  { active := true, kind := .ordinary, value := 7, assetId := 0 }

def ordinaryOutput : NoteSlot :=
  { active := true, kind := .ordinary, value := 7, assetId := 0 }

def singleKeyTypedStateForgery : AuthSurface :=
  { mode := .singleKey,
    inputs := { first := ordinaryInput, second := inactiveNote },
    outputs :=
      { first := { ordinaryOutput with kind := .accumulator }, second := inactiveNote },
    current := zeroAccumulator,
    next := zeroAccumulator,
    signerTags := [0, 0, 0, 0, 0, 0],
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := false,
    statementIntent := 0 }

theorem single_key_typed_state_forgery_rejects :
    authModeAccepted singleKeyTypedStateForgery = false := by
  decide

def duplicateApprovalAttempt : AuthSurface :=
  let current : AccumulatorState :=
    { validAccumulator with
      approvalCount := 1,
      approvedSlots := [true, false, false, false, false, false] }
  let next : AccumulatorState := current
  { mode := .approvalStep,
    inputs :=
      { first := { active := true, kind := .accumulator, value := 0, assetId := 0 },
        second := ordinaryInput },
    outputs :=
      { first := { active := true, kind := .accumulator, value := 0, assetId := 0 },
        second := inactiveNote },
    current := current,
    next := next,
    signerTags := [21, 0, 0, 0, 0, 0],
    derivedSignerTag := 21,
    chosenSignerSlot := 0,
    policyRootHashMatches := true,
    statementIntent := 12 }

theorem duplicate_approval_attempt_rejects :
    authModeAccepted duplicateApprovalAttempt = false := by
  decide

def finalWithoutAccumulatorInput : AuthSurface :=
  let approved : AccumulatorState :=
    { validAccumulator with
      approvalCount := 1,
      approvedSlots := [true, false, false, false, false, false] }
  { mode := .finalThresholdSpend,
    inputs :=
      { first := { active := true, kind := .valueLock, value := 7, assetId := 0 },
        second := ordinaryInput },
    outputs := { first := ordinaryOutput, second := inactiveNote },
    current := approved,
    next := zeroAccumulator,
    signerTags := [21, 0, 0, 0, 0, 0],
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := true,
    statementIntent := 12 }

theorem final_without_accumulator_input_rejects :
    authModeAccepted finalWithoutAccumulatorInput = false := by
  decide

end FullShakeRelation
end Hegemon
