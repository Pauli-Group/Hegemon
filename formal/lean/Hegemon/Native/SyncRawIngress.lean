import Hegemon.Bytes
import Hegemon.Native.SyncAdmission
import Hegemon.Native.SyncResponseImport

namespace Hegemon
namespace Native
namespace SyncRawIngress

open Hegemon
open Hegemon.Native.SyncAdmission
open Hegemon.Native.SyncResponseImport

inductive SyncRawIngressKind where
  | request
  | response
  | pendingAction
  | decodeError
deriving DecidableEq, Repr

inductive SyncRawIngressReject where
  | wireDecodeRejected
  | responseBlockCountTooLarge
  | pendingActionDecodeRejected
deriving DecidableEq, Repr

structure SyncRawIngressCase where
  rawBytes : List Byte
  kind : SyncRawIngressKind
  fromHeight : Nat
  toHeight : Nat
  requestBestHeight : Nat
  maxBlocks : Nat
  responseBestHeight : Nat
  responseHeights : List Nat
  outcomes : List SyncResponseImportOutcome
  localBestHeight : Nat
  peerBestHeight : Nat
  expectedRange : Option (Nat × Nat)
  expectedSortedHeights : List Nat
  expectedAttemptedBlocks : Nat
  expectedImportedBlocks : Nat
  expectedStoppedOnError : Bool
  expectedRequestMore : Bool
  expectedReject : Option SyncRawIngressReject
deriving DecidableEq, Repr

def networkWireMagic : List Byte :=
  asciiBytes "HNW1"

def syncRequestWire (fromHeight toHeight : Nat) : List Byte :=
  networkWireMagic ++ [1, byte fromHeight, byte toHeight]

def syncEmptyResponseWire (bestHeight : Nat) : List Byte :=
  networkWireMagic ++ [2, byte bestHeight, 0]

def syncPendingActionWire (actionBytes : List Byte) : List Byte :=
  networkWireMagic ++ [3, byte actionBytes.length] ++ actionBytes

def requestRangeInput (case : SyncRawIngressCase) :
    SyncResponseRangeInput :=
  {
    fromHeight := case.fromHeight,
    toHeight := case.toHeight,
    bestHeight := case.requestBestHeight,
    maxBlocks := case.maxBlocks
  }

def responseImportInput (case : SyncRawIngressCase) :
    SyncResponseImportInput :=
  {
    responseHeights := case.responseHeights,
    maxBlocks := case.maxBlocks,
    outcomes := case.outcomes,
    localBestHeight := case.localBestHeight,
    peerBestHeight := case.peerBestHeight
  }

def syncRawIngressCaseMatches (case : SyncRawIngressCase) : Bool :=
  match case.expectedReject, case.kind with
  | some SyncRawIngressReject.wireDecodeRejected, SyncRawIngressKind.decodeError =>
      true
  | some SyncRawIngressReject.responseBlockCountTooLarge, SyncRawIngressKind.response =>
      evaluateSyncResponseImportRejection (responseImportInput case) =
        some SyncResponseImportReject.responseBlockCountTooLarge
  | some SyncRawIngressReject.pendingActionDecodeRejected,
      SyncRawIngressKind.pendingAction =>
      true
  | none, SyncRawIngressKind.request =>
      responseRange (requestRangeInput case) = case.expectedRange
  | none, SyncRawIngressKind.response =>
      evaluateSyncResponseImportRejection (responseImportInput case) = none
        && sortHeights case.responseHeights = case.expectedSortedHeights
        && attemptedUntilStop case.outcomes = case.expectedAttemptedBlocks
        && importedUntilStop case.outcomes = case.expectedImportedBlocks
        && stoppedOnError case.outcomes = case.expectedStoppedOnError
        && shouldRequestMore (responseImportInput case) = case.expectedRequestMore
  | _, _ => false

def validRawRequest : SyncRawIngressCase := {
  rawBytes := syncRequestWire 3 9,
  kind := SyncRawIngressKind.request,
  fromHeight := 3,
  toHeight := 9,
  requestBestHeight := 7,
  maxBlocks := 3,
  responseBestHeight := 0,
  responseHeights := [],
  outcomes := [],
  localBestHeight := 0,
  peerBestHeight := 0,
  expectedRange := some (3, 5),
  expectedSortedHeights := [],
  expectedAttemptedBlocks := 0,
  expectedImportedBlocks := 0,
  expectedStoppedOnError := false,
  expectedRequestMore := false,
  expectedReject := none
}

def trailingRawRequest : SyncRawIngressCase :=
  { validRawRequest with
    rawBytes := syncRequestWire 3 9 ++ [0],
    kind := SyncRawIngressKind.decodeError,
    expectedRange := none,
    expectedReject := some SyncRawIngressReject.wireDecodeRejected }

def missingMarkerRawRequest : SyncRawIngressCase :=
  { validRawRequest with
    rawBytes := [1, 3, 9],
    kind := SyncRawIngressKind.decodeError,
    expectedRange := none,
    expectedReject := some SyncRawIngressReject.wireDecodeRejected }

def unknownVariantRawMessage : SyncRawIngressCase :=
  { validRawRequest with
    rawBytes := networkWireMagic ++ [4],
    kind := SyncRawIngressKind.decodeError,
    expectedRange := none,
    expectedReject := some SyncRawIngressReject.wireDecodeRejected }

def emptyPendingActionRelay : SyncRawIngressCase :=
  { validRawRequest with
    rawBytes := syncPendingActionWire [],
    kind := SyncRawIngressKind.pendingAction,
    expectedRange := none,
    expectedReject := some SyncRawIngressReject.pendingActionDecodeRejected }

def validEmptyRawResponse : SyncRawIngressCase := {
  rawBytes := syncEmptyResponseWire 11,
  kind := SyncRawIngressKind.response,
  fromHeight := 0,
  toHeight := 0,
  requestBestHeight := 0,
  maxBlocks := 512,
  responseBestHeight := 11,
  responseHeights := [],
  outcomes := [],
  localBestHeight := 5,
  peerBestHeight := 11,
  expectedRange := none,
  expectedSortedHeights := [],
  expectedAttemptedBlocks := 0,
  expectedImportedBlocks := 0,
  expectedStoppedOnError := false,
  expectedRequestMore := false,
  expectedReject := none
}

theorem sync_raw_ingress_case_matches_expected
    {case : SyncRawIngressCase} :
    syncRawIngressCaseMatches case = true ↔
      match case.expectedReject, case.kind with
      | some SyncRawIngressReject.wireDecodeRejected,
          SyncRawIngressKind.decodeError => True
      | some SyncRawIngressReject.responseBlockCountTooLarge,
          SyncRawIngressKind.response =>
          evaluateSyncResponseImportRejection (responseImportInput case) =
            some SyncResponseImportReject.responseBlockCountTooLarge
      | some SyncRawIngressReject.pendingActionDecodeRejected,
          SyncRawIngressKind.pendingAction => True
      | none, SyncRawIngressKind.request =>
          responseRange (requestRangeInput case) = case.expectedRange
      | none, SyncRawIngressKind.response =>
          evaluateSyncResponseImportRejection (responseImportInput case) = none
            ∧ sortHeights case.responseHeights = case.expectedSortedHeights
            ∧ attemptedUntilStop case.outcomes = case.expectedAttemptedBlocks
            ∧ importedUntilStop case.outcomes = case.expectedImportedBlocks
            ∧ stoppedOnError case.outcomes = case.expectedStoppedOnError
            ∧ shouldRequestMore (responseImportInput case) =
              case.expectedRequestMore
      | _, _ => False := by
  cases hReject : case.expectedReject with
  | none =>
      cases hKind : case.kind <;>
        simp [syncRawIngressCaseMatches, hReject, hKind, Bool.and_eq_true,
          decide_eq_true_eq, and_assoc]
  | some reject =>
      cases reject <;> cases hKind : case.kind <;>
        simp [syncRawIngressCaseMatches, hReject, hKind]

theorem valid_raw_sync_request_accepts :
    syncRawIngressCaseMatches validRawRequest = true := by
  decide

theorem raw_sync_request_range_caps_to_limit :
    responseRange (requestRangeInput validRawRequest) = some (3, 5) := by
  decide

theorem raw_sync_request_trailing_rejects :
    syncRawIngressCaseMatches trailingRawRequest = true := by
  decide

theorem raw_sync_missing_marker_rejects :
    syncRawIngressCaseMatches missingMarkerRawRequest = true := by
  decide

theorem raw_sync_unknown_variant_rejects :
    syncRawIngressCaseMatches unknownVariantRawMessage = true := by
  decide

theorem raw_sync_empty_pending_action_relay_rejects :
    syncRawIngressCaseMatches emptyPendingActionRelay = true := by
  decide

theorem valid_raw_empty_sync_response_accepts :
    syncRawIngressCaseMatches validEmptyRawResponse = true := by
  decide

theorem raw_empty_sync_response_never_requests_more :
    shouldRequestMore (responseImportInput validEmptyRawResponse) = false := by
  decide

end SyncRawIngress
end Native
end Hegemon
