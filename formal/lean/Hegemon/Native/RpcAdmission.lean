namespace Hegemon
namespace Native
namespace RpcAdmission

def u64Max : Nat := 18446744073709551615

def maxTimestampRows : Nat := 4096

def maxRpcBatchRequests : Nat := 128

/-- Policy permission is distinct from registration and source capability.  In
particular an unknown string can pass the historical unsafe/safe classifier
without being registered or callable. -/
inductive RpcPolicy where
  | safeOnly
  | poolOnly
  | unsafeAllowed
  | publicSubmit
deriving DecidableEq, Repr

inductive RawRpcPolicy where
  | safeToken
  | poolToken
  | unsafeToken
  | publicSubmitToken
  | autoToken
  | emptyToken
  | invalidToken
deriving DecidableEq, Repr

inductive RpcPolicyReject where
  | invalidPolicy
  | externalUnsafePolicy
  | externalPoolPolicy
deriving DecidableEq, Repr

def resolveRpcPolicy (raw : RawRpcPolicy) (rpcExternal : Bool) :
    Except RpcPolicyReject RpcPolicy :=
  match raw with
  | .safeToken => .ok .safeOnly
  | .poolToken => if rpcExternal then .error .externalPoolPolicy else .ok .poolOnly
  | .unsafeToken => if rpcExternal then .error .externalUnsafePolicy else .ok .unsafeAllowed
  | .publicSubmitToken => .ok .publicSubmit
  | .autoToken | .emptyToken => .ok .safeOnly
  | .invalidToken => .error .invalidPolicy

def rpcPolicyAccepts (raw : RawRpcPolicy) (rpcExternal : Bool) : Bool :=
  match resolveRpcPolicy raw rpcExternal with
  | .ok _ => true
  | .error _ => false

theorem rpc_policy_accepts_valid_tokens
    {raw : RawRpcPolicy} {rpcExternal : Bool}
    (valid : raw ≠ .invalidToken)
    (notExternalUnsafe : raw = .unsafeToken -> rpcExternal = false)
    (notExternalPool : raw = .poolToken -> rpcExternal = false) :
    rpcPolicyAccepts raw rpcExternal = true := by
  cases raw <;> cases rpcExternal <;> simp [rpcPolicyAccepts, resolveRpcPolicy] at *

theorem rpc_policy_rejects_invalid {rpcExternal : Bool} :
    resolveRpcPolicy .invalidToken rpcExternal = .error .invalidPolicy := by
  rfl

theorem rpc_policy_rejects_external_unsafe :
    resolveRpcPolicy .unsafeToken true = .error .externalUnsafePolicy := by rfl

theorem rpc_policy_rejects_external_pool :
    resolveRpcPolicy .poolToken true = .error .externalPoolPolicy := by rfl

theorem rpc_policy_accepts_external_public_submit :
    resolveRpcPolicy .publicSubmitToken true = .ok .publicSubmit := by rfl

theorem rpc_policy_auto_external_safe :
    resolveRpcPolicy .autoToken true = .ok .safeOnly := by rfl

theorem rpc_policy_auto_local_safe :
    resolveRpcPolicy .autoToken false = .ok .safeOnly := by rfl

theorem rpc_policy_empty_defaults_safe {external : Bool} :
    resolveRpcPolicy .emptyToken external = .ok .safeOnly := by rfl

/-- Representatives of all policy/registration/feature classes.  The generated
vectors bind their concrete method strings to the production classifier.  This
is not a proof that every future dispatch match arm is included in the registry. -/
inductive RpcMethod where
  | safeMethod
  | safeNonPoolMethod
  | daSubmitCiphertexts
  | daSubmitProofs
  | hegemonExportBridgeWitness
  | hegemonPeerGraph
  | hegemonPeerList
  | hegemonStartMining
  | hegemonStopMining
  | hegemonSubmitAction
  | systemPeers
  | poolWork
  | compactJob
  | submitPoolShare
  | submitCompactSolution
  | pendingActionChunk
  | developmentPendingActionChunk
  | assetSnapshot
  | assetRecoverySnapshot
  | disabledProofService
  | unknownMethod
deriving DecidableEq, Repr

inductive RpcMethodReject where
  | unsafeMethodDisabled
deriving DecidableEq, Repr

def rpcMethodIsUnsafeWithFeatures (method : RpcMethod) (featureEnabled : Bool) : Bool :=
  match method with
  | .safeMethod | .safeNonPoolMethod | .pendingActionChunk | .assetSnapshot
  | .assetRecoverySnapshot | .disabledProofService | .unknownMethod => false
  | .developmentPendingActionChunk => featureEnabled
  | _ => true

def rpcMethodIsUnsafe (method : RpcMethod) : Bool :=
  rpcMethodIsUnsafeWithFeatures method false

def rpcMethodIsPool : RpcMethod -> Bool
  | .safeMethod | .poolWork | .compactJob | .submitPoolShare | .submitCompactSolution => true
  | _ => false

def rpcMethodRegistered (method : RpcMethod) (featureEnabled : Bool) : Bool :=
  match method with
  | .unknownMethod => false
  | .developmentPendingActionChunk => featureEnabled
  | _ => true

def rpcMethodAllowedWithFeatures
    (policy : RpcPolicy) (method : RpcMethod) (featureEnabled : Bool) : Bool :=
  match policy with
  | .unsafeAllowed => true
  | .safeOnly => !rpcMethodIsUnsafeWithFeatures method featureEnabled
  | .poolOnly => rpcMethodIsPool method
  | .publicSubmit =>
      !rpcMethodIsUnsafeWithFeatures method featureEnabled || method == .hegemonSubmitAction

def evaluateRpcMethodGate (policy : RpcPolicy) (method : RpcMethod) :
    Option RpcMethodReject :=
  if rpcMethodAllowedWithFeatures policy method false then none else some .unsafeMethodDisabled

def rpcMethodAllowed (policy : RpcPolicy) (method : RpcMethod) : Bool :=
  rpcMethodAllowedWithFeatures policy method false

/-- Availability means the actual source/network/feature capability check passed;
policy permission by itself grants no route authority. -/
def rpcDispatchAllowed (policy : RpcPolicy) (method : RpcMethod)
    (featureEnabled available : Bool) : Bool :=
  rpcMethodRegistered method featureEnabled &&
    rpcMethodAllowedWithFeatures policy method featureEnabled && available

def rpcMethodListed := rpcDispatchAllowed

theorem safe_policy_rejects_unsafe_methods {method : RpcMethod}
    (unsafeMethod : rpcMethodIsUnsafe method = true) :
    evaluateRpcMethodGate .safeOnly method = some .unsafeMethodDisabled := by
  simp [evaluateRpcMethodGate, rpcMethodAllowedWithFeatures, rpcMethodIsUnsafe] at *
  exact unsafeMethod

theorem unsafe_policy_allows_every_method {method : RpcMethod} :
    evaluateRpcMethodGate .unsafeAllowed method = none := by rfl

theorem safe_policy_allows_safe_methods {method : RpcMethod}
    (safeMethod : rpcMethodIsUnsafe method = false) :
    evaluateRpcMethodGate .safeOnly method = none := by
  simp [evaluateRpcMethodGate, rpcMethodAllowedWithFeatures, rpcMethodIsUnsafe] at *
  exact safeMethod

theorem public_submit_adds_exactly_submit_action
    {method : RpcMethod} {featureEnabled : Bool} :
    rpcMethodAllowedWithFeatures .publicSubmit method featureEnabled =
      (rpcMethodAllowedWithFeatures .safeOnly method featureEnabled ||
        method == .hegemonSubmitAction) := by rfl

theorem public_submit_denies_other_privileged_methods
    {method : RpcMethod} {featureEnabled : Bool}
    (privileged : rpcMethodIsUnsafeWithFeatures method featureEnabled = true)
    (notSubmit : method ≠ .hegemonSubmitAction) :
    rpcMethodAllowedWithFeatures .publicSubmit method featureEnabled = false := by
  simp [rpcMethodAllowedWithFeatures, privileged, notSubmit]

theorem discovery_equals_available_dispatch
    {policy : RpcPolicy} {method : RpcMethod} {featureEnabled available : Bool} :
    rpcMethodListed policy method featureEnabled available =
      rpcDispatchAllowed policy method featureEnabled available := by rfl

theorem dispatch_requires_registration_policy_and_capability
    {policy : RpcPolicy} {method : RpcMethod} {featureEnabled available : Bool} :
    rpcDispatchAllowed policy method featureEnabled available = true ↔
      rpcMethodRegistered method featureEnabled = true ∧
      rpcMethodAllowedWithFeatures policy method featureEnabled = true ∧ available = true := by
  simp [rpcDispatchAllowed, Bool.and_eq_true, and_assoc]

theorem unknown_methods_never_dispatch
    {policy : RpcPolicy} {featureEnabled available : Bool} :
    rpcDispatchAllowed policy .unknownMethod featureEnabled available = false := by
  rfl

theorem unavailable_methods_never_dispatch
    {policy : RpcPolicy} {method : RpcMethod} {featureEnabled : Bool} :
    rpcDispatchAllowed policy method featureEnabled false = false := by
  simp [rpcDispatchAllowed]

theorem feature_disabled_route_never_dispatch
    {policy : RpcPolicy} {available : Bool} :
    rpcDispatchAllowed policy .developmentPendingActionChunk false available = false := by
  rfl

theorem public_submit_effective_surface_delta
    {method : RpcMethod} {featureEnabled available : Bool} :
    rpcDispatchAllowed .publicSubmit method featureEnabled available =
      (rpcDispatchAllowed .safeOnly method featureEnabled available ||
       (method == .hegemonSubmitAction && available)) := by
  cases method <;> cases featureEnabled <;> cases available <;> rfl

/-- Historical all-privileged-method visibility projection, not the full catalog. -/
def unsafeMethodsVisibleInList (policy : RpcPolicy) : Bool :=
  policy == .unsafeAllowed

theorem safe_method_list_hides_unsafe_methods :
    unsafeMethodsVisibleInList .safeOnly = false := by rfl

theorem unsafe_method_list_shows_unsafe_methods :
    unsafeMethodsVisibleInList .unsafeAllowed = true := by rfl

/-- This is an explicit family/action gate, not a claim to distinguish hidden
ordinary/HTLC/policy witnesses within the unchanged PrivateSpend statement. -/
def publicSubmitActionRouteAllowed (family action : Nat) : Bool :=
  family == 1 && action == 15

theorem public_action_route_is_exact {family action : Nat} :
    publicSubmitActionRouteAllowed family action = true ↔ family = 1 ∧ action = 15 := by
  simp [publicSubmitActionRouteAllowed]

theorem public_action_route_denies_other_families {family action : Nat}
    (different : family ≠ 1 ∨ action ≠ 15) :
    publicSubmitActionRouteAllowed family action = false := by
  rcases different with h | h <;> simp [publicSubmitActionRouteAllowed, h]

/-- These four arithmetic helpers are called by the production mutex counters and
client map. Rust inputs are bounded machine integers; an admitted increment is
below the representable limit, so checked_add agrees with Nat here. -/
def publicCapacityReserve (active limit : Nat) : Option Nat :=
  if active < limit then some (active + 1) else none

def publicCapacityRelease (active : Nat) : Option Nat :=
  if active = 0 then none else some (active - 1)

def publicClientCharge (used limit : Nat) (expired : Bool) : Option Nat :=
  if limit = 0 then none else if expired then some 1 else publicCapacityReserve used limit

def publicClientTableInsertAllowed (retained capacity : Nat) (known : Bool) : Bool :=
  known || retained < capacity

theorem public_reservation_bounded {active limit next : Nat}
    (accepted : publicCapacityReserve active limit = some next) :
    next = active + 1 ∧ next ≤ limit := by
  unfold publicCapacityReserve at accepted
  split at accepted
  · cases accepted
    omega
  · contradiction

theorem public_capacity_exhaustion_rejects {active limit : Nat}
    (full : limit ≤ active) : publicCapacityReserve active limit = none := by
  simp [publicCapacityReserve, Nat.not_lt.mpr full]

theorem public_release_decreases_once {active next : Nat}
    (released : publicCapacityRelease active = some next) :
    active = next + 1 := by
  unfold publicCapacityRelease at released
  split at released
  · contradiction
  · cases released
    omega

theorem public_release_empty_rejects : publicCapacityRelease 0 = none := by rfl

theorem public_client_charge_bounded {used limit next : Nat} {expired : Bool}
    (accepted : publicClientCharge used limit expired = some next) :
    1 ≤ next ∧ next ≤ limit := by
  unfold publicClientCharge at accepted
  split at accepted
  · contradiction
  · split at accepted
    · cases accepted
      omega
    · obtain ⟨rfl, h⟩ := public_reservation_bounded accepted
      omega

theorem public_client_table_full_unknown_rejects {retained capacity : Nat}
    (full : capacity ≤ retained) :
    publicClientTableInsertAllowed retained capacity false = false := by
  simp [publicClientTableInsertAllowed, Nat.not_lt.mpr full]

theorem public_client_table_insert_bounded {retained capacity : Nat} {known : Bool}
    (bounded : retained ≤ capacity)
    (accepted : publicClientTableInsertAllowed retained capacity known = true) :
    (if known then retained else retained + 1) ≤ capacity := by
  cases known <;> simp [publicClientTableInsertAllowed] at * <;> omega

/-- The implementation uses distinct counter objects for public and local work.
The public transition has no write to the local component. This contract does
not prove OS scheduling fairness or a hard verifier wall-clock deadline. -/
structure LaneCounts where
  publicActive : Nat
  localActive : Nat
deriving DecidableEq, Repr

def reservePublicLane (counts : LaneCounts) (limit : Nat) : Option LaneCounts :=
  (publicCapacityReserve counts.publicActive limit).map fun next =>
    { counts with publicActive := next }

theorem public_reservation_preserves_local_capacity {before after : LaneCounts} {limit : Nat}
    (accepted : reservePublicLane before limit = some after) :
    after.localActive = before.localActive ∧ after.publicActive ≤ limit := by
  unfold reservePublicLane at accepted
  cases result : publicCapacityReserve before.publicActive limit with
  | none => simp [result] at accepted
  | some next =>
    simp [result] at accepted
    cases accepted
    exact ⟨rfl, (public_reservation_bounded result).2⟩

/-- A non-cloneable Rust guard moves from HTTP caller to blocking worker. The
HTTP future does not own that guard after the move. `released` has no live token;
only the current owner may drop. These are ownership contracts, bound by source
ordering, Rust moves/Drop, and cancellation tests, not a model of Tokio scheduling. -/
inductive ReservationOwner where
  | caller
  | worker
  | responseBody
  | released
deriving DecidableEq, Repr

structure OwnedReservation where
  owner : ReservationOwner
  active : Nat
deriving DecidableEq, Repr

def moveReservationToWorker (state : OwnedReservation) : OwnedReservation :=
  if state.owner = .caller then { state with owner := .worker } else state

def moveReservationToResponse (state : OwnedReservation) : OwnedReservation :=
  if state.owner = .worker then { state with owner := .responseBody } else state

def dropReservation (state : OwnedReservation) : OwnedReservation :=
  if state.owner = .released then state
  else { owner := .released, active := state.active - 1 }

def disconnectCaller (state : OwnedReservation) : OwnedReservation :=
  if state.owner = .caller then dropReservation state else state

theorem worker_transfer_preserves_reservation {state : OwnedReservation} :
    (moveReservationToWorker state).active = state.active := by
  simp [moveReservationToWorker]
  split <;> rfl

theorem response_transfer_preserves_reservation {state : OwnedReservation} :
    (moveReservationToResponse state).active = state.active := by
  simp [moveReservationToResponse]
  split <;> rfl

theorem response_disconnect_releases_owned_reservation {active : Nat}
    (nonzero : 0 < active) :
    (dropReservation { owner := .responseBody, active := active }).active + 1 = active := by
  simp [dropReservation]
  omega

theorem worker_disconnect_retains_reservation {active : Nat} :
    disconnectCaller { owner := .worker, active := active } =
      { owner := .worker, active := active } := by rfl

theorem reservation_drop_is_idempotent {state : OwnedReservation} :
    dropReservation (dropReservation state) = dropReservation state := by
  cases state with
  | mk owner active => cases owner <;> simp [dropReservation]

theorem owned_drop_releases_exactly_once {owner : ReservationOwner} {active : Nat}
    (owned : owner ≠ .released) (nonzero : 0 < active) :
    (dropReservation { owner := owner, active := active }).active + 1 = active := by
  simp [dropReservation, owned]
  omega

/-- The application uses non-waiting try-reserve. Tokio may schedule admitted
blocking workers later; those workers still own slots counted against the cap.
This states no zero-queue or scheduler-fairness property about Tokio or the OS. -/
theorem owned_transfers_and_drop_preserve_outstanding_bound
    {state : OwnedReservation} {limit : Nat} (bounded : state.active ≤ limit) :
    (moveReservationToWorker state).active ≤ limit ∧
    (moveReservationToResponse state).active ≤ limit ∧
    (disconnectCaller state).active ≤ limit ∧
    (dropReservation state).active ≤ limit := by
  have dropped : (dropReservation state).active ≤ limit := by
    unfold dropReservation
    split
    · exact bounded
    · simp only
      omega
  refine ⟨?_, ?_, ?_, dropped⟩
  · simpa [worker_transfer_preserves_reservation] using bounded
  · simpa [response_transfer_preserves_reservation] using bounded
  · unfold disconnectCaller
    split
    · exact dropped
    · exact bounded

inductive TimestampRangeReject where
  | endBeforeStart
  | rangeOverflow
  | rangeTooLarge
deriving DecidableEq, Repr

structure TimestampRangeInput where
  startHeight : Nat
  endHeight : Nat
  maxRows : Nat
deriving DecidableEq, Repr

def timestampRangeRequestedRows
    (input : TimestampRangeInput) : Except TimestampRangeReject Nat :=
  if input.endHeight < input.startHeight then
    Except.error TimestampRangeReject.endBeforeStart
  else
    let delta := input.endHeight - input.startHeight
    if u64Max - delta < 1 then
      Except.error TimestampRangeReject.rangeOverflow
    else
      Except.ok (delta + 1)

def evaluateTimestampRangeRejection
    (input : TimestampRangeInput) : Option TimestampRangeReject :=
  match timestampRangeRequestedRows input with
  | Except.error rejection => some rejection
  | Except.ok rows =>
      if input.maxRows < rows then
        some TimestampRangeReject.rangeTooLarge
      else
        none

def timestampRangeAccepts (input : TimestampRangeInput) : Bool :=
  evaluateTimestampRangeRejection input = none

theorem timestamp_range_accepts_iff_requested_within_limit
    {input : TimestampRangeInput} :
    evaluateTimestampRangeRejection input = none ↔
      ∃ rows,
        timestampRangeRequestedRows input = Except.ok rows ∧
          ¬ input.maxRows < rows := by
  unfold evaluateTimestampRangeRejection
  cases requested : timestampRangeRequestedRows input with
  | error rejection =>
      simp
  | ok rows =>
      by_cases over : input.maxRows < rows
      · simp [over]
      · have within : rows <= input.maxRows := Nat.not_lt.mp over
        simp [over, within]

theorem timestamp_range_rejects_end_before_start
    {input : TimestampRangeInput}
    (beforeStart : input.endHeight < input.startHeight) :
    evaluateTimestampRangeRejection input =
      some TimestampRangeReject.endBeforeStart := by
  unfold evaluateTimestampRangeRejection timestampRangeRequestedRows
  simp [beforeStart]

theorem timestamp_range_rejects_overflow
    {input : TimestampRangeInput}
    (notBeforeStart : ¬ input.endHeight < input.startHeight)
    (overflow : u64Max - (input.endHeight - input.startHeight) < 1) :
    evaluateTimestampRangeRejection input =
      some TimestampRangeReject.rangeOverflow := by
  unfold evaluateTimestampRangeRejection timestampRangeRequestedRows
  simp [notBeforeStart, overflow]

theorem timestamp_range_rejects_too_large
    {input : TimestampRangeInput}
    {rows : Nat}
    (requested :
      timestampRangeRequestedRows input = Except.ok rows)
    (tooLarge : input.maxRows < rows) :
    evaluateTimestampRangeRejection input =
      some TimestampRangeReject.rangeTooLarge := by
  unfold evaluateTimestampRangeRejection
  simp [requested, tooLarge]

inductive ByteEncoding where
  | hex
  | base64
deriving DecidableEq, Repr

inductive ByteParseReject where
  | hexTextTooLong
  | base64TextTooLong
  | decodedTooLong
deriving DecidableEq, Repr

structure ByteParseInput where
  encoding : ByteEncoding
  rawTextBytes : Nat
  decodedBytes : Nat
  maxDecodedBytes : Nat
deriving DecidableEq, Repr

def encodedLenLimit (decodedLenLimit : Nat) : Nat :=
  (decodedLenLimit * 4 + 2) / 3 + 4

def hexLenLimit (decodedLenLimit : Nat) : Nat :=
  decodedLenLimit * 2

def rawTextWithinLimit (input : ByteParseInput) : Bool :=
  match input.encoding with
  | ByteEncoding.hex => input.rawTextBytes <= hexLenLimit input.maxDecodedBytes
  | ByteEncoding.base64 =>
      input.rawTextBytes <= encodedLenLimit input.maxDecodedBytes

def evaluateByteParseRejection
    (input : ByteParseInput) : Option ByteParseReject :=
  match input.encoding with
  | ByteEncoding.hex =>
      if hexLenLimit input.maxDecodedBytes < input.rawTextBytes then
        some ByteParseReject.hexTextTooLong
      else if input.maxDecodedBytes < input.decodedBytes then
        some ByteParseReject.decodedTooLong
      else
        none
  | ByteEncoding.base64 =>
      if encodedLenLimit input.maxDecodedBytes < input.rawTextBytes then
        some ByteParseReject.base64TextTooLong
      else if input.maxDecodedBytes < input.decodedBytes then
        some ByteParseReject.decodedTooLong
      else
        none

def byteParseAccepts (input : ByteParseInput) : Bool :=
  evaluateByteParseRejection input = none

theorem hex_byte_parse_accepts_iff_caps_hold
    {rawTextBytes decodedBytes maxDecodedBytes : Nat} :
    byteParseAccepts
      {
        encoding := ByteEncoding.hex,
        rawTextBytes := rawTextBytes,
        decodedBytes := decodedBytes,
        maxDecodedBytes := maxDecodedBytes
      } = true ↔
      ¬ hexLenLimit maxDecodedBytes < rawTextBytes ∧
        ¬ maxDecodedBytes < decodedBytes := by
  unfold byteParseAccepts evaluateByteParseRejection
  by_cases rawOver : hexLenLimit maxDecodedBytes < rawTextBytes <;>
    by_cases decodedOver : maxDecodedBytes < decodedBytes <;>
    simp [rawOver, decodedOver]

theorem base64_byte_parse_accepts_iff_caps_hold
    {rawTextBytes decodedBytes maxDecodedBytes : Nat} :
    byteParseAccepts
      {
        encoding := ByteEncoding.base64,
        rawTextBytes := rawTextBytes,
        decodedBytes := decodedBytes,
        maxDecodedBytes := maxDecodedBytes
      } = true ↔
      ¬ encodedLenLimit maxDecodedBytes < rawTextBytes ∧
        ¬ maxDecodedBytes < decodedBytes := by
  unfold byteParseAccepts evaluateByteParseRejection
  by_cases rawOver : encodedLenLimit maxDecodedBytes < rawTextBytes <;>
    by_cases decodedOver : maxDecodedBytes < decodedBytes <;>
    simp [rawOver, decodedOver]

theorem byte_parse_rejects_hex_text_over_limit
    {input : ByteParseInput}
    (isHex : input.encoding = ByteEncoding.hex)
    (rawOver : hexLenLimit input.maxDecodedBytes < input.rawTextBytes) :
    evaluateByteParseRejection input =
      some ByteParseReject.hexTextTooLong := by
  cases input with
  | mk encoding rawTextBytes decodedBytes maxDecodedBytes =>
      cases encoding
      · unfold evaluateByteParseRejection
        simp [rawOver]
      · cases isHex

theorem byte_parse_rejects_base64_text_over_limit
    {input : ByteParseInput}
    (isBase64 : input.encoding = ByteEncoding.base64)
    (rawOver : encodedLenLimit input.maxDecodedBytes < input.rawTextBytes) :
    evaluateByteParseRejection input =
      some ByteParseReject.base64TextTooLong := by
  cases input with
  | mk encoding rawTextBytes decodedBytes maxDecodedBytes =>
      cases encoding
      · cases isBase64
      · unfold evaluateByteParseRejection
        simp [rawOver]

theorem byte_parse_rejects_decoded_over_limit
    {input : ByteParseInput}
    (rawOk : rawTextWithinLimit input = true)
    (decodedOver : input.maxDecodedBytes < input.decodedBytes) :
    evaluateByteParseRejection input =
      some ByteParseReject.decodedTooLong := by
  cases input with
  | mk encoding rawTextBytes decodedBytes maxDecodedBytes =>
      cases encoding <;>
        unfold evaluateByteParseRejection rawTextWithinLimit at * <;>
        simp at rawOk <;>
        have rawNotOver := Nat.not_lt.mpr rawOk <;>
        simp [rawNotOver, decodedOver]

inductive BatchReject where
  | emptyBatch
  | batchTooLarge
deriving DecidableEq, Repr

structure BatchInput where
  requestCount : Nat
  maxRequests : Nat
deriving DecidableEq, Repr

def evaluateBatchRejection (input : BatchInput) : Option BatchReject :=
  if input.requestCount = 0 then
    some BatchReject.emptyBatch
  else if input.maxRequests < input.requestCount then
    some BatchReject.batchTooLarge
  else
    none

def batchAccepts (input : BatchInput) : Bool :=
  evaluateBatchRejection input = none

theorem batch_accepts_iff_nonempty_within_limit
    {input : BatchInput} :
    batchAccepts input = true ↔
      input.requestCount ≠ 0 ∧ ¬ input.maxRequests < input.requestCount := by
  unfold batchAccepts evaluateBatchRejection
  by_cases empty : input.requestCount = 0 <;>
    by_cases tooLarge : input.maxRequests < input.requestCount <;>
    simp [empty, tooLarge]

theorem empty_batch_rejects
    {input : BatchInput}
    (empty : input.requestCount = 0) :
    evaluateBatchRejection input = some BatchReject.emptyBatch := by
  unfold evaluateBatchRejection
  simp [empty]

theorem overlarge_batch_rejects
    {input : BatchInput}
    (nonempty : input.requestCount ≠ 0)
    (tooLarge : input.maxRequests < input.requestCount) :
    evaluateBatchRejection input = some BatchReject.batchTooLarge := by
  unfold evaluateBatchRejection
  simp [nonempty, tooLarge]

def validTimestampRange : TimestampRangeInput :=
  {
    startHeight := 0,
    endHeight := maxTimestampRows - 1,
    maxRows := maxTimestampRows
  }

theorem valid_timestamp_range_accepts :
    evaluateTimestampRangeRejection validTimestampRange = none := by
  decide

def overlargeTimestampRange : TimestampRangeInput :=
  {
    startHeight := 0,
    endHeight := maxTimestampRows,
    maxRows := maxTimestampRows
  }

theorem overlarge_timestamp_range_rejects :
    evaluateTimestampRangeRejection overlargeTimestampRange =
      some TimestampRangeReject.rangeTooLarge := by
  decide

def invertedTimestampRange : TimestampRangeInput :=
  {
    startHeight := 9,
    endHeight := 8,
    maxRows := maxTimestampRows
  }

theorem inverted_timestamp_range_rejects :
    evaluateTimestampRangeRejection invertedTimestampRange =
      some TimestampRangeReject.endBeforeStart := by
  decide

def overflowTimestampRange : TimestampRangeInput :=
  {
    startHeight := 0,
    endHeight := u64Max,
    maxRows := maxTimestampRows
  }

theorem overflow_timestamp_range_rejects :
    evaluateTimestampRangeRejection overflowTimestampRange =
      some TimestampRangeReject.rangeOverflow := by
  decide

def validBatch : BatchInput :=
  {
    requestCount := maxRpcBatchRequests,
    maxRequests := maxRpcBatchRequests
  }

theorem valid_batch_accepts :
    evaluateBatchRejection validBatch = none := by
  decide

def emptyBatch : BatchInput :=
  {
    requestCount := 0,
    maxRequests := maxRpcBatchRequests
  }

theorem empty_batch_example_rejects :
    evaluateBatchRejection emptyBatch = some BatchReject.emptyBatch := by
  decide

def overlargeBatch : BatchInput :=
  {
    requestCount := maxRpcBatchRequests + 1,
    maxRequests := maxRpcBatchRequests
  }

theorem overlarge_batch_example_rejects :
    evaluateBatchRejection overlargeBatch = some BatchReject.batchTooLarge := by
  decide

end RpcAdmission
end Native
end Hegemon
