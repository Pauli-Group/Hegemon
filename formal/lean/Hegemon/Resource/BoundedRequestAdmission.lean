namespace Hegemon
namespace Resource
namespace BoundedRequestAdmission

inductive ResourceReject where
  | rawBytesExceeded
  | decodedBytesExceeded
  | itemCountExceeded
  | itemBytesExceeded
  | aggregateBytesExceeded
  | workUnitsExceeded
deriving DecidableEq, Repr

structure ResourcePolicy where
  rawByteCap : Nat
  decodedByteCap : Nat
  itemCountCap : Nat
  itemByteCap : Nat
  aggregateByteCap : Nat
  workUnitCap : Nat
deriving DecidableEq, Repr

structure ResourceRequest where
  rawBytes : Nat
  decodedBytes : Nat
  itemCount : Nat
  maxItemBytes : Nat
  aggregateBytes : Nat
  workUnits : Nat
deriving DecidableEq, Repr

def resourcePreconditions
    (policy : ResourcePolicy) (request : ResourceRequest) : Prop :=
  ¬ policy.rawByteCap < request.rawBytes
    ∧ ¬ policy.decodedByteCap < request.decodedBytes
    ∧ ¬ policy.itemCountCap < request.itemCount
    ∧ ¬ policy.itemByteCap < request.maxItemBytes
    ∧ ¬ policy.aggregateByteCap < request.aggregateBytes
    ∧ ¬ policy.workUnitCap < request.workUnits

def evaluateBoundedRequest
    (policy : ResourcePolicy) (request : ResourceRequest) :
    Option ResourceReject :=
  if policy.rawByteCap < request.rawBytes then
    some ResourceReject.rawBytesExceeded
  else if policy.decodedByteCap < request.decodedBytes then
    some ResourceReject.decodedBytesExceeded
  else if policy.itemCountCap < request.itemCount then
    some ResourceReject.itemCountExceeded
  else if policy.itemByteCap < request.maxItemBytes then
    some ResourceReject.itemBytesExceeded
  else if policy.aggregateByteCap < request.aggregateBytes then
    some ResourceReject.aggregateBytesExceeded
  else if policy.workUnitCap < request.workUnits then
    some ResourceReject.workUnitsExceeded
  else
    none

def boundedRequestAccepts
    (policy : ResourcePolicy) (request : ResourceRequest) : Bool :=
  evaluateBoundedRequest policy request = none

structure AcceptedBoundedRequestFacts
    (policy : ResourcePolicy) (request : ResourceRequest) : Prop where
  accepted :
    evaluateBoundedRequest policy request = none
  rawBytesWithinCap :
    ¬ policy.rawByteCap < request.rawBytes
  decodedBytesWithinCap :
    ¬ policy.decodedByteCap < request.decodedBytes
  itemCountWithinCap :
    ¬ policy.itemCountCap < request.itemCount
  itemBytesWithinCap :
    ¬ policy.itemByteCap < request.maxItemBytes
  aggregateBytesWithinCap :
    ¬ policy.aggregateByteCap < request.aggregateBytes
  workUnitsWithinCap :
    ¬ policy.workUnitCap < request.workUnits

theorem accepts_iff_resource_preconditions
    {policy : ResourcePolicy} {request : ResourceRequest} :
    boundedRequestAccepts policy request = true ↔
      resourcePreconditions policy request := by
  unfold boundedRequestAccepts evaluateBoundedRequest
    resourcePreconditions
  by_cases rawOver : policy.rawByteCap < request.rawBytes
  · simp [rawOver]
  · by_cases decodedOver : policy.decodedByteCap < request.decodedBytes
    · simp [rawOver, decodedOver]
    · by_cases countOver : policy.itemCountCap < request.itemCount
      · simp [rawOver, decodedOver, countOver]
      · by_cases itemOver : policy.itemByteCap < request.maxItemBytes
        · simp [rawOver, decodedOver, countOver, itemOver]
        · by_cases aggregateOver :
            policy.aggregateByteCap < request.aggregateBytes
          · simp [rawOver, decodedOver, countOver, itemOver,
              aggregateOver]
          · by_cases workOver : policy.workUnitCap < request.workUnits
            · simp [rawOver, decodedOver, countOver, itemOver,
                aggregateOver, workOver]
            · simp [rawOver, decodedOver, countOver, itemOver,
                aggregateOver, workOver]

theorem complete_bounded_request_accepts
    {policy : ResourcePolicy} {request : ResourceRequest}
    (preconditions : resourcePreconditions policy request) :
    evaluateBoundedRequest policy request = none := by
  have accepts :
      boundedRequestAccepts policy request = true :=
    accepts_iff_resource_preconditions.mpr preconditions
  simpa [boundedRequestAccepts] using accepts

theorem accepted_bounded_request_exposes_all_caps
    {policy : ResourcePolicy} {request : ResourceRequest}
    (accepted : evaluateBoundedRequest policy request = none) :
    AcceptedBoundedRequestFacts policy request := by
  have accepts :
      boundedRequestAccepts policy request = true := by
    simp [boundedRequestAccepts, accepted]
  have preconditions :
      resourcePreconditions policy request :=
    accepts_iff_resource_preconditions.mp accepts
  exact {
    accepted := accepted,
    rawBytesWithinCap := preconditions.1,
    decodedBytesWithinCap := preconditions.2.1,
    itemCountWithinCap := preconditions.2.2.1,
    itemBytesWithinCap := preconditions.2.2.2.1,
    aggregateBytesWithinCap := preconditions.2.2.2.2.1,
    workUnitsWithinCap := preconditions.2.2.2.2.2
  }

theorem raw_bytes_over_cap_rejects
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOver : policy.rawByteCap < request.rawBytes) :
    evaluateBoundedRequest policy request =
      some ResourceReject.rawBytesExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOver]

theorem decoded_bytes_over_cap_rejects_after_raw_ok
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOk : ¬ policy.rawByteCap < request.rawBytes)
    (decodedOver : policy.decodedByteCap < request.decodedBytes) :
    evaluateBoundedRequest policy request =
      some ResourceReject.decodedBytesExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOk, decodedOver]

theorem item_count_over_cap_rejects_after_byte_ok
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOk : ¬ policy.rawByteCap < request.rawBytes)
    (decodedOk : ¬ policy.decodedByteCap < request.decodedBytes)
    (countOver : policy.itemCountCap < request.itemCount) :
    evaluateBoundedRequest policy request =
      some ResourceReject.itemCountExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOk, decodedOk, countOver]

theorem item_bytes_over_cap_rejects_after_count_ok
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOk : ¬ policy.rawByteCap < request.rawBytes)
    (decodedOk : ¬ policy.decodedByteCap < request.decodedBytes)
    (countOk : ¬ policy.itemCountCap < request.itemCount)
    (itemOver : policy.itemByteCap < request.maxItemBytes) :
    evaluateBoundedRequest policy request =
      some ResourceReject.itemBytesExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOk, decodedOk, countOk, itemOver]

theorem aggregate_bytes_over_cap_rejects_after_item_ok
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOk : ¬ policy.rawByteCap < request.rawBytes)
    (decodedOk : ¬ policy.decodedByteCap < request.decodedBytes)
    (countOk : ¬ policy.itemCountCap < request.itemCount)
    (itemOk : ¬ policy.itemByteCap < request.maxItemBytes)
    (aggregateOver : policy.aggregateByteCap < request.aggregateBytes) :
    evaluateBoundedRequest policy request =
      some ResourceReject.aggregateBytesExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOk, decodedOk, countOk, itemOk, aggregateOver]

theorem work_units_over_cap_rejects_after_aggregate_ok
    {policy : ResourcePolicy} {request : ResourceRequest}
    (rawOk : ¬ policy.rawByteCap < request.rawBytes)
    (decodedOk : ¬ policy.decodedByteCap < request.decodedBytes)
    (countOk : ¬ policy.itemCountCap < request.itemCount)
    (itemOk : ¬ policy.itemByteCap < request.maxItemBytes)
    (aggregateOk : ¬ policy.aggregateByteCap < request.aggregateBytes)
    (workOver : policy.workUnitCap < request.workUnits) :
    evaluateBoundedRequest policy request =
      some ResourceReject.workUnitsExceeded := by
  unfold evaluateBoundedRequest
  simp [rawOk, decodedOk, countOk, itemOk, aggregateOk, workOver]

theorem rejected_bounded_request_not_accepted
    {policy : ResourcePolicy} {request : ResourceRequest}
    {reject : ResourceReject}
    (rejected : evaluateBoundedRequest policy request = some reject) :
    boundedRequestAccepts policy request = false := by
  unfold boundedRequestAccepts
  simp [rejected]

def examplePolicy : ResourcePolicy :=
  {
    rawByteCap := 4096,
    decodedByteCap := 2048,
    itemCountCap := 32,
    itemByteCap := 512,
    aggregateByteCap := 8192,
    workUnitCap := 1000
  }

def exactLimitRequest : ResourceRequest :=
  {
    rawBytes := 4096,
    decodedBytes := 2048,
    itemCount := 32,
    maxItemBytes := 512,
    aggregateBytes := 8192,
    workUnits := 1000
  }

theorem exact_limit_request_accepts :
    evaluateBoundedRequest examplePolicy exactLimitRequest = none := by
  decide

def rawBytesOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with rawBytes := 4097 }

theorem raw_bytes_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy rawBytesOverLimitRequest =
      some ResourceReject.rawBytesExceeded := by
  decide

def decodedBytesOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with decodedBytes := 2049 }

theorem decoded_bytes_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy decodedBytesOverLimitRequest =
      some ResourceReject.decodedBytesExceeded := by
  decide

def itemCountOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with itemCount := 33 }

theorem item_count_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy itemCountOverLimitRequest =
      some ResourceReject.itemCountExceeded := by
  decide

def itemBytesOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with maxItemBytes := 513 }

theorem item_bytes_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy itemBytesOverLimitRequest =
      some ResourceReject.itemBytesExceeded := by
  decide

def aggregateBytesOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with aggregateBytes := 8193 }

theorem aggregate_bytes_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy aggregateBytesOverLimitRequest =
      some ResourceReject.aggregateBytesExceeded := by
  decide

def workUnitsOverLimitRequest : ResourceRequest :=
  { exactLimitRequest with workUnits := 1001 }

theorem work_units_over_limit_request_rejects :
    evaluateBoundedRequest examplePolicy workUnitsOverLimitRequest =
      some ResourceReject.workUnitsExceeded := by
  decide

end BoundedRequestAdmission
end Resource
end Hegemon
