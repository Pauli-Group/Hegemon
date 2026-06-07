namespace Hegemon
namespace Native
namespace RpcAdmission

def u64Max : Nat := 18446744073709551615

def maxTimestampRows : Nat := 4096

def maxRpcBatchRequests : Nat := 128

inductive RpcPolicy where
  | safeOnly
  | unsafeAllowed
deriving DecidableEq, Repr

inductive RawRpcPolicy where
  | safeToken
  | unsafeToken
  | autoToken
  | emptyToken
  | invalidToken
deriving DecidableEq, Repr

inductive RpcPolicyReject where
  | invalidPolicy
deriving DecidableEq, Repr

def resolveRpcPolicy
    (raw : RawRpcPolicy)
    (rpcExternal : Bool) : Except RpcPolicyReject RpcPolicy :=
  match raw with
  | RawRpcPolicy.safeToken => Except.ok RpcPolicy.safeOnly
  | RawRpcPolicy.unsafeToken => Except.ok RpcPolicy.unsafeAllowed
  | RawRpcPolicy.autoToken =>
      if rpcExternal then
        Except.ok RpcPolicy.safeOnly
      else
        Except.ok RpcPolicy.unsafeAllowed
  | RawRpcPolicy.emptyToken =>
      if rpcExternal then
        Except.ok RpcPolicy.safeOnly
      else
        Except.ok RpcPolicy.unsafeAllowed
  | RawRpcPolicy.invalidToken => Except.error RpcPolicyReject.invalidPolicy

def rpcPolicyAccepts (raw : RawRpcPolicy) (rpcExternal : Bool) : Bool :=
  match resolveRpcPolicy raw rpcExternal with
  | Except.ok _ => true
  | Except.error _ => false

theorem rpc_policy_accepts_valid_tokens
    {raw : RawRpcPolicy}
    {rpcExternal : Bool}
    (valid : raw ≠ RawRpcPolicy.invalidToken) :
    rpcPolicyAccepts raw rpcExternal = true := by
  cases raw <;> cases rpcExternal <;> simp [rpcPolicyAccepts, resolveRpcPolicy] at *

theorem rpc_policy_rejects_invalid
    {rpcExternal : Bool} :
    resolveRpcPolicy RawRpcPolicy.invalidToken rpcExternal =
      Except.error RpcPolicyReject.invalidPolicy := by
  cases rpcExternal <;> rfl

theorem rpc_policy_auto_external_safe :
    resolveRpcPolicy RawRpcPolicy.autoToken true =
      Except.ok RpcPolicy.safeOnly := by
  rfl

theorem rpc_policy_auto_local_unsafe :
    resolveRpcPolicy RawRpcPolicy.autoToken false =
      Except.ok RpcPolicy.unsafeAllowed := by
  rfl

inductive RpcMethod where
  | safeMethod
  | daSubmitCiphertexts
  | daSubmitProofs
  | hegemonStartMining
  | hegemonStopMining
deriving DecidableEq, Repr

inductive RpcMethodReject where
  | unsafeMethodDisabled
deriving DecidableEq, Repr

def rpcMethodIsUnsafe : RpcMethod -> Bool
  | RpcMethod.safeMethod => false
  | RpcMethod.daSubmitCiphertexts => true
  | RpcMethod.daSubmitProofs => true
  | RpcMethod.hegemonStartMining => true
  | RpcMethod.hegemonStopMining => true

def evaluateRpcMethodGate
    (policy : RpcPolicy)
    (method : RpcMethod) : Option RpcMethodReject :=
  if rpcMethodIsUnsafe method && policy != RpcPolicy.unsafeAllowed then
    some RpcMethodReject.unsafeMethodDisabled
  else
    none

def rpcMethodAllowed (policy : RpcPolicy) (method : RpcMethod) : Bool :=
  evaluateRpcMethodGate policy method = none

theorem safe_policy_rejects_unsafe_methods
    {method : RpcMethod}
    (unsafeMethod : rpcMethodIsUnsafe method = true) :
    evaluateRpcMethodGate RpcPolicy.safeOnly method =
      some RpcMethodReject.unsafeMethodDisabled := by
  unfold evaluateRpcMethodGate
  simp [unsafeMethod]

theorem unsafe_policy_allows_every_method
    {method : RpcMethod} :
    evaluateRpcMethodGate RpcPolicy.unsafeAllowed method = none := by
  cases method <;> rfl

theorem safe_policy_allows_safe_methods
    {method : RpcMethod}
    (safeMethod : rpcMethodIsUnsafe method = false) :
    evaluateRpcMethodGate RpcPolicy.safeOnly method = none := by
  unfold evaluateRpcMethodGate
  simp [safeMethod]

def unsafeMethodsVisibleInList (policy : RpcPolicy) : Bool :=
  policy == RpcPolicy.unsafeAllowed

theorem safe_method_list_hides_unsafe_methods :
    unsafeMethodsVisibleInList RpcPolicy.safeOnly = false := by
  rfl

theorem unsafe_method_list_shows_unsafe_methods :
    unsafeMethodsVisibleInList RpcPolicy.unsafeAllowed = true := by
  rfl

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
  native_decide

def overlargeTimestampRange : TimestampRangeInput :=
  {
    startHeight := 0,
    endHeight := maxTimestampRows,
    maxRows := maxTimestampRows
  }

theorem overlarge_timestamp_range_rejects :
    evaluateTimestampRangeRejection overlargeTimestampRange =
      some TimestampRangeReject.rangeTooLarge := by
  native_decide

def invertedTimestampRange : TimestampRangeInput :=
  {
    startHeight := 9,
    endHeight := 8,
    maxRows := maxTimestampRows
  }

theorem inverted_timestamp_range_rejects :
    evaluateTimestampRangeRejection invertedTimestampRange =
      some TimestampRangeReject.endBeforeStart := by
  native_decide

def overflowTimestampRange : TimestampRangeInput :=
  {
    startHeight := 0,
    endHeight := u64Max,
    maxRows := maxTimestampRows
  }

theorem overflow_timestamp_range_rejects :
    evaluateTimestampRangeRejection overflowTimestampRange =
      some TimestampRangeReject.rangeOverflow := by
  native_decide

def validBatch : BatchInput :=
  {
    requestCount := maxRpcBatchRequests,
    maxRequests := maxRpcBatchRequests
  }

theorem valid_batch_accepts :
    evaluateBatchRejection validBatch = none := by
  native_decide

def emptyBatch : BatchInput :=
  {
    requestCount := 0,
    maxRequests := maxRpcBatchRequests
  }

theorem empty_batch_example_rejects :
    evaluateBatchRejection emptyBatch = some BatchReject.emptyBatch := by
  native_decide

def overlargeBatch : BatchInput :=
  {
    requestCount := maxRpcBatchRequests + 1,
    maxRequests := maxRpcBatchRequests
  }

theorem overlarge_batch_example_rejects :
    evaluateBatchRejection overlargeBatch = some BatchReject.batchTooLarge := by
  native_decide

end RpcAdmission
end Native
end Hegemon
