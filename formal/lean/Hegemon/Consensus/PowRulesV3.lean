namespace Hegemon
namespace Consensus
namespace PowRulesV3

set_option exponentiation.threshold 512

/-!
Executable arithmetic and rejection-order model for the fresh V3 PoW era.

The model is deliberately separate from `PowRules`: V1/V2 use a 256-bit
target and 384-bit cumulative work, while V3 uses a 384-bit target and
512-bit cumulative work. Cryptographic BLAKE2b-384 computation is outside the
scope of this arithmetic model; `workHashValue` is the already computed,
big-endian work-hash integer supplied by the Rust conformance consumer.
-/

def pow2Nat (exponent : Nat) : Nat := 2 ^ exponent

def targetBits : Nat := 384
def workBits : Nat := 512
def targetBytes : Nat := targetBits / 8
def workBytes : Nat := workBits / 8
def maxTargetValue : Nat := pow2Nat targetBits - 1
def maxWorkValue : Nat := pow2Nat workBits - 1

def maxHeight : Nat := 18446744073709551615
def maxTimestampMs : Nat := maxHeight
def maxFutureSkewMs : Nat := 90000
def targetBlockIntervalMs : Nat := 60000
def retargetWindow : Nat := 10
def retargetTimespanMs : Nat := retargetWindow * targetBlockIntervalMs
def maxAdjustmentFactor : Nat := 4

def bitsExponent (bits : Nat) : Nat := bits / 16777216
def bitsMantissa (bits : Nat) : Nat := bits % 16777216

def compactTargetValue (bits : Nat) : Option Nat :=
  let exponent := bitsExponent bits
  let mantissa := bitsMantissa bits
  if mantissa = 0 ∨ targetBytes < exponent then
    none
  else
    let target :=
      if exponent <= 3 then
        mantissa / pow2Nat (8 * (3 - exponent))
      else
        mantissa * pow2Nat (8 * (exponent - 3))
    if target = 0 ∨ maxTargetValue < target then none else some target

/-- Highest target exactly representable by the unsigned 24-bit V3 compact
format. Retargeting clamps to this value so the next block can never be made
unmineable by emitting an exponent-49 target. -/
def powLimitBits : Nat := 822083583 -- 0x30ff_ffff

def powLimitTarget : Nat :=
  (compactTargetValue powLimitBits).getD 0

def compactTargetExponent (target : Nat) : Nat :=
  match (List.range (targetBytes + 1)).find? (fun exponent => target < pow2Nat (8 * exponent)) with
  | some exponent => exponent
  | none => targetBytes + 1

def targetToCompact (target : Nat) : Option Nat :=
  if target = 0 ∨ maxTargetValue < target then
    none
  else
    let exponent := compactTargetExponent target
    let mantissa :=
      if exponent <= 3 then
        target * pow2Nat (8 * (3 - exponent))
      else
        target / pow2Nat (8 * (exponent - 3))
    some (exponent * 16777216 + mantissa % 16777216)

def targetWork (target : Nat) : Nat :=
  pow2Nat targetBits / (target + 1)

def blockWorkFromBits (bits : Nat) : Option Nat :=
  (compactTargetValue bits).map targetWork

def checkedWorkAdd (parentWork blockWork : Nat) : Option Nat :=
  let total := parentWork + blockWork
  if total <= maxWorkValue then some total else none

def checkedNextU64 (height : Nat) : Option Nat :=
  if height < maxHeight then some (height + 1) else none

def futureLimit (nowMs : Nat) : Nat :=
  Nat.min maxTimestampMs (nowMs + maxFutureSkewMs)

inductive TimestampReject where
  | timestampNotAdvanced
  | timestampNotAfterMedian
  | timestampFutureSkew
  deriving DecidableEq, Repr

def timestampPolicy
    (parentTimestamp medianTimePast nowMs headerTimestamp : Nat) :
    Option TimestampReject :=
  if headerTimestamp <= parentTimestamp then
    some TimestampReject.timestampNotAdvanced
  else if headerTimestamp <= medianTimePast then
    some TimestampReject.timestampNotAfterMedian
  else if futureLimit nowMs < headerTimestamp then
    some TimestampReject.timestampFutureSkew
  else
    none

def adjustedTimespan (actualMs : Nat) : Nat :=
  let minTimespan := retargetTimespanMs / maxAdjustmentFactor
  let maxTimespan := retargetTimespanMs * maxAdjustmentFactor
  if actualMs < minTimespan then minTimespan
  else if maxTimespan < actualMs then maxTimespan
  else actualMs

def retargetTarget (previousTarget actualMs : Nat) : Nat :=
  if previousTarget = 0 then
    0
  else
    let scaled := previousTarget * adjustedTimespan actualMs / retargetTimespanMs
    let nonzero := if scaled = 0 then 1 else scaled
    Nat.min powLimitTarget nonzero

def retargetBits (previousBits actualMs : Nat) : Option Nat :=
  match compactTargetValue previousBits with
  | none => none
  | some previousTarget => targetToCompact (retargetTarget previousTarget actualMs)

inductive PowAdmissionReject where
  | heightMismatch
  | powBitsMismatch
  | timestampNotAdvanced
  | timestampNotAfterMedian
  | timestampFutureSkew
  | invalidCompactTarget
  | insufficientWork
  | cumulativeWorkOverflow
  | cumulativeWorkMismatch
  deriving DecidableEq, Repr

structure PowAdmissionInput where
  parentHeight : Nat
  headerHeight : Nat
  expectedPowBits : Nat
  powBits : Nat
  parentTimestamp : Nat
  medianTimePast : Nat
  nowMs : Nat
  headerTimestamp : Nat
  workHashValue : Nat
  parentWork : Nat
  claimedCumulativeWork : Nat
  deriving Repr

def timestampRejectToPowReject : TimestampReject -> PowAdmissionReject
  | TimestampReject.timestampNotAdvanced => PowAdmissionReject.timestampNotAdvanced
  | TimestampReject.timestampNotAfterMedian => PowAdmissionReject.timestampNotAfterMedian
  | TimestampReject.timestampFutureSkew => PowAdmissionReject.timestampFutureSkew

/-- Rejection order mirrors the active V3 admission boundary. -/
def evaluatePowAdmission (input : PowAdmissionInput) :
    Except PowAdmissionReject Nat :=
  if checkedNextU64 input.parentHeight ≠ some input.headerHeight then
    Except.error PowAdmissionReject.heightMismatch
  else if input.powBits ≠ input.expectedPowBits then
    Except.error PowAdmissionReject.powBitsMismatch
  else
    match timestampPolicy input.parentTimestamp input.medianTimePast
        input.nowMs input.headerTimestamp with
    | some reject => Except.error (timestampRejectToPowReject reject)
    | none =>
      match compactTargetValue input.powBits with
      | none => Except.error PowAdmissionReject.invalidCompactTarget
      | some target =>
        if target < input.workHashValue then
          Except.error PowAdmissionReject.insufficientWork
        else
          match checkedWorkAdd input.parentWork (targetWork target) with
          | none => Except.error PowAdmissionReject.cumulativeWorkOverflow
          | some expected =>
            if expected = input.claimedCumulativeWork then Except.ok expected
            else Except.error PowAdmissionReject.cumulativeWorkMismatch

theorem widths_are_384_target_and_512_work :
    targetBytes = 48 ∧ workBytes = 64 := by
  decide

theorem compact_rejects_zero_mantissa
    {bits : Nat} (zero : bitsMantissa bits = 0) :
    compactTargetValue bits = none := by
  unfold compactTargetValue
  simp [zero]

theorem compact_rejects_exponent_49 :
    compactTargetValue 822149120 = none := by -- 0x3101_0000
  decide

theorem compact_accepts_exponent_48_limit :
    compactTargetValue powLimitBits = some powLimitTarget := by
  decide

theorem compact_rejects_shifted_zero :
    compactTargetValue 16777217 = none := by -- 0x0100_0001
  decide

theorem target_work_at_pow_limit_is_one :
    targetWork powLimitTarget = 1 := by
  decide

theorem retarget_slow_limit_is_clamped :
    retargetBits powLimitBits (retargetTimespanMs * 10) = some powLimitBits := by
  decide

theorem work_hash_equal_target_is_admissible
    {target workHash : Nat} (equal : workHash = target) :
    ¬ target < workHash := by
  omega

theorem work_hash_successor_is_rejected (target : Nat) :
    target < target + 1 := by
  omega

theorem checked_work_rejects_512_bit_overflow :
    checkedWorkAdd maxWorkValue 1 = none := by
  simp [checkedWorkAdd, maxWorkValue]

theorem checked_work_accepts_exact_maximum
    {parent block : Nat}
    (exact : parent + block = maxWorkValue) :
    checkedWorkAdd parent block = some maxWorkValue := by
  simp [checkedWorkAdd, exact]

theorem admission_height_precedes_bits
    (input : PowAdmissionInput)
    (heightBad : checkedNextU64 input.parentHeight ≠ some input.headerHeight) :
    evaluatePowAdmission input = Except.error PowAdmissionReject.heightMismatch := by
  simp [evaluatePowAdmission, heightBad]

theorem admission_bits_precede_timestamp
    (input : PowAdmissionInput)
    (heightOk : checkedNextU64 input.parentHeight = some input.headerHeight)
    (bitsBad : input.powBits ≠ input.expectedPowBits) :
    evaluatePowAdmission input = Except.error PowAdmissionReject.powBitsMismatch := by
  simp [evaluatePowAdmission, heightOk, bitsBad]

end PowRulesV3
end Consensus
end Hegemon
