namespace Hegemon
namespace Consensus

def maxPowHeight : Nat := 18446744073709551615
def maxTimestampMs : Nat := maxPowHeight

def pow2Nat (exponent : Nat) : Nat :=
  2 ^ exponent

def maxPowTarget : Nat :=
  pow2Nat 256 - 1
def twoPow256 : Nat :=
  pow2Nat 256
def maxWork48 : Nat :=
  pow2Nat 384 - 1
def maxFutureSkewMs : Nat := 90000

def bitsExponent (bits : Nat) : Nat :=
  bits / 16777216

def bitsMantissa (bits : Nat) : Nat :=
  bits % 16777216

def compactTargetValue (bits : Nat) : Option Nat :=
  let exponent := bitsExponent bits
  let mantissa := bitsMantissa bits
  if mantissa = 0 ∨ 32 < exponent then
    none
  else
    let target :=
      if exponent <= 3 then
        mantissa / pow2Nat (8 * (3 - exponent))
      else
        mantissa * pow2Nat (8 * (exponent - 3))
    if target = 0 ∨ maxPowTarget < target then none else some target

def targetWork (target : Nat) : Nat :=
  twoPow256 / (target + 1)

def blockWorkFromBits (bits : Nat) : Option Nat :=
  match compactTargetValue bits with
  | none => none
  | some target => some (targetWork target)

def futureLimit (nowMs : Nat) : Nat :=
  Nat.min maxTimestampMs (nowMs + maxFutureSkewMs)

def checkedNextU64 (height : Nat) : Option Nat :=
  if height < maxPowHeight then some (height + 1) else none

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

def checkedWorkAdd (parentWork blockWork : Nat) : Option Nat :=
  let total := parentWork + blockWork
  if total <= maxWork48 then some total else none

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

def evaluatePowAdmission (input : PowAdmissionInput) : Except PowAdmissionReject Nat :=
  if checkedNextU64 input.parentHeight ≠ some input.headerHeight then
    Except.error PowAdmissionReject.heightMismatch
  else if input.powBits ≠ input.expectedPowBits then
    Except.error PowAdmissionReject.powBitsMismatch
  else
    match timestampPolicy
      input.parentTimestamp
      input.medianTimePast
      input.nowMs
      input.headerTimestamp with
    | some reject => Except.error (timestampRejectToPowReject reject)
    | none =>
      match compactTargetValue input.powBits with
      | none => Except.error PowAdmissionReject.invalidCompactTarget
      | some target =>
        if target < input.workHashValue then
          Except.error PowAdmissionReject.insufficientWork
        else
          let blockWork := targetWork target
          match checkedWorkAdd input.parentWork blockWork with
          | none => Except.error PowAdmissionReject.cumulativeWorkOverflow
          | some expected =>
            if expected = input.claimedCumulativeWork then
              Except.ok expected
            else
              Except.error PowAdmissionReject.cumulativeWorkMismatch

theorem compactTarget_rejects_zero_mantissa
    {bits : Nat}
    (h : bitsMantissa bits = 0) :
    compactTargetValue bits = none := by
  unfold compactTargetValue
  simp [h]

theorem compactTarget_rejects_large_exponent
    {bits : Nat}
    (h : 32 < bitsExponent bits) :
    compactTargetValue bits = none := by
  unfold compactTargetValue
  simp [h]

theorem compactTarget_accepts_max_valid :
    compactTargetValue 553648127 ≠ none := by
  native_decide

theorem timestamp_rejects_parent_equal
    {parent median nowMs : Nat} :
    timestampPolicy parent median nowMs parent =
      some TimestampReject.timestampNotAdvanced := by
  unfold timestampPolicy
  simp

theorem timestamp_rejects_median_equal
    {parent median nowMs header : Nat}
    (parentLt : parent < header)
    (medianEq : header = median) :
    timestampPolicy parent median nowMs header =
      some TimestampReject.timestampNotAfterMedian := by
  subst header
  unfold timestampPolicy
  have notParent : ¬ median <= parent := Nat.not_le.mpr parentLt
  simp [notParent]

theorem timestamp_rejects_future_skew
    {parent median nowMs header : Nat}
    (parentLt : parent < header)
    (medianLt : median < header)
    (futureLt : futureLimit nowMs < header) :
    timestampPolicy parent median nowMs header =
      some TimestampReject.timestampFutureSkew := by
  unfold timestampPolicy
  have notParent : ¬ header <= parent := Nat.not_le.mpr parentLt
  have notMedian : ¬ header <= median := Nat.not_le.mpr medianLt
  simp [notParent, notMedian, futureLt]

theorem checkedWorkAdd_ok
    {parent block : Nat}
    (bounded : parent + block <= maxWork48) :
    checkedWorkAdd parent block = some (parent + block) := by
  unfold checkedWorkAdd
  simp [bounded]

theorem checkedWorkAdd_rejects_overflow
    {parent block : Nat}
    (overflow : maxWork48 < parent + block) :
    checkedWorkAdd parent block = none := by
  unfold checkedWorkAdd
  have notBounded : ¬ parent + block <= maxWork48 := Nat.not_le.mpr overflow
  simp [notBounded]

theorem checkedNextU64_rejects_max :
    checkedNextU64 maxPowHeight = none := by
  unfold checkedNextU64 maxPowHeight
  simp

theorem checkedNextU64_accepts_predecessor :
    checkedNextU64 (maxPowHeight - 1) = some maxPowHeight := by
  native_decide

theorem powAdmission_rejects_height
    {input : PowAdmissionInput}
    (heightMismatch : checkedNextU64 input.parentHeight ≠ some input.headerHeight) :
    evaluatePowAdmission input =
      Except.error PowAdmissionReject.heightMismatch := by
  unfold evaluatePowAdmission
  simp [heightMismatch]

theorem powAdmission_rejects_height_overflow
    {input : PowAdmissionInput}
    (parentMax : input.parentHeight = maxPowHeight) :
    evaluatePowAdmission input =
      Except.error PowAdmissionReject.heightMismatch := by
  apply powAdmission_rejects_height
  rw [parentMax, checkedNextU64_rejects_max]
  simp

theorem powAdmission_rejects_pow_bits
    {input : PowAdmissionInput}
    (heightOk : checkedNextU64 input.parentHeight = some input.headerHeight)
    (bitsMismatch : input.powBits ≠ input.expectedPowBits) :
    evaluatePowAdmission input =
      Except.error PowAdmissionReject.powBitsMismatch := by
  unfold evaluatePowAdmission
  simp [heightOk, bitsMismatch]

theorem powAdmission_rejects_insufficient_work
    {input : PowAdmissionInput}
    {target : Nat}
    (heightOk : checkedNextU64 input.parentHeight = some input.headerHeight)
    (bitsOk : input.powBits = input.expectedPowBits)
    (timeOk :
      timestampPolicy
        input.parentTimestamp
        input.medianTimePast
        input.nowMs
        input.headerTimestamp = none)
    (targetOk : compactTargetValue input.powBits = some target)
    (workTooHigh : target < input.workHashValue) :
    evaluatePowAdmission input =
      Except.error PowAdmissionReject.insufficientWork := by
  unfold evaluatePowAdmission
  have targetExpected : compactTargetValue input.expectedPowBits = some target := by
    rw [← bitsOk]
    exact targetOk
  simp [heightOk, bitsOk, timeOk, targetExpected, workTooHigh]

theorem powAdmission_accepts_valid
    {input : PowAdmissionInput}
    {target expectedWork : Nat}
    (heightOk : checkedNextU64 input.parentHeight = some input.headerHeight)
    (bitsOk : input.powBits = input.expectedPowBits)
    (timeOk :
      timestampPolicy
        input.parentTimestamp
        input.medianTimePast
        input.nowMs
        input.headerTimestamp = none)
    (targetOk : compactTargetValue input.powBits = some target)
    (workOk : input.workHashValue <= target)
    (sumOk : checkedWorkAdd input.parentWork (targetWork target) = some expectedWork)
    (claimedOk : input.claimedCumulativeWork = expectedWork) :
    evaluatePowAdmission input = Except.ok expectedWork := by
  unfold evaluatePowAdmission
  have notWorkTooHigh : ¬ target < input.workHashValue := Nat.not_lt.mpr workOk
  have targetExpected : compactTargetValue input.expectedPowBits = some target := by
    rw [← bitsOk]
    exact targetOk
  simp [heightOk, bitsOk, timeOk, targetExpected, notWorkTooHigh, sumOk, claimedOk]

end Consensus
end Hegemon
