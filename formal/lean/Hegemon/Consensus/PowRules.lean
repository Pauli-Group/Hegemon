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
def targetBlockIntervalMs : Nat := 60000
def retargetWindow : Nat := 10
def retargetTimespanMs : Nat := retargetWindow * targetBlockIntervalMs
def maxAdjustmentFactor : Nat := 4

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

def compactTargetExponent (target : Nat) : Nat :=
  match (List.range 33).find? (fun exponent => target < pow2Nat (8 * exponent)) with
  | some exponent => exponent
  | none => 33

def targetToCompact (target : Nat) : Nat :=
  if target = 0 then
    0
  else
    let exponent := compactTargetExponent target
    let mantissa :=
      if exponent <= 3 then
        target * pow2Nat (8 * (3 - exponent))
      else
        target / pow2Nat (8 * (exponent - 3))
    exponent * 16777216 + mantissa % 16777216

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

def adjustedTimespan (actualMs : Nat) : Nat :=
  let minTimespan := retargetTimespanMs / maxAdjustmentFactor
  let maxTimespan := retargetTimespanMs * maxAdjustmentFactor
  if actualMs < minTimespan then
    minTimespan
  else if maxTimespan < actualMs then
    maxTimespan
  else
    actualMs

def retargetTarget (prevTarget actualMs : Nat) : Nat :=
  if prevTarget = 0 then
    0
  else
    let target := prevTarget * adjustedTimespan actualMs / retargetTimespanMs
    if target = 0 then 1 else target

def retargetBits (prevBits actualMs : Nat) : Option Nat :=
  match compactTargetValue prevBits with
  | none => none
  | some prevTarget => some (targetToCompact (retargetTarget prevTarget actualMs))

def retargetAnchorSteps (parentHeight newHeight : Nat) : Option Nat :=
  if newHeight = 0 then
    none
  else if retargetWindow = 0 ∨ newHeight % retargetWindow ≠ 0 then
    none
  else if newHeight <= retargetWindow then
    none
  else
    match checkedNextU64 parentHeight with
    | some nextHeight =>
        if nextHeight < retargetWindow then none else some (retargetWindow - 1)
    | none => some (retargetWindow - 1)

/-- Height-gated correction of the legacy nine-interval timing sample.
    Eligibility (including the first launch-boundary skip) remains unchanged.
    `none` explicitly models the legacy rule, independent of release activation. -/
def retargetAnchorStepsWithActivation
    (parentHeight newHeight : Nat)
    (activationHeight : Option Nat) : Option Nat :=
  match retargetAnchorSteps parentHeight newHeight with
  | none => none
  | some legacySteps =>
    match activationHeight with
    | some activation =>
      if activation <= newHeight then some retargetWindow else some legacySteps
    | none => some legacySteps

inductive PowBitsScheduleReject where
  | insufficientHistory
  | invalidCompactTarget
  deriving DecidableEq, Repr

def expectedPowBitsScheduleWithActivation
    (genesisBits parentBits parentHeight newHeight parentTimestamp : Nat)
    (anchorTimestamp : Option Nat)
    (activationHeight : Option Nat) :
    Except PowBitsScheduleReject Nat :=
  if newHeight = 0 then
    Except.ok genesisBits
  else
    match retargetAnchorStepsWithActivation parentHeight newHeight activationHeight with
    | none => Except.ok parentBits
    | some _ =>
      match anchorTimestamp with
      | none => Except.error PowBitsScheduleReject.insufficientHistory
      | some anchor =>
        match retargetBits parentBits (parentTimestamp - anchor) with
        | none => Except.error PowBitsScheduleReject.invalidCompactTarget
        | some bits => Except.ok bits

/-- Explicit legacy schedule retained for historical vectors and theorem statements. -/
def expectedPowBitsSchedule
    (genesisBits parentBits parentHeight newHeight parentTimestamp : Nat)
    (anchorTimestamp : Option Nat) : Except PowBitsScheduleReject Nat :=
  expectedPowBitsScheduleWithActivation
    genesisBits parentBits parentHeight newHeight parentTimestamp anchorTimestamp none

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

theorem compactTarget_rejects_shifted_zero_target :
    compactTargetValue 16777217 = none := by
  decide

theorem compactTarget_accepts_max_valid :
    compactTargetValue 553648127 ≠ none := by
  decide

theorem targetToCompact_zero :
    targetToCompact 0 = 0 := by
  rfl

theorem targetToCompact_easy_roundtrip :
    targetToCompact
      57896037716911750921221705069588091649609539881711309849342236841432341020672 =
      545259519 := by
  decide

theorem targetToCompact_roundtrip_easy_target :
    compactTargetValue
      (targetToCompact
        57896037716911750921221705069588091649609539881711309849342236841432341020672) =
      some
        57896037716911750921221705069588091649609539881711309849342236841432341020672 := by
  decide

theorem retargetBits_expected_timespan_keeps_bits :
    retargetBits 545259519 retargetTimespanMs = some 545259519 := by
  decide

theorem retargetBits_rejects_invalid_previous_bits :
    retargetBits 16777217 retargetTimespanMs = none := by
  decide

theorem retargetAnchorSteps_genesis_none :
    retargetAnchorSteps 0 0 = none := by
  rfl

theorem retargetAnchorSteps_non_boundary_none :
    retargetAnchorSteps 8 9 = none := by
  decide

theorem retargetAnchorSteps_early_boundary_none :
    retargetAnchorSteps 0 retargetWindow = none := by
  decide

theorem retargetAnchorSteps_first_boundary_none :
    retargetAnchorSteps 9 retargetWindow = none := by
  decide

theorem retargetAnchorSteps_boundary_requires_window :
    retargetAnchorSteps 19 (retargetWindow * 2) = some (retargetWindow - 1) := by
  decide

theorem expectedPowBitsSchedule_genesis_uses_genesis :
    expectedPowBitsSchedule 123 456 0 0 0 none = Except.ok 123 := by
  rfl

theorem expectedPowBitsSchedule_non_boundary_inherits_parent :
    expectedPowBitsSchedule 123 456 8 9 1000 none = Except.ok 456 := by
  rfl

theorem expectedPowBitsSchedule_missing_history_rejects :
    expectedPowBitsSchedule 123 545259519 19 (retargetWindow * 2) retargetTimespanMs none =
      Except.error PowBitsScheduleReject.insufficientHistory := by
  rfl

theorem expectedPowBitsSchedule_expected_timespan_keeps_bits :
    expectedPowBitsSchedule 123 545259519 19 (retargetWindow * 2) retargetTimespanMs (some 0) =
      Except.ok 545259519 := by
  rfl

theorem expectedPowBitsSchedule_invalid_previous_bits_rejects :
    expectedPowBitsSchedule 123 16777217 19 (retargetWindow * 2) retargetTimespanMs (some 0) =
      Except.error PowBitsScheduleReject.invalidCompactTarget := by
  rfl

theorem expectedPowBitsSchedule_reversed_timestamp_saturates :
    expectedPowBitsSchedule 123 545259519 19 (retargetWindow * 2) 100 (some 200) =
      Except.ok 538968063 := by
  rfl

theorem retargetAnchorStepsWithActivation_none_preserves_legacy
    (parentHeight newHeight : Nat) :
    retargetAnchorStepsWithActivation parentHeight newHeight none =
      retargetAnchorSteps parentHeight newHeight := by
  unfold retargetAnchorStepsWithActivation
  cases retargetAnchorSteps parentHeight newHeight <;> rfl

theorem retargetAnchorStepsWithActivation_before_preserves_legacy
    (parentHeight newHeight activation : Nat)
    (before : newHeight < activation) :
    retargetAnchorStepsWithActivation parentHeight newHeight (some activation) =
      retargetAnchorSteps parentHeight newHeight := by
  unfold retargetAnchorStepsWithActivation
  have notActive : ¬ activation <= newHeight := Nat.not_le.mpr before
  cases retargetAnchorSteps parentHeight newHeight <;> simp [notActive]

theorem retargetAnchorStepsWithActivation_active_eligible_uses_ten
    (parentHeight newHeight activation legacySteps : Nat)
    (active : activation <= newHeight)
    (eligible : retargetAnchorSteps parentHeight newHeight = some legacySteps) :
    retargetAnchorStepsWithActivation parentHeight newHeight (some activation) =
      some retargetWindow := by
  simp [retargetAnchorStepsWithActivation, eligible, active]

theorem retargetAnchorStepsWithActivation_before_uses_nine :
    retargetAnchorStepsWithActivation 29 30 (some 40) = some 9 := by
  decide

theorem retargetAnchorStepsWithActivation_at_uses_ten :
    retargetAnchorStepsWithActivation 39 40 (some 40) = some 10 := by
  decide

theorem retargetAnchorStepsWithActivation_after_uses_ten :
    retargetAnchorStepsWithActivation 49 50 (some 40) = some 10 := by
  decide

theorem retargetAnchorStepsWithActivation_non_boundary_skips :
    retargetAnchorStepsWithActivation 40 41 (some 40) = none := by
  decide

theorem retargetAnchorStepsWithActivation_first_boundary_skips :
    retargetAnchorStepsWithActivation 9 10 (some 0) = none := by
  decide

theorem expectedPowBitsScheduleWithActivation_none_preserves_legacy
    (genesisBits parentBits parentHeight newHeight parentTimestamp : Nat)
    (anchorTimestamp : Option Nat) :
    expectedPowBitsScheduleWithActivation
      genesisBits parentBits parentHeight newHeight parentTimestamp anchorTimestamp none =
      expectedPowBitsSchedule
        genesisBits parentBits parentHeight newHeight parentTimestamp anchorTimestamp := by
  rfl

/-- Given the correctly selected ten-step ancestor timestamp, ten 60-second
    intervals preserve compact bits. This does not prove ancestry selection. -/
theorem expectedPowBitsScheduleWithActivation_ten_intervals_preserve_bits :
    expectedPowBitsScheduleWithActivation
      123 545259519 39 40 (10 * targetBlockIntervalMs) (some 0) (some 40) =
      Except.ok 545259519 := by
  rfl

theorem expectedPowBitsScheduleWithActivation_missing_history_rejects :
    expectedPowBitsScheduleWithActivation
      123 545259519 39 40 retargetTimespanMs none (some 40) =
      Except.error PowBitsScheduleReject.insufficientHistory := by
  rfl

theorem expectedPowBitsScheduleWithActivation_fast_window_keeps_clamp :
    expectedPowBitsScheduleWithActivation
      123 545259519 39 40 100000 (some 0) (some 40) =
      Except.ok 538968063 := by
  rfl

theorem expectedPowBitsScheduleWithActivation_slow_window_keeps_clamp :
    expectedPowBitsScheduleWithActivation
      123 486810177 39 40 6000000 (some 0) (some 40) =
      Except.ok 487622916 := by
  rfl

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

theorem retargetConstants_match_consensus :
    targetBlockIntervalMs = 60000
      ∧ retargetWindow = 10
      ∧ retargetTimespanMs = 600000
      ∧ maxAdjustmentFactor = 4 := by
  decide

theorem adjustedTimespan_clamps_fast_blocks :
    adjustedTimespan 0 = retargetTimespanMs / maxAdjustmentFactor := by
  decide

theorem adjustedTimespan_keeps_expected_timespan :
    adjustedTimespan retargetTimespanMs = retargetTimespanMs := by
  decide

theorem adjustedTimespan_clamps_slow_blocks :
    adjustedTimespan (retargetTimespanMs * 10) =
      retargetTimespanMs * maxAdjustmentFactor := by
  decide

theorem retargetTarget_zero_previous_target :
    retargetTarget 0 retargetTimespanMs = 0 := by
  rfl

theorem retargetTarget_keeps_expected_timespan :
    retargetTarget 1000000 retargetTimespanMs = 1000000 := by
  decide

theorem retargetTarget_fast_timespan_is_clamped :
    retargetTarget 1000000 0 = 250000 := by
  decide

theorem retargetTarget_slow_timespan_is_clamped :
    retargetTarget 1000000 (retargetTimespanMs * 10) = 4000000 := by
  decide

theorem retargetTarget_minimum_nonzero_target :
    retargetTarget 1 0 = 1 := by
  decide

theorem checkedNextU64_rejects_max :
    checkedNextU64 maxPowHeight = none := by
  unfold checkedNextU64 maxPowHeight
  simp

theorem checkedNextU64_accepts_predecessor :
    checkedNextU64 (maxPowHeight - 1) = some maxPowHeight := by
  decide

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
