namespace Hegemon
namespace Transaction
namespace SmallWoodBalanceBoundary

def signedMagnitude (sign magnitude : Nat) : Int :=
  if sign = 0 then Int.ofNat magnitude else -(Int.ofNat magnitude)

def booleanFlag (flag : Nat) : Prop :=
  flag = 0 ∨ flag = 1

def canonicalSignedMagnitude (sign magnitude : Nat) : Prop :=
  booleanFlag sign ∧ (magnitude = 0 -> sign = 0)

def allZero : List Int -> Prop
  | [] => True
  | value :: rest => value = 0 ∧ allZero rest

structure BalanceSurface where
  nativeInputTotal : Nat
  nativeOutputTotal : Nat
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  stablecoinEnabled : Nat
  selectedStablecoinDelta : Int
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  nonSelectedNonNativeDeltas : List Int
deriving DecidableEq, Repr

def nativeExpectedDelta (surface : BalanceSurface) : Int :=
  Int.ofNat surface.fee -
    signedMagnitude
      surface.valueBalanceSign
      surface.valueBalanceMagnitude

def stablecoinExpectedDelta (surface : BalanceSurface) : Int :=
  if surface.stablecoinEnabled = 1 then
    signedMagnitude
      surface.stablecoinIssuanceSign
      surface.stablecoinIssuanceMagnitude
  else
    0

def nativeDelta (surface : BalanceSurface) : Int :=
  Int.ofNat surface.nativeInputTotal -
    Int.ofNat surface.nativeOutputTotal

structure AcceptedSmallWoodBalanceConstraints
    (surface : BalanceSurface) : Prop where
  valueBalanceCanonical :
    canonicalSignedMagnitude
      surface.valueBalanceSign
      surface.valueBalanceMagnitude
  stablecoinEnabledBoolean :
    booleanFlag surface.stablecoinEnabled
  stablecoinIssuanceCanonical :
    canonicalSignedMagnitude
      surface.stablecoinIssuanceSign
      surface.stablecoinIssuanceMagnitude
  nativeConstraint :
    nativeDelta surface = nativeExpectedDelta surface
  selectedStablecoinConstraint :
    surface.selectedStablecoinDelta =
      stablecoinExpectedDelta surface
  nonSelectedNonNativeZero :
    allZero surface.nonSelectedNonNativeDeltas

structure SmallWoodBalanceBoundaryFacts
    (surface : BalanceSurface) : Prop where
  valueBalanceCanonical :
    canonicalSignedMagnitude
      surface.valueBalanceSign
      surface.valueBalanceMagnitude
  stablecoinEnabledBoolean :
    booleanFlag surface.stablecoinEnabled
  stablecoinIssuanceCanonical :
    canonicalSignedMagnitude
      surface.stablecoinIssuanceSign
      surface.stablecoinIssuanceMagnitude
  nativeDeltaAuthorized :
    nativeDelta surface =
      Int.ofNat surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude
  selectedStablecoinDeltaAuthorized :
    surface.selectedStablecoinDelta =
      if surface.stablecoinEnabled = 1 then
        signedMagnitude
          surface.stablecoinIssuanceSign
          surface.stablecoinIssuanceMagnitude
      else
        0
  nonSelectedNonNativeDeltasZero :
    allZero surface.nonSelectedNonNativeDeltas

theorem accepted_smallwood_balance_constraints_expose_boundary_facts
    {surface : BalanceSurface}
    (accepted : AcceptedSmallWoodBalanceConstraints surface) :
    SmallWoodBalanceBoundaryFacts surface := by
  exact {
    valueBalanceCanonical := accepted.valueBalanceCanonical,
    stablecoinEnabledBoolean := accepted.stablecoinEnabledBoolean,
    stablecoinIssuanceCanonical := accepted.stablecoinIssuanceCanonical,
    nativeDeltaAuthorized := accepted.nativeConstraint,
    selectedStablecoinDeltaAuthorized :=
      accepted.selectedStablecoinConstraint,
    nonSelectedNonNativeDeltasZero :=
      accepted.nonSelectedNonNativeZero
  }

theorem accepted_smallwood_balance_constraints_authorize_native_delta
    {surface : BalanceSurface}
    (accepted : AcceptedSmallWoodBalanceConstraints surface) :
    nativeDelta surface =
      Int.ofNat surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude :=
  accepted.nativeConstraint

theorem accepted_smallwood_balance_constraints_authorize_selected_stablecoin_delta
    {surface : BalanceSurface}
    (accepted : AcceptedSmallWoodBalanceConstraints surface)
    (enabled : surface.stablecoinEnabled = 1) :
    surface.selectedStablecoinDelta =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude := by
  simpa [stablecoinExpectedDelta, enabled] using
    accepted.selectedStablecoinConstraint

theorem accepted_smallwood_balance_constraints_disabled_stablecoin_delta_zero
    {surface : BalanceSurface}
    (accepted : AcceptedSmallWoodBalanceConstraints surface)
    (disabled : surface.stablecoinEnabled = 0) :
    surface.selectedStablecoinDelta = 0 := by
  have notEnabled : surface.stablecoinEnabled ≠ 1 := by
    intro h
    rw [disabled] at h
    cases h
  simpa [stablecoinExpectedDelta, notEnabled] using
    accepted.selectedStablecoinConstraint

theorem accepted_smallwood_balance_constraints_nonselected_non_native_zero
    {surface : BalanceSurface}
    (accepted : AcceptedSmallWoodBalanceConstraints surface) :
    allZero surface.nonSelectedNonNativeDeltas :=
  accepted.nonSelectedNonNativeZero

def sampleNativeSurface : BalanceSurface :=
  {
    nativeInputTotal := 8,
    nativeOutputTotal := 2,
    fee := 5,
    valueBalanceSign := 1,
    valueBalanceMagnitude := 1,
    stablecoinEnabled := 0,
    selectedStablecoinDelta := 0,
    stablecoinIssuanceSign := 0,
    stablecoinIssuanceMagnitude := 0,
    nonSelectedNonNativeDeltas := [0, 0, 0]
  }

theorem sample_native_balance_constraints_accept :
    AcceptedSmallWoodBalanceConstraints sampleNativeSurface := by
  exact {
    valueBalanceCanonical := by
      simp [canonicalSignedMagnitude, booleanFlag, sampleNativeSurface],
    stablecoinEnabledBoolean := by
      simp [booleanFlag, sampleNativeSurface],
    stablecoinIssuanceCanonical := by
      simp [canonicalSignedMagnitude, booleanFlag, sampleNativeSurface],
    nativeConstraint := by
      decide,
    selectedStablecoinConstraint := by
      decide,
    nonSelectedNonNativeZero := by
      simp [allZero, sampleNativeSurface]
  }

def sampleStablecoinSurface : BalanceSurface :=
  {
    nativeInputTotal := 5,
    nativeOutputTotal := 0,
    fee := 5,
    valueBalanceSign := 0,
    valueBalanceMagnitude := 0,
    stablecoinEnabled := 1,
    selectedStablecoinDelta := -5,
    stablecoinIssuanceSign := 1,
    stablecoinIssuanceMagnitude := 5,
    nonSelectedNonNativeDeltas := [0, 0]
  }

theorem sample_stablecoin_balance_constraints_accept :
    AcceptedSmallWoodBalanceConstraints sampleStablecoinSurface := by
  exact {
    valueBalanceCanonical := by
      simp [canonicalSignedMagnitude, booleanFlag, sampleStablecoinSurface],
    stablecoinEnabledBoolean := by
      simp [booleanFlag, sampleStablecoinSurface],
    stablecoinIssuanceCanonical := by
      simp [canonicalSignedMagnitude, booleanFlag, sampleStablecoinSurface],
    nativeConstraint := by
      decide,
    selectedStablecoinConstraint := by
      decide,
    nonSelectedNonNativeZero := by
      simp [allZero, sampleStablecoinSurface]
  }

theorem noncanonical_zero_value_balance_sign_rejected
    {surface : BalanceSurface}
    (zeroMagnitude : surface.valueBalanceMagnitude = 0)
    (negativeZeroSign : surface.valueBalanceSign = 1) :
    ¬ AcceptedSmallWoodBalanceConstraints surface := by
  intro accepted
  have signZero :=
    accepted.valueBalanceCanonical.right zeroMagnitude
  rw [negativeZeroSign] at signZero
  cases signZero

theorem noncanonical_zero_stablecoin_issuance_sign_rejected
    {surface : BalanceSurface}
    (zeroMagnitude : surface.stablecoinIssuanceMagnitude = 0)
    (negativeZeroSign : surface.stablecoinIssuanceSign = 1) :
    ¬ AcceptedSmallWoodBalanceConstraints surface := by
  intro accepted
  have signZero :=
    accepted.stablecoinIssuanceCanonical.right zeroMagnitude
  rw [negativeZeroSign] at signZero
  cases signZero

end SmallWoodBalanceBoundary
end Transaction
end Hegemon
