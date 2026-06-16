namespace Hegemon
namespace Transaction
namespace AirBalanceBoundary

def booleanField (value : Int) : Prop :=
  value = 0 ∨ value = 1

def signedMagnitude (sign magnitude : Int) : Int :=
  magnitude - sign * magnitude * 2

def nonNativeSlot (slot : Nat) : Prop :=
  slot = 1 ∨ slot = 2 ∨ slot = 3

structure AirBalanceFinalRowSurface where
  slot0In : Int
  slot1In : Int
  slot2In : Int
  slot3In : Int
  slot0Out : Int
  slot1Out : Int
  slot2Out : Int
  slot3Out : Int
  slot0Asset : Int
  slot1Asset : Int
  slot2Asset : Int
  slot3Asset : Int
  fee : Int
  valueBalanceSign : Int
  valueBalanceMagnitude : Int
  stablecoinEnabled : Int
  stablecoinAsset : Int
  stablecoinPolicyVersion : Int
  stablecoinIssuanceSign : Int
  stablecoinIssuanceMagnitude : Int
  stablecoinPolicyHash0 : Int
  stablecoinPolicyHash1 : Int
  stablecoinPolicyHash2 : Int
  stablecoinPolicyHash3 : Int
  stablecoinPolicyHash4 : Int
  stablecoinPolicyHash5 : Int
  stablecoinOracleCommitment0 : Int
  stablecoinOracleCommitment1 : Int
  stablecoinOracleCommitment2 : Int
  stablecoinOracleCommitment3 : Int
  stablecoinOracleCommitment4 : Int
  stablecoinOracleCommitment5 : Int
  stablecoinAttestationCommitment0 : Int
  stablecoinAttestationCommitment1 : Int
  stablecoinAttestationCommitment2 : Int
  stablecoinAttestationCommitment3 : Int
  stablecoinAttestationCommitment4 : Int
  stablecoinAttestationCommitment5 : Int
  stablecoinSlotBit0 : Int
  stablecoinSlotBit1 : Int
deriving DecidableEq, Repr

def slotInput (surface : AirBalanceFinalRowSurface) (slot : Nat) : Int :=
  match slot with
  | 0 => surface.slot0In
  | 1 => surface.slot1In
  | 2 => surface.slot2In
  | 3 => surface.slot3In
  | _ => 0

def slotOutput (surface : AirBalanceFinalRowSurface) (slot : Nat) : Int :=
  match slot with
  | 0 => surface.slot0Out
  | 1 => surface.slot1Out
  | 2 => surface.slot2Out
  | 3 => surface.slot3Out
  | _ => 0

def slotDelta (surface : AirBalanceFinalRowSurface) (slot : Nat) : Int :=
  slotInput surface slot - slotOutput surface slot

def slotAsset (surface : AirBalanceFinalRowSurface) (slot : Nat) : Int :=
  match slot with
  | 0 => surface.slot0Asset
  | 1 => surface.slot1Asset
  | 2 => surface.slot2Asset
  | 3 => surface.slot3Asset
  | _ => 0

def selectorWeight
    (surface : AirBalanceFinalRowSurface)
    (slot : Nat) : Int :=
  match slot with
  | 0 =>
      (1 - surface.stablecoinSlotBit0) *
        (1 - surface.stablecoinSlotBit1)
  | 1 =>
      surface.stablecoinSlotBit0 *
        (1 - surface.stablecoinSlotBit1)
  | 2 =>
      (1 - surface.stablecoinSlotBit0) *
        surface.stablecoinSlotBit1
  | 3 =>
      surface.stablecoinSlotBit0 *
        surface.stablecoinSlotBit1
  | _ => 0

def selectedStablecoinDelta
    (surface : AirBalanceFinalRowSurface) : Int :=
  selectorWeight surface 1 * slotDelta surface 1
    + selectorWeight surface 2 * slotDelta surface 2
    + selectorWeight surface 3 * slotDelta surface 3

def stablecoinMetadataValues
    (surface : AirBalanceFinalRowSurface) : List Int :=
  [
    surface.stablecoinAsset,
    surface.stablecoinPolicyVersion,
    surface.stablecoinIssuanceSign,
    surface.stablecoinIssuanceMagnitude,
    surface.stablecoinPolicyHash0,
    surface.stablecoinPolicyHash1,
    surface.stablecoinPolicyHash2,
    surface.stablecoinPolicyHash3,
    surface.stablecoinPolicyHash4,
    surface.stablecoinPolicyHash5,
    surface.stablecoinOracleCommitment0,
    surface.stablecoinOracleCommitment1,
    surface.stablecoinOracleCommitment2,
    surface.stablecoinOracleCommitment3,
    surface.stablecoinOracleCommitment4,
    surface.stablecoinOracleCommitment5,
    surface.stablecoinAttestationCommitment0,
    surface.stablecoinAttestationCommitment1,
    surface.stablecoinAttestationCommitment2,
    surface.stablecoinAttestationCommitment3,
    surface.stablecoinAttestationCommitment4,
    surface.stablecoinAttestationCommitment5
  ]

structure AcceptedAirBalanceFinalRowConstraints
    (surface : AirBalanceFinalRowSurface) : Prop where
  valueBalanceSignBoolean :
    booleanField surface.valueBalanceSign
  stablecoinEnabledBoolean :
    booleanField surface.stablecoinEnabled
  stablecoinIssuanceSignBoolean :
    booleanField surface.stablecoinIssuanceSign
  stablecoinSlotBit0Boolean :
    booleanField surface.stablecoinSlotBit0
  stablecoinSlotBit1Boolean :
    booleanField surface.stablecoinSlotBit1
  stablecoinSelectorSum :
    selectorWeight surface 1
      + selectorWeight surface 2
      + selectorWeight surface 3 =
        surface.stablecoinEnabled
  stablecoinSlotAssetEquation :
    ∀ slot, nonNativeSlot slot ->
      selectorWeight surface slot *
        (slotAsset surface slot - surface.stablecoinAsset) = 0
  selectedStablecoinDeltaEquation :
    selectedStablecoinDelta surface =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude
  nonSelectedDeltaEquation :
    ∀ slot, nonNativeSlot slot ->
      slotDelta surface slot *
        (1 - selectorWeight surface slot) = 0
  disabledMetadataEquation :
    ∀ value, value ∈ stablecoinMetadataValues surface ->
      (1 - surface.stablecoinEnabled) * value = 0
  nativeBalanceEquation :
    slotDelta surface 0 =
      surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude
  disabledNonNativeDeltaEquation :
    ∀ slot, nonNativeSlot slot ->
      (1 - surface.stablecoinEnabled) *
        slotDelta surface slot = 0

structure AirBalanceFinalRowFacts
    (surface : AirBalanceFinalRowSurface) : Prop where
  valueBalanceSignBoolean :
    booleanField surface.valueBalanceSign
  stablecoinEnabledBoolean :
    booleanField surface.stablecoinEnabled
  stablecoinIssuanceSignBoolean :
    booleanField surface.stablecoinIssuanceSign
  stablecoinSlotBit0Boolean :
    booleanField surface.stablecoinSlotBit0
  stablecoinSlotBit1Boolean :
    booleanField surface.stablecoinSlotBit1
  stablecoinSelectorSum :
    selectorWeight surface 1
      + selectorWeight surface 2
      + selectorWeight surface 3 =
        surface.stablecoinEnabled
  nativeDeltaAuthorized :
    slotDelta surface 0 =
      surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude
  selectedStablecoinDeltaAuthorized :
    selectedStablecoinDelta surface =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude

theorem accepted_air_balance_final_row_exposes_boundary_facts
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface) :
    AirBalanceFinalRowFacts surface := by
  exact {
    valueBalanceSignBoolean := accepted.valueBalanceSignBoolean,
    stablecoinEnabledBoolean := accepted.stablecoinEnabledBoolean,
    stablecoinIssuanceSignBoolean :=
      accepted.stablecoinIssuanceSignBoolean,
    stablecoinSlotBit0Boolean := accepted.stablecoinSlotBit0Boolean,
    stablecoinSlotBit1Boolean := accepted.stablecoinSlotBit1Boolean,
    stablecoinSelectorSum := accepted.stablecoinSelectorSum,
    nativeDeltaAuthorized := accepted.nativeBalanceEquation,
    selectedStablecoinDeltaAuthorized :=
      accepted.selectedStablecoinDeltaEquation
  }

theorem accepted_air_balance_final_row_native_delta
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface) :
    slotDelta surface 0 =
      surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude :=
  accepted.nativeBalanceEquation

theorem accepted_air_balance_final_row_selected_slot_asset
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    {slot : Nat}
    (nonNative : nonNativeSlot slot)
    (selected : selectorWeight surface slot = 1) :
    slotAsset surface slot = surface.stablecoinAsset := by
  have hmul :=
    accepted.stablecoinSlotAssetEquation slot nonNative
  rw [selected] at hmul
  omega

theorem accepted_air_balance_final_row_nonselected_slot_delta_zero
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    {slot : Nat}
    (nonNative : nonNativeSlot slot)
    (notSelected : selectorWeight surface slot = 0) :
    slotDelta surface slot = 0 := by
  simpa [notSelected] using
    accepted.nonSelectedDeltaEquation slot nonNative

theorem accepted_air_balance_final_row_disabled_metadata_zero
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    (disabled : surface.stablecoinEnabled = 0)
    {value : Int}
    (member : value ∈ stablecoinMetadataValues surface) :
    value = 0 := by
  simpa [disabled] using
    accepted.disabledMetadataEquation value member

theorem accepted_air_balance_final_row_disabled_non_native_delta_zero
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    (disabled : surface.stablecoinEnabled = 0)
    {slot : Nat}
    (nonNative : nonNativeSlot slot) :
    slotDelta surface slot = 0 := by
  simpa [disabled] using
    accepted.disabledNonNativeDeltaEquation slot nonNative

theorem accepted_air_balance_final_row_slot1_selected_delta
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    (slot1Selected : selectorWeight surface 1 = 1)
    (slot2NotSelected : selectorWeight surface 2 = 0)
    (slot3NotSelected : selectorWeight surface 3 = 0) :
    slotDelta surface 1 =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude := by
  simpa [selectedStablecoinDelta, slot1Selected,
    slot2NotSelected, slot3NotSelected] using
      accepted.selectedStablecoinDeltaEquation

theorem accepted_air_balance_final_row_slot2_selected_delta
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    (slot1NotSelected : selectorWeight surface 1 = 0)
    (slot2Selected : selectorWeight surface 2 = 1)
    (slot3NotSelected : selectorWeight surface 3 = 0) :
    slotDelta surface 2 =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude := by
  simpa [selectedStablecoinDelta, slot1NotSelected,
    slot2Selected, slot3NotSelected] using
      accepted.selectedStablecoinDeltaEquation

theorem accepted_air_balance_final_row_slot3_selected_delta
    {surface : AirBalanceFinalRowSurface}
    (accepted : AcceptedAirBalanceFinalRowConstraints surface)
    (slot1NotSelected : selectorWeight surface 1 = 0)
    (slot2NotSelected : selectorWeight surface 2 = 0)
    (slot3Selected : selectorWeight surface 3 = 1) :
    slotDelta surface 3 =
      signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude := by
  simpa [selectedStablecoinDelta, slot1NotSelected,
    slot2NotSelected, slot3Selected] using
      accepted.selectedStablecoinDeltaEquation

end AirBalanceBoundary
end Transaction
end Hegemon
