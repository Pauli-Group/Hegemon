import Hegemon.Transaction.AirBalanceBoundary

open Hegemon.Transaction.AirBalanceBoundary

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def intArrayJson (values : List Int) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def boolFieldB (value : Int) : Bool :=
  value == 0 || value == 1

def intEqB (left right : Int) : Bool :=
  left == right

def nonNativeSlots : List Nat := [1, 2, 3]

def allB (values : List Bool) : Bool :=
  values.foldl (fun acc value => acc && value) true

def acceptedAirBalanceFinalRowCheck
    (surface : AirBalanceFinalRowSurface) : Bool :=
  boolFieldB surface.valueBalanceSign
    && boolFieldB surface.stablecoinEnabled
    && boolFieldB surface.stablecoinIssuanceSign
    && boolFieldB surface.stablecoinSlotBit0
    && boolFieldB surface.stablecoinSlotBit1
    && intEqB
      (selectorWeight surface 1
        + selectorWeight surface 2
        + selectorWeight surface 3)
      surface.stablecoinEnabled
    && allB
      (nonNativeSlots.map fun slot =>
        intEqB
          (selectorWeight surface slot *
            (slotAsset surface slot - surface.stablecoinAsset))
          0)
    && intEqB
      (selectedStablecoinDelta surface)
      (signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude)
    && allB
      (nonNativeSlots.map fun slot =>
        intEqB
          (slotDelta surface slot *
            (1 - selectorWeight surface slot))
          0)
    && allB
      ((stablecoinMetadataValues surface).map fun value =>
        intEqB ((1 - surface.stablecoinEnabled) * value) 0)
    && intEqB
      (slotDelta surface 0)
      (surface.fee -
        signedMagnitude
          surface.valueBalanceSign
          surface.valueBalanceMagnitude)
    && allB
      (nonNativeSlots.map fun slot =>
        intEqB
          ((1 - surface.stablecoinEnabled) *
            slotDelta surface slot)
          0)

def disabledNativeTraceSurface : AirBalanceFinalRowSurface :=
  {
    slot0In := 100,
    slot1In := 0,
    slot2In := 0,
    slot3In := 0,
    slot0Out := 80,
    slot1Out := 0,
    slot2Out := 0,
    slot3Out := 0,
    slot0Asset := 0,
    slot1Asset := 4294967294,
    slot2Asset := 4294967294,
    slot3Asset := 4294967294,
    fee := 0,
    valueBalanceSign := 1,
    valueBalanceMagnitude := 20,
    stablecoinEnabled := 0,
    stablecoinAsset := 0,
    stablecoinPolicyVersion := 0,
    stablecoinIssuanceSign := 0,
    stablecoinIssuanceMagnitude := 0,
    stablecoinPolicyHash0 := 0,
    stablecoinPolicyHash1 := 0,
    stablecoinPolicyHash2 := 0,
    stablecoinPolicyHash3 := 0,
    stablecoinPolicyHash4 := 0,
    stablecoinPolicyHash5 := 0,
    stablecoinOracleCommitment0 := 0,
    stablecoinOracleCommitment1 := 0,
    stablecoinOracleCommitment2 := 0,
    stablecoinOracleCommitment3 := 0,
    stablecoinOracleCommitment4 := 0,
    stablecoinOracleCommitment5 := 0,
    stablecoinAttestationCommitment0 := 0,
    stablecoinAttestationCommitment1 := 0,
    stablecoinAttestationCommitment2 := 0,
    stablecoinAttestationCommitment3 := 0,
    stablecoinAttestationCommitment4 := 0,
    stablecoinAttestationCommitment5 := 0,
    stablecoinSlotBit0 := 0,
    stablecoinSlotBit1 := 0
  }

def stablecoinSlot1TraceSurface : AirBalanceFinalRowSurface :=
  let policyHash := 1519143629599610133
  let oracleCommitment := 1591483802437686806
  let attestationCommitment := 1663823975275763479
  {
    slot0In := 5,
    slot1In := 0,
    slot2In := 0,
    slot3In := 0,
    slot0Out := 0,
    slot1Out := 5,
    slot2Out := 0,
    slot3Out := 0,
    slot0Asset := 0,
    slot1Asset := 4242,
    slot2Asset := 4294967294,
    slot3Asset := 4294967294,
    fee := 5,
    valueBalanceSign := 0,
    valueBalanceMagnitude := 0,
    stablecoinEnabled := 1,
    stablecoinAsset := 4242,
    stablecoinPolicyVersion := 1,
    stablecoinIssuanceSign := 1,
    stablecoinIssuanceMagnitude := 5,
    stablecoinPolicyHash0 := policyHash,
    stablecoinPolicyHash1 := policyHash,
    stablecoinPolicyHash2 := policyHash,
    stablecoinPolicyHash3 := policyHash,
    stablecoinPolicyHash4 := policyHash,
    stablecoinPolicyHash5 := policyHash,
    stablecoinOracleCommitment0 := oracleCommitment,
    stablecoinOracleCommitment1 := oracleCommitment,
    stablecoinOracleCommitment2 := oracleCommitment,
    stablecoinOracleCommitment3 := oracleCommitment,
    stablecoinOracleCommitment4 := oracleCommitment,
    stablecoinOracleCommitment5 := oracleCommitment,
    stablecoinAttestationCommitment0 := attestationCommitment,
    stablecoinAttestationCommitment1 := attestationCommitment,
    stablecoinAttestationCommitment2 := attestationCommitment,
    stablecoinAttestationCommitment3 := attestationCommitment,
    stablecoinAttestationCommitment4 := attestationCommitment,
    stablecoinAttestationCommitment5 := attestationCommitment,
    stablecoinSlotBit0 := 1,
    stablecoinSlotBit1 := 0
  }

def surfaceJson (name source : String)
    (surface : AirBalanceFinalRowSurface) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"source\": \"" ++ source ++ "\",\n"
    ++ "      \"slot_in\": "
    ++ intArrayJson
      [surface.slot0In, surface.slot1In,
        surface.slot2In, surface.slot3In] ++ ",\n"
    ++ "      \"slot_out\": "
    ++ intArrayJson
      [surface.slot0Out, surface.slot1Out,
        surface.slot2Out, surface.slot3Out] ++ ",\n"
    ++ "      \"slot_assets\": "
    ++ intArrayJson
      [surface.slot0Asset, surface.slot1Asset,
        surface.slot2Asset, surface.slot3Asset] ++ ",\n"
    ++ "      \"fee\": " ++ toString surface.fee ++ ",\n"
    ++ "      \"value_balance_sign\": "
    ++ toString surface.valueBalanceSign ++ ",\n"
    ++ "      \"value_balance_magnitude\": "
    ++ toString surface.valueBalanceMagnitude ++ ",\n"
    ++ "      \"stablecoin_enabled\": "
    ++ toString surface.stablecoinEnabled ++ ",\n"
    ++ "      \"stablecoin_asset\": "
    ++ toString surface.stablecoinAsset ++ ",\n"
    ++ "      \"stablecoin_policy_version\": "
    ++ toString surface.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"stablecoin_issuance_sign\": "
    ++ toString surface.stablecoinIssuanceSign ++ ",\n"
    ++ "      \"stablecoin_issuance_magnitude\": "
    ++ toString surface.stablecoinIssuanceMagnitude ++ ",\n"
    ++ "      \"stablecoin_policy_hash\": "
    ++ intArrayJson
      [surface.stablecoinPolicyHash0, surface.stablecoinPolicyHash1,
        surface.stablecoinPolicyHash2, surface.stablecoinPolicyHash3,
        surface.stablecoinPolicyHash4, surface.stablecoinPolicyHash5]
    ++ ",\n"
    ++ "      \"stablecoin_oracle_commitment\": "
    ++ intArrayJson
      [surface.stablecoinOracleCommitment0,
        surface.stablecoinOracleCommitment1,
        surface.stablecoinOracleCommitment2,
        surface.stablecoinOracleCommitment3,
        surface.stablecoinOracleCommitment4,
        surface.stablecoinOracleCommitment5]
    ++ ",\n"
    ++ "      \"stablecoin_attestation_commitment\": "
    ++ intArrayJson
      [surface.stablecoinAttestationCommitment0,
        surface.stablecoinAttestationCommitment1,
        surface.stablecoinAttestationCommitment2,
        surface.stablecoinAttestationCommitment3,
        surface.stablecoinAttestationCommitment4,
        surface.stablecoinAttestationCommitment5]
    ++ ",\n"
    ++ "      \"stablecoin_slot_bits\": "
    ++ intArrayJson
      [surface.stablecoinSlotBit0, surface.stablecoinSlotBit1]
    ++ ",\n"
    ++ "      \"expected_selector_weights\": "
    ++ intArrayJson
      [selectorWeight surface 0, selectorWeight surface 1,
        selectorWeight surface 2, selectorWeight surface 3] ++ ",\n"
    ++ "      \"expected_signed_value_balance\": "
    ++ toString
      (signedMagnitude
        surface.valueBalanceSign
        surface.valueBalanceMagnitude) ++ ",\n"
    ++ "      \"expected_signed_stablecoin_issuance\": "
    ++ toString
      (signedMagnitude
        surface.stablecoinIssuanceSign
        surface.stablecoinIssuanceMagnitude) ++ ",\n"
    ++ "      \"expected_native_delta\": "
    ++ toString (slotDelta surface 0) ++ ",\n"
    ++ "      \"expected_selected_stablecoin_delta\": "
    ++ toString (selectedStablecoinDelta surface) ++ ",\n"
    ++ "      \"expected_accepted\": "
    ++ boolJson (acceptedAirBalanceFinalRowCheck surface) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"air_balance_final_row_cases\": [\n"
    ++ surfaceJson "disabled-native-production-surface"
      "sample_witness" disabledNativeTraceSurface ++ ",\n"
    ++ surfaceJson "stablecoin-slot1-production-surface"
      "stablecoin_issuance_witness" stablecoinSlot1TraceSurface ++ ",\n"
    ++ surfaceJson "native-delta-mismatch-rejected"
      "manual"
      { disabledNativeTraceSurface with fee := 1 } ++ ",\n"
    ++ surfaceJson "stablecoin-delta-mismatch-rejected"
      "manual"
      { stablecoinSlot1TraceSurface with
        stablecoinIssuanceMagnitude := 4 } ++ ",\n"
    ++ surfaceJson "stablecoin-selector-asset-mismatch-rejected"
      "manual"
      { stablecoinSlot1TraceSurface with slot1Asset := 4243 } ++ ",\n"
    ++ surfaceJson "disabled-metadata-nonzero-rejected"
      "manual"
      { disabledNativeTraceSurface with stablecoinAsset := 99 } ++ ",\n"
    ++ surfaceJson "nonselected-nonnative-delta-rejected"
      "manual"
      { stablecoinSlot1TraceSurface with slot2In := 1 } ++ ",\n"
    ++ surfaceJson "stablecoin-enabled-nonboolean-rejected"
      "manual"
      { stablecoinSlot1TraceSurface with stablecoinEnabled := 2 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
