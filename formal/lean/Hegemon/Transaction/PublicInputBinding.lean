import Hegemon.Transaction.PublicInputs

namespace Hegemon
namespace Transaction
namespace PublicInputBinding

open Hegemon.Transaction.PublicInputs

structure PublicFields where
  merkleRoot : Digest
  nativeFee : Nat
  valueBalance : Int
  balanceSlotAssets : List Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinPolicyVersion : Nat
  stablecoinIssuanceDelta : Int
  stablecoinPolicyHash : Digest
  stablecoinOracleCommitment : Digest
  stablecoinAttestationCommitment : Digest
deriving DecidableEq, Repr

structure SerializedFields where
  inputFlags : List Nat
  outputFlags : List Nat
  merkleRoot : Digest
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  balanceSlotAssets : List Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinPolicyVersion : Nat
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  stablecoinPolicyHash : Digest
  stablecoinOracleCommitment : Digest
  stablecoinAttestationCommitment : Digest
deriving DecidableEq, Repr

structure BoundPublicInputs where
  inputFlags : List Nat
  outputFlags : List Nat
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  merkleRoot : Digest
  balanceSlotAssets : List Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinPolicyVersion : Nat
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  stablecoinPolicyHash : Digest
  stablecoinOracleCommitment : Digest
  stablecoinAttestationCommitment : Digest
deriving DecidableEq, Repr

def signedMagnitudeMatches (value : Int) (sign magnitude : Nat) : Bool :=
  let expectedSign := if value < 0 then 1 else 0
  expectedSign = sign && Int.natAbs value = magnitude

theorem signedMagnitudeMatches_true_eq
    {value : Int} {sign magnitude : Nat}
    (h : signedMagnitudeMatches value sign magnitude = true) :
    sign = (if value < 0 then 1 else 0)
      ∧ magnitude = Int.natAbs value := by
  unfold signedMagnitudeMatches at h
  simp at h
  exact ⟨h.left.symm, h.right.symm⟩

def selectedBalanceSlotAssets (pubFields : PublicFields) (serialized : SerializedFields) :
    Option (List Nat) :=
  if serialized.balanceSlotAssets = [] then
    if pubFields.balanceSlotAssets.length = balanceSlotCount then
      some pubFields.balanceSlotAssets
    else
      none
  else if serialized.balanceSlotAssets.length = balanceSlotCount then
    some serialized.balanceSlotAssets
  else
    none

def balanceSlotAssetsMatch (pubFields : PublicFields) (assets : List Nat) : Bool :=
  pubFields.balanceSlotAssets = assets

def stablecoinBindingMatches (pubFields : PublicFields) (serialized : SerializedFields) : Bool :=
  pubFields.stablecoinEnabled = serialized.stablecoinEnabled
    && pubFields.stablecoinAsset = serialized.stablecoinAsset
    && pubFields.stablecoinPolicyVersion = serialized.stablecoinPolicyVersion
    && signedMagnitudeMatches pubFields.stablecoinIssuanceDelta
        serialized.stablecoinIssuanceSign
        serialized.stablecoinIssuanceMagnitude
    && pubFields.stablecoinPolicyHash = serialized.stablecoinPolicyHash
    && pubFields.stablecoinOracleCommitment = serialized.stablecoinOracleCommitment
    && pubFields.stablecoinAttestationCommitment = serialized.stablecoinAttestationCommitment

def bindPublicInputs (pubFields : PublicFields) (serialized : SerializedFields) :
    Option BoundPublicInputs :=
  match selectedBalanceSlotAssets pubFields serialized with
  | none => none
  | some assets =>
      if pubFields.merkleRoot = serialized.merkleRoot
          && pubFields.nativeFee = serialized.fee
          && signedMagnitudeMatches pubFields.valueBalance
              serialized.valueBalanceSign
              serialized.valueBalanceMagnitude
          && balanceSlotAssetsMatch pubFields assets
          && stablecoinBindingMatches pubFields serialized then
        some
          { inputFlags := serialized.inputFlags
            outputFlags := serialized.outputFlags
            fee := serialized.fee
            valueBalanceSign := serialized.valueBalanceSign
            valueBalanceMagnitude := serialized.valueBalanceMagnitude
            merkleRoot := serialized.merkleRoot
            balanceSlotAssets := assets
            stablecoinEnabled := serialized.stablecoinEnabled
            stablecoinAsset := serialized.stablecoinAsset
            stablecoinPolicyVersion := serialized.stablecoinPolicyVersion
            stablecoinIssuanceSign := serialized.stablecoinIssuanceSign
            stablecoinIssuanceMagnitude := serialized.stablecoinIssuanceMagnitude
            stablecoinPolicyHash := serialized.stablecoinPolicyHash
            stablecoinOracleCommitment := serialized.stablecoinOracleCommitment
            stablecoinAttestationCommitment := serialized.stablecoinAttestationCommitment }
      else
        none

def validBinding (pubFields : PublicFields) (serialized : SerializedFields) : Bool :=
  match bindPublicInputs pubFields serialized with
  | some _ => true
  | none => false

def validPublicFields : PublicFields :=
  { merkleRoot := 101
    nativeFee := 3
    valueBalance := -5
    balanceSlotAssets := [0, 7, 8, 9]
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinPolicyVersion := 0
    stablecoinIssuanceDelta := 0
    stablecoinPolicyHash := 0
    stablecoinOracleCommitment := 0
    stablecoinAttestationCommitment := 0 }

def validSerializedFields : SerializedFields :=
  { inputFlags := [1, 0]
    outputFlags := [1, 0]
    merkleRoot := 101
    fee := 3
    valueBalanceSign := 1
    valueBalanceMagnitude := 5
    balanceSlotAssets := [0, 7, 8, 9]
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinPolicyVersion := 0
    stablecoinIssuanceSign := 0
    stablecoinIssuanceMagnitude := 0
    stablecoinPolicyHash := 0
    stablecoinOracleCommitment := 0
    stablecoinAttestationCommitment := 0 }

def validBoundPublicInputs : BoundPublicInputs :=
  { inputFlags := [1, 0]
    outputFlags := [1, 0]
    fee := 3
    valueBalanceSign := 1
    valueBalanceMagnitude := 5
    merkleRoot := 101
    balanceSlotAssets := [0, 7, 8, 9]
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinPolicyVersion := 0
    stablecoinIssuanceSign := 0
    stablecoinIssuanceMagnitude := 0
    stablecoinPolicyHash := 0
    stablecoinOracleCommitment := 0
    stablecoinAttestationCommitment := 0 }

def stablecoinPublicFields : PublicFields :=
  { validPublicFields with
    stablecoinEnabled := 1
    stablecoinAsset := 7
    stablecoinPolicyVersion := 2
    stablecoinIssuanceDelta := -13
    stablecoinPolicyHash := 201
    stablecoinOracleCommitment := 202
    stablecoinAttestationCommitment := 203 }

def stablecoinSerializedFields : SerializedFields :=
  { validSerializedFields with
    stablecoinEnabled := 1
    stablecoinAsset := 7
    stablecoinPolicyVersion := 2
    stablecoinIssuanceSign := 1
    stablecoinIssuanceMagnitude := 13
    stablecoinPolicyHash := 201
    stablecoinOracleCommitment := 202
    stablecoinAttestationCommitment := 203 }

theorem bindPublicInputs_accepts_valid :
    bindPublicInputs validPublicFields validSerializedFields = some validBoundPublicInputs := by
  decide

theorem validBinding_accepts_stablecoin :
    validBinding stablecoinPublicFields stablecoinSerializedFields = true := by
  decide

theorem validBinding_accepts_omitted_balance_assets :
    validBinding validPublicFields { validSerializedFields with balanceSlotAssets := [] } = true := by
  decide

theorem validBinding_rejects_merkle_root_mismatch :
    validBinding validPublicFields { validSerializedFields with merkleRoot := 102 } = false := by
  decide

theorem validBinding_rejects_fee_mismatch :
    validBinding validPublicFields { validSerializedFields with fee := 4 } = false := by
  decide

theorem validBinding_rejects_value_balance_sign_mismatch :
    validBinding validPublicFields { validSerializedFields with valueBalanceSign := 0 } = false := by
  decide

theorem validBinding_rejects_value_balance_magnitude_mismatch :
    validBinding validPublicFields { validSerializedFields with valueBalanceMagnitude := 6 } = false := by
  decide

theorem validBinding_rejects_balance_slot_asset_mismatch :
    validBinding validPublicFields
      { validSerializedFields with balanceSlotAssets := [0, 7, 8, 10] } = false := by
  decide

theorem validBinding_rejects_bad_balance_slot_count :
    validBinding validPublicFields
      { validSerializedFields with balanceSlotAssets := [0, 7, 8] } = false := by
  decide

theorem validBinding_rejects_stablecoin_enabled_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinEnabled := 0 } = false := by
  decide

theorem validBinding_rejects_stablecoin_asset_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinAsset := 8 } = false := by
  decide

theorem validBinding_rejects_stablecoin_policy_version_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinPolicyVersion := 3 } = false := by
  decide

theorem validBinding_rejects_stablecoin_issuance_sign_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinIssuanceSign := 0 } = false := by
  decide

theorem validBinding_rejects_stablecoin_issuance_magnitude_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinIssuanceMagnitude := 14 } = false := by
  decide

theorem validBinding_rejects_stablecoin_policy_hash_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinPolicyHash := 204 } = false := by
  decide

theorem validBinding_rejects_stablecoin_oracle_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinOracleCommitment := 204 } = false := by
  decide

theorem validBinding_rejects_stablecoin_attestation_mismatch :
    validBinding stablecoinPublicFields
      { stablecoinSerializedFields with stablecoinAttestationCommitment := 204 } = false := by
  decide

end PublicInputBinding
end Transaction
end Hegemon
