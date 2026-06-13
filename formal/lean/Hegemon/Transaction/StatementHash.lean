import Hegemon.Bytes
import Hegemon.Transaction.PublicInputs

namespace Hegemon
namespace Transaction
namespace StatementHash

open Hegemon.Transaction.PublicInputs

def digestWidth : Nat := 48
def statementHashDomain : List Byte := asciiBytes "tx-statement-v1"

structure StatementFields where
  merkleRootSeed : Nat
  nullifierSeeds : List Nat
  commitmentSeeds : List Nat
  ciphertextHashSeeds : List Nat
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  balanceTagSeed : Nat
  circuitVersion : Nat
  cryptoSuite : Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinPolicyHashSeed : Nat
  stablecoinOracleCommitmentSeed : Nat
  stablecoinAttestationCommitmentSeed : Nat
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  stablecoinPolicyVersion : Nat
deriving DecidableEq, Repr

def digestBytes (seed : Nat) : List Byte :=
  patternedBytes digestWidth seed

def zeroDigestBytes : List Byte :=
  List.replicate digestWidth 0

def digestSeedsBytes : List Nat -> List Byte
  | [] => []
  | seed :: rest => digestBytes seed ++ digestSeedsBytes rest

def zeroDigestPadding : Nat -> List Byte
  | 0 => []
  | count + 1 => zeroDigestBytes ++ zeroDigestPadding count

def paddedDigests (maxCount : Nat) (seeds : List Nat) : Option (List Byte) :=
  if seeds.length <= maxCount then
    some <| digestSeedsBytes seeds ++ zeroDigestPadding (maxCount - seeds.length)
  else
    none

def decodeSignedMagnitude (sign magnitude : Nat) : Option Int :=
  if sign = 0 then
    some (Int.ofNat magnitude)
  else if sign = 1 then
    some (-(Int.ofNat magnitude))
  else
    none

def i128le (value : Int) : List Byte :=
  let encoded :=
    if value < 0 then
      2 ^ 128 - Int.natAbs value
    else
      Int.toNat value
  u128le encoded

def statementPreimage (fields : StatementFields) : Option (List Byte) :=
  match paddedDigests maxInputs fields.nullifierSeeds,
      paddedDigests maxOutputs fields.commitmentSeeds,
      paddedDigests maxOutputs fields.ciphertextHashSeeds,
      decodeSignedMagnitude fields.valueBalanceSign fields.valueBalanceMagnitude,
      decodeSignedMagnitude fields.stablecoinIssuanceSign fields.stablecoinIssuanceMagnitude with
  | some nullifiers, some commitments, some ciphertextHashes, some valueBalance,
      some stablecoinIssuance =>
      some <|
        statementHashDomain
          ++ digestBytes fields.merkleRootSeed
          ++ nullifiers
          ++ commitments
          ++ ciphertextHashes
          ++ u64le fields.fee
          ++ i128le valueBalance
          ++ digestBytes fields.balanceTagSeed
          ++ u16le fields.circuitVersion
          ++ u16le fields.cryptoSuite
          ++ [byte fields.stablecoinEnabled]
          ++ u64le fields.stablecoinAsset
          ++ digestBytes fields.stablecoinPolicyHashSeed
          ++ digestBytes fields.stablecoinOracleCommitmentSeed
          ++ digestBytes fields.stablecoinAttestationCommitmentSeed
          ++ i128le stablecoinIssuance
          ++ u32le fields.stablecoinPolicyVersion
  | _, _, _, _, _ => none

def publicInputsDigestDomain : List Byte := asciiBytes "tx-public-inputs-digest-v1"

structure SerializedPublicInputsFields where
  inputFlags : List Nat
  outputFlags : List Nat
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  merkleRootSeed : Nat
  balanceSlotAssetIds : List Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinPolicyVersion : Nat
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  stablecoinPolicyHashSeed : Nat
  stablecoinOracleCommitmentSeed : Nat
  stablecoinAttestationCommitmentSeed : Nat
deriving DecidableEq, Repr

def postcardVarintFuel : Nat -> Nat -> List Byte
  | 0, value => [byte value]
  | fuel + 1, value =>
      if value < 128 then
        [byte value]
      else
        byte (128 + (value % 128)) :: postcardVarintFuel fuel (value / 128)

def postcardVarint (value : Nat) : List Byte :=
  postcardVarintFuel 20 value

def concatBytes : List (List Byte) -> List Byte
  | [] => []
  | bytes :: rest => bytes ++ concatBytes rest

def postcardVecU8 (values : List Nat) : List Byte :=
  postcardVarint values.length ++ values.map byte

def postcardBytes (bytes : List Byte) : List Byte :=
  postcardVarint bytes.length ++ bytes

def postcardVecU64 (values : List Nat) : List Byte :=
  postcardVarint values.length ++ concatBytes (values.map postcardVarint)

def serializedPublicInputsPostcard (fields : SerializedPublicInputsFields) : List Byte :=
  postcardVecU8 fields.inputFlags
    ++ postcardVecU8 fields.outputFlags
    ++ postcardVarint fields.fee
    ++ [byte fields.valueBalanceSign]
    ++ postcardVarint fields.valueBalanceMagnitude
    ++ postcardBytes (digestBytes fields.merkleRootSeed)
    ++ postcardVecU64 fields.balanceSlotAssetIds
    ++ [byte fields.stablecoinEnabled]
    ++ postcardVarint fields.stablecoinAsset
    ++ postcardVarint fields.stablecoinPolicyVersion
    ++ [byte fields.stablecoinIssuanceSign]
    ++ postcardVarint fields.stablecoinIssuanceMagnitude
    ++ postcardBytes (digestBytes fields.stablecoinPolicyHashSeed)
    ++ postcardBytes (digestBytes fields.stablecoinOracleCommitmentSeed)
    ++ postcardBytes (digestBytes fields.stablecoinAttestationCommitmentSeed)

def publicInputsDigestPreimage (fields : SerializedPublicInputsFields) : List Byte :=
  publicInputsDigestDomain ++ serializedPublicInputsPostcard fields

def validFields : StatementFields :=
  { merkleRootSeed := 10
    nullifierSeeds := [20, 21]
    commitmentSeeds := [30, 31]
    ciphertextHashSeeds := [40, 41]
    fee := 72623859790382856
    valueBalanceSign := 1
    valueBalanceMagnitude := 5
    balanceTagSeed := 50
    circuitVersion := 2
    cryptoSuite := 3
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinPolicyHashSeed := 0
    stablecoinOracleCommitmentSeed := 0
    stablecoinAttestationCommitmentSeed := 0
    stablecoinIssuanceSign := 0
    stablecoinIssuanceMagnitude := 0
    stablecoinPolicyVersion := 0 }

def paddedFields : StatementFields :=
  { validFields with
    nullifierSeeds := [20]
    commitmentSeeds := [30]
    ciphertextHashSeeds := [] }

def stablecoinFields : StatementFields :=
  { validFields with
    stablecoinEnabled := 1
    stablecoinAsset := 7
    stablecoinPolicyHashSeed := 60
    stablecoinOracleCommitmentSeed := 61
    stablecoinAttestationCommitmentSeed := 62
    stablecoinIssuanceSign := 1
    stablecoinIssuanceMagnitude := 13
    stablecoinPolicyVersion := 4 }

def validSerializedPublicInputs : SerializedPublicInputsFields :=
  { inputFlags := [1, 0]
    outputFlags := [1, 0]
    fee := 9
    valueBalanceSign := 1
    valueBalanceMagnitude := 5
    merkleRootSeed := 70
    balanceSlotAssetIds := [0, 1, 2, 3]
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinPolicyVersion := 0
    stablecoinIssuanceSign := 0
    stablecoinIssuanceMagnitude := 0
    stablecoinPolicyHashSeed := 0
    stablecoinOracleCommitmentSeed := 0
    stablecoinAttestationCommitmentSeed := 0 }

def stablecoinSerializedPublicInputs : SerializedPublicInputsFields :=
  { validSerializedPublicInputs with
    stablecoinEnabled := 1
    stablecoinAsset := 7
    stablecoinPolicyVersion := 4
    stablecoinIssuanceSign := 1
    stablecoinIssuanceMagnitude := 13
    stablecoinPolicyHashSeed := 71
    stablecoinOracleCommitmentSeed := 72
    stablecoinAttestationCommitmentSeed := 73 }

def expectedPreimageLength : Nat := 600

theorem statementHashDomain_length : statementHashDomain.length = 15 := by
  decide

theorem digestBytes_length (seed : Nat) : (digestBytes seed).length = digestWidth := by
  simp [digestBytes, patternedBytes_length]

theorem zeroDigestBytes_length : zeroDigestBytes.length = digestWidth := by
  simp [zeroDigestBytes, digestWidth]

theorem digestSeedsBytes_length (seeds : List Nat) :
    (digestSeedsBytes seeds).length = seeds.length * digestWidth := by
  induction seeds with
  | nil => simp [digestSeedsBytes]
  | cons seed rest ih =>
      simp [digestSeedsBytes, digestBytes_length, ih, Nat.succ_mul, Nat.add_comm]

theorem zeroDigestPadding_length (count : Nat) :
    (zeroDigestPadding count).length = count * digestWidth := by
  induction count with
  | zero => simp [zeroDigestPadding]
  | succ count ih =>
      simp [zeroDigestPadding, zeroDigestBytes_length, ih, Nat.succ_mul, Nat.add_comm]

theorem paddedDigests_length {maxCount : Nat} {seeds : List Nat} {bytes : List Byte}
    (h : paddedDigests maxCount seeds = some bytes) :
    bytes.length = maxCount * digestWidth := by
  unfold paddedDigests at h
  split at h
  next hle =>
    injection h with hbytes
    rw [← hbytes]
    simp [digestSeedsBytes_length, zeroDigestPadding_length]
    rw [← Nat.add_mul, Nat.add_sub_of_le hle]
  next =>
    contradiction

theorem i128le_length (value : Int) : (i128le value).length = 16 := by
  simp [i128le, u128le_length]

theorem statementPreimage_length_of_some {fields : StatementFields} {bytes : List Byte}
    (h : statementPreimage fields = some bytes) :
    bytes.length = expectedPreimageLength := by
  unfold statementPreimage at h
  cases hn : paddedDigests PublicInputs.maxInputs fields.nullifierSeeds with
  | none => simp [hn] at h
  | some nullifiers =>
      cases hc : paddedDigests PublicInputs.maxOutputs fields.commitmentSeeds with
      | none => simp [hn, hc] at h
      | some commitments =>
          cases hct : paddedDigests PublicInputs.maxOutputs fields.ciphertextHashSeeds with
          | none => simp [hn, hc, hct] at h
          | some ciphertextHashes =>
              cases hv : decodeSignedMagnitude fields.valueBalanceSign fields.valueBalanceMagnitude with
              | none => simp [hn, hc, hct, hv] at h
              | some valueBalance =>
                  cases hs :
                      decodeSignedMagnitude
                        fields.stablecoinIssuanceSign
                        fields.stablecoinIssuanceMagnitude with
                  | none => simp [hn, hc, hct, hv, hs] at h
                  | some stablecoinIssuance =>
                      simp [hn, hc, hct, hv, hs] at h
                      rw [← h]
                      have hnLen := paddedDigests_length hn
                      have hcLen := paddedDigests_length hc
                      have hctLen := paddedDigests_length hct
                      simp only [List.length_append, List.length_cons,
                        statementHashDomain_length, digestBytes_length, hnLen, hcLen,
                        hctLen, u16le_length, u32le_length, u64le_length, i128le_length]
                      decide

theorem statementPreimage_accepts_valid :
    (statementPreimage validFields).isSome = true := by
  decide

theorem statementPreimage_valid_length :
    (statementPreimage validFields).map List.length = some expectedPreimageLength := by
  cases h : statementPreimage validFields with
  | none =>
      have accepted := statementPreimage_accepts_valid
      simp [h] at accepted
  | some bytes =>
      simp [statementPreimage_length_of_some h]

theorem statementPreimage_accepts_padded_vectors :
    (statementPreimage paddedFields).map List.length = some expectedPreimageLength := by
  cases h : statementPreimage paddedFields with
  | none =>
      have accepted : (statementPreimage paddedFields).isSome = true := by
        decide
      simp [h] at accepted
  | some bytes =>
      simp [statementPreimage_length_of_some h]

theorem statementPreimage_accepts_stablecoin :
    (statementPreimage stablecoinFields).map List.length = some expectedPreimageLength := by
  cases h : statementPreimage stablecoinFields with
  | none =>
      have accepted : (statementPreimage stablecoinFields).isSome = true := by
        decide
      simp [h] at accepted
  | some bytes =>
      simp [statementPreimage_length_of_some h]

theorem statementPreimage_rejects_too_many_nullifiers :
    statementPreimage { validFields with nullifierSeeds := [1, 2, 3] } = none := by
  decide

theorem statementPreimage_rejects_too_many_commitments :
    statementPreimage { validFields with commitmentSeeds := [1, 2, 3] } = none := by
  decide

theorem statementPreimage_rejects_too_many_ciphertext_hashes :
    statementPreimage { validFields with ciphertextHashSeeds := [1, 2, 3] } = none := by
  decide

theorem statementPreimage_rejects_bad_value_balance_sign :
    statementPreimage { validFields with valueBalanceSign := 2 } = none := by
  decide

theorem statementPreimage_rejects_bad_stablecoin_issuance_sign :
    statementPreimage { stablecoinFields with stablecoinIssuanceSign := 2 } = none := by
  decide

end StatementHash
end Transaction
end Hegemon
