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

def expectedPreimageLength : Nat := 600

theorem statementPreimage_accepts_valid :
    (statementPreimage validFields).isSome = true := by
  native_decide

theorem statementPreimage_valid_length :
    (statementPreimage validFields).map List.length = some expectedPreimageLength := by
  native_decide

theorem statementPreimage_accepts_padded_vectors :
    (statementPreimage paddedFields).map List.length = some expectedPreimageLength := by
  native_decide

theorem statementPreimage_accepts_stablecoin :
    (statementPreimage stablecoinFields).map List.length = some expectedPreimageLength := by
  native_decide

theorem statementPreimage_rejects_too_many_nullifiers :
    statementPreimage { validFields with nullifierSeeds := [1, 2, 3] } = none := by
  native_decide

theorem statementPreimage_rejects_too_many_commitments :
    statementPreimage { validFields with commitmentSeeds := [1, 2, 3] } = none := by
  native_decide

theorem statementPreimage_rejects_too_many_ciphertext_hashes :
    statementPreimage { validFields with ciphertextHashSeeds := [1, 2, 3] } = none := by
  native_decide

theorem statementPreimage_rejects_bad_value_balance_sign :
    statementPreimage { validFields with valueBalanceSign := 2 } = none := by
  native_decide

theorem statementPreimage_rejects_bad_stablecoin_issuance_sign :
    statementPreimage { stablecoinFields with stablecoinIssuanceSign := 2 } = none := by
  native_decide

end StatementHash
end Transaction
end Hegemon
