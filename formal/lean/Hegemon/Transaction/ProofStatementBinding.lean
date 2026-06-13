import Hegemon.Bytes
import Hegemon.Transaction.PublicInputs

set_option maxRecDepth 10000

namespace Hegemon
namespace Transaction
namespace ProofStatementBinding

open Hegemon.Transaction.PublicInputs

def digestWidth : Nat := 48
def bindingHashDomain : List Byte := asciiBytes "binding-hash-v3"

structure BindingFields where
  anchorSeed : Nat
  nullifierSeeds : List Nat
  commitmentSeeds : List Nat
  ciphertextHashSeeds : List Nat
  fee : Nat
  valueBalance : Int
  balanceSlotAssets : List Nat
  stablecoinEnabled : Bool
  stablecoinAsset : Nat
  stablecoinPolicyHashSeed : Nat
  stablecoinOracleCommitmentSeed : Nat
  stablecoinAttestationCommitmentSeed : Nat
  stablecoinIssuanceDelta : Int
  stablecoinPolicyVersion : Nat
deriving DecidableEq, Repr

def digestBytes (seed : Nat) : List Byte :=
  patternedBytes digestWidth seed

def zeroDigestBytes : List Byte :=
  List.replicate digestWidth 0

def digestSeedsBytes : List Nat -> List Byte
  | [] => []
  | seed :: rest => digestBytes seed ++ digestSeedsBytes rest

def i128le (value : Int) : List Byte :=
  let encoded :=
    if value < 0 then
      2 ^ 128 - Int.natAbs value
    else
      Int.toNat value
  u128le encoded

def boolByte (value : Bool) : Byte :=
  if value then 1 else 0

def assetBytes : List Nat -> List Byte
  | [] => []
  | asset :: rest => u64le asset ++ assetBytes rest

def bindingMessage (fields : BindingFields) : Option (List Byte) :=
  if fields.balanceSlotAssets.length = balanceSlotCount then
    some <|
      digestBytes fields.anchorSeed
        ++ u32le fields.nullifierSeeds.length
        ++ digestSeedsBytes fields.nullifierSeeds
        ++ u32le fields.commitmentSeeds.length
        ++ digestSeedsBytes fields.commitmentSeeds
        ++ u32le fields.ciphertextHashSeeds.length
        ++ digestSeedsBytes fields.ciphertextHashSeeds
        ++ u64le fields.fee
        ++ i128le fields.valueBalance
        ++ assetBytes fields.balanceSlotAssets
        ++ [boolByte fields.stablecoinEnabled]
        ++ u64le (if fields.stablecoinEnabled then fields.stablecoinAsset else 0)
        ++ (if fields.stablecoinEnabled then
              digestBytes fields.stablecoinPolicyHashSeed
            else
              zeroDigestBytes)
        ++ (if fields.stablecoinEnabled then
              digestBytes fields.stablecoinOracleCommitmentSeed
            else
              zeroDigestBytes)
        ++ (if fields.stablecoinEnabled then
              digestBytes fields.stablecoinAttestationCommitmentSeed
            else
              zeroDigestBytes)
        ++ i128le (if fields.stablecoinEnabled then fields.stablecoinIssuanceDelta else 0)
        ++ u32le (if fields.stablecoinEnabled then fields.stablecoinPolicyVersion else 0)
  else
    none

def bindingHashPreimage (chunk : Nat) (message : List Byte) : List Byte :=
  bindingHashDomain ++ [byte chunk] ++ message

def validFields : BindingFields :=
  { anchorSeed := 10
    nullifierSeeds := [20]
    commitmentSeeds := [30]
    ciphertextHashSeeds := [40]
    fee := 72623859790382856
    valueBalance := -5
    balanceSlotAssets := [0, 7, paddingAsset, paddingAsset]
    stablecoinEnabled := false
    stablecoinAsset := 0
    stablecoinPolicyHashSeed := 0
    stablecoinOracleCommitmentSeed := 0
    stablecoinAttestationCommitmentSeed := 0
    stablecoinIssuanceDelta := 0
    stablecoinPolicyVersion := 0 }

def stablecoinFields : BindingFields :=
  { validFields with
    stablecoinEnabled := true
    stablecoinAsset := 7
    stablecoinPolicyHashSeed := 60
    stablecoinOracleCommitmentSeed := 61
    stablecoinAttestationCommitmentSeed := 62
    stablecoinIssuanceDelta := -13
    stablecoinPolicyVersion := 4 }

def fieldPaddingCollisionFields : BindingFields :=
  { validFields with
    balanceSlotAssets := [0, 4294967294, paddingAsset, paddingAsset] }

def expectedValidMessageLength : Nat := 433
def expectedValidBindingHashPreimageLength : Nat := 449

theorem bindingHashDomain_length : bindingHashDomain.length = 15 := by
  decide

theorem bindingHashPreimage_valid_chunk0_length :
    (bindingMessage validFields).map (fun message => (bindingHashPreimage 0 message).length) =
      some expectedValidBindingHashPreimageLength := by
  decide

theorem bindingHashPreimage_valid_chunk1_length :
    (bindingMessage validFields).map (fun message => (bindingHashPreimage 1 message).length) =
      some expectedValidBindingHashPreimageLength := by
  decide

theorem bindingMessage_accepts_valid :
    (bindingMessage validFields).map List.length = some expectedValidMessageLength := by
  decide

theorem bindingMessage_accepts_stablecoin :
    (bindingMessage stablecoinFields).map List.length = some expectedValidMessageLength := by
  decide

theorem bindingMessage_rejects_bad_balance_slot_count :
    bindingMessage { validFields with balanceSlotAssets := [0, 7, paddingAsset] } = none := by
  decide

theorem bindingMessage_distinguishes_field_padding_collision_from_padding :
    (bindingMessage fieldPaddingCollisionFields != bindingMessage validFields) = true := by
  decide

theorem bindingHashPreimage_chunks_are_domain_separated :
    (bindingMessage validFields).map
        (fun message => bindingHashPreimage 0 message != bindingHashPreimage 1 message) =
      some true := by
  decide

end ProofStatementBinding
end Transaction
end Hegemon
