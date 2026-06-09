namespace Hegemon
namespace Transaction
namespace PublicInputs

def maxInputs : Nat := 2
def maxOutputs : Nat := 2
def balanceSlotCount : Nat := 4
def nativeAsset : Nat := 0
def paddingAsset : Nat := 18446744073709551615

abbrev Digest := Nat

def isBoolFlag (value : Nat) : Bool :=
  value = 0 || value = 1

def isZeroDigest (value : Digest) : Bool :=
  value = 0

def validInputSlot (flag : Nat) (nullifier : Digest) : Bool :=
  isBoolFlag flag
    && ((flag = 0 && isZeroDigest nullifier) || (flag = 1 && !isZeroDigest nullifier))

def validOutputSlot (flag : Nat) (commitment ciphertextHash : Digest) : Bool :=
  isBoolFlag flag
    && ((flag = 0 && isZeroDigest commitment && isZeroDigest ciphertextHash)
      || (flag = 1 && !isZeroDigest commitment))

def allInputsValid : List Nat -> List Digest -> Bool
  | [], [] => true
  | flag :: flags, nullifier :: nullifiers =>
      validInputSlot flag nullifier && allInputsValid flags nullifiers
  | _, _ => false

def allOutputsValid : List Nat -> List Digest -> List Digest -> Bool
  | [], [], [] => true
  | flag :: flags, commitment :: commitments, ciphertextHash :: ciphertextHashes =>
      validOutputSlot flag commitment ciphertextHash
        && allOutputsValid flags commitments ciphertextHashes
  | _, _, _ => false

def nonZeroExists : List Digest -> Bool
  | [] => false
  | value :: rest => !isZeroDigest value || nonZeroExists rest

def balanceSlotsOrdered : List Nat -> Bool
  | first :: rest =>
      if first != nativeAsset then
        false
      else
        let rec go (previous : Nat) (sawPadding : Bool) : List Nat -> Bool
          | [] => true
          | asset :: more =>
              if asset = paddingAsset then
                go previous true more
              else if sawPadding then
                false
              else if asset = nativeAsset || asset <= previous then
                false
              else
                go asset false more
        go nativeAsset false rest
  | [] => false

structure PublicInputShape where
  inputFlags : List Nat
  outputFlags : List Nat
  nullifiers : List Digest
  commitments : List Digest
  ciphertextHashes : List Digest
  balanceSlotAssets : List Nat
  valueBalanceSign : Nat
  stablecoinEnabled : Nat
  stablecoinAsset : Nat
  stablecoinIssuanceSign : Nat
deriving DecidableEq, Repr

def stablecoinAssetPresent (shape : PublicInputShape) : Bool :=
  shape.balanceSlotAssets.drop 1 |>.any fun asset => asset = shape.stablecoinAsset

def validPublicInputShape (shape : PublicInputShape) : Bool :=
  shape.inputFlags.length = maxInputs
    && shape.outputFlags.length = maxOutputs
    && shape.nullifiers.length = maxInputs
    && shape.commitments.length = maxOutputs
    && shape.ciphertextHashes.length = maxOutputs
    && shape.balanceSlotAssets.length = balanceSlotCount
    && balanceSlotsOrdered shape.balanceSlotAssets
    && allInputsValid shape.inputFlags shape.nullifiers
    && allOutputsValid shape.outputFlags shape.commitments shape.ciphertextHashes
    && (nonZeroExists shape.nullifiers || nonZeroExists shape.commitments)
    && isBoolFlag shape.valueBalanceSign
    && isBoolFlag shape.stablecoinEnabled
    && isBoolFlag shape.stablecoinIssuanceSign
    && (shape.stablecoinEnabled = 0 || stablecoinAssetPresent shape)

def validShape : PublicInputShape :=
  { inputFlags := [1, 0]
    outputFlags := [1, 0]
    nullifiers := [11, 0]
    commitments := [22, 0]
    ciphertextHashes := [33, 0]
    balanceSlotAssets := [0, 7, paddingAsset, paddingAsset]
    valueBalanceSign := 0
    stablecoinEnabled := 0
    stablecoinAsset := 0
    stablecoinIssuanceSign := 0 }

theorem validPublicInputShape_accepts_valid :
    validPublicInputShape validShape = true := by
  decide

theorem validPublicInputShape_rejects_bad_input_flag :
    validPublicInputShape { validShape with inputFlags := [2, 0] } = false := by
  decide

theorem validPublicInputShape_rejects_inactive_input_nonzero :
    validPublicInputShape { validShape with inputFlags := [0, 0], nullifiers := [11, 0] } = false := by
  decide

theorem validPublicInputShape_rejects_active_input_zero :
    validPublicInputShape { validShape with inputFlags := [1, 0], nullifiers := [0, 0] } = false := by
  decide

theorem validPublicInputShape_rejects_inactive_output_nonzero_commitment :
    validPublicInputShape { validShape with outputFlags := [0, 0], commitments := [22, 0] } = false := by
  decide

theorem validPublicInputShape_rejects_empty_transaction :
    validPublicInputShape { validShape with inputFlags := [0, 0], outputFlags := [0, 0], nullifiers := [0, 0], commitments := [0, 0], ciphertextHashes := [0, 0] } = false := by
  decide

theorem validPublicInputShape_rejects_bad_slot_zero :
    validPublicInputShape { validShape with balanceSlotAssets := [1, 7, paddingAsset, paddingAsset] } = false := by
  decide

theorem validPublicInputShape_rejects_padding_not_suffix :
    validPublicInputShape { validShape with balanceSlotAssets := [0, paddingAsset, 7, paddingAsset] } = false := by
  decide

theorem validPublicInputShape_rejects_duplicate_asset :
    validPublicInputShape { validShape with balanceSlotAssets := [0, 7, 7, paddingAsset] } = false := by
  decide

theorem validPublicInputShape_rejects_stablecoin_missing_asset :
    validPublicInputShape { validShape with stablecoinEnabled := 1, stablecoinAsset := 42 } = false := by
  decide

theorem validPublicInputShape_accepts_stablecoin_present :
    validPublicInputShape { validShape with stablecoinEnabled := 1, stablecoinAsset := 7 } = true := by
  decide

end PublicInputs
end Transaction
end Hegemon
