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

def OutputSlotAt :
    List Nat -> List Digest -> List Digest ->
      Nat -> Nat -> Digest -> Digest -> Prop
  | flag :: _, commitment :: _, ciphertextHash :: _, 0, activeFlag,
      publicCommitment, publicCiphertextHash =>
      activeFlag = flag
        ∧ publicCommitment = commitment
        ∧ publicCiphertextHash = ciphertextHash
  | _ :: flags, _ :: commitments, _ :: ciphertextHashes, index + 1,
      activeFlag, publicCommitment, publicCiphertextHash =>
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
  | _, _, _, _, _, _, _ => False

def OutputSlotFacts
    (activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest) : Prop :=
  (activeFlag = 1 -> publicCommitment ≠ 0)
    ∧ (activeFlag = 0 -> publicCommitment = 0 ∧ publicCiphertextHash = 0)
    ∧ (activeFlag = 0 ∨ activeFlag = 1)

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

theorem validOutputSlot_implies_output_slot_facts
    {activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (valid :
      validOutputSlot
        activeFlag
        publicCommitment
        publicCiphertextHash = true) :
    OutputSlotFacts
      activeFlag
      publicCommitment
      publicCiphertextHash := by
  unfold validOutputSlot isBoolFlag isZeroDigest at valid
  unfold OutputSlotFacts
  by_cases inactive : activeFlag = 0
  · simp [inactive] at valid ⊢
    exact valid
  · by_cases active : activeFlag = 1
    · simp [active] at valid ⊢
      intro zeroCommitment
      exact valid zeroCommitment
    · simp [inactive, active] at valid

theorem allOutputsValid_head_facts
    {flag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    (valid :
      allOutputsValid
        (flag :: flags)
        (publicCommitment :: commitments)
        (publicCiphertextHash :: ciphertextHashes) = true) :
    OutputSlotFacts flag publicCommitment publicCiphertextHash := by
  unfold allOutputsValid at valid
  simp at valid
  exact validOutputSlot_implies_output_slot_facts valid.left

theorem allOutputsValid_tail_valid
    {flag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    (valid :
      allOutputsValid
        (flag :: flags)
        (publicCommitment :: commitments)
        (publicCiphertextHash :: ciphertextHashes) = true) :
    allOutputsValid flags commitments ciphertextHashes = true := by
  unfold allOutputsValid at valid
  simp at valid
  exact valid.right

theorem allOutputsValid_output_slot_facts_at
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash)
    (valid :
      allOutputsValid flags commitments ciphertextHashes = true) :
    OutputSlotFacts
      activeFlag
      publicCommitment
      publicCiphertextHash := by
  induction flags generalizing commitments ciphertextHashes index activeFlag
      publicCommitment publicCiphertextHash with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases index <;>
        simp [OutputSlotAt] at slot
  | cons headFlag tailFlags ih =>
      cases commitments with
      | nil =>
          cases ciphertextHashes <;> cases index <;> simp [OutputSlotAt] at slot
      | cons headCommitment tailCommitments =>
          cases ciphertextHashes with
          | nil =>
              cases index <;> simp [OutputSlotAt] at slot
          | cons headCiphertextHash tailCiphertextHashes =>
              cases index with
              | zero =>
                  simp [OutputSlotAt] at slot
                  rcases slot with
                    ⟨hflag, hcommitment, hciphertextHash⟩
                  subst activeFlag
                  subst publicCommitment
                  subst publicCiphertextHash
                  exact allOutputsValid_head_facts valid
              | succ tailIndex =>
                  exact
                    ih
                      slot
                      (allOutputsValid_tail_valid valid)

theorem validPublicInputShape_output_slot_facts_at
    {shape : PublicInputShape}
    {index activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (valid : validPublicInputShape shape = true)
    (slot :
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash) :
    OutputSlotFacts
      activeFlag
      publicCommitment
      publicCiphertextHash := by
  cases shape with
  | mk inputFlags outputFlags nullifiers commitments ciphertextHashes
      balanceSlotAssets valueBalanceSign stablecoinEnabled stablecoinAsset
      stablecoinIssuanceSign =>
  unfold validPublicInputShape at valid
  have beforeStablecoinPresent := (Bool.and_eq_true_iff.mp valid).left
  have beforeStablecoinIssuanceSign :=
    (Bool.and_eq_true_iff.mp beforeStablecoinPresent).left
  have beforeStablecoinEnabled :=
    (Bool.and_eq_true_iff.mp beforeStablecoinIssuanceSign).left
  have beforeValueBalanceSign :=
    (Bool.and_eq_true_iff.mp beforeStablecoinEnabled).left
  have beforeNonzeroExists :=
    (Bool.and_eq_true_iff.mp beforeValueBalanceSign).left
  have outputsValid :=
    (Bool.and_eq_true_iff.mp beforeNonzeroExists).right
  exact
    allOutputsValid_output_slot_facts_at
      slot
      outputsValid

end PublicInputs
end Transaction
end Hegemon
