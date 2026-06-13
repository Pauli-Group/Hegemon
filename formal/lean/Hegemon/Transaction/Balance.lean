namespace Hegemon
namespace Transaction

def nativeAsset : Nat := 0
def paddingAsset : Nat := 18446744073709551615
def balanceSlotCount : Nat := 4

structure NoteSummary where
  assetId : Nat
  value : Nat
deriving DecidableEq, Repr

structure BalanceSlot where
  assetId : Nat
  delta : Int
deriving DecidableEq, Repr

structure StablecoinBinding where
  enabled : Bool
  assetId : Nat
  issuanceDelta : Int
  policyVersion : Nat
deriving DecidableEq, Repr

structure BalanceWitness where
  inputs : List NoteSummary
  outputs : List NoteSummary
  fee : Nat
  valueBalance : Int
  stablecoin : StablecoinBinding
deriving DecidableEq, Repr

def paddingSlot : BalanceSlot :=
  { assetId := paddingAsset, delta := 0 }

def intEq (left right : Int) : Bool :=
  if left = right then true else false

def natEq (left right : Nat) : Bool :=
  if left = right then true else false

def insertDelta (assetId : Nat) (delta : Int) : List BalanceSlot -> List BalanceSlot
  | [] => [{ assetId, delta }]
  | slot :: rest =>
      if assetId = slot.assetId then
        { slot with delta := slot.delta + delta } :: rest
      else if assetId < slot.assetId then
        { assetId, delta } :: slot :: rest
      else
        slot :: insertDelta assetId delta rest

def addInput (slots : List BalanceSlot) (note : NoteSummary) : List BalanceSlot :=
  insertDelta note.assetId (Int.ofNat note.value) slots

def addOutput (slots : List BalanceSlot) (note : NoteSummary) : List BalanceSlot :=
  insertDelta note.assetId (-(Int.ofNat note.value)) slots

def containsAsset (assetId : Nat) : List BalanceSlot -> Bool
  | [] => false
  | slot :: rest =>
      if assetId = slot.assetId then true else containsAsset assetId rest

def ensureAsset (assetId : Nat) (slots : List BalanceSlot) : List BalanceSlot :=
  if containsAsset assetId slots then slots else insertDelta assetId 0 slots

def accumulateInputs (slots : List BalanceSlot) (inputs : List NoteSummary) : List BalanceSlot :=
  inputs.foldl addInput slots

def accumulateOutputs (slots : List BalanceSlot) (outputs : List NoteSummary) : List BalanceSlot :=
  outputs.foldl addOutput slots

def unpaddedBalanceSlots (witness : BalanceWitness) : List BalanceSlot :=
  let inputSlots := accumulateInputs [] witness.inputs
  let outputSlots := accumulateOutputs inputSlots witness.outputs
  let withNative := ensureAsset nativeAsset outputSlots
  if witness.stablecoin.enabled then
    ensureAsset witness.stablecoin.assetId withNative
  else
    withNative

def padSlots (slots : List BalanceSlot) : Option (List BalanceSlot) :=
  if slots.length <= balanceSlotCount then
    some (slots ++ List.replicate (balanceSlotCount - slots.length) paddingSlot)
  else
    none

def balanceSlots (witness : BalanceWitness) : Option (List BalanceSlot) :=
  padSlots (unpaddedBalanceSlots witness)

def slotDelta (assetId : Nat) : List BalanceSlot -> Int
  | [] => 0
  | slot :: rest =>
      if assetId = slot.assetId then slot.delta else slotDelta assetId rest

def allNonNativeZero : List BalanceSlot -> Bool
  | [] => true
  | slot :: rest =>
      if slot.assetId = nativeAsset then
        allNonNativeZero rest
      else if slot.assetId = paddingAsset then
        intEq slot.delta 0 && allNonNativeZero rest
      else
        intEq slot.delta 0 && allNonNativeZero rest

def stablecoinZeroed (binding : StablecoinBinding) : Bool :=
  (!binding.enabled)
    && natEq binding.assetId 0
    && intEq binding.issuanceDelta 0
    && natEq binding.policyVersion 0

def stablecoinRules (binding : StablecoinBinding) (slots : List BalanceSlot) : Bool :=
  if binding.enabled then
    (binding.assetId != nativeAsset)
      && (binding.assetId != paddingAsset)
      && intEq (slotDelta binding.assetId slots) binding.issuanceDelta
      && allNonNativeZero
          (slots.map fun slot =>
            if slot.assetId = binding.assetId then
              { slot with delta := 0 }
            else
              slot)
  else
    stablecoinZeroed binding && allNonNativeZero slots

def nativeExpected (witness : BalanceWitness) : Int :=
  Int.ofNat witness.fee - witness.valueBalance

def validBalance (witness : BalanceWitness) : Bool :=
  match balanceSlots witness with
  | none => false
  | some slots =>
      intEq (slotDelta nativeAsset slots) (nativeExpected witness)
        && stablecoinRules witness.stablecoin slots

theorem validBalance_has_slots
    {witness : BalanceWitness} :
    validBalance witness = true ->
    ∃ slots, balanceSlots witness = some slots := by
  intro valid
  unfold validBalance at valid
  split at valid
  · contradiction
  · rename_i slots slotsEq
    exact ⟨slots, slotsEq⟩

theorem validBalance_rejects_slot_overflow
    {witness : BalanceWitness} :
    balanceSlots witness = none ->
    validBalance witness = false := by
  intro overflow
  unfold validBalance
  rw [overflow]

theorem intEq_true_eq {left right : Int} :
    intEq left right = true ->
    left = right := by
  unfold intEq
  split
  · intro _
    assumption
  · intro impossible
    cases impossible

theorem validBalance_native_delta
    {witness : BalanceWitness} {slots : List BalanceSlot} :
    balanceSlots witness = some slots ->
    validBalance witness = true ->
    slotDelta nativeAsset slots = nativeExpected witness := by
  intro slotsEq valid
  unfold validBalance at valid
  rw [slotsEq] at valid
  simp at valid
  exact intEq_true_eq valid.1

theorem validBalance_stablecoin_rules
    {witness : BalanceWitness} {slots : List BalanceSlot} :
    balanceSlots witness = some slots ->
    validBalance witness = true ->
    stablecoinRules witness.stablecoin slots = true := by
  intro slotsEq valid
  unfold validBalance at valid
  rw [slotsEq] at valid
  simp at valid
  exact valid.2

theorem allNonNativeZero_slotDelta_zero
    {slots : List BalanceSlot} {assetId : Nat}
    (nonNative : assetId ≠ nativeAsset)
    (allZero : allNonNativeZero slots = true) :
    slotDelta assetId slots = 0 := by
  induction slots with
  | nil => rfl
  | cons slot rest ih =>
      unfold allNonNativeZero at allZero
      unfold slotDelta
      by_cases hNative : slot.assetId = nativeAsset
      · simp [hNative] at allZero
        by_cases hAsset : assetId = slot.assetId
        · rw [hAsset, hNative] at nonNative
          exact False.elim (nonNative rfl)
        · simp [hAsset]
          exact ih allZero
      · simp [hNative] at allZero
        have slotZero : slot.delta = 0 := intEq_true_eq allZero.1
        have restZero : allNonNativeZero rest = true := allZero.2
        by_cases hAsset : assetId = slot.assetId
        · simp [hAsset, slotZero]
        · simp [hAsset]
          exact ih restZero

theorem slotDelta_zeroSelected_preserves_other
    {slots : List BalanceSlot} {assetId selectedAsset : Nat}
    (other : assetId ≠ selectedAsset) :
    slotDelta assetId
      (slots.map fun slot =>
        if slot.assetId = selectedAsset then
          { slot with delta := 0 }
        else
          slot) =
      slotDelta assetId slots := by
  induction slots with
  | nil => rfl
  | cons slot rest ih =>
      unfold slotDelta
      by_cases selected : slot.assetId = selectedAsset
      · by_cases target : assetId = slot.assetId
        · rw [target, selected] at other
          exact False.elim (other rfl)
        · simp [selected, other, ih]
      · by_cases target : assetId = slot.assetId
        · simp [selected, target]
        · simp [selected, target, ih]

theorem validBalance_no_stablecoin_non_native_delta_zero
    {witness : BalanceWitness} {slots : List BalanceSlot} {assetId : Nat}
    (slotsEq : balanceSlots witness = some slots)
    (valid : validBalance witness = true)
    (stablecoinDisabled : witness.stablecoin.enabled = false)
    (nonNative : assetId ≠ nativeAsset) :
    slotDelta assetId slots = 0 := by
  have rules := validBalance_stablecoin_rules slotsEq valid
  unfold stablecoinRules at rules
  simp [stablecoinDisabled] at rules
  exact allNonNativeZero_slotDelta_zero nonNative rules.right

theorem validBalance_stablecoin_selected_delta
    {witness : BalanceWitness} {slots : List BalanceSlot}
    (slotsEq : balanceSlots witness = some slots)
    (valid : validBalance witness = true)
    (stablecoinEnabled : witness.stablecoin.enabled = true) :
    slotDelta witness.stablecoin.assetId slots =
      witness.stablecoin.issuanceDelta := by
  have rules := validBalance_stablecoin_rules slotsEq valid
  unfold stablecoinRules at rules
  simp [stablecoinEnabled] at rules
  exact intEq_true_eq rules.left.right

theorem validBalance_stablecoin_non_selected_non_native_delta_zero
    {witness : BalanceWitness} {slots : List BalanceSlot} {assetId : Nat}
    (slotsEq : balanceSlots witness = some slots)
    (valid : validBalance witness = true)
    (stablecoinEnabled : witness.stablecoin.enabled = true)
    (nonNative : assetId ≠ nativeAsset)
    (notStablecoin : assetId ≠ witness.stablecoin.assetId) :
    slotDelta assetId slots = 0 := by
  have rules := validBalance_stablecoin_rules slotsEq valid
  unfold stablecoinRules at rules
  simp [stablecoinEnabled] at rules
  have mappedZero :=
    allNonNativeZero_slotDelta_zero
      (slots := slots.map fun slot =>
        if slot.assetId = witness.stablecoin.assetId then
          { slot with delta := 0 }
        else
          slot)
      (assetId := assetId)
      nonNative
      rules.right
  rw [slotDelta_zeroSelected_preserves_other notStablecoin] at mappedZero
  exact mappedZero

end Transaction
end Hegemon
