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

end Transaction
end Hegemon
