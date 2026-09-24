import Std

namespace Hegemon
namespace FullShakeRelation

/-!
The executable semantic core for the prospective V5/Delta full SHAKE256
relation.  This file deliberately models digests as opaque values.  It proves
shape, range, conservation, and state-machine facts; it does not prove SHAKE256
security or equivalence to Rust or M4 code.
-/

abbrev Digest := Nat

def digestBytes : Nat := 56
def canonicalStatementBytes : Nat := 853
def maxInputs : Nat := 2
def maxOutputs : Nat := 2
def balanceSlots : Nat := 4
def maxSigners : Nat := 6
def maxNoteValue : Nat := 2 ^ 61 - 1
def nativeAssetId : Nat := 0

structure Slot2 (alpha : Type) where
  first : alpha
  second : alpha
deriving DecidableEq, Repr

def Slot2.map {alpha beta : Type} (f : alpha -> beta) (slots : Slot2 alpha) : Slot2 beta :=
  { first := f slots.first, second := f slots.second }

def Slot2.any (slots : Slot2 Bool) : Bool :=
  slots.first || slots.second

def Slot2.all (slots : Slot2 Bool) : Bool :=
  slots.first && slots.second

def Slot2.anyBy {alpha : Type} (slots : Slot2 alpha) (predicate : alpha -> Bool) : Bool :=
  predicate slots.first || predicate slots.second

structure ActivityFlags where
  inputs : Slot2 Bool
  outputs : Slot2 Bool
deriving DecidableEq, Repr

def activityAccepted (flags : ActivityFlags) : Bool :=
  flags.inputs.any && flags.outputs.any

structure InputPublicSlot where
  active : Bool
  nullifier : Digest
  inactiveWitnessPayloadZero : Bool
deriving DecidableEq, Repr

structure OutputPublicSlot where
  active : Bool
  commitment : Digest
  ciphertextHash : Digest
  inactiveWitnessPayloadZero : Bool
deriving DecidableEq, Repr

def inputPublicSlotAccepted (slot : InputPublicSlot) : Bool :=
  if slot.active then
    slot.nullifier != 0
  else
    slot.nullifier == 0 && slot.inactiveWitnessPayloadZero

def outputPublicSlotAccepted (slot : OutputPublicSlot) : Bool :=
  if slot.active then
    slot.commitment != 0 && slot.ciphertextHash != 0
  else
    slot.commitment == 0
      && slot.ciphertextHash == 0
      && slot.inactiveWitnessPayloadZero

structure FixedPublicShape where
  inputs : Slot2 InputPublicSlot
  outputs : Slot2 OutputPublicSlot
deriving DecidableEq, Repr

def FixedPublicShape.activity (shape : FixedPublicShape) : ActivityFlags :=
  { inputs := shape.inputs.map InputPublicSlot.active,
    outputs := shape.outputs.map OutputPublicSlot.active }

def fixedPublicShapeAccepted (shape : FixedPublicShape) : Bool :=
  activityAccepted shape.activity
    && inputPublicSlotAccepted shape.inputs.first
    && inputPublicSlotAccepted shape.inputs.second
    && outputPublicSlotAccepted shape.outputs.first
    && outputPublicSlotAccepted shape.outputs.second
    && (!(shape.inputs.first.active && shape.inputs.second.active)
      || shape.inputs.first.nullifier != shape.inputs.second.nullifier)

theorem accepted_fixed_shape_has_input_and_output
    {shape : FixedPublicShape}
    (accepted : fixedPublicShapeAccepted shape = true) :
    activityAccepted shape.activity = true := by
  simp_all [fixedPublicShapeAccepted]

/- Bit order matches the Rust fixture: i0, i1, o0, o1. -/
def flagsFromMask (mask : Nat) : ActivityFlags :=
  { inputs := { first := mask.testBit 0, second := mask.testBit 1 },
    outputs := { first := mask.testBit 2, second := mask.testBit 3 } }

def acceptedMaskCodes : List Nat :=
  (List.range 16).filter (fun mask => activityAccepted (flagsFromMask mask))

def rejectedMaskCodes : List Nat :=
  (List.range 16).filter (fun mask => !(activityAccepted (flagsFromMask mask)))

theorem exact_nine_activity_masks :
    acceptedMaskCodes = [5, 6, 7, 9, 10, 11, 13, 14, 15] := by
  decide

theorem exact_seven_rejected_activity_masks :
    rejectedMaskCodes = [0, 1, 2, 3, 4, 8, 12] := by
  decide

theorem accepted_activity_mask_count : acceptedMaskCodes.length = 9 := by
  decide

theorem rejected_activity_mask_count : rejectedMaskCodes.length = 7 := by
  decide

def duplicateNullifierShape : FixedPublicShape :=
  { inputs :=
      { first := { active := true, nullifier := 7, inactiveWitnessPayloadZero := true },
        second := { active := true, nullifier := 7, inactiveWitnessPayloadZero := true } },
    outputs :=
      { first :=
          { active := true,
            commitment := 8,
            ciphertextHash := 9,
            inactiveWitnessPayloadZero := true },
        second :=
          { active := false,
            commitment := 0,
            ciphertextHash := 0,
            inactiveWitnessPayloadZero := true } } }

theorem duplicate_active_nullifier_rejects :
    fixedPublicShapeAccepted duplicateNullifierShape = false := by
  decide

def inactiveNonzeroNullifierShape : FixedPublicShape :=
  { duplicateNullifierShape with
    inputs :=
      { first := duplicateNullifierShape.inputs.first,
        second :=
          { active := false,
            nullifier := 7,
            inactiveWitnessPayloadZero := true } } }

theorem inactive_nonzero_nullifier_rejects :
    fixedPublicShapeAccepted inactiveNonzeroNullifierShape = false := by
  decide

structure SignedAmount where
  negative : Bool
  magnitude : Nat
deriving DecidableEq, Repr

def signedCanonical (amount : SignedAmount) : Bool :=
  amount.magnitude <= maxNoteValue
    && !(amount.negative && amount.magnitude == 0)

def zeroSignedAmount : SignedAmount :=
  { negative := false, magnitude := 0 }

def valueInRange (value : Nat) : Bool :=
  value <= maxNoteValue

structure BalanceRow where
  input0 : Nat
  input1 : Nat
  output0 : Nat
  output1 : Nat
  expectedDelta : SignedAmount
deriving DecidableEq, Repr

def BalanceRow.inputs (row : BalanceRow) : Nat := row.input0 + row.input1
def BalanceRow.outputs (row : BalanceRow) : Nat := row.output0 + row.output1

def balanceRowAccepted (row : BalanceRow) : Bool :=
  valueInRange row.input0
    && valueInRange row.input1
    && valueInRange row.output0
    && valueInRange row.output1
    && signedCanonical row.expectedDelta
    && if row.expectedDelta.negative then
      row.inputs + row.expectedDelta.magnitude == row.outputs
    else
      row.inputs == row.outputs + row.expectedDelta.magnitude

theorem zero_delta_balance_is_no_mint
    {row : BalanceRow}
    (zeroDelta : row.expectedDelta = zeroSignedAmount)
    (accepted : balanceRowAccepted row = true) :
    row.inputs = row.outputs := by
  unfold balanceRowAccepted at accepted
  rw [zeroDelta] at accepted
  simp_all [zeroSignedAmount]

theorem accepted_balance_values_are_61_bit
    {row : BalanceRow}
    (accepted : balanceRowAccepted row = true) :
    row.input0 <= maxNoteValue
      ∧ row.input1 <= maxNoteValue
      ∧ row.output0 <= maxNoteValue
      ∧ row.output1 <= maxNoteValue := by
  simp_all [balanceRowAccepted, valueInRange]

structure PublicBalanceSurface where
  valueBalance : SignedAmount
  nativeRow : BalanceRow
  stableEnabled : Bool
  stableIssuance : SignedAmount
deriving DecidableEq, Repr

def publicBalanceAccepted (surface : PublicBalanceSurface) : Bool :=
  surface.valueBalance == zeroSignedAmount
    && surface.nativeRow.expectedDelta.negative == false
    && balanceRowAccepted surface.nativeRow
    && signedCanonical surface.stableIssuance
    && ((!surface.stableEnabled && surface.stableIssuance == zeroSignedAmount)
      || (surface.stableEnabled && surface.stableIssuance.magnitude != 0))

theorem accepted_public_balance_has_zero_value_balance
    {surface : PublicBalanceSurface}
    (accepted : publicBalanceAccepted surface = true) :
    surface.valueBalance = zeroSignedAmount := by
  simp_all [publicBalanceAccepted]

theorem enabled_stable_issuance_is_nonzero
    {surface : PublicBalanceSurface}
    (accepted : publicBalanceAccepted surface = true)
    (enabled : surface.stableEnabled = true) :
    surface.stableIssuance.magnitude != 0 := by
  simp_all [publicBalanceAccepted]

def negativeZero : SignedAmount :=
  { negative := true, magnitude := 0 }

theorem negative_zero_is_not_canonical : signedCanonical negativeZero = false := by
  decide

end FullShakeRelation
end Hegemon
