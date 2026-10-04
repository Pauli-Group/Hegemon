import SmzaRp05SupplyClosureDistinctInputs
import SmzaRp05SupplyClosureOutputs

/-! Exact two-slot expansion of the existing typed native balance view.
The public flags are read from the canonical encoded statement, not supplied
as a separate input-value realization premise. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs (outputOpenings activeOutputSlots)
open SmzaFiniteLedgerSupply (nativeValue)
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameSource
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldSub)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)

set_option autoImplicit false
set_option maxRecDepth 10000

def inputSlotNative (statement : V8PublicStatement) (packed : List Nat)
    (input : Fin 2) : Nat :=
  if flagAt statement.inputFlags input.val = 1 then
    nativeValue (projectNote packed (noteCall input)) else 0

theorem input_native_two_slots (statement : V8PublicStatement) (packed : List Nat) :
    inputNative statement packed =
      inputSlotNative statement packed 0 + inputSlotNative statement packed 1 := by
  simp only [inputNative, typedWitness, SmzaRp05BalanceCore.projectTypedWitness,
    inputValueForAsset, SmzaRp05BalanceCore.projectInput,
    V8Smz9SemanticDecoder.projectInput,
    SmzaRp05BalanceCore.noteCall, inputSlotNative, noteCall, nativeValue,
    flagAt, nativeAssetId,
    List.range_succ, List.range_zero, List.map_append, List.map_nil,
    List.map_cons, List.foldl_append, List.foldl_nil, List.foldl_cons,
    List.getD_cons_zero, List.getD_cons_succ]
  simp only [Fin.val_zero, Fin.val_one, ↓reduceIte, Nat.zero_add]
  by_cases leftActive : statement.inputFlags.getD 0 0 = 1 <;>
    by_cases rightActive : statement.inputFlags.getD 1 0 = 1 <;>
    by_cases leftNative : (projectNote packed 1).assetId = 0 <;>
    by_cases rightNative : (projectNote packed 38).assetId = 0 <;>
    simp_all

theorem positive_input_slot_active (statement : V8PublicStatement) (packed : List Nat)
    (input : Fin 2) (positive : 0 < inputSlotNative statement packed input) :
    flagAt statement.inputFlags input.val = 1 := by
  by_contra inactive
  simp [inputSlotNative, inactive] at positive

theorem active_input_slot_native (statement : V8PublicStatement) (packed : List Nat)
    (input : Fin 2) (active : flagAt statement.inputFlags input.val = 1) :
    inputSlotNative statement packed input =
      nativeValue (projectNote packed (noteCall input)) := by
  simp [inputSlotNative, active]

theorem positive_input_slot_public_active
    (statement : V8PublicStatement) (packed : List Nat)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (input : Fin 2) (positive : 0 < inputSlotNative statement packed input) :
    (encodePublicStatement statement).getD input.val 0 = 1 := by
  rw [V8Smz9SemanticAssetMembership.encoded_input_flag statement canonical input.isLt]
  exact positive_input_slot_active statement packed input positive

theorem slot_native_from_equal_words
    (statement : V8PublicStatement) (packed : List Nat) (input : Fin 2)
    (opening : V8NoteOpening)
    (same : exactV8NoteWords (projectNote packed (noteCall input)) =
      exactV8NoteWords opening) :
    inputSlotNative statement packed input ≤ nativeValue opening := by
  unfold inputSlotNative
  split
  · exact Nat.le_of_eq (SmzaFiniteLedgerSupply.note_words_preserve_native same)
  · exact Nat.zero_le _

def noteOwnerWord (limb : Fin 7) : Nat :=
  if limb.val < 4 then 14 + limb.val else 10 + (limb.val - 4)

/-- The seven owner-vector words are copied into the actual note sponge.
These are the existing fourteen input frame rows, not an owner-binding
assumption supplied to the cross-transaction freshness proof. -/
theorem accepted_input_owner_source {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7) :
    spongeSourceWord packed (noteCall input) (noteOwnerWord limb) =
      packed.getD ((95 + input.val) * 64 + limb.val) 0 := by
  let cell : NoteCell := (input,
    ⟨noteOwnerWord limb / 8, by fin_cases limb <;> decide⟩,
    ⟨noteOwnerWord limb % 8, by omega⟩)
  have bound : boundCell cell := by
    dsimp only [cell]
    fin_cases input <;> fin_cases limb <;> decide
  have source : sourceIndex cell = some ((95 + input.val) * 64 + limb.val) := by
    dsimp only [cell]
    fin_cases input <;> fin_cases limb <;> rfl
  have constant : expectedConstant cell = 0 := by fin_cases limb <;> rfl
  have notFirst : cell.2.1.val ≠ 0 := by
    dsimp only [cell]
    fin_cases input <;> fin_cases limb <;> decide
  have equation := accepted_cell_field SmzaRp05NoteFrameInstance.certificate
    accepted cell bound
  rw [source, constant, if_neg notFirst] at equation
  dsimp only at equation
  have previousBound := packed_word_canonical accepted.2.1
    (hashFinalIndex (noteCall input + cell.2.1.val - 1) cell.2.2.val)
  have subtractBound :
      packed.getD (hashFinalIndex (noteCall input + cell.2.1.val - 1) cell.2.2.val) 0 ≤
      packed.getD (hashInitialIndex (noteCall input + cell.2.1.val) cell.2.2.val) 0 +
        fieldModulus := by
    change packed.getD _ 0 < fieldModulus at previousBound
    omega
  apply canonical_nat_cast_injective
    (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  simp only [spongeSourceWord,
    if_neg (show noteOwnerWord limb / 8 ≠ 0 from notFirst)]
  change (fieldSub
    (packed.getD (hashInitialIndex (noteCall input + cell.2.1.val) cell.2.2.val) 0)
    (packed.getD (hashFinalIndex (noteCall input + cell.2.1.val - 1) cell.2.2.val) 0) :
      Goldilocks) = _
  rw [field_sub_cast _ _ subtractBound]
  simp only [V8Smz9SemanticDecoder.packedWord]
  linear_combination equation

theorem equal_projected_note_words_coordinate
    {left right : List Nat} (leftCall rightCall : Nat)
    (same : exactV8NoteWords (projectNote left leftCall) =
      exactV8NoteWords (projectNote right rightCall))
    (word : Nat) (bound : word < 18) :
    spongeSourceWord left leftCall word = spongeSourceWord right rightCall word := by
  have equality := congrArg (fun words : List Nat => words.getD word 0) same
  change (((List.range 18).map (spongeSourceWord left leftCall)).getD word 0) =
    (((List.range 18).map (spongeSourceWord right rightCall)).getD word 0) at equality
  simpa [List.getD_eq_getElem?_getD, bound] using equality

theorem same_accepted_note_owner_words
    {leftPublic leftPacked rightPublic rightPacked : List Nat}
    (leftAccepted : program.AcceptsPacked leftPublic leftPacked)
    (rightAccepted : program.AcceptsPacked rightPublic rightPacked)
    (leftInput rightInput : Fin 2)
    (same : exactV8NoteWords (projectNote leftPacked (noteCall leftInput)) =
      exactV8NoteWords (projectNote rightPacked (noteCall rightInput))) (limb : Fin 7) :
    leftPacked.getD ((95 + leftInput.val) * 64 + limb.val) 0 =
      rightPacked.getD ((95 + rightInput.val) * 64 + limb.val) 0 := by
  rw [← accepted_input_owner_source leftAccepted leftInput limb,
    ← accepted_input_owner_source rightAccepted rightInput limb]
  exact equal_projected_note_words_coordinate _ _ same (noteOwnerWord limb)
    (by unfold noteOwnerWord; split_ifs <;> omega)

theorem output_native_two_slots (statement : V8PublicStatement) (packed : List Nat) :
    outputNative statement packed =
      (if flagAt statement.outputFlags 0 = 1 then nativeValue (projectNote packed 75) else 0) +
      (if flagAt statement.outputFlags 1 = 1 then nativeValue (projectNote packed 78) else 0) := by
  simp only [outputNative, typedWitness, SmzaRp05BalanceCore.projectTypedWitness,
    outputValueForAsset, SmzaRp05BalanceCore.projectOutput,
    V8Smz9SemanticDecoder.projectOutput,
    SmzaRp05BalanceCore.noteCall, nativeValue,
    flagAt, nativeAssetId,
    List.range_succ, List.range_zero, List.map_append, List.map_nil,
    List.map_cons, List.foldl_append, List.foldl_nil, List.foldl_cons,
    List.getD_cons_zero, List.getD_cons_succ, Nat.reduceAdd]
  simp only [Nat.zero_add]
  split_ifs <;> omega

/-- The ordered extracted output log carries exactly the typed native
output sum; duplicate commitment values remain distinct appended positions. -/
theorem accepted_output_stream_native (statement : V8PublicStatement) (packed : List Nat)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    ((outputOpenings (encodePublicStatement statement) packed).map nativeValue).sum =
      outputNative statement packed := by
  have flag0 := V8Smz9SemanticAssetMembership.encoded_output_flag
    statement canonical (output := 0) (by decide)
  have flag1 := V8Smz9SemanticAssetMembership.encoded_output_flag
    statement canonical (output := 1) (by decide)
  rw [output_native_two_slots]
  simp only [outputOpenings, activeOutputSlots, List.filter_cons, List.filter_nil]
  simp only [flag0, flag1]
  split_ifs <;> simp_all [SmzaRp05SupplyClosureOutputFrame.noteCall]

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
