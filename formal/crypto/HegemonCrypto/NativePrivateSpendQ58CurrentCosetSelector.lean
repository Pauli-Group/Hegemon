import HegemonCrypto.NativePrivateSpendQ58CurrentChronologicalRequest
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset

/-! Current descriptor search and selected-target certificate. The source
checks each candidate against all13173 interpolation coordinates and returns
only a passing descriptor. This finite success guard, not a supplied rank or
uniformity assertion, certifies the current58-target continuation. No claim
that historical shift388 is the current descriptor is made. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCosetSelector
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom
open V8Smz9HonestOpeningSchedule NativePrivateSpendQ58CurrentChronologicalRequest
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev Index := V8Smz9HiddenPatch.LeafIndex

/-- Equivalent field predicate checked by the source's ratio-to-subgroup
test: the shift is nonzero and its domain power differs from every ordinary
interpolation coordinate. Zero is also included, and is automatically safe. -/
def acceptsShift (shift : Goldilocks) : Prop :=
  shift ≠ 0 ∧ ∀ node : Fin 13173,
    (node.val : Goldilocks) ^ 8388608 ≠ shift ^ 8388608

abbrev Descriptor := { shift : Goldilocks // acceptsShift shift }

def descriptorSearch : List Nat → Option Descriptor
  | [] => none
  | candidate :: rest =>
      if accepted : acceptsShift (candidate : Goldilocks) then
        some ⟨candidate, accepted⟩
      else descriptorSearch rest

/-- Literal current source start and4096-candidate limit. A failed search
remains an error; the proof never assumes that a particular candidate passes. -/
def currentDescriptor : Option Descriptor :=
  descriptorSearch ((List.range 4096).map (fun offset => 13173 + offset))

def pointForIndex (descriptor : Descriptor) (index : Index) : Goldilocks :=
  descriptor.val * V8Smz9DisjointCoset.radix2Root ^ index.val

theorem current_points_distinct (descriptor : Descriptor) :
    Function.Injective (pointForIndex descriptor) := by
  intro left right same
  have powers : V8Smz9DisjointCoset.radix2Root ^ left.val =
      V8Smz9DisjointCoset.radix2Root ^ right.val :=
    mul_left_cancel₀ descriptor.property.1 same
  have finiteOrder : IsOfFinOrder V8Smz9DisjointCoset.radix2Root :=
    isOfFinOrder_iff_pow_eq_one.mpr
      ⟨V8Smz9DisjointCoset.domainSize, by decide,
        V8Smz9DisjointCoset.radix2_root_pow_domain⟩
  have remainders := (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp powers
  rw [V8Smz9DisjointCoset.radix2_root_order] at remainders
  change left.val % 8388608 = right.val % 8388608 at remainders
  rw [Nat.mod_eq_of_lt left.isLt, Nat.mod_eq_of_lt right.isLt] at remainders
  exact Fin.ext remainders

theorem current_point_power (descriptor : Descriptor) (index : Index) :
    pointForIndex descriptor index ^ 8388608 = descriptor.val ^ 8388608 := by
  have rootPower : (V8Smz9DisjointCoset.radix2Root ^ index.val) ^ 8388608 = 1 := by
    rw [← pow_mul, Nat.mul_comm, pow_mul]
    change (V8Smz9DisjointCoset.radix2Root ^ V8Smz9DisjointCoset.domainSize) ^ index.val = 1
    rw [V8Smz9DisjointCoset.radix2_root_pow_domain, one_pow]
  rw [pointForIndex, mul_pow, rootPower, mul_one]

theorem current_points_outside (descriptor : Descriptor) (index : Index) (node : Fin 13173) :
    pointForIndex descriptor index ≠ (node.val : Goldilocks) := by
  intro same
  have powered := congrArg (fun value : Goldilocks => value ^ 8388608) same
  rw [current_point_power] at powered
  exact descriptor.property.2 node powered.symm

theorem current_index_collection_nodup (candidates : List FieldWord) (selected : List Index)
    (nodup : selected.Nodup) : (collectCurrentIndices candidates selected).Nodup := by
  induction candidates generalizing selected with
  | nil => exact nodup
  | cons candidate rest ih =>
      simp only [collectCurrentIndices]
      split
      · exact nodup
      · split
        · split
          · exact ih _ nodup
          · exact ih _ (List.Nodup.concat (by assumption) nodup)
        · exact ih _ nodup

theorem current_sorted_indices_nodup (candidates : List FieldWord) :
    (sortedCurrentIndices candidates).Nodup :=
  (current_index_collection_nodup candidates [] (by simp)).mergeSort

/-- Success produces an injective vector of EXACTLY the actual sorted first58
indices. Failure staysNone, including deterministic field-poison candidates. -/
def selectedCertificate (candidates : List FieldWord) :
    Option { indices : Fin 58 → Index // Function.Injective indices } :=
  let indices := sortedCurrentIndices candidates
  if enough : indices.length = 58 then
    let selected : Fin 58 → Index := fun index => indices.get (index.cast enough.symm)
    some ⟨selected, by
      intro left right same
      have equal := (current_sorted_indices_nodup candidates).injective_get same
      exact Fin.ext (congrArg (fun index : Fin indices.length => index.val) equal)⟩
  else none

theorem certificate_has_actual_indices (candidates : List FieldWord) :
    (selectedCertificate candidates).map Subtype.val = selectedCurrentIndices candidates := by
  unfold selectedCertificate selectedCurrentIndices
  dsimp only
  split <;> rfl

def selectedTargets (descriptor : Descriptor)
    (selected : { indices : Fin 58 → Index // Function.Injective indices }) :
    NativePrivateSpendQ58Compff01OpeningContinuation.Targets :=
  ⟨fun opening => pointForIndex descriptor (selected.val opening),
    ⟨(current_points_distinct descriptor).comp selected.property,
      fun opening node => current_points_outside descriptor (selected.val opening) node⟩⟩

/-- A total public fallback is used ONLY to totalize an invertible fiber on
DECS exhaustion. That branch still returns the original error and no leaves. -/
def fallbackTargets (descriptor : Descriptor) :
    NativePrivateSpendQ58Compff01OpeningContinuation.Targets :=
  selectedTargets descriptor ⟨fun index => ⟨index.val, index.isLt.trans_le (by decide)⟩,
    by intro left right same; exact Fin.ext (congrArg (@Fin.val 8388608) same)⟩

theorem current_opening_transition (bound : Nat) (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonce : Fin 16) (nonces : List (Fin 16))
    (oracle : NativePrivateSpendQ58CurrentLeafInput.CurrentOtherRawInput bound → DigestRegister) :
    V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle (currentChooseOpeningLoop bound largeEnough digest pending (nonce :: nonces)) =
      let sampled := V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle (currentOpeningXof bound largeEnough nonce digest)
      let words := sourceReturnedWords 6 sampled
      let failed := sourcePendingFailure pending sampled
      if currentOpeningValid words then
        ⟨some (nonce, words), sourcePendingFailure failed sampled⟩
      else V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle (currentChooseOpeningLoop bound largeEnough digest failed nonces) := by
  simp only [currentChooseOpeningLoop, V8Smz9HonestRequestSchedule.NonleafProgram.interpret_bind]
  split
  · rw [V8Smz9HonestRequestSchedule.NonleafProgram.interpret_bind]
    rfl
  · rfl

theorem current_selected_opening_loop_valid (bound : Nat) (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonces : List (Fin 16))
    (oracle : NativePrivateSpendQ58CurrentLeafInput.CurrentOtherRawInput bound → DigestRegister)
    (nonce : Fin 16) (words : List FieldWord)
    (selected : (V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle
      (currentChooseOpeningLoop bound largeEnough digest pending nonces)).selected = some (nonce, words)) :
    currentOpeningValid words = true := by
  induction nonces generalizing pending with
  | nil => simp only [currentChooseOpeningLoop, V8Smz9HonestRequestSchedule.NonleafProgram.interpret] at selected; cases selected
  | cons attempt rest ih =>
      rw [current_opening_transition] at selected
      dsimp only at selected
      split at selected
      · rename_i valid
        have pair := Option.some.inj selected
        have equal := congrArg Prod.snd pair
        dsimp only at equal
        rw [← equal]
        exact valid
      · exact ih _ selected

theorem current_selected_opening_valid (bound : Nat) (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : NativePrivateSpendQ58CurrentLeafInput.CurrentOtherRawInput bound → DigestRegister)
    (nonce : Fin 16) (words : List FieldWord)
    (selected : (V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle
      (currentChooseOpening bound largeEnough digest pending)).selected = some (nonce, words)) :
    words.length = 6 ∧ currentOpeningAdmissible (sourcePointVector words) := by
  have valid := current_selected_opening_loop_valid bound largeEnough digest pending _ oracle nonce words selected
  simpa only [currentOpeningValid, decide_eq_true_eq] using valid

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCosetSelector
