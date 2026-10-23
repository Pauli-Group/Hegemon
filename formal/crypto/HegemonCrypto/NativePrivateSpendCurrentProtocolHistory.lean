import HegemonCrypto.NativePrivateSpendCurrentAcceptedHistory

/-! Source-derived Final threshold and zero-value accumulator joins. This
module supplies no verifier-acceptance assumption, authorized bitmap field,
successful replay premise or collision-free premise. The primitive failure
arm is the existing current accumulator game on explicit original inputs. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentProtocolHistory
open NativePrivateSpendCurrentSixCaseSemantics
open NativePrivateSpendCurrentAcceptedHistory NativePrivateSpendCurrentRoleGames
open NativePrivateSpendArithmeticTopology NativePrivateSpendLocalSemantics
open NativePrivateSpendPackedLowering NativePrivateSpendRoleBridge
open NativePrivateSpendCsrCertificate
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open NativeLaunchConstraintAdapterBridge
noncomputable section

local instance : Fact (Nat.Prime modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

/-- Exact seven-limb identity in the current native empty note: the SINGLE
sponge of the fixed key [1,0,0,0,0], padded by two zeros. This default is not
an issued note or an Approval. An accumulator reaching this fixed digest is
an explicit new current primitive target event, not the zero-digest event. -/
def nativeEmptyIdentityWord (lane : Fin 7) : Nat :=
  (poseidon2V8Sponge
    HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain
    [1, 0, 0, 0, 0, 0, 0]).getD lane.val 0

def nativeEmptyOwner : Digest := List.ofFn nativeEmptyIdentityWord

/-- Circuit `range(final_mode * (count - 2), 1)`: only operation locators. -/
structure FinalCountChecked (g : Graph K) (mode count : Word K) where
  difference : Word K
  gatedDifference : Word K
  subtract : SubData g count (.constant 2) difference
  multiply : MulData g mode difference gatedDifference
  range : RangeData g gatedDifference 1

section Source
variable [Fact (Nat.Prime modulus)]

theorem final_count_from_source (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (mode count : Word K) (checked : FinalCountChecked g mode count)
    (selected : natural z mode = 1) :
    2 ≤ natural z count ∧ natural z count ≤ 3 := by
  have modeOne : read z mode = 1 := by
    rw [← natural_cast z mode, selected, Nat.cast_one]
  have difference : read z checked.difference = read z count - 2 :=
    sub_sound g layout z sem checked.subtract
  have product := mul_sound g layout z sem checked.multiply
  rw [modeOne, one_mul, difference] at product
  obtain ⟨value, bound, rangeEq⟩ :=
    range_witness g layout z sem _ 1 checked.range
  have countField : read z count = (value : K) + 2 := by
    calc
      read z count = (read z count - 2) + 2 := by ring
      _ = read z checked.gatedDifference + 2 := by rw [← product]
      _ = (value : K) + 2 := by rw [← rangeEq]
  have countNat : natural z count = value + 2 := by
    apply small_cast_injective
    · exact ZMod.val_lt _
    · norm_num [modulus] at bound ⊢
      omega
    · simpa only [natural_cast, Nat.cast_add, Nat.cast_ofNat] using countField
  norm_num at bound
  omega

theorem relation_final_count (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (mode count : Word K) (checked : FinalCountChecked g mode count)
    (selected : natural (sourceAssignment packed) mode = 1) :
    2 ≤ natural (sourceAssignment packed) count ∧
      natural (sourceAssignment packed) count ≤ 3 := by
  exact final_count_from_source g layout (sourceAssignment packed)
    (relation_derives_structural_semantics relation packed valid g layout csr certificate)
    mode count checked selected

theorem bitmap_count_from_equations (z : Nat → K) (bits : Bits3) (count : Word K)
    (boolean : ∀ i, read z (bits i) = 0 ∨ read z (bits i) = 1)
    (sum : read z count = (read z (bits 0) + read z (bits 1)) + read z (bits 2)) :
    natural z count = (sourceBitmap z bits).card := by
  classical
  have h0 := boolean 0
  have h1 := boolean 1
  have h2 := boolean 2
  have slotUniverse : (Finset.univ : Finset (Fin 3)) = {0, 1, 2} := by decide
  have field : read z count = ((sourceBitmap z bits).card : K) := by
    rcases h0 with h0 | h0 <;> rcases h1 with h1 | h1 <;> rcases h2 with h2 | h2
    all_goals
      norm_num only [h0, h1, h2] at sum
      simpa [sourceBitmap, slotUniverse, Finset.filter_insert,
        Finset.filter_singleton, h0, h1, h2] using sum
  apply small_cast_injective
  · exact ZMod.val_lt _
  · have bound := Finset.card_le_univ (sourceBitmap z bits)
    simp only [Fintype.card_fin] at bound
    norm_num [modulus]
    omega
  · simpa only [natural_cast] using field

theorem source_bitmap_count (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (bits : Bits3) (count : Word K)
    (checkedBits : ∀ i, BooleanData g (bits i))
    (checkedSum : ThreeSumChecked g bits count) :
    natural z count = (sourceBitmap z bits).card :=
  bitmap_count_from_equations z bits count
    (fun i => boolean_sound g layout z sem _ (checkedBits i))
    (three_sum_sound g layout z sem bits count checkedSum)

/-- Final's bitmap weight comes from the same source count, not a threshold
field in a history certificate. -/
theorem relation_final_bitmap_threshold (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (mode count : Word K) (bits : Bits3)
    (checked : FinalCountChecked g mode count)
    (checkedBits : ∀ i, BooleanData g (bits i))
    (checkedSum : ThreeSumChecked g bits count)
    (selected : natural (sourceAssignment packed) mode = 1) :
    2 ≤ (sourceBitmap (sourceAssignment packed) bits).card ∧
      (sourceBitmap (sourceAssignment packed) bits).card ≤ 3 := by
  have sem := relation_derives_structural_semantics relation packed valid g layout csr certificate
  have threshold := final_count_from_source g layout (sourceAssignment packed) sem mode count checked selected
  rw [source_bitmap_count g layout (sourceAssignment packed) sem bits count checkedBits checkedSum] at threshold
  exact threshold
end Source

def accumulatorInput (context : Context) (bitmap : Finset Slot) :
    AccumulatorOwnerInput :=
  ⟨context.key, context.tags, context.intent, bitmapBits bitmap⟩

theorem bitmapBits_injective : Function.Injective bitmapBits := by
  classical
  intro left right same
  apply Finset.ext
  intro i
  have lane := congrFun same i
  by_cases hl : i ∈ left <;> by_cases hr : i ∈ right
  <;> simp [bitmapBits, hl, hr] at lane ⊢

theorem accumulatorInput_injective (left right : Context)
    (before after : Finset Slot)
    (same : accumulatorInput left before = accumulatorInput right after) :
    left = right ∧ before = after := by
  have keyEq := congrArg AccumulatorOwnerInput.key same
  have tagsEq := congrArg AccumulatorOwnerInput.tags same
  have intentEq := congrArg AccumulatorOwnerInput.intent same
  have bitsEq := congrArg AccumulatorOwnerInput.approved same
  have bitmapEq : before = after := bitmapBits_injective bitsEq
  refine ⟨?_, bitmapEq⟩
  cases left with
  | mk key tags intent =>
    cases right with
    | mk key' tags' intent' =>
      change key = key' at keyEq
      change tags = tags' at tagsEq
      change intent = intent' at intentEq
      cases keyEq
      cases tagsEq
      cases intentEq
      rfl

/-- An occupied value-zero note has the same contextual owner rule as every
other accumulator. Equal owner digests never silently certify the context. -/
theorem accumulator_owner_identifies_or_collision (left right : Context)
    (before after : Finset Slot)
    (sameOwner : encodedAccumulator left before = encodedAccumulator right after) :
    (left = right ∧ before = after) ∨
      accumulatorCollision (accumulatorInput left before, accumulatorInput right after) := by
  classical
  by_cases sameInput : accumulatorInput left before = accumulatorInput right after
  · exact Or.inl (accumulatorInput_injective left right before after sameInput)
  · exact Or.inr ⟨sameInput, sameOwner⟩

/-- The native occupied-note readback supplies an owner equality, not a
lineage. Collision-free identity is derived here only as the explicit good
arm; the unequal-input primitive event remains a concrete alternative. -/
theorem occupied_approval_parent_join (record : Record)
    (prior : CertifiedAccumulator)
    (ownerEq : record.beforeOwner = encodedAccumulator prior.context prior.bitmap)
    (sourceOwner : record.beforeOwner = encodedAccumulator record.context record.before) :
    (prior.context = record.context ∧ prior.bitmap = record.before) ∨
      accumulatorCollision
        (accumulatorInput prior.context prior.bitmap,
         accumulatorInput record.context record.before) := by
  exact accumulator_owner_identifies_or_collision _ _ _ _
    (ownerEq.symm.trans sourceOwner)

/-- Once the source-derived Final count is identified with its source bitmap,
the authenticated accumulator owner yields two distinct original Approval
records, or the exact existing current accumulator collision event. -/
theorem final_authorization_or_collision (context : Context)
    (bitmap : Finset Slot) (prior : CertifiedAccumulator)
    (sameOwner : encodedAccumulator context bitmap =
      encodedAccumulator prior.context prior.bitmap)
    (threshold : 2 ≤ bitmap.card) :
    (context = prior.context ∧ bitmap = prior.bitmap ∧
      (prior.records.map Record.signer).Nodup ∧ 2 ≤ prior.records.length) ∨
      accumulatorCollision
        (accumulatorInput context bitmap, accumulatorInput prior.context prior.bitmap) := by
  rcases accumulator_owner_identifies_or_collision context prior.context
      bitmap prior.bitmap sameOwner with good | collision
  · refine Or.inl ⟨good.1, good.2, (certified_record_slots prior).1, ?_⟩
    rw [good.2, (certified_record_slots prior).2] at threshold
    exact threshold
  · exact Or.inr collision

/- Origin alternatives for an occupied accumulator note. The producing
owner role is data from a historical transaction's source equations; it is
not an assertion that the current consumer is authorized. -/
/-- Output recipients are arbitrary canonical seven-word digests; source
`ordinary(recipients[i])` does not require a SINGLE-key preimage. -/
def ordinaryRecipientOwner (recipient : Digest) : Digest :=
  poseidon2V8Sponge NativePrivateSpendCurrentRoleGames.ordinaryOwnerDomain recipient

def ordinaryRecipientAccumulatorClaw (recipient : Digest)
    (input : AccumulatorOwnerInput) : Prop :=
  ordinaryRecipientOwner recipient = accumulatorOwner input

inductive OwnerOrigin where
  | ordinary (recipient : Digest)
  | value (input : ValueOwnerInput)
  | accumulator (input : AccumulatorOwnerInput)
  | htlc (input : HtlcOwnerInput)

def originOwner : OwnerOrigin → Digest
  | .ordinary recipient => ordinaryRecipientOwner recipient
  | .value input => valueOwner input
  | .accumulator input => accumulatorOwner input
  | .htlc input => htlcOwner input

def AccumulatorOriginFailure (origin : OwnerOrigin) (input : AccumulatorOwnerInput) : Prop :=
  match origin with
  | .ordinary recipient => ordinaryRecipientAccumulatorClaw recipient input
  | .value value => valueAccumulatorClaw (value, input)
  | .accumulator prior => accumulatorCollision (prior, input)
  | .htlc htlc => accumulatorHtlcClaw (input, htlc)

theorem accumulator_origin_or_role_failure (origin : OwnerOrigin)
    (input : AccumulatorOwnerInput)
    (sameOwner : originOwner origin = accumulatorOwner input) :
    origin = .accumulator input ∨ AccumulatorOriginFailure origin input := by
  classical
  cases origin with
  | ordinary recipient => exact Or.inr sameOwner
  | value value => exact Or.inr sameOwner
  | htlc htlc => exact Or.inr sameOwner.symm
  | accumulator prior =>
    by_cases same : prior = input
    · exact Or.inl (congrArg OwnerOrigin.accumulator same)
    · exact Or.inr ⟨same, sameOwner⟩
end
end HegemonCrypto.NativePrivateSpendCurrentProtocolHistory
