import HegemonCrypto.SmallWoodV8Smz9TypedSchedulePlan
import Mathlib.Tactic.Tauto
import Mathlib.Tactic.SplitIfs

namespace HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxHeartbeats 1200000
set_option maxRecDepth 10000

theorem canonical_take (values : List Nat) (h : CanonicalWords values) (n : Nat) :
    CanonicalWords (values.take n) := fun value member => h value (List.mem_of_mem_take member)

theorem canonical_drop (values : List Nat) (h : CanonicalWords values) (n : Nat) :
    CanonicalWords (values.drop n) := fun value member => h value (List.mem_of_mem_drop member)

theorem canonical_fixed (n : Nat) (values : List Nat) (h : CanonicalWords values) :
    CanonicalWords (fixedWords n values) := by
  intro value member
  obtain ⟨i, _, rfl⟩ := List.mem_map.mp member
  exact getD_canonical values h i

theorem canonical_append (left right : List Nat) (hl : CanonicalWords left) (hr : CanonicalWords right) :
    CanonicalWords (left ++ right) := by
  intro value member
  exact (List.mem_append.mp member).elim (hl value) (hr value)

theorem canonical_stable_slice (witness : V8StablecoinWitness)
    (h : CanonicalWords witness.words) (start count : Nat) :
    CanonicalWords (stableWitnessSlice witness start count) := by
  intro value member
  obtain ⟨i, _, rfl⟩ := List.mem_map.mp member
  exact getD_canonical witness.words h _

theorem canonical_final_digest (earlier : Nat → State) (call : Nat) :
    CanonicalWords (finalDigest earlier call) := canonical_take _ (state_words_canonical _) _

theorem canonical_orient (position level : Nat) (left right : List Nat)
    (hl : CanonicalWords left) (hr : CanonicalWords right) :
    CanonicalWords (orient position level left right).1 ∧
      CanonicalWords (orient position level left right).2 := by
  unfold orient
  split
  · exact ⟨hl,hr⟩
  · exact ⟨hr,hl⟩

structure CompressionSourcesCanonical (statement : V8PublicStatement) (witness : V8Witness) : Prop where
  inputSibling : ∀ input, input < 2 → ∀ level, level < 32 →
    CanonicalWords (fixedWords 7 ((inputAt witness input).siblings.getD level []))
  stableWitness : CanonicalWords witness.stablecoin.words
  stablePublic : CanonicalWords (encodeStablecoinPublic statement.stablecoin)

/-- This source-only canonicality fact is derived from the fixed typed relation,
not from packed acceptance or a complete-frame-canonicality assumption. -/
theorem typed_valid_supplies_compression_sources (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    CompressionSourcesCanonical statement witness := by
  constructor
  · intro slot hs level hl
    have input := valid.2.1.2.2.1 slot hs
    change _ ∧ (if (inputAt witness slot).active = 0 then ZeroInputWitness (inputAt witness slot) else _) at input
    have siblings : (inputAt witness slot).siblings.length = 32 ∧
        ∀ digest, digest ∈ (inputAt witness slot).siblings → ExactWords 7 digest := by
      by_cases inactive : (inputAt witness slot).active = 0
      · rw [if_pos inactive] at input
        have h := input.2
        exact ⟨h.2.2.2.2.2.1, fun d hd => (h.2.2.2.2.2.2.1 d hd).1⟩
      · rw [if_neg inactive] at input
        exact ⟨input.2.2.2.2.2.1, input.2.2.2.2.2.2.1⟩
    have atLevel : (inputAt witness slot).siblings.getD level [] ∈ (inputAt witness slot).siblings := by
      have bound : level < (inputAt witness slot).siblings.length := by rw [siblings.1]; exact hl
      simpa only [List.getD_eq_getElem _ _ bound] using List.getElem_mem bound
    exact canonical_fixed 7 _ (siblings.2 _ atLevel).2
  · have exactStable : ExactWords 94 witness.stablecoin.words := valid.2.1.2.2.2.2.2
    exact exactStable.2
  · have exactPublic : ExactWords 120 (encodePublicStatement statement) := by
      have pub := valid.1
      simp only [CanonicalPublicStatement] at pub
      tauto
    intro value member
    apply exactPublic.2 value
    apply List.mem_append.mpr
    exact Or.inr member

theorem canonical_stable_leaf_right (statement : V8PublicStatement) (witness : V8Witness)
    (h : CompressionSourcesCanonical statement witness) (after : Bool) :
    CanonicalWords (stableLeafRight statement witness after) := by
  apply canonical_append
  · cases after with
    | false => exact canonical_stable_slice _ h.stableWitness _ _
    | true =>
      intro value member
      change value ∈ sourceCounterWords statement.stablecoin.after at member
      apply h.stablePublic value
      simp only [sourceCounterWords, List.mem_cons, List.not_mem_nil, or_false] at member
      simp only [encodeStablecoinPublic, List.mem_append, List.mem_cons, List.not_mem_nil, or_false]
      tauto
  · intro value member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl
    · exact Nat.lt_trans (Nat.mod_lt _ (by decide : 0 < 16)) (by decide)
    · exact modulus_positive
    · exact modulus_positive

def PlanRawCanonical : Plan → Prop
  | .sponge _ domain inputs _ _ _ =>
      domain < Poseidon2Width16Kernel.fieldModulus ∧ inputs.length < Poseidon2Width16Kernel.fieldModulus
  | .compress _ domain left right =>
      domain < Poseidon2Width16Kernel.fieldModulus ∧ CanonicalWords left ∧ CanonicalWords right
  | .padding => True

theorem input_plan_raw_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (h : CompressionSourcesCanonical statement witness) (earlier : Nat → State)
    (call input first : Nat) (hi : input < 2) (ho : call-first < 36) :
    PlanRawCanonical (sourceInputPlan statement witness earlier call input first) := by
  unfold sourceInputPlan
  dsimp only
  split
  · change 1 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [note_words_length]
    decide
  · split
    · change 4 < Poseidon2Width16Kernel.fieldModulus ∧ _
      exact ⟨by decide, canonical_orient _ _ _ _ (canonical_final_digest earlier _)
        (h.inputSibling input hi (call-first-3) (by omega))⟩
    · change 2 < Poseidon2Width16Kernel.fieldModulus ∧ _
      rw [nullifier_words_length]
      decide

theorem compress_frame_exact (domain : Nat) (left right : List Nat)
    (hd : domain < Poseidon2Width16Kernel.fieldModulus)
    (hl : CanonicalWords left) (hr : CanonicalWords right) :
    stateWords (compressFrame domain left right) = compressFrameWords domain left right := by
  apply state_of_words_exact
  · simp only [compressFrameWords, List.length_map, List.length_range]
  · intro value member
    obtain ⟨lane, _, rfl⟩ := List.mem_map.mp member
    split
    · exact getD_canonical left hl _
    · split
      · exact getD_canonical right hr _
      · split
        · exact hd
        · decide

def rawPreparedPlan (earlier : Nat → State) : Plan → List Nat
  | .sponge _ domain inputs blocks block previous =>
      spongePreparedWords domain inputs blocks
        (stateWords (match previous with | none => zeroState | some call => earlier call)) block
  | .compress _ domain left right => compressFrameWords domain left right
  | .padding => stateWords zeroState

theorem prepare_plan_does_not_alter_canonical_frame (earlier : Nat → State) (plan : Plan)
    (canonical : PlanRawCanonical plan) :
    stateWords (preparePlan earlier plan) = rawPreparedPlan earlier plan := by
  cases plan with
  | sponge role domain inputs blocks block previous =>
    exact sponge_frame_exact _ _ _ _ _ canonical.1 canonical.2
  | compress role domain left right => exact compress_frame_exact _ _ _ canonical.1 canonical.2.1 canonical.2.2
  | padding => rfl


theorem canonical_issuer_right (statement : V8PublicStatement) (witness : V8Witness)
    (h : CompressionSourcesCanonical statement witness) :
    CanonicalWords [statement.stablecoin.assetId, statement.stablecoin.policyVersion, 0,0,0,0,0] := by
  intro value member
  simp only [List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · apply h.stablePublic
    simp only [encodeStablecoinPublic, List.mem_append, List.mem_cons]
    tauto
  · apply h.stablePublic
    simp only [encodeStablecoinPublic, List.mem_append, List.mem_cons]
    tauto
  all_goals exact modulus_positive

theorem canonical_stable_action (statement : V8PublicStatement) (witness : V8Witness)
    (h : CompressionSourcesCanonical statement witness) :
    CanonicalWords (fixedWords 7 statement.stablecoin.actionIntent) := by
  apply canonical_fixed
  intro value member
  apply h.stablePublic value
  simp only [encodeStablecoinPublic, List.mem_append]
  tauto

theorem source_call_plan_raw_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (h : CompressionSourcesCanonical statement witness) (earlier : Nat → State)
    (call : Nat) (hc : call < 125) : PlanRawCanonical (sourceCallPlan statement witness call earlier) := by
  by_cases h0 : call = 0
  · simp only [sourceCallPlan, if_pos h0]
    change 2 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [global_spend_key_length]
    decide
  by_cases h1 : call < 37
  · simp only [sourceCallPlan, if_neg h0, if_pos h1]
    exact input_plan_raw_canonical statement witness h earlier call 0 1 (by omega) (by omega)
  by_cases h2 : call < 73
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_pos h2]
    exact input_plan_raw_canonical statement witness h earlier call 1 37 (by omega) (by omega)
  by_cases h3 : call < 79
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_pos h3]
    change 1 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [note_words_length]
    decide
  by_cases h4 : call < 94
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_pos h4]
    change poseidon2V8ActionIntentDomain < Poseidon2Width16Kernel.fieldModulus ∧ _
    simp only [exactV8ActionIntentProjection, List.length_map, List.length_range, publicWordCount]
    decide
  by_cases h5 : call < 98
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_pos h5]
    change 7 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [policy_words_length]
    decide
  by_cases h6 : call < 101
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_pos h6]
    change 6 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [accumulator_words_length]
    decide
  by_cases h7 : call < 104
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_pos h7]
    change 6 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [accumulator_words_length]
    decide
  by_cases h8 : call < 106
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_pos h8]
    change 8 < Poseidon2Width16Kernel.fieldModulus ∧ _
    rw [value_lock_words_length]
    decide
  by_cases h9 : call < 110
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_pos h9]
    refine ⟨?_, canonical_fixed _ _ (canonical_drop _ (canonical_stable_slice _ h.stableWitness _ _) _),
      canonical_fixed _ _ (canonical_drop _ (canonical_stable_slice _ h.stableWitness _ _) _)⟩
    have domains : CanonicalWords stablecoinV8ConfigChunkDomains := by
      intro value member
      simp only [stablecoinV8ConfigChunkDomains, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl <;> decide
    exact getD_canonical _ domains _
  by_cases h10 : call = 110
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_pos h10]
    exact ⟨by decide, canonical_final_digest _ _, canonical_final_digest _ _⟩
  by_cases h11 : call = 111
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_pos h11]
    exact ⟨by decide, canonical_final_digest _ _, canonical_final_digest _ _⟩
  by_cases h12 : call = 112
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_pos h12]
    exact ⟨by decide, canonical_final_digest _ _, canonical_final_digest _ _⟩
  by_cases h13 : call < 115
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_neg h12, if_pos h13]
    exact ⟨by decide, canonical_final_digest _ _, canonical_stable_leaf_right statement witness h _⟩
  by_cases h14 : call < 123
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_neg h12, if_neg h13, if_pos h14]
    refine ⟨?_, canonical_orient _ _ _ _ (canonical_final_digest _ _)
      (canonical_stable_slice _ h.stableWitness _ _)⟩
    have level : (call-115)/2 < 4 := by omega
    change 5211583102908843008 + (call-115)/2 < 18446744069414584321
    omega
  by_cases h15 : call = 123
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_neg h12, if_neg h13, if_neg h14, if_pos h15]
    exact ⟨by decide, canonical_stable_slice _ h.stableWitness _ _, canonical_issuer_right statement witness h⟩
  by_cases h16 : call = 124
  · simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_neg h12, if_neg h13, if_neg h14, if_neg h15, if_pos h16]
    exact ⟨by decide, canonical_stable_slice _ h.stableWitness _ _, canonical_stable_action statement witness h⟩
  simp only [sourceCallPlan, if_neg h0, if_neg h1, if_neg h2, if_neg h3, if_neg h4, if_neg h5, if_neg h6, if_neg h7, if_neg h8, if_neg h9, if_neg h10, if_neg h11, if_neg h12, if_neg h13, if_neg h14, if_neg h15, if_neg h16, PlanRawCanonical]

/-- Full typed endpoint: fixed typed validity discharges source canonicality for
every one of the 125 call frames. The canonical wrapper changes no raw word. -/
theorem typed_valid_schedule_frame_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) :
    stateWords (typedLiveInitialStates statement witness call) =
      rawPreparedPlan (builtFinals statement witness call.val)
        (sourceCallPlan statement witness call.val (builtFinals statement witness call.val)) :=
  prepare_plan_does_not_alter_canonical_frame _ _ (source_call_plan_raw_canonical statement witness
    (typed_valid_supplies_compression_sources statement witness valid) _ call.val call.isLt)

end HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

