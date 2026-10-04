import HegemonCrypto.SmallWoodV8Smz9TypedScheduleKernel

namespace HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

/-- Fixed Rust-array projection. Missing/out-of-range typed list values are only
total-function defaults; well-shaped source inputs have exactly these entries. -/
def fixedWords (count : Nat) (values : List Nat) : List Nat :=
  (List.range count).map (fun i => values.getD i 0)

theorem fixed_words_length (count : Nat) (values : List Nat) :
    (fixedWords count values).length = count := by simp only [fixedWords, List.length_map, List.length_range]

theorem fixed_words_exact (count : Nat) (values : List Nat) (shape : values.length = count) :
    fixedWords count values = values :=
  HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.range_getD values count shape

def inputAt (witness : V8Witness) (input : Nat) : V8InputWitness := witness.inputs.getD input default
def outputAt (witness : V8Witness) (output : Nat) : V8OutputWitness := witness.outputs.getD output default

def sourceNoteWords (note : V8NoteOpening) : List Nat :=
  [note.value, note.assetId] ++ fixedWords 4 note.recipientKey ++ fixedWords 4 note.rho ++
    fixedWords 4 note.randomness ++ fixedWords 4 note.authorizationKey

def sourceAccumulatorWords (opening : V8AccumulatorOpening) : List Nat :=
  fixedWords 7 opening.policyRoot ++ fixedWords 7 opening.intentDigest ++
    [opening.threshold, opening.signerCount, opening.approvalCount] ++ fixedWords 6 opening.approvedSlots

def sourceValueLockWords (opening : V8AccumulatorOpening) : List Nat :=
  fixedWords 7 opening.policyRoot ++ fixedWords 7 opening.intentDigest

def sourcePolicyWords (auth : V8AuthorizationWitness) : List Nat :=
  [auth.current.threshold, auth.current.signerCount] ++
    (List.range 6).flatMap (fun slot => fixedWords 5 (auth.policySignerTags.getD slot []))

def effectiveNext (auth : V8AuthorizationWitness) : V8AccumulatorOpening :=
  { policyRoot := auth.current.policyRoot
    intentDigest := auth.current.intentDigest
    threshold := auth.current.threshold
    signerCount := auth.current.signerCount
    approvalCount := auth.next.approvalCount
    approvedSlots := auth.next.approvedSlots }

def globalSpendKey (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  if statement.inputFlags.getD 0 0 = 1 then fixedWords 4 (inputAt witness 0).spendKey
  else if statement.inputFlags.getD 1 0 = 1 then fixedWords 4 (inputAt witness 1).spendKey
  else List.replicate 4 0

/-- This repeats the source helper's concrete preparation/fold, with no selected
primitive parameter. -/
def sourceSpongeDigest (domain : Nat) (inputs : List Nat) : List Nat :=
  let blocks := max 1 ((inputs.length + 8 - 1) / 8)
  let final := (List.range blocks).foldl
    (fun state block => Poseidon2Width16Kernel.permutation
      (spongePreparedWords domain inputs blocks state block)) (List.replicate 16 0)
  final.take 7

theorem source_sponge_is_exact_specification (domain : Nat) (inputs : List Nat) :
    sourceSpongeDigest domain inputs = poseidon2V8Sponge domain inputs := rfl

def effectiveInputPrf (statement : V8PublicStatement) (witness : V8Witness)
    (legacy : Nat) (input : Nat) : Nat :=
  if statement.inputFlags.getD input 0 ≠ 1 then 0
  else
    let current := (sourceSpongeDigest 6 (sourceAccumulatorWords witness.authorization.current)).getD 4 0
    let valueLock := (sourceSpongeDigest 8 (sourceValueLockWords witness.authorization.current)).getD 4 0
    match witness.authorization.mode with
    | .singleKey => legacy
    | .approvalStep => if input = 0 then current else legacy
    | .finalThresholdSpend => if input = 0 then valueLock else current

def sourceNullifierWords (statement : V8PublicStatement) (witness : V8Witness)
    (legacy input : Nat) : List Nat :=
  let active := statement.inputFlags.getD input 0 = 1
  [effectiveInputPrf statement witness legacy input,
    if active then (inputAt witness input).position else 0] ++
    (if active then fixedWords 4 (inputAt witness input).note.rho else List.replicate 4 0)

def sourceCounterWords (counters : V8StablecoinCounters) : List Nat :=
  [counters.epochId, counters.mintedInEpoch, counters.totalDebt, counters.sequence]

def stableConfigWords (witness : V8Witness) : List Nat :=
  stableWitnessSlice witness.stablecoin 0 55

def stableBeforeWords (witness : V8Witness) : List Nat :=
  stableWitnessSlice witness.stablecoin 55 4

def stableSibling (witness : V8Witness) (level : Nat) : List Nat :=
  stableWitnessSlice witness.stablecoin (59 + level * 7) 7

def stableSecret (witness : V8Witness) : List Nat :=
  stableWitnessSlice witness.stablecoin 87 7

def stableLeafRight (statement : V8PublicStatement) (witness : V8Witness) (after : Bool) : List Nat :=
  (if after then sourceCounterWords statement.stablecoin.after else stableBeforeWords witness) ++
    [statement.stablecoin.assetId % 16, 0, 0]

theorem note_words_length (note : V8NoteOpening) : (sourceNoteWords note).length = 18 := by
  simp only [sourceNoteWords, List.length_append, List.length_cons, List.length_nil, fixed_words_length]

theorem accumulator_words_length (opening : V8AccumulatorOpening) :
    (sourceAccumulatorWords opening).length = 23 := by
  simp only [sourceAccumulatorWords, List.length_append, List.length_cons, List.length_nil, fixed_words_length]

theorem value_lock_words_length (opening : V8AccumulatorOpening) :
    (sourceValueLockWords opening).length = 14 := by
  simp only [sourceValueLockWords, List.length_append, fixed_words_length]

theorem policy_words_length (auth : V8AuthorizationWitness) : (sourcePolicyWords auth).length = 32 := by
  simp [sourcePolicyWords, List.range_succ, fixed_words_length]

theorem global_spend_key_length (statement : V8PublicStatement) (witness : V8Witness) :
    (globalSpendKey statement witness).length = 4 := by
  unfold globalSpendKey
  split
  · exact fixed_words_length _ _
  · split
    · exact fixed_words_length _ _
    · simp only [List.length_replicate]

theorem nullifier_words_length (statement : V8PublicStatement) (witness : V8Witness)
    (legacy input : Nat) : (sourceNullifierWords statement witness legacy input).length = 6 := by
  simp only [sourceNullifierWords, List.length_append, List.length_cons, List.length_nil]
  split <;> simp only [fixed_words_length, List.length_replicate]

theorem first_active_key_wins (statement : V8PublicStatement) (witness : V8Witness)
    (first : statement.inputFlags.getD 0 0 = 1) :
    globalSpendKey statement witness = fixedWords 4 (inputAt witness 0).spendKey := by
  simp only [globalSpendKey, if_pos first]

theorem inactive_nullifier_still_has_six_zero_words (statement : V8PublicStatement)
    (witness : V8Witness) (legacy input : Nat) (inactive : statement.inputFlags.getD input 0 ≠ 1) :
    sourceNullifierWords statement witness legacy input = List.replicate 6 0 := by
  simp only [sourceNullifierWords, effectiveInputPrf, if_pos inactive, if_neg inactive]
  rfl

theorem effective_next_preserves_fixed_current (auth : V8AuthorizationWitness) :
    (effectiveNext auth).policyRoot = auth.current.policyRoot ∧
    (effectiveNext auth).intentDigest = auth.current.intentDigest ∧
    (effectiveNext auth).threshold = auth.current.threshold ∧
    (effectiveNext auth).signerCount = auth.current.signerCount ∧
    (effectiveNext auth).approvalCount = auth.next.approvalCount ∧
    (effectiveNext auth).approvedSlots = auth.next.approvedSlots := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

end HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

