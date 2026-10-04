import SmzaRp05AuthorizationClosureModes
import SmzaRp05AuthorizationClosureBoundFrame
import SmzaRp05DirectCsrCertificate

/-! Accepted source owner/key pairing in every mode. Bound messages retain
five key words, exactly two zero pads, seven right words and the live domain. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05AcceptedModeExhaustiveness
open HegemonCrypto.SmallWood.SmzaRp05AcceptedAllModeNullifierKeys
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureModes
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureBoundFrame
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05AuthSourceBridge
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
open scoped Classical

def modeValue (packed : List Nat) (row : Nat) : Goldilocks :=
  ((packedWitnessLaneRows packed 0).getD row 0 : Goldilocks)

def selectedRow (packed : List Nat) (input : Fin 2) : Nat :=
  if modeValue packed approvalRow = 1 then
    if input.val = 0 then 110 else 106
  else if modeValue packed finalRow = 1 then
    if input.val = 0 then 111 else 110
  else 106

private theorem modes_at_lane {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (lane : Fin 7) :
    ((packedWitnessLaneRows packed lane.val).getD singleRow 0 : Goldilocks) =
      modeValue packed singleRow ∧
    ((packedWitnessLaneRows packed lane.val).getD approvalRow 0 : Goldilocks) =
      modeValue packed approvalRow ∧
    ((packedWitnessLaneRows packed lane.val).getD finalRow 0 : Goldilocks) =
      modeValue packed finalRow := by
  exact ⟨congrArg (fun n : Nat => (n : Goldilocks))
      (accepted_lane_mode_eq accepted 0 lane),
    congrArg (fun n : Nat => (n : Goldilocks))
      (accepted_lane_mode_eq accepted 1 lane),
    congrArg (fun n : Nat => (n : Goldilocks))
      (accepted_lane_mode_eq accepted 2 lane)⟩

theorem accepted_owner_selected_row {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1)
    (limb : Fin 7) :
    packed.getD ((95 + input.val) * 64 + limb.val) 0 =
      packed.getD (selectedRow packed input * 64 + limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics
    SmzaRp05LocalCertificate.certificate accepted ⟨limb.val, by omega⟩
  have equation := semantic (.inputAuthorization input)
  have modes := (accepted_mode_selectors_exhaustive accepted 0).2
  change
    (modeValue packed singleRow = 1 ∧ modeValue packed approvalRow = 0 ∧
      modeValue packed finalRow = 0) ∨
    (modeValue packed singleRow = 0 ∧ modeValue packed approvalRow = 1 ∧
      modeValue packed finalRow = 0) ∨
    (modeValue packed singleRow = 0 ∧ modeValue packed approvalRow = 0 ∧
      modeValue packed finalRow = 1) at modes
  obtain ⟨s, a, f⟩ := modes_at_lane accepted limb
  have fieldEqual :
      ((packedWitnessLaneRows packed limb.val).getD (inputNoteVectorRow input) 0 : Goldilocks) =
        ((packedWitnessLaneRows packed limb.val).getD (selectedRow packed input) 0 : Goldilocks) := by
    simp only [localCheckTerm, SourceTerm.eval, active, Nat.cast_one,
      s, a, f] at equation
    rcases modes with ⟨hs, ha, hf⟩ | ⟨hs, ha, hf⟩ | ⟨hs, ha, hf⟩ <;>
      fin_cases input <;>
      simp [hs, ha, hf, selectedRow, legacyVectorRow, boundCurrentVectorRow,
        boundSecondaryVectorRow] at equation ⊢ <;>
      first | exact equation | exact sub_eq_zero.mp equation
  have rowBound : selectedRow packed input < relationRowCount := by
    unfold selectedRow
    split <;> split <;> simp_all [relationRowCount]
    all_goals split <;> simp_all
  rw [lane_row packed limb.val _ (by
      have := input.isLt; change 95 + input.val < 686; omega),
    lane_row packed limb.val _ rowBound] at fieldEqual
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) fieldEqual

inductive FramedAuthorizationInput where
  | single (key : Fin 5 → Nat)
  | bound (key : Fin 5 → Nat) (right : List Nat)

def FramedAuthorizationInput.key : FramedAuthorizationInput → Fin 5 → Nat
  | .single key => key
  | .bound key _ => key

def FramedAuthorizationInput.digest : FramedAuthorizationInput → List Nat
  | .single key => LiveAuthorizationInput.digest (.singleKey key)
  | .bound key right => LiveAuthorizationInput.digest
      (.accumulator (List.ofFn key ++ [0, 0]) right)

def FramedAuthorizationInput.Canonical (message : FramedAuthorizationInput) : Prop :=
  (∀ limb, message.key limb <
    Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus) ∧
  match message with
  | .single _ => True
  | .bound _ right => right.length = 7 ∧ ∀ word ∈ right,
      word < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus

def boundKey (packed : List Nat) : Fin 5 → Nat :=
  fun limb => packed.getD (97 * 64 + limb.val) 0

theorem bound_key_padded (packed : List Nat) :
    List.ofFn (boundKey packed) ++ [0, 0] = bindingKey packed := by
  rfl

def selectedMessage (packed : List Nat) (input : Fin 2) : FramedAuthorizationInput :=
  if selectedRow packed input = 106 then .single (acceptedGlobalKey packed)
  else .bound (boundKey packed)
    (bindingRight packed (if selectedRow packed input = 110 then 0 else 1))

theorem accepted_bound_vector_word {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (which : Fin 2) (limb : Fin 7) :
    packed.getD ((110 + which.val) * 64 + limb.val) 0 =
      (FramedAuthorizationInput.digest
        (.bound (boundKey packed) (bindingRight packed which))).getD limb.val 0 := by
  have bound := current_bound_compress14 accepted which
  have word := congrArg (fun words : List Nat => words.getD limb.val 0) bound
  have copied : packed.getD ((110 + which.val) * 64 + limb.val) 0 =
      packed.getD (Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalIndex
        (107 + which.val) limb.val) 0 := by
    fin_cases which
    · exact accepted_current_direct_word SmzaRp05DirectCsrCertificate.certificate
        accepted (.boundCurrent limb)
    · exact accepted_current_direct_word SmzaRp05DirectCsrCertificate.certificate
        accepted (.boundSecondary limb)
  rw [copied]
  rw [← bound_key_padded] at word
  simpa [FramedAuthorizationInput.digest, LiveAuthorizationInput.digest,
    SmzaRp05ThresholdRegistry.currentAuthorizationBindingDomain,
    packedFinalState, packedWord, List.getD_eq_getElem?_getD,
    List.getElem?_take, limb.isLt] using word

theorem accepted_owner_message_digest {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1)
    (limb : Fin 7) :
    packed.getD ((95 + input.val) * 64 + limb.val) 0 =
      (selectedMessage packed input).digest.getD limb.val 0 := by
  rw [accepted_owner_selected_row accepted input active limb]
  have rowCases : selectedRow packed input = 106 ∨ selectedRow packed input = 110 ∨
      selectedRow packed input = 111 := by
    unfold selectedRow
    split <;> split <;> simp_all
    all_goals split <;> simp_all
  rcases rowCases with h | h | h
  · simpa [selectedMessage, h, FramedAuthorizationInput.digest] using
      accepted_legacy_words_eq_semantic_single_key_digest accepted limb
  · simpa [selectedMessage, h] using accepted_bound_vector_word accepted 0 limb
  · simpa [selectedMessage, h] using accepted_bound_vector_word accepted 1 limb

theorem accepted_message_key_word {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 5) :
    (nullifierPreimage packed input).getD limb.val 0 =
      (selectedMessage packed input).key limb := by
  have key := accepted_all_mode_nullifier_preimage_key_word accepted
    SmzaRp05NullifierMuxCertificate.certificate input limb
  have keyZero := accepted_all_mode_nullifier_preimage_key_word accepted
    SmzaRp05NullifierMuxCertificate.certificate 0 limb
  have rawZero : (nullifierPreimage packed 0).getD limb.val 0 = boundKey packed limb := by
    fin_cases limb <;> simp [nullifierPreimage, inputNullifierKeyRow, boundKey]
  rw [rawZero] at keyZero
  obtain ⟨s, a, f⟩ := modes_at_lane accepted ⟨limb.val, by omega⟩
  rw [a, f] at key keyZero
  have modes := (accepted_mode_selectors_exhaustive accepted 0).2
  change
    (modeValue packed singleRow = 1 ∧ modeValue packed approvalRow = 0 ∧
      modeValue packed finalRow = 0) ∨
    (modeValue packed singleRow = 0 ∧ modeValue packed approvalRow = 1 ∧
      modeValue packed finalRow = 0) ∨
    (modeValue packed singleRow = 0 ∧ modeValue packed approvalRow = 0 ∧
      modeValue packed finalRow = 1) at modes
  rcases modes with ⟨hs, ha, hf⟩ | ⟨hs, ha, hf⟩ | ⟨hs, ha, hf⟩ <;>
    fin_cases input <;>
    simp [ha, hf] at key keyZero <;>
    simp [selectedMessage, selectedRow, FramedAuthorizationInput.key, ha, hf] <;>
    first | exact key | exact key.trans keyZero.symm

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureIdentity
