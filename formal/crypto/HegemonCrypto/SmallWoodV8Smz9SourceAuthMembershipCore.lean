import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastCore
import HegemonCrypto.SmallWoodV8Smz9SourceAuthFinalCore

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMembershipCore
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalCore
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem approval_global_spend_key (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    globalSpendKey statement witness = selectedTransactionSpendKey statement witness := by
  have nonsingle : witness.authorization.mode ≠ .singleKey := by simp [approval]
  have flags := active_input_flags statement witness valid nonsingle
  have length := (valid_input_spend_words_exact statement witness valid 0 (by decide)).1
  simp only [globalSpendKey,selectedTransactionSpendKey,flags,flagAt,List.getD_cons_zero,
    ↓reduceIte,inputAt]
  exact fixed_words_exact 4 _ length

theorem source_transaction_prf_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 0)).take 7 =
      exactV8TransactionPrf (globalSpendKey statement witness) := by
  exact source_sponge_segment_digest statement witness 0 1 2 (globalSpendKey statement witness)
    (fun _ => .transactionPrf) (by decide) (by decide)
    (by
      intro block bound
      have zero : block = 0 := by omega
      subst block
      rfl)
    (by decide) (by rw [global_spend_key_length]; decide)
    (by rw [global_spend_key_length]; rfl)

theorem approval_legacy_tag (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    List.ofFn (fun limb : Fin 5 => authHashWord (typedSourceFinals statement witness) 0 limb.val) =
      (exactV8TransactionPrf (selectedTransactionSpendKey statement witness)).take 5 := by
  have digest := source_transaction_prf_digest statement witness
  rw [approval_global_spend_key statement witness valid approval] at digest
  rw [← digest,List.take_take]
  apply List.ext_getElem
  · simp [state_words_length]
  · intro i left right
    have bound : i < 5 := by simpa using left
    simp only [List.getElem_ofFn,List.getElem_take]
    rw [auth_hash_word_readback _ ⟨0,by decide⟩ ⟨i,by omega⟩]
    change callFinalWord (typedLiveInitialStates statement witness) 0 i = _
    rw [typed_call_final_word_is_scheduled statement witness ⟨0,by decide⟩]
    simp [List.getD,show i < (stateWords (scheduledFinal statement witness 0)).length by
      rw [state_words_length]; omega]

theorem approval_change_facts (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) (slot : Fin 6)
    (changed : wordAt witness.authorization.current.approvedSlots slot.val ≠
      wordAt witness.authorization.next.approvedSlots slot.val) :
    wordAt witness.authorization.current.approvedSlots slot.val = 0 ∧
      wordAt witness.authorization.next.approvedSlots slot.val = 1 ∧
      slot.val < witness.authorization.current.signerCount ∧
      witness.authorization.policySignerTags.getD slot.val [] =
        List.ofFn (fun limb : Fin 5 => authHashWord (typedSourceFinals statement witness) 0 limb.val) := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  obtain ⟨_,_,current,next,_,_,_,_,_,same,_,_,monotone,signer,_,_,_⟩ := auth
  have cb := current.2.2.2.2.2.2.2.2.2.1 slot.val slot.isLt
  have nb := next.2.2.2.2.2.2.2.2.2.1 slot.val slot.isLt
  have cZero : wordAt witness.authorization.current.approvedSlots slot.val = 0 := by
    rcases cb with zero | one
    · exact zero
    · exact False.elim (changed (one.trans (monotone slot.val slot.isLt one).symm))
  have nOne : wordAt witness.authorization.next.approvedSlots slot.val = 1 := by
    rcases nb with zero | one
    · exact False.elim (changed (cZero.trans zero.symm))
    · exact one
  have below : slot.val < witness.authorization.current.signerCount := by
    by_contra beyond
    have zero := next.2.2.2.2.2.2.2.2.2.2.2 slot.val (by omega) slot.isLt
    omega
  refine ⟨cZero,nOne,below,?_⟩
  rw [approval_legacy_tag statement witness valid approval]
  exact signer slot.val slot.isLt changed

theorem approval_changed_slot_exists (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    ∃ slot : Fin 6, wordAt witness.authorization.current.approvedSlots slot.val ≠
      wordAt witness.authorization.next.approvedSlots slot.val := by
  by_contra! allSame
  have current := non_single_current_canonical statement witness valid (by simp [approval])
  have next := approval_next_canonical statement witness valid approval
  have equal : witness.authorization.current.approvedSlots = witness.authorization.next.approvedSlots := by
    apply List.ext_getElem
    · exact current.2.2.2.2.2.2.2.2.1.trans next.2.2.2.2.2.2.2.2.1.symm
    · intro i left right
      have bound : i < 6 := by rw [current.2.2.2.2.2.2.2.2.1] at left; exact left
      simpa [wordAt,List.getD,left,right] using allSame ⟨i,bound⟩
  have csum := current.2.2.2.2.2.2.2.2.2.2.1
  have nsum := next.2.2.2.2.2.2.2.2.2.2.1
  rw [equal] at csum
  have increment := approval_count_increment statement witness valid approval
  omega

theorem active_tag_injective (auth : V8AuthorizationWitness) (tags : CanonicalSignerTags auth)
    (left right : Fin 6) (leftBelow : left.val < auth.current.signerCount)
    (rightBelow : right.val < auth.current.signerCount)
    (same : auth.policySignerTags.getD left.val [] = auth.policySignerTags.getD right.val []) :
    left = right := by
  apply Fin.ext
  by_contra different
  have wordSame := congrArg (fun words => wordAt words 0) same
  rcases lt_or_gt_of_ne different with less | greater
  · exact tags.2.2.2.1 left.val right.val less rightBelow wordSame
  · exact tags.2.2.2.1 right.val left.val greater leftBelow wordSame.symm

theorem membership_selected_slot (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) (selected slot : Fin 6)
    (changed : wordAt witness.authorization.current.approvedSlots selected.val ≠
      wordAt witness.authorization.next.approvedSlots selected.val) :
    authMembership witness.authorization (typedSourceFinals statement witness) slot.val =
      authBit (slot = selected) := by
  have nonsingle : witness.authorization.mode ≠ .singleKey := by simp [approval]
  have chosen := approval_change_facts statement witness valid approval selected changed
  have chosenActive : authSlotActive witness.authorization selected.val = 1 := by
    rw [slot_active_exact statement witness valid nonsingle selected]
    simp [authBit,chosen.2.2.1]
  have selectedIff : (witness.authorization.mode = .approvalStep ∧
      authSlotActive witness.authorization slot.val = 1 ∧
      witness.authorization.policySignerTags.getD slot.val [] =
        List.ofFn (fun limb : Fin 5 => authHashWord (typedSourceFinals statement witness) 0 limb.val)) ↔
      slot = selected := by
    constructor
    · intro h
      have below : slot.val < witness.authorization.current.signerCount := by
        have active := h.2.1
        rw [slot_active_exact statement witness valid nonsingle slot] at active
        by_contra beyond
        simp [authBit,beyond] at active
      exact active_tag_injective _ (non_single_tags_canonical statement witness valid nonsingle)
        slot selected below chosen.2.2.1 (h.2.2.trans chosen.2.2.2.symm)
    · intro same
      subst slot
      exact ⟨approval,chosenActive,chosen.2.2.2⟩
  simp only [authMembership,authBit,selectedIff]

theorem unselected_bitmap_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) (selected slot : Fin 6)
    (changed : wordAt witness.authorization.current.approvedSlots selected.val ≠
      wordAt witness.authorization.next.approvedSlots selected.val)
    (different : slot ≠ selected) :
    wordAt witness.authorization.current.approvedSlots slot.val =
      wordAt witness.authorization.next.approvedSlots slot.val := by
  by_contra alsoChanged
  have chosen := approval_change_facts statement witness valid approval selected changed
  have other := approval_change_facts statement witness valid approval slot alsoChanged
  exact different (active_tag_injective _
    (non_single_tags_canonical statement witness valid (by simp [approval]))
    slot selected other.2.2.1 chosen.2.2.1 (other.2.2.2.trans chosen.2.2.2.symm))

theorem membership_transition_products (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6) :
    (wordAt witness.authorization.current.approvedSlots slot.val : F) *
      ((authModeFlag witness.authorization.mode 1 : F) *
        (authMembership witness.authorization (typedSourceFinals statement witness) slot.val : F)) = 0 ∧
    (authModeFlag witness.authorization.mode 1 : F) *
      (((wordAt witness.authorization.next.approvedSlots slot.val : F) -
        (wordAt witness.authorization.current.approvedSlots slot.val : F)) -
        (authMembership witness.authorization (typedSourceFinals statement witness) slot.val : F)) = 0 := by
  by_cases approval : witness.authorization.mode = .approvalStep
  · obtain ⟨selected,changed⟩ := approval_changed_slot_exists statement witness valid approval
    rw [membership_selected_slot statement witness valid approval selected slot changed]
    by_cases same : slot = selected
    · subst slot
      have chosen := approval_change_facts statement witness valid approval selected changed
      simp [chosen.1,chosen.2.1,authBit]
    · rw [unselected_bitmap_unchanged statement witness valid approval selected slot changed same]
      simp [authBit,same]
  · have gate : authModeFlag witness.authorization.mode 1 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    simp [gate]

theorem membership_sum_product (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (authModeFlag witness.authorization.mode 1 : F) *
      (((List.range 6).map fun slot =>
        (authMembership witness.authorization (typedSourceFinals statement witness) slot : F)).sum - 1) = 0 := by
  by_cases approval : witness.authorization.mode = .approvalStep
  · obtain ⟨selected,changed⟩ := approval_changed_slot_exists statement witness valid approval
    have equal : ((List.range 6).map fun slot =>
        (authMembership witness.authorization (typedSourceFinals statement witness) slot : F)).sum =
        ((List.range 6).map fun slot => (authBit (slot = selected.val) : F)).sum := by
      congr 1
      apply List.map_congr_left
      intro slot member
      have bound := List.mem_range.mp member
      rw [membership_selected_slot statement witness valid approval selected ⟨slot,bound⟩ changed]
      simp only [Fin.ext_iff]
    rw [equal]
    fin_cases selected <;> norm_num [authBit,List.range_succ]
  · have gate : authModeFlag witness.authorization.mode 1 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthMembershipCore
