import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem bit_boolean (condition : Prop) [Decidable condition] : BooleanWord (authBit condition) := by
  unfold authBit
  split_ifs <;> simp [BooleanWord]

theorem bit_polynomial (value : Nat) (boolean : BooleanWord value) :
    (value : F) * ((value : F) - 1) = 0 := by
  rcases boolean with h | h <;> simp [h]

theorem source_boolean_row (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row : Nat)
    (bounds : (78 ≤ row ∧ row < 104) ∨ (134 ≤ row ∧ row < 140)) :
    BooleanWord (sourceAuthRow statement witness hashes row) := by
  unfold sourceAuthRow
  simp only [if_neg (show ¬row < 3 by omega),if_neg (show ¬row < 5 by omega),
    if_neg (show ¬row < 13 by omega),if_neg (show ¬row < 18 by omega),
    if_neg (show ¬row < 25 by omega),if_neg (show ¬row < 32 by omega),
    if_neg (show ¬row < 39 by omega),if_neg (show ¬row < 46 by omega),
    if_neg (show ¬row < 53 by omega),if_neg (show ¬row < 60 by omega),
    if_neg (show ¬row < 78 by omega)]
  split_ifs <;> try omega
  · unfold authThresholdFlag
    split_ifs <;> first | exact Or.inl rfl | exact bit_boolean _
  · unfold authSignerFlag
    split_ifs <;> first | exact Or.inl rfl | exact bit_boolean _
  · unfold authCurrentCountFlag
    split_ifs <;> first | exact Or.inl rfl | exact bit_boolean _
  · cases mode : witness.authorization.mode <;> simp only [authNextCountFlag,mode]
    · exact Or.inl rfl
    · exact bit_boolean _
    · exact bit_boolean _
  · exact bit_boolean _

theorem non_single_current_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    CanonicalAccumulator witness.authorization.current := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode
  · exact False.elim (nonsingle mode)
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.2.2.1
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.2.1

theorem approval_next_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    CanonicalAccumulator witness.authorization.next := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  exact auth.2.2.2.1

theorem active_input_flags (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) : statement.inputFlags = [1,1] := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode
  · exact False.elim (nonsingle mode)
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.1
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.1

theorem approval_output_flag (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) : flagAt statement.outputFlags 0 = 1 := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  exact auth.2.1

theorem source_reserved_zero (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (index : Fin 2) :
    sourceAuthRow statement witness hashes (76 + index.val) = 0 := by
  fin_cases index <;> rfl

theorem source_input_activity (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (gate : Fin 2) :
    (authModeFlag witness.authorization.mode (1+gate.val) : F) *
      ((flagAt statement.inputFlags input.val : F)-1) = 0 := by
  by_cases single : witness.authorization.mode = .singleKey
  · fin_cases gate <;> simp [authModeFlag,authBit,single]
  · have flags := active_input_flags statement witness valid single
    fin_cases input <;> simp [flagAt,flags]

theorem source_output_activity (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (authModeFlag witness.authorization.mode 1 : F) *
      ((flagAt statement.outputFlags 0 : F)-1) = 0 := by
  by_cases approval : witness.authorization.mode = .approvalStep
  · rw [approval_output_flag statement witness valid approval,Nat.cast_one,sub_self,mul_zero]
  · have gate : authModeFlag witness.authorization.mode 1 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

theorem source_approved_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (next : Bool) (slot : Fin 6) :
    BooleanWord (wordAt (if next then witness.authorization.next.approvedSlots
      else witness.authorization.current.approvedSlots) slot.val) := by
  cases mode : witness.authorization.mode
  · obtain ⟨current,future,_⟩ := single_zero_openings statement witness valid mode
    cases next
    · exact Or.inl (zero_words_readback _ current.2.2.2.2.2.2.2.2 slot.val)
    · exact Or.inl (zero_words_readback _ future.2.2.2.2.2.2.2.2 slot.val)
  · have current := non_single_current_canonical statement witness valid (by simp [mode])
    have future := approval_next_canonical statement witness valid mode
    cases next
    · exact current.2.2.2.2.2.2.2.2.2.1 slot.val slot.isLt
    · exact future.2.2.2.2.2.2.2.2.2.1 slot.val slot.isLt
  · have current := non_single_current_canonical statement witness valid (by simp [mode])
    have future := final_zero_next statement witness valid mode
    cases next
    · exact current.2.2.2.2.2.2.2.2.2.1 slot.val slot.isLt
    · exact Or.inl (zero_words_readback _ future.2.2.2.2.2.2.2.2 slot.val)

theorem source_bitmap_row_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (next : Bool) (slot : Fin 6) :
    BooleanWord (sourceAuthRow statement witness hashes
      (if next then 70 + slot.val else 63 + slot.val)) := by
  have boolean := source_approved_boolean statement witness valid next slot
  cases next <;> fin_cases slot <;>
    simpa [sourceAuthRow,authScalar] using boolean

theorem membership_tag_difference (auth : V8AuthorizationWitness) (hashes : AuthHashFinals)
    (slot : Nat) (limb : Fin 5) :
    (authMembership auth hashes slot : F) *
      ((authHashWord hashes 0 limb.val : F) -
        (wordAt (auth.policySignerTags.getD slot []) limb.val : F)) = 0 := by
  unfold authMembership authBit
  split_ifs with selected
  · rw [selected.2.2]
    simp only [wordAt,List.getD_eq_getElem?_getD,List.getElem?_ofFn,
      dif_pos limb.isLt,Option.getD_some,Nat.cast_one,sub_self,mul_zero]
  · simp only [Nat.cast_zero,zero_mul]

theorem current_scalar_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    1 ≤ witness.authorization.current.threshold ∧
      witness.authorization.current.threshold ≤ witness.authorization.current.signerCount ∧
      witness.authorization.current.signerCount ≤ 6 ∧
      witness.authorization.current.approvalCount ≤ witness.authorization.current.signerCount := by
  obtain ⟨_,_,_,_,positive,threshold,signers,count,_,_,_,_⟩ :=
    non_single_current_canonical statement witness valid nonsingle
  exact ⟨positive,threshold,signers,count⟩

theorem threshold_flag_sum (auth : V8AuthorizationWitness) (nonsingle : auth.mode ≠ .singleKey)
    (lower : 1 ≤ auth.current.threshold) (upper : auth.current.threshold ≤ 6) :
    (authThresholdFlag auth 5 : F) + ((authThresholdFlag auth 4 : F) +
      ((authThresholdFlag auth 3 : F) + ((authThresholdFlag auth 2 : F) +
        ((authThresholdFlag auth 0 : F) + (authThresholdFlag auth 1 : F))))) - 1 = 0 := by
  simp only [authThresholdFlag,if_neg nonsingle]
  interval_cases auth.current.threshold <;> norm_num [authBit]

theorem approval_count_increment (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    witness.authorization.next.approvalCount = witness.authorization.current.approvalCount + 1 := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  exact auth.2.2.2.2.2.2.2.2.2.2.1

theorem approval_next_count_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    witness.authorization.next.approvalCount ≤ 6 := by
  obtain ⟨_,_,_,_,_,_,signers,count,_,_,_,_⟩ := approval_next_canonical statement witness valid approval
  exact le_trans count signers

theorem final_threshold_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (finalMode : witness.authorization.mode = .finalThresholdSpend) :
    witness.authorization.current.threshold ≤ witness.authorization.current.approvalCount := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,finalMode] at auth
  exact auth.2.2.2.2.2.1

end HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
