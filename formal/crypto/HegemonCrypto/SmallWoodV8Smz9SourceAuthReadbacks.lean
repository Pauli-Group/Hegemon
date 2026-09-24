import HegemonCrypto.SmallWoodV8Smz9SourceAuthRows

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (packedWitnessLaneRows)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

inductive AuthFamily where
  | mode | inputPrf | inputKey | legacy | current | next | valueLock
  | statementDigest | policy | intent | scalar | thresholdFlag | signerFlag
  | currentCountFlag | nextCountFlag | policyTag | membership | distinctInverse
deriving DecidableEq, Repr

def AuthFamily.base : AuthFamily → Nat
  | .mode => 0 | .inputPrf => 3 | .inputKey => 5 | .legacy => 13
  | .current => 18 | .next => 25 | .valueLock => 32 | .statementDigest => 39
  | .policy => 46 | .intent => 53 | .scalar => 60 | .thresholdFlag => 78
  | .signerFlag => 84 | .currentCountFlag => 90 | .nextCountFlag => 97
  | .policyTag => 104 | .membership => 134 | .distinctInverse => 140

def AuthFamily.width : AuthFamily → Nat
  | .mode => 3 | .inputPrf => 2 | .inputKey => 8 | .legacy => 5
  | .current | .next | .valueLock | .statementDigest | .policy | .intent => 7
  | .scalar => 18 | .thresholdFlag | .signerFlag => 6
  | .currentCountFlag | .nextCountFlag => 7 | .policyTag => 30
  | .membership => 6 | .distinctInverse => 15

def authFamilies : List AuthFamily :=
  [.mode,.inputPrf,.inputKey,.legacy,.current,.next,.valueLock,.statementDigest,
   .policy,.intent,.scalar,.thresholdFlag,.signerFlag,.currentCountFlag,
   .nextCountFlag,.policyTag,.membership,.distinctInverse]

theorem auth_family_extent_bound (family : AuthFamily) : family.base + family.width ≤ 155 := by
  cases family <;> decide

theorem auth_family_widths_sum : (authFamilies.map AuthFamily.width).sum = 155 := by decide

theorem auth_family_intervals_disjoint :
    authFamilies.Pairwise (fun left right => left.base + left.width ≤ right.base) := by decide

theorem auth_families_cover_every_row :
    ∀ row : Fin 155, authFamilies.any (fun family =>
      decide (family.base ≤ row.val ∧ row.val < family.base + family.width)) = true := by decide

def authFamilyWord (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (family : AuthFamily) (index : Nat) : Nat :=
  match family with
  | .mode => authModeFlag witness.authorization.mode index
  | .inputPrf => authInputPrf statement witness.authorization hashes index
  | .inputKey => authInputKey statement witness.authorization hashes (index / 4) (index % 4)
  | .legacy => authHashWord hashes 0 index
  | .current => authHashWord hashes 100 index
  | .next => authHashWord hashes 103 index
  | .valueLock => authHashWord hashes 105 index
  | .statementDigest => authHashWord hashes 93 index
  | .policy => authPolicyWord witness.authorization hashes index
  | .intent => wordAt witness.authorization.current.intentDigest index
  | .scalar => authScalar witness.authorization index
  | .thresholdFlag => authThresholdFlag witness.authorization index
  | .signerFlag => authSignerFlag witness.authorization index
  | .currentCountFlag => authCurrentCountFlag witness.authorization index
  | .nextCountFlag => authNextCountFlag witness.authorization index
  | .policyTag => wordAt (witness.authorization.policySignerTags.getD (index / 5) []) (index % 5)
  | .membership => authMembership witness.authorization hashes index
  | .distinctInverse => authDistinctInverse witness.authorization index

/-- Named source-family addresses, not only local-list indexing. -/
theorem source_auth_family_readback (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (family : AuthFamily) (index : Nat) (bound : index < family.width) :
    sourceAuthRow statement witness hashes (family.base + index) =
      authFamilyWord statement witness hashes family index := by
  cases family <;> simp only [AuthFamily.base, AuthFamily.width, authFamilyWord] at bound ⊢ <;>
    unfold sourceAuthRow <;> dsimp only
  · rw [if_pos (show 0 + index < 3 from by omega)]
    simp only [Nat.zero_add]
  · rw [if_neg (show ¬(3 + index < 3) from by omega),
      if_pos (show 3 + index < 5 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(5 + index < 3) from by omega),
      if_neg (show ¬(5 + index < 5) from by omega),
      if_pos (show 5 + index < 13 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(13 + index < 3) from by omega),
      if_neg (show ¬(13 + index < 5) from by omega),
      if_neg (show ¬(13 + index < 13) from by omega),
      if_pos (show 13 + index < 18 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(18 + index < 3) from by omega),
      if_neg (show ¬(18 + index < 5) from by omega),
      if_neg (show ¬(18 + index < 13) from by omega),
      if_neg (show ¬(18 + index < 18) from by omega),
      if_pos (show 18 + index < 25 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(25 + index < 3) from by omega),
      if_neg (show ¬(25 + index < 5) from by omega),
      if_neg (show ¬(25 + index < 13) from by omega),
      if_neg (show ¬(25 + index < 18) from by omega),
      if_neg (show ¬(25 + index < 25) from by omega),
      if_pos (show 25 + index < 32 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(32 + index < 3) from by omega),
      if_neg (show ¬(32 + index < 5) from by omega),
      if_neg (show ¬(32 + index < 13) from by omega),
      if_neg (show ¬(32 + index < 18) from by omega),
      if_neg (show ¬(32 + index < 25) from by omega),
      if_neg (show ¬(32 + index < 32) from by omega),
      if_pos (show 32 + index < 39 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(39 + index < 3) from by omega),
      if_neg (show ¬(39 + index < 5) from by omega),
      if_neg (show ¬(39 + index < 13) from by omega),
      if_neg (show ¬(39 + index < 18) from by omega),
      if_neg (show ¬(39 + index < 25) from by omega),
      if_neg (show ¬(39 + index < 32) from by omega),
      if_neg (show ¬(39 + index < 39) from by omega),
      if_pos (show 39 + index < 46 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(46 + index < 3) from by omega),
      if_neg (show ¬(46 + index < 5) from by omega),
      if_neg (show ¬(46 + index < 13) from by omega),
      if_neg (show ¬(46 + index < 18) from by omega),
      if_neg (show ¬(46 + index < 25) from by omega),
      if_neg (show ¬(46 + index < 32) from by omega),
      if_neg (show ¬(46 + index < 39) from by omega),
      if_neg (show ¬(46 + index < 46) from by omega),
      if_pos (show 46 + index < 53 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(53 + index < 3) from by omega),
      if_neg (show ¬(53 + index < 5) from by omega),
      if_neg (show ¬(53 + index < 13) from by omega),
      if_neg (show ¬(53 + index < 18) from by omega),
      if_neg (show ¬(53 + index < 25) from by omega),
      if_neg (show ¬(53 + index < 32) from by omega),
      if_neg (show ¬(53 + index < 39) from by omega),
      if_neg (show ¬(53 + index < 46) from by omega),
      if_neg (show ¬(53 + index < 53) from by omega),
      if_pos (show 53 + index < 60 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(60 + index < 3) from by omega),
      if_neg (show ¬(60 + index < 5) from by omega),
      if_neg (show ¬(60 + index < 13) from by omega),
      if_neg (show ¬(60 + index < 18) from by omega),
      if_neg (show ¬(60 + index < 25) from by omega),
      if_neg (show ¬(60 + index < 32) from by omega),
      if_neg (show ¬(60 + index < 39) from by omega),
      if_neg (show ¬(60 + index < 46) from by omega),
      if_neg (show ¬(60 + index < 53) from by omega),
      if_neg (show ¬(60 + index < 60) from by omega),
      if_pos (show 60 + index < 78 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(78 + index < 3) from by omega),
      if_neg (show ¬(78 + index < 5) from by omega),
      if_neg (show ¬(78 + index < 13) from by omega),
      if_neg (show ¬(78 + index < 18) from by omega),
      if_neg (show ¬(78 + index < 25) from by omega),
      if_neg (show ¬(78 + index < 32) from by omega),
      if_neg (show ¬(78 + index < 39) from by omega),
      if_neg (show ¬(78 + index < 46) from by omega),
      if_neg (show ¬(78 + index < 53) from by omega),
      if_neg (show ¬(78 + index < 60) from by omega),
      if_neg (show ¬(78 + index < 78) from by omega),
      if_pos (show 78 + index < 84 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(84 + index < 3) from by omega),
      if_neg (show ¬(84 + index < 5) from by omega),
      if_neg (show ¬(84 + index < 13) from by omega),
      if_neg (show ¬(84 + index < 18) from by omega),
      if_neg (show ¬(84 + index < 25) from by omega),
      if_neg (show ¬(84 + index < 32) from by omega),
      if_neg (show ¬(84 + index < 39) from by omega),
      if_neg (show ¬(84 + index < 46) from by omega),
      if_neg (show ¬(84 + index < 53) from by omega),
      if_neg (show ¬(84 + index < 60) from by omega),
      if_neg (show ¬(84 + index < 78) from by omega),
      if_neg (show ¬(84 + index < 84) from by omega),
      if_pos (show 84 + index < 90 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(90 + index < 3) from by omega),
      if_neg (show ¬(90 + index < 5) from by omega),
      if_neg (show ¬(90 + index < 13) from by omega),
      if_neg (show ¬(90 + index < 18) from by omega),
      if_neg (show ¬(90 + index < 25) from by omega),
      if_neg (show ¬(90 + index < 32) from by omega),
      if_neg (show ¬(90 + index < 39) from by omega),
      if_neg (show ¬(90 + index < 46) from by omega),
      if_neg (show ¬(90 + index < 53) from by omega),
      if_neg (show ¬(90 + index < 60) from by omega),
      if_neg (show ¬(90 + index < 78) from by omega),
      if_neg (show ¬(90 + index < 84) from by omega),
      if_neg (show ¬(90 + index < 90) from by omega),
      if_pos (show 90 + index < 97 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(97 + index < 3) from by omega),
      if_neg (show ¬(97 + index < 5) from by omega),
      if_neg (show ¬(97 + index < 13) from by omega),
      if_neg (show ¬(97 + index < 18) from by omega),
      if_neg (show ¬(97 + index < 25) from by omega),
      if_neg (show ¬(97 + index < 32) from by omega),
      if_neg (show ¬(97 + index < 39) from by omega),
      if_neg (show ¬(97 + index < 46) from by omega),
      if_neg (show ¬(97 + index < 53) from by omega),
      if_neg (show ¬(97 + index < 60) from by omega),
      if_neg (show ¬(97 + index < 78) from by omega),
      if_neg (show ¬(97 + index < 84) from by omega),
      if_neg (show ¬(97 + index < 90) from by omega),
      if_neg (show ¬(97 + index < 97) from by omega),
      if_pos (show 97 + index < 104 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(104 + index < 3) from by omega),
      if_neg (show ¬(104 + index < 5) from by omega),
      if_neg (show ¬(104 + index < 13) from by omega),
      if_neg (show ¬(104 + index < 18) from by omega),
      if_neg (show ¬(104 + index < 25) from by omega),
      if_neg (show ¬(104 + index < 32) from by omega),
      if_neg (show ¬(104 + index < 39) from by omega),
      if_neg (show ¬(104 + index < 46) from by omega),
      if_neg (show ¬(104 + index < 53) from by omega),
      if_neg (show ¬(104 + index < 60) from by omega),
      if_neg (show ¬(104 + index < 78) from by omega),
      if_neg (show ¬(104 + index < 84) from by omega),
      if_neg (show ¬(104 + index < 90) from by omega),
      if_neg (show ¬(104 + index < 97) from by omega),
      if_neg (show ¬(104 + index < 104) from by omega),
      if_pos (show 104 + index < 134 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(134 + index < 3) from by omega),
      if_neg (show ¬(134 + index < 5) from by omega),
      if_neg (show ¬(134 + index < 13) from by omega),
      if_neg (show ¬(134 + index < 18) from by omega),
      if_neg (show ¬(134 + index < 25) from by omega),
      if_neg (show ¬(134 + index < 32) from by omega),
      if_neg (show ¬(134 + index < 39) from by omega),
      if_neg (show ¬(134 + index < 46) from by omega),
      if_neg (show ¬(134 + index < 53) from by omega),
      if_neg (show ¬(134 + index < 60) from by omega),
      if_neg (show ¬(134 + index < 78) from by omega),
      if_neg (show ¬(134 + index < 84) from by omega),
      if_neg (show ¬(134 + index < 90) from by omega),
      if_neg (show ¬(134 + index < 97) from by omega),
      if_neg (show ¬(134 + index < 104) from by omega),
      if_neg (show ¬(134 + index < 134) from by omega),
      if_pos (show 134 + index < 140 from by omega)]
    simp only [Nat.add_sub_cancel_left]
  · rw [if_neg (show ¬(140 + index < 3) from by omega),
      if_neg (show ¬(140 + index < 5) from by omega),
      if_neg (show ¬(140 + index < 13) from by omega),
      if_neg (show ¬(140 + index < 18) from by omega),
      if_neg (show ¬(140 + index < 25) from by omega),
      if_neg (show ¬(140 + index < 32) from by omega),
      if_neg (show ¬(140 + index < 39) from by omega),
      if_neg (show ¬(140 + index < 46) from by omega),
      if_neg (show ¬(140 + index < 53) from by omega),
      if_neg (show ¬(140 + index < 60) from by omega),
      if_neg (show ¬(140 + index < 78) from by omega),
      if_neg (show ¬(140 + index < 84) from by omega),
      if_neg (show ¬(140 + index < 90) from by omega),
      if_neg (show ¬(140 + index < 97) from by omega),
      if_neg (show ¬(140 + index < 104) from by omega),
      if_neg (show ¬(140 + index < 134) from by omega),
      if_neg (show ¬(140 + index < 140) from by omega),
      if_pos (show 140 + index < 155 from by omega)]
    simp only [Nat.add_sub_cancel_left]

theorem source_auth_global_family_readback (before after : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 5888) (family : AuthFamily)
    (index : Nat) (bound : index < family.width) (lane : Fin 64) :
    (packedWitnessLaneRows (embedSourceAuth before after statement witness hashes) lane.val).getD
        (92 + family.base + index) 0 = authFamilyWord statement witness hashes family index := by
  have extent := auth_family_extent_bound family
  have rowBound : family.base + index < 155 := by omega
  rw [show 92 + family.base + index = 92 + (family.base + index) by omega,
    source_auth_global_lane_readback before after statement witness hashes prefixLength
      ⟨family.base + index, rowBound⟩ lane]
  exact source_auth_family_readback statement witness hashes family index bound

theorem source_auth_prefix_unchanged (before after : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (index : Nat) (bound : index < before.length) (fallback : Nat) :
    (embedSourceAuth before after statement witness hashes).getD index fallback =
      before.getD index fallback := by
  simp only [embedSourceAuth, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_left bound]

theorem source_auth_suffix_readback (before after : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (index fallback : Nat) :
    (embedSourceAuth before after statement witness hashes).getD
        (before.length + 9920 + index) fallback = after.getD index fallback := by
  have length := (source_auth_shape statement witness hashes).2
  simp only [embedSourceAuth, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (by omega)]
  have address : before.length + 9920 + index - before.length = 9920 + index := by omega
  rw [address, List.getElem?_append_right (by omega)]
  have finalAddress : 9920 + index - (sourceAuthPacked statement witness hashes).length = index := by omega
  rw [finalAddress]

theorem source_auth_full_rectangle_length (before after : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 5888) (suffixLength : after.length = 28096) :
    (embedSourceAuth before after statement witness hashes).length = 43904 := by
  simp only [embedSourceAuth, List.length_append, prefixLength, suffixLength,
    (source_auth_shape statement witness hashes).2]

theorem inactive_auth_input_sources_zero (statement : V8PublicStatement) (auth : V8AuthorizationWitness)
    (hashes : AuthHashFinals) (input : Nat) (inactive : flagAt statement.inputFlags input = 0) :
    authInputPrf statement auth hashes input = 0 ∧
      ∀ limb, authInputKey statement auth hashes input limb = 0 := by
  simp only [authInputPrf, authInputKey, if_pos inactive, true_and, implies_true]

theorem final_next_count_flag_exact (auth : V8AuthorizationWitness)
    (mode : auth.mode = .finalThresholdSpend) (slot : Nat) :
    authNextCountFlag auth slot = if slot = 0 then 1 else 0 := by
  by_cases zero : slot = 0
  · subst slot
    simp only [authNextCountFlag, mode, authBit]
  · have notZero : ¬0 = slot := Ne.symm zero
    simp only [authNextCountFlag, mode, authBit, if_neg zero, if_neg notZero]

theorem final_next_count_zero_flag_is_one (auth : V8AuthorizationWitness)
    (mode : auth.mode = .finalThresholdSpend) : authNextCountFlag auth 0 = 1 := by
  simpa using final_next_count_flag_exact auth mode 0

theorem reserved_auth_scalars_zero (auth : V8AuthorizationWitness) :
    authScalar auth 16 = 0 ∧ authScalar auth 17 = 0 := by
  constructor <;> rfl


end HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
