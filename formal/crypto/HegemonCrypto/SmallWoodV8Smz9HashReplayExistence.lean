import HegemonCrypto.SmallWoodV8Smz9SemanticPoseidonKernelBinding

namespace HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
noncomputable section

def replayRows (group : Nat) (initial : Nat → F) (row : Nat) : F :=
  sourceHashReplay group initial (row - (283 + 182 * group))

theorem replay_initial (group : Nat) (initial : Nat → F) (i : Nat) (hi : i < 16) :
    replayRows group initial (283 + 182 * group + i) = initial i := by
  unfold replayRows
  rw [Nat.add_sub_cancel_left, sourceHashReplay_eq, if_pos hi]

/-- The exact source DAG admits its constructive replay, for arbitrary public words. -/
theorem replay_has_actual_recurrence (group : Nat) (hg : group < 2)
    (initial pub : Nat → F) : HashRecurrence group pub (replayRows group initial) := by
  intro wire hw
  have off : hashRow group wire - (283 + 182 * group) = 16 + wire := by
    unfold hashRow
    omega
  change sourceHashReplay group initial (hashRow group wire - (283 + 182 * group)) = _
  rw [off, sourceHashReplay_eq, if_neg (by omega), if_pos (by omega)]
  rw [Nat.add_sub_cancel_left]
  obtain ⟨_, _, _, lower, upper⟩ := exact_hash_roots_valid hg hw
  apply fieldAt_congr_on_span (fun _ => 0) pub _ _ (283 + 182 * group)
    (hashRow group wire) (by unfold hashRow; omega) _ _ lower upper
  intro row lo hi
  have window : 283 + 182 * group ≤ row ∧ row < 283 + 182 * group + (16 + wire) := by
    unfold hashRow at hi
    omega
  simp only [if_pos window, replayRows]

theorem recurrence_root_zero (group : Nat) (hg : group < 2) (pub rows : Nat → F)
    (recurrence : HashRecurrence group pub rows) (wire : Nat) (hw : wire < 166) :
    nodeField pub rows (hashRootPair group wire).1 = 0 := by
  obtain ⟨root, _, _, _, _⟩ := exact_hash_roots_valid hg hw
  have equation := HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership.actual_node_field_equation
    pub rows root
  change nodeField pub rows (hashRootPair group wire).1 =
    nodeField pub rows (124 + hashRow group wire) - nodeField pub rows (hashRootPair group wire).2
    at equation
  rw [equation, actual_witness_node_field pub rows (by unfold hashRow; omega)]
  exact sub_eq_zero.mpr (recurrence wire hw)

end
end HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
