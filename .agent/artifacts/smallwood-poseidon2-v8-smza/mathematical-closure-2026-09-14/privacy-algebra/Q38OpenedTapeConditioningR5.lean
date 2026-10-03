import Q38LeafFrameHybridR4
import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout

namespace HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
-- Match the imported generic HiddenPatch proof's finite-function elaboration depth.
set_option maxRecDepth 5000

attribute [local irreducible] header suffix

abbrev Unopened (unopened : Finset LeafIndex) := { i : LeafIndex // i ∈ unopened }
abbrev Opened (unopened : Finset LeafIndex) := { i : LeafIndex // i ∉ unopened }

def q38Unopened (selected : Fin 38 → LeafIndex) : Finset LeafIndex :=
  (Finset.univ.image selected)ᶜ

theorem q38_opened_cardinality (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected) :
    Fintype.card (Opened (q38Unopened selected)) = 38 := by
  simp only [Opened, q38Unopened, Finset.mem_compl, not_not]
  rw [Fintype.card_coe, Finset.card_image_of_injective _ distinct]
  simp

theorem q38_unopened_nonempty (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected) :
    (q38Unopened selected).Nonempty := by
  apply Finset.card_pos.mp
  have count : (Finset.univ.image selected).card = 38 := by
    rw [Finset.card_image_of_injective _ distinct]
    simp
  rw [q38Unopened, Finset.card_compl, count]
  simp only [LeafIndex, Fintype.card_fin]
  norm_num

/-- The set is fixed before this table is sampled. This equivalence does not
    assert independence for a set chosen using the secret table or its oracle. -/
def tapeSplit (unopened : Finset LeafIndex) : (LeafIndex → LeafTape) ≃
    ((Opened unopened → LeafTape) × (Unopened unopened → LeafTape)) where
  toFun table := (fun i => table i, fun i => table i)
  invFun pair i := if h : i ∈ unopened then pair.2 ⟨i, h⟩ else pair.1 ⟨i, h⟩
  left_inv table := by
    funext i
    by_cases h : i ∈ unopened <;> simp [h]
  right_inv pair := by
    apply Prod.ext
    · funext i
      simp [i.property]
    · funext i
      simp [i.property]

/-- Exact full-table joint law, including both revealed and hidden coordinates. -/
theorem tape_split_joint_uniform (unopened : Finset LeafIndex) :
    pmfMap (uniformFintypePMF (LeafIndex → LeafTape)) (tapeSplit unopened) =
      uniformFintypePMF ((Opened unopened → LeafTape) × (Unopened unopened → LeafTape)) :=
  uniform_pmf_map_equiv (tapeSplit unopened)

/-- Pointwise factorization proves fresh unopened tapes after fixing any
    revealed value. It is not merely equality of the two marginals. -/
theorem tape_split_joint_factorization (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape) (fresh : Unopened unopened → LeafTape) :
    pmfMap (uniformFintypePMF (LeafIndex → LeafTape)) (tapeSplit unopened) (visible, fresh) =
      uniformFintypePMF (Opened unopened → LeafTape) visible *
        uniformFintypePMF (Unopened unopened → LeafTape) fresh := by
  rw [tape_split_joint_uniform]
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul]
  exact ENNReal.mul_inv (Or.inr (by simp)) (Or.inl (by simp))

/-- Source q38 opening cardinality is explicit rather than inherited from q20. -/
theorem thirty_eight_opened_coordinates (unopened : Finset LeafIndex)
    (selected : Fintype.card (Opened unopened) = 38) :
    Fintype.card (Opened unopened → LeafTape) = (2 ^ 512 : ℕ) ^ 38 := by
  rw [Fintype.card_fun, selected, leaf_tape_cardinality]

def completeTapes (unopened : Finset LeafIndex) (known : LeafIndex → LeafTape)
    (fresh : Unopened unopened → LeafTape) : LeafIndex → LeafTape :=
  fun i => if h : i ∈ unopened then fresh ⟨i, h⟩ else known i

theorem complete_is_split_reconstruction (unopened : Finset LeafIndex)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape) :
    completeTapes unopened known fresh =
      (tapeSplit unopened).symm ((tapeSplit unopened known).1, fresh) := rfl

theorem complete_retains_fresh_coordinates (unopened : Finset LeafIndex)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape) :
    (tapeSplit unopened (completeTapes unopened known fresh)).2 = fresh := by
  rw [complete_is_split_reconstruction, Equiv.apply_symm_apply]

def selectUnopened (unopened : Finset LeafIndex) (anchor : Unopened unopened)
    (input : LeafInput) : Unopened unopened :=
  if h : rawInputIndex input ∈ unopened then ⟨rawInputIndex input, h⟩ else anchor

/-- Opened tapes are retained as known context, never resampled. -/
theorem complete_preserves_opened (unopened : Finset LeafIndex)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape)
    (i : LeafIndex) (opened : i ∉ unopened) :
    completeTapes unopened known fresh i = known i := by
  simp [completeTapes, opened]

/-- Abstract image-support argument: no concrete tape or input cardinality
    is unfolded while proving membership and the dependent coordinate choice. -/
theorem image_restricted_projection
    {Index Raw Tape : Type*} [DecidableEq Index] [DecidableEq Raw]
    (indices : Finset Index) (anchor : {i : Index // i ∈ indices})
    (constructor : Index → Tape → Raw) (inputIndex : Raw → Index) (inputTape : Raw → Tape)
    (indexLeft : ∀ i tape, inputIndex (constructor i tape) = i)
    (tapeLeft : ∀ i tape, inputTape (constructor i tape) = tape)
    (full : Index → Tape) (fresh : {i : Index // i ∈ indices} → Tape)
    (agrees : ∀ i (hi : i ∈ indices), full i = fresh ⟨i, hi⟩)
    (input : Raw) (member : input ∈ indices.image (fun i => constructor i (full i))) :
    fresh (if h : inputIndex input ∈ indices then ⟨inputIndex input, h⟩ else anchor) =
      inputTape input := by
  obtain ⟨i, hi, same⟩ := Finset.mem_image.mp member
  rw [← same]
  simp only [indexLeft, tapeLeft, dif_pos hi]
  exact (agrees i hi).symm

theorem completed_patch_support {Other : Type*} [Fintype Other] [DecidableEq Other]
    (unopened : Finset LeafIndex) (anchor : Unopened unopened)
    (known : LeafIndex → LeafTape) (fresh : Unopened unopened → LeafTape)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (input : LeafInput)
    (member : input ∈ sourcePatchSupport unopened (fun _ => header salt)
      (fun i => suffix (data i)) (completeTapes unopened known fresh)) :
    (Sum.inl input : LeafInput ⊕ Other) ∈
      indexedSupport (Sum.elim (selectUnopened unopened anchor) (fun _ : Other => anchor))
        (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))) fresh := by
  simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and,
    Sum.elim_inl, selectUnopened]
  exact image_restricted_projection (Index := LeafIndex) (Raw := LeafInput) (Tape := LeafTape)
    unopened anchor (fun i tape => sourceLeafInput (header salt) (suffix (data i)) i tape)
    rawInputIndex leafTapeProjection
    (fun i tape => source_leaf_index_projection (header salt) (suffix (data i)) i tape)
    (fun i tape => source_leaf_tape_projection (header salt) (suffix (data i)) i tape)
    (completeTapes unopened known fresh) fresh
    (fun i hi => by simp only [completeTapes, dif_pos hi]) input member

/-- Freshness is needed only for the unopened coordinates. The public
    reference circuit may depend on all known opened tapes. It may not
    depend on the fresh unopened table. Queries can mix leaf/nonleaf inputs. -/
theorem conditioned_opened_tape_distance
    {Other Output Workspace : Type*}
    [Fintype Other] [DecidableEq Other]
    [Fintype Output] [AddGroup Output] [Fintype Workspace]
    (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (known : LeafIndex → LeafTape)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (steps : ℕ → State (Input := LeafInput ⊕ Other) (Output := Output)
      (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (initial : State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (queries : ℕ) :
    (∑ fresh : Unopened unopened → LeafTape,
      ‖run (fullSourceOverlay oldLeaf other targets unopened (fun _ => header salt)
          (fun i => suffix (data i)) (completeTapes unopened known fresh)) steps initial queries -
        run (Sum.elim oldLeaf other) steps initial queries‖) /
      (Fintype.card (Unopened unopened → LeafTape) : ℝ) ≤
        Real.sqrt (4 * (queries : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  apply mean_run_distance_le_sqrt (Sum.elim oldLeaf other)
    (fun fresh => fullSourceOverlay oldLeaf other targets unopened (fun _ => header salt)
      (fun i => suffix (data i)) (completeTapes unopened known fresh))
    (indexedSupport (Sum.elim (selectUnopened unopened anchor) (fun _ : Other => anchor))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))))
    (2 ^ 512 : ℝ)⁻¹ (by positivity) _ _ steps initial normalized queries
  · intro fresh input outside
    cases input with
    | inl input =>
      have noSource : input ∉ sourcePatchSupport unopened (fun _ => header salt)
          (fun i => suffix (data i)) (completeTapes unopened known fresh) := by
        intro member
        apply outside
        simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and,
          Sum.elim_inl, selectUnopened]
        exact image_restricted_projection (Index := LeafIndex) (Raw := LeafInput) (Tape := LeafTape)
          unopened anchor (fun i tape => sourceLeafInput (header salt) (suffix (data i)) i tape)
          rawInputIndex leafTapeProjection
          (fun i tape => source_leaf_index_projection (header salt) (suffix (data i)) i tape)
          (fun i tape => source_leaf_tape_projection (header salt) (suffix (data i)) i tape)
          (completeTapes unopened known fresh) fresh
          (fun i hi => by simp only [completeTapes, dif_pos hi]) input member
      simp [fullSourceOverlay, sourceOverlay, noSource]
    | inr input => rfl
  · intro input
    exact (indexed_leaf_tape_support_count
      (Sum.elim (selectUnopened unopened anchor) (fun _ : Other => anchor))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))) input).le

/-- A full quantum observer, including hidden-table-dependent final operations,
    is preserved. All pre-measurement circuits may depend on the fixed revealed
    context. Only the unopened table is averaged; no revealed tape is redrawn. -/
theorem conditioned_opened_tape_observation
    {Other Output Workspace : Type*}
    [Fintype Other] [DecidableEq Other]
    [Fintype Output] [AddGroup Output] [DecidableEq Output]
    [Fintype Workspace] [DecidableEq Workspace]
    (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (known : LeafIndex → LeafTape)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (steps : ℕ → State (Input := LeafInput ⊕ Other) (Output := Output)
      (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (initial : State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (queries : ℕ)
    (post : (Unopened unopened → LeafTape) →
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (event : (Unopened unopened → LeafTape) →
      Finset (QueryBasis (LeafInput ⊕ Other) Output Workspace)) :
    |(∑ fresh : Unopened unopened → LeafTape,
        born (event fresh) (post fresh
          (run (fullSourceOverlay oldLeaf other targets unopened (fun _ => header salt)
            (fun i => suffix (data i)) (completeTapes unopened known fresh)) steps initial queries))) /
          (Fintype.card (Unopened unopened → LeafTape) : ℝ) -
      (∑ fresh : Unopened unopened → LeafTape,
        born (event fresh) (post fresh
          (run (Sum.elim oldLeaf other) steps initial queries))) /
          (Fintype.card (Unopened unopened → LeafTape) : ℝ)| ≤
      2 * Real.sqrt (4 * (queries : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) := by
  have measurement := cq_born_difference_le
    (fun fresh => run (fullSourceOverlay oldLeaf other targets unopened (fun _ => header salt)
      (fun i => suffix (data i)) (completeTapes unopened known fresh)) steps initial queries)
    (fun _fresh => run (Sum.elim oldLeaf other) steps initial queries) post event
    (fun _fresh => (run_norm _ steps initial queries).trans normalized)
    (fun _fresh => (run_norm (Sum.elim oldLeaf other) steps initial queries).trans normalized)
  exact measurement.trans (mul_le_mul_of_nonneg_left
    (conditioned_opened_tape_distance oldLeaf other targets unopened anchor known salt data
      steps initial normalized queries) (by norm_num))

end
end HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
