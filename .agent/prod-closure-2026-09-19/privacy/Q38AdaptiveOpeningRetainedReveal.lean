import Q38AdaptiveOpeningSelectionLifting
import Q38RetainedOpenedOverlay
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch

/-! The exact retained-overlay and averaged-reveal bridge. Split from
Q38AdaptiveOpening without changing its hypotheses or physical games. -/
namespace HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid V8Smz9MeasuredSourceHiddenPatch
open V8Smz9HonestLeafBatch V8SmzaLeafFrameHybrid V8SmzaRetainedOpenedOverlay V8SmzaSelectionFeedback
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Other Work Job : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]
abbrev Input (Other : Type) := LeafInput ⊕ Other
abbrev Tapes := LeafIndex → LeafTape

/-- Measured retained-opened hop for an arbitrary subnormalized branch.
This derives the support bound using the actual source index/tape projections. -/
theorem conditioned_measured_distance
    (randomized : Bool) (program : Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (known : Tapes)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) :
    uniformAverage (fun fresh : Unopened unopened → LeafTape =>
      |V8Smz9HonestWholeViewGames.run randomized program
          (fullSourceOverlay old other targets Finset.univ (fun _ => header salt)
            (fun i => suffix (data i)) (completeTapes unopened known fresh)) state -
        V8Smz9HonestWholeViewGames.run randomized program
          (fullSourceOverlay old other targets unopenedᶜ (fun _ => header salt)
            (fun i => suffix (data i)) known) state|) ≤
      queryLoss (2 ^ 512 : ℝ)⁻¹ (queryCount program) state := by
  let base := sourceOverlay old targets unopenedᶜ (fun _ => header salt) (fun i => suffix (data i)) known
  let support := indexedSupport
    (Sum.elim (selectUnopened unopened anchor) (fun _ : Other => anchor))
    (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape)))
  have supportBound (input : Input Other) : supportCount support input ≤
      (Fintype.card (Unopened unopened → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
    (indexed_leaf_tape_support_count
      (Sum.elim (selectUnopened unopened anchor) (fun _ : Other => anchor))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))) input).le
  have same (fresh : Unopened unopened → LeafTape) (input : Input Other)
      (outside : input ∉ support fresh) :
      Sum.elim base other input =
        fullSourceOverlay base other targets unopened (fun _ => header salt)
          (fun i => suffix (data i)) (completeTapes unopened known fresh) input := by
    cases input with
    | inl input =>
      have noSource : input ∉ sourcePatchSupport unopened (fun _ => header salt)
          (fun i => suffix (data i)) (completeTapes unopened known fresh) := by
        intro member
        apply outside
        -- Reduce membership to one coordinate equality before specializing
        -- the generic image lemma. This avoids elaborating the concrete
        -- full-sum Fintype enumeration through `completed_patch_support`.
        simp only [support, indexedSupport, Finset.mem_filter,
          Finset.mem_univ, true_and, Sum.elim_inl, selectUnopened]
        exact image_restricted_projection
          (Index := LeafIndex) (Raw := LeafInput) (Tape := LeafTape)
          unopened anchor
          (fun i tape => sourceLeafInput (header salt) (suffix (data i)) i tape)
          rawInputIndex leafTapeProjection
          (fun i tape => source_leaf_index_projection
            (header salt) (suffix (data i)) i tape)
          (fun i tape => source_leaf_tape_projection
            (header salt) (suffix (data i)) i tape)
          (completeTapes unopened known fresh) fresh
          (fun i hi => by simp only [completeTapes, dif_pos hi]) input member
      simp only [fullSourceOverlay, Sum.elim_inl, sourceOverlay, if_neg noSource]
    | inr input => rfl
  simp_rw [full_overlay_decomposition old other targets unopened known]
  exact measured_program_hidden_patch_bound randomized program support (2 ^ 512 : ℝ)⁻¹
    (by positivity) (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num))) supportBound
    (Sum.elim base other)
    (fun fresh => fullSourceOverlay base other targets unopened (fun _ => header salt)
      (fun i => suffix (data i)) (completeTapes unopened known fresh)) same state

def visiblePadding (unopened : Finset LeafIndex) (visible : Opened unopened → LeafTape) : Tapes :=
  (tapeSplit unopened).symm (visible, fun _ => 0)

theorem visible_padding_split (unopened : Finset LeafIndex) (visible : Opened unopened → LeafTape) :
    (tapeSplit unopened (visiblePadding unopened visible)).1 = visible := by
  exact congrArg Prod.fst ((tapeSplit unopened).apply_symm_apply (visible, fun _ => 0))

theorem completed_visible_is_split (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape) (fresh : Unopened unopened → LeafTape) :
    completeTapes unopened (visiblePadding unopened visible) fresh =
      (tapeSplit unopened).symm (visible, fresh) := by
  rw [complete_is_split_reconstruction, visible_padding_split]

theorem opened_split_overlay (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape) (fresh : Unopened unopened → LeafTape)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister)
    (heads : LeafIndex → LeafHeader) (tails : LeafIndex → LeafSuffix) :
    fullSourceOverlay old other targets unopenedᶜ heads tails
        ((tapeSplit unopened).symm (visible, fresh)) =
      fullSourceOverlay old other targets unopenedᶜ heads tails (visiblePadding unopened visible) := by
  rw [← completed_visible_is_split]
  unfold fullSourceOverlay sourceOverlay
  rw [opened_support_retained]

def revealProgram (unopened : Finset LeafIndex)
    (program : (Opened unopened → LeafTape) → Program (Input Other) Work) (tapes : Tapes) :=
  program ((tapeSplit unopened tapes).1)

/-- All tapes are sampled once. Selection has already occurred using the
reference selecPrefix. Exact product disintegration, followed by the measured
support theorem, justifies revealing those selected coordinates. -/
theorem averaged_reveal_bound
    (randomized : Bool) (unopened : Finset LeafIndex) (anchor : Unopened unopened)
    (program : (Opened unopened → LeafTape) → Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ visible, queryCount (program visible) ≤ queries)
    (state : GameState (Input := Input Other) (Work := Work)) :
    |uniformAverage (fun tapes : Tapes =>
        V8Smz9HonestWholeViewGames.run randomized (revealProgram unopened program tapes)
          (fullSourceOverlay old other targets Finset.univ (fun _ => header salt)
            (fun i => suffix (data i)) tapes) state) -
      uniformAverage (fun tapes : Tapes =>
        V8Smz9HonestWholeViewGames.run randomized (revealProgram unopened program tapes)
          (fullSourceOverlay old other targets unopenedᶜ (fun _ => header salt)
            (fun i => suffix (data i)) tapes) state)| ≤
      queryLoss (2 ^ 512 : ℝ)⁻¹ queries state := by
  let real (tapes : Tapes) := V8Smz9HonestWholeViewGames.run randomized
    (revealProgram unopened program tapes)
    (fullSourceOverlay old other targets Finset.univ (fun _ => header salt)
      (fun i => suffix (data i)) tapes) state
  let reference (tapes : Tapes) := V8Smz9HonestWholeViewGames.run randomized
    (revealProgram unopened program tapes)
    (fullSourceOverlay old other targets unopenedᶜ (fun _ => header salt)
      (fun i => suffix (data i)) tapes) state
  change |uniformAverage real - uniformAverage reference| ≤ _
  rw [← uniform_average_equiv (tapeSplit unopened).symm real,
    ← uniform_average_equiv (tapeSplit unopened).symm reference]
  rw [uniform_average_product
      (fun (visible : Opened unopened → LeafTape) (fresh : Unopened unopened → LeafTape) =>
        real ((tapeSplit unopened).symm (visible, fresh))),
    uniform_average_product
      (fun (visible : Opened unopened → LeafTape) (fresh : Unopened unopened → LeafTape) =>
        reference ((tapeSplit unopened).symm (visible, fresh)))]
  apply (average_difference_abs_le _ _).trans
  apply average_le_const
  intro visible
  apply (average_difference_abs_le _ _).trans
  have bound := conditioned_measured_distance randomized (program visible) old other targets unopened anchor
    (visiblePadding unopened visible) salt data state
  simp only [completed_visible_is_split] at bound
  have transported :
      uniformAverage (fun fresh : Unopened unopened → LeafTape =>
        |real ((tapeSplit unopened).symm (visible, fresh)) -
          reference ((tapeSplit unopened).symm (visible, fresh))|) ≤
        queryLoss (2 ^ 512 : ℝ)⁻¹ (queryCount (program visible)) state := by
    simpa only [real, reference, revealProgram, Equiv.apply_symm_apply, opened_split_overlay] using bound
  exact transported.trans (query_loss_mono _ (bounded visible) state)


end
end HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
