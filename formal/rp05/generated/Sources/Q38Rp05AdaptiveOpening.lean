import Q38Rp05LeafSupport
import Q38AdaptiveOpeningSelectionLifting
import Q38RetainedOpenedOverlay
import Q38AdaptiveOpeningFeedbackOperator
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch

/-! Selection feedback and retained openings for the RP05 strict-leaf key.
Only the leaf projection and generic selection/retention interfaces are
needed here; the concrete CMS request compiler is not a dependency. -/
namespace HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid
open HegemonCrypto.SmallWood.V8Smz9MeasuredSourceHiddenPatch
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

-- Prove monotonicity before specializing the secret to the full tape table.
-- Case analysis inside that concrete finite sum expands its gigantic carrier.
private theorem support_count_mono
    {Raw Hidden : Type} [DecidableEq Raw] [Fintype Hidden]
    (left right : Hidden → Finset Raw)
    (included : ∀ hidden, left hidden ⊆ right hidden) (input : Raw) :
    supportCount left input ≤ supportCount right input := by
  unfold supportCount
  apply Finset.sum_le_sum
  intro hidden _
  by_cases member : input ∈ left hidden
  · have larger := included hidden member
    simp only [if_pos member, if_pos larger, le_refl]
  · simp only [if_neg member]
    split <;> norm_num

-- Keep the subset-to-count bridge abstract as well: specializing a concrete
-- subset proof would still compare the full raw-input finite enumerations.
private theorem image_leaf_support_count_bound
    {Raw Index : Type} [Fintype Raw] [DecidableEq Raw]
    [Fintype Index] [DecidableEq Index]
    (make : Index → LeafTape → Raw) (inputIndex : Raw → Index)
    (inputTape : Raw → LeafTape)
    (indexLeft : ∀ index tape, inputIndex (make index tape) = index)
    (tapeLeft : ∀ index tape, inputTape (make index tape) = tape)
    (indices : Finset Index) (input : Raw) :
    supportCount (fun hidden : Index → LeafTape =>
      indices.image (fun index => make index (hidden index))) input ≤
      (Fintype.card (Index → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  exact (support_count_mono
    (fun hidden : Index → LeafTape => indices.image (fun index => make index (hidden index)))
    (indexedSupport inputIndex inputTape)
    (image_subset_indexed_support make inputIndex inputTape indexLeft tapeLeft indices)
    input).trans (indexed_leaf_tape_support_count inputIndex inputTape input).le

variable {Other Work Job : Type}
variable [Fintype Other] [DecidableEq Other] [Fintype Work]
abbrev Input (Other : Type) := Rp05LeafInput ⊕ Other
abbrev Tapes := LeafIndex → LeafTape

-- These are definitionally the full-sum projections from the concrete CMS
-- module. Keep them local so this leaf does not import that request compiler.
local notation "rp05FullIndex" =>
  (Sum.elim rp05IndexProjection (fun _ : Other => (0 : LeafIndex)))
local notation "rp05FullTape" =>
  (Sum.elim rp05TapeProjection (fun _ : Other => (0 : LeafTape)))

def constructor (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes)
    (index : LeafIndex) : Input Other :=
  Sum.inl (rp05SourceLeafInput preamble salt (data index) index (tapes index))

def support (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (programmed : Finset LeafIndex)
    (tapes : Tapes) : Finset (Input Other) :=
  programmed.image (constructor preamble salt data tapes)

def overlay (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (programmed : Finset LeafIndex)
    (tapes : Tapes) : Input Other → DigestRegister := fun input =>
  if input ∈ support preamble salt data programmed tapes then
    targets (rp05FullIndex input)
  else Sum.elim old other input

omit [Fintype Other] [DecidableEq Other] in
theorem constructor_index (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes)
    (index : LeafIndex) :
    rp05FullIndex (constructor (Other := Other) preamble salt data tapes index) =
      index := rp05_source_leaf_index_projection _ _ _ _ _

omit [Fintype Other] [DecidableEq Other] in
theorem constructor_tape (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes)
    (index : LeafIndex) :
    rp05FullTape (constructor (Other := Other) preamble salt data tapes index) =
      tapes index := rp05_source_leaf_tape_projection _ _ _ _ _

theorem support_subset_indexed (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (programmed : Finset LeafIndex) (tapes : Tapes) :
    support (Other := Other) preamble salt data programmed tapes ⊆
      indexedSupport rp05FullIndex rp05FullTape tapes := by
  exact image_subset_indexed_support
    (fun index tape => (Sum.inl
      (rp05SourceLeafInput preamble salt (data index) index tape) : Input Other))
    rp05FullIndex rp05FullTape
    (fun index tape => rp05_source_leaf_index_projection _ _ _ _ _)
    (fun index tape => rp05_source_leaf_tape_projection _ _ _ _ _)
    programmed tapes

theorem support_count_bound (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (programmed : Finset LeafIndex)
    (input : Input Other) :
    supportCount (fun tapes : Tapes =>
      support (Other := Other) preamble salt data programmed tapes) input ≤
      (Fintype.card Tapes : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
  exact image_leaf_support_count_bound (Raw := Input Other) (Index := LeafIndex)
    (fun index tape => (Sum.inl
      (rp05SourceLeafInput preamble salt (data index) index tape) : Input Other))
    rp05FullIndex rp05FullTape
    (fun index tape => rp05_source_leaf_index_projection _ _ _ _ _)
    (fun index tape => rp05_source_leaf_tape_projection _ _ _ _ _)
    programmed input

def realOracle (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) :
    Input Other → DigestRegister :=
  overlay old other targets preamble salt data Finset.univ tapes

def realKernel (randomized : Bool) (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) :
    PhysicalKernel (Input := Input Other) (Work := Work) Job :=
  programKernel randomized
    (fun job => program job ((tapeSplit (unopened job) tapes).1))
    (fun _ => realOracle old other targets preamble salt data tapes)

def publicKernel (randomized : Bool) (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) :
    PhysicalKernel (Input := Input Other) (Work := Work) Job :=
  programKernel randomized
    (fun job => program job ((tapeSplit (unopened job) tapes).1))
    (fun job => overlay old other targets preamble salt data
      (unopened job)ᶜ tapes)

def fullGame (randomized : Bool) (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) : ℝ :=
  uniformAverage fun tapes : Tapes => execute selecPrefix
    (realKernel randomized unopened program old other targets preamble salt data tapes).observe
    (realOracle old other targets preamble salt data tapes) state

def publicGame (randomized : Bool) (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) : ℝ :=
  uniformAverage fun tapes : Tapes => execute selecPrefix
    (publicKernel randomized unopened program old other targets preamble salt data tapes).observe
    (Sum.elim old other) state

/- The two charged stages are expressed with the generic measured-patch
theorems.  This successor specialization supplies their support count from
the literal v2 tape projection rather than accepting it as a premise. -/
theorem preselection_feedback_bound (randomized : Bool)
    (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) :
    |fullGame randomized selecPrefix unopened program old other targets preamble salt data state -
      uniformAverage (fun tapes : Tapes => execute selecPrefix
        (realKernel randomized unopened program old other targets preamble salt data tapes).observe
        (Sum.elim old other) state)| ≤
      queryLoss (2 ^ 512 : ℝ)⁻¹ (exposures selecPrefix) state := by
  -- Compose probability continuity at abstract carrier types in the checked
  -- operator; specialize once to the 2,511-byte RP05 carrier here.
  exact selection_feedback_probability_bound
    (Input := Input Other) (Work := Work) (Job := Job) (Secret := Tapes)
    selecPrefix
    (realKernel randomized unopened program old other targets preamble salt data)
    (fun tapes => support (Other := Other) preamble salt data Finset.univ tapes)
    (2 ^ 512 : ℝ)⁻¹ (by positivity)
    (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num)))
    (support_count_bound preamble salt data Finset.univ)
    (Sum.elim old other)
    (realOracle old other targets preamble salt data)
    (fun tapes input outside => by
      simp only [realOracle, overlay, if_neg outside]) state

def selectRp05Unopened (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (input : Input Other) : Unopened unopened :=
  if h : rp05FullIndex input ∈ unopened then ⟨rp05FullIndex input, h⟩ else anchor

theorem completed_support_subset (unopened : Finset LeafIndex)
    (anchor : Unopened unopened) (known : Tapes)
    (fresh : Unopened unopened → LeafTape)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) :
    support (Other := Other) preamble salt data unopened
        (completeTapes unopened known fresh) ⊆
      indexedSupport (selectRp05Unopened unopened anchor) rp05FullTape fresh := by
  intro input member
  simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and,
    selectRp05Unopened]
  exact image_restricted_projection (Index := LeafIndex)
    (Raw := Input Other) (Tape := LeafTape) unopened anchor
    (fun index tape => (Sum.inl
      (rp05SourceLeafInput preamble salt (data index) index tape) : Input Other))
    rp05FullIndex rp05FullTape
    (fun index tape => rp05_source_leaf_index_projection _ _ _ _ _)
    (fun index tape => rp05_source_leaf_tape_projection _ _ _ _ _)
    (completeTapes unopened known fresh) fresh
    (fun index hi => by simp [completeTapes, hi]) input member

omit [Fintype Other] in
theorem opened_support_retained (unopened : Finset LeafIndex)
    (known : Tapes) (fresh : Unopened unopened → LeafTape)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) :
    support (Other := Other) preamble salt data unopenedᶜ
        (completeTapes unopened known fresh) =
      support (Other := Other) preamble salt data unopenedᶜ known := by
  apply Finset.image_congr
  intro index member
  dsimp only [constructor]
  rw [complete_preserves_opened unopened known fresh index
    (Finset.mem_compl.mp member)]

omit [Fintype Other] in
theorem overlay_decomposition (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (unopened : Finset LeafIndex) (known : Tapes)
    (fresh : Unopened unopened → LeafTape)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) :
    overlay old other targets preamble salt data Finset.univ
        (completeTapes unopened known fresh) =
      overlay
        (fun input => overlay old other targets preamble salt data
          unopenedᶜ known (Sum.inl input))
        other targets preamble salt data unopened
          (completeTapes unopened known fresh) := by
  have openedEq := opened_support_retained (Other := Other) unopened known fresh
    preamble salt data
  dsimp only [support] at openedEq
  have union : unopenedᶜ ∪ unopened = Finset.univ := by
    ext index
    by_cases member : index ∈ unopened <;> simp [member]
  funext input
  cases input with
  | inl leaf =>
      unfold overlay support
      rw [← union, Finset.image_union, openedEq]
      simp only [Finset.mem_union, Sum.elim_inl]
      by_cases hu : (Sum.inl leaf : Input Other) ∈ unopened.image
          (constructor (Other := Other) preamble salt data (completeTapes unopened known fresh))
      · simp only [hu, or_true, ite_true]
      · simp only [hu, or_false, ite_false]
  | inr nonleaf =>
      have absent (indices : Finset LeafIndex) (tapes : Tapes) :
          (Sum.inr nonleaf : Input Other) ∉
            indices.image (constructor preamble salt data tapes) := by
        intro member
        obtain ⟨index, _, impossible⟩ := Finset.mem_image.mp member
        cases impossible
      simp [overlay, support, absent]

/-- Conditional erasure of exactly the unopened RP05 cells.  The 512-bit
fiber probability follows from the literal successor address projection. -/
theorem conditioned_measured_distance (randomized : Bool)
    (program : Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (unopened : Finset LeafIndex) (anchor : Unopened unopened)
    (known : Tapes) (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) :
    uniformAverage (fun fresh : Unopened unopened → LeafTape =>
      |V8Smz9HonestWholeViewGames.run randomized program
          (overlay old other targets preamble salt data Finset.univ
            (completeTapes unopened known fresh)) state -
        V8Smz9HonestWholeViewGames.run randomized program
          (overlay old other targets preamble salt data unopenedᶜ known) state|) ≤
      queryLoss (2 ^ 512 : ℝ)⁻¹ (queryCount program) state := by
  let retained : Rp05LeafInput → DigestRegister := fun input =>
    overlay old other targets preamble salt data unopenedᶜ known (Sum.inl input)
  have retainedOracle : Sum.elim retained other =
      overlay old other targets preamble salt data unopenedᶜ known := by
    funext input
    cases input with
    | inl leaf => rfl
    | inr nonleaf =>
        have absent : (Sum.inr nonleaf : Input Other) ∉
            support preamble salt data unopenedᶜ known := by
          intro member
          change Sum.inr nonleaf ∈ unopenedᶜ.image
            (constructor preamble salt data known) at member
          obtain ⟨index, _, impossible⟩ := Finset.mem_image.mp member
          cases impossible
        simp only [overlay, if_neg absent, Sum.elim_inr]
  let indexed := indexedSupport (selectRp05Unopened unopened anchor) rp05FullTape
  have countBound (input : Input Other) : supportCount indexed input ≤
      (Fintype.card (Unopened unopened → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
    (indexed_leaf_tape_support_count
      (selectRp05Unopened unopened anchor) rp05FullTape input).le
  have same (fresh : Unopened unopened → LeafTape) (input : Input Other)
      (outside : input ∉ indexed fresh) :
      Sum.elim retained other input =
        overlay retained other targets preamble salt data unopened
          (completeTapes unopened known fresh) input := by
    unfold overlay
    rw [if_neg]
    intro member
    apply outside
    -- Reduce to the selected coordinate before applying the abstract image
    -- lemma. Applying a concrete Finset subset unfolds the huge carrier.
    simp only [indexed, indexedSupport, Finset.mem_filter, Finset.mem_univ,
      true_and, selectRp05Unopened]
    exact image_restricted_projection (Index := LeafIndex)
      (Raw := Input Other) (Tape := LeafTape) unopened anchor
      (fun index tape => (Sum.inl
        (rp05SourceLeafInput preamble salt (data index) index tape) : Input Other))
      rp05FullIndex rp05FullTape
      (fun index tape => rp05_source_leaf_index_projection _ _ _ _ _)
      (fun index tape => rp05_source_leaf_tape_projection _ _ _ _ _)
      (completeTapes unopened known fresh) fresh
      (fun index hi => by simp only [completeTapes, dif_pos hi]) input member
  simp_rw [overlay_decomposition old other targets unopened known]
  have distance := measured_program_hidden_patch_bound randomized program indexed
    (2 ^ 512 : ℝ)⁻¹ (by positivity)
    (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num))) countBound
    (Sum.elim retained other)
    (fun fresh => overlay retained other targets preamble salt data unopened
      (completeTapes unopened known fresh)) same state
  simpa only [programDistance, retainedOracle] using distance

def visiblePadding (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape) : Tapes :=
  (tapeSplit unopened).symm (visible, fun _ => 0)

def revealProgram (unopened : Finset LeafIndex)
    (program : (Opened unopened → LeafTape) → Program (Input Other) Work)
    (tapes : Tapes) : Program (Input Other) Work :=
  program ((tapeSplit unopened tapes).1)

theorem completed_visible_is_split (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape)
    (fresh : Unopened unopened → LeafTape) :
    completeTapes unopened (visiblePadding unopened visible) fresh =
      (tapeSplit unopened).symm (visible, fresh) := by
  rw [complete_is_split_reconstruction]
  unfold visiblePadding
  rw [Equiv.apply_symm_apply]

omit [Fintype Other] in
theorem opened_overlay_split (unopened : Finset LeafIndex)
    (visible : Opened unopened → LeafTape)
    (fresh : Unopened unopened → LeafTape)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) :
    overlay old other targets preamble salt data unopenedᶜ
        ((tapeSplit unopened).symm (visible, fresh)) =
      overlay old other targets preamble salt data unopenedᶜ
        (visiblePadding unopened visible) := by
  rw [← completed_visible_is_split]
  unfold overlay
  rw [opened_support_retained]

/-- Exact product disintegration of the full table followed by the conditional
measured-patch bound.  Opened coordinates remain present in the reference. -/
theorem averaged_reveal_bound (randomized : Bool)
    (unopened : Finset LeafIndex) (anchor : Unopened unopened)
    (program : (Opened unopened → LeafTape) → Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ visible, queryCount (program visible) ≤ queries)
    (state : GameState (Input := Input Other) (Work := Work)) :
    |uniformAverage (fun tapes : Tapes =>
        V8Smz9HonestWholeViewGames.run randomized
          (revealProgram unopened program tapes)
          (realOracle old other targets preamble salt data tapes) state) -
      uniformAverage (fun tapes : Tapes =>
        V8Smz9HonestWholeViewGames.run randomized
          (revealProgram unopened program tapes)
          (overlay old other targets preamble salt data unopenedᶜ tapes) state)| ≤
      queryLoss (2 ^ 512 : ℝ)⁻¹ queries state := by
  let real (tapes : Tapes) := V8Smz9HonestWholeViewGames.run randomized
    (revealProgram unopened program tapes)
    (realOracle old other targets preamble salt data tapes) state
  let reference (tapes : Tapes) := V8Smz9HonestWholeViewGames.run randomized
    (revealProgram unopened program tapes)
    (overlay old other targets preamble salt data unopenedᶜ tapes) state
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
  have bound := conditioned_measured_distance randomized (program visible) old other
    targets unopened anchor (visiblePadding unopened visible) preamble salt data state
  simp only [completed_visible_is_split] at bound
  have transported :
      uniformAverage (fun fresh : Unopened unopened → LeafTape =>
        |real ((tapeSplit unopened).symm (visible, fresh)) -
          reference ((tapeSplit unopened).symm (visible, fresh))|) ≤
        queryLoss (2 ^ 512 : ℝ)⁻¹ (queryCount (program visible)) state := by
    simpa only [real, reference, realOracle, revealProgram,
      Equiv.apply_symm_apply, opened_overlay_split] using bound
  exact transported.trans (query_loss_mono _ (bounded visible) state)

/-- The complete two-stage successor bound: first remove tape feedback from
the adaptive selection prefix, then erase only the unopened cells after exact
product disintegration.  The only hypotheses are executable query bounds. -/
theorem adaptive_opening_bound_mass (randomized : Bool)
    (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (anchor : ∀ job, Unopened (unopened job))
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState (Input := Input Other) (Work := Work)) :
    |fullGame randomized selecPrefix unopened program old other targets preamble salt data state -
      publicGame randomized selecPrefix unopened program old other targets preamble salt data state| ≤
      (4 * ((exposures selecPrefix : ℝ) + queries) / (2 ^ 256 : ℝ)) *
        ‖state‖ ^ 2 := by
  let real := realKernel randomized unopened program old other targets preamble salt data
  let reference := publicKernel randomized unopened program old other targets preamble salt data
  let middle := uniformAverage fun tapes : Tapes =>
    execute selecPrefix (real tapes).observe (Sum.elim old other) state
  have first :
      |fullGame randomized selecPrefix unopened program old other targets preamble salt data state -
        middle| ≤ queryLoss (2 ^ 512 : ℝ)⁻¹ (exposures selecPrefix) state :=
    preselection_feedback_bound randomized selecPrefix unopened program old other targets
      preamble salt data state
  have second :
      |middle - publicGame randomized selecPrefix unopened program old other targets
        preamble salt data state| ≤
        queryLoss (2 ^ 512 : ℝ)⁻¹ queries state := by
    change |uniformAverage (fun tapes : Tapes =>
        execute selecPrefix (real tapes).observe (Sum.elim old other) state) -
      uniformAverage (fun tapes : Tapes =>
        execute selecPrefix (reference tapes).observe (Sum.elim old other) state)| ≤ _
    rw [execute_average, execute_average]
    apply execute_pivot_bound selecPrefix _ _
      (4 * (queries : ℝ) * Real.sqrt (2 ^ 512 : ℝ)⁻¹)
    intro job branchState
    exact averaged_reveal_bound randomized (unopened job) (anchor job)
      (program job) old other targets preamble salt data queries
      (bounded job) branchState
  calc
    _ ≤ |fullGame randomized selecPrefix unopened program old other targets preamble salt data state -
          middle| +
        |middle - publicGame randomized selecPrefix unopened program old other targets
          preamble salt data state| := abs_sub_le _ _ _
    _ ≤ queryLoss (2 ^ 512 : ℝ)⁻¹ (exposures selecPrefix) state +
        queryLoss (2 ^ 512 : ℝ)⁻¹ queries state := add_le_add first second
    _ = _ := by
      simp only [queryLoss, sqrt_source_tape_cap]
      ring

/-- Unit-state specialization. The mass form above also covers zero-mass
and unnormalised measured branches without changing their oracle family. -/
theorem adaptive_opening_bound (randomized : Bool)
    (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (anchor : ∀ job, Unopened (unopened job))
    (program : (job : Job) → (Opened (unopened job) → LeafTape) →
      Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState (Input := Input Other) (Work := Work))
    (normalized : ‖state‖ = 1) :
    |fullGame randomized selecPrefix unopened program old other targets preamble salt data state -
      publicGame randomized selecPrefix unopened program old other targets preamble salt data state| ≤
      4 * ((exposures selecPrefix : ℝ) + queries) / (2 ^ 256 : ℝ) := by
  simpa only [normalized, one_pow, mul_one] using
    adaptive_opening_bound_mass randomized selecPrefix unopened anchor program
      old other targets preamble salt data queries bounded state

def q38Anchor (selected : Fin 38 → LeafIndex)
    (distinct : Function.Injective selected) :
    Unopened (q38Unopened selected) :=
  ⟨(q38_unopened_nonempty selected distinct).choose,
    (q38_unopened_nonempty selected distinct).choose_spec⟩

theorem q38_adaptive_opening_bound (randomized : Bool)
    (selecPrefix : Selection (Input Other) Work Job)
    (selected : Job → Fin 38 → LeafIndex)
    (distinct : ∀ job, Function.Injective (selected job))
    (program : (job : Job) →
      (Opened (q38Unopened (selected job)) → LeafTape) →
        Program (Input Other) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Other → DigestRegister) (targets : LeafIndex → DigestRegister)
    (preamble : SmzaRp05StatementNamespace.Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (queries : Nat) (bounded : ∀ job visible,
      queryCount (program job visible) ≤ queries)
    (state : GameState (Input := Input Other) (Work := Work))
    (normalized : ‖state‖ = 1) :
    |fullGame randomized selecPrefix (fun job => q38Unopened (selected job)) program
        old other targets preamble salt data state -
      publicGame randomized selecPrefix (fun job => q38Unopened (selected job)) program
        old other targets preamble salt data state| ≤
      4 * ((exposures selecPrefix : ℝ) + queries) / (2 ^ 256 : ℝ) :=
  adaptive_opening_bound randomized selecPrefix
    (fun job => q38Unopened (selected job))
    (fun job => q38Anchor (selected job) (distinct job)) program
    old other targets preamble salt data queries bounded state normalized

end
end HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
