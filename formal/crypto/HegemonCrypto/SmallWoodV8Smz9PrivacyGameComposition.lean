import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch

/-!
# Atomic SMZ9 privacy-game composition

Fresh tape disintegration is derived from an explicit product experiment. The
opening selector and reference context are generated without reading fresh
unopened tapes. No whole-view privacy or game-equivalence premise is used.
The separate honest-hash/randomized-label QROM transition remains external.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition

open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout V8Smz9HiddenLeafQrom
open V8Smz9HonestHybrid V8Smz9EagerPrivacy V8Smz9HiddenPatch
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000
set_option linter.unusedSectionVars false

theorem uniform_product_bind {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] :
    uniformFintypePMF (A × B) = (uniformFintypePMF A).bind fun a =>
      pmfMap (uniformFintypePMF B) (fun b => (a, b)) := by
  apply PMF.ext
  intro pair
  rcases pair with ⟨a, b⟩
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul,
    PMF.bind_apply, pmfMap, Function.comp_apply, PMF.pure_apply, Prod.mk.injEq]
  simp [ite_and]
  exact @ENNReal.mul_inv (Fintype.card A : ℝ≥0∞) (Fintype.card B : ℝ≥0∞)
    (Or.inr (by simp)) (Or.inl (by simp))

variable {Index Tape : Type*} [Fintype Index] [DecidableEq Index]
variable [Fintype Tape] [Nonempty Tape]

abbrev OpenedTapes (opened : Finset Index) := {index // index ∈ opened} → Tape
abbrev HiddenTapes (opened : Finset Index) := {index // index ∉ opened} → Tape

def splitTapes (opened : Finset Index) :
    (Index → Tape) ≃ OpenedTapes (Tape := Tape) opened × HiddenTapes (Tape := Tape) opened :=
  Equiv.piEquivPiSubtypeProd (fun index => index ∈ opened) (fun _ => Tape)

def mergeTapes (opened : Finset Index) (visible : OpenedTapes (Tape := Tape) opened)
    (hidden : HiddenTapes (Tape := Tape) opened) : Index → Tape :=
  (splitTapes opened).symm (visible, hidden)

theorem merge_tapes_opened (opened : Finset Index) (visible : OpenedTapes (Tape := Tape) opened)
    (hidden : HiddenTapes (Tape := Tape) opened) (index : Index) (member : index ∈ opened) :
    mergeTapes opened visible hidden index = visible ⟨index, member⟩ := by
  simp [mergeTapes, splitTapes, member]

theorem merge_tapes_hidden (opened : Finset Index) (visible : OpenedTapes (Tape := Tape) opened)
    (hidden : HiddenTapes (Tape := Tape) opened) (index : Index) (outside : index ∉ opened) :
    mergeTapes opened visible hidden index = hidden ⟨index, outside⟩ := by
  simp [mergeTapes, splitTapes, outside]

theorem split_tapes_uniform (opened : Finset Index) :
    pmfMap (uniformFintypePMF (Index → Tape)) (splitTapes opened) =
      uniformFintypePMF (OpenedTapes (Tape := Tape) opened × HiddenTapes (Tape := Tape) opened) :=
  uniform_pmf_map_equiv (splitTapes opened)

/-- Full disintegration retains arbitrary observations of both tape halves. -/
theorem fresh_tape_disintegration {Result : Type*} (opened : Finset Index)
    (observe : OpenedTapes (Tape := Tape) opened → HiddenTapes (Tape := Tape) opened → PMF Result) :
    ((uniformFintypePMF (Index → Tape)).bind fun tapes =>
      observe ((splitTapes opened tapes).1) ((splitTapes opened tapes).2)) =
    ((uniformFintypePMF (OpenedTapes (Tape := Tape) opened)).bind fun visible =>
      (uniformFintypePMF (HiddenTapes (Tape := Tape) opened)).bind fun hidden => observe visible hidden) := by
  calc
    _ = (pmfMap (uniformFintypePMF (Index → Tape)) (splitTapes opened)).bind
        (fun pair => observe pair.1 pair.2) := by
      simp only [pmfMap, PMF.bind_bind, Function.comp_apply, PMF.pure_bind]
    _ = _ := by
      rw [split_tapes_uniform, uniform_product_bind]
      simp only [pmfMap, PMF.bind_bind, Function.comp_apply, PMF.pure_bind]

/-- The opening set may depend on the entire non-leaf context, but not on fresh tapes.
This equality also retains a context/opened-tape-generated reference cq state.
-/
theorem generated_context_has_fresh_hidden_tapes {Context Reference Result : Type*}
    (contextLaw : PMF Context) (chooseOpened : Context → Finset Index)
    (reference : (context : Context) → OpenedTapes (Tape := Tape) (chooseOpened context) → Reference)
    (observe : (context : Context) → OpenedTapes (Tape := Tape) (chooseOpened context) →
      HiddenTapes (Tape := Tape) (chooseOpened context) → Reference → PMF Result) :
    (contextLaw.bind fun context =>
      (uniformFintypePMF (Index → Tape)).bind fun tapes =>
        let split := splitTapes (chooseOpened context) tapes
        observe context split.1 split.2 (reference context split.1)) =
    (contextLaw.bind fun context =>
      (uniformFintypePMF (OpenedTapes (Tape := Tape) (chooseOpened context))).bind fun visible =>
        (uniformFintypePMF (HiddenTapes (Tape := Tape) (chooseOpened context))).bind fun hidden =>
          observe context visible hidden (reference context visible)) := by
  apply congrArg (PMF.bind contextLaw)
  funext context
  exact fresh_tape_disintegration (chooseOpened context)
    (fun visible hidden => observe context visible hidden (reference context visible))

/-- A sampler abort reveals no leaf tapes; the unopened support is the full domain. -/
def openedOrEmpty (selection : Option (Finset Index)) : Finset Index := selection.getD ∅

theorem aborted_opened_set : openedOrEmpty (none : Option (Finset Index)) = ∅ := rfl

theorem uniform_hidden_padding (opened : Finset Index) :
    pmfMap (uniformFintypePMF (Index → Tape)) (fun tapes => (splitTapes opened tapes).2) =
      uniformFintypePMF (HiddenTapes (Tape := Tape) opened) := by
  have split := split_tapes_uniform (Tape := Tape) opened
  have pushed := congrArg (fun law => pmfMap law Prod.snd) split
  rw [pmfMap_comp, uniform_product_bind] at pushed
  simpa [pmfMap, PMF.bind_bind, Function.comp_def] using pushed

/-- Unused fresh coordinates on opened leaves do not change any hidden-half observation. -/
theorem fresh_hidden_padding_observation {Result : Type*} (opened : Finset Index)
    (observe : HiddenTapes (Tape := Tape) opened → PMF Result) :
    ((uniformFintypePMF (Index → Tape)).bind fun tapes => observe (splitTapes opened tapes).2) =
      (uniformFintypePMF (HiddenTapes (Tape := Tape) opened)).bind observe := by
  have pushed := congrArg (fun law => law.bind observe) (uniform_hidden_padding (Tape := Tape) opened)
  simpa only [pmfMap, PMF.bind_bind, Function.comp_apply, PMF.pure_bind] using pushed

/-- The actual leaf role cannot affect the generated adaptive non-leaf trace or its selector. -/
theorem atomic_nonleaf_selection_independent_of_overlay
    {Payload Output Result : Type*}
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output)
    (program : NonLeafProgram Payload Output Result)
    (chooseOpened : (Result × List ((HashRole × Payload) × Output)) → Option (Finset Index)) :
    openedOrEmpty (chooseOpened (runNonLeafProgram (applyLeafOverlay oracle overlay) program)) =
      openedOrEmpty (chooseOpened (runNonLeafProgram oracle program)) := by
  rw [delayed_leaf_overlay_preserves_all_internal_queries]

section SourceAlgebraicContext

open V8Smz9ZeroKnowledge V8Smz9SingleProofPrivacy V8Smz9JointAlgebraicLaw

/-- The first Q/M chronological transport also retains the entire fresh tape
table and original masks, including every correlated leaf-program input.
-/
theorem joint_mask_transport_with_fresh_tapes
    {F Base Leaves Result : Type*} [Field F] [Fintype F]
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (gammaD : Leaves → DecsGamma F)
    (heads : Base → PiopCoefficients F → LvcsCommittedHeads F)
    (tails : Base → LvcsRandomTailCoins F)
    (piopUnmasked : Base → Leaves → DecsFullCoefficients F → PiopCoefficients F)
    (observe : Base → Leaves → (Index → Tape) → JointMaskCoins F → JointMaskOutputs F → PMF Result) :
    (baseLaw.bind fun base =>
      (uniformFintypePMF (JointMaskCoins F)).bind fun coins =>
        leafLaw.bind fun leaves => (uniformFintypePMF (Index → Tape)).bind fun tapes =>
          observe base leaves tapes coins
            (jointMaskForward (gammaD leaves) (heads base) (tails base) (piopUnmasked base leaves) coins)) =
    (leafLaw.bind fun leaves =>
      (uniformFintypePMF (JointMaskOutputs F)).bind fun output =>
        baseLaw.bind fun base => (uniformFintypePMF (Index → Tape)).bind fun tapes =>
          observe base leaves tapes
            (jointMaskInverse (gammaD leaves) (heads base) (tails base) (piopUnmasked base leaves) output) output) :=
  chronological_joint_mask_transport baseLaw leafLaw gammaD heads tails piopUnmasked
    (fun base leaves coins output => (uniformFintypePMF (Index → Tape)).bind fun tapes =>
      observe base leaves tapes coins output)

/-- Append fresh tapes to the already-proved source chronological algebraic transport.
The arbitrary public context, abort and reference-state generator are retained.
-/
theorem source_partial_context_fresh_tape_transport
    {F Context Result : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points))
    (publicContext : SourcePartialRemainingView F → Context)
    (observe : Context → (Index → Tape) → PMF Result) :
    ((uniformFintypePMF (SourceRemainingCoins F)).bind fun coins =>
      (uniformFintypePMF (Index → Tape)).bind fun tapes =>
        observe (publicContext
          (sourceRemainingPartialChronologicalView values points pcsBase heads chooseTargets coins)) tapes) =
    ((uniformFintypePMF (SourceRemainingView F)).bind fun view =>
      (uniformFintypePMF (Index → Tape)).bind fun tapes =>
        observe (publicContext (sourceRemainingAbortProjection chooseTargets view)) tapes) := by
  have transported := source_remaining_partial_chronological_joint_law values points
    witnessAdmissible pointsNonzero pcsBase heads fallback chooseTargets
  have observed := congrArg (fun law => law.bind fun output =>
    (uniformFintypePMF (Index → Tape)).bind fun tapes => observe (publicContext output) tapes) transported
  simpa only [pmfMap, PMF.bind_bind, Function.comp_apply, PMF.pure_bind] using observed

/-- The exact source transport followed by conditional opened/unopened tape separation.
The selection is generated from the complete non-tape public view; `none` is retained.
-/
theorem source_partial_context_conditional_tape_law
    {F Context Reference Result : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points))
    (publicContext : SourcePartialRemainingView F → Context)
    (selection : Context → Option (Finset Index))
    (reference : (context : Context) → OpenedTapes (Tape := Tape) (openedOrEmpty (selection context)) → Reference)
    (observe : (context : Context) → OpenedTapes (Tape := Tape) (openedOrEmpty (selection context)) →
      HiddenTapes (Tape := Tape) (openedOrEmpty (selection context)) → Reference → PMF Result) :
    ((uniformFintypePMF (SourceRemainingCoins F)).bind fun coins =>
      (uniformFintypePMF (Index → Tape)).bind fun tapes =>
        let context := publicContext
          (sourceRemainingPartialChronologicalView values points pcsBase heads chooseTargets coins)
        let split := splitTapes (openedOrEmpty (selection context)) tapes
        observe context split.1 split.2 (reference context split.1)) =
    ((uniformFintypePMF (SourceRemainingView F)).bind fun view =>
      let context := publicContext (sourceRemainingAbortProjection chooseTargets view)
      (uniformFintypePMF (OpenedTapes (Tape := Tape) (openedOrEmpty (selection context)))).bind fun visible =>
        (uniformFintypePMF (HiddenTapes (Tape := Tape) (openedOrEmpty (selection context)))).bind fun hidden =>
          observe context visible hidden (reference context visible)) := by
  refine (source_partial_context_fresh_tape_transport values points witnessAdmissible pointsNonzero
    pcsBase heads fallback chooseTargets publicContext
    (fun context (tapes : Index → Tape) =>
      let split := splitTapes (openedOrEmpty (selection context)) tapes
      observe context split.1 split.2 (reference context split.1))).trans ?_
  apply congrArg (PMF.bind (uniformFintypePMF (SourceRemainingView F)))
  funext view
  let context := publicContext (sourceRemainingAbortProjection chooseTargets view)
  exact fresh_tape_disintegration (Tape := Tape) (openedOrEmpty (selection context))
    (fun visible hidden => observe context visible hidden (reference context visible))

end SourceAlgebraicContext

theorem image_eq_of_tapes_agree {Input : Type*} [DecidableEq Input]
    (constructor : Index → Tape → Input) (indices : Finset Index) (left right : Index → Tape)
    (agree : ∀ index ∈ indices, left index = right index) :
    indices.image (fun index => constructor index (left index)) =
      indices.image (fun index => constructor index (right index)) := by
  apply Finset.image_congr
  intro index member
  exact congrArg (constructor index) (agree index member)

theorem source_overlay_eq_of_tapes_agree {Output : Type*}
    (oldLeaf : LeafInput → Output) (targets : LeafIndex → Output)
    (indices : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (left right : LeafIndex → LeafTape)
    (agree : ∀ index ∈ indices, left index = right index) :
    sourceOverlay oldLeaf targets indices header suffix left =
      sourceOverlay oldLeaf targets indices header suffix right := by
  have supports := image_eq_of_tapes_agree
    (fun index tape => sourceLeafInput (header index) (suffix index) index tape) indices left right agree
  change sourcePatchSupport indices header suffix left = sourcePatchSupport indices header suffix right at supports
  funext input
  simp only [sourceOverlay, supports]

theorem source_overlay_hidden_padding {Output : Type*}
    (oldLeaf : LeafInput → Output) (targets : LeafIndex → Output)
    (opened : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (visible : OpenedTapes (Tape := LeafTape) opened) (padded : LeafIndex → LeafTape) :
    sourceOverlay oldLeaf targets (Finset.univ \ opened) header suffix
        (mergeTapes opened visible (splitTapes opened padded).2) =
      sourceOverlay oldLeaf targets (Finset.univ \ opened) header suffix padded := by
  apply source_overlay_eq_of_tapes_agree
  intro index member
  have outside := (Finset.mem_sdiff.mp member).2
  rw [merge_tapes_hidden opened visible _ index outside]
  rfl

theorem source_opened_overlay_independent_of_hidden {Output : Type*}
    (oldLeaf : LeafInput → Output) (targets : LeafIndex → Output)
    (opened : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (left right : HiddenTapes (Tape := LeafTape) opened) :
    sourceOverlay oldLeaf targets opened header suffix (mergeTapes opened visible left) =
      sourceOverlay oldLeaf targets opened header suffix (mergeTapes opened visible right) := by
  apply source_overlay_eq_of_tapes_agree
  intro index member
  rw [merge_tapes_opened opened visible left index member,
    merge_tapes_opened opened visible right index member]

theorem overlay_union {Input Output : Type*} [DecidableEq Input]
    (oldOracle value : Input → Output) (left right : Finset Input) :
    (fun input => if input ∈ left then value input else
      if input ∈ right then value input else oldOracle input) =
    (fun input => if input ∈ left ∪ right then value input else oldOracle input) := by
  funext input
  by_cases inleft : input ∈ left <;> by_cases inright : input ∈ right <;>
    simp [inleft, inright]

/-- Literal table equality: retain opened programs and remove only unopened programs. -/
theorem source_opened_then_unopened_is_full_overlay {Output : Type*}
    (oldLeaf : LeafInput → Output) (targets : LeafIndex → Output)
    (opened : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (tapes : LeafIndex → LeafTape) :
    sourceOverlay (sourceOverlay oldLeaf targets opened header suffix tapes)
        targets (Finset.univ \ opened) header suffix tapes =
      sourceOverlay oldLeaf targets Finset.univ header suffix tapes := by
  have union_support :
      sourcePatchSupport (Finset.univ \ opened) header suffix tapes ∪
        sourcePatchSupport opened header suffix tapes =
      sourcePatchSupport Finset.univ header suffix tapes := by
    unfold sourcePatchSupport
    rw [← Finset.image_union, Finset.sdiff_union_of_subset (Finset.subset_univ opened)]
  unfold sourceOverlay
  rw [overlay_union, union_support]

/-- Actual full overlay versus opened-only reference, using independently padded hidden coins. -/
theorem full_overlay_from_opened_reference {Output : Type*}
    (oldLeaf : LeafInput → Output) (targets : LeafIndex → Output)
    (opened : Finset LeafIndex) (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (visible : OpenedTapes (Tape := LeafTape) opened) (padded : LeafIndex → LeafTape) :
    sourceOverlay
      (sourceOverlay oldLeaf targets opened header suffix
        (mergeTapes opened visible (fun _ => (0 : LeafTape))))
      targets (Finset.univ \ opened) header suffix padded =
    sourceOverlay oldLeaf targets Finset.univ header suffix
      (mergeTapes opened visible (splitTapes opened padded).2) := by
  rw [← source_overlay_hidden_padding _ targets opened header suffix visible padded]
  rw [source_opened_overlay_independent_of_hidden oldLeaf targets opened header suffix visible
    (fun _ => (0 : LeafTape)) (splitTapes opened padded).2]
  exact source_opened_then_unopened_is_full_overlay _ _ _ _ _ _

theorem finite_average_congr {A : Type*} [Fintype A] (left right : A → ℝ)
    (equal : ∀ value, left value = right value) :
    (∑ value, left value) / (Fintype.card A : ℝ) =
      (∑ value, right value) / (Fintype.card A : ℝ) := by
  apply congrArg (fun value : ℝ => value / (Fintype.card A : ℝ))
  exact Finset.sum_congr rfl (fun value _ => equal value)

section PhysicalConditionalExperiment

variable {Other Output Workspace : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Output] [DecidableEq Output] [AddGroup Output]
variable [Fintype Workspace] [DecidableEq Workspace]

abbrev PhysicalState := V8Smz9HiddenPatch.State (Input := LeafInput ⊕ Other)
  (Output := Output) (Workspace := Workspace)
abbrev TapeTable := LeafIndex → LeafTape

/-- The fixed reference on a public-context/opened-tape fiber. All fields are
physical data, not an assumed indistinguishability or game-equivalence statement.
-/
structure AtomicReference where
  oldLeaf : LeafInput → Output
  other : Other → Output
  targets : LeafIndex → Output
  header : LeafIndex → LeafHeader
  suffix : LeafIndex → LeafSuffix
  initial : PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  normalized : ‖initial‖ = 1
  steps : ℕ → PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
    PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  queries : ℕ
  post : TapeTable → PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
    PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  event : TapeTable → Finset (V8Smz9HiddenLeafQrom.QueryBasis (LeafInput ⊕ Other) Output Workspace)

/-- Build the reference oracle by keeping exactly the programs whose tapes were revealed.
The zero hidden half is immaterial by the proved opened-overlay independence.
-/
def keepOpenedPrograms (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) :
    AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace) :=
  { reference with
    oldLeaf := sourceOverlay reference.oldLeaf reference.targets opened
      reference.header reference.suffix (mergeTapes opened visible (fun _ => (0 : LeafTape))) }

/-- The physical oracle really is the original full programmed table, not a renamed game. -/
theorem kept_opened_reference_recovers_full_table (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (padded : TapeTable) :
    fullSourceOverlay (keepOpenedPrograms opened visible reference).oldLeaf reference.other
      reference.targets (Finset.univ \ opened) reference.header reference.suffix padded =
    fullSourceOverlay reference.oldLeaf reference.other reference.targets Finset.univ
      reference.header reference.suffix (mergeTapes opened visible (splitTapes opened padded).2) := by
  unfold fullSourceOverlay keepOpenedPrograms
  rw [full_overlay_from_opened_reference]

def referenceAcceptance (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) : ℝ :=
  (∑ hidden : TapeTable, born (reference.event hidden) (reference.post hidden
    (run (Sum.elim reference.oldLeaf reference.other) reference.steps reference.initial reference.queries))) /
      (Fintype.card TapeTable : ℝ)

def overlayAcceptance (opened : Finset LeafIndex)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) : ℝ :=
  (∑ hidden : TapeTable, born (reference.event hidden) (reference.post hidden
    (run (fullSourceOverlay reference.oldLeaf reference.other reference.targets
      (Finset.univ \ opened) reference.header reference.suffix hidden)
      reference.steps reference.initial reference.queries))) / (Fintype.card TapeTable : ℝ)

/-- All original leaf programs remain, with fixed revealed tapes and a fresh hidden half. -/
def fullProgrammedAcceptance (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) : ℝ :=
  (∑ padded : TapeTable, born (reference.event padded) (reference.post padded
    (run (fullSourceOverlay reference.oldLeaf reference.other reference.targets Finset.univ
      reference.header reference.suffix (mergeTapes opened visible (splitTapes opened padded).2))
      reference.steps reference.initial reference.queries))) / (Fintype.card TapeTable : ℝ)

theorem full_programmed_acceptance_eq_added_hidden_overlay (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) :
    fullProgrammedAcceptance opened visible reference =
      overlayAcceptance opened (keepOpenedPrograms opened visible reference) := by
  unfold fullProgrammedAcceptance overlayAcceptance
  apply finite_average_congr
  intro padded
  simp only [keepOpenedPrograms, fullSourceOverlay, full_overlay_from_opened_reference]

def hiddenPatchLoss (queries : ℕ) : ℝ :=
  2 * Real.sqrt (4 * (queries : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹)

theorem conditional_source_patch_bound (opened : Finset LeafIndex)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) :
    |overlayAcceptance opened reference - referenceAcceptance reference| ≤ hiddenPatchLoss reference.queries :=
  full_source_overlay_cq_born_distance_le reference.oldLeaf reference.other reference.targets
    (Finset.univ \ opened) reference.header reference.suffix reference.steps reference.initial
    reference.normalized reference.queries reference.post reference.event

theorem hidden_patch_loss_mono {left right : ℕ} (bound : left ≤ right) :
    hiddenPatchLoss left ≤ hiddenPatchLoss right := by
  unfold hiddenPatchLoss
  apply mul_le_mul_of_nonneg_left _ (by norm_num)
  apply Real.sqrt_le_sqrt
  gcongr

theorem pmf_real_weights_sum {A : Type*} [Fintype A] (law : PMF A) :
    (∑ value, (law value).toReal) = 1 := by
  have total := congrArg ENNReal.toReal law.tsum_coe
  rw [tsum_fintype, ENNReal.toReal_sum (fun value _ => law.apply_ne_top value)] at total
  simpa only [ENNReal.toReal_one] using total

/-- Finite classical mixing pays no multiplicative number of contexts. -/
theorem pmf_mixture_difference_le {A : Type*} [Fintype A]
    (law : PMF A) (left right : A → ℝ) (loss : ℝ)
    (bound : ∀ value, |left value - right value| ≤ loss) :
    |(∑ value, (law value).toReal * left value) -
      (∑ value, (law value).toReal * right value)| ≤ loss := by
  rw [← Finset.sum_sub_distrib]
  simp_rw [← mul_sub]
  calc
    _ ≤ ∑ value, |(law value).toReal * (left value - right value)| :=
      Finset.abs_sum_le_sum_abs _ _
    _ = ∑ value, (law value).toReal * |left value - right value| := by
      apply Finset.sum_congr rfl
      intro value _
      rw [abs_mul, abs_of_nonneg ENNReal.toReal_nonneg]
    _ ≤ ∑ value, (law value).toReal * loss := by
      apply Finset.sum_le_sum
      intro value _
      exact mul_le_mul_of_nonneg_left (bound value) ENNReal.toReal_nonneg
    _ = loss := by rw [← Finset.sum_mul, pmf_real_weights_sum, one_mul]

def atomicPublicLaw {Context : Type*} (contextLaw : PMF Context)
    (selection : Context → Option (Finset LeafIndex)) :
    PMF (Σ context, OpenedTapes (Tape := LeafTape) (openedOrEmpty (selection context))) :=
  contextLaw.bind fun context =>
    pmfMap (uniformFintypePMF (OpenedTapes (Tape := LeafTape) (openedOrEmpty (selection context))))
      (fun visible => ⟨context, visible⟩)

/-- The generated public context and revealed tapes are mixed explicitly. Every
fiber uses the proved physical source bound; query budgets include all future
honest/adversarial raw calls. Aborted invocations use `openedOrEmpty none = ∅`.
-/
theorem atomic_context_mixture_patch_bound {Context : Type*} [Fintype Context]
    (contextLaw : PMF Context) (selection : Context → Option (Finset LeafIndex))
    (reference : (context : Context) →
      OpenedTapes (Tape := LeafTape) (openedOrEmpty (selection context)) →
        AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (queryBound : ℕ) (queries_bounded : ∀ context visible, (reference context visible).queries ≤ queryBound) :
    |(∑ contextValue, ((atomicPublicLaw contextLaw selection) contextValue).toReal *
        overlayAcceptance (openedOrEmpty (selection contextValue.1)) (reference contextValue.1 contextValue.2)) -
      (∑ contextValue, ((atomicPublicLaw contextLaw selection) contextValue).toReal *
        referenceAcceptance (reference contextValue.1 contextValue.2))| ≤ hiddenPatchLoss queryBound := by
  apply pmf_mixture_difference_le
  intro contextValue
  exact (conditional_source_patch_bound (openedOrEmpty (selection contextValue.1))
    (reference contextValue.1 contextValue.2)).trans
      (hidden_patch_loss_mono (queries_bounded contextValue.1 contextValue.2))

/-- Atomic full-programmed game to its opened-program-only reference, with the
actual raw table identity and classical-context mixture discharged locally.
-/
theorem atomic_full_vs_opened_reference_bound {Context : Type*} [Fintype Context]
    (contextLaw : PMF Context) (selection : Context → Option (Finset LeafIndex))
    (reference : (context : Context) →
      OpenedTapes (Tape := LeafTape) (openedOrEmpty (selection context)) →
        AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (queryBound : ℕ) (queries_bounded : ∀ context visible, (reference context visible).queries ≤ queryBound) :
    |(∑ contextValue, ((atomicPublicLaw contextLaw selection) contextValue).toReal *
        fullProgrammedAcceptance (openedOrEmpty (selection contextValue.1)) contextValue.2
          (reference contextValue.1 contextValue.2)) -
      (∑ contextValue, ((atomicPublicLaw contextLaw selection) contextValue).toReal *
        referenceAcceptance (keepOpenedPrograms (openedOrEmpty (selection contextValue.1)) contextValue.2
          (reference contextValue.1 contextValue.2)))| ≤ hiddenPatchLoss queryBound := by
  simp_rw [full_programmed_acceptance_eq_added_hidden_overlay]
  exact atomic_context_mixture_patch_bound contextLaw selection
    (fun context visible => keepOpenedPrograms (openedOrEmpty (selection context)) visible
      (reference context visible)) queryBound queries_bounded

end PhysicalConditionalExperiment

end

end HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
