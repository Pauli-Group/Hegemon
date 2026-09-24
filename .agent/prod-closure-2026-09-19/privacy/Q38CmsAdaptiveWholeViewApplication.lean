import Q38CmsAdaptiveWholeViewBound
import Q38CmsPhaseDecodeIsometry

/-!
Canonical total-family reconstruction and the exact phase-game application
of the CMS continuation bound.

Unlike an existential family premise, `TotalDatabaseSupport` is a directly
checkable invariant of the same persistent database state.  The canonical
family below is an explicit inverse to `totalOracleFamilyState` on that
invariant.
-/
namespace HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open scoped BigOperators Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

/-- The standard-database state has amplitude only on complete database
functions.  This is the exact support invariant produced by whole-domain CMS
decompression; it says nothing about the amplitudes or the desired security
conclusion. -/
def TotalDatabaseSupport (state : ResponseCmsState Input Work) : Prop :=
  ∀ basis, (¬ ∃ oracle : Input → DigestRegister,
    basis.database = totalDatabase oracle) → state basis = 0

theorem total_database_support_response_fourier_inverse
    (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (responseFourierInverseState state) := by
  intro basis noMatch
  have allZero (phase : DigestRegister) :
      state { basis with phase := phase } = 0 := by
    apply supported
    simpa using noMatch
  simp [responseFourierInverseState, digestResponseFourierInverse, allZero]

section SupportTransport

variable {OtherWork Index Branch : Type}
variable [Fintype OtherWork] [DecidableEq OtherWork]
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]

theorem total_database_support_transport_workspace
    (equivalence : Work ≃ OtherWork)
    (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (transportWorkspace equivalence state) := by
  intro basis noMatch
  unfold transportWorkspace
  apply supported
  exact noMatch

theorem total_database_support_raw_swap
    (selected : Input)
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input DigestRegister DigestRegister (DigestRegister × Work))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (rawSwap selected state) := by
  intro basis noMatch
  unfold rawSwap
  apply supported
  rintro ⟨oracle, sourceDatabase⟩
  apply noMatch
  cases answer : basis.database selected with
  | none =>
      refine ⟨oracle, ?_⟩
      simpa [swapBasis, answer] using sourceDatabase
  | some old =>
      refine ⟨Function.update oracle selected old, ?_⟩
      funext input
      by_cases same : input = selected
      · subst input
        simp [totalDatabase, answer]
      · calc
          basis.database input =
              (swapBasis selected basis).database input :=
            (swap_preserves_other selected input same basis).symm
          _ = totalDatabase oracle input := congrFun sourceDatabase input
          _ = totalDatabase (Function.update oracle selected old) input := by
            simp [totalDatabase, Function.update_of_ne same]

theorem total_database_support_indexed_raw_swap
    (key : Input) (index : Index)
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input DigestRegister DigestRegister ((Index → DigestRegister) × Work))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (indexedRawSwap key index state) := by
  unfold indexedRawSwap
  apply total_database_support_transport_workspace
  apply total_database_support_raw_swap
  apply total_database_support_transport_workspace
  exact supported

theorem total_database_support_raw_swap_list
    (keys : Index → Input) (indices : List Index)
    (state : HegemonCrypto.CmsCompressedOracle.State
      Input DigestRegister DigestRegister ((Index → DigestRegister) × Work))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (rawSwapList keys indices state) := by
  induction indices generalizing state with
  | nil => exact supported
  | cons index tail inductionHypothesis =>
      exact inductionHypothesis _
        (total_database_support_indexed_raw_swap
          (keys index) index state supported)

theorem total_database_support_slice
    (branch : Branch)
    (state : ResponseCmsState Input
      ((Index → DigestRegister) × (Branch × Work)))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (slice branch state) := by
  intro basis noMatch
  unfold slice
  apply supported
  exact noMatch

theorem total_database_support_controlled_raw
    (keys : Branch → Index → Input) (indices : List Index)
    (state : ResponseCmsState Input
      ((Index → DigestRegister) × (Branch × Work)))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (controlledRaw keys indices state) := by
  intro basis noMatch
  unfold controlledRaw
  apply total_database_support_raw_swap_list
    (keys basis.workspace.2.1) indices (slice basis.workspace.2.1 state)
    (total_database_support_slice basis.workspace.2.1 state supported)
  exact noMatch

end SupportTransport

section InitializedSupport

variable {Index Branch BaseWork : Type}
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- Add the retained uniform fresh-label table without changing the CMS
database or the pre-existing branch/work registers. -/
def appendUniformLabelState
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    ResponseCmsState Input
      ((Index → DigestRegister) × (Branch × BaseWork)) :=
  fun basis =>
    state
      { input := basis.input
        phase := basis.phase
        workspace := (basis.workspace.2.1, basis.workspace.2.2)
        database := basis.database } *
      ((Real.sqrt (Fintype.card (Index → DigestRegister) : ℝ) : ℂ)⁻¹)

theorem initializedFreshState_coreOf_eq_append
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    initializedFreshState (Index := Index) (coreOfCmsState state) =
      appendUniformLabelState (Index := Index) state := by
  funext basis
  rfl

def coreStateEquiv :
    Core Input Branch (Input × DigestRegister × BaseWork) DigestRegister ≃
      HegemonCrypto.CmsCompressedOracle.Basis
        Input DigestRegister DigestRegister (Branch × BaseWork) where
  toFun basis :=
    { input := basis.2.2.1
      phase := basis.2.2.2.1
      workspace := (basis.1, basis.2.2.2.2)
      database := basis.2.1 }
  invFun basis :=
    (basis.workspace.1, basis.database,
      (basis.input, basis.phase, basis.workspace.2))
  left_inv basis := by cases basis; rfl
  right_inv basis := by cases basis; rfl

theorem coreOfCmsState_mass
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    (∑ basis :
        Core Input Branch (Input × DigestRegister × BaseWork)
          DigestRegister,
      ‖coreOfCmsState state basis‖ ^ 2) = normSquared state := by
  unfold normSquared
  calc
    (∑ basis :
        Core Input Branch (Input × DigestRegister × BaseWork)
          DigestRegister,
      ‖coreOfCmsState state basis‖ ^ 2) =
        ∑ basis :
          Core Input Branch (Input × DigestRegister × BaseWork)
            DigestRegister,
          Complex.normSq (state (coreStateEquiv basis)) := by
      apply Finset.sum_congr rfl
      intro basis _
      exact Complex.sq_norm _
    _ = ∑ basis :
        HegemonCrypto.CmsCompressedOracle.Basis
          Input DigestRegister DigestRegister (Branch × BaseWork),
        Complex.normSq (state basis) :=
      coreStateEquiv.sum_comp
        (fun basis :
          HegemonCrypto.CmsCompressedOracle.Basis
            Input DigestRegister DigestRegister (Branch × BaseWork) =>
          Complex.normSq (state basis))

theorem decompress_at_append_uniform_labels
    (selected : Input)
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    decompressAt selected (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index) (decompressAt selected state) := by
  funext target
  unfold appendUniformLabelState
  rw [decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
  rw [Finset.sum_mul]
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem decompress_list_append_uniform_labels
    (inputs : List Input)
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    decompressList inputs (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index) (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons selected remaining inductionHypothesis =>
      rw [decompress_list_cons, decompress_list_cons,
        inductionHypothesis, decompress_at_append_uniform_labels]

theorem global_decompress_append_uniform_labels
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    globalDecompress (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index) (globalDecompress state) := by
  unfold globalDecompress
  exact decompress_list_append_uniform_labels _ state

theorem total_database_support_append_uniform_labels
    (state : ResponseCmsState Input (Branch × BaseWork))
    (supported : TotalDatabaseSupport state) :
    TotalDatabaseSupport (appendUniformLabelState (Index := Index) state) := by
  intro basis noMatch
  unfold appendUniformLabelState
  rw [supported
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.2.1, basis.workspace.2.2)
      database := basis.database }
    (by simpa using noMatch), zero_mul]

theorem initializedFreshState_total_support_of_core_state
    (state : ResponseCmsState Input (Branch × BaseWork))
    (supported : TotalDatabaseSupport (globalDecompress state)) :
    TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := Index) (coreOfCmsState state))) := by
  rw [initializedFreshState_coreOf_eq_append,
    global_decompress_append_uniform_labels]
  exact total_database_support_append_uniform_labels _ supported

/-- An actual initialized raw CMS execution supplies the sole total-database
support premise of the phase-game hybrid.  This consumes the checked exact CMS
simulation theorem, not an adaptive-reprogramming or semantic-distance
assumption. -/
theorem raw_run_initializedFreshState_total_support
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Branch × BaseWork)))
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := DigestRegister)
        (Workspace := Branch × BaseWork) → ℂ)
    (capacity : steps.length ≤ queryBound) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := Index) (coreOfCmsState reached))) := by
  dsimp only
  apply initializedFreshState_total_support_of_core_state
  rw [compressed_run_is_uniform_random_oracle_purification
    system queryBound steps initialRegisters capacity]
  intro basis noMatch
  exact total_oracle_family_state_eq_zero_of_no_match _ basis noMatch

end InitializedSupport

theorem total_oracle_family_has_total_database_support
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    TotalDatabaseSupport (totalOracleFamilyState family) := by
  intro basis noMatch
  exact total_oracle_family_state_eq_zero_of_no_match family basis noMatch

private theorem purificationScale_ne_zero :
    inverseSqrtOutputCard (Output := DigestRegister) ^ Fintype.card Input ≠ 0 := by
  apply pow_ne_zero
  unfold inverseSqrtOutputCard
  apply inv_ne_zero
  exact_mod_cast
    (ne_of_gt (Real.sqrt_pos.2
      (show (0 : ℝ) < Fintype.card DigestRegister by positivity)))

/-- Explicit inverse family on total database branches. -/
def canonicalTotalFamily (state : ResponseCmsState Input Work) :
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work) :=
  fun oracle register =>
    (inverseSqrtOutputCard (Output := DigestRegister) ^
      Fintype.card Input)⁻¹ *
      state
        { input := register.1
          phase := register.2.1
          workspace := register.2.2
          database := totalDatabase oracle }

/-- On exact total-database support, the canonical family reconstructs the
complete state, including every register and database amplitude. -/
theorem total_oracle_family_canonical_eq
    (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport state) :
    totalOracleFamilyState (canonicalTotalFamily state) = state := by
  funext basis
  by_cases matched : ∃ oracle : Input → DigestRegister,
      basis.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEq⟩ := matched
    rcases basis with ⟨input, phase, workspace, database⟩
    dsimp at databaseEq ⊢
    subst database
    rw [total_oracle_family_state_apply]
    unfold canonicalTotalFamily
    rw [← mul_assoc, mul_inv_cancel₀ purificationScale_ne_zero, one_mul]
  · rw [total_oracle_family_state_eq_zero_of_no_match _ basis matched]
    exact (supported basis matched).symm

/-- The checked seven-constructor continuation is 2-Lipschitz for
subnormalized total-oracle purifications.  This is the form needed after an
actual sequence of database-blind contractions. -/
theorem database_run_total_family_difference_subnormalized
    (randomized : Bool) (program : Program Input Work)
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (leftSubnormalized :
      normSquared (totalOracleFamilyState left) ≤ 1)
    (rightSubnormalized :
      normSquared (totalOracleFamilyState right) ≤ 1) :
    |databaseRun randomized program (totalOracleFamilyState left) -
        databaseRun randomized program (totalOracleFamilyState right)| ≤
      2 * Real.sqrt
        (normSquared
          (totalOracleFamilyState left - totalOracleFamilyState right)) := by
  rw [databaseRun_totalOracleFamilyState,
    databaseRun_totalOracleFamilyState]
  apply (average_difference_abs_le _ _).trans
  have pointwise (oracle : Input → DigestRegister) :
      |databaseRun randomized program
            (oracleState oracle (familyGameState left oracle)) -
          databaseRun randomized program
            (oracleState oracle (familyGameState right oracle))| ≤
        (‖familyGameState left oracle‖ +
            ‖familyGameState right oracle‖) *
          ‖familyGameState left oracle -
            familyGameState right oracle‖ := by
    rw [databaseRun_oracleState, databaseRun_oracleState]
    exact run_difference_subnormalized randomized program oracle
      (familyGameState left oracle) (familyGameState right oracle)
  apply (average_mono _ _ pointwise).trans
  apply (uniform_average_mul_le_sqrt_mul_sqrt
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle‖ + ‖familyGameState right oracle‖)
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle - familyGameState right oracle‖)).trans
  have firstMoment :
      uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2) ≤ 4 := by
    calc
      _ ≤ uniformAverage (fun oracle : Input → DigestRegister =>
          2 * ‖familyGameState left oracle‖ ^ 2 +
            2 * ‖familyGameState right oracle‖ ^ 2) := by
        apply average_mono
        intro oracle
        nlinarith [sq_nonneg
          (‖familyGameState left oracle‖ -
            ‖familyGameState right oracle‖)]
      _ = 2 * normSquared (totalOracleFamilyState left) +
          2 * normSquared (totalOracleFamilyState right) := by
        rw [average_add, average_mul_left, average_mul_left,
          ← total_oracle_family_norm_squared,
          ← total_oracle_family_norm_squared]
      _ ≤ 4 := by nlinarith
  have firstSqrt :
      Real.sqrt (uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2)) ≤ 2 := by
    have nonnegative : 0 ≤
        uniformAverage (fun oracle : Input → DigestRegister =>
          (‖familyGameState left oracle‖ +
            ‖familyGameState right oracle‖) ^ 2) := by
      exact Finset.sum_nonneg fun oracle _ =>
        mul_nonneg ENNReal.toReal_nonneg (sq_nonneg _)
    nlinarith [Real.sq_sqrt nonnegative, Real.sqrt_nonneg
      (uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2))]
  rw [← total_oracle_family_difference_norm_squared]
  exact mul_le_mul_of_nonneg_right firstSqrt (Real.sqrt_nonneg _)

theorem total_family_whole_view_hybrid_subnormalized
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftFamily : Secret → OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (rightFamily : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (leftRepresentation : ∀ secret,
      left secret = totalOracleFamilyState (leftFamily secret))
    (rightRepresentation : right = totalOracleFamilyState rightFamily)
    (leftSubnormalized : ∀ secret, normSquared (left secret) ≤ 1)
    (rightSubnormalized : normSquared right ≤ 1)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (meanSquare : uniformAverage (fun secret =>
      normSquared (left secret - right)) ≤ loss) :
    |uniformAverage (fun secret =>
        databaseRun randomized program (left secret)) -
      databaseRun randomized program right| ≤
      2 * Real.sqrt loss := by
  have constantAverage :
      uniformAverage (fun _ : Secret =>
        databaseRun randomized program right) =
          databaseRun randomized program right := by
    unfold uniformAverage
    rw [← Finset.sum_mul,
      HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition.pmf_real_weights_sum,
      one_mul]
  rw [← constantAverage]
  apply (average_difference_abs_le _ _).trans
  have pointwise (secret : Secret) :
      |databaseRun randomized program (left secret) -
          databaseRun randomized program right| ≤
        2 * Real.sqrt (normSquared (left secret - right)) := by
    rw [leftRepresentation secret, rightRepresentation]
    exact database_run_total_family_difference_subnormalized
      randomized program (leftFamily secret) rightFamily
      (by simpa [leftRepresentation secret] using leftSubnormalized secret)
      (by simpa [rightRepresentation] using rightSubnormalized)
  apply (average_mono _ _ pointwise).trans
  rw [average_mul_left]
  apply mul_le_mul_of_nonneg_left _ (by norm_num)
  apply uniform_average_le_sqrt_mean_square
    (fun secret => Real.sqrt (normSquared (left secret - right)))
    (fun _ => Real.sqrt_nonneg _) loss lossNonnegative
  have distanceNonnegative (secret : Secret) :
      0 ≤ normSquared (left secret - right) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ =>
      Complex.normSq_nonneg ((left secret - right) basis)
  simpa only [Real.sq_sqrt (distanceNonnegative _)] using meanSquare

/-- The family representation obligations in the generic hybrid are
discharged canonically from total-database support. -/
theorem total_support_whole_view_hybrid
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftSupport : ∀ secret, TotalDatabaseSupport (left secret))
    (rightSupport : TotalDatabaseSupport right)
    (leftSubnormalized : ∀ secret, normSquared (left secret) ≤ 1)
    (rightSubnormalized : normSquared right ≤ 1)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (meanSquare : uniformAverage (fun secret =>
      normSquared (left secret - right)) ≤ loss) :
    |uniformAverage (fun secret =>
        databaseRun randomized program (left secret)) -
      databaseRun randomized program right| ≤
      2 * Real.sqrt loss := by
  apply total_family_whole_view_hybrid_subnormalized (loss := loss)
    randomized program left right
    (fun secret => canonicalTotalFamily (left secret))
    (canonicalTotalFamily right)
  · intro secret
    exact (total_oracle_family_canonical_eq
      (left secret) (leftSupport secret)).symm
  · exact (total_oracle_family_canonical_eq right rightSupport).symm
  · exact leftSubnormalized
  · exact rightSubnormalized
  · exact lossNonnegative
  · exact meanSquare

/-- Exact phase-game form.  All seven program constructors are already
inside `phaseRun`; the hypotheses are only the standard-basis support,
normalization and mean-square facts about `phaseDecode`. -/
theorem phase_run_total_support_hybrid
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftSupport : ∀ secret,
      TotalDatabaseSupport (phaseDecode (left secret)))
    (rightSupport : TotalDatabaseSupport (phaseDecode right))
    (leftSubnormalized : ∀ secret,
      normSquared (phaseDecode (left secret)) ≤ 1)
    (rightSubnormalized : normSquared (phaseDecode right) ≤ 1)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (meanSquare : uniformAverage (fun secret =>
      normSquared
        (phaseDecode (left secret) - phaseDecode right)) ≤ loss) :
    |uniformAverage (fun secret => phaseRun randomized program (left secret)) -
      phaseRun randomized program right| ≤
      2 * Real.sqrt loss := by
  simp_rw [phase_run_eq_database_run]
  exact total_support_whole_view_hybrid randomized program
    (fun secret => phaseDecode (left secret)) (phaseDecode right)
    leftSupport rightSupport leftSubnormalized rightSubnormalized
    loss lossNonnegative meanSquare

/-! ## Concrete full-domain q38 application -/

section FullDomain

variable {Branch Other BaseWork : Type}
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Other] [DecidableEq Other]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => LeafInput ⊕ Other
local notation "FullWork" =>
  (LeafIndex → DigestRegister) × (Branch × BaseWork)
local notation "FullCore" =>
  Core FullInput Branch
    (FullInput × DigestRegister × BaseWork) DigestRegister

/-- Full q38 application of the checked CMS disturbance to an arbitrary
subsequent seven-constructor whole-view program.  Normalization and the
mean-square premise are discharged here from the actual initialized state,
the controlled-swap isometry, and the full-domain assembly theorem.

The sole support premise is on the undecorated decompressed base state.  The
response Fourier transform is database-blind, and the preceding raw-swap
lemmas derive support of every branch-controlled changed state from it.  Thus
neither a family witness nor a changed-state support premise remains. -/
theorem initialized_cms_full_domain_phase_run_bound
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (coreSubnormalized : ∑ basis : FullCore, ‖core basis‖ ^ 2 ≤ 1)
    (randomized : Bool) (program : Program FullInput FullWork)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core))) :
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized program
          (controlledCompressed (fullPhysicalSelected salt data tapes)
            indices (initializedFreshState core))) -
      phaseRun randomized program
        (initializedFreshState (Index := LeafIndex) core)| ≤
      2 * Real.sqrt
        (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  let base : ResponseCmsState FullInput FullWork :=
    initializedFreshState (Index := LeafIndex) core
  let changed : (LeafIndex → LeafTape) →
      ResponseCmsState FullInput FullWork :=
    fun tapes => controlledCompressed
      (fullPhysicalSelected salt data tapes) indices base
  have jZero :
      J (Input := FullInput) (Output := DigestRegister)
          (Phase := DigestRegister) (Work := BaseWork)
          (Index := LeafIndex) (Branch := Branch)
          (0 : ResponseCmsState FullInput FullWork) = 0 := by
    ext basis
    rfl
  have baseSubnormalized : normSquared base ≤ 1 := by
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      base (0 : ResponseCmsState FullInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J base = freshLabels (Index := LeafIndex) core by
      exact J_initializedFreshState core] at native
    rw [fresh_labels_norm_sq] at native
    rw [← native]
    exact coreSubnormalized
  have changedSubnormalized (tapes : LeafIndex → LeafTape) :
      normSquared (changed tapes) ≤ 1 := by
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      (changed tapes) (0 : ResponseCmsState FullInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J (changed tapes) =
        exchangeMany (fullPhysicalSelected salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) by
      unfold changed base
      rw [J_controlled_many, J_initializedFreshState]] at native
    rw [(exchangeMany (fullPhysicalSelected salt data tapes)
      indices).norm_map, fresh_labels_norm_sq] at native
    rw [← native]
    exact coreSubnormalized
  have decodedBaseSubnormalized : normSquared (phaseDecode base) ≤ 1 := by
    rw [phase_decode_norm_squared]
    exact baseSubnormalized
  have decodedChangedSubnormalized (tapes : LeafIndex → LeafTape) :
      normSquared (phaseDecode (changed tapes)) ≤ 1 := by
    rw [phase_decode_norm_squared]
    exact changedSubnormalized tapes
  have decodedBaseSupport : TotalDatabaseSupport (phaseDecode base) := by
    unfold phaseDecode
    exact total_database_support_response_fourier_inverse
      (globalDecompress base) baseSupport
  have decodedChangedSupport (tapes : LeafIndex → LeafTape) :
      TotalDatabaseSupport (phaseDecode (changed tapes)) := by
    unfold phaseDecode
    apply total_database_support_response_fourier_inverse
    rw [show globalDecompress (changed tapes) =
        controlledRaw (fullPhysicalSelected salt data tapes) indices
          (globalDecompress base) by
      unfold changed
      exact global_controlled_swap_intertwining _ _ _]
    exact total_database_support_controlled_raw
      (fullPhysicalSelected salt data tapes) indices
      (globalDecompress base) baseSupport
  have meanSquare :
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        normSquared
          (phaseDecode (changed tapes) - phaseDecode base)) ≤
        4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
    have native := initialized_cms_full_domain_resampling_disturbance
      (Phase := DigestRegister) (Work := BaseWork)
      (Branch := Branch) (Other := Other)
      salt data indices core queries bounded
    calc
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
          ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
        simpa only [changed, base, phase_decode_difference_norm_squared]
          using native
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
        simpa only [mul_one] using
          (mul_le_mul_of_nonneg_left coreSubnormalized
            (show 0 ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ by
              positivity))
  apply phase_run_total_support_hybrid randomized program changed base
    decodedChangedSupport decodedBaseSupport
    decodedChangedSubnormalized decodedBaseSubnormalized
    (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)
    (by positivity) meanSquare

/-- Fully initialized form for an actual raw CMS execution from the empty
compressed database.  Query support, total-oracle support, and the core mass
bound are all discharged by existing checked execution theorems. -/
theorem raw_run_full_domain_phase_run_bound
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex)
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × BaseWork)))
    (initialRegisters :
      RegisterBasis (Input := FullInput) (Phase := DigestRegister)
        (Workspace := Branch × BaseWork) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (initialSubnormalized : Subnormalized
      (partialRandomOracleState (Output := DigestRegister) ∅
        initialRegisters))
    (randomized : Bool) (program : Program FullInput FullWork) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let core := coreOfCmsState reached
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized program
          (controlledCompressed (fullPhysicalSelected salt data tapes)
            indices (initializedFreshState (Index := LeafIndex) core))) -
      phaseRun randomized program
        (initializedFreshState (Index := LeafIndex) core)| ≤
      2 * Real.sqrt
        (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  dsimp only
  let initial : ResponseCmsState FullInput (Branch × BaseWork) :=
    partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let reached : ResponseCmsState FullInput (Branch × BaseWork) :=
    rawRun system queryBound blindSteps initial
  let core : FullCore → ℂ := coreOfCmsState reached
  have boundedInitial : BoundedState 0 initial := by
    unfold initial
    exact partial_random_oracle_empty_bounded initialRegisters
  have capacityBlind : 0 + blindSteps.length ≤ queryBound := by
    simpa only [blindSteps, List.length_map, zero_add] using capacity
  have bounded : BoundedState queryBound
      (initializedFreshState (Index := LeafIndex) core) := by
    unfold core reached
    exact raw_run_initializedFreshState_bounded
      system queryBound blindSteps initial 0 capacityBlind boundedInitial
  have reachedSubnormalized : Subnormalized reached := by
    unfold reached
    exact raw_run_subnormalized_of_bounded
      system queryBound blindSteps initial 0 capacityBlind boundedInitial
      (by simpa only [initial] using initialSubnormalized)
  have coreSubnormalized :
      (∑ basis : FullCore, ‖core basis‖ ^ 2) ≤ 1 := by
    rw [show (∑ basis : FullCore, ‖core basis‖ ^ 2) =
        normSquared reached by
      unfold core
      exact coreOfCmsState_mass reached]
    exact reachedSubnormalized
  have baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core)) := by
    unfold core reached blindSteps initial
    exact raw_run_initializedFreshState_total_support
      (Index := LeafIndex) system queryBound steps initialRegisters capacity
  exact initialized_cms_full_domain_phase_run_bound
    salt data indices core queryBound bounded coreSubnormalized
    randomized program baseSupport

end FullDomain

end
end HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
