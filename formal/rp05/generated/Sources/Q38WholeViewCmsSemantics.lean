import Q38CmsInitializedResampling
import Q38MeasuredCmsNonleafCore
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument
import HegemonCrypto.SmallWoodV8Smz9SourceLifetime

/-!
An exact database semantics for every constructor of the existing
`HonestWholeViewGames.Program`.

The standard form below keeps one persistent finite oracle database.  Honest
reads are complete coordinate projections.  A randomized `freshInput` first
projects the old value, replaces that coordinate, and retains the old value as
an unobserved finite branch; hence no irreversible overwrite is represented as
a pure-state map.  The compressed form is its exact conjugate by the existing
whole-table CMS decompression involution.

The concrete digest DFT below identifies the response-register query with the
CMS phase query.  On strict reachable support, its response-basis compressed
presentation is proved equal to the implemented `CmsCompressedOracle.queryState`
with exactly the same query cap.
-/
namespace HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open scoped BigOperators Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unusedVariables false

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

abbrev ResponseCmsState (Input Work : Type) :=
  HegemonCrypto.CmsCompressedOracle.State
    Input DigestRegister DigestRegister Work

/-! ## Exact response/phase Fourier bridge

The existing whole-view game writes the digest answer by translation in its
second register.  CMS uses that same finite register in the character basis.
The following normalized finite Fourier transform is independent of the
oracle database.  Its displayed inverse is its conjugate transpose; the two
inverse laws are proved from the concrete 512-bit character orthogonality.
-/

theorem digest_character_symmetric
    (left right : DigestRegister) :
    digestCharacter left right = digestCharacter right left := by
  simp only [digestCharacter, AddChar.coe_mk]
  apply Finset.prod_congr rfl
  intro bit _
  rw [mul_comm]

/-- Column orthogonality of the concrete Walsh character table. -/
theorem digest_phase_character_sum (value : DigestRegister) :
    (∑ phase : DigestRegister, digestCharacter phase value) =
      if value = 0 then (Fintype.card DigestRegister : ℂ) else 0 := by
  calc
    (∑ phase : DigestRegister, digestCharacter phase value) =
        ∑ phase : DigestRegister, digestCharacter value phase := by
      apply Finset.sum_congr rfl
      intro phase _
      exact digest_character_symmetric phase value
    _ = if digestCharacter value = 0 then
          (Fintype.card DigestRegister : ℂ) else 0 :=
      AddChar.sum_eq_ite (digestCharacter value)
    _ = if value = 0 then
          (Fintype.card DigestRegister : ℂ) else 0 := by
      apply if_congr
      · constructor
        · intro trivial
          exact digest_character_injective
            (trivial.trans digest_character_zero.symm)
        · rintro rfl
          exact digest_character_zero
      · rfl
      · rfl

theorem digest_phase_character_orthogonality
    (left right : DigestRegister) :
    (∑ phase : DigestRegister,
        digestCharacter phase (right - left)) =
      if right = left then (Fintype.card DigestRegister : ℂ) else 0 := by
  simpa only [sub_eq_zero] using digest_phase_character_sum (right - left)

/-- Row orthogonality of the same square character table. -/
theorem digest_output_character_orthogonality
    (left right : DigestRegister) :
    (∑ output : DigestRegister,
        digestCharacter left output * digestCharacter right (-output)) =
      if left = right then (Fintype.card DigestRegister : ℂ) else 0 := by
  calc
    (∑ output : DigestRegister,
        digestCharacter left output * digestCharacter right (-output)) =
        ∑ output : DigestRegister,
          (digestCharacter left - digestCharacter right) output := by
      apply Finset.sum_congr rfl
      intro output _
      exact (AddChar.sub_apply _ _ output).symm
    _ = if digestCharacter left - digestCharacter right = 0 then
          (Fintype.card DigestRegister : ℂ) else 0 :=
      AddChar.sum_eq_ite (digestCharacter left - digestCharacter right)
    _ = if left = right then
          (Fintype.card DigestRegister : ℂ) else 0 := by
      apply if_congr
      · rw [sub_eq_zero]
        exact digest_character_injective.eq_iff
      · rfl
      · rfl

theorem digest_fourier_normalization :
    inverseSqrtOutputCard (Output := DigestRegister) *
        inverseSqrtOutputCard (Output := DigestRegister) *
        (Fintype.card DigestRegister : ℂ) = 1 := by
  rw [inverse_sqrt_output_card_mul_self]
  unfold inverseOutputCard
  change (((Fintype.card DigestRegister : ℝ) : ℂ))⁻¹ *
      ((Fintype.card DigestRegister : ℝ) : ℂ) = 1
  have cardNonzero :
      (((Fintype.card DigestRegister : ℝ) : ℂ)) ≠ 0 := by
    exact_mod_cast (show (Fintype.card DigestRegister : ℝ) ≠ 0 by positivity)
  exact inv_mul_cancel₀ cardNonzero

/-- Normalized DFT from the answer/translation basis to the CMS phase basis. -/
def digestResponseFourier
    (state : DigestRegister → ℂ) : DigestRegister → ℂ :=
  fun phase =>
    inverseSqrtOutputCard (Output := DigestRegister) *
      ∑ response : DigestRegister,
        digestCharacter phase response * state response

/-- The conjugate-transpose normalized DFT. -/
def digestResponseFourierInverse
    (state : DigestRegister → ℂ) : DigestRegister → ℂ :=
  fun response =>
    inverseSqrtOutputCard (Output := DigestRegister) *
      ∑ phase : DigestRegister,
        digestCharacter phase (-response) * state phase

theorem digest_fourier_inverse_kernel_is_conjugate
    (phase response : DigestRegister) :
    inverseSqrtOutputCard (Output := DigestRegister) *
        digestCharacter phase (-response) =
      star
        (inverseSqrtOutputCard (Output := DigestRegister) *
          digestCharacter phase response) := by
  have characterConjugate :
      digestCharacter phase (-response) =
        star (digestCharacter phase response) :=
    AddChar.map_neg_eq_conj (digestCharacter phase) response
  have scaleConjugate :
      inverseSqrtOutputCard (Output := DigestRegister) =
        star (inverseSqrtOutputCard (Output := DigestRegister)) := by
    unfold inverseSqrtOutputCard
    rw [star_inv₀]
    congr 1
    rw [RCLike.star_def, Complex.conj_ofReal]
  rw [star_mul, ← scaleConjugate, ← characterConjugate]
  exact mul_comm _ _

theorem digest_response_fourier_inverse_left
    (state : DigestRegister → ℂ) :
    digestResponseFourierInverse (digestResponseFourier state) = state := by
  funext response
  unfold digestResponseFourierInverse digestResponseFourier
  calc
    inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ phase : DigestRegister,
            digestCharacter phase (-response) *
              (inverseSqrtOutputCard (Output := DigestRegister) *
                ∑ source : DigestRegister,
                  digestCharacter phase source * state source) =
        ∑ phase : DigestRegister, ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (digestCharacter phase (-response) *
            digestCharacter phase source) * state source := by
      simp_rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro phase _
      apply Finset.sum_congr rfl
      intro source _
      ring
    _ = ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (∑ phase : DigestRegister,
            digestCharacter phase (source - response)) * state source := by
      rw [Finset.sum_comm]
      apply Finset.sum_congr rfl
      intro source _
      rw [Finset.mul_sum, Finset.sum_mul]
      apply Finset.sum_congr rfl
      intro phase _
      rw [← AddChar.map_add_eq_mul]
      congr 2
      abel
    _ = ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (if source = response then
            (Fintype.card DigestRegister : ℂ) else 0) * state source := by
      apply Finset.sum_congr rfl
      intro source _
      rw [digest_phase_character_orthogonality response source]
    _ = state response := by
      rw [Fintype.sum_eq_single response]
      · rw [if_pos rfl]
        rw [digest_fourier_normalization, one_mul]
      · simp_all

theorem digest_response_fourier_inverse_right
    (state : DigestRegister → ℂ) :
    digestResponseFourier (digestResponseFourierInverse state) = state := by
  funext phase
  unfold digestResponseFourier digestResponseFourierInverse
  calc
    inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ response : DigestRegister,
            digestCharacter phase response *
              (inverseSqrtOutputCard (Output := DigestRegister) *
                ∑ source : DigestRegister,
                  digestCharacter source (-response) * state source) =
        ∑ response : DigestRegister, ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (digestCharacter phase response *
            digestCharacter source (-response)) * state source := by
      simp_rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro response _
      apply Finset.sum_congr rfl
      intro source _
      ring
    _ = ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (∑ response : DigestRegister,
            digestCharacter phase response *
              digestCharacter source (-response)) * state source := by
      rw [Finset.sum_comm]
      apply Finset.sum_congr rfl
      intro source _
      rw [Finset.mul_sum, Finset.sum_mul]
    _ = ∑ source : DigestRegister,
          (inverseSqrtOutputCard (Output := DigestRegister) *
            inverseSqrtOutputCard (Output := DigestRegister)) *
          (if phase = source then
            (Fintype.card DigestRegister : ℂ) else 0) * state source := by
      apply Finset.sum_congr rfl
      intro source _
      rw [digest_output_character_orthogonality phase source]
    _ = state phase := by
      rw [Fintype.sum_eq_single phase]
      · rw [if_pos rfl]
        rw [digest_fourier_normalization, one_mul]
      · simp_all [eq_comm]

/-- Translating the answer register becomes multiplication by the CMS
character. -/
theorem digest_response_fourier_shift
    (answer : DigestRegister) (state : DigestRegister → ℂ) :
    digestResponseFourier (fun response => state (response - answer)) =
      fun phase => digestCharacter phase answer *
        digestResponseFourier state phase := by
  funext phase
  unfold digestResponseFourier
  rw [← Equiv.sum_comp (Equiv.addRight answer)
    (fun response : DigestRegister =>
      digestCharacter phase response * state (response - answer))]
  simp only [Equiv.coe_addRight, add_sub_cancel_right,
    AddChar.map_add_eq_mul]
  calc
    inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ response : DigestRegister,
            (digestCharacter phase response * digestCharacter phase answer) *
              state response =
        inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ response : DigestRegister,
            digestCharacter phase answer *
              (digestCharacter phase response * state response) := by
      apply congrArg
      apply Finset.sum_congr rfl
      intro response _
      ring
    _ = digestCharacter phase answer *
          (inverseSqrtOutputCard (Output := DigestRegister) *
            ∑ response : DigestRegister,
              digestCharacter phase response * state response) := by
      rw [← Finset.mul_sum]
      ring

/-- Apply the response DFT independently on every fixed input/work/database
fiber.  In particular it cannot inspect or modify the CMS database. -/
def responseFourierState (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  fun target =>
    digestResponseFourier
      (fun response => state { target with phase := response }) target.phase

def responseFourierInverseState (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  fun target =>
    digestResponseFourierInverse
      (fun phase => state { target with phase := phase }) target.phase

/-- The same basis change on the adversary registers before they are coupled
to a database coordinate. -/
def responseFourierRegisters
    (state : RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ) :
    RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ :=
  fun target => digestResponseFourier
    (fun response => state (target.1, response, target.2.2)) target.2.1

def responseFourierInverseRegisters
    (state : RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ) :
    RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ :=
  fun target => digestResponseFourierInverse
    (fun phase => state (target.1, phase, target.2.2)) target.2.1

@[simp]
theorem response_fourier_registers_inverse_left
    (state : RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ) :
    responseFourierInverseRegisters (responseFourierRegisters state) = state := by
  funext target
  rcases target with ⟨input, phase, workspace⟩
  exact congrFun (digest_response_fourier_inverse_left
    (fun response => state (input, response, workspace))) phase

@[simp]
theorem response_fourier_inverse_left
    (state : ResponseCmsState Input Work) :
    responseFourierInverseState (responseFourierState state) = state := by
  funext target
  rcases target with ⟨input, phase, workspace, database⟩
  exact congrFun (digest_response_fourier_inverse_left
    (fun response => state
      { input := input, phase := response,
        workspace := workspace, database := database })) phase

@[simp]
theorem response_fourier_inverse_right
    (state : ResponseCmsState Input Work) :
    responseFourierState (responseFourierInverseState state) = state := by
  funext target
  rcases target with ⟨input, phase, workspace, database⟩
  exact congrFun (digest_response_fourier_inverse_right
    (fun response => state
      { input := input, phase := response,
        workspace := workspace, database := database })) phase

theorem response_fourier_coordinate_projection
    (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    responseFourierState (coordinateEventProjection input answer state) =
      coordinateEventProjection input answer (responseFourierState state) := by
  funext target
  by_cases selected : target.database input = some answer
  · simp [responseFourierState, digestResponseFourier,
      coordinateEventProjection, selected]
  · simp [responseFourierState, digestResponseFourier,
      coordinateEventProjection, selected]

theorem response_fourier_inverse_coordinate_projection
    (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    responseFourierInverseState
        (coordinateEventProjection input answer state) =
      coordinateEventProjection input answer
        (responseFourierInverseState state) := by
  funext target
  by_cases selected : target.database input = some answer
  · simp [responseFourierInverseState, digestResponseFourierInverse,
      coordinateEventProjection, selected]
  · simp [responseFourierInverseState, digestResponseFourierInverse,
      coordinateEventProjection, selected]

theorem response_fourier_state_bounded
    {bound : Nat} {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (responseFourierState state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have fiberZero :
        ∀ response : DigestRegister,
          state { target with phase := response } = 0 := by
      intro response
      exact bounded_state_apply_eq_zero_of_lt bounded
        { target with phase := response } above
    simp [HegemonCrypto.CmsCompressedOracle.project, within, responseFourierState,
      digestResponseFourier, fiberZero]

theorem response_fourier_inverse_state_bounded
    {bound : Nat} {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (responseFourierInverseState state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have fiberZero :
        ∀ phase : DigestRegister,
          state { target with phase := phase } = 0 := by
      intro phase
      exact bounded_state_apply_eq_zero_of_lt bounded
        { target with phase := phase } above
    simp [HegemonCrypto.CmsCompressedOracle.project, within, responseFourierInverseState,
      digestResponseFourierInverse, fiberZero]

/-- The response DFT is database-blind and therefore commutes with one CMS
coordinate reflection. -/
theorem decompress_at_response_fourier_state
    (selected : Input) (state : ResponseCmsState Input Work) :
    decompressAt selected (responseFourierState state) =
      responseFourierState (decompressAt selected state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold responseFourierState digestResponseFourier
  simp_rw [decompress_at_eq_sum_kernel]
  simp only [Finset.sum_mul, Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro response _
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem decompress_at_response_fourier_inverse_state
    (selected : Input) (state : ResponseCmsState Input Work) :
    decompressAt selected (responseFourierInverseState state) =
      responseFourierInverseState (decompressAt selected state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold responseFourierInverseState digestResponseFourierInverse
  simp_rw [decompress_at_eq_sum_kernel]
  simp only [Finset.sum_mul, Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro phase _
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem decompress_list_response_fourier_state
    (inputs : List Input) (state : ResponseCmsState Input Work) :
    decompressList inputs (responseFourierState state) =
      responseFourierState (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons selected remaining ih =>
      simp only [decompress_list_cons]
      rw [ih, decompress_at_response_fourier_state]

theorem decompress_list_response_fourier_inverse_state
    (inputs : List Input) (state : ResponseCmsState Input Work) :
    decompressList inputs (responseFourierInverseState state) =
      responseFourierInverseState (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons selected remaining ih =>
      simp only [decompress_list_cons]
      rw [ih, decompress_at_response_fourier_inverse_state]

@[simp]
theorem global_decompress_response_fourier_state
    (state : ResponseCmsState Input Work) :
    globalDecompress (responseFourierState state) =
      responseFourierState (globalDecompress state) := by
  unfold globalDecompress
  exact decompress_list_response_fourier_state _ state

@[simp]
theorem global_decompress_response_fourier_inverse_state
    (state : ResponseCmsState Input Work) :
    globalDecompress (responseFourierInverseState state) =
      responseFourierInverseState (globalDecompress state) := by
  unfold globalDecompress
  exact decompress_list_response_fourier_inverse_state _ state

/-- Fourier inversion acts independently inside every purified total-oracle
branch; the oracle amplitudes and database labels are unchanged. -/
theorem response_fourier_inverse_total_oracle_family_state
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    responseFourierInverseState (totalOracleFamilyState family) =
      totalOracleFamilyState
        (fun oracle => responseFourierInverseRegisters (family oracle)) := by
  funext target
  by_cases matched : ∃ oracle : Input → DigestRegister,
      target.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEq⟩ := matched
    rcases target with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEq ⊢
    subst database
    unfold responseFourierInverseState responseFourierInverseRegisters
    unfold digestResponseFourierInverse
    simp_rw [total_oracle_family_state_apply]
    calc
      _ = inverseSqrtOutputCard (Output := DigestRegister) *
          ∑ phase : DigestRegister,
            (inverseSqrtOutputCard (Output := DigestRegister) ^
                Fintype.card Input) *
              (digestCharacter phase (-phaseValue) *
                family oracle (registerInput, phase, workspace)) := by
          apply congrArg
          apply Finset.sum_congr rfl
          intro phase _
          ring
      _ = (inverseSqrtOutputCard (Output := DigestRegister) *
              inverseSqrtOutputCard (Output := DigestRegister) ^
                Fintype.card Input) *
            ∑ phase : DigestRegister,
              digestCharacter phase (-phaseValue) *
                family oracle (registerInput, phase, workspace) := by
          simp_rw [Finset.mul_sum]
          apply Finset.sum_congr rfl
          intro phase _
          ring
      _ = _ := by ring
  · have allZero : ∀ phase : DigestRegister,
        totalOracleFamilyState family
          { target with phase := phase } = 0 := by
      intro phase
      apply total_oracle_family_state_eq_zero_of_no_match
      simpa using matched
    have targetZero :
        totalOracleFamilyState
          (fun oracle => responseFourierInverseRegisters (family oracle))
          target = 0 := by
      apply total_oracle_family_state_eq_zero_of_no_match
      exact matched
    simp [responseFourierInverseState, digestResponseFourierInverse,
      allZero, targetZero]

/-- Restrict a database state to one persistent database coordinate.  The
remaining registers are exactly the existing whole-view game registers. -/
def databaseSlice (state : ResponseCmsState Input Work)
    (database : Database Input DigestRegister) :
    GameState (Input := Input) (Work := Work) :=
  WithLp.toLp 2 fun basis => state
    { input := basis.1
      phase := basis.2.1
      workspace := basis.2.2
      database := database }

/-- Lift an existing whole-view unitary without inspecting or changing the
persistent database. -/
def liftGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  fun target => operation (databaseSlice state target.database)
    (target.input, target.phase, target.workspace)

@[simp]
theorem database_slice_liftGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work)
    (database : Database Input DigestRegister) :
    databaseSlice (liftGate operation state) database =
      operation (databaseSlice state database) := by
  ext basis
  rfl

/-- Lift one Kraus branch of an existing complete whole-view instrument. -/
def liftInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  fun target => operation.branch outcome (databaseSlice state target.database)
    (target.input, target.phase, target.workspace)

/-- Lift any linear operation on the whole-view registers while retaining the
compressed database coordinate verbatim. -/
def liftLinear
    (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  fun target => operation (databaseSlice state target.database)
    (target.input, target.phase, target.workspace)

theorem liftGate_eq_liftLinear
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    liftGate operation state =
      liftLinear
        (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
          GameState (Input := Input) (Work := Work)) state := by
  rfl

theorem liftInstrumentBranch_eq_liftLinear {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) :
    liftInstrumentBranch operation outcome state =
      liftLinear (operation.branch outcome) state := by
  rfl

/-- Every register-linear operation commutes with one decompression
reflection because both preserve the complementary coordinate. -/
theorem decompress_at_liftLinear
    (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Work))
    (selected : Input) (state : ResponseCmsState Input Work) :
    decompressAt selected (liftLinear operation state) =
      liftLinear operation (decompressAt selected state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold liftLinear
  have sliceEq :
      databaseSlice (decompressAt selected state) target.database =
        ∑ source : Option DigestRegister,
          decompressKernel (Output := DigestRegister) source
              (target.database selected) •
            databaseSlice state
              (setDatabaseCoordinate target.database selected source) := by
    ext basis
    simp only [databaseSlice, WithLp.ofLp_sum, WithLp.ofLp_smul,
      WithLp.toLp_ofLp, Finset.sum_apply, PiLp.smul_apply,
      Pi.smul_apply, smul_eq_mul]
    rw [decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    ring
  rw [sliceEq, map_sum]
  simp only [map_smul, WithLp.ofLp_sum, WithLp.ofLp_smul,
    Finset.sum_apply, PiLp.smul_apply, Pi.smul_apply, smul_eq_mul]
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem decompress_list_liftLinear
    (operation : GameState (Input := Input) (Work := Work) →ₗ[ℂ]
      GameState (Input := Input) (Work := Work))
    (inputs : List Input) (state : ResponseCmsState Input Work) :
    decompressList inputs (liftLinear operation state) =
      liftLinear operation (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons selected remaining ih =>
      simp only [decompress_list_cons]
      rw [ih, decompress_at_liftLinear]

@[simp]
theorem global_decompress_liftGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    globalDecompress (liftGate operation state) =
      liftGate operation (globalDecompress state) := by
  rw [liftGate_eq_liftLinear, liftGate_eq_liftLinear]
  unfold globalDecompress
  exact decompress_list_liftLinear _ _ state

@[simp]
theorem global_decompress_liftInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) :
    globalDecompress (liftInstrumentBranch operation outcome state) =
      liftInstrumentBranch operation outcome (globalDecompress state) := by
  rw [liftInstrumentBranch_eq_liftLinear,
    liftInstrumentBranch_eq_liftLinear]
  unfold globalDecompress
  exact decompress_list_liftLinear _ _ state

@[simp]
theorem database_slice_liftInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work)
    (database : Database Input DigestRegister) :
    databaseSlice (liftInstrumentBranch operation outcome state) database =
      operation.branch outcome (databaseSlice state database) := by
  ext basis
  rfl

theorem liftGate_bounded
    {bound : Nat}
    (operation : GameGate (Input := Input) (Work := Work))
    {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (liftGate operation state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have sliceZero : databaseSlice state target.database = 0 := by
      ext basis
      exact bounded_state_apply_eq_zero_of_lt bounded
        { input := basis.1
          phase := basis.2.1
          workspace := basis.2.2
          database := target.database } above
    simp [HegemonCrypto.CmsCompressedOracle.project, within, liftGate, sliceZero]

theorem liftInstrumentBranch_bounded {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    {bound : Nat} {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (liftInstrumentBranch operation outcome state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have sliceZero : databaseSlice state target.database = 0 := by
      ext basis
      exact bounded_state_apply_eq_zero_of_lt bounded
        { input := basis.1
          phase := basis.2.1
          workspace := basis.2.2
          database := target.database } above
    simp [HegemonCrypto.CmsCompressedOracle.project, within,
      liftInstrumentBranch, sliceZero]

/-- The ordinary response-register oracle query on an explicit database.
An absent coordinate is interpreted as the additive-zero answer.  This makes
the operation a permutation on every database fiber (not merely on the
total-oracle invariant) and exactly matches `recordedPhase = 1` on an absent
CMS coordinate. -/
def databaseResponseQuery (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  fun target =>
    match target.database target.input with
    | none => state target
    | some answer => state
        { target with phase := target.phase - answer }

/-- The database-blind DFT carries the literal response-translation query to
the ordinary CMS phase query on every finite database, including absent
coordinates. -/
theorem response_fourier_database_response_query
    (state : ResponseCmsState Input Work) :
    responseFourierState (databaseResponseQuery state) =
      phaseQueryState digestPhaseSystem (responseFourierState state) := by
  funext target
  cases value : target.database target.input with
  | none =>
      simp [responseFourierState, digestResponseFourier,
        databaseResponseQuery, phaseQueryState, recordedPhase, value]
  | some answer =>
      simp only [responseFourierState, databaseResponseQuery,
        phaseQueryState, recordedPhase, value]
      change
        digestResponseFourier
            (fun response => state { target with phase := response - answer })
            target.phase =
          digestCharacter target.phase answer *
            digestResponseFourier
              (fun response => state { target with phase := response })
              target.phase
      exact congrFun (digest_response_fourier_shift answer
        (fun response => state { target with phase := response })) target.phase

/-- On a named total oracle branch this is definitionally the query used by
`HonestWholeViewGames.Program.quantumQuery`. -/
theorem database_slice_response_query_total
    (state : ResponseCmsState Input Work)
    (oracle : Input → DigestRegister) :
    databaseSlice (databaseResponseQuery state) (totalDatabase oracle) =
      query oracle (databaseSlice state (totalDatabase oracle)) := by
  ext basis
  simp [databaseSlice, databaseResponseQuery, totalDatabase, query_apply]

/-- Complete public branch for an honest classical read in standard database
coordinates. -/
def databaseReadBranch (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  coordinateEventProjection input answer state

/-- After measuring the old value, replace exactly that database coordinate.
The old value remains an outer finite branch of the recursive interpreter. -/
def replaceReadBranch (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  fun target =>
    if target.database input = some fresh then
      state { target with database :=
        setDatabaseCoordinate target.database input (some old) }
    else 0

theorem response_fourier_replace_read_branch
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    responseFourierState (replaceReadBranch input old fresh state) =
      replaceReadBranch input old fresh (responseFourierState state) := by
  funext target
  by_cases selected : target.database input = some fresh
  · simp [responseFourierState, digestResponseFourier,
      replaceReadBranch, selected]
  · simp [responseFourierState, digestResponseFourier,
      replaceReadBranch, selected]

theorem response_fourier_inverse_replace_read_branch
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    responseFourierInverseState
        (replaceReadBranch input old fresh state) =
      replaceReadBranch input old fresh
        (responseFourierInverseState state) := by
  funext target
  by_cases selected : target.database input = some fresh
  · simp [responseFourierInverseState, digestResponseFourierInverse,
      replaceReadBranch, selected]
  · simp [responseFourierInverseState, digestResponseFourierInverse,
      replaceReadBranch, selected]

/-- Replacing a measured coordinate has the expected exact action on every
named total-oracle branch. -/
theorem database_slice_replace_read_branch_total
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work)
    (oracle : Input → DigestRegister) :
    databaseSlice (replaceReadBranch input old fresh state)
        (totalDatabase oracle) =
      if oracle input = fresh then
        databaseSlice state (totalDatabase (Function.update oracle input old))
      else 0 := by
  ext basis
  by_cases selected : oracle input = fresh
  · simp only [databaseSlice, replaceReadBranch, totalDatabase, selected,
      if_true, Function.update_self]
    have databaseEq :
        setDatabaseCoordinate (totalDatabase oracle) input (some old) =
          totalDatabase (Function.update oracle input old) := by
      funext address
      by_cases same : address = input
      · subst address
        simp [setDatabaseCoordinate, totalDatabase]
      · have reverse : input ≠ address := Ne.symm same
        rw [set_database_coordinate_other _ same]
        simp [totalDatabase, Function.update_of_ne same, reverse]
    rw [databaseEq]
  · simp [databaseSlice, replaceReadBranch, totalDatabase, selected]

/-- A single named classical oracle branch, with no normalization factor. -/
def oracleState (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    ResponseCmsState Input Work :=
  fun basis =>
    if basis.database = totalDatabase oracle then
      state (basis.input, basis.phase, basis.workspace)
    else 0

@[simp]
theorem oracleState_zero (oracle : Input → DigestRegister) :
    oracleState oracle (0 : GameState (Input := Input) (Work := Work)) = 0 := by
  funext target
  simp [oracleState]

@[simp]
theorem database_slice_oracleState
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work))
    (database : Database Input DigestRegister) :
    databaseSlice (oracleState oracle state) database =
      if database = totalDatabase oracle then state else 0 := by
  by_cases same : database = totalDatabase oracle
  · subst database
    ext basis
    simp [databaseSlice, oracleState]
  · ext basis
    simp [databaseSlice, oracleState, same]

@[simp]
theorem liftGate_oracleState
    (operation : GameGate (Input := Input) (Work := Work))
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    liftGate operation (oracleState oracle state) =
      oracleState oracle (operation state) := by
  funext target
  by_cases same : target.database = totalDatabase oracle
  · simp [liftGate, databaseSlice, oracleState, same]
  · have sliceZero :
        databaseSlice (oracleState oracle state) target.database = 0 := by
      rw [database_slice_oracleState, if_neg same]
    unfold liftGate
    rw [sliceZero, map_zero]
    simp [oracleState, same]

@[simp]
theorem liftInstrumentBranch_oracleState {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    liftInstrumentBranch operation outcome (oracleState oracle state) =
      oracleState oracle (operation.branch outcome state) := by
  funext target
  by_cases same : target.database = totalDatabase oracle
  · simp [liftInstrumentBranch, databaseSlice, oracleState, same]
  · have sliceZero :
        databaseSlice (oracleState oracle state) target.database = 0 := by
      rw [database_slice_oracleState, if_neg same]
    unfold liftInstrumentBranch
    rw [sliceZero, map_zero]
    simp [oracleState, same]

@[simp]
theorem databaseResponseQuery_oracleState
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    databaseResponseQuery (oracleState oracle state) =
      oracleState oracle (query oracle state) := by
  funext target
  by_cases same : target.database = totalDatabase oracle
  · simp [databaseResponseQuery, oracleState, same, totalDatabase,
      query_apply]
  · cases value : target.database target.input with
    | none => simp [databaseResponseQuery, oracleState, same, value]
    | some answer => simp [databaseResponseQuery, oracleState, same, value]

@[simp]
theorem databaseReadBranch_oracleState
    (input : Input) (answer : DigestRegister)
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    databaseReadBranch input answer (oracleState oracle state) =
      if oracle input = answer then oracleState oracle state else 0 := by
  funext target
  by_cases selected : oracle input = answer
  <;> by_cases same : target.database = totalDatabase oracle
  <;> simp [databaseReadBranch, coordinateEventProjection, oracleState,
    same, selected, totalDatabase]

/-- Updating one coordinate of a total database is the total database of the
updated oracle. -/
theorem set_total_database_coordinate
    (oracle : Input → DigestRegister) (input : Input)
    (answer : DigestRegister) :
    setDatabaseCoordinate (totalDatabase oracle) input (some answer) =
      totalDatabase (Function.update oracle input answer) := by
  funext selected
  by_cases same : selected = input
  · subst selected
    simp [setDatabaseCoordinate, totalDatabase]
  · have reverse : input ≠ selected := Ne.symm same
    rw [set_database_coordinate_other _ same]
    simp [totalDatabase, Function.update_of_ne same, reverse]

/-- The two conditions used by a measured replacement characterize exactly
one updated total-oracle branch. -/
theorem replace_total_database_iff
    (database : Database Input DigestRegister)
    (oracle : Input → DigestRegister) (input : Input)
    (old fresh : DigestRegister) :
    database input = some fresh ∧
        setDatabaseCoordinate database input (some old) = totalDatabase oracle ↔
      oracle input = old ∧
        database = totalDatabase (Function.update oracle input fresh) := by
  constructor
  · rintro ⟨atInput, replaced⟩
    have oldValue : oracle input = old := by
      have atSelected := congrFun replaced input
      simpa [setDatabaseCoordinate, totalDatabase] using atSelected.symm
    refine ⟨oldValue, ?_⟩
    funext selected
    by_cases same : selected = input
    · subst selected
      simp [totalDatabase, atInput]
    · have atSelected := congrFun replaced selected
      simpa [setDatabaseCoordinate, totalDatabase,
        Function.update_of_ne same, same] using atSelected
  · rintro ⟨oldValue, rfl⟩
    constructor
    · simp [totalDatabase]
    · rw [set_total_database_coordinate]
      congr 1
      funext selected
      by_cases same : selected = input
      · subst selected
        simp [oldValue]
      · simp [Function.update_of_ne same]

@[simp]
theorem replaceReadBranch_oracleState
    (input : Input) (old fresh : DigestRegister)
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    replaceReadBranch input old fresh (oracleState oracle state) =
      if oracle input = old then
        oracleState (Function.update oracle input fresh) state
      else 0 := by
  funext target
  have characterize := replace_total_database_iff
    target.database oracle input old fresh
  by_cases freshAt : target.database input = some fresh
  · have reduced :
        setDatabaseCoordinate target.database input (some old) =
            totalDatabase oracle ↔
          oracle input = old ∧
            target.database =
              totalDatabase (Function.update oracle input fresh) := by
      simpa only [freshAt, true_and] using characterize
    by_cases oldMatches : oracle input = old
    · by_cases updated : target.database =
          totalDatabase (Function.update oracle input fresh)
      · have sourceTotal := reduced.mpr ⟨oldMatches, updated⟩
        unfold replaceReadBranch oracleState
        rw [if_pos freshAt, if_pos sourceTotal, if_pos oldMatches,
          if_pos updated]
      · simp [replaceReadBranch, oracleState, freshAt, reduced,
          oldMatches, updated]
    · simp [replaceReadBranch, oracleState, freshAt, reduced, oldMatches]
  · have notUpdated :
        target.database ≠
          totalDatabase (Function.update oracle input fresh) := by
      intro equal
      apply freshAt
      have atInput := congrFun equal input
      simpa [totalDatabase] using atInput
    by_cases oldMatches : oracle input = old
    · simp [replaceReadBranch, oracleState, freshAt, notUpdated, oldMatches]
    · simp [replaceReadBranch, oracleState, freshAt, oldMatches]

/-- Final Born mass, summed over the retained database rather than erasing it
coherently. -/
def databaseBorn (event : Finset (QueryBasis Input DigestRegister Work))
    (state : ResponseCmsState Input Work) : ℝ :=
  ∑ database : Database Input DigestRegister,
    born event (databaseSlice state database)

@[simp]
theorem databaseBorn_zero
    (event : Finset (QueryBasis Input DigestRegister Work)) :
    databaseBorn event (0 : ResponseCmsState Input Work) = 0 := by
  unfold databaseBorn
  apply Finset.sum_eq_zero
  intro database _
  have sliceZero :
      databaseSlice (0 : ResponseCmsState Input Work) database = 0 := by
    rfl
  rw [sliceZero]
  simp [born]

@[simp]
theorem databaseBorn_oracleState
    (event : Finset (QueryBasis Input DigestRegister Work))
    (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    databaseBorn event (oracleState oracle state) = born event state := by
  classical
  unfold databaseBorn
  rw [Finset.sum_eq_single (totalDatabase oracle)]
  · simp [database_slice_oracleState]
  · intro database _ different
    simp [database_slice_oracleState, different, born]
  · simp

/-- Exact recursive standard-database semantics for the existing whole-view
program grammar.  Every measurement outcome remains in an additive sum and
every local random source remains a uniform average. -/
def databaseRun (randomized : Bool) :
    Program Input Work → ResponseCmsState Input Work → ℝ
  | .finish event, state => databaseBorn event state
  | .gate operation next, state =>
      databaseRun randomized next (liftGate operation state)
  | .quantumQuery next, state =>
      databaseRun randomized next (databaseResponseQuery state)
  | .honestRead input next, state =>
      ∑ answer : DigestRegister,
        databaseRun randomized (next answer)
          (databaseReadBranch input answer state)
  | .instrument operation next, state =>
      ∑ outcome,
        databaseRun randomized (next outcome)
          (liftInstrumentBranch operation outcome state)
  | .random source next, state =>
      uniformAverage fun coins : source.Coins =>
        databaseRun randomized (next coins) state
  | .freshInput sampler next, state =>
      uniformAverage fun coins : sampler.Coins =>
        let input := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            ∑ old : DigestRegister,
              databaseRun randomized (next coins fresh)
                (replaceReadBranch input old fresh
                  (databaseReadBranch input old state))
        else
          ∑ old : DigestRegister,
            databaseRun randomized (next coins old)
              (databaseReadBranch input old state)

@[simp]
theorem liftGate_zero
    (operation : GameGate (Input := Input) (Work := Work)) :
    liftGate operation (0 : ResponseCmsState Input Work) = 0 := by
  funext target
  have sliceZero :
      databaseSlice (0 : ResponseCmsState Input Work) target.database = 0 := by
    rfl
  unfold liftGate
  rw [sliceZero, map_zero]
  rfl

@[simp]
theorem liftInstrumentBranch_zero {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count) :
    liftInstrumentBranch operation outcome
        (0 : ResponseCmsState Input Work) = 0 := by
  funext target
  have sliceZero :
      databaseSlice (0 : ResponseCmsState Input Work) target.database = 0 := by
    rfl
  unfold liftInstrumentBranch
  rw [sliceZero, map_zero]
  rfl

@[simp]
theorem databaseResponseQuery_zero :
    databaseResponseQuery (0 : ResponseCmsState Input Work) = 0 := by
  funext target
  unfold databaseResponseQuery
  split <;> rfl

@[simp]
theorem databaseReadBranch_zero (input : Input) (answer : DigestRegister) :
    databaseReadBranch input answer (0 : ResponseCmsState Input Work) = 0 := by
  funext target
  simp [databaseReadBranch, coordinateEventProjection]

@[simp]
theorem replaceReadBranch_zero
    (input : Input) (old fresh : DigestRegister) :
    replaceReadBranch input old fresh (0 : ResponseCmsState Input Work) = 0 := by
  funext target
  simp [replaceReadBranch]

@[simp]
theorem databaseRun_zero (randomized : Bool)
    (program : Program Input Work) :
    databaseRun randomized program (0 : ResponseCmsState Input Work) = 0 := by
  induction program with
  | finish event => exact databaseBorn_zero event
  | gate operation next ih => simpa only [databaseRun, liftGate_zero] using ih
  | quantumQuery next ih =>
      simpa only [databaseRun, databaseResponseQuery_zero] using ih
  | honestRead input next ih =>
      simp only [databaseRun, databaseReadBranch_zero, ih,
        Finset.sum_const_zero]
  | instrument operation next ih =>
      simp only [databaseRun, liftInstrumentBranch_zero, ih,
        Finset.sum_const_zero]
  | random source next ih =>
      simpa only [databaseRun, ih] using
        (uniform_average_const (A := source.Coins) (0 : ℝ))
  | freshInput sampler next ih =>
      cases randomized <;>
        simp only [databaseRun, Bool.false_eq_true, if_false, if_true,
          databaseReadBranch_zero, replaceReadBranch_zero, ih,
          Finset.sum_const_zero, uniform_average_const]

/-- Pointwise semantic adequacy of the database interpreter.  It is proved
for every fixed oracle and arbitrary subnormalised game state, then may be
averaged over the uniform oracle without an oracle-dependent premise. -/
theorem databaseRun_oracleState (randomized : Bool)
    (program : Program Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    databaseRun randomized program (oracleState oracle state) =
      V8Smz9HonestWholeViewGames.run randomized program oracle state := by
  induction program generalizing oracle state with
  | finish event =>
      rw [databaseRun, V8Smz9HonestWholeViewGames.run]
      convert databaseBorn_oracleState event oracle state using 1
      apply congrArg (fun decision :
          DecidableEq (QueryBasis Input DigestRegister Work) =>
        @born (QueryBasis Input DigestRegister Work) _ decision event state)
      exact Subsingleton.elim _ _
  | gate operation next ih =>
      simp [databaseRun, V8Smz9HonestWholeViewGames.run, ih]
  | quantumQuery next ih =>
      simp [databaseRun, V8Smz9HonestWholeViewGames.run, ih]
  | honestRead input next ih =>
      simp only [databaseRun, V8Smz9HonestWholeViewGames.run]
      rw [Finset.sum_eq_single (oracle input)]
      · simp [ih]
      · intro answer _ different
        rw [databaseReadBranch_oracleState, if_neg (Ne.symm different),
          databaseRun_zero]
      · simp
  | instrument operation next ih =>
      simp only [databaseRun, V8Smz9HonestWholeViewGames.run]
      apply Finset.sum_congr rfl
      intro outcome _
      rw [liftInstrumentBranch_oracleState, ih outcome]
  | random source next ih =>
      simp only [databaseRun, V8Smz9HonestWholeViewGames.run]
      apply congrArg uniformAverage
      funext coins
      exact ih coins oracle state
  | freshInput sampler next ih =>
      cases randomized with
      | false =>
          simp only [databaseRun, V8Smz9HonestWholeViewGames.run,
            Bool.false_eq_true, if_false]
          apply congrArg uniformAverage
          funext coins
          rw [Finset.sum_eq_single (oracle (sampler.input coins))]
          · simp [ih, uniform_average_const]
          · intro old _ different
            rw [databaseReadBranch_oracleState,
              if_neg (Ne.symm different), databaseRun_zero]
          · simp
      | true =>
          simp only [databaseRun, V8Smz9HonestWholeViewGames.run, if_true,
            Function.update_self]
          apply congrArg uniformAverage
          funext coins
          apply congrArg uniformAverage
          funext fresh
          rw [Finset.sum_eq_single (oracle (sampler.input coins))]
          · rw [databaseReadBranch_oracleState, if_pos rfl,
              replaceReadBranch_oracleState, if_pos rfl,
              ih coins fresh]
          · intro old _ different
            rw [databaseReadBranch_oracleState,
              if_neg (Ne.symm different)]
            rw [replaceReadBranch_zero, databaseRun_zero]
          · simp

/-! ## Uniform-purification semantics

The induction below is deliberately stated for an arbitrary oracle-indexed
register family.  A constant-family statement is not closed under
`freshInput`: after measuring `old` and writing `fresh`, the resulting family
is supported only on total oracles whose selected coordinate is `fresh`.
-/

abbrev familyGameState
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister) :
    GameState (Input := Input) (Work := Work) :=
  WithLp.toLp 2 (family oracle)

theorem uniformAverage_eq_sum_div
    {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) :
    uniformAverage value =
      (∑ coin, value coin) / (Fintype.card Coins : ℝ) := by
  simp only [uniformAverage, uniformFintypePMF_apply,
    ENNReal.toReal_inv, ENNReal.toReal_natCast]
  rw [← Finset.mul_sum, div_eq_mul_inv, mul_comm]

theorem born_eq_sum_event
    (event : Finset (QueryBasis Input DigestRegister Work))
    (state : GameState (Input := Input) (Work := Work)) :
    born event state =
      ∑ basis ∈ event, Complex.normSq (state basis) := by
  unfold born
  rw [EuclideanSpace.norm_sq_eq]
  calc
    (∑ basis, ‖eventProjection event state basis‖ ^ 2) =
        ∑ basis, if basis ∈ event
          then Complex.normSq (state basis) else 0 := by
      apply Finset.sum_congr rfl
      intro basis _
      by_cases member : basis ∈ event
      · simp [eventProjection, member, Complex.sq_norm]
      · simp [eventProjection, member]
    _ = ∑ basis ∈ event, Complex.normSq (state basis) := by
      simp

theorem databaseBorn_totalOracleFamilyState
    (event : Finset (QueryBasis Input DigestRegister Work))
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    databaseBorn event (totalOracleFamilyState family) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        born event (familyGameState family oracle)) := by
  rw [uniformAverage_eq_sum_div]
  unfold databaseBorn
  simp_rw [born_eq_sum_event]
  simp only [databaseSlice]
  rw [Finset.sum_comm]
  simp_rw [sum_database_normSq_total_oracle_family_state]
  simp_rw [Finset.sum_div]
  rw [Finset.sum_comm]

@[simp]
theorem databaseReadBranch_totalOracleFamilyState
    (input : Input) (answer : DigestRegister)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    databaseReadBranch input answer (totalOracleFamilyState family) =
      totalOracleFamilyState (fun oracle =>
        if oracle input = answer then family oracle else 0) := by
  funext target
  by_cases matched : ∃ oracle : Input → DigestRegister,
      target.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEq⟩ := matched
    rcases target with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEq ⊢
    subst database
    by_cases selected : oracle input = answer <;>
      simp [databaseReadBranch, coordinateEventProjection, totalDatabase,
        total_oracle_family_state_apply, selected]
  · have leftZero : totalOracleFamilyState family target = 0 :=
      total_oracle_family_state_eq_zero_of_no_match family target matched
    have rightZero :
        totalOracleFamilyState
          (fun oracle => if oracle input = answer then family oracle else 0)
          target = 0 :=
      total_oracle_family_state_eq_zero_of_no_match _ target matched
    simp [databaseReadBranch, coordinateEventProjection, leftZero, rightZero]

@[simp]
theorem replaceReadBranch_totalOracleFamilyState
    (input : Input) (old fresh : DigestRegister)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    replaceReadBranch input old fresh (totalOracleFamilyState family) =
      totalOracleFamilyState (fun oracle =>
        if oracle input = fresh then
          family (Function.update oracle input old)
        else 0) := by
  funext target
  by_cases matched : ∃ oracle : Input → DigestRegister,
      target.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEq⟩ := matched
    rcases target with ⟨registerInput, phaseValue, workspace, database⟩
    dsimp at databaseEq ⊢
    subst database
    by_cases selected : oracle input = fresh <;>
      simp [replaceReadBranch, totalDatabase, set_total_database_coordinate,
        total_oracle_family_state_apply, selected]
  · have rightZero :
        totalOracleFamilyState
          (fun oracle => if oracle input = fresh then
            family (Function.update oracle input old) else 0) target = 0 :=
      total_oracle_family_state_eq_zero_of_no_match _ target matched
    by_cases selected : target.database input = some fresh
    · have sourceNoMatch : ¬ ∃ oracle : Input → DigestRegister,
          setDatabaseCoordinate target.database input (some old) =
            totalDatabase oracle := by
        rintro ⟨oracle, sourceEq⟩
        have characterized := (replace_total_database_iff
          target.database oracle input old fresh).mp ⟨selected, sourceEq⟩
        exact matched ⟨Function.update oracle input fresh,
          characterized.2⟩
      have sourceZero := total_oracle_family_state_eq_zero_of_no_match
        family
        { target with database :=
            setDatabaseCoordinate target.database input (some old) }
        sourceNoMatch
      simp [replaceReadBranch, selected, sourceZero, rightZero]
    · simp [replaceReadBranch, selected, rightZero]

theorem databaseSlice_totalOracleFamilyState
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister) :
    databaseSlice (totalOracleFamilyState family) (totalDatabase oracle) =
      (inverseSqrtOutputCard (Output := DigestRegister) ^
          Fintype.card Input) • familyGameState family oracle := by
  ext basis
  rcases basis with ⟨registerInput, phaseValue, workspace⟩
  simp [databaseSlice, familyGameState,
    total_oracle_family_state_apply]

/-- Reindex the measured-old/write-fresh branches without dropping the old
value.  This is the finite bijection used in the `freshInput` constructor. -/
theorem uniformAverage_update_partition
    (input : Input)
    (value : DigestRegister → DigestRegister →
      (Input → DigestRegister) → ℝ) :
    uniformAverage (fun fresh : DigestRegister =>
      ∑ old : DigestRegister,
        uniformAverage (fun oracle : Input → DigestRegister =>
          if oracle input = fresh then value old fresh oracle else 0)) =
    uniformAverage (fun oracle : Input → DigestRegister =>
      uniformAverage (fun fresh : DigestRegister =>
        value (oracle input) fresh
          (Function.update oracle input fresh))) := by
  let split := Equiv.funSplitAt input DigestRegister
  have raw :
      (∑ fresh : DigestRegister, ∑ old : DigestRegister,
        ∑ oracle : Input → DigestRegister,
          if oracle input = fresh then value old fresh oracle else 0) =
      ∑ oracle : Input → DigestRegister, ∑ fresh : DigestRegister,
        value (oracle input) fresh
          (Function.update oracle input fresh) := by
    calc
      _ = ∑ fresh : DigestRegister, ∑ old : DigestRegister,
          ∑ pair : DigestRegister ×
              ({ other : Input // other ≠ input } → DigestRegister),
            if (split.symm pair) input = fresh then
              value old fresh (split.symm pair) else 0 := by
          apply Finset.sum_congr rfl
          intro fresh _
          apply Finset.sum_congr rfl
          intro old _
          exact Fintype.sum_equiv split
            (fun oracle => if oracle input = fresh then
              value old fresh oracle else 0)
            (fun pair => if (split.symm pair) input = fresh then
              value old fresh (split.symm pair) else 0)
            (fun oracle => by rw [split.symm_apply_apply])
      _ = ∑ fresh : DigestRegister, ∑ old : DigestRegister,
          ∑ rest : { other : Input // other ≠ input } → DigestRegister,
            value old fresh (split.symm (fresh, rest)) := by
          simp only [Fintype.sum_prod_type]
          simp [split, Equiv.funSplitAt, Equiv.piSplitAt]
      _ = ∑ old : DigestRegister,
          ∑ rest : { other : Input // other ≠ input } → DigestRegister,
            ∑ fresh : DigestRegister,
              value old fresh (split.symm (fresh, rest)) := by
          rw [Finset.sum_comm]
          apply Finset.sum_congr rfl
          intro old _
          rw [Finset.sum_comm]
      _ = ∑ pair : DigestRegister ×
              ({ other : Input // other ≠ input } → DigestRegister),
            ∑ fresh : DigestRegister,
              value pair.1 fresh (split.symm (fresh, pair.2)) := by
          rw [Fintype.sum_prod_type]
      _ = ∑ oracle : Input → DigestRegister,
          ∑ fresh : DigestRegister,
            value (oracle input) fresh
              (Function.update oracle input fresh) := by
          exact (Fintype.sum_equiv split
            (fun oracle => ∑ fresh : DigestRegister,
              value (oracle input) fresh
                (Function.update oracle input fresh))
            (fun pair => ∑ fresh : DigestRegister,
              value pair.1 fresh (split.symm (fresh, pair.2)))
            (fun oracle => by
              apply Finset.sum_congr rfl
              intro fresh _
              have updated :
                  Function.update oracle input fresh =
                    split.symm (fresh, (split oracle).2) := by
                funext selected
                by_cases same : selected = input
                · subst selected
                  simp [split, Equiv.funSplitAt, Equiv.piSplitAt]
                · simp [split, Equiv.funSplitAt, Equiv.piSplitAt,
                    Function.update_of_ne same, same]
              rw [updated]
              simp [split, Equiv.funSplitAt, Equiv.piSplitAt])).symm
  have scaled := congrArg (fun total : ℝ =>
    total / (Fintype.card (Input → DigestRegister) : ℝ) /
      (Fintype.card DigestRegister : ℝ)) raw
  simp_rw [uniformAverage_eq_sum_div]
  convert scaled using 1 <;> simp only [Finset.sum_div]
  apply Finset.sum_congr rfl
  intro oracle _
  apply Finset.sum_congr rfl
  intro fresh _
  ring

/-- Exact Born-average identity for the persistent-database interpreter. -/
theorem databaseRun_totalOracleFamilyState (randomized : Bool)
    (program : Program Input Work)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    databaseRun randomized program (totalOracleFamilyState family) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        databaseRun randomized program
          (oracleState oracle (familyGameState family oracle))) := by
  induction program generalizing family with
  | finish event =>
      simpa [databaseRun, databaseBorn_oracleState] using
        databaseBorn_totalOracleFamilyState event family
  | gate operation next ih =>
      -- Register-only gates retain each total-database fiber.
      simp only [databaseRun]
      rw [show liftGate operation (totalOracleFamilyState family) =
          totalOracleFamilyState (fun oracle =>
            (operation (familyGameState family oracle)).ofLp) by
        funext target
        by_cases matched : ∃ oracle : Input → DigestRegister,
            target.database = totalDatabase oracle
        · obtain ⟨oracle, databaseEq⟩ := matched
          rcases target with ⟨registerInput, phaseValue, workspace, database⟩
          dsimp at databaseEq ⊢
          subst database
          unfold liftGate
          rw [databaseSlice_totalOracleFamilyState, map_smul,
            total_oracle_family_state_apply]
          rfl
        · have sliceZero :
              databaseSlice (totalOracleFamilyState family)
                  target.database = 0 := by
            ext register
            apply total_oracle_family_state_eq_zero_of_no_match
            simpa using matched
          unfold liftGate
          rw [sliceZero, map_zero]
          symm
          apply total_oracle_family_state_eq_zero_of_no_match
          exact matched]
      rw [ih]
      apply congrArg uniformAverage
      funext oracle
      simp [databaseRun]
  | quantumQuery next ih =>
      simp only [databaseRun]
      rw [show databaseResponseQuery (totalOracleFamilyState family) =
          totalOracleFamilyState (fun oracle =>
            ((query oracle) (familyGameState family oracle)).ofLp) by
        funext target
        by_cases matched : ∃ oracle : Input → DigestRegister,
            target.database = totalDatabase oracle
        · obtain ⟨oracle, databaseEq⟩ := matched
          rcases target with ⟨registerInput, phaseValue, workspace, database⟩
          dsimp at databaseEq ⊢
          subst database
          simp [databaseResponseQuery, totalDatabase, query_apply,
            total_oracle_family_state_apply]
        · have rightZero :
              totalOracleFamilyState (fun oracle =>
                ((query oracle) (familyGameState family oracle)).ofLp)
                target = 0 :=
            total_oracle_family_state_eq_zero_of_no_match _ target matched
          rw [rightZero]
          unfold databaseResponseQuery
          split
          · exact total_oracle_family_state_eq_zero_of_no_match
              family target matched
          · apply total_oracle_family_state_eq_zero_of_no_match
            simpa using matched]
      rw [ih]
      apply congrArg uniformAverage
      funext oracle
      simp [databaseRun]
  | honestRead input next ih =>
      simp only [databaseRun, databaseReadBranch_totalOracleFamilyState]
      simp_rw [ih]
      rw [V8Smz9MeasuredRunContinuity.average_sum]
      apply Finset.sum_congr rfl
      intro answer _
      apply congrArg uniformAverage
      funext oracle
      by_cases selected : oracle input = answer
      · simp [familyGameState, databaseReadBranch_oracleState, selected]
      · simp [familyGameState, databaseReadBranch_oracleState, selected,
          databaseRun_zero]
  | instrument operation next ih =>
      simp only [databaseRun]
      have transform (outcome) :
          liftInstrumentBranch operation outcome
              (totalOracleFamilyState family) =
            totalOracleFamilyState
              (fun oracle =>
                (operation.branch outcome
                  (familyGameState family oracle)).ofLp) := by
        funext target
        by_cases matched : ∃ oracle : Input → DigestRegister,
            target.database = totalDatabase oracle
        · obtain ⟨oracle, databaseEq⟩ := matched
          rcases target with ⟨registerInput, phaseValue, workspace, database⟩
          dsimp at databaseEq ⊢
          subst database
          unfold liftInstrumentBranch
          rw [databaseSlice_totalOracleFamilyState, map_smul,
            total_oracle_family_state_apply]
          rfl
        · have sliceZero :
              databaseSlice (totalOracleFamilyState family)
                  target.database = 0 := by
            ext register
            apply total_oracle_family_state_eq_zero_of_no_match
            simpa using matched
          unfold liftInstrumentBranch
          rw [sliceZero, map_zero]
          symm
          apply total_oracle_family_state_eq_zero_of_no_match
          exact matched
      simp_rw [transform, ih]
      rw [V8Smz9MeasuredRunContinuity.average_sum]
      apply Finset.sum_congr rfl
      intro outcome _
      apply congrArg uniformAverage
      funext oracle
      rw [liftInstrumentBranch_oracleState]
  | random source next ih =>
      simp only [databaseRun]
      simp_rw [ih]
      exact V8Smz9CurrentPrivacyComposition.uniform_average_comm _
  | freshInput sampler next ih =>
      cases randomized with
      | false =>
          simp only [databaseRun, Bool.false_eq_true, if_false,
            databaseReadBranch_totalOracleFamilyState]
          simp_rw [ih]
          calc
            uniformAverage (fun coins : sampler.Coins =>
                ∑ old : DigestRegister,
                  uniformAverage (fun oracle : Input → DigestRegister =>
                    databaseRun false (next coins old)
                      (oracleState oracle
                        (WithLp.toLp 2
                          (if oracle (sampler.input coins) = old then
                            family oracle else 0))))) =
              uniformAverage (fun coins : sampler.Coins =>
                uniformAverage (fun oracle : Input → DigestRegister =>
                  ∑ old : DigestRegister,
                    databaseRun false (next coins old)
                      (oracleState oracle
                        (WithLp.toLp 2
                          (if oracle (sampler.input coins) = old then
                            family oracle else 0))))) := by
                apply congrArg uniformAverage
                funext coins
                exact (V8Smz9MeasuredRunContinuity.average_sum
                  (fun oracle : Input → DigestRegister =>
                    fun old : DigestRegister =>
                      databaseRun false (next coins old)
                        (oracleState oracle
                          (WithLp.toLp 2
                            (if oracle (sampler.input coins) = old then
                              family oracle else 0))))).symm
            _ = uniformAverage (fun oracle : Input → DigestRegister =>
                uniformAverage (fun coins : sampler.Coins =>
                  ∑ old : DigestRegister,
                    databaseRun false (next coins old)
                      (oracleState oracle
                        (WithLp.toLp 2
                          (if oracle (sampler.input coins) = old then
                            family oracle else 0))))) :=
              V8Smz9CurrentPrivacyComposition.uniform_average_comm _
            _ = uniformAverage (fun oracle : Input → DigestRegister =>
                uniformAverage (fun coins : sampler.Coins =>
                  databaseRun false
                    (next coins (oracle (sampler.input coins)))
                    (oracleState oracle
                      (familyGameState family oracle)))) := by
              apply congrArg uniformAverage
              funext oracle
              apply congrArg uniformAverage
              funext coins
              rw [Finset.sum_eq_single (oracle (sampler.input coins))]
              · simp
              · intro old _ different
                simp [Ne.symm different, databaseRun_zero]
              · simp
            _ = uniformAverage (fun oracle : Input → DigestRegister =>
                uniformAverage (fun coins : sampler.Coins =>
                  ∑ old : DigestRegister,
                    databaseRun false (next coins old)
                      (databaseReadBranch (sampler.input coins) old
                        (oracleState oracle
                          (familyGameState family oracle))))) := by
              apply congrArg uniformAverage
              funext oracle
              apply congrArg uniformAverage
              funext coins
              rw [Finset.sum_eq_single (oracle (sampler.input coins))]
              · rw [databaseReadBranch_oracleState, if_pos rfl]
              · intro old _ different
                rw [databaseReadBranch_oracleState,
                  if_neg (Ne.symm different), databaseRun_zero]
              · simp
      | true =>
          simp only [databaseRun, if_true,
            databaseReadBranch_totalOracleFamilyState,
            replaceReadBranch_totalOracleFamilyState]
          simp_rw [ih]
          calc
            _ = uniformAverage (fun coins : sampler.Coins =>
                uniformAverage (fun fresh : DigestRegister =>
                  ∑ old : DigestRegister,
                    uniformAverage (fun oracle : Input → DigestRegister =>
                      if oracle (sampler.input coins) = fresh then
                        databaseRun true (next coins fresh)
                          (oracleState oracle
                            (familyGameState family (Function.update oracle
                              (sampler.input coins) old)))
                      else 0))) := by
                apply congrArg uniformAverage
                funext coins
                apply congrArg uniformAverage
                funext fresh
                apply Finset.sum_congr rfl
                intro old _
                apply congrArg uniformAverage
                funext oracle
                by_cases selected : oracle (sampler.input coins) = fresh
                · simp [familyGameState, selected, Function.update_self]
                · simp [familyGameState, selected, databaseRun_zero]
            _ =
              uniformAverage (fun coins : sampler.Coins =>
                uniformAverage (fun oracle : Input → DigestRegister =>
                  uniformAverage (fun fresh : DigestRegister =>
                    databaseRun true (next coins fresh)
                      (oracleState
                        (Function.update oracle (sampler.input coins) fresh)
                        (familyGameState family oracle))))) := by
                apply congrArg uniformAverage
                funext coins
                simpa [Function.update_self, Function.update_idem] using
                  uniformAverage_update_partition
                    (sampler.input coins)
                    (fun old fresh oracle =>
                      databaseRun true (next coins fresh)
                        (oracleState oracle
                          (familyGameState family (Function.update oracle
                            (sampler.input coins) old))))
            _ = uniformAverage (fun oracle : Input → DigestRegister =>
                uniformAverage (fun coins : sampler.Coins =>
                  uniformAverage (fun fresh : DigestRegister =>
                    databaseRun true (next coins fresh)
                      (oracleState
                        (Function.update oracle (sampler.input coins) fresh)
                        (familyGameState family oracle))))) :=
              V8Smz9CurrentPrivacyComposition.uniform_average_comm _
            _ = uniformAverage (fun oracle : Input → DigestRegister =>
                uniformAverage (fun coins : sampler.Coins =>
                  uniformAverage (fun fresh : DigestRegister =>
                    ∑ old : DigestRegister,
                      databaseRun true (next coins fresh)
                        (replaceReadBranch (sampler.input coins) old fresh
                          (databaseReadBranch (sampler.input coins) old
                            (oracleState oracle
                              (familyGameState family oracle))))))) := by
              apply congrArg uniformAverage
              funext oracle
              apply congrArg uniformAverage
              funext coins
              apply congrArg uniformAverage
              funext fresh
              rw [Finset.sum_eq_single (oracle (sampler.input coins))]
              · rw [databaseReadBranch_oracleState, if_pos rfl,
                  replaceReadBranch_oracleState, if_pos rfl]
              · intro old _ different
                rw [databaseReadBranch_oracleState,
                  if_neg (Ne.symm different), replaceReadBranch_zero,
                  databaseRun_zero]
              · simp

/-- The existing whole-view acceptance is therefore exactly the uniform
average of the one-persistent-database executions above. -/
theorem acceptance_eq_databaseRun (randomized : Bool)
    (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.acceptance randomized program initial =
      uniformAverage (fun oracle : Input → DigestRegister =>
        databaseRun randomized program (oracleState oracle initial)) := by
  unfold V8Smz9HonestWholeViewGames.acceptance
  apply congrArg uniformAverage
  funext oracle
  exact (databaseRun_oracleState randomized program oracle initial).symm

/-- Constant-family corollary: the initialized coherent purification has
exactly the existing whole-view acceptance probability. -/
theorem databaseRun_initialized_family_eq_acceptance
    (randomized : Bool) (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    databaseRun randomized program
        (totalOracleFamilyState
          (fun _oracle : Input → DigestRegister => initial)) =
      V8Smz9HonestWholeViewGames.acceptance randomized program initial := by
  rw [databaseRun_totalOracleFamilyState]
  exact (acceptance_eq_databaseRun randomized program initial).symm

/-! The compressed interpreter is the exact conjugate of the preceding
standard-database interpreter at every state-transforming constructor. -/

def compressedGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  globalDecompress (liftGate operation (globalDecompress state))

def compressedInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  globalDecompress
    (liftInstrumentBranch operation outcome (globalDecompress state))

def compressedResponseQuery (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  globalDecompress (databaseResponseQuery (globalDecompress state))

/-- Response-basis presentation of one implemented CMS query.  The outer
decompression changes the ordinary database coordinates back to compressed
coordinates; the two response DFTs change only the adversary digest register.
-/
def fourierResponseCompressedQuery (queryBound : Nat)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  globalDecompress
    (responseFourierState
      (databaseResponseQuery
        (responseFourierInverseState (globalDecompress state))))

/-- After full CMS decompression, a strict reachable compressed query is the
ordinary response-translation query conjugated by the finite digest DFT. -/
theorem global_decompress_cms_query_eq_fourier_response
    (queryBound : Nat) (state : ResponseCmsState Input Work)
    (strict : StrictSupport queryBound state) :
    globalDecompress
        (queryState digestPhaseSystem queryBound state) =
      responseFourierState
        (databaseResponseQuery
          (responseFourierInverseState (globalDecompress state))) := by
  calc
    globalDecompress
        (queryState digestPhaseSystem queryBound state) =
      phaseQueryState digestPhaseSystem (globalDecompress state) :=
        global_decompress_query_state_eq_phase
          digestPhaseSystem queryBound state strict
    _ = phaseQueryState digestPhaseSystem
          (responseFourierState
            (responseFourierInverseState (globalDecompress state))) := by
      rw [response_fourier_inverse_right]
    _ = responseFourierState
          (databaseResponseQuery
            (responseFourierInverseState (globalDecompress state))) :=
      (response_fourier_database_response_query
        (responseFourierInverseState (globalDecompress state))).symm

/-- Consequently the response-basis construction is not a surrogate query:
on the exact strict-support domain it is definitionally the implemented CMS
kernel, with one query and the unchanged query cap. -/
theorem fourier_response_compressed_query_eq_queryState
    (queryBound : Nat) (state : ResponseCmsState Input Work)
    (strict : StrictSupport queryBound state) :
    fourierResponseCompressedQuery queryBound state =
      queryState digestPhaseSystem queryBound state := by
  unfold fourierResponseCompressedQuery
  rw [← global_decompress_cms_query_eq_fourier_response
    queryBound state strict]
  exact global_decompress_involutive _

def compressedReplaceReadBranch (input : Input)
    (old fresh : DigestRegister) (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  globalDecompress
    (replaceReadBranch input old fresh
      (coordinateEventProjection input old (globalDecompress state)))

@[simp]
theorem global_decompress_compressedGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    globalDecompress (compressedGate operation state) =
      liftGate operation (globalDecompress state) := by
  exact global_decompress_involutive _

@[simp]
theorem global_decompress_compressedInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) :
    globalDecompress (compressedInstrumentBranch operation outcome state) =
      liftInstrumentBranch operation outcome (globalDecompress state) := by
  exact global_decompress_involutive _

@[simp]
theorem global_decompress_compressedResponseQuery
    (state : ResponseCmsState Input Work) :
    globalDecompress (compressedResponseQuery state) =
      databaseResponseQuery (globalDecompress state) := by
  exact global_decompress_involutive _

@[simp]
theorem global_decompress_compressedReplaceReadBranch
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    globalDecompress (compressedReplaceReadBranch input old fresh state) =
      replaceReadBranch input old fresh
        (coordinateEventProjection input old (globalDecompress state)) := by
  exact global_decompress_involutive _

/-! ## Global response/phase representation invariant

The whole-view game stores an additive response register, whereas the CMS
kernel consumes its Fourier-dual phase register.  A complete CMS execution
must therefore maintain `D · F · standard`, not merely `D · standard`.
The following encode/decode pair makes that invariant explicit for every
constructor. -/

/-- Encode a standard-database response-register state as a compressed CMS
phase-register state. -/
def phaseEncode (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  globalDecompress (responseFourierState state)

/-- Decode a compressed CMS phase-register state back to the standard
response-register presentation used by `Program`. -/
def phaseDecode (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  responseFourierInverseState (globalDecompress state)

@[simp]
theorem phase_decode_encode (state : ResponseCmsState Input Work) :
    phaseDecode (phaseEncode state) = state := by
  unfold phaseDecode phaseEncode
  rw [global_decompress_involutive, response_fourier_inverse_left]

@[simp]
theorem phase_encode_decode (state : ResponseCmsState Input Work) :
    phaseEncode (phaseDecode state) = state := by
  unfold phaseDecode phaseEncode
  rw [response_fourier_inverse_right, global_decompress_involutive]

/-- Exact phase-basis conjugation of a database-blind game gate. -/
def phaseGate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  phaseEncode (liftGate operation (phaseDecode state))

/-- Exact phase-basis conjugation of one complete-instrument branch. -/
def phaseInstrumentBranch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  phaseEncode
    (liftInstrumentBranch operation outcome (phaseDecode state))

/-- Exact phase-basis conjugation of the ordinary additive oracle response.
This is the operator already identified with the implemented CMS kernel. -/
def phaseResponseQuery (state : ResponseCmsState Input Work) :
    ResponseCmsState Input Work :=
  phaseEncode (databaseResponseQuery (phaseDecode state))

/-- Exact phase-basis branch of one public classical read. -/
def phaseReadBranch (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  phaseEncode (databaseReadBranch input answer (phaseDecode state))

/-- Exact phase-basis branch of an adaptive fresh-input replacement.  The
overwritten answer is retained in the explicit outer `old` branch. -/
def phaseReplaceReadBranch (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) : ResponseCmsState Input Work :=
  phaseEncode
    (replaceReadBranch input old fresh
      (databaseReadBranch input old (phaseDecode state)))

@[simp]
theorem phase_decode_gate
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    phaseDecode (phaseGate operation state) =
      liftGate operation (phaseDecode state) := by
  simp [phaseGate]

theorem phase_gate_eq_local
    (operation : GameGate (Input := Input) (Work := Work))
    (state : ResponseCmsState Input Work) :
    phaseGate operation state =
      responseFourierState
        (liftGate operation (responseFourierInverseState state)) := by
  unfold phaseGate phaseEncode phaseDecode
  rw [global_decompress_response_fourier_state,
    global_decompress_liftGate,
    global_decompress_response_fourier_inverse_state,
    global_decompress_involutive]

theorem phase_gate_bounded
    (operation : GameGate (Input := Input) (Work := Work))
    {bound : Nat} {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (phaseGate operation state) := by
  rw [phase_gate_eq_local]
  exact response_fourier_state_bounded
    (liftGate_bounded operation
      (response_fourier_inverse_state_bounded bounded))

@[simp]
theorem phase_decode_instrument_branch {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) :
    phaseDecode (phaseInstrumentBranch operation outcome state) =
      liftInstrumentBranch operation outcome (phaseDecode state) := by
  simp [phaseInstrumentBranch]

theorem phase_instrument_branch_eq_local {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    (state : ResponseCmsState Input Work) :
    phaseInstrumentBranch operation outcome state =
      responseFourierState
        (liftInstrumentBranch operation outcome
          (responseFourierInverseState state)) := by
  unfold phaseInstrumentBranch phaseEncode phaseDecode
  rw [global_decompress_response_fourier_state,
    global_decompress_liftInstrumentBranch,
    global_decompress_response_fourier_inverse_state,
    global_decompress_involutive]

theorem phase_instrument_branch_bounded {count : Nat}
    (operation : Instrument Input Work count) (outcome : Fin count)
    {bound : Nat} {state : ResponseCmsState Input Work}
    (bounded : BoundedState bound state) :
    BoundedState bound
      (phaseInstrumentBranch operation outcome state) := by
  rw [phase_instrument_branch_eq_local]
  exact response_fourier_state_bounded
    (liftInstrumentBranch_bounded operation outcome
      (response_fourier_inverse_state_bounded bounded))

@[simp]
theorem phase_decode_response_query (state : ResponseCmsState Input Work) :
    phaseDecode (phaseResponseQuery state) =
      databaseResponseQuery (phaseDecode state) := by
  simp [phaseResponseQuery]

@[simp]
theorem phase_decode_read_branch
    (input : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    phaseDecode (phaseReadBranch input answer state) =
      databaseReadBranch input answer (phaseDecode state) := by
  simp [phaseReadBranch]

@[simp]
theorem phase_decode_replace_read_branch
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    phaseDecode (phaseReplaceReadBranch input old fresh state) =
      replaceReadBranch input old fresh
        (databaseReadBranch input old (phaseDecode state)) := by
  simp [phaseReplaceReadBranch]

theorem phase_replace_read_branch_eq_compressed
    (input : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    phaseReplaceReadBranch input old fresh state =
      compressedReplaceReadBranch input old fresh state := by
  unfold phaseReplaceReadBranch phaseEncode phaseDecode
  unfold databaseReadBranch compressedReplaceReadBranch
  rw [response_fourier_replace_read_branch,
    response_fourier_coordinate_projection,
    response_fourier_inverse_right]

theorem phase_response_query_eq_fourier
    (queryBound : Nat) (state : ResponseCmsState Input Work) :
    phaseResponseQuery state =
      fourierResponseCompressedQuery queryBound state := by
  rfl

/-- The phase-basis query is exactly the implemented CMS query on the strict
reachable support; no response-basis surrogate remains. -/
theorem phase_response_query_eq_queryState
    (queryBound : Nat) (state : ResponseCmsState Input Work)
    (strict : StrictSupport queryBound state) :
    phaseResponseQuery state =
      queryState digestPhaseSystem queryBound state := by
  rw [phase_response_query_eq_fourier]
  exact fourier_response_compressed_query_eq_queryState
    queryBound state strict

/-- One actual phase-basis query consumes exactly one support slot. -/
theorem phase_response_query_bounded_succ
    (queryBound bound : Nat) (state : ResponseCmsState Input Work)
    (belowCap : bound < queryBound) (bounded : BoundedState bound state) :
    BoundedState (bound + 1) (phaseResponseQuery state) := by
  rw [phase_response_query_eq_queryState queryBound state
    (bounded_state_strict_support bounded belowCap)]
  exact query_state_bounded_succ_of_bounded
    digestPhaseSystem queryBound bound state belowCap bounded

/-! Classical read branches are also coordinate-local in the compressed
database.  The next lemmas cancel every decompression away from the selected
input and then prove the exact one-slot support increase on the remaining
fiber. -/

theorem coordinate_projection_decompress_at_of_ne
    (selected : Input) (answer : DigestRegister) (changed : Input)
    (state : ResponseCmsState Input Work) (different : selected ≠ changed) :
    coordinateEventProjection selected answer (decompressAt changed state) =
      decompressAt changed
        (coordinateEventProjection selected answer state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold coordinateEventProjection
  by_cases accepted : target.database selected = some answer
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceAccepted :
        setDatabaseCoordinate target.database changed source selected =
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_pos sourceAccepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceRejected :
        setDatabaseCoordinate target.database changed source selected ≠
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_neg sourceRejected]
    simp

theorem coordinate_projection_decompress_list_of_outside
    (selected : Input) (answer : DigestRegister) (inputs : List Input)
    (state : ResponseCmsState Input Work)
    (outside : ∀ changed ∈ inputs, selected ≠ changed) :
    coordinateEventProjection selected answer (decompressList inputs state) =
      decompressList inputs
        (coordinateEventProjection selected answer state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : selected ≠ changed :=
        outside changed (by simp)
      have remainingOutside :
          ∀ input ∈ remaining, selected ≠ input := by
        intro input member
        exact outside input (by simp [member])
      simp only [decompress_list_cons]
      rw [coordinate_projection_decompress_at_of_ne
        selected answer changed _ changedOutside]
      rw [ih remainingOutside]

theorem coordinate_projection_decompress_except
    (selected : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    coordinateEventProjection selected answer
        (decompressExcept selected state) =
      decompressExcept selected
        (coordinateEventProjection selected answer state) := by
  unfold decompressExcept
  apply coordinate_projection_decompress_list_of_outside
  intro changed member
  have erased : changed ∈ (Finset.univ : Finset Input).erase selected := by
    simpa using member
  exact fun same => (Finset.mem_erase.mp erased).1 same.symm

theorem replace_read_branch_decompress_at_of_ne
    (selected : Input) (old fresh : DigestRegister) (changed : Input)
    (state : ResponseCmsState Input Work) (different : selected ≠ changed) :
    replaceReadBranch selected old fresh (decompressAt changed state) =
      decompressAt changed (replaceReadBranch selected old fresh state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold replaceReadBranch
  by_cases accepted : target.database selected = some fresh
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceAccepted :
        setDatabaseCoordinate target.database changed source selected =
          some fresh := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_pos sourceAccepted]
    have changedCoordinate :
        setDatabaseCoordinate target.database selected (some old) changed =
          target.database changed := by
      rw [set_database_coordinate_other target.database
        (Ne.symm different) (some old)]
    change
      state
          { target with database :=
              (setDatabaseCoordinate
                (setDatabaseCoordinate target.database selected (some old))
                changed source) } *
          decompressKernel source
            (setDatabaseCoordinate target.database selected (some old) changed) =
        state
          { target with database :=
              (setDatabaseCoordinate
                (setDatabaseCoordinate target.database changed source)
                selected (some old)) } *
          decompressKernel source (target.database changed)
    rw [changedCoordinate]
    congr 2
    exact congrArg (fun database => { target with database := database })
      (set_database_coordinate_commutes target.database selected changed
        different (some old) source)
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceRejected :
        setDatabaseCoordinate target.database changed source selected ≠
          some fresh := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_neg sourceRejected]
    simp

theorem replace_read_branch_decompress_list_of_outside
    (selected : Input) (old fresh : DigestRegister) (inputs : List Input)
    (state : ResponseCmsState Input Work)
    (outside : ∀ changed ∈ inputs, selected ≠ changed) :
    replaceReadBranch selected old fresh (decompressList inputs state) =
      decompressList inputs (replaceReadBranch selected old fresh state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : selected ≠ changed :=
        outside changed (by simp)
      have remainingOutside :
          ∀ input ∈ remaining, selected ≠ input := by
        intro input member
        exact outside input (by simp [member])
      simp only [decompress_list_cons]
      rw [replace_read_branch_decompress_at_of_ne
        selected old fresh changed _ changedOutside]
      rw [ih remainingOutside]

theorem replace_read_branch_decompress_except
    (selected : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    replaceReadBranch selected old fresh (decompressExcept selected state) =
      decompressExcept selected
        (replaceReadBranch selected old fresh state) := by
  unfold decompressExcept
  apply replace_read_branch_decompress_list_of_outside
  intro changed member
  have erased : changed ∈ (Finset.univ : Finset Input).erase selected := by
    simpa using member
  exact fun same => (Finset.mem_erase.mp erased).1 same.symm

/-- The global measured read is exactly a one-coordinate CMS operation; all
other coordinate reflections cancel rather than consuming support. -/
theorem measuredReadBranch_eq_selected
    (selected : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    measuredReadBranch selected answer state =
      decompressAt selected
        (coordinateEventProjection selected answer
          (decompressAt selected state)) := by
  unfold measuredReadBranch
  rw [global_decompress_eq_selected_last,
    global_decompress_eq_selected_last]
  rw [coordinate_projection_decompress_except]
  unfold decompressExcept
  rw [decompress_at_decompress_list_commutes]
  rw [decompress_list_involutive]

/-- As with a measured read, full decompression around a retained-old-value
replacement cancels away from the selected coordinate. -/
theorem compressedReplaceReadBranch_eq_selected
    (selected : Input) (old fresh : DigestRegister)
    (state : ResponseCmsState Input Work) :
    compressedReplaceReadBranch selected old fresh state =
      decompressAt selected
        (replaceReadBranch selected old fresh
          (coordinateEventProjection selected old
            (decompressAt selected state))) := by
  unfold compressedReplaceReadBranch
  rw [global_decompress_eq_selected_last,
    global_decompress_eq_selected_last]
  rw [coordinate_projection_decompress_except]
  rw [replace_read_branch_decompress_except]
  unfold decompressExcept
  rw [decompress_at_decompress_list_commutes]
  rw [decompress_list_involutive]

theorem selected_measured_branch_bounded_succ
    (selected : Input) (answer : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (decompressAt selected
        (coordinateEventProjection selected answer
          (decompressAt selected state))) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound + 1
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound + 1 < size target.database :=
      Nat.lt_of_not_ge within
    let coordinate :=
      databaseEquiv (Output := DigestRegister) selected target.database
    have databaseEq :
        (databaseEquiv (Output := DigestRegister) selected).symm coordinate =
          target.database := by
      exact Equiv.symm_apply_apply
        (databaseEquiv (Output := DigestRegister) selected) target.database
    rcases coordinate with ⟨base, targetCoordinate⟩
    have baseAbove : bound < size base.1 := by
      cases targetCoordinate with
      | none =>
          rw [databaseEquiv_symm_none] at databaseEq
          have sizeEq := congrArg size databaseEq
          omega
      | some output =>
          rw [databaseEquiv_symm_some] at databaseEq
          have sizeEq := congrArg size databaseEq
          have insertedSize :=
            size_insert_of_absent base.1 selected output base.2
          omega
    have sourceFiberZero :
        databaseFiberState state target.input target.phase target.workspace
            selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      apply bounded_state_apply_eq_zero_of_lt bounded
      cases source with
      | none =>
          rw [databaseEquiv_symm_none]
          exact baseAbove
      | some output =>
          rw [databaseEquiv_symm_some,
            size_insert_of_absent base.1 selected output base.2]
          omega
    have decompressedFiberZero :
        databaseFiberState (decompressAt selected state)
            target.input target.phase target.workspace selected base = 0 := by
      rw [database_fiber_state_decompress_at, sourceFiberZero]
      simp
    have projectedFiberZero :
        databaseFiberState
            (coordinateEventProjection selected answer
              (decompressAt selected state))
            target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      by_cases recorded :
          ((databaseEquiv (Output := DigestRegister) selected).symm
            (base, source)) selected = some answer
      · simp only [coordinateEventProjection, recorded, if_true]
        simpa only [database_fiber_state_apply] using
          congrArg (fun fiber => fiber source) decompressedFiberZero
      · simp [coordinateEventProjection, recorded]
    have targetEq :
        ({ input := target.input
           phase := target.phase
           workspace := target.workspace
           database :=
             (databaseEquiv (Output := DigestRegister) selected).symm
               (base, targetCoordinate) } :
          HegemonCrypto.CmsCompressedOracle.Basis
            Input DigestRegister DigestRegister Work) = target := by
      cases target
      simp_all
    have targetZero :
        decompressAt selected
            (coordinateEventProjection selected answer
              (decompressAt selected state)) target = 0 := by
      rw [← targetEq, decompress_at_apply_coordinate, projectedFiberZero]
      simp
    simp [HegemonCrypto.CmsCompressedOracle.project, within, targetZero]

theorem selected_replace_branch_bounded_succ
    (selected : Input) (old fresh : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (decompressAt selected
        (replaceReadBranch selected old fresh
          (coordinateEventProjection selected old
            (decompressAt selected state)))) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound + 1
  · simp [HegemonCrypto.CmsCompressedOracle.project, within]
  · have above : bound + 1 < size target.database :=
      Nat.lt_of_not_ge within
    let coordinate :=
      databaseEquiv (Output := DigestRegister) selected target.database
    have databaseEq :
        (databaseEquiv (Output := DigestRegister) selected).symm coordinate =
          target.database := by
      exact Equiv.symm_apply_apply
        (databaseEquiv (Output := DigestRegister) selected) target.database
    rcases coordinate with ⟨base, targetCoordinate⟩
    have baseAbove : bound < size base.1 := by
      cases targetCoordinate with
      | none =>
          rw [databaseEquiv_symm_none] at databaseEq
          have sizeEq := congrArg size databaseEq
          omega
      | some output =>
          rw [databaseEquiv_symm_some] at databaseEq
          have sizeEq := congrArg size databaseEq
          have insertedSize :=
            size_insert_of_absent base.1 selected output base.2
          omega
    have sourceFiberZero :
        databaseFiberState state target.input target.phase target.workspace
            selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      apply bounded_state_apply_eq_zero_of_lt bounded
      cases source with
      | none =>
          rw [databaseEquiv_symm_none]
          exact baseAbove
      | some output =>
          rw [databaseEquiv_symm_some,
            size_insert_of_absent base.1 selected output base.2]
          omega
    have decompressedFiberZero :
        databaseFiberState (decompressAt selected state)
            target.input target.phase target.workspace selected base = 0 := by
      rw [database_fiber_state_decompress_at, sourceFiberZero]
      simp
    have projectedFiberZero :
        databaseFiberState
            (coordinateEventProjection selected old
              (decompressAt selected state))
            target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      by_cases recorded :
          ((databaseEquiv (Output := DigestRegister) selected).symm
            (base, source)) selected = some old
      · simp only [coordinateEventProjection, recorded, if_true]
        simpa only [database_fiber_state_apply] using
          congrArg (fun fiber => fiber source) decompressedFiberZero
      · simp [coordinateEventProjection, recorded]
    have replacedFiberZero :
        databaseFiberState
            (replaceReadBranch selected old fresh
              (coordinateEventProjection selected old
                (decompressAt selected state)))
            target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      let sourceDatabase :=
        (databaseEquiv (Output := DigestRegister) selected).symm
          (base, source)
      by_cases selectedFresh : sourceDatabase selected = some fresh
      · rw [show
          replaceReadBranch selected old fresh
              (coordinateEventProjection selected old
                (decompressAt selected state))
              { input := target.input
                phase := target.phase
                workspace := target.workspace
                database := sourceDatabase } =
            coordinateEventProjection selected old
                (decompressAt selected state)
              { input := target.input
                phase := target.phase
                workspace := target.workspace
                database :=
                  setDatabaseCoordinate sourceDatabase selected (some old) } by
            simp [replaceReadBranch, selectedFresh]]
        have sourceBase :
            (databaseEquiv (Output := DigestRegister) selected sourceDatabase).1 =
              base := by
          have applied := Equiv.apply_symm_apply
            (databaseEquiv (Output := DigestRegister) selected) (base, source)
          exact congrArg Prod.fst applied
        have replacedDatabase :
            setDatabaseCoordinate sourceDatabase selected (some old) =
              (databaseEquiv (Output := DigestRegister) selected).symm
                (base, some old) := by
          rw [← database_equiv_symm_fiber_eq_set_coordinate]
          rw [sourceBase]
        rw [replacedDatabase]
        change
          coordinateEventProjection selected old (decompressAt selected state)
              { input := target.input
                phase := target.phase
                workspace := target.workspace
                database :=
                  (databaseEquiv (Output := DigestRegister) selected).symm
                    (base, some old) } = 0
        simpa only [database_fiber_state_apply, PiLp.zero_apply] using
          congrArg (fun fiber => fiber (some old)) projectedFiberZero
      · simp [replaceReadBranch, sourceDatabase, selectedFresh]
    have targetEq :
        ({ input := target.input
           phase := target.phase
           workspace := target.workspace
           database :=
             (databaseEquiv (Output := DigestRegister) selected).symm
               (base, targetCoordinate) } :
          HegemonCrypto.CmsCompressedOracle.Basis
            Input DigestRegister DigestRegister Work) = target := by
      cases target
      simp_all
    have targetZero :
        decompressAt selected
            (replaceReadBranch selected old fresh
              (coordinateEventProjection selected old
                (decompressAt selected state))) target = 0 := by
      rw [← targetEq, decompress_at_apply_coordinate, replacedFiberZero]
      simp
    simp [HegemonCrypto.CmsCompressedOracle.project, within, targetZero]

theorem measured_read_branch_bounded_succ
    (selected : Input) (answer : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (measuredReadBranch selected answer state) := by
  rw [measuredReadBranch_eq_selected]
  exact selected_measured_branch_bounded_succ
    selected answer bound state bounded

theorem compressed_replace_read_branch_bounded_succ
    (selected : Input) (old fresh : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (compressedReplaceReadBranch selected old fresh state) := by
  rw [compressedReplaceReadBranch_eq_selected]
  exact selected_replace_branch_bounded_succ
    selected old fresh bound state bounded

theorem phase_read_branch_eq_measured
    (selected : Input) (answer : DigestRegister)
    (state : ResponseCmsState Input Work) :
    phaseReadBranch selected answer state =
      measuredReadBranch selected answer state := by
  unfold phaseReadBranch phaseEncode phaseDecode databaseReadBranch
  rw [response_fourier_coordinate_projection,
    response_fourier_inverse_right]
  rfl

theorem phase_read_branch_bounded_succ
    (selected : Input) (answer : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (phaseReadBranch selected answer state) := by
  rw [phase_read_branch_eq_measured]
  exact measured_read_branch_bounded_succ
    selected answer bound state bounded

theorem phase_replace_read_branch_bounded_succ
    (selected : Input) (old fresh : DigestRegister)
    (bound : Nat) (state : ResponseCmsState Input Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (phaseReplaceReadBranch selected old fresh state) := by
  rw [phase_replace_read_branch_eq_compressed]
  exact compressed_replace_read_branch_bounded_succ
    selected old fresh bound state bounded

/-- Constructor-for-constructor phase-basis execution.  Unlike
`compressedRun`, its representation invariant matches the implemented CMS
phase kernel at every quantum-query constructor. -/
def phaseRun (randomized : Bool) :
    Program Input Work → ResponseCmsState Input Work → ℝ
  | .finish event, state => databaseBorn event (phaseDecode state)
  | .gate operation next, state =>
      phaseRun randomized next (phaseGate operation state)
  | .quantumQuery next, state =>
      phaseRun randomized next (phaseResponseQuery state)
  | .honestRead input next, state =>
      ∑ answer : DigestRegister,
        phaseRun randomized (next answer)
          (phaseReadBranch input answer state)
  | .instrument operation next, state =>
      ∑ outcome,
        phaseRun randomized (next outcome)
          (phaseInstrumentBranch operation outcome state)
  | .random source next, state =>
      uniformAverage fun coins : source.Coins =>
        phaseRun randomized (next coins) state
  | .freshInput sampler next, state =>
      uniformAverage fun coins : sampler.Coins =>
        let input := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            ∑ old : DigestRegister,
              phaseRun randomized (next coins fresh)
                (phaseReplaceReadBranch input old fresh state)
        else
          ∑ old : DigestRegister,
            phaseRun randomized (next coins old)
              (phaseReadBranch input old state)

/-- Exact semantic adequacy of the global phase invariant for all seven
constructors.  This equality precedes (and is independent of) support
accounting. -/
theorem phase_run_eq_database_run (randomized : Bool)
    (program : Program Input Work) (state : ResponseCmsState Input Work) :
    phaseRun randomized program state =
      databaseRun randomized program (phaseDecode state) := by
  induction program generalizing state with
  | finish event => rfl
  | gate operation next ih =>
      simp only [phaseRun, databaseRun, ih, phase_decode_gate]
  | quantumQuery next ih =>
      simp only [phaseRun, databaseRun, ih, phase_decode_response_query]
  | honestRead input next ih =>
      simp only [phaseRun, databaseRun]
      apply Finset.sum_congr rfl
      intro answer _
      rw [ih answer, phase_decode_read_branch]
  | instrument operation next ih =>
      simp only [phaseRun, databaseRun]
      apply Finset.sum_congr rfl
      intro outcome _
      rw [ih outcome, phase_decode_instrument_branch]
  | random source next ih =>
      simp only [phaseRun, databaseRun]
      apply congrArg uniformAverage
      funext coins
      exact ih coins state
  | freshInput sampler next ih =>
      simp only [phaseRun, databaseRun]
      apply congrArg uniformAverage
      funext coins
      split
      · apply congrArg uniformAverage
        funext fresh
        apply Finset.sum_congr rfl
        intro old _
        rw [ih coins fresh, phase_decode_replace_read_branch]
      · apply Finset.sum_congr rfl
        intro old _
        rw [ih coins old, phase_decode_read_branch]

/-- The named-oracle phase game uses the exact same public distribution as
the existing whole-view acceptance experiment. -/
def phaseAcceptance (randomized : Bool) (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun oracle : Input → DigestRegister =>
    phaseRun randomized program
      (phaseEncode (oracleState oracle initial))

theorem phase_acceptance_eq (randomized : Bool)
    (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    phaseAcceptance randomized program initial =
      V8Smz9HonestWholeViewGames.acceptance randomized program initial := by
  rw [acceptance_eq_databaseRun]
  unfold phaseAcceptance
  apply congrArg uniformAverage
  funext oracle
  rw [phase_run_eq_database_run, phase_decode_encode]

/-- Direct GHHM adaptive bound for the exact seven-constructor phase game.
The only external mathematical premise remains the existing published GHHM
theorem; no semantic-distance or execution-bound premise is introduced. -/
theorem phase_adaptive_leaf_game_bound
    (ghhm : ExternalAdaptiveReprogramming (Input := Input) (Work := Work))
    (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work))
    (queries leaves : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : queryCount program ≤ queries)
    (leafBound : programmingCount program ≤ leaves)
    (massBound : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ program) :
    |phaseAcceptance true program initial -
        phaseAcceptance false program initial| ≤
      (leaves : ℝ) *
        (Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
          (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) := by
  rw [phase_acceptance_eq, phase_acceptance_eq]
  exact measured_adaptive_leaf_game_bound ghhm program initial
    queries leaves normalized queryBound leafBound massBound

/-- Every branch of the phase-basis execution carries its exact CMS support
counter.  At quantum queries the predicate additionally records equality with
the implemented capped CMS kernel.  Honest reads and fresh replacements each
consume the one slot already charged by `Program.queryCount`; gates,
instruments, and local randomness consume none. -/
def PhaseSupport (queryBound : Nat) :
    (spent : Nat) → Program Input Work → ResponseCmsState Input Work → Prop
  | spent, .finish _, state => BoundedState spent state
  | spent, .gate operation next, state =>
      BoundedState spent state ∧
        PhaseSupport queryBound spent next (phaseGate operation state)
  | spent, .quantumQuery next, state =>
      BoundedState spent state ∧
        phaseResponseQuery state =
          queryState digestPhaseSystem queryBound state ∧
        PhaseSupport queryBound (spent + 1) next
          (phaseResponseQuery state)
  | spent, .honestRead input next, state =>
      BoundedState spent state ∧
        ∀ answer, PhaseSupport queryBound (spent + 1) (next answer)
          (phaseReadBranch input answer state)
  | spent, .instrument operation next, state =>
      BoundedState spent state ∧
        ∀ outcome, PhaseSupport queryBound spent (next outcome)
          (phaseInstrumentBranch operation outcome state)
  | spent, .random source next, state =>
      BoundedState spent state ∧
        ∀ coins : source.Coins,
          PhaseSupport queryBound spent (next coins) state
  | spent, .freshInput sampler next, state =>
      BoundedState spent state ∧
        (∀ coins : sampler.Coins, ∀ fresh old : DigestRegister,
          PhaseSupport queryBound (spent + 1) (next coins fresh)
            (phaseReplaceReadBranch (sampler.input coins) old fresh state)) ∧
        (∀ coins : sampler.Coins, ∀ old : DigestRegister,
          PhaseSupport queryBound (spent + 1) (next coins old)
            (phaseReadBranch (sampler.input coins) old state))

/-- The existing syntactic query counter discharges the complete adaptive CMS
support invariant.  No separate execution-bound premise is accepted. -/
theorem phase_support_of_queryCount
    (queryBound spent : Nat) (program : Program Input Work)
    (state : ResponseCmsState Input Work)
    (capacity : spent + queryCount program ≤ queryBound)
    (bounded : BoundedState spent state) :
    PhaseSupport queryBound spent program state := by
  induction program generalizing spent state with
  | finish event =>
      exact bounded
  | gate operation next ih =>
      constructor
      · exact bounded
      · exact ih spent (phaseGate operation state) capacity
          (phase_gate_bounded operation bounded)
  | quantumQuery next ih =>
      have belowCap : spent < queryBound := by
        simp only [queryCount] at capacity
        omega
      refine ⟨bounded,
        phase_response_query_eq_queryState queryBound state
          (bounded_state_strict_support bounded belowCap), ?_⟩
      apply ih (spent + 1) (phaseResponseQuery state)
      · simp only [queryCount] at capacity
        omega
      · exact phase_response_query_bounded_succ
          queryBound spent state belowCap bounded
  | honestRead input next ih =>
      constructor
      · exact bounded
      · intro answer
        apply ih answer (spent + 1) (phaseReadBranch input answer state)
        · simp only [queryCount] at capacity
          have branchLe : queryCount (next answer) ≤
              Finset.univ.sup fun output => queryCount (next output) :=
            Finset.le_sup
              (f := fun output : DigestRegister => queryCount (next output))
              (Finset.mem_univ answer)
          omega
        · exact phase_read_branch_bounded_succ
            input answer spent state bounded
  | instrument operation next ih =>
      constructor
      · exact bounded
      · intro outcome
        apply ih outcome spent
          (phaseInstrumentBranch operation outcome state)
        · simp only [queryCount] at capacity
          exact (Nat.add_le_add_left
            (Finset.le_sup
              (f := fun branch => queryCount (next branch))
              (Finset.mem_univ outcome)) spent).trans capacity
        · exact phase_instrument_branch_bounded operation outcome bounded
  | random source next ih =>
      constructor
      · exact bounded
      · intro coins
        apply ih coins spent state
        · simp only [queryCount] at capacity
          exact (Nat.add_le_add_left
            (Finset.le_sup
              (f := fun coin => queryCount (next coin))
              (Finset.mem_univ coins)) spent).trans capacity
        · exact bounded
  | freshInput sampler next ih =>
      refine ⟨bounded, ?_, ?_⟩
      · intro coins fresh old
        apply ih coins fresh (spent + 1)
          (phaseReplaceReadBranch (sampler.input coins) old fresh state)
        · simp only [queryCount] at capacity
          have outputLe : queryCount (next coins fresh) ≤
              Finset.univ.sup fun output => queryCount (next coins output) :=
            Finset.le_sup
              (f := fun output : DigestRegister => queryCount (next coins output))
              (Finset.mem_univ fresh)
          have coinLe :
              (Finset.univ.sup fun output => queryCount (next coins output)) ≤
                Finset.univ.sup fun coin =>
                  Finset.univ.sup fun output => queryCount (next coin output) :=
            Finset.le_sup
              (f := fun coin : sampler.Coins =>
                Finset.univ.sup fun output => queryCount (next coin output))
              (Finset.mem_univ coins)
          omega
        · exact phase_replace_read_branch_bounded_succ
            (sampler.input coins) old fresh spent state bounded
      · intro coins old
        apply ih coins old (spent + 1)
          (phaseReadBranch (sampler.input coins) old state)
        · simp only [queryCount] at capacity
          have outputLe : queryCount (next coins old) ≤
              Finset.univ.sup fun output => queryCount (next coins output) :=
            Finset.le_sup
              (f := fun output : DigestRegister => queryCount (next coins output))
              (Finset.mem_univ old)
          have coinLe :
              (Finset.univ.sup fun output => queryCount (next coins output)) ≤
                Finset.univ.sup fun coin =>
                  Finset.univ.sup fun output => queryCount (next coin output) :=
            Finset.le_sup
              (f := fun coin : sampler.Coins =>
                Finset.univ.sup fun output => queryCount (next coin output))
              (Finset.mem_univ coins)
          omega
        · exact phase_read_branch_bounded_succ
            (sampler.input coins) old spent state bounded

/-- Zero-initialized specialization used by the concrete whole-view game. -/
theorem phase_support_from_zero
    (queryBound : Nat) (program : Program Input Work)
    (state : ResponseCmsState Input Work)
    (capacity : queryCount program ≤ queryBound)
    (bounded : BoundedState 0 state) :
    PhaseSupport queryBound 0 program state := by
  exact phase_support_of_queryCount queryBound 0 program state
    (by simpa using capacity) bounded

/-- Same seven-constructor interpreter, now executing the implemented capped
CMS kernel literally at each quantum-query node. -/
def actualPhaseRun (queryBound : Nat) (randomized : Bool) :
    Program Input Work → ResponseCmsState Input Work → ℝ
  | .finish event, state => databaseBorn event (phaseDecode state)
  | .gate operation next, state =>
      actualPhaseRun queryBound randomized next (phaseGate operation state)
  | .quantumQuery next, state =>
      actualPhaseRun queryBound randomized next
        (queryState digestPhaseSystem queryBound state)
  | .honestRead input next, state =>
      ∑ answer : DigestRegister,
        actualPhaseRun queryBound randomized (next answer)
          (phaseReadBranch input answer state)
  | .instrument operation next, state =>
      ∑ outcome,
        actualPhaseRun queryBound randomized (next outcome)
          (phaseInstrumentBranch operation outcome state)
  | .random source next, state =>
      uniformAverage fun coins : source.Coins =>
        actualPhaseRun queryBound randomized (next coins) state
  | .freshInput sampler next, state =>
      uniformAverage fun coins : sampler.Coins =>
        let input := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            ∑ old : DigestRegister,
              actualPhaseRun queryBound randomized (next coins fresh)
                (phaseReplaceReadBranch input old fresh state)
        else
          ∑ old : DigestRegister,
            actualPhaseRun queryBound randomized (next coins old)
              (phaseReadBranch input old state)

/-- Support accounting removes the last representation-level query: the
phase interpreter and literal CMS interpreter have identical probabilities
on every complete adaptive branch. -/
theorem actual_phase_run_eq_phase_run
    (queryBound spent : Nat) (randomized : Bool)
    (program : Program Input Work) (state : ResponseCmsState Input Work)
    (supported : PhaseSupport queryBound spent program state) :
    actualPhaseRun queryBound randomized program state =
      phaseRun randomized program state := by
  induction program generalizing spent state with
  | finish event => rfl
  | gate operation next ih =>
      rcases supported with ⟨_, tail⟩
      simp only [actualPhaseRun, phaseRun]
      exact ih spent (phaseGate operation state) tail
  | quantumQuery next ih =>
      rcases supported with ⟨_, queryEq, tail⟩
      simp only [actualPhaseRun, phaseRun]
      rw [← queryEq]
      exact ih (spent + 1) (phaseResponseQuery state) tail
  | honestRead input next ih =>
      rcases supported with ⟨_, tails⟩
      simp only [actualPhaseRun, phaseRun]
      apply Finset.sum_congr rfl
      intro answer _
      exact ih answer (spent + 1)
        (phaseReadBranch input answer state) (tails answer)
  | instrument operation next ih =>
      rcases supported with ⟨_, tails⟩
      simp only [actualPhaseRun, phaseRun]
      apply Finset.sum_congr rfl
      intro outcome _
      exact ih outcome spent
        (phaseInstrumentBranch operation outcome state) (tails outcome)
  | random source next ih =>
      rcases supported with ⟨_, tails⟩
      simp only [actualPhaseRun, phaseRun]
      apply congrArg uniformAverage
      funext coins
      exact ih coins spent state (tails coins)
  | freshInput sampler next ih =>
      rcases supported with ⟨_, randomizedTails, honestTails⟩
      simp only [actualPhaseRun, phaseRun]
      apply congrArg uniformAverage
      funext coins
      split
      · apply congrArg uniformAverage
        funext fresh
        apply Finset.sum_congr rfl
        intro old _
        exact ih coins fresh (spent + 1)
          (phaseReplaceReadBranch (sampler.input coins) old fresh state)
          (randomizedTails coins fresh old)
      · apply Finset.sum_congr rfl
        intro old _
        exact ih coins old (spent + 1)
          (phaseReadBranch (sampler.input coins) old state)
          (honestTails coins old)

theorem actual_phase_run_eq_database_run
    (queryBound spent : Nat) (randomized : Bool)
    (program : Program Input Work) (state : ResponseCmsState Input Work)
    (supported : PhaseSupport queryBound spent program state) :
    actualPhaseRun queryBound randomized program state =
      databaseRun randomized program (phaseDecode state) := by
  rw [actual_phase_run_eq_phase_run
    queryBound spent randomized program state supported]
  exact phase_run_eq_database_run randomized program state

/-- Decoding the empty CMS database initialized in the phase basis produces
the exact uniform purified family with the requested response-basis register
state. -/
theorem phase_decode_empty_fourier_initial
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := DigestRegister)
        (Workspace := Work) → ℂ) :
    phaseDecode
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters initialRegisters)) =
      totalOracleFamilyState (fun _oracle : Input → DigestRegister =>
        initialRegisters) := by
  unfold phaseDecode
  rw [global_decompress_empty_support,
    partial_random_oracle_state_univ_eq_family,
    response_fourier_inverse_total_oracle_family_state]
  apply congrArg totalOracleFamilyState
  funext oracle
  exact response_fourier_registers_inverse_left initialRegisters

/-- Fully initialized endpoint: the existing empty compressed random-oracle
state and the existing syntactic query count supply all support premises for
the literal CMS execution. -/
theorem actual_phase_run_empty_eq_database_run
    (queryBound : Nat) (randomized : Bool)
    (program : Program Input Work)
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := DigestRegister)
        (Workspace := Work) → ℂ)
    (capacity : queryCount program ≤ queryBound) :
    actualPhaseRun queryBound randomized program
        (partialRandomOracleState (Output := DigestRegister) ∅
          initialRegisters) =
      databaseRun randomized program
        (phaseDecode
          (partialRandomOracleState (Output := DigestRegister) ∅
            initialRegisters)) := by
  apply actual_phase_run_eq_database_run queryBound 0
  exact phase_support_from_zero queryBound program
    (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    capacity (partial_random_oracle_empty_bounded initialRegisters)

/-- Response-basis initialized form of the preceding endpoint. -/
theorem actual_phase_run_initialized_family
    (queryBound : Nat) (randomized : Bool)
    (program : Program Input Work)
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := DigestRegister)
        (Workspace := Work) → ℂ)
    (capacity : queryCount program ≤ queryBound) :
    actualPhaseRun queryBound randomized program
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters initialRegisters)) =
      databaseRun randomized program
        (totalOracleFamilyState
          (fun _oracle : Input → DigestRegister => initialRegisters)) := by
  rw [actual_phase_run_empty_eq_database_run
    queryBound randomized program (responseFourierRegisters initialRegisters)
    capacity]
  rw [phase_decode_empty_fourier_initial]

/-- End-to-end probability identification for the literal capped CMS run. -/
theorem actual_phase_run_initialized_acceptance
    (queryBound : Nat) (randomized : Bool)
    (program : Program Input Work)
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := DigestRegister)
        (Workspace := Work) → ℂ)
    (capacity : queryCount program ≤ queryBound) :
    actualPhaseRun queryBound randomized program
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters initialRegisters)) =
      V8Smz9HonestWholeViewGames.acceptance randomized program
        (WithLp.toLp 2 initialRegisters) := by
  rw [actual_phase_run_initialized_family queryBound randomized program
    initialRegisters capacity]
  exact databaseRun_initialized_family_eq_acceptance
    randomized program (WithLp.toLp 2 initialRegisters)

/-- Constructor-for-constructor compressed execution of the existing program.
The database persists through every branch. -/
def compressedRun (randomized : Bool) :
    Program Input Work → ResponseCmsState Input Work → ℝ
  | .finish event, state => databaseBorn event (globalDecompress state)
  | .gate operation next, state =>
      compressedRun randomized next (compressedGate operation state)
  | .quantumQuery next, state =>
      compressedRun randomized next (compressedResponseQuery state)
  | .honestRead input next, state =>
      ∑ answer : DigestRegister,
        compressedRun randomized (next answer)
          (measuredReadBranch input answer state)
  | .instrument operation next, state =>
      ∑ outcome,
        compressedRun randomized (next outcome)
          (compressedInstrumentBranch operation outcome state)
  | .random source next, state =>
      uniformAverage fun coins : source.Coins =>
        compressedRun randomized (next coins) state
  | .freshInput sampler next, state =>
      uniformAverage fun coins : sampler.Coins =>
        let input := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            ∑ old : DigestRegister,
              compressedRun randomized (next coins fresh)
                (compressedReplaceReadBranch input old fresh state)
        else
          ∑ old : DigestRegister,
            compressedRun randomized (next coins old)
              (measuredReadBranch input old state)

/-- Exact conjugation theorem for the entire existing program grammar.  This
is an equality of the executable finite branch sums, not a supplied semantic
correspondence premise. -/
theorem compressed_run_eq_database_run (randomized : Bool)
    (program : Program Input Work) (state : ResponseCmsState Input Work) :
    compressedRun randomized program state =
      databaseRun randomized program (globalDecompress state) := by
  induction program generalizing state with
  | finish event => rfl
  | gate operation next ih =>
      simp only [compressedRun, databaseRun, ih,
        global_decompress_compressedGate]
  | quantumQuery next ih =>
      simp only [compressedRun, databaseRun, ih,
        global_decompress_compressedResponseQuery]
  | honestRead input next ih =>
      simp only [compressedRun, databaseRun]
      apply Finset.sum_congr rfl
      intro answer _
      rw [ih answer, global_decompress_measured_read_branch]
      rfl
  | instrument operation next ih =>
      simp only [compressedRun, databaseRun]
      apply Finset.sum_congr rfl
      intro outcome _
      rw [ih outcome, global_decompress_compressedInstrumentBranch]
  | random source next ih =>
      simp only [compressedRun, databaseRun]
      apply congrArg uniformAverage
      funext coins
      exact ih coins state
  | freshInput sampler next ih =>
      simp only [compressedRun, databaseRun]
      apply congrArg uniformAverage
      funext coins
      split
      · apply congrArg uniformAverage
        funext fresh
        apply Finset.sum_congr rfl
        intro old _
        rw [ih coins fresh,
          global_decompress_compressedReplaceReadBranch]
        rfl
      · apply Finset.sum_congr rfl
        intro old _
        rw [ih coins old, global_decompress_measured_read_branch]
        rfl

/-- The compressed interpreter is pointwise equal to the existing game on the
compressed representative of every named oracle state. -/
theorem compressedRun_compressedOracleState (randomized : Bool)
    (program : Program Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    compressedRun randomized program
        (globalDecompress (oracleState oracle state)) =
      V8Smz9HonestWholeViewGames.run randomized program oracle state := by
  rw [compressed_run_eq_database_run, global_decompress_involutive,
    databaseRun_oracleState]

section InitializedFreshInput

variable {Index Branch : Type}
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]

/-- One named oracle branch with one retained fresh-label register. -/
def labeledOracleState (oracle : Input → DigestRegister)
    (label : DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    HegemonCrypto.CmsCompressedOracle.State
      Input DigestRegister DigestRegister (DigestRegister × Work) :=
  fun basis =>
    if basis.database = totalDatabase oracle ∧ basis.workspace.1 = label then
      state (basis.input, basis.phase, basis.workspace.2)
    else 0

/-- Literal fresh-input identity on a named total oracle: raw swap installs
the fresh label in the persistent oracle and retains the overwritten answer in
the label register.  This is the reversible purification of the destructive
coordinate replacement used by `databaseRun.freshInput`. -/
theorem rawSwap_labeledOracleState
    (selected : Input) (oracle : Input → DigestRegister)
    (fresh : DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    rawSwap selected (labeledOracleState oracle fresh state) =
      labeledOracleState (Function.update oracle selected fresh)
        (oracle selected) state := by
  funext target
  cases value : target.database selected with
  | none =>
      have notOld : target.database ≠ totalDatabase oracle := by
        intro equal
        have atSelected := congrFun equal selected
        simp [totalDatabase, value] at atSelected
      have notNew :
          target.database ≠
            totalDatabase (Function.update oracle selected fresh) := by
        intro equal
        have atSelected := congrFun equal selected
        simp [totalDatabase, value] at atSelected
      simp [rawSwap, swapBasis, value, labeledOracleState, notOld, notNew]
  | some answer =>
      have conditions :
          (setDatabaseCoordinate target.database selected
                (some target.workspace.1) = totalDatabase oracle ∧
              answer = fresh) ↔
            (target.database =
                totalDatabase (Function.update oracle selected fresh) ∧
              target.workspace.1 = oracle selected) := by
        constructor
        · rintro ⟨replaced, answerFresh⟩
          have labelOld : target.workspace.1 = oracle selected := by
            have atSelected := congrFun replaced selected
            simpa [setDatabaseCoordinate, totalDatabase] using atSelected
          refine ⟨?_, labelOld⟩
          funext input
          by_cases same : input = selected
          · subst input
            simp [totalDatabase, value, answerFresh]
          · have atInput := congrFun replaced input
            simpa [setDatabaseCoordinate, totalDatabase,
              Function.update_of_ne same, same] using atInput
        · rintro ⟨updated, labelOld⟩
          constructor
          · funext input
            by_cases same : input = selected
            · subst input
              simp [setDatabaseCoordinate, totalDatabase, labelOld]
            · have atInput := congrFun updated input
              simpa [setDatabaseCoordinate, totalDatabase,
                Function.update_of_ne same, same] using atInput
          · have atSelected := congrFun updated selected
            simpa [totalDatabase, value] using atSelected
      simp only [rawSwap, swapBasis, value, labeledOracleState]
      exact if_congr conditions rfl rfl

/-- The actual initialized fresh-input operation: measure the new database
answer only after applying the checked branch-controlled compressed swap.
Whole-table decompression turns it into the literal raw database/label swap
followed by the same answer projector. -/
theorem initialized_controlled_fresh_branch_intertwining
    (keys : Branch → Index → Input) (indices : List Index)
    (answer : DigestRegister)
    (core : Core Input Branch (Input × DigestRegister × Work) DigestRegister → ℂ)
    (input : Input) :
    globalDecompress
        (measuredReadBranch input answer
          (controlledCompressed keys indices
            (initializedFreshState (Index := Index) core))) =
      coordinateEventProjection input answer
        (controlledRaw keys indices
          (globalDecompress (initializedFreshState (Index := Index) core))) := by
  rw [global_decompress_measured_read_branch,
    global_controlled_swap_intertwining]

end InitializedFreshInput

end
end HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
