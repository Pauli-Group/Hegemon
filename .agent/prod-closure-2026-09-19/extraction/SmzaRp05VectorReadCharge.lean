import SmzaRp05PhysicalTerminalRead
import SmzaRp05PhysicalReadSupport
import SmzaRp05AdaptiveFilteredCollision
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle

/-!
# Full-vector response-register query conjugation

This is the finite Fourier part of charging a physical terminal read to a
quantum query.  A response register translated by the *full* vector oracle
answer is exactly the existing vector CMS phase query in the Fourier basis.
An explicit fresh response ancilla and saved query registers identify each
terminal answer branch with one charged CMS query and database-blind
prepare/Fourier/readout maps. This circuit identity alone does not certify
the measured instrument's four-role bad-event probability.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05VectorReadCharge

open scoped BigOperators Classical ComplexConjugate InnerProductSpace
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead
open HegemonCrypto.SmallWood.SmzaRp05PhysicalReadSupport
open HegemonCrypto.SmallWood.SmzaRp05AdaptiveFilteredCollision
open HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument
open HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

abbrev Answer := VectorOutput Counter
abbrev VectorCmsState := State Key (Answer (Counter := Counter))
  (Answer (Counter := Counter)) Work

theorem vector_character_symmetric
    (left right : Answer (Counter := Counter)) :
    vectorCharacter left right = vectorCharacter right left := by
  simp only [vectorCharacter, AddChar.coe_mk]
  apply Finset.prod_congr rfl
  intro counter _
  simp only [digestCharacter, AddChar.coe_mk]
  apply Finset.prod_congr rfl
  intro bit _
  rw [mul_comm]

theorem vector_phase_character_sum
    (value : Answer (Counter := Counter)) :
    (∑ phase : Answer (Counter := Counter), vectorCharacter phase value) =
      if value = 0 then (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 := by
  calc
    _ = ∑ phase : Answer (Counter := Counter), vectorCharacter value phase := by
      apply Finset.sum_congr rfl
      intro phase _
      exact vector_character_symmetric phase value
    _ = if vectorCharacter value = 0 then
          (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 :=
      AddChar.sum_eq_ite (vectorCharacter value)
    _ = if value = 0 then
          (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 := by
      apply if_congr
      · constructor
        · intro trivial
          exact vector_character_injective
            (trivial.trans vector_character_zero.symm)
        · rintro rfl
          exact vector_character_zero
      · rfl
      · rfl

theorem vector_phase_character_orthogonality
    (left right : Answer (Counter := Counter)) :
    (∑ phase : Answer (Counter := Counter),
      vectorCharacter phase (right - left)) =
      if right = left then
        (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 := by
  simpa only [sub_eq_zero] using vector_phase_character_sum (right - left)

theorem vector_output_character_orthogonality
    (left right : Answer (Counter := Counter)) :
    (∑ output : Answer (Counter := Counter),
      vectorCharacter left output * vectorCharacter right (-output)) =
      if left = right then
        (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 := by
  calc
    _ = ∑ output : Answer (Counter := Counter),
          (vectorCharacter left - vectorCharacter right) output := by
      apply Finset.sum_congr rfl
      intro output _
      exact (AddChar.sub_apply _ _ output).symm
    _ = if vectorCharacter left - vectorCharacter right = 0 then
          (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 :=
      AddChar.sum_eq_ite (vectorCharacter left - vectorCharacter right)
    _ = if left = right then
          (Fintype.card (Answer (Counter := Counter)) : ℂ) else 0 := by
      apply if_congr
      · rw [sub_eq_zero]
        exact vector_character_injective.eq_iff
      · rfl
      · rfl

theorem vector_fourier_normalization :
    inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
        inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
        (Fintype.card (Answer (Counter := Counter)) : ℂ) = 1 := by
  rw [inverse_sqrt_output_card_mul_self]
  unfold inverseOutputCard
  change (((Fintype.card (Answer (Counter := Counter)) : ℝ) : ℂ))⁻¹ *
      ((Fintype.card (Answer (Counter := Counter)) : ℝ) : ℂ) = 1
  have cardNonzero :
      (((Fintype.card (Answer (Counter := Counter)) : ℝ) : ℂ)) ≠ 0 := by
    exact_mod_cast
      (show (Fintype.card (Answer (Counter := Counter)) : ℝ) ≠ 0 by positivity)
  exact inv_mul_cancel₀ cardNonzero

/-- Normalized response-to-phase Fourier transform of the entire vector. -/
def vectorResponseFourier
    (state : Answer (Counter := Counter) → ℂ) :
    Answer (Counter := Counter) → ℂ :=
  fun phase => inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
    ∑ response : Answer (Counter := Counter),
      vectorCharacter phase response * state response

def vectorResponseFourierInverse
    (state : Answer (Counter := Counter) → ℂ) :
    Answer (Counter := Counter) → ℂ :=
  fun response => inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
    ∑ phase : Answer (Counter := Counter),
      vectorCharacter phase (-response) * state phase

theorem vector_response_fourier_inverse_left
    (state : Answer (Counter := Counter) → ℂ) :
    vectorResponseFourierInverse (vectorResponseFourier state) = state := by
  funext response
  unfold vectorResponseFourierInverse vectorResponseFourier
  calc
    _ = ∑ phase : Answer (Counter := Counter),
          ∑ source : Answer (Counter := Counter),
            (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
              inverseSqrtOutputCard (Output := Answer (Counter := Counter))) *
              (vectorCharacter phase (-response) *
                vectorCharacter phase source) * state source := by
          simp_rw [Finset.mul_sum]
          apply Finset.sum_congr rfl
          intro phase _
          apply Finset.sum_congr rfl
          intro source _
          ring
    _ = ∑ source : Answer (Counter := Counter),
          (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
            inverseSqrtOutputCard (Output := Answer (Counter := Counter))) *
            (∑ phase : Answer (Counter := Counter),
              vectorCharacter phase (source - response)) * state source := by
          rw [Finset.sum_comm]
          apply Finset.sum_congr rfl
          intro source _
          rw [Finset.mul_sum, Finset.sum_mul]
          apply Finset.sum_congr rfl
          intro phase _
          rw [← AddChar.map_add_eq_mul]
          congr 2
          abel
    _ = state response := by
          simp_rw [vector_phase_character_orthogonality response]
          rw [Fintype.sum_eq_single response]
          · rw [if_pos rfl, vector_fourier_normalization, one_mul]
          · simp_all

theorem vector_fourier_inverse_kernel_is_conjugate
    (phase response : Answer (Counter := Counter)) :
    inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
        vectorCharacter phase (-response) =
      star (inverseSqrtOutputCard
        (Output := Answer (Counter := Counter)) *
          vectorCharacter phase response) := by
  have characterConjugate :
      vectorCharacter phase (-response) =
        star (vectorCharacter phase response) :=
    AddChar.map_neg_eq_conj (vectorCharacter phase) response
  have scaleConjugate :
      inverseSqrtOutputCard (Output := Answer (Counter := Counter)) =
        star (inverseSqrtOutputCard
          (Output := Answer (Counter := Counter))) := by
    unfold inverseSqrtOutputCard
    rw [star_inv₀]
    congr 1
    rw [RCLike.star_def, Complex.conj_ofReal]
  rw [star_mul, ← scaleConjugate, ← characterConjugate]
  exact mul_comm _ _

theorem vector_response_fourier_inverse_right
    (state : Answer (Counter := Counter) → ℂ) :
    vectorResponseFourier (vectorResponseFourierInverse state) = state := by
  funext phase
  unfold vectorResponseFourier vectorResponseFourierInverse
  calc
    _ = ∑ response : Answer (Counter := Counter),
          ∑ source : Answer (Counter := Counter),
            (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
              inverseSqrtOutputCard (Output := Answer (Counter := Counter))) *
              (vectorCharacter phase response *
                vectorCharacter source (-response)) * state source := by
          simp_rw [Finset.mul_sum]
          apply Finset.sum_congr rfl
          intro response _
          apply Finset.sum_congr rfl
          intro source _
          ring
    _ = ∑ source : Answer (Counter := Counter),
          (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
            inverseSqrtOutputCard (Output := Answer (Counter := Counter))) *
            (∑ response : Answer (Counter := Counter),
              vectorCharacter phase response *
                vectorCharacter source (-response)) * state source := by
          rw [Finset.sum_comm]
          apply Finset.sum_congr rfl
          intro source _
          rw [Finset.mul_sum, Finset.sum_mul]
    _ = state phase := by
          simp_rw [vector_output_character_orthogonality phase]
          rw [Fintype.sum_eq_single phase]
          · rw [if_pos rfl, vector_fourier_normalization, one_mul]
          · intro x different
            simp [Ne.symm different]

/-- Translation of the entire answer vector is the vector CMS phase. -/
theorem vector_response_fourier_shift
    (answer : Answer (Counter := Counter))
    (state : Answer (Counter := Counter) → ℂ) :
    vectorResponseFourier (fun response => state (response - answer)) =
      fun phase => vectorCharacter phase answer *
        vectorResponseFourier state phase := by
  funext phase
  unfold vectorResponseFourier
  rw [← Equiv.sum_comp (Equiv.addRight answer)
    (fun response : Answer (Counter := Counter) =>
      vectorCharacter phase response * state (response - answer))]
  simp only [Equiv.coe_addRight, add_sub_cancel_right,
    AddChar.map_add_eq_mul]
  calc
    _ = inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
          ∑ response : Answer (Counter := Counter),
            vectorCharacter phase answer *
              (vectorCharacter phase response * state response) := by
          apply congrArg
          apply Finset.sum_congr rfl
          intro response _
          ring
    _ = vectorCharacter phase answer *
          (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
            ∑ response : Answer (Counter := Counter),
              vectorCharacter phase response * state response) := by
          rw [← Finset.mul_sum]
          ring

def vectorFourierState (state : VectorCmsState (Key := Key)
    (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) :=
  fun target => vectorResponseFourier
    (fun response => state { target with phase := response }) target.phase

def vectorFourierInverseState (state : VectorCmsState (Key := Key)
    (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) :=
  fun target => vectorResponseFourierInverse
    (fun phase => state { target with phase := phase }) target.phase

theorem vector_fourier_inverse_state_left
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    vectorFourierInverseState (vectorFourierState state) = state := by
  funext target
  rcases target with ⟨input, phase, workspace, database⟩
  exact congrFun (vector_response_fourier_inverse_left
    (fun response => state
      { input := input, phase := response,
        workspace := workspace, database := database })) phase

abbrev VectorFourierSpace :=
  EuclideanSpace ℂ (Answer (Counter := Counter))

def vectorFourierVector
    (state : VectorFourierSpace (Counter := Counter)) :
    VectorFourierSpace (Counter := Counter) :=
  WithLp.toLp 2 (vectorResponseFourier fun response => state response)

def vectorFourierInverseVector
    (state : VectorFourierSpace (Counter := Counter)) :
    VectorFourierSpace (Counter := Counter) :=
  WithLp.toLp 2 (vectorResponseFourierInverse fun phase => state phase)

@[simp]
theorem vector_fourier_vector_apply
    (state : VectorFourierSpace (Counter := Counter))
    (phase : Answer (Counter := Counter)) :
    vectorFourierVector state phase = vectorResponseFourier state phase := by
  rfl

@[simp]
theorem vector_fourier_inverse_vector_apply
    (state : VectorFourierSpace (Counter := Counter))
    (response : Answer (Counter := Counter)) :
    vectorFourierInverseVector state response =
      vectorResponseFourierInverse state response := by
  rfl

theorem vector_fourier_adjoint
    (left right : VectorFourierSpace (Counter := Counter)) :
    ⟪vectorFourierVector left, right⟫_ℂ =
      ⟪left, vectorFourierInverseVector right⟫_ℂ := by
  simp only [PiLp.inner_apply, RCLike.inner_apply',
    vector_fourier_vector_apply, vector_fourier_inverse_vector_apply]
  unfold vectorResponseFourier vectorResponseFourierInverse
  calc
    (∑ phase : Answer (Counter := Counter),
        star (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
          ∑ response : Answer (Counter := Counter),
            vectorCharacter phase response * left response) *
          right phase) =
      ∑ phase : Answer (Counter := Counter),
        ∑ response : Answer (Counter := Counter),
          star (inverseSqrtOutputCard
            (Output := Answer (Counter := Counter)) *
              vectorCharacter phase response) *
          star (left response) * right phase := by
        apply Finset.sum_congr rfl
        intro phase _
        simp_rw [star_mul, star_sum, Finset.sum_mul]
        apply Finset.sum_congr rfl
        intro response _
        rw [star_mul]
        ring
    _ = ∑ response : Answer (Counter := Counter),
        ∑ phase : Answer (Counter := Counter),
          star (left response) *
            (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
              vectorCharacter phase (-response) * right phase) := by
        rw [Finset.sum_comm]
        apply Finset.sum_congr rfl
        intro response _
        apply Finset.sum_congr rfl
        intro phase _
        rw [vector_fourier_inverse_kernel_is_conjugate]
        ring
    _ = ∑ response : Answer (Counter := Counter),
        star (left response) *
          (inverseSqrtOutputCard (Output := Answer (Counter := Counter)) *
            ∑ phase : Answer (Counter := Counter),
              vectorCharacter phase (-response) * right phase) := by
        apply Finset.sum_congr rfl
        intro response _
        simp_rw [Finset.mul_sum]
        ring

theorem vector_fourier_vector_norm
    (state : VectorFourierSpace (Counter := Counter)) :
    ‖vectorFourierVector state‖ = ‖state‖ := by
  have inverse : vectorFourierInverseVector (vectorFourierVector state) =
      state := by
    ext response
    exact congrFun (vector_response_fourier_inverse_left state) response
  have innerEquality := vector_fourier_adjoint state
    (vectorFourierVector state)
  rw [inverse] at innerEquality
  have squareEquality := congrArg (RCLike.re : ℂ → ℝ) innerEquality
  rw [← norm_sq_eq_re_inner, ← norm_sq_eq_re_inner] at squareEquality
  nlinarith [norm_nonneg (vectorFourierVector state), norm_nonneg state]

theorem vector_fourier_sum_normSq
    (state : Answer (Counter := Counter) → ℂ) :
    (∑ phase : Answer (Counter := Counter),
      Complex.normSq (vectorResponseFourier state phase)) =
      ∑ response : Answer (Counter := Counter),
        Complex.normSq (state response) := by
  let vector : VectorFourierSpace (Counter := Counter) := WithLp.toLp 2 state
  have preserved := congrArg (fun value : ℝ => value ^ 2)
    (vector_fourier_vector_norm vector)
  rw [EuclideanSpace.norm_sq_eq, EuclideanSpace.norm_sq_eq] at preserved
  simpa only [vector, vectorFourierVector, Complex.sq_norm] using preserved

theorem vector_fourier_inverse_sum_normSq
    (state : Answer (Counter := Counter) → ℂ) :
    (∑ response : Answer (Counter := Counter),
      Complex.normSq (vectorResponseFourierInverse state response)) =
      ∑ phase : Answer (Counter := Counter),
        Complex.normSq (state phase) := by
  have forward := vector_fourier_sum_normSq
    (vectorResponseFourierInverse state)
  simpa only [vector_response_fourier_inverse_right] using forward.symm

/-- Parseval in every input/workspace/database fiber of the full-vector
terminal response register. No factor proportional to the output cardinality
is introduced by the inverse Fourier map. -/
theorem vector_fourier_inverse_state_norm_squared
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (vectorFourierInverseState state) = normSquared state := by
  let reindex :
      ((Key × Work × Database Key (Answer (Counter := Counter))) ×
          Answer (Counter := Counter)) ≃
        Basis Key (Answer (Counter := Counter))
          (Answer (Counter := Counter)) Work :=
    { toFun := fun pair =>
        { input := pair.1.1
          phase := pair.2
          workspace := pair.1.2.1
          database := pair.1.2.2 }
      invFun := fun basis =>
        ((basis.input, basis.workspace, basis.database), basis.phase)
      left_inv := by intro pair; cases pair; rfl
      right_inv := by intro basis; cases basis; rfl }
  unfold normSquared
  rw [← reindex.sum_comp
      (fun basis => Complex.normSq (vectorFourierInverseState state basis))]
  rw [← reindex.sum_comp (fun basis => Complex.normSq (state basis))]
  calc
    (∑ pair : (Key × Work × Database Key (Answer (Counter := Counter))) ×
        Answer (Counter := Counter),
      Complex.normSq (vectorFourierInverseState state (reindex pair))) =
        ∑ rest : Key × Work × Database Key (Answer (Counter := Counter)),
          ∑ response : Answer (Counter := Counter),
            Complex.normSq
              (vectorFourierInverseState state (reindex (rest, response))) :=
      Fintype.sum_prod_type
        (fun pair : (Key × Work × Database Key (Answer (Counter := Counter))) ×
            Answer (Counter := Counter) =>
          Complex.normSq (vectorFourierInverseState state (reindex pair)))
    _ = ∑ rest : Key × Work × Database Key (Answer (Counter := Counter)),
          ∑ phase : Answer (Counter := Counter),
            Complex.normSq (state (reindex (rest, phase))) := by
      apply Finset.sum_congr rfl
      intro rest _
      simpa [reindex, vectorFourierInverseState] using
        vector_fourier_inverse_sum_normSq
          (fun phase => state
            { input := rest.1
              phase := phase
              workspace := rest.2.1
              database := rest.2.2 })
    _ = ∑ pair : (Key × Work × Database Key (Answer (Counter := Counter))) ×
          Answer (Counter := Counter),
        Complex.normSq (state (reindex pair)) :=
      (Fintype.sum_prod_type
        (fun pair : (Key × Work × Database Key (Answer (Counter := Counter))) ×
            Answer (Counter := Counter) =>
          Complex.normSq (state (reindex pair)))).symm

theorem vector_fourier_state_norm_squared
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (vectorFourierState state) = normSquared state := by
  have inverse := vector_fourier_inverse_state_norm_squared
    (vectorFourierState state)
  rw [vector_fourier_inverse_state_left] at inverse
  exact inverse.symm

theorem vector_fourier_state_bounded
    {bound : Nat}
    {state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)}
    (bounded : BoundedState bound state) :
    BoundedState bound (vectorFourierState state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have fiberZero :
        ∀ response : Answer (Counter := Counter),
          state { target with phase := response } = 0 := by
      intro response
      exact bounded_state_apply_eq_zero_of_lt bounded
        { target with phase := response } above
    simp [project, within, vectorFourierState, vectorResponseFourier,
      fiberZero]

theorem decompress_at_vector_fourier_state
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    decompressAt selected (vectorFourierState state) =
      vectorFourierState (decompressAt selected state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold vectorFourierState vectorResponseFourier
  simp_rw [decompress_at_eq_sum_kernel]
  simp only [Finset.sum_mul, Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro response _
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem decompress_list_vector_fourier_state
    (inputs : List Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    decompressList inputs (vectorFourierState state) =
      vectorFourierState (decompressList inputs state) := by
  induction inputs with
  | nil => rfl
  | cons selected remaining ih =>
      simp only [decompress_list_cons]
      rw [ih, decompress_at_vector_fourier_state]

theorem global_decompress_vector_fourier_state
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    globalDecompress (vectorFourierState state) =
      vectorFourierState (globalDecompress state) := by
  unfold globalDecompress
  exact decompress_list_vector_fourier_state _ state

theorem decompress_at_vector_fourier_inverse_state
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    decompressAt selected (vectorFourierInverseState state) =
      vectorFourierInverseState (decompressAt selected state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold vectorFourierInverseState vectorResponseFourierInverse
  simp_rw [decompress_at_eq_sum_kernel]
  simp only [Finset.sum_mul, Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro response _
  apply Finset.sum_congr rfl
  intro source _
  ring

theorem global_decompress_vector_fourier_inverse_state
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    globalDecompress (vectorFourierInverseState state) =
      vectorFourierInverseState (globalDecompress state) := by
  unfold globalDecompress
  have commute (inputs : List Key) :
      decompressList inputs (vectorFourierInverseState state) =
        vectorFourierInverseState (decompressList inputs state) := by
    induction inputs with
    | nil => rfl
    | cons changed remaining ih =>
        simp only [decompress_list_cons]
        rw [ih, decompress_at_vector_fourier_inverse_state]
  exact commute _

/-- The standard additive response query, including absent coordinates. -/
def vectorDatabaseResponseQuery (state : VectorCmsState (Key := Key)
    (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) :=
  fun target => match target.database target.input with
    | none => state target
    | some answer => state { target with phase := target.phase - answer }

/-- One literal full-vector response translation is exactly one vector CMS
phase query after the database-blind response Fourier transform. -/
theorem vector_fourier_database_response_query
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    vectorFourierState (vectorDatabaseResponseQuery state) =
      phaseQueryState vectorPhaseSystem (vectorFourierState state) := by
  funext target
  cases value : target.database target.input with
  | none =>
      simp [vectorFourierState, vectorResponseFourier,
        vectorDatabaseResponseQuery, phaseQueryState, recordedPhase, value]
  | some answer =>
      simp only [vectorFourierState, vectorDatabaseResponseQuery,
        phaseQueryState, recordedPhase, value]
      change vectorResponseFourier
          (fun response => state { target with phase := response - answer })
          target.phase =
        vectorCharacter target.phase answer *
          vectorResponseFourier
            (fun response => state { target with phase := response }) target.phase
      exact congrFun (vector_response_fourier_shift answer
        (fun response => state { target with phase := response })) target.phase

/-- Exact full-vector charged-query equation on strict compressed support.
The left operator is the generic CMS `queryState` instantiated with the
existing complete vector phase system, and the right operator is literal
response translation of the same full vector on the standard oracle. -/
theorem charged_vector_query_eq_response_translation
    (queryBound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (strict : StrictSupport queryBound (vectorFourierState state)) :
    globalDecompress
        (queryState vectorPhaseSystem queryBound (vectorFourierState state)) =
      vectorFourierState
        (vectorDatabaseResponseQuery (globalDecompress state)) := by
  rw [global_decompress_query_state_eq_phase vectorPhaseSystem queryBound _ strict,
    global_decompress_vector_fourier_state,
    ← vector_fourier_database_response_query]

theorem charged_vector_query_eq_response_translation_of_bounded
    (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) :
    globalDecompress
        (queryState vectorPhaseSystem (bound + 1) (vectorFourierState state)) =
      vectorFourierState
        (vectorDatabaseResponseQuery (globalDecompress state)) := by
  apply charged_vector_query_eq_response_translation
  exact bounded_state_strict_support
    (vector_fourier_state_bounded bounded) (Nat.lt_succ_self bound)

/-- Preserve the old query input and phase in finite private registers and
prepare a fresh response register at zero for the selected public read. -/
def prepareZeroAt
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work) :=
  fun target =>
    if target.input = selected ∧ target.phase = 0 then
      state
        { input := target.workspace.1
          phase := target.workspace.2.1
          workspace := target.workspace.2.2
          database := target.database }
    else 0

theorem prepare_zero_at_bounded
    (selected : Key) {bound : Nat}
    {state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)}
    (bounded : BoundedState bound state) :
    BoundedState bound (prepareZeroAt selected state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have oldZero : state
        { input := target.workspace.1
          phase := target.workspace.2.1
          workspace := target.workspace.2.2
          database := target.database } = 0 :=
      bounded_state_apply_eq_zero_of_lt bounded _ above
    simp [project, within, prepareZeroAt, oldZero]

theorem decompress_at_prepare_zero_at
    (selected changed : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    decompressAt changed (prepareZeroAt selected state) =
      prepareZeroAt selected (decompressAt changed state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  by_cases prepared : target.input = selected ∧ target.phase = 0
  · simp [prepareZeroAt, prepared, decompress_at_eq_sum_kernel]
  · simp [prepareZeroAt, prepared]

theorem global_decompress_prepare_zero_at
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    globalDecompress (prepareZeroAt selected state) =
      prepareZeroAt selected (globalDecompress state) := by
  unfold globalDecompress
  have commute (inputs : List Key) :
      decompressList inputs (prepareZeroAt selected state) =
        prepareZeroAt selected (decompressList inputs state) := by
    induction inputs with
    | nil => rfl
    | cons changed remaining ih =>
        simp only [decompress_list_cons]
        rw [ih, decompress_at_prepare_zero_at]
  exact commute _

/-- Read one response outcome, then restore the original query registers.
The fresh response register is measured, not silently discarded. -/
def readoutAndRestore
    (selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work)) :
    VectorCmsState (Key := Key) (Counter := Counter) (Work := Work) :=
  fun target => state
    { input := selected
      phase := answer
      workspace := (target.input, target.phase, target.workspace)
      database := target.database }

/-- The answer-register readout restores saved query registers and never
inspects or changes the oracle database. -/
theorem decompress_at_readout_and_restore
    (changed selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work)) :
    decompressAt changed (readoutAndRestore selected answer state) =
      readoutAndRestore selected answer (decompressAt changed state) := by
  funext target
  simp only [readoutAndRestore, decompress_at_eq_sum_kernel]

theorem global_decompress_readout_and_restore
    (selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work)) :
    globalDecompress (readoutAndRestore selected answer state) =
      readoutAndRestore selected answer (globalDecompress state) := by
  unfold globalDecompress
  have commute (inputs : List Key) :
      decompressList inputs (readoutAndRestore selected answer state) =
        readoutAndRestore selected answer (decompressList inputs state) := by
    induction inputs with
    | nil => rfl
    | cons changed remaining ih =>
        simp only [decompress_list_cons]
        rw [ih, decompress_at_readout_and_restore]
  exact commute _

/-- The certified role event ignores the temporary saved query registers. -/
def liftedReadEvent
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    (Key × Answer (Counter := Counter) × Work) →
      Database Key (Answer (Counter := Counter)) → Prop :=
  fun registers database => event registers.2.2 database

theorem lifted_read_event_instability
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (queryBound : Nat) (bound : ℝ)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) queryBound bound) :
    ∀ registers,
      RealInstabilityBound (liftedReadEvent event registers)
        queryBound bound := by
  intro registers
  exact instability registers.2.2

theorem workspace_event_eq_adaptive_project_of_bounded
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState cap state) :
    workspaceEventProjection event state = adaptiveProject event cap state := by
  funext basis
  by_cases within : size basis.database ≤ cap
  · simp [workspaceEventProjection, adaptiveProject, within]
  · have zero := bounded_state_apply_eq_zero_of_lt bounded basis
      (Nat.lt_of_not_ge within)
    simp [workspaceEventProjection, adaptiveProject, within, zero]

theorem sqrt_norm_squared_eq_state_norm
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    Real.sqrt (normSquared state) = stateNorm state := by
  rw [← state_norm_sq_eq_norm_squared]
  exact Real.sqrt_sq (state_norm_nonnegative state)

theorem readout_and_restore_event_commute
    (selected : Key) (answer : Answer (Counter := Counter))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (state : VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work)) :
    workspaceEventProjection event (readoutAndRestore selected answer state) =
      readoutAndRestore selected answer
        (workspaceEventProjection (liftedReadEvent event) state) := by
  funext target
  by_cases enabled : event target.workspace target.database <;>
    simp [workspaceEventProjection, readoutAndRestore,
      liftedReadEvent, enabled]

/-- Summing every recorded answer selects only the fixed fresh query-input
sector of the extended state. It is a contraction, not a branch-count loss. -/
theorem sum_readout_and_restore_norm_squared_le
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Key × Answer (Counter := Counter) × Work)) :
    (∑ answer : Answer (Counter := Counter),
      normSquared (readoutAndRestore selected answer state)) ≤
        normSquared state := by
  let reindex :
      (Key × Answer (Counter := Counter) ×
        Basis Key (Answer (Counter := Counter))
          (Answer (Counter := Counter)) Work) ≃
      Basis Key (Answer (Counter := Counter))
        (Answer (Counter := Counter))
        (Key × Answer (Counter := Counter) × Work) :=
    { toFun := fun triple =>
        { input := triple.1
          phase := triple.2.1
          workspace :=
            (triple.2.2.input, triple.2.2.phase,
              triple.2.2.workspace)
          database := triple.2.2.database }
      invFun := fun basis =>
        (basis.input, basis.phase,
          { input := basis.workspace.1
            phase := basis.workspace.2.1
            workspace := basis.workspace.2.2
            database := basis.database })
      left_inv := by intro triple; cases triple; rfl
      right_inv := by intro basis; cases basis; rfl }
  have readout :
      (∑ answer : Answer (Counter := Counter),
        normSquared (readoutAndRestore selected answer state)) =
      ∑ answer : Answer (Counter := Counter),
        ∑ basis : Basis Key (Answer (Counter := Counter))
            (Answer (Counter := Counter)) Work,
          Complex.normSq (state (reindex (selected, answer, basis))) := by
    rfl
  have full : normSquared state =
      ∑ input : Key,
        ∑ answer : Answer (Counter := Counter),
          ∑ basis : Basis Key (Answer (Counter := Counter))
              (Answer (Counter := Counter)) Work,
            Complex.normSq (state (reindex (input, answer, basis))) := by
    unfold normSquared
    rw [← reindex.sum_comp (fun basis => Complex.normSq (state basis))]
    simp only [Fintype.sum_prod_type]
  have nonnegative (input : Key) :
      0 ≤ ∑ answer : Answer (Counter := Counter),
        ∑ basis : Basis Key (Answer (Counter := Counter))
            (Answer (Counter := Counter)) Work,
          Complex.normSq (state (reindex (input, answer, basis))) := by
    apply Finset.sum_nonneg
    intro answer _
    apply Finset.sum_nonneg
    intro basis _
    exact Complex.normSq_nonneg _
  calc
    _ = ∑ answer : Answer (Counter := Counter),
        ∑ basis : Basis Key (Answer (Counter := Counter))
            (Answer (Counter := Counter)) Work,
          Complex.normSq (state (reindex (selected, answer, basis))) := readout
    _ ≤ ∑ input : Key,
        ∑ answer : Answer (Counter := Counter),
          ∑ basis : Basis Key (Answer (Counter := Counter))
              (Answer (Counter := Counter)) Work,
            Complex.normSq (state (reindex (input, answer, basis))) :=
      Finset.single_le_sum (fun input _ => nonnegative input)
        (Finset.mem_univ selected)
    _ = normSquared state := full.symm

/-- Preparing the fresh zero answer register and saving the old query
registers is an isometry on the complete compressed-oracle state. -/
theorem prepare_zero_at_norm_squared
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (prepareZeroAt selected state) = normSquared state := by
  let reindex :
      (Key × Answer (Counter := Counter) ×
        Basis Key (Answer (Counter := Counter))
          (Answer (Counter := Counter)) Work) ≃
      Basis Key (Answer (Counter := Counter))
        (Answer (Counter := Counter))
        (Key × Answer (Counter := Counter) × Work) :=
    { toFun := fun triple =>
        { input := triple.1
          phase := triple.2.1
          workspace :=
            (triple.2.2.input, triple.2.2.phase,
              triple.2.2.workspace)
          database := triple.2.2.database }
      invFun := fun basis =>
        (basis.input, basis.phase,
          { input := basis.workspace.1
            phase := basis.workspace.2.1
            workspace := basis.workspace.2.2
            database := basis.database })
      left_inv := by intro triple; cases triple; rfl
      right_inv := by intro basis; cases basis; rfl }
  unfold normSquared
  rw [← reindex.sum_comp
    (fun basis => Complex.normSq (prepareZeroAt selected state basis))]
  rw [Fintype.sum_prod_type]
  simp only [prepareZeroAt, reindex]
  rw [Finset.sum_eq_single selected]
  · rw [Fintype.sum_prod_type]
    rw [Finset.sum_eq_single 0]
    · simp
    · intro answer _ different
      simp [different]
    · simp
  · intro key _ different
    simp [different]
  · simp

theorem vector_fourier_inverse_event_commute
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    workspaceEventProjection event (vectorFourierInverseState state) =
      vectorFourierInverseState (workspaceEventProjection event state) := by
  funext target
  by_cases enabled : event target.workspace target.database <;>
    simp [workspaceEventProjection, vectorFourierInverseState,
      vectorResponseFourierInverse, enabled]

theorem vector_fourier_event_commute
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    workspaceEventProjection event (vectorFourierState state) =
      vectorFourierState (workspaceEventProjection event state) := by
  funext target
  by_cases enabled : event target.workspace target.database <;>
    simp [workspaceEventProjection, vectorFourierState,
      vectorResponseFourier, enabled]

theorem prepare_zero_at_event_commute
    (selected : Key)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    workspaceEventProjection (liftedReadEvent event)
        (prepareZeroAt selected state) =
      prepareZeroAt selected (workspaceEventProjection event state) := by
  funext target
  by_cases prepared : target.input = selected ∧ target.phase = 0 <;>
    by_cases enabled : event target.workspace.2.2 target.database <;>
    simp [workspaceEventProjection, prepareZeroAt, liftedReadEvent,
      prepared, enabled]

/-- The source bad-event energy is unchanged when the fresh response
register is prepared and rotated to the vector Fourier basis. -/
theorem prepared_fourier_role_mass_eq_source
    (selected : Key)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (workspaceEventProjection (liftedReadEvent event)
        (vectorFourierState (prepareZeroAt selected state))) =
      normSquared (workspaceEventProjection event state) := by
  rw [vector_fourier_event_commute,
    vector_fourier_state_norm_squared,
    prepare_zero_at_event_commute,
    prepare_zero_at_norm_squared]

theorem prepared_fourier_norm_squared_eq_source
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (vectorFourierState (prepareZeroAt selected state)) =
      normSquared state := by
  rw [vector_fourier_state_norm_squared, prepare_zero_at_norm_squared]

/-! Orthogonal storage of classical answer histories. -/

def packReadFamily
    {Index : Type} [Fintype Index]
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter)
      (Work := Index × Work) :=
  fun basis => branches basis.workspace.1
    { input := basis.input
      phase := basis.phase
      workspace := basis.workspace.2
      database := basis.database }

/-- Different classical histories occupy orthogonal workspace sectors;
packing them neither renormalizes nor multiplies their total mass. -/
theorem pack_read_family_norm_squared
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (packReadFamily branches) =
      ∑ index : Index, normSquared (branches index) := by
  let reindex :
      (Index × Basis Key (Answer (Counter := Counter))
        (Answer (Counter := Counter)) Work) ≃
      Basis Key (Answer (Counter := Counter))
        (Answer (Counter := Counter)) (Index × Work) :=
    { toFun := fun pair =>
        { input := pair.2.input
          phase := pair.2.phase
          workspace := (pair.1, pair.2.workspace)
          database := pair.2.database }
      invFun := fun basis =>
        (basis.workspace.1,
          { input := basis.input
            phase := basis.phase
            workspace := basis.workspace.2
            database := basis.database })
      left_inv := by intro pair; cases pair; rfl
      right_inv := by intro basis; cases basis; rfl }
  unfold normSquared
  rw [← reindex.sum_comp
    (fun basis => Complex.normSq (packReadFamily branches basis))]
  rw [Fintype.sum_prod_type]
  rfl

def packedReadEvent
    {Index : Type}
    (event : Index → Work → Database Key (Answer (Counter := Counter)) → Prop) :
    (Index × Work) → Database Key (Answer (Counter := Counter)) → Prop :=
  fun workspace database => event workspace.1 workspace.2 database

theorem pack_read_family_event_commute
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (event : Index → Work → Database Key (Answer (Counter := Counter)) → Prop)
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    workspaceEventProjection (packedReadEvent event)
        (packReadFamily branches) =
      packReadFamily (fun index =>
        workspaceEventProjection (event index) (branches index)) := by
  funext basis
  by_cases selected : event basis.workspace.1 basis.workspace.2
      basis.database <;>
    simp [workspaceEventProjection, packedReadEvent, packReadFamily, selected]

theorem pack_read_family_event_mass
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (event : Index → Work → Database Key (Answer (Counter := Counter)) → Prop)
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (workspaceEventProjection (packedReadEvent event)
        (packReadFamily branches)) =
      ∑ index : Index,
        normSquared (workspaceEventProjection (event index)
          (branches index)) := by
  rw [pack_read_family_event_commute, pack_read_family_norm_squared]

theorem decompress_at_pack_read_family
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (selected : Key)
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    decompressAt selected (packReadFamily branches) =
      packReadFamily (fun index => decompressAt selected (branches index)) := by
  funext basis
  simp only [packReadFamily, decompress_at_eq_sum_kernel]

theorem global_decompress_pack_read_family
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    globalDecompress (packReadFamily branches) =
      packReadFamily (fun index => globalDecompress (branches index)) := by
  unfold globalDecompress
  have commute (inputs : List Key) :
      decompressList inputs (packReadFamily branches) =
        packReadFamily (fun index => decompressList inputs (branches index)) := by
    induction inputs with
    | nil => rfl
    | cons selected remaining ih =>
        simp only [decompress_list_cons]
        rw [ih, decompress_at_pack_read_family]
  exact commute _

theorem standard_total_pack_read_family
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : ∀ index, StandardTotal (branches index)) :
    StandardTotal (packReadFamily branches) := by
  intro selected basis absent
  rw [global_decompress_pack_read_family]
  simpa [packReadFamily] using
    ((total basis.workspace.1) selected
      { input := basis.input
        phase := basis.phase
        workspace := basis.workspace.2
        database := basis.database } absent)

theorem bounded_pack_read_family
    {Index : Type} [Fintype Index] [DecidableEq Index]
    (cap : Nat)
    (branches : Index →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : ∀ index, BoundedState cap (branches index)) :
    BoundedState cap (packReadFamily branches) := by
  unfold BoundedState
  funext basis
  by_cases within : size basis.database ≤ cap
  · simp [project, within]
  · have zero := bounded_state_apply_eq_zero_of_lt
      (bounded basis.workspace.1)
      { input := basis.input
        phase := basis.phase
        workspace := basis.workspace.2
        database := basis.database }
      (Nat.lt_of_not_ge within)
    simp [project, packReadFamily, within, zero]

/-- On the standard total-oracle presentation, the literal one-query
prepare/translation/readout circuit is exactly the honest coordinate read.
This is an equality of state vectors and holds for arbitrary pre-existing
query input/phase registers, which are saved and restored. -/
theorem one_response_query_realizes_standard_read
    (selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : TotalAt selected state) :
    readoutAndRestore selected answer
        (vectorDatabaseResponseQuery (prepareZeroAt selected state)) =
      coordinateEventProjection selected answer state := by
  funext target
  cases value : target.database selected with
  | none =>
      have absent : state target = 0 := total target value
      simp [readoutAndRestore, vectorDatabaseResponseQuery, prepareZeroAt,
        coordinateEventProjection, value, absent]
  | some observed =>
      by_cases same : observed = answer
      · subst observed
        simp [readoutAndRestore, vectorDatabaseResponseQuery, prepareZeroAt,
          coordinateEventProjection, value]
      · have phaseNonzero : answer - observed ≠ 0 := by
          intro zero
          exact same (sub_eq_zero.mp zero).symm
        simp [readoutAndRestore, vectorDatabaseResponseQuery, prepareZeroAt,
          coordinateEventProjection, value, same, phaseNonzero]

/-- The physical terminal read is the same one-query response circuit,
conjugated to and from the standard-oracle presentation.  The query itself
is identified with the full-vector CMS phase query by
`vector_fourier_database_response_query` above. -/
theorem physical_read_branch_eq_one_response_query
    (selected : Key) (answer : Answer (Counter := Counter))
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : TotalAt selected (globalDecompress state)) :
    physicalReadBranch selected answer state =
      globalDecompress
        (readoutAndRestore selected answer
          (vectorDatabaseResponseQuery
            (prepareZeroAt selected (globalDecompress state)))) := by
  rw [one_response_query_realizes_standard_read selected answer
    (globalDecompress state) total]
  rfl

/-- Exact one-charge realization of the honest full-vector terminal read.
The query is the existing `queryState vectorPhaseSystem (bound + 1)` on the
prepared compressed state.  The fresh answer phase and saved old registers
are finite, database-blind ancillary coordinates. -/
theorem physical_read_branch_eq_one_charged_vector_query
    (selected : Key) (answer : Answer (Counter := Counter)) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalAt selected (globalDecompress state)) :
    physicalReadBranch selected answer state =
      globalDecompress
        (readoutAndRestore selected answer
          (vectorFourierInverseState
            (globalDecompress
              (queryState vectorPhaseSystem (bound + 1)
                (vectorFourierState (prepareZeroAt selected state)))))) := by
  have charged := charged_vector_query_eq_response_translation_of_bounded
    (Key := Key) (Counter := Counter)
    (Work := Key × Answer (Counter := Counter) × Work)
    bound (prepareZeroAt selected state)
    (prepare_zero_at_bounded selected bounded)
  rw [global_decompress_prepare_zero_at] at charged
  calc
    physicalReadBranch selected answer state =
        globalDecompress
          (readoutAndRestore selected answer
            (vectorDatabaseResponseQuery
              (prepareZeroAt selected (globalDecompress state)))) :=
      physical_read_branch_eq_one_response_query selected answer state total
    _ = globalDecompress
          (readoutAndRestore selected answer
            (vectorFourierInverseState
              (globalDecompress
                (queryState vectorPhaseSystem (bound + 1)
                  (vectorFourierState (prepareZeroAt selected state)))))) := by
      rw [charged, vector_fourier_inverse_state_left]

/-- The two database decompressions in the charged read cancel around the
database-blind inverse Fourier and answer-register readout. Thus a terminal
read is literally one CMS query bracketed only by ancillary register maps;
no second oracle query is hidden in the readout wrapper. -/
theorem physical_read_branch_eq_one_query_and_blind_readout
    (selected : Key) (answer : Answer (Counter := Counter)) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalAt selected (globalDecompress state)) :
    physicalReadBranch selected answer state =
      readoutAndRestore selected answer
        (vectorFourierInverseState
          (queryState vectorPhaseSystem (bound + 1)
            (vectorFourierState (prepareZeroAt selected state)))) := by
  rw [physical_read_branch_eq_one_charged_vector_query
    selected answer bound state bounded total]
  rw [global_decompress_readout_and_restore,
    global_decompress_vector_fourier_inverse_state,
    global_decompress_involutive]

/-- For a database/workspace role event, all database-blind operations can
be pushed past the event projector. Only the one CMS query remains inside
the projector, exposing the precise point where the instability estimate
must be applied before the answer branches are summed. -/
theorem physical_read_branch_event_after_one_query
    (selected : Key) (answer : Answer (Counter := Counter)) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalAt selected (globalDecompress state))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    workspaceEventProjection event
        (physicalReadBranch selected answer state) =
      readoutAndRestore selected answer
        (vectorFourierInverseState
          (workspaceEventProjection (liftedReadEvent event)
            (queryState vectorPhaseSystem (bound + 1)
              (vectorFourierState (prepareZeroAt selected state))))) := by
  rw [physical_read_branch_eq_one_query_and_blind_readout
    selected answer bound state bounded total,
    readout_and_restore_event_commute,
    vector_fourier_inverse_event_commute]

/-- Exact answer-instrument energy bound for any role event that ignores
the fresh query registers. The only possible increase in bad-event mass is
at the one exposed CMS query; Fourier inversion and complete answer readout
cannot amplify it. No output-cardinality or answer-count factor appears. -/
theorem sum_physical_read_role_mass_le_one_query_role_mass
    (selected : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalAt selected (globalDecompress state))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    (∑ answer : Answer (Counter := Counter),
      normSquared (workspaceEventProjection event
        (physicalReadBranch selected answer state))) ≤
      normSquared
        (workspaceEventProjection (liftedReadEvent event)
          (queryState vectorPhaseSystem (bound + 1)
            (vectorFourierState (prepareZeroAt selected state)))) := by
  let queryResult := queryState vectorPhaseSystem (bound + 1)
    (vectorFourierState (prepareZeroAt selected state))
  let badResult := workspaceEventProjection (liftedReadEvent event) queryResult
  calc
    _ = ∑ answer : Answer (Counter := Counter),
        normSquared (readoutAndRestore selected answer
          (vectorFourierInverseState badResult)) := by
      apply Finset.sum_congr rfl
      intro answer _
      rw [physical_read_branch_event_after_one_query
        selected answer bound state bounded total event]
    _ ≤ normSquared (vectorFourierInverseState badResult) :=
      sum_readout_and_restore_norm_squared_le selected _
    _ = normSquared badResult :=
      vector_fourier_inverse_state_norm_squared _

/-- One physical answer instrument inherits the current CMS role-instability
amplitude charge exactly once, after summing all outcomes. The input role
mass and source norm are the original compressed state, not a normalized
postselected answer branch. -/
theorem physical_read_role_amplitude_le_one_query_charge
    (selected : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : TotalAt selected (globalDecompress state))
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (localBound : ℝ) (localNonnegative : 0 ≤ localBound)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) (bound + 1) localBound) :
    Real.sqrt (∑ answer : Answer (Counter := Counter),
      normSquared (workspaceEventProjection event
        (physicalReadBranch selected answer state))) ≤
      stateNorm (workspaceEventProjection event state) +
        Real.sqrt (6 * localBound) * stateNorm state := by
  let rotated := vectorFourierState (prepareZeroAt selected state)
  have preparedBounded : BoundedState bound
      (prepareZeroAt selected state) :=
    prepare_zero_at_bounded selected bounded
  have rotatedBounded : BoundedState bound rotated :=
    vector_fourier_state_bounded preparedBounded
  have below : bound < bound + 1 := Nat.lt_succ_self bound
  have rotatedCap : BoundedState (bound + 1) rotated :=
    bounded_state_mono (Nat.le_succ bound) rotatedBounded
  have queryBounded : BoundedState (bound + 1)
      (queryState vectorPhaseSystem (bound + 1) rotated) :=
    query_state_bounded_succ_of_bounded vectorPhaseSystem (bound + 1)
      bound rotated below rotatedBounded
  have amplitude :=
    SmzaRp05AdaptiveFilteredCollision.adaptive_one_query_amplitude_homogeneous
      vectorPhaseSystem (liftedReadEvent event) (bound + 1) rotated
      (bound := localBound) localNonnegative
      (lifted_read_event_instability event (bound + 1) localBound instability)
  rw [capped_query_state_eq_query_state_of_bounded_lt
    vectorPhaseSystem (bound + 1) bound rotated below rotatedBounded] at amplitude
  rw [← workspace_event_eq_adaptive_project_of_bounded
    (liftedReadEvent event) (bound + 1)
    (queryState vectorPhaseSystem (bound + 1) rotated) queryBounded,
    ← workspace_event_eq_adaptive_project_of_bounded
      (liftedReadEvent event) (bound + 1) rotated rotatedCap] at amplitude
  have initialNormEq :
      stateNorm (workspaceEventProjection (liftedReadEvent event) rotated) =
        stateNorm (workspaceEventProjection event state) := by
    have massEq := prepared_fourier_role_mass_eq_source selected event state
    change normSquared
        (workspaceEventProjection (liftedReadEvent event) rotated) =
          normSquared (workspaceEventProjection event state) at massEq
    have leftSquare := state_norm_sq_eq_norm_squared
      (workspaceEventProjection (liftedReadEvent event) rotated)
    have rightSquare := state_norm_sq_eq_norm_squared
      (workspaceEventProjection event state)
    nlinarith [state_norm_nonnegative
      (workspaceEventProjection (liftedReadEvent event) rotated),
      state_norm_nonnegative (workspaceEventProjection event state)]
  have sourceNormEq : stateNorm rotated = stateNorm state := by
    have massEq := prepared_fourier_norm_squared_eq_source selected state
    change normSquared rotated = normSquared state at massEq
    have leftSquare := state_norm_sq_eq_norm_squared rotated
    have rightSquare := state_norm_sq_eq_norm_squared state
    nlinarith [state_norm_nonnegative rotated, state_norm_nonnegative state]
  have readBound := sum_physical_read_role_mass_le_one_query_role_mass
    selected bound state bounded total event
  calc
    _ ≤ Real.sqrt (normSquared
        (workspaceEventProjection (liftedReadEvent event)
          (queryState vectorPhaseSystem (bound + 1) rotated))) :=
      Real.sqrt_le_sqrt readBound
    _ = stateNorm (workspaceEventProjection (liftedReadEvent event)
          (queryState vectorPhaseSystem (bound + 1) rotated)) :=
      sqrt_norm_squared_eq_state_norm _
    _ ≤ stateNorm (workspaceEventProjection (liftedReadEvent event) rotated) +
          Real.sqrt (6 * localBound) * stateNorm rotated := amplitude
    _ = stateNorm (workspaceEventProjection event state) +
          Real.sqrt (6 * localBound) * stateNorm state := by
      rw [initialNormEq, sourceNormEq]

/-- Pack every answer in a classical workspace register. On a standard-total
input the packed read has exactly the original unnormalised mass. -/
theorem packed_physical_read_norm_squared_eq_source
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : StandardTotal state) :
    normSquared (packReadFamily (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch selected answer state)) = normSquared state := by
  rw [pack_read_family_norm_squared]
  exact sum_physical_read_branch_norm_squared selected state total

theorem packed_physical_read_standard_total
    (selected : Key)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : StandardTotal state) :
    StandardTotal
      (packReadFamily (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch selected answer state)) := by
  apply standard_total_pack_read_family
  intro answer
  exact physical_read_branch_standard_total selected answer state total

theorem packed_physical_read_bounded_succ
    (selected : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (packReadFamily (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch selected answer state)) := by
  apply bounded_pack_read_family
  intro answer
  exact physical_read_branch_bounded_succ selected answer bound state bounded

/-- The homogeneous one-read inequality in its composable direct-sum form.
The answer register is orthogonal workspace, not a new oracle sample. -/
theorem packed_physical_read_role_amplitude_le_one_query_charge
    (selected : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : StandardTotal state)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (localBound : ℝ) (localNonnegative : 0 ≤ localBound)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) (bound + 1) localBound) :
    stateNorm (workspaceEventProjection
        (packedReadEvent (fun _ => event))
        (packReadFamily (fun answer : Answer (Counter := Counter) =>
          physicalReadBranch selected answer state))) ≤
      stateNorm (workspaceEventProjection event state) +
        Real.sqrt (6 * localBound) * stateNorm state := by
  have readCharge := physical_read_role_amplitude_le_one_query_charge
    selected bound state bounded (total selected) event localBound localNonnegative
    instability
  rw [← pack_read_family_event_mass (fun _ => event)
    (fun answer : Answer (Counter := Counter) =>
      physicalReadBranch selected answer state)] at readCharge
  rw [sqrt_norm_squared_eq_state_norm] at readCharge
  exact readCharge

/-- Two successive physical reads use one homogeneous instability charge
per read, not per first-read answer. The nested answer workspaces are the
literal orthogonal branches of the sequential instrument. -/
theorem two_packed_physical_reads_role_amplitude_le
    (firstKey secondKey : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state)
    (total : StandardTotal state)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (firstLoss secondLoss : ℝ)
    (firstNonnegative : 0 ≤ firstLoss)
    (secondNonnegative : 0 ≤ secondLoss)
    (firstInstability : ∀ workspace,
      RealInstabilityBound (event workspace) (bound + 1) firstLoss)
    (secondInstability : ∀ workspace,
      RealInstabilityBound (event workspace) (bound + 1 + 1) secondLoss) :
    let firstState := packReadFamily
      (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch firstKey answer state)
    let firstEvent := packedReadEvent
      (Index := Answer (Counter := Counter)) (fun _ => event)
    stateNorm (workspaceEventProjection
        (packedReadEvent (fun _ => firstEvent))
        (packReadFamily (fun answer : Answer (Counter := Counter) =>
          physicalReadBranch secondKey answer firstState))) ≤
      stateNorm (workspaceEventProjection event state) +
        (Real.sqrt (6 * firstLoss) + Real.sqrt (6 * secondLoss)) *
          stateNorm state := by
  dsimp only
  let firstState := packReadFamily
    (fun answer : Answer (Counter := Counter) =>
      physicalReadBranch firstKey answer state)
  let firstEvent := packedReadEvent
    (Index := Answer (Counter := Counter)) (fun _ => event)
  have firstBound := packed_physical_read_role_amplitude_le_one_query_charge
    firstKey bound state bounded total event firstLoss firstNonnegative
    firstInstability
  have firstBounded : BoundedState (bound + 1) firstState :=
    packed_physical_read_bounded_succ firstKey bound state bounded
  have firstTotal : StandardTotal firstState :=
    packed_physical_read_standard_total firstKey state total
  have secondBound := packed_physical_read_role_amplitude_le_one_query_charge
    secondKey (bound + 1) firstState firstBounded firstTotal
    firstEvent secondLoss secondNonnegative
    (by
      intro workspace
      exact secondInstability workspace.2)
  have firstMass := packed_physical_read_norm_squared_eq_source
    firstKey state total
  change normSquared firstState = normSquared state at firstMass
  have firstNormEq : stateNorm firstState = stateNorm state := by
    have leftSquare := state_norm_sq_eq_norm_squared firstState
    have rightSquare := state_norm_sq_eq_norm_squared state
    nlinarith [state_norm_nonnegative firstState,
      state_norm_nonnegative state]
  change stateNorm (workspaceEventProjection firstEvent firstState) ≤
    stateNorm (workspaceEventProjection event state) +
      Real.sqrt (6 * firstLoss) * stateNorm state at firstBound
  rw [firstNormEq] at secondBound
  calc
    _ ≤ stateNorm (workspaceEventProjection firstEvent firstState) +
        Real.sqrt (6 * secondLoss) * stateNorm state := secondBound
    _ ≤ stateNorm (workspaceEventProjection event state) +
        (Real.sqrt (6 * firstLoss) + Real.sqrt (6 * secondLoss)) *
          stateNorm state := by nlinarith [firstBound]

/-! A selected key may depend on an earlier classical transcript. The
transcript is an orthogonal workspace sector, never a postselected oracle
sample. These identities keep the whole controlled answer instrument in one
state and charge one physical read on each reached sector. -/

def packControlledPhysicalRead
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    VectorCmsState (Key := Key) (Counter := Counter)
      (Work := (History × Answer (Counter := Counter)) × Work) :=
  packReadFamily (fun historyAnswer : History × Answer (Counter := Counter) =>
    physicalReadBranch (selected historyAnswer.1) historyAnswer.2
      (branches historyAnswer.1))

theorem pack_controlled_physical_read_norm_squared
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : ∀ history, StandardTotal (branches history)) :
  normSquared (packControlledPhysicalRead selected branches) =
      normSquared (packReadFamily branches) := by
  unfold packControlledPhysicalRead
  conv_lhs =>
    rw [pack_read_family_norm_squared, Fintype.sum_prod_type]
  conv_rhs =>
    rw [pack_read_family_norm_squared]
  apply Finset.sum_congr rfl
  intro history _
  exact sum_physical_read_branch_norm_squared
    (selected history) (branches history) (total history)

theorem pack_controlled_physical_read_standard_total
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : ∀ history, StandardTotal (branches history)) :
    StandardTotal (packControlledPhysicalRead selected branches) := by
  unfold packControlledPhysicalRead
  apply standard_total_pack_read_family
  intro historyAnswer
  exact physical_read_branch_standard_total
    (selected historyAnswer.1) historyAnswer.2
    (branches historyAnswer.1) (total historyAnswer.1)

theorem pack_controlled_physical_read_bounded_succ
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key) (bound : Nat)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : ∀ history, BoundedState bound (branches history)) :
    BoundedState (bound + 1)
      (packControlledPhysicalRead selected branches) := by
  unfold packControlledPhysicalRead
  apply bounded_pack_read_family
  intro historyAnswer
  exact physical_read_branch_bounded_succ
    (selected historyAnswer.1) historyAnswer.2 bound
    (branches historyAnswer.1) (bounded historyAnswer.1)

/-- The database-dependent bad event is measured after each controlled
physical answer branch. The classical history chooses its key and event;
the all-branch estimate has neither a history nor answer cardinality factor.
The remaining adaptive telescope must relate these sectors to the actual
verifier workspace and compose their homogeneous amplitude estimates. -/
theorem pack_controlled_physical_read_event_mass_le_charged
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key) (bound : Nat)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : ∀ history, BoundedState bound (branches history))
    (total : ∀ history, StandardTotal (branches history))
    (event : History → Work →
      Database Key (Answer (Counter := Counter)) → Prop) :
    normSquared (workspaceEventProjection
        (packedReadEvent
          (fun historyAnswer : History × Answer (Counter := Counter) =>
            event historyAnswer.1))
        (packControlledPhysicalRead selected branches)) ≤
      ∑ history : History,
        normSquared (workspaceEventProjection
          (liftedReadEvent (event history))
          (queryState vectorPhaseSystem (bound + 1)
            (vectorFourierState
              (prepareZeroAt (selected history) (branches history))))) := by
  unfold packControlledPhysicalRead
  conv_lhs =>
    rw [pack_read_family_event_mass, Fintype.sum_prod_type]
  apply Finset.sum_le_sum
  intro history _
  exact sum_physical_read_role_mass_le_one_query_role_mass
    (selected history) bound (branches history)
    (bounded history) (total history (selected history)) (event history)

/-- Finite orthogonal-sector triangle inequality in the exact form needed
for a history-controlled read. It prevents replacing every subnormalized
branch by a unit-mass estimate, which would pay for the number of histories. -/
theorem sqrt_sum_sq_le_of_pointwise
    {History : Type} [Fintype History]
    (after before source : History → ℝ) (charge : ℝ)
    (afterNonnegative : ∀ history, 0 ≤ after history)
    (beforeNonnegative : ∀ history, 0 ≤ before history)
    (sourceNonnegative : ∀ history, 0 ≤ source history)
    (chargeNonnegative : 0 ≤ charge)
    (pointwise : ∀ history,
      after history ≤ before history + charge * source history) :
    Real.sqrt (∑ history, after history ^ 2) ≤
      Real.sqrt (∑ history, before history ^ 2) +
        charge * Real.sqrt (∑ history, source history ^ 2) := by
  let afterSq := ∑ history, after history ^ 2
  let beforeSq := ∑ history, before history ^ 2
  let sourceSq := ∑ history, source history ^ 2
  let cross := ∑ history, before history * source history
  have afterSqNonnegative : 0 ≤ afterSq :=
    Finset.sum_nonneg (fun history _ => sq_nonneg _)
  have beforeSqNonnegative : 0 ≤ beforeSq :=
    Finset.sum_nonneg (fun history _ => sq_nonneg _)
  have sourceSqNonnegative : 0 ≤ sourceSq :=
    Finset.sum_nonneg (fun history _ => sq_nonneg _)
  have localSquares : ∀ history,
      after history ^ 2 ≤
        (before history + charge * source history) ^ 2 := by
    intro history
    exact (sq_le_sq₀ (afterNonnegative history)
      (add_nonneg (beforeNonnegative history)
        (mul_nonneg chargeNonnegative (sourceNonnegative history)))).2
      (pointwise history)
  have sumSquares : afterSq ≤
      ∑ history, (before history + charge * source history) ^ 2 :=
    Finset.sum_le_sum (fun history _ => localSquares history)
  have expand :
      (∑ history, (before history + charge * source history) ^ 2) =
        beforeSq + 2 * charge * cross + charge ^ 2 * sourceSq := by
    calc
      _ = ∑ history, (before history ^ 2 +
            (2 * charge) * (before history * source history) +
            charge ^ 2 * source history ^ 2) := by
          apply Finset.sum_congr rfl
          intro history _
          ring
      _ = beforeSq + 2 * charge * cross +
          charge ^ 2 * sourceSq := by
          simp only [Finset.sum_add_distrib, ← Finset.mul_sum]
          ring
  have cauchy : cross ≤
      Real.sqrt beforeSq * Real.sqrt sourceSq := by
    exact Real.sum_mul_le_sqrt_mul_sqrt
      (Finset.univ : Finset History) before source
  have weightedCauchy := mul_le_mul_of_nonneg_left cauchy
    (show 0 ≤ 2 * charge by positivity)
  have rightNonnegative :
      0 ≤ Real.sqrt beforeSq + charge * Real.sqrt sourceSq :=
    add_nonneg (Real.sqrt_nonneg _)
      (mul_nonneg chargeNonnegative (Real.sqrt_nonneg _))
  apply (sq_le_sq₀ (Real.sqrt_nonneg _) rightNonnegative).1
  rw [Real.sq_sqrt afterSqNonnegative]
  rw [add_sq, mul_pow, Real.sq_sqrt beforeSqNonnegative,
    Real.sq_sqrt sourceSqNonnegative]
  nlinarith [sumSquares, weightedCauchy, expand]

/-- A history-controlled physical read incurs one homogeneous CMS query
charge on the entire unnormalised direct-sum state. The key and role event
may both depend on the already classical history. This does not assert that
the actual verifier's history has yet been identified with these sectors. -/
theorem pack_controlled_physical_read_role_amplitude_le
    {History : Type} [Fintype History] [DecidableEq History]
    (selected : History → Key) (bound : Nat)
    (branches : History →
      VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : ∀ history, BoundedState bound (branches history))
    (total : ∀ history, StandardTotal (branches history))
    (event : History → Work →
      Database Key (Answer (Counter := Counter)) → Prop)
    (localBound : ℝ) (localNonnegative : 0 ≤ localBound)
    (instability : ∀ history workspace,
      RealInstabilityBound (event history workspace)
        (bound + 1) localBound) :
    stateNorm (workspaceEventProjection
        (packedReadEvent
          (fun historyAnswer : History × Answer (Counter := Counter) =>
            event historyAnswer.1))
        (packControlledPhysicalRead selected branches)) ≤
      stateNorm (workspaceEventProjection
        (packedReadEvent event) (packReadFamily branches)) +
        Real.sqrt (6 * localBound) *
          stateNorm (packReadFamily branches) := by
  let after : History → ℝ := fun history =>
    stateNorm (workspaceEventProjection
      (packedReadEvent (fun _ : Answer (Counter := Counter) =>
        event history))
      (packReadFamily (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch (selected history) answer (branches history))))
  let before : History → ℝ := fun history =>
    stateNorm (workspaceEventProjection (event history) (branches history))
  let source : History → ℝ := fun history =>
    stateNorm (branches history)
  have pointwise : ∀ history,
      after history ≤ before history +
        Real.sqrt (6 * localBound) * source history := by
    intro history
    exact packed_physical_read_role_amplitude_le_one_query_charge
      (selected history) bound (branches history)
      (bounded history) (total history) (event history)
      localBound localNonnegative (instability history)
  have afterMass :
      (∑ history, after history ^ 2) =
      normSquared (workspaceEventProjection
        (packedReadEvent
          (fun historyAnswer : History × Answer (Counter := Counter) =>
            event historyAnswer.1))
        (packControlledPhysicalRead selected branches)) := by
    simp only [after, state_norm_sq_eq_norm_squared]
    unfold packControlledPhysicalRead
    conv_rhs =>
      rw [pack_read_family_event_mass, Fintype.sum_prod_type]
    apply Finset.sum_congr rfl
    intro history _
    exact pack_read_family_event_mass
      (fun _ : Answer (Counter := Counter) => event history)
      (fun answer : Answer (Counter := Counter) =>
        physicalReadBranch (selected history) answer (branches history))
  have beforeMass :
      (∑ history, before history ^ 2) =
      normSquared (workspaceEventProjection
        (packedReadEvent event) (packReadFamily branches)) := by
    simp only [before, state_norm_sq_eq_norm_squared]
    exact (pack_read_family_event_mass event branches).symm
  have sourceMass :
      (∑ history, source history ^ 2) =
      normSquared (packReadFamily branches) := by
    simp only [source, state_norm_sq_eq_norm_squared]
    exact (pack_read_family_norm_squared branches).symm
  have aggregate := sqrt_sum_sq_le_of_pointwise
    after before source (Real.sqrt (6 * localBound))
    (fun history => state_norm_nonnegative _)
    (fun history => state_norm_nonnegative _)
    (fun history => state_norm_nonnegative _)
    (Real.sqrt_nonneg _) pointwise
  rw [afterMass, beforeMass, sourceMass] at aggregate
  simpa only [sqrt_norm_squared_eq_state_norm] using aggregate

/-- Once each controlled read is identified with an actual execution step,
its homogeneous charge telescopes over the entire lifetime. The mass cap is
always relative to the original source, not a normalization of each answer
branch. No per-history or per-answer multiplier is introduced. -/
theorem homogeneous_controlled_read_telescope
    (reads : Nat) (bad mass charge : Nat → ℝ) :
    (∀ index, index < reads →
      bad (index + 1) ≤ bad index + charge index * mass index) →
    (∀ index, index < reads → mass index ≤ mass 0) →
    (∀ index, index < reads → 0 ≤ charge index) →
    bad reads ≤ bad 0 +
      (∑ index ∈ Finset.range reads, charge index) * mass 0 := by
  induction reads with
  | zero =>
      intro _ _ _
      simp
  | succ prior ih =>
      intro step massBound chargeNonnegative
      have earlierStep : ∀ index, index < prior →
          bad (index + 1) ≤ bad index + charge index * mass index := by
        intro index within
        exact step index (Nat.lt_trans within (Nat.lt_succ_self prior))
      have earlierMass : ∀ index, index < prior →
          mass index ≤ mass 0 := by
        intro index within
        exact massBound index (Nat.lt_trans within (Nat.lt_succ_self prior))
      have earlierCharge : ∀ index, index < prior →
          0 ≤ charge index := by
        intro index within
        exact chargeNonnegative index
          (Nat.lt_trans within (Nat.lt_succ_self prior))
      have previous := ih earlierStep earlierMass earlierCharge
      have lastMass := massBound prior (Nat.lt_succ_self prior)
      have lastCharge := chargeNonnegative prior (Nat.lt_succ_self prior)
      have lastTerm := mul_le_mul_of_nonneg_left lastMass lastCharge
      calc
        bad (prior + 1) ≤
            bad prior + charge prior * mass prior :=
          step prior (Nat.lt_succ_self prior)
        _ ≤ (bad 0 +
            (∑ index ∈ Finset.range prior, charge index) * mass 0) +
              charge prior * mass 0 :=
          add_le_add previous lastTerm
        _ = bad 0 +
            (∑ index ∈ Finset.range (prior + 1), charge index) *
              mass 0 := by
          rw [Finset.sum_range_succ]
          ring

/-- Exactly the same post-read mass for any event inspecting only the
original database and base workspace, not the temporary ancillary registers.
No triangle bound or claim about unmeasured outcome branches is used. -/
theorem physical_read_workspace_database_event_mass_eq_charged
    (selected : Key) (answer : Answer (Counter := Counter)) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) (total : StandardTotal state)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop) :
    normSquared (workspaceEventProjection event
        (physicalReadBranch selected answer state)) =
      normSquared (workspaceEventProjection event
        (globalDecompress
          (readoutAndRestore selected answer
            (vectorFourierInverseState
              (globalDecompress
                (queryState vectorPhaseSystem (bound + 1)
                  (vectorFourierState (prepareZeroAt selected state)))))))) := by
  rw [physical_read_branch_eq_one_charged_vector_query
    selected answer bound state bounded (total selected)]

/-- The charged CMS query uses exactly one additional compressed-database
support slot.  The later readout is not hidden inside this support claim. -/
theorem prepared_vector_query_bounded_succ
    (selected : Key) (bound : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (queryState vectorPhaseSystem (bound + 1)
        (vectorFourierState (prepareZeroAt selected state))) := by
  exact query_state_bounded_succ_of_bounded vectorPhaseSystem
    (bound + 1) bound _ (Nat.lt_succ_self bound)
    (vector_fourier_state_bounded (prepare_zero_at_bounded selected bounded))

end
end HegemonCrypto.SmallWood.SmzaRp05VectorReadCharge
