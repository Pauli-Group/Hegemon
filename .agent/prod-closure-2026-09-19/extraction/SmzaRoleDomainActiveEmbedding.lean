import SmzaRoleDomainConditionedRun

/-!
# Embedding a role-conditioned query into an `ActiveKey` CMS oracle

The conditioned run still carries the original full-key query register.  This
file moves that register into private workspace and exposes only `ActiveKey`
to the standard CMS oracle.  Fixed-domain branches are routed to an arbitrary
live key with the trivial Fourier phase, so they neither consult nor record an
oracle value.

The routing is an exact zero-extension isometry.  Arbitrary private
database-independent contractions are transported through it as contractions;
their proof is obtained from the original lifted-state contractivity, not from
an additional security premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRoleDomainConditioning

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation
open SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

/-! ## Register norms and database slices -/

def registerNormSquared {Input Phase Workspace : Type*}
    [Fintype Input] [Fintype Phase] [Fintype Workspace]
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) : ℝ :=
  ∑ basis, Complex.normSq (state basis)

def databaseSlice {Input Output Phase Workspace : Type*}
    (state : State Input Output Phase Workspace)
    (database : Database Input Output) :
    RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ :=
  fun basis =>
    state
      { input := basis.1
        phase := basis.2.1
        workspace := basis.2.2
        database := database }

def databaseRegisterEquiv (Input Output Phase Workspace : Type*) :
    (Database Input Output ×
      RegisterBasis (Input := Input) (Phase := Phase)
        (Workspace := Workspace)) ≃
      Basis Input Output Phase Workspace where
  toFun value :=
    { input := value.2.1
      phase := value.2.2.1
      workspace := value.2.2.2
      database := value.1 }
  invFun basis := (basis.database, basisRegisters basis)
  left_inv value := by rcases value with ⟨database, input, phase, workspace⟩; rfl
  right_inv basis := by cases basis; rfl

theorem normSquared_eq_sum_database_registerNormSquared
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (state : State Input Output Phase Workspace) :
    normSquared state =
      ∑ database : Database Input Output,
        registerNormSquared (databaseSlice state database) := by
  unfold normSquared registerNormSquared databaseSlice
  rw [← (databaseRegisterEquiv Input Output Phase Workspace).sum_comp
    (fun basis => Complex.normSq (state basis))]
  rw [Fintype.sum_prod_type]
  rfl

def stateAtDatabase {Input Output Phase Workspace : Type*}
    [DecidableEq (Database Input Output)]
    (database : Database Input Output)
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    State Input Output Phase Workspace :=
  fun basis =>
    if basis.database = database then state (basisRegisters basis) else 0

theorem normSquared_stateAtDatabase
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (database : Database Input Output)
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    normSquared (stateAtDatabase database state) = registerNormSquared state := by
  rw [normSquared_eq_sum_database_registerNormSquared]
  unfold databaseSlice stateAtDatabase registerNormSquared
  rw [Finset.sum_eq_single database]
  · simp [basisRegisters]
  · intro candidate _ different
    simp [different]
  · simp

theorem apply_stateAtDatabase
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (database : Database Input Output)
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    step.apply (stateAtDatabase database state) =
      stateAtDatabase database (step.applyRegister state) := by
  funext target
  rcases target with ⟨input, phase, workspace, targetDatabase⟩
  by_cases same : targetDatabase = database
  · subst targetDatabase
    simp [DatabaseIndependentContraction.apply,
      DatabaseIndependentContraction.applyRegister, liftRegisterKernel,
      stateAtDatabase, basisRegisters]
  · simp [DatabaseIndependentContraction.apply,
      liftRegisterKernel, stateAtDatabase, basisRegisters, same]

/-- Contractivity of the lifted full-state kernel implies contractivity of
the same kernel on adversary registers alone. -/
theorem applyRegister_normSquared_le
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    registerNormSquared (step.applyRegister state) ≤
      registerNormSquared state := by
  let database : Database Input Output := empty
  have normBound := step.contractive (stateAtDatabase database state)
  change stateNorm (step.apply (stateAtDatabase database state)) ≤
    stateNorm (stateAtDatabase database state) at normBound
  rw [apply_stateAtDatabase] at normBound
  have squared :
      stateNorm (stateAtDatabase database (step.applyRegister state)) ^ 2 ≤
        stateNorm (stateAtDatabase database state) ^ 2 := by
    nlinarith [state_norm_nonnegative
      (stateAtDatabase database (step.applyRegister state)),
      state_norm_nonnegative (stateAtDatabase database state)]
  rw [state_norm_sq_eq_norm_squared, state_norm_sq_eq_norm_squared,
    normSquared_stateAtDatabase, normSquared_stateAtDatabase] at squared
  exact squared

/-! ## The `ActiveKey` route and its zero-extension isometry -/

structure ActiveRouteMemory (Key Phase Workspace : Type*) where
  original : RegisterBasis (Input := Key) (Phase := Phase)
    (Workspace := Workspace)
deriving Fintype, DecidableEq

def activeRouteMemoryEquiv (Key Phase Workspace : Type*) :
    ActiveRouteMemory Key Phase Workspace ≃
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) where
  toFun memory := memory.original
  invFun original := ⟨original⟩
  left_inv memory := by cases memory; rfl
  right_inv _ := rfl

def activeRouteInput {Key Phase Workspace : Type*}
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    ActiveKey selected blockCap keyBytes :=
  if isActive : RoleActive selected blockCap keyBytes basis.1 then
    ⟨basis.1, isActive⟩
  else
    dummy

def activeRoutePhase {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) : Phase :=
  if RoleActive selected blockCap keyBytes basis.1 then
    basis.2.1
  else
    system.zeroPhase

def activeRouteBasis {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) :=
  (activeRouteInput selected blockCap keyBytes dummy basis,
    activeRoutePhase system selected blockCap keyBytes basis, ⟨basis⟩)

theorem active_route_basis_injective {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes) :
    Function.Injective
      (activeRouteBasis (Workspace := Workspace) system selected blockCap keyBytes dummy) := by
  intro left right same
  exact congrArg (fun basis => basis.2.2.original) same

def OnActiveRoute {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (basis : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace)) : Prop :=
  basis = activeRouteBasis system selected blockCap keyBytes dummy
    basis.2.2.original

def activeRegisterEmbed {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → ℂ :=
  fun basis =>
    if OnActiveRoute system selected blockCap keyBytes dummy basis then
      state basis.2.2.original
    else
      0

def activeRegisterRestrict {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → ℂ) :
    RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ :=
  fun basis =>
    state (activeRouteBasis system selected blockCap keyBytes dummy basis)

@[simp]
theorem active_register_embed_at_route {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    activeRegisterEmbed system selected blockCap keyBytes dummy state
        (activeRouteBasis system selected blockCap keyBytes dummy basis) =
      state basis := by
  simp [activeRegisterEmbed, OnActiveRoute, activeRouteBasis]

@[simp]
theorem active_register_restrict_embed {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    activeRegisterRestrict system selected blockCap keyBytes dummy
        (activeRegisterEmbed system selected blockCap keyBytes dummy state) =
      state := by
  funext basis
  exact active_register_embed_at_route
    system selected blockCap keyBytes dummy state basis

theorem sum_on_active_route {Key Output Phase Workspace Scalar : Type*}
    [Fintype Key] [DecidableEq Key]
    [AddCommGroup Output]
    [AddCommMonoid Scalar]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (value : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → Scalar) :
    (∑ basis, if OnActiveRoute system selected blockCap keyBytes dummy basis then
        value basis else 0) =
      ∑ memory : ActiveRouteMemory Key Phase Workspace,
        value (activeRouteBasis system selected blockCap keyBytes dummy memory.original) := by
  rw [Fintype.sum_prod_type]
  calc
    (∑ input : ActiveKey selected blockCap keyBytes,
        ∑ rest : Phase × ActiveRouteMemory Key Phase Workspace,
          if OnActiveRoute system selected blockCap keyBytes dummy (input, rest) then
            value (input, rest) else 0) =
      ∑ input : ActiveKey selected blockCap keyBytes,
        ∑ phase : Phase,
          ∑ memory : ActiveRouteMemory Key Phase Workspace,
            if OnActiveRoute system selected blockCap keyBytes dummy
                (input, phase, memory) then
              value (input, phase, memory) else 0 := by
        apply Finset.sum_congr rfl
        intro input _
        rw [Fintype.sum_prod_type]
    _ = ∑ input : ActiveKey selected blockCap keyBytes,
        ∑ memory : ActiveRouteMemory Key Phase Workspace,
          ∑ phase : Phase,
            if OnActiveRoute system selected blockCap keyBytes dummy
                (input, phase, memory) then
              value (input, phase, memory) else 0 := by
        apply Finset.sum_congr rfl
        intro input _
        exact Finset.sum_comm
    _ = ∑ memory : ActiveRouteMemory Key Phase Workspace,
        ∑ input : ActiveKey selected blockCap keyBytes,
          ∑ phase : Phase,
            if OnActiveRoute system selected blockCap keyBytes dummy
                (input, phase, memory) then
              value (input, phase, memory) else 0 := by
        exact Finset.sum_comm
    _ = _ := by
      apply Finset.sum_congr rfl
      intro memory _
      rw [Finset.sum_eq_single
        (activeRouteInput selected blockCap keyBytes dummy memory.original)]
      · rw [Finset.sum_eq_single
          (activeRoutePhase system selected blockCap keyBytes memory.original)]
        · simp [OnActiveRoute, activeRouteBasis]
        · intro phase _ different
          simp [OnActiveRoute, activeRouteBasis, different]
        · simp
      · intro input _ different
        apply Finset.sum_eq_zero
        intro phase _
        simp [OnActiveRoute, activeRouteBasis, different]
      · simp

theorem active_register_embed_normSquared {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    registerNormSquared
        (activeRegisterEmbed system selected blockCap keyBytes dummy state) =
      registerNormSquared state := by
  unfold registerNormSquared
  calc
    (∑ basis,
        Complex.normSq
          (activeRegisterEmbed system selected blockCap keyBytes dummy state basis)) =
      ∑ basis,
        if OnActiveRoute system selected blockCap keyBytes dummy basis then
          Complex.normSq (state basis.2.2.original) else 0 := by
        apply Finset.sum_congr rfl
        intro basis _
        by_cases routed : OnActiveRoute system selected blockCap keyBytes dummy basis
        · simp [activeRegisterEmbed, routed]
        · simp [activeRegisterEmbed, routed]
    _ = ∑ memory : ActiveRouteMemory Key Phase Workspace,
        Complex.normSq (state memory.original) := by
      exact sum_on_active_route system selected blockCap keyBytes dummy
        (fun basis => Complex.normSq (state basis.2.2.original))
    _ = ∑ basis, Complex.normSq (state basis) := by
      exact (activeRouteMemoryEquiv Key Phase Workspace).sum_comp
        (fun basis => Complex.normSq (state basis))

theorem active_register_restrict_normSquared_le {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (state : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → ℂ) :
    registerNormSquared
        (activeRegisterRestrict system selected blockCap keyBytes dummy state) ≤
      registerNormSquared state := by
  rw [← active_register_embed_normSquared
    (system := system) selected blockCap keyBytes dummy]
  unfold registerNormSquared
  apply Finset.sum_le_sum
  intro basis _
  by_cases routed : OnActiveRoute system selected blockCap keyBytes dummy basis
  · rw [show basis = activeRouteBasis system selected blockCap keyBytes dummy
        basis.2.2.original from routed]
    rw [active_register_embed_at_route]
    rfl
  · simp [activeRegisterEmbed, routed, Complex.normSq_nonneg]

/-! ## Transporting arbitrary private contractions -/

def transportedKernel {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (source target : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace)) : ℂ :=
  if OnActiveRoute system selected blockCap keyBytes dummy source ∧
      OnActiveRoute system selected blockCap keyBytes dummy target then
    step.kernel source.2.2.original target.2.2.original
  else
    0

theorem transported_kernel_action {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → ℂ) :
    (fun target => ∑ source, state source *
        transportedKernel system selected blockCap keyBytes dummy step source target) =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (step.applyRegister
          (activeRegisterRestrict system selected blockCap keyBytes dummy state)) := by
  funext target
  by_cases routed : OnActiveRoute system selected blockCap keyBytes dummy target
  · rw [show target = activeRouteBasis system selected blockCap keyBytes dummy
        target.2.2.original from routed]
    simp only [active_register_embed_at_route]
    unfold DatabaseIndependentContraction.applyRegister activeRegisterRestrict
    calc
      (∑ source, state source *
          transportedKernel system selected blockCap keyBytes dummy step source
            (activeRouteBasis system selected blockCap keyBytes dummy
              target.2.2.original)) =
        ∑ source,
          if OnActiveRoute system selected blockCap keyBytes dummy source then
            state source * step.kernel source.2.2.original target.2.2.original
          else 0 := by
            apply Finset.sum_congr rfl
            intro source _
            simp [transportedKernel, OnActiveRoute, activeRouteBasis]
      _ = ∑ memory : ActiveRouteMemory Key Phase Workspace,
          state (activeRouteBasis system selected blockCap keyBytes dummy
            memory.original) * step.kernel memory.original target.2.2.original :=
        sum_on_active_route system selected blockCap keyBytes dummy
          (fun source => state source *
            step.kernel source.2.2.original target.2.2.original)
      _ = ∑ source,
          state (activeRouteBasis system selected blockCap keyBytes dummy source) *
            step.kernel source target.2.2.original := by
        exact (activeRouteMemoryEquiv Key Phase Workspace).sum_comp
          (fun source =>
            state (activeRouteBasis system selected blockCap keyBytes dummy source) *
              step.kernel source target.2.2.original)
  · simp [activeRegisterEmbed, transportedKernel, routed]

theorem transported_register_normSquared_le {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : RegisterBasis
      (Input := ActiveKey selected blockCap keyBytes)
      (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) → ℂ) :
    registerNormSquared
        (fun target => ∑ source, state source *
          transportedKernel system selected blockCap keyBytes dummy step source target) ≤
      registerNormSquared state := by
  rw [transported_kernel_action]
  rw [active_register_embed_normSquared]
  exact (applyRegister_normSquared_le step _).trans
    (active_register_restrict_normSquared_le system selected blockCap keyBytes dummy state)

/-- Conjugate a private full-key contraction through the exact route.  The
new CMS database is indexed only by `ActiveKey`. -/
def transportContraction {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) :
    DatabaseIndependentContraction
      (Input := ActiveKey selected blockCap keyBytes)
      (Output := Output) (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace) where
  kernel := transportedKernel system selected blockCap keyBytes dummy step
  contractive := by
    intro state
    apply state_norm_le_of_norm_squared_le
    rw [normSquared_eq_sum_database_registerNormSquared,
      normSquared_eq_sum_database_registerNormSquared]
    apply Finset.sum_le_sum
    intro database _
    have sliceAction :
        databaseSlice
            (liftRegisterKernel
              (transportedKernel system selected blockCap keyBytes dummy step) state)
            database =
          fun target => ∑ source,
            databaseSlice state database source *
              transportedKernel system selected blockCap keyBytes dummy step source target := by
      funext target
      rfl
    rw [sliceAction]
    exact transported_register_normSquared_le
      system selected blockCap keyBytes dummy step (databaseSlice state database)

theorem transport_contraction_applyRegister_embed
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    (transportContraction system selected blockCap keyBytes dummy step).applyRegister
        (activeRegisterEmbed system selected blockCap keyBytes dummy state) =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (step.applyRegister state) := by
  change
    (fun target => ∑ source,
      activeRegisterEmbed system selected blockCap keyBytes dummy state source *
        transportedKernel system selected blockCap keyBytes dummy step source target) = _
  rw [transported_kernel_action, active_register_restrict_embed]

/-! Two private contractions separated by no oracle call remain one private
contraction.  This packages the fixed-other phase immediately before the
original inter-query step, without adding a spurious `ActiveKey` query. -/

def composeContractions {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (first second : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) :
    DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace) where
  kernel := fun source target =>
    ∑ middle, first.kernel source middle * second.kernel middle target
  contractive := by
    intro state
    have action :
        liftRegisterKernel
            (fun source target =>
              ∑ middle, first.kernel source middle * second.kernel middle target)
            state =
          second.apply (first.apply state) := by
      funext target
      unfold DatabaseIndependentContraction.apply liftRegisterKernel
      simp_rw [Finset.mul_sum]
      rw [Finset.sum_comm]
      apply Finset.sum_congr rfl
      intro middle _
      rw [Finset.sum_mul]
      apply Finset.sum_congr rfl
      intro source _
      simp only [basisRegisters]
      ring
    rw [action]
    exact (second.contractive _).trans (first.contractive _)

theorem compose_contractions_applyRegister
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (first second : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (state : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    (composeContractions first second).applyRegister state =
      second.applyRegister (first.applyRegister state) := by
  funext target
  unfold composeContractions DatabaseIndependentContraction.applyRegister
  simp_rw [Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro middle _
  rw [Finset.sum_mul]
  apply Finset.sum_congr rfl
  intro source _
  ring

/-! ## The live phase query is a standard `ActiveKey` query -/

theorem active_phase_query_at_route
    {Key Output Phase Workspace : Type*}
    [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    phaseRegisterState system active
        (activeRegisterEmbed system selected blockCap keyBytes dummy state)
        (activeRouteBasis system selected blockCap keyBytes dummy basis) =
      activeRegisterEmbed system selected blockCap keyBytes dummy
      (liveRolePhaseRegisterState system selected blockCap keyBytes active state)
        (activeRouteBasis system selected blockCap keyBytes dummy basis) := by
  unfold phaseRegisterState
  rw [active_register_embed_at_route, active_register_embed_at_route]
  by_cases isActive : RoleActive selected blockCap keyBytes basis.1
  · simp [activeRouteBasis, activeRouteInput,
      activeRoutePhase, liveRolePhaseRegisterState,
      liveRolePhaseMultiplier, isActive]
  · simp [activeRouteBasis, activeRouteInput,
      activeRoutePhase, liveRolePhaseRegisterState,
      liveRolePhaseMultiplier, isActive, system.character_zero]

/-- Exact intertwining: the controlled live full-key action is one ordinary
phase query whose CMS table is indexed only by `ActiveKey`. -/
theorem active_phase_query_embed
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    phaseRegisterState system active
        (activeRegisterEmbed system selected blockCap keyBytes dummy state) =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (liveRolePhaseRegisterState system selected blockCap keyBytes active state) := by
  funext target
  by_cases routed : OnActiveRoute system selected blockCap keyBytes dummy target
  · rw [show target = activeRouteBasis system selected blockCap keyBytes dummy
        target.2.2.original from routed]
    exact active_phase_query_at_route system selected blockCap keyBytes dummy
      active state target.2.2.original
  · simp [phaseRegisterState, activeRegisterEmbed, routed]

/-! ## Complete run on the reduced CMS input domain -/

def activeConditionedSteps
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) →
    List (DatabaseIndependentContraction
      (Input := ActiveKey selected blockCap keyBytes)
      (Output := Output) (Phase := Phase)
      (Workspace := ActiveRouteMemory Key Phase Workspace))
  | [] => []
  | step :: remaining =>
      transportContraction system selected blockCap keyBytes dummy
          (composeContractions
            (fixedOtherPhaseContraction system selected blockCap keyBytes fixed)
            step) ::
        activeConditionedSteps system selected blockCap keyBytes dummy fixed remaining

theorem active_conditioned_step_embed
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (active : ActiveKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    (transportContraction system selected blockCap keyBytes dummy
        (composeContractions
          (fixedOtherPhaseContraction system selected blockCap keyBytes fixed) step)).applyRegister
      (phaseRegisterState system active
        (activeRegisterEmbed system selected blockCap keyBytes dummy state)) =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (step.applyRegister
          ((fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister
            (liveRolePhaseRegisterState system selected blockCap keyBytes active state))) := by
  rw [active_phase_query_embed,
    transport_contraction_applyRegister_embed,
    compose_contractions_applyRegister]

/-- The standard `ActiveKey` oracle-family run is exactly the embedded
role-conditioned full-register run. -/
theorem active_oracle_family_run_eq_conditioned_embed
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)))
    (family : (ActiveKey selected blockCap keyBytes → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (active : ActiveKey selected blockCap keyBytes → Output) :
    oracleFamilyRun system
        (activeConditionedSteps system selected blockCap keyBytes dummy fixed steps)
        (fun live =>
          activeRegisterEmbed system selected blockCap keyBytes dummy (family live)) active =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed steps family
          active) := by
  induction steps generalizing family with
  | nil =>
      rfl
  | cons step remaining inductionHypothesis =>
      rw [activeConditionedSteps, oracleFamilyRun,
        roleConditionedOracleFamilyRun]
      calc
        oracleFamilyRun system
            (activeConditionedSteps system selected blockCap keyBytes dummy fixed remaining)
            (fun live =>
              (transportContraction system selected blockCap keyBytes dummy
                (composeContractions
                  (fixedOtherPhaseContraction system selected blockCap keyBytes fixed)
                  step)).applyRegister
                (phaseRegisterState system live
                  (activeRegisterEmbed system selected blockCap keyBytes dummy
                    (family live)))) active =
          oracleFamilyRun system
            (activeConditionedSteps system selected blockCap keyBytes dummy fixed remaining)
            (fun live =>
              activeRegisterEmbed system selected blockCap keyBytes dummy
                (step.applyRegister
                  ((fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister
                    (liveRolePhaseRegisterState system selected blockCap keyBytes live
                      (family live))))) active := by
            apply congrArg
              (fun nextFamily =>
                oracleFamilyRun system
                  (activeConditionedSteps system selected blockCap keyBytes dummy fixed remaining)
                  nextFamily active)
            funext live
            exact active_conditioned_step_embed system selected blockCap keyBytes dummy fixed
              step live (family live)
        _ = _ := inductionHypothesis _

/-- End-to-end execution identity.  The left side uses a standard CMS oracle
whose database input is only `ActiveKey`; the right side is the original
full-table phase run after fixing the independent other-role table. -/
theorem active_oracle_family_run_eq_full_embed
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)))
    (family : (Key → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (active : ActiveKey selected blockCap keyBytes → Output) :
    oracleFamilyRun system
        (activeConditionedSteps system selected blockCap keyBytes dummy fixed steps)
        (fun live =>
          activeRegisterEmbed system selected blockCap keyBytes dummy
            (family ((roleTableSplit selected blockCap keyBytes).symm (live, fixed)))) active =
      activeRegisterEmbed system selected blockCap keyBytes dummy
        (oracleFamilyRun system steps family
          ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))) := by
  rw [active_oracle_family_run_eq_conditioned_embed]
  rw [oracle_family_run_eq_role_conditioned]

end
end HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
