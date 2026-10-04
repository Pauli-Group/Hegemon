import SmzaRoleDomainActiveEmbedding
import SmzaStageVectorInstability
import SmzaDynamicStageLabels

/-!
# A one-role CMS bound on the original full-table execution

This file closes the event-level bridge left by exact role conditioning.  The
event mass below is defined directly by uniformly averaging the original
full oracle tables and the final original register basis.  For every fixed
other-role table, the exact `ActiveKey` run embedding identifies that mass
with the adaptive-claims projector in the reduced CMS system.  The checked
finite table equivalence then averages the pointwise CMS bound back to the
unchanged full-table execution.

The fixed table is used only to construct private contractions and fixed
advice.  It is never part of the CMS database input, and the transformed run
has exactly the original number of queries.
-/
namespace HegemonCrypto.SmallWood.SmzaRoleDomainConditioning

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsLifting
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets
open SmzaFixedAdvicePrefix
open SmzaDynamicDatabaseSoundness
open SmzaDynamicStageLabels

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option exponentiation.threshold 1024

/-! ## Uniform table/register event masses -/

/-- Uniform-table event mass, with the table input domain deliberately
separated from the adversary's register input domain.  The separation is
needed while the full-key register is stored privately in an `ActiveKey`
CMS execution. -/
def uniformTableRegisterEventMass
    {TableInput Output RegisterInput Phase Workspace : Type*}
    [Fintype TableInput] [DecidableEq TableInput] [Fintype Output]
    [Fintype RegisterInput] [Fintype Phase] [Fintype Workspace]
    (family : (TableInput → Output) →
      RegisterBasis (Input := RegisterInput) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (event : (TableInput → Output) →
      RegisterBasis (Input := RegisterInput) (Phase := Phase)
        (Workspace := Workspace) → Prop) : ℝ :=
  (∑ table : TableInput → Output,
      ∑ register, if event table register then
        Complex.normSq (family table register) else 0) /
    Fintype.card (TableInput → Output)

/-- At one register basis value, a diagonal event on a purified total-oracle
state is exactly the uniform finite-table average of that event. -/
theorem sum_database_total_family_event_eq
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (event : Database Input Output → Prop)
    (register : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace)) :
    (∑ database : Database Input Output,
        Complex.normSq
          (if event database then
            totalOracleFamilyState family
              { input := register.1
                phase := register.2.1
                workspace := register.2.2
                database := database }
          else 0)) =
      (∑ oracle : Input → Output,
          if event (totalDatabase oracle) then
            Complex.normSq (family oracle register)
          else 0) /
        Fintype.card (Input → Output) := by
  classical
  calc
    (∑ database : Database Input Output,
        Complex.normSq
          (if event database then
            totalOracleFamilyState family
              { input := register.1
                phase := register.2.1
                workspace := register.2.2
                database := database }
          else 0)) =
        ∑ database : Database Input Output,
          ∑ oracle : Input → Output,
            if event database then
              if database = totalDatabase oracle then
                Complex.normSq
                  (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
                    family oracle register)
              else 0
            else 0 := by
      apply Finset.sum_congr rfl
      intro database _
      by_cases accepted : event database
      · simp only [if_pos accepted]
        exact normSq_total_oracle_family_state_eq_sum family
          { input := register.1
            phase := register.2.1
            workspace := register.2.2
            database := database }
      · simp [accepted]
    _ = ∑ oracle : Input → Output,
          ∑ database : Database Input Output,
            if event database then
              if database = totalDatabase oracle then
                Complex.normSq
                  (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
                    family oracle register)
              else 0
            else 0 := by
      rw [Finset.sum_comm]
    _ = ∑ oracle : Input → Output,
          if event (totalDatabase oracle) then
            Complex.normSq
              (inverseSqrtOutputCard (Output := Output) ^ Fintype.card Input *
                family oracle register)
          else 0 := by
      apply Finset.sum_congr rfl
      intro oracle _
      by_cases accepted : event (totalDatabase oracle)
      · rw [if_pos accepted, Finset.sum_eq_single (totalDatabase oracle)]
        · simp [accepted]
        · intro database _ different
          simp [different]
        · simp
      · rw [if_neg accepted]
        apply Finset.sum_eq_zero
        intro database _
        by_cases same : database = totalDatabase oracle
        · subst database
          simp [accepted]
        · simp [same]
    _ = (∑ oracle : Input → Output,
          if event (totalDatabase oracle) then
            Complex.normSq (family oracle register)
          else 0) /
        Fintype.card (Input → Output) := by
      simp_rw [Complex.normSq_mul, normSq_uniform_oracle_amplitude]
      calc
        (∑ oracle : Input → Output,
            if event (totalDatabase oracle) then
              (1 / (Fintype.card (Input → Output) : ℝ)) *
                Complex.normSq (family oracle register)
            else 0) =
            (1 / (Fintype.card (Input → Output) : ℝ)) *
              ∑ oracle : Input → Output,
                if event (totalDatabase oracle) then
                  Complex.normSq (family oracle register)
                else 0 := by
          rw [Finset.mul_sum]
          apply Finset.sum_congr rfl
          intro oracle _
          by_cases accepted : event (totalDatabase oracle) <;> simp [accepted]
        _ = _ := by
          simp [div_eq_mul_inv, mul_comm]

/-- A workspace/database projector on the exact total-oracle purification is
the corresponding uniform table/register event mass. -/
theorem total_family_workspace_event_mass
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (family : OracleRegisterFamily
      (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace))
    (event : Workspace → Database Input Output → Prop) :
    normSquared
        (workspaceEventProjection event (totalOracleFamilyState family)) =
      uniformTableRegisterEventMass family
        (fun oracle register => event register.2.2 (totalDatabase oracle)) := by
  classical
  unfold normSquared workspaceEventProjection
  rw [← (databaseRegisterEquiv Input Output Phase Workspace).sum_comp
    (fun basis =>
      Complex.normSq
        (if event basis.workspace basis.database then
          totalOracleFamilyState family basis else 0))]
  rw [Fintype.sum_prod_type, Finset.sum_comm]
  unfold uniformTableRegisterEventMass
  calc
    (∑ register : RegisterBasis (Input := Input) (Phase := Phase)
          (Workspace := Workspace),
        ∑ database : Database Input Output,
          Complex.normSq
            (if event register.2.2 database then
              totalOracleFamilyState family
                { input := register.1
                  phase := register.2.1
                  workspace := register.2.2
                  database := database }
            else 0)) =
        ∑ register : RegisterBasis (Input := Input) (Phase := Phase)
            (Workspace := Workspace),
          ((∑ oracle : Input → Output,
              if event register.2.2 (totalDatabase oracle) then
                Complex.normSq (family oracle register)
              else 0) /
            Fintype.card (Input → Output)) := by
      apply Finset.sum_congr rfl
      intro register _
      exact sum_database_total_family_event_eq family
        (event register.2.2) register
    _ = ((∑ register : RegisterBasis (Input := Input) (Phase := Phase)
            (Workspace := Workspace),
          ∑ oracle : Input → Output,
            if event register.2.2 (totalDatabase oracle) then
              Complex.normSq (family oracle register)
            else 0) /
          Fintype.card (Input → Output)) := by
      rw [Finset.sum_div]
    _ = ((∑ oracle : Input → Output,
          ∑ register : RegisterBasis (Input := Input) (Phase := Phase)
              (Workspace := Workspace),
            if event register.2.2 (totalDatabase oracle) then
              Complex.normSq (family oracle register)
            else 0) /
          Fintype.card (Input → Output)) := by
      rw [Finset.sum_comm]
    _ = _ := by rfl

/-! ## Claims on the original full table -/

/-- Claims selected by an original workspace, evaluated directly on the
original full table.  Claim keys are certified members of the active domain. -/
def OriginalRoleClaimsEvent
    {Key Output Phase Workspace : Type*}
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × Output))
    (table : Key → Output)
    (register : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) : Prop :=
  enabled register.2.2 ∧
    ∀ claim ∈ claims register.2.2, table claim.1.val = claim.2

def activeRouteEnabled
    {Key Phase Workspace : Type*}
    (enabled : Workspace → Prop) :
    ActiveRouteMemory Key Phase Workspace → Prop :=
  fun memory => enabled memory.original.2.2

def activeRouteClaims
    {Key Output Phase Workspace : Type*}
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × Output)) :
    ActiveRouteMemory Key Phase Workspace →
      List (ActiveKey selected blockCap keyBytes × Output) :=
  fun memory => claims memory.original.2.2

@[simp]
theorem adaptive_claims_total_database_iff
    {Input Output Workspace : Type*}
    (enabled : Workspace → Prop)
    (claims : Workspace → List (Input × Output))
    (workspace : Workspace) (oracle : Input → Output) :
    AdaptiveClaimsEvent enabled claims workspace (totalDatabase oracle) ↔
      enabled workspace ∧
        ∀ claim ∈ claims workspace, oracle claim.1 = claim.2 := by
  simp [AdaptiveClaimsEvent, ClaimsDatabaseEvent, totalDatabase]

@[simp]
theorem active_route_claims_event_at_route_iff
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × Output))
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (register : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    (activeRouteEnabled enabled
        (activeRouteBasis system selected blockCap keyBytes dummy register).2.2 ∧
      ∀ claim ∈
          activeRouteClaims selected blockCap keyBytes claims
            (activeRouteBasis system selected blockCap keyBytes dummy register).2.2,
        active claim.1 = claim.2) ↔
      OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) register := by
  change
    (enabled register.2.2 ∧
      ∀ claim ∈ claims register.2.2, active claim.1 = claim.2) ↔
    (enabled register.2.2 ∧
      ∀ claim ∈ claims register.2.2,
        (roleTableSplit selected blockCap keyBytes).symm (active, fixed)
          claim.1.val = claim.2)
  constructor
  · rintro ⟨accepted, records⟩
    refine ⟨accepted, ?_⟩
    intro claim member
    rw [role_table_merge_active]
    exact records claim member
  · rintro ⟨accepted, records⟩
    refine ⟨accepted, ?_⟩
    intro claim member
    simpa only [role_table_merge_active] using records claim member

/-- Zero-extension preserves the exact event mass while keeping the original
full-key register in private route memory. -/
theorem active_embed_claim_event_sum
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × Output))
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    (∑ register : RegisterBasis
        (Input := ActiveKey selected blockCap keyBytes)
        (Phase := Phase) (Workspace := ActiveRouteMemory Key Phase Workspace),
      if activeRouteEnabled enabled register.2.2 ∧
          (∀ claim ∈
            activeRouteClaims selected blockCap keyBytes claims register.2.2,
              active claim.1 = claim.2) then
        Complex.normSq
          (activeRegisterEmbed system selected blockCap keyBytes dummy state register)
      else 0) =
      ∑ register : RegisterBasis (Input := Key) (Phase := Phase)
          (Workspace := Workspace),
        if OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) register then
          Complex.normSq (state register)
        else 0 := by
  classical
  calc
    (∑ register : RegisterBasis
        (Input := ActiveKey selected blockCap keyBytes)
        (Phase := Phase) (Workspace := ActiveRouteMemory Key Phase Workspace),
      if activeRouteEnabled enabled register.2.2 ∧
          (∀ claim ∈
            activeRouteClaims selected blockCap keyBytes claims register.2.2,
              active claim.1 = claim.2) then
        Complex.normSq
          (activeRegisterEmbed system selected blockCap keyBytes dummy state register)
      else 0) =
      ∑ register,
        if OnActiveRoute system selected blockCap keyBytes dummy register then
          (if activeRouteEnabled enabled register.2.2 ∧
              (∀ claim ∈
                activeRouteClaims selected blockCap keyBytes claims register.2.2,
                  active claim.1 = claim.2) then
            Complex.normSq (state register.2.2.original)
          else 0)
        else 0 := by
      apply Finset.sum_congr rfl
      intro register _
      by_cases routed : OnActiveRoute system selected blockCap keyBytes dummy register
      · simp [activeRegisterEmbed, routed]
      · simp [activeRegisterEmbed, routed]
    _ = ∑ memory : ActiveRouteMemory Key Phase Workspace,
        if activeRouteEnabled enabled
              (activeRouteBasis system selected blockCap keyBytes dummy
                memory.original).2.2 ∧
            (∀ claim ∈
              activeRouteClaims selected blockCap keyBytes claims
                (activeRouteBasis system selected blockCap keyBytes dummy
                  memory.original).2.2,
                active claim.1 = claim.2) then
          Complex.normSq (state memory.original)
        else 0 := by
      exact sum_on_active_route system selected blockCap keyBytes dummy
        (fun register =>
          if activeRouteEnabled enabled register.2.2 ∧
              (∀ claim ∈
                activeRouteClaims selected blockCap keyBytes claims register.2.2,
                  active claim.1 = claim.2) then
            Complex.normSq (state register.2.2.original)
          else 0)
    _ = ∑ memory : ActiveRouteMemory Key Phase Workspace,
        if OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))
            memory.original then
          Complex.normSq (state memory.original)
        else 0 := by
      apply Finset.sum_congr rfl
      intro memory _
      have eventEquivalence := active_route_claims_event_at_route_iff
        system selected blockCap keyBytes dummy enabled claims active fixed memory.original
      by_cases accepted :
          activeRouteEnabled enabled
              (activeRouteBasis system selected blockCap keyBytes dummy
                memory.original).2.2 ∧
            (∀ claim ∈
              activeRouteClaims selected blockCap keyBytes claims
                (activeRouteBasis system selected blockCap keyBytes dummy
                  memory.original).2.2,
                active claim.1 = claim.2)
      · have originalAccepted := eventEquivalence.mp accepted
        simp only [if_pos accepted, if_pos originalAccepted]
      · have originalRejected :
          ¬OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))
            memory.original := by
          exact fun originalAccepted => accepted (eventEquivalence.mpr originalAccepted)
        simp only [if_neg accepted, if_neg originalRejected]
    _ = _ := by
      exact (activeRouteMemoryEquiv Key Phase Workspace).sum_comp
        (fun register =>
          if OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
              ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))
              register then
            Complex.normSq (state register)
          else 0)

/-- The private embedding also preserves subnormalization of the initialized
empty-database CMS state. -/
theorem partial_random_oracle_empty_eq_state_at_database
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    partialRandomOracleState (Output := Output) ∅ registers =
      stateAtDatabase (empty : Database Input Output) registers := by
  funext basis
  unfold partialRandomOracleState stateAtDatabase
  by_cases records : RecordsExactly (Output := Output) ∅ basis.database
  · have databaseEmpty : basis.database = (empty : Database Input Output) :=
      (records_exactly_empty_iff basis.database).mp records
    simp only [if_pos records, if_pos databaseEmpty, Finset.card_empty,
      pow_zero, one_mul]
  · have databaseNotEmpty : basis.database ≠ (empty : Database Input Output) := by
      exact fun databaseEmpty => records
        ((records_exactly_empty_iff basis.database).mpr databaseEmpty)
    simp only [if_neg records, if_neg databaseNotEmpty]

theorem active_initial_subnormalized
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := Output) ∅ registers)) :
    Subnormalized
      (partialRandomOracleState (Output := Output) ∅
        (activeRegisterEmbed system selected blockCap keyBytes dummy registers)) := by
  unfold Subnormalized at normalized ⊢
  rw [partial_random_oracle_empty_eq_state_at_database,
    normSquared_stateAtDatabase, active_register_embed_normSquared,
    ← normSquared_stateAtDatabase
      (Output := Output) (database := (empty : Database Key Output)),
    ← partial_random_oracle_empty_eq_state_at_database]
  exact normalized

@[simp]
theorem active_conditioned_steps_length
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
      (Workspace := Workspace))) :
    (activeConditionedSteps system selected blockCap keyBytes dummy fixed steps).length =
      steps.length := by
  induction steps with
  | nil => rfl
  | cons step remaining inductionHypothesis =>
      simp [activeConditionedSteps, inductionHypothesis]

/-! ## Exact conditioned event identity -/

/-- For one fixed other-role table, the `ActiveKey` adaptive-claims projector
is exactly the corresponding original-register event mass. -/
theorem conditioned_projection_eq_fixed_original_mass
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
    (registers : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × Output)) :
    normSquared
        (workspaceEventProjection
          (AdaptiveClaimsEvent (activeRouteEnabled enabled)
            (activeRouteClaims selected blockCap keyBytes claims))
          (totalOracleFamilyState
            (oracleFamilyRun system
              (activeConditionedSteps system selected blockCap keyBytes dummy fixed steps)
              (fun _active =>
                activeRegisterEmbed system selected blockCap keyBytes dummy registers)))) =
      uniformTableRegisterEventMass
        (fun active : ActiveKey selected blockCap keyBytes → Output =>
          oracleFamilyRun system steps (fun _table => registers)
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)))
    (fun active register =>
          OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) register) := by
  rw [total_family_workspace_event_mass]
  unfold uniformTableRegisterEventMass
  congr 1
  apply Finset.sum_congr rfl
  intro active _
  have runIdentity :
      oracleFamilyRun system
          (activeConditionedSteps system selected blockCap keyBytes dummy fixed steps)
          (fun _active =>
            activeRegisterEmbed system selected blockCap keyBytes dummy registers) active =
        activeRegisterEmbed system selected blockCap keyBytes dummy
          (oracleFamilyRun system steps (fun _table => registers)
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))) := by
    simpa only using
      (active_oracle_family_run_eq_full_embed system selected blockCap keyBytes
        dummy fixed steps (fun _table => registers) active)
  rw [runIdentity]
  simpa only [adaptive_claims_total_database_iff] using
    active_embed_claim_event_sum system selected blockCap keyBytes dummy
      enabled claims active fixed
      (oracleFamilyRun system steps (fun _table => registers)
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)))

/-! ## Recombining the fixed tables -/

/-- Exact finite-table disintegration for an arbitrary quantum register event
mass.  This is an algebraic reindexing, not a conditional probability premise. -/
theorem uniform_full_table_mass_eq_fixed_average
    {Key Output Phase Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Output] [DecidableEq Output] [Nonempty Output]
    [Fintype Phase] [Fintype Workspace]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (family : (Key → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (event : (Key → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → Prop) :
    uniformTableRegisterEventMass family event =
      (∑ fixed : FixedOtherKey selected blockCap keyBytes → Output,
        uniformTableRegisterEventMass
          (fun active : ActiveKey selected blockCap keyBytes → Output =>
            family ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)))
          (fun active register =>
            event ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))
              register)) /
        Fintype.card (FixedOtherKey selected blockCap keyBytes → Output) := by
  let fullTableFintype : Fintype (Key → Output) := inferInstance
  let activeTableFintype :
      Fintype (ActiveKey selected blockCap keyBytes → Output) := inferInstance
  let fixedTableFintype :
      Fintype (FixedOtherKey selected blockCap keyBytes → Output) := inferInstance
  classical
  letI : Fintype (Key → Output) := fullTableFintype
  letI : Fintype (ActiveKey selected blockCap keyBytes → Output) := activeTableFintype
  letI : Fintype (FixedOtherKey selected blockCap keyBytes → Output) := fixedTableFintype
  let split := roleTableSplit (Output := Output) selected blockCap keyBytes
  have cardIdentity :
      Fintype.card (Key → Output) =
        Fintype.card (ActiveKey selected blockCap keyBytes → Output) *
          Fintype.card (FixedOtherKey selected blockCap keyBytes → Output) := by
    rw [Fintype.card_congr split, Fintype.card_prod]
  have cardIdentityReal :
      (Fintype.card (Key → Output) : ℝ) =
        (Fintype.card (ActiveKey selected blockCap keyBytes → Output) : ℝ) *
          (Fintype.card (FixedOtherKey selected blockCap keyBytes → Output) : ℝ) := by
    exact_mod_cast cardIdentity
  unfold uniformTableRegisterEventMass
  rw [cardIdentityReal]
  have reindex := (split.symm.sum_comp
    (fun table : Key → Output =>
      ∑ register, if event table register then
        Complex.normSq (family table register) else 0)).symm
  rw [reindex, Fintype.sum_prod_type, Finset.sum_comm]
  rw [← Finset.sum_div, div_div]

/-- Event mass of one selected role on the original, unconditioned, uniformly
random full table and the original full-key execution. -/
def originalRoleOracleFailureMass
    {Key Counter Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype Workspace] [DecidableEq Workspace]
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × VectorOutput Counter)) : ℝ :=
  uniformTableRegisterEventMass
    (oracleFamilyRun vectorPhaseSystem steps (fun _table => registers))
    (fun table register =>
      OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims table register)

/-! ## One-role bound on the unchanged execution -/

variable {Key Counter Label Advice Workspace : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- The checked dynamic-label CMS theorem, transported through exact role
conditioning and averaged back onto the original full-table execution.

`advice fixed` may contain deterministic data decoded from the fixed other-role
table.  The only database charged to the CMS theorem is the live `ActiveKey`
database, and `included` is a deterministic accepted-claims-to-`DynamicBad`
implication for that database. -/
theorem conditioned_role_oracle_failure_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (selected : Role) (fuel : Nat)
    (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (dummy : ActiveKey selected blockCap keyBytes)
    (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : (FixedOtherKey selected blockCap keyBytes → VectorOutput Counter) → Advice)
    (bad : Label → ActiveKey selected blockCap keyBytes →
      VectorOutput Counter → Prop)
    (epsilon : Rat) (nonnegative : 0 ≤ epsilon)
    (perLabel : ∀ value input,
      outputEventProbability (bad value input) ≤ epsilon)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey selected blockCap keyBytes × VectorOutput Counter))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀
      (fixed : FixedOtherKey selected blockCap keyBytes → VectorOutput Counter)
      (memory : ActiveRouteMemory Key (VectorOutput Counter) Workspace)
      (database : Database (ActiveKey selected blockCap keyBytes)
        (VectorOutput Counter)),
      AdaptiveClaimsEvent (activeRouteEnabled enabled)
          (activeRouteClaims selected blockCap keyBytes claims) memory database →
        DynamicBad
          (actualRoleLabel next selected fuel
            (fun key : ActiveKey selected blockCap keyBytes => keyBytes key.val)
            counter code (advice fixed)) bad database) :
    originalRoleOracleFailureMass (Key := Key) (Counter := Counter)
        (Workspace := Workspace) selected blockCap keyBytes steps registers enabled claims ≤
      oracleLoss
        (databaseLoss steps.length
          (((3 * steps.length : Rat) / (2^512 : Rat) + epsilon : Rat) : ℝ))
        ((maxClaims : ℝ)^2 /
          (Fintype.card (VectorOutput Counter) : ℝ)) := by
  classical
  unfold originalRoleOracleFailureMass
  rw [uniform_full_table_mass_eq_fixed_average selected blockCap keyBytes]
  have positive :
      (0 : ℝ) < Fintype.card
        (FixedOtherKey selected blockCap keyBytes → VectorOutput Counter) := by
    exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ positive).2
  calc
    (∑ fixed : FixedOtherKey selected blockCap keyBytes → VectorOutput Counter,
        uniformTableRegisterEventMass
          (fun active : ActiveKey selected blockCap keyBytes → VectorOutput Counter =>
            oracleFamilyRun vectorPhaseSystem steps (fun _table => registers)
              ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)))
          (fun active register =>
            OriginalRoleClaimsEvent selected blockCap keyBytes enabled claims
              ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))
              register)) ≤
      ∑ _fixed : FixedOtherKey selected blockCap keyBytes → VectorOutput Counter,
        oracleLoss
          (databaseLoss steps.length
            (((3 * steps.length : Rat) / (2^512 : Rat) + epsilon : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) := by
      apply Finset.sum_le_sum
      intro fixed _
      rw [← conditioned_projection_eq_fixed_original_mass vectorPhaseSystem selected
        blockCap keyBytes dummy fixed steps registers enabled claims]
      have activeBound := actual_role_oracle_failure_bound next children selected fuel
        (fun key : ActiveKey selected blockCap keyBytes => keyBytes key.val)
        counter code (advice fixed) bad epsilon nonnegative perLabel
        (activeConditionedSteps vectorPhaseSystem selected blockCap keyBytes dummy fixed steps)
        (activeRegisterEmbed vectorPhaseSystem selected blockCap keyBytes dummy registers)
        (active_initial_subnormalized vectorPhaseSystem selected blockCap keyBytes dummy
          registers normalized)
        (activeRouteEnabled enabled)
        (activeRouteClaims selected blockCap keyBytes claims)
        (fun memory => distinct memory.original.2.2)
        maxClaims (fun memory => claimBound memory.original.2.2)
        (included fixed)
      simpa only [active_conditioned_steps_length] using activeBound
    _ = oracleLoss
          (databaseLoss steps.length
            (((3 * steps.length : Rat) / (2^512 : Rat) + epsilon : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) *
        Fintype.card
          (FixedOtherKey selected blockCap keyBytes → VectorOutput Counter) := by
      simp [mul_comm]

end
end HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
