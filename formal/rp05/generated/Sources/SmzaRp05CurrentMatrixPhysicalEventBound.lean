import SmzaRp05CurrentMatrixRoleEvent
import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05CurrentPiopRoleEvents
import SmzaRp05ConditionedEventJoin
import SmzaConditionedRoleOracleBound
import SmzaRp05VectorReadCharge

/-! # Current DECS-matrix event on the original quantum execution

The event uses the current 406-map prefix decoder and the current contiguous
DECS-matrix sampler. Its original full-table mass is obtained by the same
active/fixed-table disintegration used for the current PIOP events. The only
semantic premise is explicit deterministic inclusion from retained claims.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMatrixPhysicalEventBound

abbrev RawInput := V8SmzaOracleParser.RawInput

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open SmzaDynamicOracleExecution
open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05CurrentSourceRoleEvent
open SmzaRp05CurrentPiopRoleEvents
open SmzaRp05CurrentMatrixRoleEvent
open SmzaRp04RoleBadCells
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaRp05CurrentRoleLabels SmzaRp05ActiveFiberEvent
open SmzaRp05ChallengeRecordErasure SmzaRp04StatementRecordFilter
open SmzaRp05AdaptiveDynamicBad SmzaRp04AuthorizedLabelTransport
open SmzaRp05TracePrefixes SmzaRp04McaRoleCells
open SmzaRp05CurrentMaxAgreementSelectedStage SmzaRp04RawRoleSampling
open SmzaRoleDomainConditioning
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRawDatabaseRecords V8Smz9CoherentVectorMerkle
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentMerkleGeometry
open SmzaRp05VectorReadCharge (VectorCmsState)
open SmzaRp04CompleteRawRoleCells
open SmzaRp04RawMcaSampling
open SmzaDynamicDatabaseSoundness
open SmzaRp05ActiveFiberEvent

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

/-- Current-map DECS-matrix dynamic-label probability on the same
total-oracle family execution. The project loss is derived from the actual
current matrix instability theorem; the claim penalty remains C²/M. -/
theorem current_matrix_role_claims_oracle_mass_le
    {Key Counter Work : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (enabled : Work → Prop)
    (claims : Work → List (Key × VectorOutput Counter))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀ workspace database,
      AdaptiveClaimsEvent enabled claims workspace database →
        currentSourceMatrixRoleEvent406 model ns keyBytes counter routes advice
          outerFuel innerFuel authorized database) :
    normSquared (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
      (totalOracleFamilyState
        (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)))) ≤
      oracleLoss
        (databaseLoss steps.length
          (((6 * steps.length : Rat) / (2^512 : Rat) +
            currentMatrixLoss : Rat) : ℝ))
        ((maxClaims : ℝ)^2 /
          (Fintype.card (VectorOutput Counter) : ℝ)) := by
  classical
  let property := currentSourceMatrixRoleEvent406 model ns keyBytes counter routes
    advice outerFuel innerFuel authorized
  let initial := partialRandomOracleState
    (Output := VectorOutput Counter) ∅ registers
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let finalState := rawRun vectorPhaseSystem steps.length blind initial
  have initialBounded : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have capacity : blind.length ≤ steps.length := by simp [blind]
  have bounded : BoundedState steps.length finalState :=
    raw_run_bounded_of_bounded vectorPhaseSystem steps.length blind initial 0
      (by simpa using capacity) initialBounded
  have finalNormalized : Subnormalized finalState :=
    raw_run_subnormalized_of_bounded vectorPhaseSystem steps.length blind initial 0
      (by simpa using capacity) initialBounded normalized
  have instability : RealInstabilityBound property steps.length
      (((6 * steps.length : Rat) / (2^512 : Rat) +
        currentMatrixLoss : Rat) : ℝ) := by
    simpa [property] using
      (current_source_matrix_role_instability_406 model ns keyBytes counter routes
        advice outerFuel innerFuel steps.length authorized).toReal
  have initiallyOutside : project property steps.length initial = 0 := by
    funext basis
    by_cases records : RecordsExactly
        (Output := VectorOutput Counter) ∅ basis.database
    · have same := (records_exactly_empty_iff basis.database).mp records
      have outside : ¬ property (empty : Database Key (VectorOutput Counter)) := by
        change ¬ currentSourceMatrixRoleEvent406 model ns keyBytes counter routes advice
          outerFuel innerFuel authorized
          (empty : Database Key (VectorOutput Counter))
        unfold currentSourceMatrixRoleEvent406 currentMatrixRoleEvent406
          roleEvent DynamicBad
        rintro ⟨key, output, recorded, _bad⟩
        simp at recorded
      simp [project, same, size_empty, outside]
    · simp [project, initial, partialRandomOracleState, records]
  have databaseBound : normSquared (project property steps.length finalState) ≤
      databaseLoss steps.length
        (((6 * steps.length : Rat) / (2^512 : Rat) +
          currentMatrixLoss : Rat) : ℝ) := by
    have result := raw_database_game_probability_le vectorPhaseSystem property
      steps.length blind initial instability capacity initialBounded normalized
      initiallyOutside
    simpa [finalState, databaseLoss, blind] using result
  have bridged := adaptive_claims_probability_le finalState
    (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers))
    (compressed_run_is_uniform_random_oracle_purification
      vectorPhaseSystem steps.length steps registers le_rfl)
    enabled claims distinct maxClaims claimBound property included
    steps.length bounded finalNormalized
    (databaseLoss steps.length
      (((6 * steps.length : Rat) / (2^512 : Rat) +
        currentMatrixLoss : Rat) : ℝ)) databaseBound
  simpa only [div_eq_mul_inv, one_div, one_mul] using bridged

/-- Average the current DECS-matrix claims event over the original uniformly
random full oracle table. This is unnormalised original event mass, not a
conditional-slice probability. -/
theorem current_matrix_role_original_mass_le
    {Key Counter Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype Workspace] [DecidableEq Workspace]
    [Nonempty (VectorOutput Counter)]
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (blockCap : Role → Nat)
    (dummy : ActiveKey .decsMatrix blockCap keyBytes)
    (advice : (FixedOtherKey .decsMatrix blockCap keyBytes →
        VectorOutput Counter) → AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (enabled : Workspace → Prop)
    (claims : Workspace →
      List (ActiveKey .decsMatrix blockCap keyBytes × VectorOutput Counter))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀
      (fixed : FixedOtherKey .decsMatrix blockCap keyBytes → VectorOutput Counter)
      (memory : ActiveRouteMemory Key (VectorOutput Counter) Workspace)
      (database : Database (ActiveKey .decsMatrix blockCap keyBytes)
        (VectorOutput Counter)),
      AdaptiveClaimsEvent (activeRouteEnabled enabled)
          (activeRouteClaims .decsMatrix blockCap keyBytes claims) memory database →
        currentSourceMatrixRoleEvent406 model ns
          (fun key => keyBytes key.val) counter routes (advice fixed)
          outerFuel innerFuel authorized database) :
    originalRoleOracleFailureMass (Key := Key) (Counter := Counter)
        (Workspace := Workspace) .decsMatrix blockCap keyBytes steps registers
        enabled claims ≤
      oracleLoss
        (databaseLoss steps.length
          (((6 * steps.length : Rat) / (2^512 : Rat) +
            currentMatrixLoss : Rat) : ℝ))
        ((maxClaims : ℝ)^2 /
          (Fintype.card (VectorOutput Counter) : ℝ)) := by
  classical
  unfold originalRoleOracleFailureMass
  rw [uniform_full_table_mass_eq_fixed_average .decsMatrix blockCap keyBytes]
  have positive : (0 : ℝ) < Fintype.card
      (FixedOtherKey .decsMatrix blockCap keyBytes → VectorOutput Counter) := by
    exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ positive).2
  calc
    (∑ fixed : FixedOtherKey .decsMatrix blockCap keyBytes → VectorOutput Counter,
        uniformTableRegisterEventMass
          (fun active : ActiveKey .decsMatrix blockCap keyBytes → VectorOutput Counter =>
            oracleFamilyRun vectorPhaseSystem steps (fun _table => registers)
              ((roleTableSplit .decsMatrix blockCap keyBytes).symm (active, fixed)))
          (fun active register =>
            OriginalRoleClaimsEvent .decsMatrix blockCap keyBytes enabled claims
              ((roleTableSplit .decsMatrix blockCap keyBytes).symm (active, fixed))
              register)) ≤
      ∑ _fixed : FixedOtherKey .decsMatrix blockCap keyBytes → VectorOutput Counter,
        oracleLoss
          (databaseLoss steps.length
            (((6 * steps.length : Rat) / (2^512 : Rat) +
              currentMatrixLoss : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) := by
      apply Finset.sum_le_sum
      intro fixed _
      rw [← conditioned_projection_eq_fixed_original_mass vectorPhaseSystem
        .decsMatrix blockCap keyBytes dummy fixed steps registers enabled claims]
      have activeBound := current_matrix_role_claims_oracle_mass_le
        (Key := ActiveKey .decsMatrix blockCap keyBytes)
        (Counter := Counter)
        (Work := ActiveRouteMemory Key (VectorOutput Counter) Workspace)
        (model := model) (ns := ns)
        (keyBytes := fun key => keyBytes key.val) (counter := counter)
        (routes := routes) (advice := advice fixed)
        (outerFuel := outerFuel) (innerFuel := innerFuel)
        (authorized := authorized)
        (steps := activeConditionedSteps vectorPhaseSystem .decsMatrix
          blockCap keyBytes dummy fixed steps)
        (registers := activeRegisterEmbed vectorPhaseSystem .decsMatrix
          blockCap keyBytes dummy registers)
        (normalized := active_initial_subnormalized vectorPhaseSystem .decsMatrix
          blockCap keyBytes dummy registers normalized)
        (enabled := activeRouteEnabled enabled)
        (claims := activeRouteClaims .decsMatrix blockCap keyBytes claims)
        (distinct := fun memory => distinct memory.original.2.2)
        (maxClaims := maxClaims)
        (claimBound := fun memory => claimBound memory.original.2.2)
        (included := included fixed)
      simpa only [active_conditioned_steps_length] using activeBound
    _ = oracleLoss
          (databaseLoss steps.length
            (((6 * steps.length : Rat) / (2^512 : Rat) +
              currentMatrixLoss : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) *
        Fintype.card
          (FixedOtherKey .decsMatrix blockCap keyBytes → VectorOutput Counter) := by
      simp [mul_comm]

/-- Select the current 406-map event for each of the four verifier roles.
The matrix and sample DECS roles use their current source-label compilers;
the two PIOP roles use the current decoded-prefix compiler. -/
def currentRoleEvent406For
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) :
    Role → Database Key (VectorOutput Counter) → Prop
  | .decsMatrix => currentSourceMatrixRoleEvent406 model ns keyBytes counter
      routes (advice .decsMatrix) outerFuel innerFuel authorized
  | .piopMatrix => currentPiopRoleEvent406 model ns keyBytes counter routes
      .matrix (advice .piopMatrix) outerFuel innerFuel authorized
  | .piopOpening => currentPiopRoleEvent406 model ns keyBytes counter routes
      .opening (advice .piopOpening) outerFuel innerFuel authorized
  | .decsSample => currentSourceRoleEvent406 model ns keyBytes counter routes
      (advice .decsSample) outerFuel innerFuel authorized

/-- The current four-role union is bounded by the sum of the four event
masses on one and the same unnormalised CMS state. This is only the finite
projector union step; it does not identify any role event with a verifier
failure or replace a physical Born state. -/
theorem current_any_role_event406_mass_le_sum
    {Key Counter Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : (role : Role) → AllEarlierTables model role)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (workspaceEventProjection
      (fun _ database => ∃ role,
        currentRoleEvent406For model ns keyBytes counter routes advice
          outerFuel innerFuel authorized role database) state) ≤
      ∑ role : Role, normSquared (workspaceEventProjection
        (fun _ database => currentRoleEvent406For model ns keyBytes counter
          routes advice outerFuel innerFuel authorized role database) state) := by
  classical
  unfold normSquared workspaceEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases anyRole : ∃ role,
      currentRoleEvent406For model ns keyBytes counter routes advice
        outerFuel innerFuel authorized role basis.database
  · obtain ⟨role, selected⟩ := anyRole
    have anyRoleWitness : ∃ chosen,
        currentRoleEvent406For model ns keyBytes counter routes advice
          outerFuel innerFuel authorized chosen basis.database :=
      ⟨role, selected⟩
    have lower := Finset.single_le_sum
      (s := Finset.univ)
      (f := fun chosen : Role => Complex.normSq
        (if currentRoleEvent406For model ns keyBytes counter routes advice
            outerFuel innerFuel authorized chosen basis.database then
          state basis else 0))
      (fun chosen _ => Complex.normSq_nonneg _)
      (Finset.mem_univ role)
    simpa [anyRoleWitness, selected] using lower
  · simp only [if_neg anyRole, Complex.normSq_zero]
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMatrixPhysicalEventBound
