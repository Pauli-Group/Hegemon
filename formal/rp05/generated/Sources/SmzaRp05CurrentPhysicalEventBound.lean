import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05ConditionedEventJoin
import SmzaConditionedRoleOracleBound

/-! # Same-event restriction and fixed-table current-role bridge

The current-map source-role event is evaluated on the exact same merged
physical table as its sparse ActiveKey restriction.  The proof uses the
filtered-trace equality for the fixed fiber; it does not infer quantum
freshness from absence in a classical log.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalEventBound

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

open scoped Classical BigOperators
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open SmzaDynamicOracleExecution
open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp04RoleBadCells
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05CurrentSourceRoleEvent
open SmzaDynamicDatabaseSoundness
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentRoleLabels SmzaRp05ActiveFiberEvent
open SmzaRp05ChallengeRecordErasure SmzaRp04StatementRecordFilter
open SmzaRp05AdaptiveDynamicBad SmzaRp04AuthorizedLabelTransport
open SmzaRp05TracePrefixes SmzaRp04McaRoleCells
open SmzaRp05CurrentMaxAgreementSelectedStage SmzaRp04RawRoleSampling
open SmzaRoleDomainConditioning
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRawDatabaseRecords V8Smz9CoherentVectorMerkle
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentMerkleGeometry

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

variable {Key Counter : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]

def sourceContext406 (model : RelationModel)
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte)) :
    Context (Key := Key) (Counter := Counter) (BaseWork := Unit) :=
  { model := model, leafNamespace := ns, keyBytes := keyBytes,
    counter := counter, routes := routes, role := .decsSample,
    advice := advice, outerFuel := outerFuel, innerFuel := innerFuel,
    authorizedOf := fun _ => authorized }

/-- The literal 406-map source label on a trace extracted from one database. -/
def sourceInputLabel406
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := Unit))
    (advice : AllEarlierTables ctx.model .decsSample)
    (authorized : Finset (List Byte))
    (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (input : RawInput) :=
  completeFilteredLabel (globalLeafStatement ctx.leafNamespace)
    (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (targetOfRaw .decsSample)
      (fun _ trace => preambleFromTrace ctx.leafNamespace .decsSample trace)
      ctx.outerFuel)
    (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun _ key => targetOfRaw .decsSample key)
      (fun statement _ trace => currentSourceRoleLabelsFromBytes406
        ctx.model ctx.leafNamespace advice statement trace)
      ctx.innerFuel)
    authorized records input

theorem source_input_label_merged_eq_active406
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := Unit))
    (advice : AllEarlierTables ctx.model .decsSample)
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (authorized : Finset (List Byte)) (input : RawInput) :
    sourceInputLabel406 ctx advice authorized
      (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
        (mergeFixedActive ctx blockCap fixed active)) input =
    sourceInputLabel406 ctx advice authorized
      (rawRecords (fun key => ctx.keyBytes key.val)
        (vectorOutputBytes ctx.counter) active) input := by
  have outer : extract (globalOnlineNext ctx.leafNamespace)
      (nonleafFilter (globalLeafStatement ctx.leafNamespace)
        (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
          (mergeFixedActive ctx blockCap fixed active))) ctx.outerFuel
      (targetOfRaw .decsSample input).1 (targetOfRaw .decsSample input).2 =
    extract (globalOnlineNext ctx.leafNamespace)
      (nonleafFilter (globalLeafStatement ctx.leafNamespace)
        (rawRecords (fun key => ctx.keyBytes key.val)
          (vectorOutputBytes ctx.counter) active)) ctx.outerFuel
      (targetOfRaw .decsSample input).1 (targetOfRaw .decsSample input).2 := by
    unfold nonleafFilter
    convert extract_merged_filtered_eq_active ctx blockCap fixed active
      (fun raw => globalLeafStatement ctx.leafNamespace raw = none)
      ctx.outerFuel (targetOfRaw .decsSample input).1
        (targetOfRaw .decsSample input).2 using 1 <;> congr 1 <;> ext record <;> simp
  unfold sourceInputLabel406 completeFilteredLabel rawTraceDecoder
    statementTraceDecoder nonleafFilter oneStatementFilter
  unfold nonleafFilter at outer
  rw [outer]
  simp only [extract_merged_filtered_eq_active]

/-- Exact 406-map event equivalence across the actual fixed-role fiber.  The
selected-role witness transfers because a decs-sample key is active; its
current source label agrees by the filtered trace equality above. -/
theorem current_source_role_event_merged_iff_active406
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (blockCap : Role → Nat)
    (fixed : FixedTable
      (sourceContext406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized) blockCap)
    (active : ActiveDatabase
      (sourceContext406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized) blockCap) :
    currentSourceRoleEvent406 model ns keyBytes counter routes advice
      outerFuel innerFuel authorized
      (mergeFixedActive (sourceContext406 model ns keyBytes counter routes advice
        outerFuel innerFuel authorized) blockCap fixed active) ↔
    currentSourceRoleEvent406 model ns (fun key => keyBytes key.val) counter
      routes advice outerFuel innerFuel authorized active := by
  let ctx := sourceContext406 model ns keyBytes counter routes advice
    outerFuel innerFuel authorized
  constructor
  · rintro ⟨key, output, present, selected, bad⟩
    obtain ⟨query, parsed, sameRole⟩ := selected
    have live := selected_role_is_active .decsSample blockCap keyBytes
      key query parsed sameRole
    refine ⟨⟨key, live⟩, output, ?_, ⟨query, parsed, sameRole⟩, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active ⟨key, live⟩).symm.trans present
    · have same := source_input_label_merged_eq_active406 ctx advice blockCap fixed active
        authorized (keyBytes key)
      exact (congrArg (fun label => AuthorizedBad
        (fun _ label output => currentSourceRoleBad406 model routes label output)
        label output) same).mp bad
  · rintro ⟨key, output, present, selected, bad⟩
    refine ⟨key.val, output, ?_, selected, ?_⟩
    · exact (merge_fixed_active_at_active ctx blockCap fixed active key).trans present
    · have same := source_input_label_merged_eq_active406 ctx advice blockCap fixed active
        authorized (keyBytes key.val)
      exact (congrArg (fun label => AuthorizedBad
        (fun _ label output => currentSourceRoleBad406 model routes label output)
        label output) same).mpr bad

/-- Same-run raw-CMS database-game bound for the current-map source-role
event, with its instability derived from the actual current 406-map label
decoder.  The initial state is the standard empty CMS database; no event-mass
premise is supplied by the caller. -/
theorem current_source_role_event_mass_after_quantum_producer_le
    {Key Counter Work : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (stepsWithin : steps.length ≤ queryBound)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared (workspaceEventProjection
      (fun _ : Work => currentSourceRoleEvent406 model ns keyBytes counter
        routes advice outerFuel innerFuel authorized)
      (rawRun vectorPhaseSystem queryBound
        (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      6 * (steps.length : ℝ)^2 *
        (((6 * queryBound : Rat) / (2^512 : Rat) +
          smallSupportLoss + roleLoss .decsSample : Rat) : ℝ) := by
  classical
  let property := currentSourceRoleEvent406 model ns keyBytes counter routes
    advice outerFuel innerFuel authorized
  let initial := partialRandomOracleState
    (Output := VectorOutput Counter) ∅ registers
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let state := rawRun vectorPhaseSystem queryBound blind initial
  have initialBounded : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have capacity : blind.length ≤ queryBound := by
    simpa [blind] using stepsWithin
  have bounded : BoundedState queryBound state := by
    simpa [state] using
      raw_run_bounded_of_bounded vectorPhaseSystem queryBound blind initial 0
        (by simpa using capacity) initialBounded
  have initiallyOutside : project property queryBound initial = 0 := by
    funext basis
    by_cases records : RecordsExactly
        (Output := VectorOutput Counter) ∅ basis.database
    · have same := (records_exactly_empty_iff basis.database).mp records
      have noRole : ¬ property basis.database := by
        rw [same]
        change ¬ currentSourceRoleEvent406 model ns keyBytes counter routes advice
          outerFuel innerFuel authorized
          (empty : Database Key (VectorOutput Counter))
        unfold currentSourceRoleEvent406 roleEvent DynamicBad
        rintro ⟨key, output, recorded, _bad⟩
        simp at recorded
      simp [project, noRole]
    · have initialZero : initial basis = 0 := by
        simp [initial, partialRandomOracleState, records]
      simp [project, initialZero]
  have instability :
      RealInstabilityBound property queryBound
        (((6 * queryBound : Rat) / (2^512 : Rat) +
          smallSupportLoss + roleLoss .decsSample : Rat) : ℝ) := by
    simpa [property] using
      (current_source_role_instability_406 model ns keyBytes counter routes
        advice outerFuel innerFuel queryBound authorized).toReal
  have databaseBound := raw_database_game_probability_le vectorPhaseSystem property
    queryBound blind initial instability (by simpa [blind] using stepsWithin)
    initialBounded normalized initiallyOutside
  have eventBelowProject :
      normSquared (workspaceEventProjection (fun _ : Work => property) state) ≤
        normSquared (project property queryBound state) :=
    workspace_event_norm_squared_le_project (fun _ : Work => property) property
      (by intro _ _ event; exact event) queryBound state bounded
  calc
    normSquared (workspaceEventProjection
        (fun _ : Work => currentSourceRoleEvent406 model ns keyBytes counter
          routes advice outerFuel innerFuel authorized)
        (rawRun vectorPhaseSystem queryBound blind initial)) =
      normSquared (workspaceEventProjection (fun _ : Work => property) state) := by
        simp [property, state]
    _ ≤ normSquared (project property queryBound state) := eventBelowProject
    _ ≤ 6 * (steps.length : ℝ)^2 *
          (((6 * queryBound : Rat) / (2^512 : Rat) +
            smallSupportLoss + roleLoss .decsSample : Rat) : ℝ) := by
        simpa [blind] using databaseBound

/-- Current 406-map dynamic-label probability on the same total-oracle
family execution.  The raw CMS project bound is derived from the current
source-label instability theorem, then the standard purification bridge
converts it to the accepted-claims event.  The only semantic premise is the
explicit deterministic `included` implication supplied by source extraction.
-/
theorem current_source_role_claims_oracle_mass_le
    {Key Counter Work : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : Namespace) (keyBytes : Key → RawInput)
    (counter : Counter) (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
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
        currentSourceRoleEvent406 model ns keyBytes counter routes advice
          outerFuel innerFuel authorized database) :
    normSquared (workspaceEventProjection (AdaptiveClaimsEvent enabled claims)
      (totalOracleFamilyState
        (oracleFamilyRun vectorPhaseSystem steps (fun _ => registers)))) ≤
      oracleLoss
        (databaseLoss steps.length
          (((6 * steps.length : Rat) / (2^512 : Rat) +
            smallSupportLoss + roleLoss .decsSample : Rat) : ℝ))
        ((maxClaims : ℝ)^2 /
          (Fintype.card (VectorOutput Counter) : ℝ)) := by
  classical
  let property := currentSourceRoleEvent406 model ns keyBytes counter routes
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
        smallSupportLoss + roleLoss .decsSample : Rat) : ℝ) := by
    simpa [property] using
      (current_source_role_instability_406 model ns keyBytes counter routes
        advice outerFuel innerFuel steps.length authorized).toReal
  have initiallyOutside : project property steps.length initial = 0 := by
    funext basis
    by_cases records : RecordsExactly
        (Output := VectorOutput Counter) ∅ basis.database
    · have same := (records_exactly_empty_iff basis.database).mp records
      have outside : ¬ property (empty : Database Key (VectorOutput Counter)) := by
        change ¬ currentSourceRoleEvent406 model ns keyBytes counter routes advice
          outerFuel innerFuel authorized
          (empty : Database Key (VectorOutput Counter))
        unfold currentSourceRoleEvent406 roleEvent DynamicBad
        rintro ⟨key, output, recorded, _bad⟩
        simp at recorded
      simp [project, same, size_empty, outside]
    · simp [project, initial, partialRandomOracleState, records]
  have databaseBound : normSquared (project property steps.length finalState) ≤
      databaseLoss steps.length
        (((6 * steps.length : Rat) / (2^512 : Rat) +
          smallSupportLoss + roleLoss .decsSample : Rat) : ℝ) := by
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
        smallSupportLoss + roleLoss .decsSample : Rat) : ℝ)) databaseBound
  simpa only [div_eq_mul_inv, one_div, one_mul] using bridged

/-- The same current-source event bound averaged over the original uniformly
random full table.  For each fixed complementary table, the adaptive claims
event is run on the matching active-key quantum execution; the exact
conditioned projection identity and finite-table disintegration restore the
original, unconditioned Born mass.  No normalized conditional-probability
assumption or replacement execution is introduced.
-/
theorem current_source_role_original_mass_le
    {Key Counter Workspace : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype Workspace] [DecidableEq Workspace]
    [Nonempty (VectorOutput Counter)]
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (blockCap : Role → Nat)
    (dummy : ActiveKey .decsSample blockCap keyBytes)
    (advice : (FixedOtherKey .decsSample blockCap keyBytes →
        VectorOutput Counter) → AllEarlierTables model .decsSample)
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
      List (ActiveKey .decsSample blockCap keyBytes × VectorOutput Counter))
    (distinct : ∀ workspace, ((claims workspace).map Prod.fst).Nodup)
    (maxClaims : Nat)
    (claimBound : ∀ workspace, (claims workspace).length ≤ maxClaims)
    (included : ∀
      (fixed : FixedOtherKey .decsSample blockCap keyBytes → VectorOutput Counter)
      (memory : ActiveRouteMemory Key (VectorOutput Counter) Workspace)
      (database : Database (ActiveKey .decsSample blockCap keyBytes)
        (VectorOutput Counter)),
      AdaptiveClaimsEvent (activeRouteEnabled enabled)
          (activeRouteClaims .decsSample blockCap keyBytes claims) memory database →
        currentSourceRoleEvent406 model ns
          (fun key => keyBytes key.val) counter routes (advice fixed)
          outerFuel innerFuel authorized database) :
    originalRoleOracleFailureMass (Key := Key) (Counter := Counter)
        (Workspace := Workspace) .decsSample blockCap keyBytes steps registers
        enabled claims ≤
      oracleLoss
        (databaseLoss steps.length
          (((6 * steps.length : Rat) / (2^512 : Rat) +
            smallSupportLoss + roleLoss .decsSample : Rat) : ℝ))
        ((maxClaims : ℝ)^2 /
          (Fintype.card (VectorOutput Counter) : ℝ)) := by
  classical
  unfold originalRoleOracleFailureMass
  rw [uniform_full_table_mass_eq_fixed_average .decsSample blockCap keyBytes]
  have positive :
      (0 : ℝ) < Fintype.card
        (FixedOtherKey .decsSample blockCap keyBytes → VectorOutput Counter) := by
    exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ positive).2
  calc
    (∑ fixed : FixedOtherKey .decsSample blockCap keyBytes → VectorOutput Counter,
        uniformTableRegisterEventMass
          (fun active : ActiveKey .decsSample blockCap keyBytes → VectorOutput Counter =>
            oracleFamilyRun vectorPhaseSystem steps (fun _table => registers)
              ((roleTableSplit .decsSample blockCap keyBytes).symm (active, fixed)))
          (fun active register =>
            OriginalRoleClaimsEvent .decsSample blockCap keyBytes enabled claims
              ((roleTableSplit .decsSample blockCap keyBytes).symm (active, fixed))
              register)) ≤
      ∑ _fixed : FixedOtherKey .decsSample blockCap keyBytes → VectorOutput Counter,
        oracleLoss
          (databaseLoss steps.length
            (((6 * steps.length : Rat) / (2^512 : Rat) +
              smallSupportLoss + roleLoss .decsSample : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) := by
      apply Finset.sum_le_sum
      intro fixed _
      rw [← conditioned_projection_eq_fixed_original_mass vectorPhaseSystem
        .decsSample blockCap keyBytes dummy fixed steps registers enabled claims]
      have activeBound := current_source_role_claims_oracle_mass_le
        (Key := ActiveKey .decsSample blockCap keyBytes)
        (Counter := Counter)
        (Work := ActiveRouteMemory Key (VectorOutput Counter) Workspace)
        (model := model) (ns := ns)
        (keyBytes := fun key => keyBytes key.val) (counter := counter)
        (routes := routes) (advice := advice fixed)
        (outerFuel := outerFuel) (innerFuel := innerFuel)
        (authorized := authorized)
        (steps := activeConditionedSteps vectorPhaseSystem .decsSample
          blockCap keyBytes dummy fixed steps)
        (registers := activeRegisterEmbed vectorPhaseSystem .decsSample
          blockCap keyBytes dummy registers)
        (normalized := active_initial_subnormalized vectorPhaseSystem .decsSample
          blockCap keyBytes dummy registers normalized)
        (enabled := activeRouteEnabled enabled)
        (claims := activeRouteClaims .decsSample blockCap keyBytes claims)
        (distinct := fun memory => distinct memory.original.2.2)
        (maxClaims := maxClaims)
        (claimBound := fun memory => claimBound memory.original.2.2)
        (included := included fixed)
      simpa only [active_conditioned_steps_length] using activeBound
    _ = oracleLoss
          (databaseLoss steps.length
            (((6 * steps.length : Rat) / (2^512 : Rat) +
              smallSupportLoss + roleLoss .decsSample : Rat) : ℝ))
          ((maxClaims : ℝ)^2 /
            (Fintype.card (VectorOutput Counter) : ℝ)) *
        Fintype.card
          (FixedOtherKey .decsSample blockCap keyBytes → VectorOutput Counter) := by
      simp [mul_comm]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPhysicalEventBound
