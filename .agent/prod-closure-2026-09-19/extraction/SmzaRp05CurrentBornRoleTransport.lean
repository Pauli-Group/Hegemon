import SmzaRp05CurrentQ38RawSamplerDensity
import SmzaRp05CurrentCoset406
import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05CurrentRoleLabels
import SmzaRp05ReadExecutionBound
import SmzaRp05AdaptiveRetainedAdviceTotality
import SmzaRp05SourceReadSchedule

/-!
# Current q38 endpoint and the Born-role transport boundary

The current-map finite and raw-sampler endpoint is available below.  It is
not yet an endpoint for the original Born-weighted adaptive role execution:
that execution's LVCS bad-cell predicate is the historical `decsRootIndices`
event, whereas the current q38 detector uses the 406-map roots.  In
particular, the historical leaf-zero point is 388, which is a node of the
current interpolation domain.  No current-to-historical event inclusion is
assumed here.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentBornRoleTransport

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

open SmzaRp05CurrentQ38DetectionProbability
open SmzaRp05CurrentQ38RawSamplerDensity
open SmzaQ38McaSourceBinding
open V8Smz9RobustQueryMismatch
open SmzaQ38Recovery
open SmzaRp04ChronologicalAlgebra
open SmzaRp04RoleBadCells SmzaRp04RawMcaSampling
open SmzaRp04McaRoleCells
open SmzaRp04RawRoleSampling SmzaRp04CompleteRawRoleCells
open SmzaRp05TracePrefixes SmzaRp05AdaptiveDynamicBad
open SmzaDynamicDatabaseSoundness
open SmzaRp05CurrentRoleLabels SmzaRp05AdaptivePhysicalReadBound
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05AdaptiveFilteredCollision
open SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05ReadExecutionBound
open SmzaRp05RoleReadTotality
open HegemonCrypto.CmsClassicalDatabase HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalReadSupport
open SmzaRp05PhysicalReadTelescope SmzaRp05VectorReadCharge
open SmzaRp05SequentialReadCharge SmzaRp05SuffixReadout
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9RuntimeFieldLayout V8Smz9CappedRawSampler
open V8Smz9RawCounterCompiler
open SmzaChallengeStageTargets V8SmzaOracleParser
open V8Smz9CoherentVectorMerkle V8Smz9CoherentMerkleInstrument
open V8Smz9McaRecovery

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

private theorem output_event_probability_false {Output : Type*} [Fintype Output] :
    outputEventProbability (fun _ : Output => False) = 0 := by
  classical
  unfold outputEventProbability
  simp

/-- Exact missing event premise for joining the current q38 miss event to the
historical LVCS bad event consumed by the original role-density/Born path.
This is a contract only; it is not proved by the current root-count theorem. -/
def CurrentMissRefinesHistoricalEvent
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) : Prop :=
  ∀ query : Query,
    query ∈ currentLvcsBadQueryEvent rows points claimed →
      query ∈ SmzaRp04ChronologicalAlgebra.lvcsBadQueryEvent
        rows points claimed

/-- Strongest current source endpoint available without identifying the
current q38 law with the Born-weighted adaptive role execution.  This bounds
the capped raw sampler's successful current-event mass, retaining rejects in
the denominator. -/
theorem current_raw_q38_bad_and_success_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405) :
    outputEventProbability
      (fun raw : Fin (V8Smz9RawCounterCompiler.digestCallCap q38CandidateCount) → RawByteBlock =>
        ∃ query, rawDecsSampleOutput raw = some query ∧
          query ∈ currentLvcsBadQueryEvent rows points claimed) ≤
      q38LvcsLoss :=
  raw_current_lvcs_bad_query_probability_le rows points claimed
    rowsDegree claimedDegree

/-- The geometry needed by a root-event transport is already different at
leaf zero: the historical evaluation point is an interpolation node in the
current 406-point domain, and it is not the current evaluation point. -/
theorem historical_leaf_zero_blocks_map_identification :
    V8Smz9DisjointCoset.evaluationPoint ⟨0, by decide⟩ =
        ((⟨388, by decide⟩ : Fin 406).val : Goldilocks) ∧
      SmzaRp05CurrentCoset406.evaluationPoint ⟨0, by decide⟩ ≠
        V8Smz9DisjointCoset.evaluationPoint ⟨0, by decide⟩ := by
  exact ⟨SmzaRp05CurrentCoset406.historical_leaf_zero_hits_current_interpolation,
    SmzaRp05CurrentCoset406.current_leaf_zero_differs_from_historical⟩

/-! ## Reinstantiated role instability with the 406-map event

The selected-role mechanism is unchanged.  Only the DECS-sample LVCS bad
predicate and its density input differ: this version uses the current event
proved in `SmzaRp05CurrentQ38RawSamplerDensity`.
-/

/-- The current-map q38 predicate on one fixed chronological DECS prefix.
Rows outside the recovered degree range have no chargeable event. -/
def currentDecsSamplePrefixBad (key : DecsSamplePrefixKey) (output : Query) : Prop :=
  (∀ row, (key.rows row).natDegree ≤ 405) ∧
    output ∈ currentLvcsBadQueryEvent key.rows key.points
      (claimedPolynomials key.claimedCoefficients)

theorem current_decs_sample_prefix_density (key : DecsSamplePrefixKey) :
    outputEventProbability (currentDecsSamplePrefixBad key) ≤
      roleLoss .decsSample := by
  by_cases rowsDegree : ∀ row, (key.rows row).natDegree ≤ 405
  · have same : currentDecsSamplePrefixBad key =
        (fun output => output ∈ currentLvcsBadQueryEvent key.rows key.points
          (claimedPolynomials key.claimedCoefficients)) := by
      funext output
      simp [currentDecsSamplePrefixBad, rowsDegree]
    rw [same, output_event_probability_membership]
    exact current_lvcs_bad_query_probability_le key.rows key.points
      (claimedPolynomials key.claimedCoefficients) rowsDegree
      (claimed_polynomials_degree405 key.claimedCoefficients)
  · have empty : currentDecsSamplePrefixBad key = (fun _ => False) := by
      funext output
      simp [currentDecsSamplePrefixBad, rowsDegree]
    rw [empty]
    have nonnegative : 0 ≤ roleLoss .decsSample := by
      unfold roleLoss q38LvcsLoss q38SingleRootLoss
      positivity
    simpa [outputEventProbability] using nonnegative

/-- Current-event replacement for the old DECS-sample branch of `completeBad`.
All other role predicates remain byte-for-byte the original ones. -/
def currentCompleteBad {Counter : Type*} {width : Nat}
    (routes : Routes Counter width) (role : Role) (label : Prefix width)
    (vector : VectorOutput Counter) : Prop :=
  match role with
  | .decsMatrix => optionalEvent
      (fun oracle vector => ∃ output,
        actualDecsMatrixOutput routes.decsMatrix vector = some output ∧
          matrixBad oracle output) label.decsMatrix vector
  | .piopMatrix => optionalEvent
      (fun cellLabel vector => ∃ output,
        actualPiopMatrixOutput routes.piopMatrix vector = some output ∧
          matrixCellBad cellLabel output) label.piopMatrix vector
  | .piopOpening => optionalEvent
      (fun cellLabel vector => ∃ output,
        actualPiopOpeningOutput routes.piopOpening vector = some output ∧
          openingCellBad cellLabel output) label.piopOpening vector
  | .decsSample =>
      optionalEvent
        (fun cellLabel vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            smallSupportBad cellLabel output) label.smallSupport vector ∨
      optionalEvent
        (fun cellLabel vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            currentDecsSamplePrefixBad cellLabel output) label.lvcs vector

theorem current_complete_bad_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {width : Nat} (routes : Routes Counter width) (role : Role)
    (label : Prefix width) :
    outputEventProbability (currentCompleteBad routes role label) ≤
      completeRoleLoss role := by
  cases role with
  | decsMatrix =>
      have eventEq : currentCompleteBad routes .decsMatrix label =
          completeBad routes .decsMatrix label := by
        funext vector
        rfl
      rw [eventEq]
      exact complete_bad_density routes .decsMatrix label
  | piopMatrix =>
      have eventEq : currentCompleteBad routes .piopMatrix label =
          completeBad routes .piopMatrix label := by
        funext vector
        rfl
      rw [eventEq]
      exact complete_bad_density routes .piopMatrix label
  | piopOpening =>
      have eventEq : currentCompleteBad routes .piopOpening label =
          completeBad routes .piopOpening label := by
        funext vector
        rfl
      rw [eventEq]
      exact complete_bad_density routes .piopOpening label
  | decsSample =>
      have supportBound := optional_event_probability_le
        (fun cellLabel vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            smallSupportBad cellLabel output) smallSupportLoss
        (by unfold smallSupportLoss; positivity)
        (fun cellLabel => actual_small_support_bad_and_success_le
          routes.decsSample cellLabel)
        label.smallSupport
      have rootLossNonnegative : 0 ≤ q38SingleRootLoss := by
        unfold q38SingleRootLoss
        exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
      have lvcsNonnegative : 0 ≤ roleLoss .decsSample := by
        change 0 ≤ 12 * q38SingleRootLoss
        exact mul_nonneg (by norm_num) rootLossNonnegative
      have currentBound := optional_event_probability_le
        (fun key vector => ∃ output,
          actualDecsSampleOutput routes.decsSample vector = some output ∧
            currentDecsSamplePrefixBad key output)
        (roleLoss .decsSample) lvcsNonnegative
        (fun key => by
          by_cases rowsDegree : ∀ row, (key.rows row).natDegree ≤ 405
          · have same : (fun vector : VectorOutput Counter =>
                ∃ output, actualDecsSampleOutput routes.decsSample vector =
                    some output ∧ currentDecsSamplePrefixBad key output) =
              (fun vector => ∃ query,
                actualDecsSampleOutput routes.decsSample vector = some query ∧
                  query ∈ currentLvcsBadQueryEvent key.rows key.points
                    (claimedPolynomials key.claimedCoefficients)) := by
              funext vector
              simp [currentDecsSamplePrefixBad, rowsDegree]
            rw [same]
            exact current_decs_sample_bad_and_success_le routes.decsSample
              key.rows key.points (claimedPolynomials key.claimedCoefficients)
              rowsDegree (claimed_polynomials_degree405 key.claimedCoefficients)
          · have empty : (fun vector : VectorOutput Counter =>
                ∃ output, actualDecsSampleOutput routes.decsSample vector =
                    some output ∧ currentDecsSamplePrefixBad key output) =
              (fun _ => False) := by
              funext vector
              simp [currentDecsSamplePrefixBad, rowsDegree]
            rw [empty]
            calc
              outputEventProbability (fun _ : VectorOutput Counter => False) = 0 :=
                output_event_probability_false
              _ ≤ roleLoss .decsSample := lvcsNonnegative)
        label.lvcs
      change outputEventProbability (fun vector =>
          optionalEvent
            (fun cellLabel vector => ∃ output,
              actualDecsSampleOutput routes.decsSample vector = some output ∧
                smallSupportBad cellLabel output) label.smallSupport vector ∨
           optionalEvent
            (fun cellLabel vector => ∃ output,
              actualDecsSampleOutput routes.decsSample vector = some output ∧
                currentDecsSamplePrefixBad cellLabel output) label.lvcs vector) ≤
        smallSupportLoss + roleLoss .decsSample
      exact (output_event_union_le _ _).trans
        (add_le_add supportBound currentBound)

/-- Typed current-event density needed by the generic two-pass role theorem. -/
def typedCurrentCompleteRawBad {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) (role : Role)
    (label : TypedPrefixLabel model.width) (vector : VectorOutput Counter) : Prop :=
  match label with
  | .unavailable => False
  | .decoded statement labels =>
      currentCompleteBad (routes statement) role labels vector

theorem typed_current_complete_raw_density
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (routes : TypedRoutes model Counter)
    (role : Role) (label : TypedPrefixLabel model.width) :
    outputEventProbability (typedCurrentCompleteRawBad model routes role label) ≤
      completeRoleLoss role := by
  cases label with
  | unavailable =>
      change outputEventProbability (fun _ : VectorOutput Counter => False) ≤
        completeRoleLoss role
      rw [output_event_probability_false]
      exact complete_role_loss_nonnegative role
  | decoded statement labels =>
      exact current_complete_bad_density (routes statement) role labels

/-- The same physical current RP05 role event as before, but with the 406-map
LVCS event installed in its DECS-sample branch. -/
def currentRoleEvent406 {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  roleEvent keyBytes (vectorOutputBytes counter)
    (globalLeafStatement ns)
    (rawTraceDecoder (globalOnlineNext ns)
      (fun key => targetOfRaw role (keyBytes key))
      (fun _ trace => preambleFromTrace ns role trace) outerFuel)
    (statementTraceDecoder (globalOnlineNext ns)
      (fun _ key => targetOfRaw role (keyBytes key))
      (fun statement _ trace =>
        roleLabelsFromBytes model ns role advice statement trace)
      innerFuel)
    (fun key => InRoleDomain role (keyBytes key))
    (fun _ label output => typedCurrentCompleteRawBad model routes role label output)
    authorized

/-- Reinstantiation of the original two-pass decoder instability proof using
the current-map raw density. This closes the fixed-prefix Born role charge
without identifying either evaluation map. -/
theorem current_role_instability_406
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel cap : Nat)
    (authorized : Finset (List Byte)) :
    InstabilityBound
      (currentRoleEvent406 model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role) := by
  change InstabilityBound
    (roleEvent keyBytes (vectorOutputBytes counter) (globalLeafStatement ns)
      (rawTraceDecoder (globalOnlineNext ns)
        (fun key => targetOfRaw role (keyBytes key))
        (fun _ trace => preambleFromTrace ns role trace) outerFuel)
      (statementTraceDecoder (globalOnlineNext ns)
        (fun _ key => targetOfRaw role (keyBytes key))
        (fun statement _ trace =>
          roleLabelsFromBytes model ns role advice statement trace) innerFuel)
      (fun key => InRoleDomain role (keyBytes key))
      (fun _ label output => typedCurrentCompleteRawBad model routes role label output)
      authorized)
    cap ((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role)
  exact rp05_role_instability ns keyBytes counter
      (fun key => targetOfRaw role (keyBytes key))
      (fun _ trace => preambleFromTrace ns role trace)
      (fun _ key => targetOfRaw role (keyBytes key))
      (fun statement _ trace =>
        roleLabelsFromBytes model ns role advice statement trace)
      outerFuel innerFuel authorized cap
      (fun key => InRoleDomain role (keyBytes key))
      (fun _ label output =>
        typedCurrentCompleteRawBad model routes role label output)
      (completeRoleLoss role) (complete_role_loss_nonnegative role)
      (fun _statement label =>
        typed_current_complete_raw_density model routes role label)

/-- Adaptive physical-read mass bound for the current 406-map role event.
The caller supplies the same physical read budget/support facts as in the
historical generic theorem; the event instability itself is now discharged
above from the current sampler density. -/
theorem current_adaptive_read_role_mass_sqrt_le
    {Key Counter Work Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (depth : Nat) (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key)
    (keysWithin : ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state)
    (total : StandardOn keys state)
    (within : support + depth ≤ cap) :
    Real.sqrt (adaptiveReadMass encode decode
      (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized) program state) ≤
      stateNorm (workspaceEventProjection
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
          outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt
          (6 * (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)) *
            stateNorm state := by
  exact adaptive_read_role_amplitude_le depth encode decode program readBound keys
    keysWithin support cap state bounded total within
    (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized)
    (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)
    (by
      have numeratorNonnegative : (0 : Rat) ≤ 6 * cap := by
        exact_mod_cast (Nat.zero_le (6 * cap))
      have denominatorNonnegative : (0 : Rat) ≤ (2^512 : Rat) := by
        exact_mod_cast (Nat.zero_le (2^512))
      have fractionNonnegative :
          (0 : Rat) ≤ (6 * cap : Rat) / (2^512 : Rat) :=
        div_nonneg numeratorNonnegative denominatorNonnegative
      exact_mod_cast add_nonneg fractionNonnegative
        (complete_role_loss_nonnegative role))
    (by
      intro workspace
      exact (current_role_instability_406 model ns keyBytes counter routes role
        advice outerFuel innerFuel cap authorized).toReal)

/-- Squared Born-mass endpoint for the current-map role event, directly in the
form consumed by adaptive physical-read composition. -/
theorem current_adaptive_read_role_mass_le
    {Key Counter Work Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (depth : Nat) (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key)
    (keysWithin : ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state)
    (total : StandardOn keys state)
    (within : support + depth ≤ cap) :
    adaptiveReadMass encode decode
      (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized) program state ≤
      (stateNorm (workspaceEventProjection
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
          outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt
          (6 * (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)) *
            stateNorm state)^2 := by
  exact adaptive_read_role_mass_le depth encode decode program readBound keys
    keysWithin support cap state bounded total within
    (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized)
    (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)
    (by
      have numeratorNonnegative : (0 : Rat) ≤ 6 * cap := by
        exact_mod_cast (Nat.zero_le (6 * cap))
      have denominatorNonnegative : (0 : Rat) ≤ (2^512 : Rat) := by
        exact_mod_cast (Nat.zero_le (2^512))
      have fractionNonnegative :
          (0 : Rat) ≤ (6 * cap : Rat) / (2^512 : Rat) :=
        div_nonneg numeratorNonnegative denominatorNonnegative
      exact_mod_cast add_nonneg fractionNonnegative
        (complete_role_loss_nonnegative role))
    (by
      intro workspace
      exact (current_role_instability_406 model ns keyBytes counter routes role
        advice outerFuel innerFuel cap authorized).toReal)

/-- The fixed-authorization 406-map role event already present after a quantum
producer run has the current database-game probability bound.  The run's
initial event is zero because an empty database has no recorded witness; the
bound is then the direct CMS raw database-game theorem on the same producer
steps.  This charges the measured role event before any later readout.
-/
theorem current_role_event_mass_after_quantum_producer_le
    {Key Counter Work : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (stepsWithin : steps.length ≤ queryBound)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :
    normSquared
        (workspaceEventProjection
          (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
            advice outerFuel innerFuel authorized)
          (rawRun vectorPhaseSystem queryBound
            (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
            (partialRandomOracleState
              (Output := VectorOutput Counter) ∅ registers))) ≤
      6 * (steps.length : ℝ)^2 *
        (((6 * queryBound : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ) := by
  classical
  let property := currentRoleEvent406 model ns keyBytes counter routes role advice
    outerFuel innerFuel authorized
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
        change ¬ currentRoleEvent406 model ns keyBytes counter routes role advice
          outerFuel innerFuel authorized (empty : Database Key (VectorOutput Counter))
        unfold currentRoleEvent406 roleEvent DynamicBad
        rintro ⟨key, output, recorded, _selected, _bad⟩
        simp at recorded
      simp [project, noRole]
    · have initialZero : initial basis = 0 := by
        simp [initial, partialRandomOracleState, records]
      simp [project, initialZero]
  have instability :
      RealInstabilityBound property queryBound
        (((6 * queryBound : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ) := by
    simpa [property] using
      (current_role_instability_406 model ns keyBytes counter routes role advice
        outerFuel innerFuel queryBound authorized).toReal
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
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role advice
          outerFuel innerFuel authorized)
        (rawRun vectorPhaseSystem queryBound blind initial)) =
      normSquared (workspaceEventProjection (fun _ : Work => property) state) := by
        simp [property, state]
    _ ≤ normSquared (project property queryBound state) := eventBelowProject
    _ ≤ 6 * (steps.length : ℝ)^2 *
          (((6 * queryBound : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ) := by
        simpa [blind] using databaseBound

/-- The current 406-map role bound applies to a source `Program` continuation
after the actual CMS execution of database-independent quantum producer
steps.  The producer's decompressed state is the total-oracle family reached
by those same steps, so every possible continuation read is standard there;
the original unnormalized branch mass is carried into the adaptive read
instrument.  This theorem establishes no relation between log absence and
freshness, and the producer steps must remain database-independent as stated.
-/
theorem current_role_read_mass_after_quantum_producer_le
    {Key Counter Work Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (stepsWithin : steps.length ≤ queryBound)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (cap : Nat) (within : queryBound + depth ≤ cap) :
    adaptiveReadMass encode decode
      (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
        advice outerFuel innerFuel authorized) program
      (rawRun vectorPhaseSystem queryBound
        (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (stateNorm (workspaceEventProjection
          (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
            advice outerFuel innerFuel authorized)
          (rawRun vectorPhaseSystem queryBound
            (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
            (partialRandomOracleState
              (Output := VectorOutput Counter) ∅ registers))) +
        (depth : ℝ) * Real.sqrt
          (6 * (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)) *
          stateNorm
            (rawRun vectorPhaseSystem queryBound
              (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
              (partialRandomOracleState
                (Output := VectorOutput Counter) ∅ registers)))^2 := by
  let initial := partialRandomOracleState
    (Output := VectorOutput Counter) ∅ registers
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let state := rawRun vectorPhaseSystem queryBound blind initial
  have initialBounded : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have capacity : 0 + blind.length ≤ queryBound := by
    simp [blind]
    exact stepsWithin
  have bounded : BoundedState queryBound state := by
    simpa [state, blind] using
      raw_run_bounded_of_bounded vectorPhaseSystem queryBound blind initial 0
        capacity initialBounded
  let initialFamily :
      OracleRegisterFamily (Input := Key) (Output := VectorOutput Counter)
        (Phase := VectorOutput Counter) (Workspace := Work) :=
    fun _oracle => registers
  have initialSimulation : globalDecompress initial =
      totalOracleFamilyState initialFamily := by
    rw [global_decompress_empty_support,
      partial_random_oracle_state_univ_eq_family]
  have stateSimulation : globalDecompress state =
      totalOracleFamilyState (oracleFamilyRun vectorPhaseSystem steps initialFamily) := by
    calc
      globalDecompress state =
          standardRun vectorPhaseSystem steps (globalDecompress initial) := by
        simpa [state, blind] using
          global_decompress_raw_run_eq_standard_run vectorPhaseSystem queryBound
            steps initial 0 (by simpa using stepsWithin) initialBounded
      _ = standardRun vectorPhaseSystem steps (totalOracleFamilyState initialFamily) := by
        rw [initialSimulation]
      _ = totalOracleFamilyState (oracleFamilyRun vectorPhaseSystem steps initialFamily) :=
        standard_run_total_oracle_family vectorPhaseSystem steps initialFamily
  have total : StandardOn keys state := by
    intro key _member
    rw [stateSimulation]
    exact total_oracle_family_state_total_at
      (oracleFamilyRun vectorPhaseSystem steps initialFamily) key
  simpa [state, blind] using
    current_adaptive_read_role_mass_le model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized encode decode depth program readBound keys
      keysWithin queryBound cap state bounded total (by simpa using within)

/-- Composed same-run role bound for a bounded quantum producer followed by
an adaptive source-Program readout.  The pre-read role projection is charged
by the raw CMS database game on the producer's actual steps; the subsequent
read instrument is bounded from that same unnormalized producer state.  The
final expression keeps separate producer and read charges and uses the current
406-map local loss throughout.
-/
theorem current_role_adaptive_read_mass_after_quantum_producer_le
    {Key Counter Work Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (stepsWithin : steps.length ≤ queryBound)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (readBound : ReadsAtMost decode depth program)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys program)
    (cap : Nat) (within : queryBound + depth ≤ cap) :
    adaptiveReadMass encode decode
      (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
        advice outerFuel innerFuel authorized) program
      (rawRun vectorPhaseSystem queryBound
        (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (Real.sqrt
          (6 * (steps.length : ℝ)^2 *
            (((6 * queryBound : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)) +
        (depth : ℝ) * Real.sqrt
          (6 * (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)))^2 := by
  classical
  let initial := partialRandomOracleState
    (Output := VectorOutput Counter) ∅ registers
  let blind := steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let state := rawRun vectorPhaseSystem queryBound blind initial
  let queryLoss : ℝ :=
    (((6 * queryBound : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)
  let readLoss : ℝ :=
    (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)
  have queryLossNonnegative : 0 ≤ queryLoss := by
    unfold queryLoss
    exact_mod_cast add_nonneg
      (div_nonneg (by positivity : (0 : Rat) ≤ 6 * queryBound)
        (by positivity : (0 : Rat) ≤ (2^512 : Rat)))
      (complete_role_loss_nonnegative role)
  have readLossNonnegative : 0 ≤ readLoss := by
    unfold readLoss
    exact_mod_cast add_nonneg
      (div_nonneg (by positivity : (0 : Rat) ≤ 6 * cap)
        (by positivity : (0 : Rat) ≤ (2^512 : Rat)))
      (complete_role_loss_nonnegative role)
  have initialEventBound := current_role_event_mass_after_quantum_producer_le
    model ns keyBytes counter routes role advice outerFuel innerFuel authorized
    queryBound steps stepsWithin registers normalized
  have producerInitialBounded : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have capacity : 0 + blind.length ≤ queryBound := by
    simp [blind]
    exact stepsWithin
  have finalSubnormalized : Subnormalized state :=
    raw_run_subnormalized_of_bounded vectorPhaseSystem queryBound blind initial 0
      capacity producerInitialBounded normalized
  have stateNormBound : stateNorm state ≤ 1 := by
    have := state_norm_le_sqrt state (by norm_num) finalSubnormalized
    simpa using this
  have projectionNormBound :
      stateNorm (workspaceEventProjection
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
          advice outerFuel innerFuel authorized) state) ≤
        Real.sqrt (6 * (steps.length : ℝ)^2 * queryLoss) := by
    apply state_norm_le_sqrt
    · positivity
    · simpa [state, blind, queryLoss, initial] using initialEventBound
  have readEndpoint := current_role_read_mass_after_quantum_producer_le
    model ns keyBytes counter routes role advice outerFuel innerFuel authorized
    queryBound steps stepsWithin registers depth encode decode program readBound keys
    keysWithin cap within
  have tailCoefficientNonnegative : 0 ≤ (depth : ℝ) * Real.sqrt (6 * readLoss) :=
    mul_nonneg (by positivity) (Real.sqrt_nonneg _)
  have innerBound :
      stateNorm (workspaceEventProjection
          (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
            advice outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt (6 * readLoss) * stateNorm state ≤
      Real.sqrt (6 * (steps.length : ℝ)^2 * queryLoss) +
        (depth : ℝ) * Real.sqrt (6 * readLoss) := by
    calc
      _ ≤ Real.sqrt (6 * (steps.length : ℝ)^2 * queryLoss) +
          ((depth : ℝ) * Real.sqrt (6 * readLoss)) * 1 :=
        add_le_add projectionNormBound
          (mul_le_mul_of_nonneg_left stateNormBound tailCoefficientNonnegative)
      _ = _ := by ring
  have innerNonnegative : 0 ≤
      stateNorm (workspaceEventProjection
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
          advice outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt (6 * readLoss) * stateNorm state :=
    add_nonneg (state_norm_nonnegative _)
      (mul_nonneg tailCoefficientNonnegative (state_norm_nonnegative _))
  have upperNonnegative : 0 ≤ Real.sqrt (6 * (steps.length : ℝ)^2 * queryLoss) +
      (depth : ℝ) * Real.sqrt (6 * readLoss) := by positivity
  have squaredInnerBound := mul_self_le_mul_self innerNonnegative innerBound
  have readEndpoint' :
      adaptiveReadMass encode decode
        (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
          advice outerFuel innerFuel authorized) program state ≤
      (stateNorm (workspaceEventProjection
          (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
            advice outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt (6 * readLoss) * stateNorm state)^2 := by
    simpa [state, blind, readLoss, initial] using readEndpoint
  calc
    _ ≤ (stateNorm (workspaceEventProjection
          (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
            advice outerFuel innerFuel authorized) state) +
        (depth : ℝ) * Real.sqrt (6 * readLoss) * stateNorm state)^2 := readEndpoint'
    _ ≤ (Real.sqrt (6 * (steps.length : ℝ)^2 * queryLoss) +
        (depth : ℝ) * Real.sqrt (6 * readLoss))^2 := by
      nlinarith [squaredInnerBound]

/-- Specialization of the composed role bound to the actual finite-answer
source `Program`: its structural worst-path read budget and finite key-space
read set are derived from the program itself.  Only the combined producer and
source read budget remains an input bound.
-/
theorem current_role_source_program_after_quantum_producer_le
    {Key Counter Work Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter)
      (Phase := VectorOutput Counter) (Workspace := Work)))
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter) (Workspace := Work) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (program : Program Result) (cap : Nat)
    (combinedBudget : steps.length +
      SmzaRp05SourceReadSchedule.readBudget decode program ≤ cap) :
    adaptiveReadMass encode decode
      (fun _ : Work => currentRoleEvent406 model ns keyBytes counter routes role
        advice outerFuel innerFuel authorized) program
      (rawRun vectorPhaseSystem steps.length
        (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (Real.sqrt
          (6 * (steps.length : ℝ)^2 *
            (((6 * steps.length : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)) +
        (SmzaRp05SourceReadSchedule.readBudget decode program : ℝ) * Real.sqrt
          (6 * (((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role : Rat) : ℝ)))^2 := by
  exact current_role_adaptive_read_mass_after_quantum_producer_le
    model ns keyBytes counter routes role advice outerFuel innerFuel authorized
    steps.length steps le_rfl registers normalized
    (SmzaRp05SourceReadSchedule.readBudget decode program) encode decode program
    (SmzaRp05SourceReadSchedule.source_reads_within_budget decode program)
    (Finset.univ : Finset Key).toList
    (SmzaRp05SourceReadSchedule.source_reads_within_finite_address_space
      encode decode program)
    cap combinedBudget

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentBornRoleTransport

/-
The attempted certified-prefix instantiation is preserved below as source
notes, but remains outside the strict-checked core until its compiler-level
namespace and generated-step proof obligations are resolved.

/-! ## Certified prefix instantiation

This layer restores the dynamic authorization set carried by the actual
execution context, then applies the same adaptive-read theorem to the state
produced by a certified physical skeleton.  The compiled `ActualProgram` run
is identified with that skeleton by its checked run equation.
-/

/-- Base-work form of the current event, used to certify retained-answer
replacement steps in a separately compiled current-event telescope. -/
def currentBaseEvent406 {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    SmzaRp05AdaptiveFilteredCollision.AdaptiveEvent Key
      (VectorOutput Counter) BaseWork :=
  fun base database =>
    currentRoleEvent406 ctx.model ctx.leafNamespace ctx.keyBytes ctx.counter
      ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
      (ctx.authorizedOf base) database

/-- Dynamic-workspace event matching the original context event, with only
the DECS-sample LVCS branch replaced by the current 406-map predicate. -/
def currentContextEvent406 {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    SmzaRp05AdaptiveFilteredCollision.AdaptiveEvent Key (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) :=
  ignoreRetained (currentBaseEvent406 ctx)

theorem current_context_mark_transport_406
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (statement : List Byte)
    (authorization : ctx.authorizedOf target.workspace.2 =
      insert statement (ctx.authorizedOf source.workspace.2))
    (sameDatabase : target.database = source.database)
    (after : currentContextEvent406 ctx target.workspace target.database) :
    currentContextEvent406 ctx source.workspace source.database := by
  unfold currentContextEvent406 ignoreRetained currentBaseEvent406 at after ⊢
  rw [sameDatabase, authorization] at after
  exact role_event_mark_mono _ _ _ _ _ _ _
    (ctx.authorizedOf source.workspace.2) statement source.database
    (by simpa [currentRoleEvent406] using after)

theorem current_context_private_transport_406
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (sameAuthorization : ctx.authorizedOf source.workspace.2 =
      ctx.authorizedOf target.workspace.2)
    (sameDatabase : source.database = target.database)
    (after : currentContextEvent406 ctx target.workspace target.database) :
    currentContextEvent406 ctx source.workspace source.database := by
  unfold currentContextEvent406 ignoreRetained currentBaseEvent406 at after ⊢
  simpa [sameAuthorization, sameDatabase] using after

theorem current_base_coordinate_invariant_406
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (key : Key) (statement : List Byte)
    (marked : ∀ base, statement ∈ ctx.authorizedOf base)
    (parsed : globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement) :
    CoordinateInvariant (currentBaseEvent406 ctx) key := by
  intro base left right sameOutside
  have markedHere := marked base
  have notSelected : ¬ InRoleDomain ctx.role (ctx.keyBytes key) :=
    SmzaRp05ChallengeRecordErasure.global_leaf_statement_not_in_role_domain
      ctx.leafNamespace (ctx.keyBytes key) statement parsed ctx.role
  have iff := role_event_iff_off_marked_key
    ctx.keyBytes (vectorOutputBytes ctx.counter) (globalLeafStatement ctx.leafNamespace)
    (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun input => targetOfRaw ctx.role (ctx.keyBytes input))
      (fun _ trace => preambleFromTrace ctx.leafNamespace ctx.role trace) ctx.outerFuel)
    (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun _ input => targetOfRaw ctx.role (ctx.keyBytes input))
      (fun statement _ trace => roleLabelsFromBytes ctx.model ctx.leafNamespace
        ctx.role ctx.advice statement trace) ctx.innerFuel)
    (fun input => InRoleDomain ctx.role (ctx.keyBytes input))
    (fun _ label output => typedCurrentCompleteRawBad ctx.model ctx.routes ctx.role
      label output)
    (ctx.authorizedOf base) statement markedHere key notSelected parsed left right sameOutside
  simpa [currentBaseEvent406, currentRoleEvent406] using iff

theorem current_context_marked_write_transport_406
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (source target : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (key : Key) (statement : List Byte)
    (sameAuthorization : ctx.authorizedOf source.workspace.2 =
      ctx.authorizedOf target.workspace.2)
    (marked : statement ∈ ctx.authorizedOf target.workspace.2)
    (parsed : globalLeafStatement ctx.leafNamespace (ctx.keyBytes key) = some statement)
    (sameOutside : ∀ other, other ≠ key → source.database other = target.database other)
    (after : currentContextEvent406 ctx target.workspace target.database) :
    currentContextEvent406 ctx source.workspace source.database := by
  unfold currentContextEvent406 ignoreRetained currentBaseEvent406 at after ⊢
  rw [sameAuthorization]
  have notSelected : ¬ InRoleDomain ctx.role (ctx.keyBytes key) :=
    SmzaRp05ChallengeRecordErasure.global_leaf_statement_not_in_role_domain
      ctx.leafNamespace (ctx.keyBytes key) statement parsed ctx.role
  have iff := role_event_iff_off_marked_key
    ctx.keyBytes (vectorOutputBytes ctx.counter) (globalLeafStatement ctx.leafNamespace)
    (rawTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun input => targetOfRaw ctx.role (ctx.keyBytes input))
      (fun _ trace => preambleFromTrace ctx.leafNamespace ctx.role trace) ctx.outerFuel)
    (statementTraceDecoder (globalOnlineNext ctx.leafNamespace)
      (fun _ input => targetOfRaw ctx.role (ctx.keyBytes input))
      (fun statement _ trace => roleLabelsFromBytes ctx.model ctx.leafNamespace
        ctx.role ctx.advice statement trace) ctx.innerFuel)
    (fun input => InRoleDomain ctx.role (ctx.keyBytes input))
    (fun _ label output => typedCurrentCompleteRawBad ctx.model ctx.routes ctx.role
      label output)
    (ctx.authorizedOf target.workspace.2) statement marked key notSelected parsed
    source.database target.database sameOutside
  exact iff.mpr (by simpa [currentRoleEvent406] using after)

namespace CurrentActualProgram

def compileOpcode
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    CertifiedAdaptiveStep (Phase := VectorOutput Counter)
      (currentContextEvent406 ctx) (currentContextEvent406 ctx) cap before after := by
  cases opcode with
  | query room =>
      exact certifiedOrdinaryQueryStep vectorPhaseSystem
        (currentContextEvent406 ctx) cap before room
        (local_bound_nonnegative ctx cap)
        (current_context_event_instability_406 ctx cap)
  | privateKernel within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent => by
          obtain ⟨sameAuthorization, sameDatabase⟩ := localStep source target nonzero
          exact current_context_private_transport_406 ctx source target
            sameAuthorization sameDatabase afterEvent)
        contractive bounded
  | mark within transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before before within within transition
        (fun source target nonzero afterEvent => by
          obtain ⟨statement, authorization, sameDatabase⟩ :=
            localStep source target nonzero
          exact current_context_mark_transport_406 ctx source target statement
            authorization sameDatabase afterEvent)
        contractive bounded
  | markedWrite beforeWithin afterWithin transition localStep contractive bounded =>
      exact certifiedKernelStep _ _ cap before after beforeWithin afterWithin transition
        (fun source target nonzero afterEvent => by
          obtain ⟨key, statement, sameAuthorization, marked, parsed, sameOutside⟩ :=
            localStep source target nonzero
          exact current_context_marked_write_transport_406 ctx source target key
            statement sameAuthorization marked parsed sameOutside afterEvent)
        contractive bounded
  | copy within update authorization =>
      exact databaseControlledWorkspaceUpdateStep (currentContextEvent406 ctx) update
        (by
          intro database workspace
          unfold currentContextEvent406 ignoreRetained currentBaseEvent406
          rw [authorization database workspace])
        cap before within
  | retainedWrite room key statement marked parsed fresh =>
      exact vectorRetainedOldReplaceStep (currentBaseEvent406 ctx) key
        (current_base_coordinate_invariant_406 ctx key statement marked parsed)
        cap before room fresh

def compile
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries) :
    AdaptiveProgram (Phase := VectorOutput Counter) cap
      (currentContextEvent406 ctx) start (currentContextEvent406 ctx) finish :=
  match program with
  | .nil _ => .nil
  | .cons first remaining =>
      .cons (compileOpcode ctx cap first) (compile ctx cap remaining)

theorem compileOpcode_leak
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {before after charged : Nat}
    (opcode : Opcode ctx cap before after charged) :
    (compileOpcode ctx cap opcode).leak =
      (charged : ℝ) * Real.sqrt (6 * localBound ctx cap) := by
  cases opcode <;>
    simp [compileOpcode, certifiedOrdinaryQueryStep, certifiedKernelStep,
      databaseControlledWorkspaceUpdateStep, vectorRetainedOldReplaceStep,
      retainedOldReplaceStep, Real.sqrt_mul]

theorem compile_total_leak
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries) :
    AdaptiveProgram.totalLeak (compile ctx cap program) =
      (queries : ℝ) * Real.sqrt (6 * localBound ctx cap) := by
  induction program with
  | nil budget => simp [compile, AdaptiveProgram.totalLeak]
  | cons first remaining ih =>
      simp [compile, AdaptiveProgram.totalLeak, compileOpcode_leak, ih]
      ring

theorem run_eq_original
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat}
    (program : ActualProgram ctx cap start finish queries)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    AdaptiveProgram.run (compile ctx cap program) state =
      AdaptiveProgram.run (ActualProgram.compile ctx cap program) state := by
  induction program generalizing state with
  | nil budget => rfl
  | cons first remaining ih =>
      change AdaptiveProgram.run (compile ctx cap remaining)
          ((compileOpcode ctx cap first).apply state) =
        AdaptiveProgram.run (ActualProgram.compile ctx cap remaining)
          ((Opcode.compile ctx cap first).apply state)
      have applyEq : (compileOpcode ctx cap first).apply state =
          (Opcode.compile ctx cap first).apply state := by
        cases first <;> rfl
      rw [applyEq, ih]

end CurrentActualProgram

/-- The current 406 role event is absent from the empty-oracle initialized
state.  This is proved directly from the physical event's recorded-cell
witness, rather than borrowed from the legacy event. -/
theorem current_context_initialized_projection_zero
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    adaptiveProject (currentContextEvent406 ctx) cap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) = 0 := by
  funext basis
  by_cases records : RecordsExactly
      (Output := VectorOutput Counter) ∅ basis.database
  · have same := (records_exactly_empty_iff basis.database).mp records
    have outside : ¬ currentContextEvent406 ctx basis.workspace
        (empty : Database Key (VectorOutput Counter)) := by
      change ¬ currentRoleEvent406 ctx.model ctx.leafNamespace ctx.keyBytes
        ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel
        (ctx.authorizedOf basis.workspace.2)
        (empty : Database Key (VectorOutput Counter))
      rintro ⟨key, output, recorded, selected, bad⟩
      cases recorded
    simp [adaptiveProject, currentContextEvent406, ignoreRetained,
      currentBaseEvent406, same, outside]
  · simp [adaptiveProject, partialRandomOracleState, records]

/-- Pre-read current-event projection amplitude for the actual certified
physical prefix.  The prefix is separately compiled against the 406 event;
its state transformer is proved equal to the existing physical compiler's
transformer, so the bound applies to that literal execution. -/
theorem current_compiled_prefix_pre_read_amplitude
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    {contexts : Role → SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (finishWithin : finish ≤ cap) :
    stateNorm (workspaceEventProjection (currentContextEvent406 (contexts role))
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (queries : ℝ) * Real.sqrt (6 * localBound (contexts role) cap) := by
  let actual := CertifiedPhysicalProgram.compilePhysical (contexts role)
    (CertifiedFor.program certified role)
  let compiled := CurrentActualProgram.compile (contexts role) cap actual
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  have runEq : AdaptiveProgram.run compiled initial =
      PhysicalProgramSkeleton.run skeleton initial := by
    change AdaptiveProgram.run
        (CurrentActualProgram.compile (contexts role) cap
          (CertifiedPhysicalProgram.compilePhysical (contexts role)
            (CertifiedFor.program certified role))) initial = _
    rw [CurrentActualProgram.run_eq_original]
    rw [← CertifiedPhysicalProgram.run_eq_compiled_physical]
    exact CertifiedFor.program_run_eq_skeleton certified role initial
  have bounded : BoundedState 0 initial := partial_random_oracle_empty_bounded registers
  have reached := AdaptiveProgram.run_bounded compiled bounded
  have amplitude := AdaptiveProgram.amplitude_telescope compiled initial bounded subnormalized
  rw [current_context_initialized_projection_zero (contexts role) cap registers,
    state_norm_zero, zero_add, CurrentActualProgram.compile_total_leak] at amplitude
  rw [← workspace_event_eq_adaptive_project_of_bounded
    (currentContextEvent406 (contexts role)) cap _
      (bounded_state_mono finishWithin reached), runEq] at amplitude
  exact amplitude

/-- Full current-event Born mass endpoint for a certified physical prefix
followed by the answer-adaptive suffix.  This derives the current-event
pre-read projection bound above, and does not identify the current event with
the historical event consumed by the original `ActualProgram.compile`. -/
theorem current_compiled_prefix_read_mass_le
    {Key Counter BaseWork Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    {contexts : Role → SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (suffix : Program Result)
    (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key)
    (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap)
    (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (currentContextEvent406 (contexts role)) suffix
      (PhysicalProgramSkeleton.run skeleton
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      6 * (cap : ℝ)^2 * localBound (contexts role) cap := by
  let state := PhysicalProgramSkeleton.run skeleton
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  let charge := Real.sqrt (6 * localBound (contexts role) cap)
  have bounded : BoundedState finish state :=
    common_run_bounded certified role _
      (partial_random_oracle_empty_bounded registers)
  have pre := current_compiled_prefix_pre_read_amplitude certified role registers
    subnormalized (by omega)
  have amplitude := adaptive_read_role_amplitude_le depth encode decode suffix
    readBound keys keysWithin finish cap state bounded total supportWithin
    (currentContextEvent406 (contexts role)) (localBound (contexts role) cap)
    (local_bound_nonnegative (contexts role) cap)
    (current_context_event_instability_406 (contexts role) cap)
  have sourceNorm : stateNorm state ≤ 1 := by
    have sourceMass := CertifiedFor.common_run_subnormalized certified role subnormalized
    have normBound := state_norm_le_sqrt state (by norm_num) sourceMass
    simpa using normBound
  have chargeNonnegative : 0 ≤ charge := Real.sqrt_nonneg _
  have readCharge : (depth : ℝ) * charge * stateNorm state ≤
      (depth : ℝ) * charge := by
    nlinarith [mul_le_mul_of_nonneg_left sourceNorm
      (mul_nonneg (Nat.cast_nonneg depth) chargeNonnegative)]
  have count : (queries : ℝ) + depth ≤ cap := by exact_mod_cast queriesWithin
  have totalAmplitude :
      Real.sqrt (adaptiveReadMass encode decode
        (currentContextEvent406 (contexts role)) suffix state) ≤
        (cap : ℝ) * charge := by
    change _ ≤ _ + (depth : ℝ) * charge * stateNorm state at amplitude
    change stateNorm
      (workspaceEventProjection (currentContextEvent406 (contexts role)) state) ≤
        (queries : ℝ) * charge at pre
    nlinarith [mul_le_mul_of_nonneg_right count chargeNonnegative]
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) (by positivity)).2 totalAmplitude
  rw [Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode
      (currentContextEvent406 (contexts role)) suffix state), mul_pow,
    show charge^2 = 6 * localBound (contexts role) cap from
      Real.sq_sqrt (mul_nonneg (by norm_num) (local_bound_nonnegative _ _))] at squared
  nlinarith

theorem current_context_event_instability_406
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) :
    ∀ workspace,
      RealInstabilityBound (currentContextEvent406 ctx workspace) cap
        (localBound ctx cap) := by
  intro workspace
  exact (current_role_instability_406 ctx.model ctx.leafNamespace ctx.keyBytes
    ctx.counter ctx.routes ctx.role ctx.advice ctx.outerFuel ctx.innerFuel cap
    (ctx.authorizedOf workspace.2)).toReal

/-- Generic adaptive-read mass bound specialized to a real role context with
its workspace-dependent authorization set. -/
theorem current_context_adaptive_read_role_mass_le
    {Key Counter BaseWork Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (depth : Nat) (program : Program Result)
    (readBound : ReadsAtMost decode depth program)
    (keys : List Key)
    (keysWithin : ReadsWithinKeys encode decode keys program)
    (support cap : Nat)
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState support state)
    (total : StandardOn keys state)
    (within : support + depth ≤ cap) :
    adaptiveReadMass encode decode (currentContextEvent406 ctx) program state ≤
      (stateNorm (workspaceEventProjection (currentContextEvent406 ctx) state) +
        (depth : ℝ) * Real.sqrt (6 * localBound ctx cap) * stateNorm state)^2 := by
  exact adaptive_read_role_mass_le depth encode decode program readBound keys
    keysWithin support cap state bounded total within (currentContextEvent406 ctx)
    (localBound ctx cap) (local_bound_nonnegative ctx cap)
    (current_context_event_instability_406 ctx cap)

/-- Adaptive q38 bad-event mass after the actual certified physical prefix.
The state is stated as the literal `ActualProgram` compilation; its equality
to `PhysicalProgramSkeleton.run` lets us reuse the existing bounded-support
and `StandardOn` premises from the historical endpoint. -/
theorem current_compiled_prefix_adaptive_read_role_mass_le
    {Key Counter BaseWork Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    {contexts : Role → SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (suffix : Program Result)
    (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key)
    (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap)
    (total : StandardOn keys (PhysicalProgramSkeleton.run skeleton
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (currentContextEvent406 (contexts role)) suffix
      (AdaptiveProgram.run (ActualProgram.compile (contexts role) cap
        (CertifiedPhysicalProgram.compilePhysical (contexts role)
          (CertifiedFor.program certified role)))
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (stateNorm (workspaceEventProjection (currentContextEvent406 (contexts role))
        (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) +
        (depth : ℝ) * Real.sqrt (6 * localBound (contexts role) cap) *
          stateNorm (PhysicalProgramSkeleton.run skeleton
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))^2 := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  have boundedInitial : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have bounded : BoundedState finish (PhysicalProgramSkeleton.run skeleton initial) :=
    common_run_bounded certified role initial boundedInitial
  have compiledEq :
      AdaptiveProgram.run (ActualProgram.compile (contexts role) cap
        (CertifiedPhysicalProgram.compilePhysical (contexts role)
          (CertifiedFor.program certified role))) initial =
        PhysicalProgramSkeleton.run skeleton initial := by
    rw [← CertifiedPhysicalProgram.run_eq_compiled_physical,
      CertifiedFor.program_run_eq_skeleton certified role]
  rw [compiledEq]
  exact current_context_adaptive_read_role_mass_le (contexts role) encode decode
    depth suffix readBound keys keysWithin finish cap
    (PhysicalProgramSkeleton.run skeleton initial) bounded total supportWithin

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentBornRoleTransport
-/
