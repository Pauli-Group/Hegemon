import HegemonCrypto.SecurityAuthority
import HegemonCrypto.CmsAdaptiveClaimBridge
import HegemonCrypto.CmsFinitePhaseSystem
import HegemonCrypto.CmsLifting
import HegemonCrypto.SmallWoodCmsQrom

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Heterogeneous statement-indexed ideal-QROM extraction

This module gives one finite ideal oracle to an ordered family of active SmallWood statements.
One oracle output is a dependent product containing one independent logical response for every
statement index. A tagged query consumes only its matching coordinate. Uniformity of that
coordinate is proved exactly, so the interactive instability is charged once under one global
query bound rather than union-bounded once per statement.

The product-output oracle is deliberately stronger than the deployed SHA-512 interface because one
logical response exposes every coordinate. A deployed standard-QROM reduction must account for the
physical hash queries needed to simulate that product; no such reduction appears here.  Moreover,
the logical response type in this module is still the historical `activeParameters` response with
five PIOP openings and twenty-three DECS openings.  It is not definitionally the HGV8RP03/SMZ9
response with six and twenty openings.  The exact profile boundary below prevents the global-query
theorem from being cited as an SMZ9 instantiation without an additional transcript theorem.
-/

namespace HegemonCrypto.SmallWood.HeterogeneousCmsQrom

open scoped BigOperators

open HegemonCrypto.SecurityAuthority
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFinitePhaseSystem
open HegemonCrypto.CmsLifting
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.CmsExtraction
open HegemonCrypto.SmallWood.CmsQrom
open HegemonCrypto.SmallWood.LogicalOracle
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive

noncomputable section

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

/-! ## Exact scope of the logical oracle used below -/

/-- PIOP openings carried by the logical response type used in this module. -/
def modeledPiopOpeningCount : Nat :=
  HegemonCrypto.SmallWoodTranscript.activeParameters.openedEvaluations

/-- DECS openings carried by the logical response type used in this module. -/
def modeledDecsOpeningCount : Nat :=
  HegemonCrypto.SmallWoodTranscript.activeParameters.decsOpenedEvaluations

/-- Row width of the uniform DECS batching message used in this module. -/
def modeledDecsRowWidth : Nat :=
  HegemonCrypto.SmallWoodTranscript.activeDecsRowWidth

/--
Machine-checked profile identity for the heterogeneous ideal theorem.  These dimensions are useful
for the historical active logical model, but differ from SMZ9's `6 / 20 / 140` dimensions.
-/
theorem exact_modeled_logical_oracle_profile :
    modeledPiopOpeningCount = 5 ∧ modeledDecsOpeningCount = 23 ∧
      modeledDecsRowWidth = 138 := by
  decide

/-- One query tagged by the statement/proof index whose local transcript it extends. -/
abbrev IndexedVerifierQuery
    (Index : Type)
    (statement : Index -> Statement) :=
  Sigma fun index => VerifierQuery (statement index)

/-- The dependent product of independent statement-specific logical responses. -/
abbrev IndexedLogicalResponse
    (Index : Type)
    (statement : Index -> Statement) :=
  (index : Index) -> LogicalOutput (statement index)

/--
One common cyclic output register, canonically enumerating the dependent response product. The
cyclic representation is used only by the CMS Fourier oracle; verifier semantics decode it back to
`IndexedLogicalResponse`.
-/
abbrev IndexedLogicalOutput
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :=
  Fin (Fintype.card (IndexedLogicalResponse Index statement))

noncomputable instance indexedVerifierQueryFintype
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    Fintype (IndexedVerifierQuery Index statement) :=
  inferInstance

noncomputable instance indexedVerifierQueryDecidableEq
    (Index : Type)
    (statement : Index -> Statement) :
    DecidableEq (IndexedVerifierQuery Index statement) :=
  Classical.decEq _

noncomputable instance indexedLogicalOutputFintype
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    Fintype (IndexedLogicalOutput Index statement) :=
  inferInstance

noncomputable instance indexedLogicalOutputDecidableEq
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    DecidableEq (IndexedLogicalOutput Index statement) :=
  inferInstance

noncomputable instance indexedLogicalResponseNonempty
    (Index : Type)
    (statement : Index -> Statement) :
    Nonempty (IndexedLogicalResponse Index statement) :=
  inferInstance

noncomputable instance indexedLogicalResponseInhabited
    (Index : Type)
    (statement : Index -> Statement) :
    Inhabited (IndexedLogicalResponse Index statement) :=
  ⟨Classical.choice (indexedLogicalResponseNonempty Index statement)⟩

noncomputable instance indexedLogicalOutputCardNeZero
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    NeZero (Fintype.card (IndexedLogicalResponse Index statement)) :=
  ⟨Fintype.card_ne_zero⟩

noncomputable def indexedLogicalResponseEquivOutput
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    IndexedLogicalResponse Index statement ≃ IndexedLogicalOutput Index statement :=
  Fintype.equivFin (IndexedLogicalResponse Index statement)

noncomputable def indexedLogicalOutputAddEquivZMod
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    IndexedLogicalOutput Index statement ≃+
      ZMod (Fintype.card (IndexedLogicalResponse Index statement)) :=
  (ZMod.finEquiv
    (Fintype.card (IndexedLogicalResponse Index statement))).toAddEquiv

/-- Decode the selected statement-specific coordinate from the common cyclic output register. -/
noncomputable def indexedLogicalOutputCoordinate
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (output : IndexedLogicalOutput Index statement)
    (index : Index) : LogicalOutput (statement index) :=
  (indexedLogicalResponseEquivOutput Index statement).symm output index

abbrev IndexedLogicalPhase
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :=
  ZMod (Fintype.card (IndexedLogicalResponse Index statement))

noncomputable def indexedCompletePhaseSystem
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    CompletePhaseSystem
      (IndexedLogicalOutput Index statement)
      (IndexedLogicalPhase Index statement) :=
  cyclicCompletePhaseSystem (indexedLogicalOutputAddEquivZMod Index statement)

/-- A uniform dependent-product response has an exactly uniform selected coordinate. -/
theorem indexed_logical_output_coordinate_uniform
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    (statement : Index -> Statement)
    (index : Index)
    (event : LogicalOutput (statement index) -> Prop) :
    uniformEventProbability
        (fun output : IndexedLogicalOutput Index statement =>
          event (indexedLogicalOutputCoordinate output index)) =
      uniformEventProbability event := by
  let decode := (indexedLogicalResponseEquivOutput Index statement).symm
  let split := Equiv.piSplitAt index (fun selected => LogicalOutput (statement selected))
  calc
    _ = uniformEventProbability
          (fun response : IndexedLogicalResponse Index statement =>
            event (response index)) := by
      simpa [indexedLogicalOutputCoordinate, decode] using
        uniform_event_probability_equiv decode
          (fun response : IndexedLogicalResponse Index statement =>
            event (response index))
    _ = uniformEventProbability
          (fun output :
            LogicalOutput (statement index) ×
              ((selected : { selected // selected ≠ index }) ->
                LogicalOutput (statement selected)) => event output.1) := by
      simpa [split] using
        uniform_event_probability_equiv split
          (fun output :
            LogicalOutput (statement index) ×
              ((selected : { selected // selected ≠ index }) ->
                LogicalOutput (statement selected)) => event output.1)
    _ = uniformEventProbability event :=
      uniform_probability_first event

theorem indexed_query_output_probability_eq_next_semantic_good
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (index : Index)
    (query : VerifierQuery (statement index)) :
    uniformEventProbability
        (fun output : IndexedLogicalOutput Index statement =>
          semanticState
              (verifierExtension
                (queryPrefix (active index) query)
                (queryChallenge (active index) query
                  (indexedLogicalOutputCoordinate output index))) =
            true) =
      nextSemanticGoodProbability (queryPrefix (active index) query) := by
  calc
    _ = uniformEventProbability
          (fun output : LogicalOutput (statement index) =>
            semanticState
                (verifierExtension
                  (queryPrefix (active index) query)
                  (queryChallenge (active index) query output)) =
              true) :=
      indexed_logical_output_coordinate_uniform statement index _
    _ = nextSemanticGoodProbability (queryPrefix (active index) query) := by
      cases query with
      | first oracle =>
          exact first_query_output_probability_eq_next_semantic_good (active index) oracle
      | second query =>
          exact second_query_output_probability_eq_next_semantic_good (active index) query
      | third query =>
          exact third_query_output_probability_eq_next_semantic_good (active index) query
      | fourth query =>
          exact fourth_query_output_probability_eq_next_semantic_good (active index) query

/-! ## One global classical database and one global instability bound -/

abbrev IndexedLogicalDatabase
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :=
  Database
    (IndexedVerifierQuery Index statement)
    (IndexedLogicalOutput Index statement)

/--
The shared database records one statement-tagged false-to-true verifier transition for which the
statement-specific deterministic extractor has no valid witness.
-/
def IndexedBadTransition
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index)) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  fun database =>
    ∃ query output,
      database query = some output ∧
        semanticState (queryPrefix (active query.1) query.2) = false ∧
        semanticState
            (verifierExtension
              (queryPrefix (active query.1) query.2)
              (queryChallenge (active query.1) query.2
                (indexedLogicalOutputCoordinate output query.1))) =
          true ∧
        NoValidExtraction (active query.1) query.2

def IndexedCollisionFreeDatabase
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  complement
    (HasCollision :
      Property
        (IndexedVerifierQuery Index statement)
        (IndexedLogicalOutput Index statement))

def IndexedBadCollisionFree
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index)) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  intersection (IndexedBadTransition active)
    (IndexedCollisionFreeDatabase Index statement)

def IndexedNoBadCollisionFree
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index)) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  intersection (complement (IndexedBadTransition active))
    (IndexedCollisionFreeDatabase Index statement)

theorem indexed_bad_transition_mono
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {smaller larger : IndexedLogicalDatabase Index statement}
    (extension : Extends smaller larger)
    (bad : IndexedBadTransition active smaller) :
    IndexedBadTransition active larger := by
  obtain ⟨query, output, recorded, doomed, good, noExtraction⟩ := bad
  exact ⟨query, output, extension query output recorded, doomed, good, noExtraction⟩

theorem indexed_logical_query_extends
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (database : IndexedLogicalDatabase Index statement)
    (query : IndexedVerifierQuery Index statement)
    (output : IndexedLogicalOutput Index statement) :
    Extends database
      (HegemonCrypto.CmsClassicalDatabase.query database query output) := by
  by_cases absent : database query = none
  · rw [query_of_absent absent]
    exact extends_insert_of_absent database query output absent
  · obtain ⟨recordedOutput, recorded⟩ := Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recorded output]
    exact Extends.refl database

theorem indexed_bad_transition_survives_query
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {database : IndexedLogicalDatabase Index statement}
    (bad : IndexedBadTransition active database)
    (query : IndexedVerifierQuery Index statement)
    (output : IndexedLogicalOutput Index statement) :
    IndexedBadTransition active
      (HegemonCrypto.CmsClassicalDatabase.query database query output) :=
  indexed_bad_transition_mono
    (indexed_logical_query_extends database query output) bad

def IndexedSelectedTransitionGood
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (selected : IndexedVerifierQuery Index statement) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  fun database =>
    ∃ output,
      database selected = some output ∧
        semanticState
            (verifierExtension
              (queryPrefix (active selected.1) selected.2)
              (queryChallenge (active selected.1) selected.2
                (indexedLogicalOutputCoordinate output selected.1))) =
          true

theorem indexed_selected_transition_step_probability
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (database : IndexedLogicalDatabase Index statement)
    (selected : IndexedVerifierQuery Index statement)
    (absent : database selected = none) :
    stepProbability (IndexedSelectedTransitionGood active selected) database selected =
      uniformEventProbability
        (fun output : IndexedLogicalOutput Index statement =>
          semanticState
              (verifierExtension
                (queryPrefix (active selected.1) selected.2)
                (queryChallenge (active selected.1) selected.2
                  (indexedLogicalOutputCoordinate output selected.1))) =
            true) := by
  let event := fun output : IndexedLogicalOutput Index statement =>
    semanticState
        (verifierExtension
          (queryPrefix (active selected.1) selected.2)
          (queryChallenge (active selected.1) selected.2
            (indexedLogicalOutputCoordinate output selected.1))) =
      true
  have successfulSetEq :
      successfulAnswers
          (IndexedSelectedTransitionGood active selected) database selected =
        uniformEventSet event := by
    ext output
    simp only [successfulAnswers, uniformEventSet,
      Finset.mem_filter, Finset.mem_univ, true_and]
    rw [query_of_absent absent]
    constructor
    · rintro ⟨recordedOutput, recorded, good⟩
      have outputEqual : output = recordedOutput := by
        simpa using recorded
      simpa [event, outputEqual] using good
    · intro good
      exact ⟨output, by simp, by simpa [event] using good⟩
  unfold stepProbability uniformEventProbability
  rw [successfulSetEq]

theorem indexed_selected_transition_step_probability_eq_next_good
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (database : IndexedLogicalDatabase Index statement)
    (selected : IndexedVerifierQuery Index statement)
    (absent : database selected = none) :
    stepProbability
        (IndexedSelectedTransitionGood active selected) database selected =
      nextSemanticGoodProbability
        (queryPrefix (active selected.1) selected.2) := by
  exact
    (indexed_selected_transition_step_probability active database selected absent).trans
      (indexed_query_output_probability_eq_next_semantic_good
        active selected.1 selected.2)

theorem indexed_new_bad_transition_uses_selected_query
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {database : IndexedLogicalDatabase Index statement}
    {selected : IndexedVerifierQuery Index statement}
    {sampled : IndexedLogicalOutput Index statement}
    (absent : database selected = none)
    (notBad : ¬IndexedBadTransition active database)
    (badAfter :
      IndexedBadTransition active
        (HegemonCrypto.CmsClassicalDatabase.query
          database selected sampled)) :
    semanticState (queryPrefix (active selected.1) selected.2) = false ∧
      semanticState
          (verifierExtension
            (queryPrefix (active selected.1) selected.2)
            (queryChallenge (active selected.1) selected.2
              (indexedLogicalOutputCoordinate sampled selected.1))) =
        true ∧
      NoValidExtraction (active selected.1) selected.2 := by
  rw [query_of_absent absent] at badAfter
  obtain ⟨query, output, recorded, doomed, good, noExtraction⟩ := badAfter
  by_cases sameQuery : query = selected
  · subst query
    have sameOutput : output = sampled := by
      exact (Option.some.inj (by simpa using recorded)).symm
    subst output
    exact ⟨doomed, good, noExtraction⟩
  · have recordedBefore : database query = some output := by
      simpa [HegemonCrypto.FiniteOracleDatabase.insert, sameQuery] using recorded
    exact
      (notBad ⟨query, output, recordedBefore, doomed, good, noExtraction⟩).elim

theorem indexed_forward_bad_transition_step_probability_le
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat) :
    FlipBound
      (IndexedNoBadCollisionFree active)
      (IndexedBadCollisionFree active)
      queryBound
      activeInteractiveKnowledgeError := by
  refine ⟨active_interactive_knowledge_error_nonnegative, ?_⟩
  intro database source _sizeBound selected
  by_cases absent : database selected = none
  · let target := IndexedBadCollisionFree active
    let event := fun output : IndexedLogicalOutput Index statement =>
      semanticState
          (verifierExtension
            (queryPrefix (active selected.1) selected.2)
            (queryChallenge (active selected.1) selected.2
              (indexedLogicalOutputCoordinate output selected.1))) =
        true
    have probabilityMono :
        stepProbability target database selected ≤
          outputEventProbability event := by
      apply step_probability_le_output_event
      intro output targetAfter
      have facts :=
        indexed_new_bad_transition_uses_selected_query
          absent source.1 targetAfter.1
      exact facts.2.1
    have eventProbabilityEq :
        outputEventProbability event =
          nextSemanticGoodProbability
            (queryPrefix (active selected.1) selected.2) := by
      calc
        outputEventProbability event =
            uniformEventProbability event := by
          unfold outputEventProbability uniformEventProbability uniformEventSet
          rfl
        _ = stepProbability
              (IndexedSelectedTransitionGood active selected) database selected :=
          (indexed_selected_transition_step_probability
            active database selected absent).symm
        _ = nextSemanticGoodProbability
              (queryPrefix (active selected.1) selected.2) :=
          indexed_selected_transition_step_probability_eq_next_good
            active database selected absent
    by_cases existsSuccess :
        ∃ output,
          target
            (HegemonCrypto.CmsClassicalDatabase.query
              database selected output)
    · obtain ⟨output, success⟩ := existsSuccess
      have transitionFacts :=
        indexed_new_bad_transition_uses_selected_query
          absent source.1 success.1
      calc
        stepProbability target database selected ≤
            outputEventProbability event :=
          probabilityMono
        _ = nextSemanticGoodProbability
              (queryPrefix (active selected.1) selected.2) :=
          eventProbabilityEq
        _ ≤ activeInteractiveKnowledgeError :=
          next_good_probability_le_knowledge_error
            (active selected.1) selected.2
            transitionFacts.1 transitionFacts.2.2
    · have never :
          ∀ output,
            ¬target
              (HegemonCrypto.CmsClassicalDatabase.query
                database selected output) := by
        intro output success
        exact existsSuccess ⟨output, success⟩
      have zeroTarget :=
        step_probability_eq_zero_of_never
          target database selected never
      rw [zeroTarget]
      exact active_interactive_knowledge_error_nonnegative
  · obtain ⟨recordedOutput, recorded⟩ := Option.ne_none_iff_exists'.mp absent
    have never :
        ∀ output,
          ¬IndexedBadCollisionFree active
            (HegemonCrypto.CmsClassicalDatabase.query
              database selected output) := by
      intro output targetAfter
      rw [query_of_recorded recorded output] at targetAfter
      exact source.1 targetAfter.1
    have zeroTarget :=
      step_probability_eq_zero_of_never
        (IndexedBadCollisionFree active) database selected never
    rw [zeroTarget]
    exact active_interactive_knowledge_error_nonnegative

theorem indexed_reverse_bad_transition_step_probability_le
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat) :
    FlipBound
      (IndexedBadCollisionFree active)
      (IndexedNoBadCollisionFree active)
      queryBound
      activeInteractiveKnowledgeError := by
  refine ⟨active_interactive_knowledge_error_nonnegative, ?_⟩
  intro database source _sizeBound selected
  have never :
      ∀ output,
        ¬IndexedNoBadCollisionFree active
          (HegemonCrypto.CmsClassicalDatabase.query
            database selected output) := by
    intro output targetAfter
    exact targetAfter.1
      (indexed_bad_transition_survives_query source.1 selected output)
  have zeroTarget :=
    step_probability_eq_zero_of_never
      (IndexedNoBadCollisionFree active) database selected never
  rw [zeroTarget]
  exact active_interactive_knowledge_error_nonnegative

/--
The heterogeneous family has one conditional-instability charge: the selected tagged query is
bounded by the same active interactive knowledge error, independently of which statement index it
targets.
-/
theorem indexed_bad_transition_conditional_instability
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat) :
    ConditionalInstabilityBound
      (IndexedBadTransition active)
      (IndexedCollisionFreeDatabase Index statement)
      queryBound
      activeInteractiveKnowledgeError :=
  ⟨by
      simpa [IndexedNoBadCollisionFree, IndexedBadCollisionFree] using
        indexed_forward_bad_transition_step_probability_le active queryBound,
    by
      simpa [IndexedNoBadCollisionFree, IndexedBadCollisionFree] using
        indexed_reverse_bad_transition_step_probability_le active queryBound⟩

/-- One global bad-database property: either a full-output collision or failed extraction. -/
def IndexedKnowledgeFailureProperty
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index)) :
    Property
      (IndexedVerifierQuery Index statement)
      (IndexedLogicalOutput Index statement) :=
  union
    (HasCollision :
      Property
        (IndexedVerifierQuery Index statement)
        (IndexedLogicalOutput Index statement))
    (IndexedBadTransition active)

/--
One total query bound controls the whole heterogeneous database. There is no sum over statement
indices in either the collision term or the interactive knowledge term.
-/
theorem indexed_knowledge_failure_instability
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat) :
    InstabilityBound
      (IndexedKnowledgeFailureProperty active)
      queryBound
      ((queryBound : Rat) /
          Fintype.card (IndexedLogicalOutput Index statement) +
        activeInteractiveKnowledgeError) := by
  exact collision_union_instability_bound
    (IndexedBadTransition active)
    queryBound
    (collision_instability_bound queryBound)
    (indexed_bad_transition_conditional_instability active queryBound)

/-! ## Adaptive heterogeneous failure claim and ideal-QROM theorem -/

/--
One final adversary workspace adaptively selects both a statement index and a query at that index.
The claimed common oracle output is projected only at that selected index.
-/
structure IndexedIdealFailureSelector
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (Workspace : Type*) where
  enabled : Workspace -> Prop
  selectedIndex : Workspace -> Index
  query : (workspace : Workspace) ->
    VerifierQuery (statement (selectedIndex workspace))
  output : Workspace -> IndexedLogicalOutput Index statement
  doomed : ∀ workspace, enabled workspace ->
    semanticState
        (queryPrefix
          (active (selectedIndex workspace))
          (query workspace)) =
      false
  accepted : ∀ workspace, enabled workspace ->
    semanticState
        (verifierExtension
          (queryPrefix
            (active (selectedIndex workspace))
            (query workspace))
          (queryChallenge
            (active (selectedIndex workspace))
            (query workspace)
            (indexedLogicalOutputCoordinate
              (output workspace)
              (selectedIndex workspace)))) =
      true
  noValidExtraction : ∀ workspace, enabled workspace ->
    NoValidExtraction
      (active (selectedIndex workspace))
      (query workspace)

def indexedFailureClaims
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector active Workspace)
    (workspace : Workspace) :
    List
      (IndexedVerifierQuery Index statement ×
        IndexedLogicalOutput Index statement) :=
  [(⟨selector.selectedIndex workspace, selector.query workspace⟩,
    selector.output workspace)]

def IndexedIdealFailureEvent
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector active Workspace) :
    Workspace ->
      IndexedLogicalDatabase Index statement -> Prop :=
  AdaptiveClaimsEvent selector.enabled (indexedFailureClaims selector)

theorem indexed_failure_claim_inputs_nodup
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector active Workspace)
    (workspace : Workspace) :
    ((indexedFailureClaims selector workspace).map Prod.fst).Nodup := by
  simp [indexedFailureClaims]

theorem indexed_failure_claim_length
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector active Workspace)
    (workspace : Workspace) :
    (indexedFailureClaims selector workspace).length = 1 := by
  simp [indexedFailureClaims]

theorem indexed_failure_event_implies_knowledge_failure
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {active : (index : Index) -> ActiveStatement (statement index)}
    {Workspace : Type*}
    (selector : IndexedIdealFailureSelector active Workspace)
    (workspace : Workspace)
    (database : IndexedLogicalDatabase Index statement)
    (failure : IndexedIdealFailureEvent selector workspace database) :
    IndexedKnowledgeFailureProperty active database := by
  rcases failure with ⟨enabled, records⟩
  apply Or.inr
  refine
    ⟨⟨selector.selectedIndex workspace, selector.query workspace⟩,
      selector.output workspace, ?_,
      selector.doomed workspace enabled,
      selector.accepted workspace enabled,
      selector.noValidExtraction workspace enabled⟩
  exact records
    (⟨selector.selectedIndex workspace, selector.query workspace⟩,
      selector.output workspace)
    (by simp [indexedFailureClaims])

theorem indexed_knowledge_failure_empty_false
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index)) :
    ¬IndexedKnowledgeFailureProperty active
      (empty : IndexedLogicalDatabase Index statement) := by
  intro failure
  rcases failure with collision | transition
  · rcases collision with
      ⟨left, right, output, different, leftRecorded, _rightRecorded⟩
    simp at leftRecorded
  · rcases transition with
      ⟨query, output, recorded, _doomed, _accepted, _noExtraction⟩
    simp at recorded

theorem indexed_initial_knowledge_failure_project_eq_zero
    {Index : Type}
    [Fintype Index]
    {statement : Index -> Statement}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat)
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery Index statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ) :
    project (IndexedKnowledgeFailureProperty active) queryBound
        (partialRandomOracleState
          (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters) =
      0 := by
  funext basis
  by_cases records :
      RecordsExactly (Output := IndexedLogicalOutput Index statement)
        ∅ basis.database
  · have databaseEmpty :
        basis.database =
          (empty : IndexedLogicalDatabase Index statement) :=
      (records_exactly_empty_iff basis.database).mp records
    simp [project, databaseEmpty, size_empty,
      indexed_knowledge_failure_empty_false active]
  · simp [project, partialRandomOracleState, records]

/-- Exact real instability for the one shared heterogeneous database. -/
def indexedIdealLogicalInstability
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement)
    (queries : Nat) : ℝ :=
  ((((queries : Rat) /
      Fintype.card (IndexedLogicalOutput Index statement)) +
    activeInteractiveKnowledgeError : Rat) : ℝ)

theorem indexed_knowledge_failure_real_instability
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    (active : (index : Index) -> ActiveStatement (statement index))
    (queryBound : Nat) :
    RealInstabilityBound
      (IndexedKnowledgeFailureProperty active)
      queryBound
      (indexedIdealLogicalInstability Index statement queryBound) := by
  unfold indexedIdealLogicalInstability
  exact (indexed_knowledge_failure_instability active queryBound).toReal

/-- One adaptive claim against the shared common-output oracle. -/
def indexedIdealLogicalBridgeLoss
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement) : ℝ :=
  1 / (Fintype.card (IndexedLogicalOutput Index statement) : ℝ)

/-- Final ideal heterogeneous logical-QROM extraction-failure bound. -/
def indexedIdealLogicalQromFailureBound
    (Index : Type)
    [Fintype Index]
    (statement : Index -> Statement)
    (queries : Nat) : ℝ :=
  oracleLoss
    (databaseLoss queries
      (indexedIdealLogicalInstability Index statement queries))
    (indexedIdealLogicalBridgeLoss Index statement)

/--
Heterogeneous statement-indexed ideal logical-QROM knowledge theorem.

`steps` is one adversary computation over one common tagged oracle. Its length is the total quantum
query count in that ideal run, not a per-statement maximum. Any prior proof interaction correlated
with the same oracle must be included in that run by a deployed reduction; the arbitrary initial
workspace does not itself justify omitting such queries. The theorem has one CMS database game,
one instability charge, and one final adaptive claim. It does not reduce the deployed SHA-512
sampler (or any native commitment/hash) to this stronger product-output oracle.
-/
theorem indexed_ideal_logical_qrom_failure_probability_le
    {Index : Type}
    [Fintype Index] [DecidableEq Index]
    {statement : Index -> Statement}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (active : (index : Index) -> ActiveStatement (statement index))
    (completePhaseSystem :
      CompletePhaseSystem (IndexedLogicalOutput Index statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := IndexedVerifierQuery Index statement)
      (Output := IndexedLogicalOutput Index statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := IndexedVerifierQuery Index statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters))
    (selector : IndexedIdealFailureSelector active Workspace) :
    ScopedSecurityClaim .idealLogicalQrom
      (normSquared
          (workspaceEventProjection (IndexedIdealFailureEvent selector)
            (totalOracleFamilyState
              (oracleFamilyRun completePhaseSystem.system steps
                (fun _oracle => initialRegisters)))) <=
        indexedIdealLogicalQromFailureBound
          Index statement steps.length) := by
  apply ScopedSecurityClaim.ofIdealLogicalQrom
  let system := completePhaseSystem.system
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initialState :=
    partialRandomOracleState
      (Output := IndexedLogicalOutput Index statement) ∅ initialRegisters
  let compressedState :=
    rawRun system steps.length blindSteps initialState
  let family :=
    oracleFamilyRun system steps (fun _oracle => initialRegisters)
  have initialBounded : BoundedState 0 initialState := by
    exact partial_random_oracle_empty_bounded initialRegisters
  have capacity : blindSteps.length <= steps.length := by
    simp [blindSteps]
  have simulation :
      globalDecompress compressedState =
        totalOracleFamilyState family := by
    exact compressed_run_is_uniform_random_oracle_purification
      system steps.length steps initialRegisters (by simp)
  have compressedBounded :
      BoundedState steps.length compressedState := by
    exact raw_run_bounded_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded
  have compressedSubnormalized :
      Subnormalized compressedState := by
    exact raw_run_subnormalized_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded initialSubnormalized
  have databaseGame :
      normSquared
          (project (IndexedKnowledgeFailureProperty active) steps.length
            compressedState) <=
        databaseLoss steps.length
          (indexedIdealLogicalInstability Index statement steps.length) := by
    have lifted :=
      implemented_raw_database_game_le_database_loss
        system
        (IndexedKnowledgeFailureProperty active)
        steps.length
        blindSteps
        initialState
        (indexed_knowledge_failure_real_instability active steps.length)
        capacity
        initialBounded
        initialSubnormalized
        (indexed_initial_knowledge_failure_project_eq_zero
          active steps.length initialRegisters)
    have blindLength : blindSteps.length = steps.length := by
      simp [blindSteps]
    rw [blindLength] at lifted
    exact lifted
  have transferred :=
    adaptive_claims_probability_le
      compressedState
      family
      simulation
      selector.enabled
      (indexedFailureClaims selector)
      (indexed_failure_claim_inputs_nodup selector)
      1
      (by
        intro workspace
        rw [indexed_failure_claim_length selector workspace])
      (IndexedKnowledgeFailureProperty active)
      (indexed_failure_event_implies_knowledge_failure selector)
      steps.length
      compressedBounded
      compressedSubnormalized
      (databaseLoss steps.length
        (indexedIdealLogicalInstability Index statement steps.length))
      databaseGame
  have bridgeEq :
      ((1 : Nat) : ℝ) ^ 2 *
          (1 /
            (Fintype.card
              (IndexedLogicalOutput Index statement) : ℝ)) =
        indexedIdealLogicalBridgeLoss Index statement := by
    unfold indexedIdealLogicalBridgeLoss
    rw [Nat.cast_one, one_pow, one_mul]
  change
    normSquared
        (workspaceEventProjection
          (AdaptiveClaimsEvent selector.enabled
            (indexedFailureClaims selector))
          (totalOracleFamilyState family)) <=
      oracleLoss
        (databaseLoss steps.length
          (indexedIdealLogicalInstability Index statement steps.length))
        (indexedIdealLogicalBridgeLoss Index statement)
  rw [← bridgeEq]
  exact transferred

/-! ## Deliberately absent deployed transfer -/

/--
Evidence that one conventional SHA-512 query interface simulates the dependent product-output
oracle above with an explicitly charged query expansion and distinguishing loss.  This type has no
constructor in the checked-in model.  In particular, the ideal theorem does not manufacture a
standard-QROM SHA-512 theorem merely because all statement coordinates share one syntactic domain.
-/
inductive Sha512ToIndexedProductOracleReduction : Prop

/--
Evidence that the historical logical response type has been replaced or refined by the exact
HGV8RP03/SMZ9 `6 / 20 / 140` response and verifier transition.  This is also constructor-free here;
the numerical SMZ9 ledger lives in a separate module.
-/
inductive ExactSmz9IndexedLogicalOracleInstantiation : Prop

theorem sha512_to_indexed_product_oracle_reduction_is_unavailable :
    ¬ Sha512ToIndexedProductOracleReduction := by
  intro reduction
  exact nomatch reduction

theorem exact_smz9_indexed_logical_oracle_instantiation_is_unavailable :
    ¬ ExactSmz9IndexedLogicalOracleInstantiation := by
  intro instantiation
  exact nomatch instantiation

end

end HegemonCrypto.SmallWood.HeterogeneousCmsQrom
