import HegemonCrypto.SmallWoodLogicalOracle

/-!
# CMS bad-transition extraction for active SmallWood

This module connects the exact four-turn interactive knowledge theorem to the classical database
property consumed by the Chiesa--Manohar--Spooner compressed-oracle lifting theorem.

A database is bad precisely when it records a verifier answer that moves a doomed interactive
prefix into the good state while the deterministic oracle extractor does not yield a valid
Hegemon witness.  Such a property is monotone under database extension.  More importantly, one
new logical oracle answer creates it with probability at most the proved interactive knowledge
error.  No BCS or QROM theorem is postulated here.
-/

namespace HegemonCrypto.SmallWood.CmsExtraction

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.LogicalOracle

noncomputable section

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option linter.unusedSectionVars false

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

abbrev LogicalDatabase (statement : ActiveStatementType) :=
  Database (VerifierQuery statement) (LogicalOutput statement)

def NoValidExtraction
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement) : Prop :=
  ¬∃ witness,
    extractedWitnessAtPrefix (queryPrefix active query) = some witness ∧
      ((queryPrefix active query).statement, witness) ∈ Relation

/--
The database has recorded one knowledge-violating verifier transition.  Recording the query and
answer explicitly makes the property monotone and gives the measured-database extractor the exact
prefix at which it must rewind.
-/
def BadTransition
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  fun database =>
    ∃ query output,
      database query = some output ∧
        semanticState (queryPrefix active query) = false ∧
        semanticState
            (verifierExtension
              (queryPrefix active query)
              (queryChallenge active query output)) =
          true ∧
        NoValidExtraction active query

def CollisionFreeDatabase
    (statement : ActiveStatementType) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  complement
    (HasCollision :
      Property (VerifierQuery statement) (LogicalOutput statement))

def BadCollisionFree
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  intersection (BadTransition active) (CollisionFreeDatabase statement)

def NoBadCollisionFree
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  intersection (complement (BadTransition active))
    (CollisionFreeDatabase statement)

theorem bad_transition_mono
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {smaller larger : LogicalDatabase statement}
    (extension : Extends smaller larger)
    (bad : BadTransition active smaller) :
    BadTransition active larger := by
  obtain ⟨query, output, recorded, doomed, good, noExtraction⟩ := bad
  exact ⟨query, output, extension query output recorded, doomed, good, noExtraction⟩

theorem logical_query_extends
    {statement : ActiveStatementType}
    (database : LogicalDatabase statement)
    (query : VerifierQuery statement)
    (output : LogicalOutput statement) :
    Extends database
      (HegemonCrypto.CmsClassicalDatabase.query database query output) := by
  by_cases absent : database query = none
  · rw [query_of_absent absent]
    exact extends_insert_of_absent database query output absent
  · obtain ⟨recordedOutput, recorded⟩ := Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recorded output]
    exact Extends.refl database

theorem bad_transition_survives_query
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {database : LogicalDatabase statement}
    (bad : BadTransition active database)
    (query : VerifierQuery statement)
    (output : LogicalOutput statement) :
    BadTransition active
      (HegemonCrypto.CmsClassicalDatabase.query database query output) :=
  bad_transition_mono (logical_query_extends database query output) bad

theorem next_good_probability_le_knowledge_error
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (query : VerifierQuery statement)
    (doomed : semanticState (queryPrefix active query) = false)
    (noExtraction : NoValidExtraction active query) :
    nextSemanticGoodProbability (queryPrefix active query) ≤
      activeInteractiveKnowledgeError := by
  by_contra notBounded
  have aboveError :
      activeInteractiveKnowledgeError <
        nextSemanticGoodProbability (queryPrefix active query) :=
    lt_of_not_ge notBounded
  obtain ⟨witness, extracted, relation⟩ :=
    concrete_extract_above_error
      (queryPrefix active query)
      (query_prefix_is_verifier_turn active query)
      doomed
      aboveError
  exact noExtraction ⟨witness, extracted, relation⟩

def SelectedTransitionGood
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (selected : VerifierQuery statement) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  fun database =>
    ∃ output,
      database selected = some output ∧
        semanticState
            (verifierExtension
              (queryPrefix active selected)
              (queryChallenge active selected output)) =
          true

theorem selected_transition_step_probability
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (database : LogicalDatabase statement)
    (selected : VerifierQuery statement)
    (absent : database selected = none) :
    stepProbability (SelectedTransitionGood active selected) database selected =
      uniformEventProbability
        (fun output : LogicalOutput statement =>
          semanticState
              (verifierExtension
                (queryPrefix active selected)
                (queryChallenge active selected output)) =
            true) := by
  let event := fun output : LogicalOutput statement =>
    semanticState
        (verifierExtension
          (queryPrefix active selected)
          (queryChallenge active selected output)) =
      true
  have successfulSetEq :
      successfulAnswers
          (SelectedTransitionGood active selected) database selected =
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

theorem selected_transition_step_probability_eq_next_good
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (database : LogicalDatabase statement)
    (selected : VerifierQuery statement)
    (absent : database selected = none) :
    stepProbability
        (SelectedTransitionGood active selected) database selected =
      nextSemanticGoodProbability (queryPrefix active selected) := by
  cases selected with
  | first oracle =>
      exact
        (selected_transition_step_probability
          active database (.first oracle) absent).trans
          (first_query_output_probability_eq_next_semantic_good active oracle)
  | second query =>
      exact
        (selected_transition_step_probability
          active database (.second query) absent).trans
          (second_query_output_probability_eq_next_semantic_good active query)
  | third query =>
      exact
        (selected_transition_step_probability
          active database (.third query) absent).trans
          (third_query_output_probability_eq_next_semantic_good active query)
  | fourth query =>
      exact
        (selected_transition_step_probability
          active database (.fourth query) absent).trans
          (fourth_query_output_probability_eq_next_semantic_good active query)

theorem new_bad_transition_uses_selected_query
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {database : LogicalDatabase statement}
    {selected : VerifierQuery statement}
    {sampled : LogicalOutput statement}
    (absent : database selected = none)
    (notBad : ¬BadTransition active database)
    (badAfter :
      BadTransition active
        (HegemonCrypto.CmsClassicalDatabase.query
          database selected sampled)) :
    semanticState (queryPrefix active selected) = false ∧
      semanticState
          (verifierExtension
            (queryPrefix active selected)
            (queryChallenge active selected sampled)) =
        true ∧
      NoValidExtraction active selected := by
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
    exact (notBad ⟨query, output, recordedBefore, doomed, good, noExtraction⟩).elim

theorem forward_bad_transition_step_probability_le
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (queryBound : Nat) :
    FlipBound
      (NoBadCollisionFree active)
      (BadCollisionFree active)
      queryBound
      activeInteractiveKnowledgeError := by
  refine ⟨active_interactive_knowledge_error_nonnegative, ?_⟩
  intro database source _sizeBound selected
  by_cases absent : database selected = none
  · let target := BadCollisionFree active
    let event := fun output : LogicalOutput statement =>
      semanticState
          (verifierExtension
            (queryPrefix active selected)
            (queryChallenge active selected output)) =
        true
    have probabilityMono :
        stepProbability target database selected ≤
          outputEventProbability event := by
      apply step_probability_le_output_event
      intro output targetAfter
      have facts :=
        new_bad_transition_uses_selected_query
          absent source.1 targetAfter.1
      exact facts.2.1
    have eventProbabilityEq :
        outputEventProbability event =
          nextSemanticGoodProbability (queryPrefix active selected) := by
      calc
        outputEventProbability event =
            uniformEventProbability event := by
          unfold outputEventProbability uniformEventProbability uniformEventSet
          rfl
        _ = stepProbability
              (SelectedTransitionGood active selected) database selected :=
          (selected_transition_step_probability
            active database selected absent).symm
        _ = nextSemanticGoodProbability (queryPrefix active selected) :=
          selected_transition_step_probability_eq_next_good
            active database selected absent
    by_cases existsSuccess :
        ∃ output,
          target
            (HegemonCrypto.CmsClassicalDatabase.query
              database selected output)
    · obtain ⟨output, success⟩ := existsSuccess
      have transitionFacts :=
        new_bad_transition_uses_selected_query
          absent source.1 success.1
      calc
        stepProbability target database selected ≤
            outputEventProbability event :=
          probabilityMono
        _ = nextSemanticGoodProbability (queryPrefix active selected) :=
          eventProbabilityEq
        _ ≤ activeInteractiveKnowledgeError :=
          next_good_probability_le_knowledge_error
            active selected transitionFacts.1 transitionFacts.2.2
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
          ¬BadCollisionFree active
            (HegemonCrypto.CmsClassicalDatabase.query
              database selected output) := by
      intro output targetAfter
      rw [query_of_recorded recorded output] at targetAfter
      exact source.1 targetAfter.1
    have zeroTarget :=
      step_probability_eq_zero_of_never
        (BadCollisionFree active) database selected never
    rw [zeroTarget]
    exact active_interactive_knowledge_error_nonnegative

theorem reverse_bad_transition_step_probability_le
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (queryBound : Nat) :
    FlipBound
      (BadCollisionFree active)
      (NoBadCollisionFree active)
      queryBound
      activeInteractiveKnowledgeError := by
  refine ⟨active_interactive_knowledge_error_nonnegative, ?_⟩
  intro database source _sizeBound selected
  have never :
      ∀ output,
        ¬NoBadCollisionFree active
          (HegemonCrypto.CmsClassicalDatabase.query
            database selected output) := by
    intro output targetAfter
    exact targetAfter.1
      (bad_transition_survives_query source.1 selected output)
  have zeroTarget :=
    step_probability_eq_zero_of_never
      (NoBadCollisionFree active) database selected never
  rw [zeroTarget]
  exact active_interactive_knowledge_error_nonnegative

/--
Exact conditional-instability premise consumed by the CMS query-sequence theorem.  The only
probability in this theorem is the active interactive knowledge error; the reverse transition is
zero because recorded bad transitions are monotone.
-/
theorem active_bad_transition_conditional_instability
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (queryBound : Nat) :
    ConditionalInstabilityBound
      (BadTransition active)
      (CollisionFreeDatabase statement)
      queryBound
      activeInteractiveKnowledgeError :=
  ⟨by
      simpa [NoBadCollisionFree, BadCollisionFree] using
        forward_bad_transition_step_probability_le active queryBound,
    by
      simpa [NoBadCollisionFree, BadCollisionFree] using
        reverse_bad_transition_step_probability_le active queryBound⟩

end

end HegemonCrypto.SmallWood.CmsExtraction
