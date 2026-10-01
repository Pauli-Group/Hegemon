import HegemonCrypto.FiniteOracleDatabase
import Mathlib.Data.Fintype.Card
import Mathlib.Data.Finset.Image
import Mathlib.Data.Rat.Defs
import Mathlib.Data.Real.Basic
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Positivity

/-!
# Classical database quantities for the CMS QROM lifting theorem

Chiesa, Manohar, and Spooner reduce quantum random-oracle games to one classical quantity:
the probability that one uniformly random oracle answer changes a finite database property.  This
module defines that quantity over the same finite recorded databases used by the Hegemon extractor.

The definitions are deliberately phrased as upper-bound predicates.  This avoids hiding a maximum
over an exponentially large finite space behind an executable `max`, while retaining exactly the
statement consumed by the lifting proof.  No quantum statement is made here.
-/

namespace HegemonCrypto.CmsClassicalDatabase

open HegemonCrypto.FiniteOracleDatabase

variable {Input Output : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [Inhabited Output] [Nonempty Output]

abbrev Property (Input Output : Type*) :=
  Database Input Output -> Prop

/--
One classical random-oracle query.  An already-recorded input keeps its unique answer; an absent
input records the sampled answer.
-/
def query
    (database : Database Input Output)
    (input : Input)
    (output : Output) : Database Input Output :=
  if database input = none then insert database input output else database

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [Inhabited Output]
    [Nonempty Output] in
@[simp]
theorem query_of_absent
    {database : Database Input Output}
    {input : Input}
    (absent : database input = none)
    (output : Output) :
    query database input output = insert database input output := by
  simp [query, absent]

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [Inhabited Output]
    [Nonempty Output] in
@[simp]
theorem query_of_recorded
    {database : Database Input Output}
    {input : Input}
    {recordedOutput : Output}
    (recorded : database input = some recordedOutput)
    (sampledOutput : Output) :
    query database input sampledOutput = database := by
  simp [query, recorded]

/-- Oracle answers that make `target` true after one query. -/
noncomputable def successfulAnswers
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) : Finset Output := by
  classical
  exact Finset.univ.filter fun output => target (query database input output)

/-- Exact probability over one uniformly sampled oracle output. -/
noncomputable def stepProbability
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) : Rat :=
  (successfulAnswers target database input).card / Fintype.card Output

/-- Exact probability of an arbitrary event over one uniformly sampled oracle output. -/
noncomputable def outputEventProbability
    (event : Output -> Prop) : Rat := by
  classical
  exact ((Finset.univ.filter event).card : Rat) / Fintype.card Output

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] in
theorem step_probability_le_output_event
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input)
    (event : Output -> Prop)
    (included :
      ∀ output, target (query database input output) -> event output) :
    stepProbability target database input <=
      outputEventProbability event := by
  classical
  unfold stepProbability outputEventProbability
  have successSubset :
      successfulAnswers target database input ⊆
        Finset.univ.filter event := by
    intro output membership
    simp only [successfulAnswers, Finset.mem_filter, Finset.mem_univ, true_and]
      at membership ⊢
    exact included output membership
  have cardBound := Finset.card_le_card successSubset
  have denominatorNonnegative : (0 : Rat) <= Fintype.card Output := by
    positivity
  exact div_le_div_of_nonneg_right
    (by exact_mod_cast cardBound)
    denominatorNonnegative

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] [Nonempty Output] in
theorem step_probability_eq_zero_of_never
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input)
    (never : ∀ output, ¬target (query database input output)) :
    stepProbability target database input = 0 := by
  classical
  unfold stepProbability successfulAnswers
  have empty :
      (Finset.univ.filter fun output =>
        target (query database input output)) =
        ∅ := by
    ext output
    simp [never output]
  rw [empty]
  simp

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] in
theorem step_probability_nonnegative
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) :
    0 <= stepProbability target database input := by
  unfold stepProbability
  positivity

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] in
theorem step_probability_at_most_one
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) :
    stepProbability target database input <= 1 := by
  unfold stepProbability
  have outputCardPositive : (0 : Rat) < Fintype.card Output := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_one outputCardPositive]
  exact_mod_cast Finset.card_le_card (Finset.subset_univ (successfulAnswers target database input))

/--
Every bounded source database and every next query changes into `target` with probability at most
`bound`.  This is the directional `flip(source -> target, t)` inequality.
-/
def FlipBound
    (source target : Property Input Output)
    (queryBound : Nat)
    (bound : Rat) : Prop :=
  0 <= bound ∧
    ∀ database,
      source database ->
      size database < queryBound ->
      ∀ input, stepProbability target database input <= bound

def complement
    (property : Property Input Output) : Property Input Output :=
  fun database => ¬property database

def intersection
    (left right : Property Input Output) : Property Input Output :=
  fun database => left database ∧ right database

def union
    (left right : Property Input Output) : Property Input Output :=
  fun database => left database ∨ right database

/-- Exact upper-bound form of CMS instability `I(P,t)`. -/
def InstabilityBound
    (property : Property Input Output)
    (queryBound : Nat)
    (bound : Rat) : Prop :=
  FlipBound (complement property) property queryBound bound ∧
    FlipBound property (complement property) queryBound bound

/-- Exact upper-bound form of conditional instability `I(P | Q,t)`. -/
def ConditionalInstabilityBound
    (property condition : Property Input Output)
    (queryBound : Nat)
    (bound : Rat) : Prop :=
  FlipBound
      (intersection (complement property) condition)
      (intersection property condition)
      queryBound bound ∧
    FlipBound
      (intersection property condition)
      (intersection (complement property) condition)
      queryBound bound

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] in
theorem step_probability_mono
    {left right : Property Input Output}
    (included : ∀ database, left database -> right database)
    (database : Database Input Output)
    (input : Input) :
    stepProbability left database input <=
      stepProbability right database input := by
  classical
  unfold stepProbability
  have cardBound :
      (successfulAnswers left database input).card <=
        (successfulAnswers right database input).card := by
    apply Finset.card_le_card
    intro output membership
    simp only [successfulAnswers, Finset.mem_filter, Finset.mem_univ, true_and] at membership ⊢
    exact included _ membership
  have outputCardNonnegative : (0 : Rat) <= Fintype.card Output := by positivity
  exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound) outputCardNonnegative

omit [Fintype Input] [Inhabited Output] in
theorem step_probability_union_le
    (left right : Property Input Output)
    (database : Database Input Output)
    (input : Input) :
    stepProbability (union left right) database input <=
      stepProbability left database input +
        stepProbability right database input := by
  classical
  unfold stepProbability
  have successSubset :
      successfulAnswers (union left right) database input ⊆
        successfulAnswers left database input ∪
          successfulAnswers right database input := by
    intro output membership
    simp only [successfulAnswers, Finset.mem_filter, Finset.mem_univ, true_and,
      Finset.mem_union, union] at membership ⊢
    exact membership
  have cardBound :
      (successfulAnswers (union left right) database input).card <=
        (successfulAnswers left database input).card +
          (successfulAnswers right database input).card := by
    exact (Finset.card_le_card successSubset).trans
      (Finset.card_union_le
        (successfulAnswers left database input)
        (successfulAnswers right database input))
  have outputCardPositive : (0 : Rat) < Fintype.card Output := by
    exact_mod_cast Fintype.card_pos
  rw [← add_div]
  exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound) outputCardPositive.le

omit [DecidableEq Output] [Inhabited Output] in
theorem flip_bound_target_mono
    {source left right : Property Input Output}
    {queryBound : Nat}
    {bound : Rat}
    (included : ∀ database, right database -> left database)
    (leftBound : FlipBound source left queryBound bound) :
    FlipBound source right queryBound bound := by
  refine ⟨leftBound.1, ?_⟩
  intro database sourceMembership sizeBound input
  exact (step_probability_mono included database input).trans
    (leftBound.2 database sourceMembership sizeBound input)

omit [Inhabited Output] in
theorem flip_bound_target_union
    {source left right : Property Input Output}
    {queryBound : Nat}
    {leftBound rightBound : Rat}
    (leftFlip : FlipBound source left queryBound leftBound)
    (rightFlip : FlipBound source right queryBound rightBound) :
    FlipBound source (union left right) queryBound (leftBound + rightBound) := by
  refine ⟨add_nonneg leftFlip.1 rightFlip.1, ?_⟩
  intro database sourceMembership sizeBound input
  calc
    stepProbability (union left right) database input <=
        stepProbability left database input +
          stepProbability right database input :=
      step_probability_union_le left right database input
    _ <= leftBound + rightBound :=
      add_le_add
        (leftFlip.2 database sourceMembership sizeBound input)
        (rightFlip.2 database sourceMembership sizeBound input)

omit [Inhabited Output] in
/--
The union of the collision property with a property analyzed conditionally on collision freedom
has instability bounded by the sum of the collision and conditional bounds.
-/
theorem collision_union_instability_bound
    (property : Property Input Output)
    (queryBound : Nat)
    {collisionBound conditionalBound : Rat}
    (collision :
      InstabilityBound
        (HasCollision : Property Input Output) queryBound collisionBound)
    (conditional :
      ConditionalInstabilityBound property
        (complement (HasCollision : Property Input Output))
        queryBound conditionalBound) :
    InstabilityBound
      (union (HasCollision : Property Input Output) property)
      queryBound
      (collisionBound + conditionalBound) := by
  constructor
  · refine ⟨add_nonneg collision.1.1 conditional.1.1, ?_⟩
    intro database outsideUnion sizeBound input
    have collisionFree : complement
        (HasCollision : Property Input Output) database := by
      exact fun collisionMembership => outsideUnion (Or.inl collisionMembership)
    have outsideProperty : complement property database := by
      exact fun propertyMembership => outsideUnion (Or.inr propertyMembership)
    have collisionStep :
        stepProbability (HasCollision : Property Input Output) database input <=
          collisionBound :=
      collision.1.2 database collisionFree sizeBound input
    have conditionalStep :
        stepProbability
            (intersection property
              (complement (HasCollision : Property Input Output)))
            database input <=
          conditionalBound :=
      conditional.1.2 database ⟨outsideProperty, collisionFree⟩ sizeBound input
    calc
      stepProbability
          (union (HasCollision : Property Input Output) property)
          database input <=
        stepProbability
            (union (HasCollision : Property Input Output)
              (intersection property
                (complement (HasCollision : Property Input Output))))
            database input := by
          apply step_probability_mono
          intro selected membership
          rcases membership with collisionMembership | propertyMembership
          · exact Or.inl collisionMembership
          · by_cases selectedCollision : HasCollision selected
            · exact Or.inl selectedCollision
            · exact Or.inr ⟨propertyMembership, selectedCollision⟩
      _ <=
          stepProbability (HasCollision : Property Input Output) database input +
            stepProbability
              (intersection property
                (complement (HasCollision : Property Input Output)))
              database input :=
        step_probability_union_le _ _ database input
      _ <= collisionBound + conditionalBound :=
        add_le_add collisionStep conditionalStep
  · refine ⟨add_nonneg collision.2.1 conditional.2.1, ?_⟩
    intro database insideUnion sizeBound input
    rcases insideUnion with databaseCollision | propertyMembership
    · calc
        stepProbability
            (complement
              (union (HasCollision : Property Input Output) property))
            database input <=
          stepProbability
            (complement (HasCollision : Property Input Output))
            database input := by
              apply step_probability_mono
              intro selected outsideUnion
              exact fun selectedCollision => outsideUnion (Or.inl selectedCollision)
        _ <= collisionBound :=
          collision.2.2 database databaseCollision sizeBound input
        _ <= collisionBound + conditionalBound :=
          le_add_of_nonneg_right conditional.2.1
    · by_cases databaseCollision : HasCollision database
      · calc
          stepProbability
              (complement
                (union (HasCollision : Property Input Output) property))
              database input <=
            stepProbability
              (complement (HasCollision : Property Input Output))
              database input := by
                apply step_probability_mono
                intro selected outsideUnion
                exact fun selectedCollision => outsideUnion (Or.inl selectedCollision)
          _ <= collisionBound :=
            collision.2.2 database databaseCollision sizeBound input
          _ <= collisionBound + conditionalBound :=
            le_add_of_nonneg_right conditional.2.1
      · have conditionalStep :
            stepProbability
                (intersection (complement property)
                  (complement (HasCollision : Property Input Output)))
                database input <=
              conditionalBound :=
          conditional.2.2 database
            ⟨propertyMembership, databaseCollision⟩ sizeBound input
        calc
          stepProbability
              (complement
                (union (HasCollision : Property Input Output) property))
              database input <=
            stepProbability
                (intersection (complement property)
                  (complement (HasCollision : Property Input Output)))
                database input := by
              apply step_probability_mono
              intro selected outside
              exact ⟨fun inProperty => outside (Or.inr inProperty),
                fun collisionMembership => outside (Or.inl collisionMembership)⟩
          _ <= conditionalBound := conditionalStep
          _ <= collisionBound + conditionalBound :=
            le_add_of_nonneg_left collision.2.1

/-- Outputs already present in a database, represented as an image of its finite support. -/
def recordedOutputs
    (database : Database Input Output) : Finset Output :=
  (support database).image fun input => (database input).getD default

omit [DecidableEq Input] [Fintype Output] [Nonempty Output] in
theorem recorded_output_mem
    {database : Database Input Output}
    {input : Input}
    {output : Output}
    (recorded : database input = some output) :
    output ∈ recordedOutputs database := by
  classical
  apply Finset.mem_image.mpr
  refine ⟨input, ?_, ?_⟩
  · rw [mem_support_iff]
    exact ⟨output, recorded⟩
  · simp [recorded]

omit [DecidableEq Input] [Fintype Output] [Nonempty Output] in
theorem recorded_outputs_card_le_size
    (database : Database Input Output) :
    (recordedOutputs database).card <= size database := by
  exact Finset.card_image_le

omit [Fintype Input] [Fintype Output] [DecidableEq Output] [Inhabited Output]
    [Nonempty Output] in
/-- Adding a fresh answer cannot erase a collision already present in the database. -/
theorem query_preserves_collision
    {database : Database Input Output}
    (collision : HasCollision database)
    (input : Input)
    (output : Output) :
    HasCollision (query database input output) := by
  by_cases absent : database input = none
  · rw [query_of_absent absent]
    rcases collision with
      ⟨left, right, commonOutput, different, leftRecorded, rightRecorded⟩
    refine ⟨left, right, commonOutput, different, ?_, ?_⟩
    · by_cases same : left = input
      · subst left
        rw [absent] at leftRecorded
        contradiction
      · simpa [FiniteOracleDatabase.insert, same] using leftRecorded
    · by_cases same : right = input
      · subst right
        rw [absent] at rightRecorded
        contradiction
      · simpa [FiniteOracleDatabase.insert, same] using rightRecorded
  · obtain ⟨recordedOutput, recorded⟩ : ∃ recordedOutput, database input = some recordedOutput := by
      exact Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recorded output]
    exact collision

omit [Fintype Output] [Nonempty Output] in
/--
If one fresh answer creates the first database collision, that answer equals an output already
recorded before the query.
-/
theorem new_collision_answer_was_recorded
    {database : Database Input Output}
    (collisionFree : CollisionFree database)
    (input : Input)
    (output : Output)
    (newCollision : HasCollision (query database input output)) :
    output ∈ recordedOutputs database := by
  classical
  by_cases absent : database input = none
  · rw [query_of_absent absent] at newCollision
    rcases newCollision with
      ⟨left, right, commonOutput, different, leftRecorded, rightRecorded⟩
    by_cases leftIsInput : left = input
    · subst left
      have outputEqual : output = commonOutput := by
        have someEqual : some output = some commonOutput := by
          simpa [FiniteOracleDatabase.insert] using leftRecorded
        exact Option.some.inj someEqual
      have rightDifferent : right ≠ input := by
        exact fun same => different same.symm
      have rightWasRecorded : database right = some commonOutput := by
        simpa [FiniteOracleDatabase.insert, rightDifferent] using rightRecorded
      simpa [outputEqual] using recorded_output_mem rightWasRecorded
    · by_cases rightIsInput : right = input
      · subst right
        have outputEqual : output = commonOutput := by
          have someEqual : some output = some commonOutput := by
            simpa [FiniteOracleDatabase.insert] using rightRecorded
          exact Option.some.inj someEqual
        have leftWasRecorded : database left = some commonOutput := by
          simpa [FiniteOracleDatabase.insert, leftIsInput] using leftRecorded
        simpa [outputEqual] using recorded_output_mem leftWasRecorded
      · apply False.elim
        apply collisionFree
        exact ⟨left, right, commonOutput, different,
          by simpa [FiniteOracleDatabase.insert, leftIsInput] using leftRecorded,
          by simpa [FiniteOracleDatabase.insert, rightIsInput] using rightRecorded⟩
  · obtain ⟨recordedOutput, recorded⟩ : ∃ recordedOutput, database input = some recordedOutput := by
      exact Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recorded output] at newCollision
    exact False.elim (collisionFree newCollision)

/-- Exact one-query collision-creation probability, bounded by occupied database entries. -/
theorem collision_step_probability_le_size
    {database : Database Input Output}
    (collisionFree : CollisionFree database)
    (input : Input) :
    stepProbability HasCollision database input <=
      (size database : Rat) / Fintype.card Output := by
  classical
  unfold stepProbability
  have answerSubset :
      successfulAnswers HasCollision database input ⊆ recordedOutputs database := by
    intro output membership
    simp only [successfulAnswers, Finset.mem_filter, Finset.mem_univ, true_and] at membership
    exact new_collision_answer_was_recorded collisionFree input output membership
  have cardBound :
      (successfulAnswers HasCollision database input).card <= size database :=
    (Finset.card_le_card answerSubset).trans (recorded_outputs_card_le_size database)
  have outputCardNonnegative : (0 : Rat) <= Fintype.card Output := by positivity
  exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound) outputCardNonnegative

/--
The collision database property has instability at most `t / |Output|`: collisions are monotone,
and creating the first collision requires sampling one of at most `t` recorded outputs.
-/
theorem collision_instability_bound
    (queryBound : Nat) :
    InstabilityBound
      (HasCollision : Property Input Output)
      queryBound
      ((queryBound : Rat) / Fintype.card Output) := by
  constructor
  · refine ⟨div_nonneg (by positivity) (by positivity), ?_⟩
    intro database collisionFree sizeBound input
    calc
      stepProbability HasCollision database input <=
          (size database : Rat) / Fintype.card Output :=
        collision_step_probability_le_size collisionFree input
      _ <= (queryBound : Rat) / Fintype.card Output := by
        have sizeLe : size database <= queryBound := Nat.le_of_lt sizeBound
        exact div_le_div_of_nonneg_right (by exact_mod_cast sizeLe) (by positivity)
  · refine ⟨div_nonneg (by positivity) (by positivity), ?_⟩
    intro database collision _ input
    have noSuccessfulAnswers :
        successfulAnswers (complement HasCollision) database input = ∅ := by
      apply Finset.eq_empty_of_forall_notMem
      intro output membership
      simp only [successfulAnswers, Finset.mem_filter, Finset.mem_univ, true_and,
        complement] at membership
      exact membership (query_preserves_collision collision input output)
    rw [stepProbability, noSuccessfulAnswers]
    simp
    exact div_nonneg (by positivity) (by positivity)

/-- Real-valued presentation of the exact finite uniform step probability. -/
noncomputable def realStepProbability
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) : ℝ :=
  (successfulAnswers target database input).card / Fintype.card Output

omit [Fintype Input] [DecidableEq Output] [Inhabited Output] [Nonempty Output] in
theorem cast_step_probability
    (target : Property Input Output)
    (database : Database Input Output)
    (input : Input) :
    ((stepProbability target database input : Rat) : ℝ) =
      realStepProbability target database input := by
  simp [stepProbability, realStepProbability]

/-- Real form of the directional finite-database flip bound used by Hilbert-space inequalities. -/
def RealFlipBound
    (source target : Property Input Output)
    (queryBound : Nat)
    (bound : ℝ) : Prop :=
  0 <= bound ∧
    ∀ database,
      source database ->
      size database < queryBound ->
      ∀ input, realStepProbability target database input <= bound

/-- Real form of two-sided CMS instability. -/
def RealInstabilityBound
    (property : Property Input Output)
    (queryBound : Nat)
    (bound : ℝ) : Prop :=
  RealFlipBound (complement property) property queryBound bound ∧
    RealFlipBound property (complement property) queryBound bound

omit [DecidableEq Output] [Inhabited Output] [Nonempty Output] in
theorem FlipBound.toReal
    {source target : Property Input Output}
    {queryBound : Nat}
    {bound : Rat}
    (flip : FlipBound source target queryBound bound) :
    RealFlipBound source target queryBound (bound : ℝ) := by
  refine ⟨by exact_mod_cast flip.1, ?_⟩
  intro database sourceMembership sizeBound input
  rw [← cast_step_probability]
  exact_mod_cast flip.2 database sourceMembership sizeBound input

omit [DecidableEq Output] [Inhabited Output] [Nonempty Output] in
theorem InstabilityBound.toReal
    {property : Property Input Output}
    {queryBound : Nat}
    {bound : Rat}
    (instability : InstabilityBound property queryBound bound) :
    RealInstabilityBound property queryBound (bound : ℝ) :=
  ⟨instability.1.toReal, instability.2.toReal⟩

end HegemonCrypto.CmsClassicalDatabase
