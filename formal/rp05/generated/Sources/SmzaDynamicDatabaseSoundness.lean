import SmzaSelectedStageSearch

/-! One-execution CMS soundness with database-dependent commitment labels.
This does not compare an adaptive quantum readout with a uniform challenge
experiment.  It bounds the literal dynamic bad-database property, then applies
the existing adaptive-claims bridge on the same initialized oracle execution.
The remaining instantiation obligations are per-label challenge densities,
the insertion instability of extracted labels, and deterministic accepted
claim inclusion; none is a supplied quantum probability-transfer inequality. -/
namespace HegemonCrypto.SmallWood.SmzaDynamicDatabaseSoundness

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open HegemonCrypto.CmsFinitePhaseSystem

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Input Output Label : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [Inhabited Output]

def DynamicBad (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop) (database : Database Input Output) : Prop :=
  ∃ input output, database input = some output ∧ bad (label database input) input output

/-- Track all old recorded keys and the queried key.  Since the source
database has size strictly below the query cap, there are at most cap targets. -/
def TrackedLabelChange (label : Database Input Output → Input → Label)
    (database : Database Input Output) (queried : Input)
    (after : Database Input Output) : Prop :=
  ∃ input, (input = queried ∨ database input ≠ none) ∧
    label after input ≠ label database input

theorem classical_query_preserves_recorded (database : Database Input Output)
    (queried input : Input) (sampled recorded : Output)
    (present : database input = some recorded) :
    query database queried sampled input = some recorded := by
  by_cases absent : database queried = none
  · rw [query_of_absent absent]
    have different : input ≠ queried := by
      intro same
      subst input
      rw [absent] at present
      contradiction
    simpa only [HegemonCrypto.FiniteOracleDatabase.insert, if_neg different] using present
  · simp only [query, if_neg absent, present]

theorem new_dynamic_bad_implies_change_or_sample
    (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop)
    (database : Database Input Output) (queried : Input) (sampled : Output)
    (notBad : ¬ DynamicBad label bad database)
    (created : DynamicBad label bad (query database queried sampled)) :
    TrackedLabelChange label database queried (query database queried sampled) ∨
      bad (label database queried) queried sampled := by
  by_cases changed : TrackedLabelChange label database queried
      (query database queried sampled)
  · exact Or.inl changed
  · right
    by_cases absent : database queried = none
    · obtain ⟨input, output, recorded, badOutput⟩ := created
      rw [query_of_absent absent] at recorded
      by_cases same : input = queried
      · subst input
        have outputSame : output = sampled :=
          (Option.some.inj (by simpa using recorded)).symm
        have labelSame : label (query database queried sampled) queried =
            label database queried := by
          by_contra different
          exact changed ⟨queried, Or.inl rfl, different⟩
        simpa only [labelSame, outputSame] using badOutput
      · have old : database input = some output := by
          simpa only [HegemonCrypto.FiniteOracleDatabase.insert, if_neg same] using recorded
        have labelSame : label (query database queried sampled) input =
            label database input := by
          by_contra different
          exact changed ⟨input, Or.inr (by rw [old]; simp), different⟩
        exact (notBad ⟨input, output, old, by simpa only [labelSame] using badOutput⟩).elim
    · exact (notBad (by simpa only [query, if_neg absent] using created)).elim

theorem lost_dynamic_bad_implies_label_change
    (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop)
    (database : Database Input Output) (queried : Input) (sampled : Output)
    (present : DynamicBad label bad database)
    (lost : ¬ DynamicBad label bad (query database queried sampled)) :
    TrackedLabelChange label database queried (query database queried sampled) := by
  obtain ⟨input, output, recorded, badOutput⟩ := present
  refine ⟨input, Or.inr (by rw [recorded]; simp), ?_⟩
  intro same
  apply lost
  exact ⟨input, output,
    classical_query_preserves_recorded database queried input sampled output recorded,
    by simpa only [same] using badOutput⟩

/-- A changing commitment label and a new bad selected output are the only
ways to enter the event.  Leaving it requires a label change.  Both directions
are proved for the same dynamic database predicate. -/
theorem dynamic_bad_instability
    (label : Database Input Output → Input → Label)
    (bad : Label → Input → Output → Prop) (cap : Nat) (epsilon delta : Rat)
    (epsilonNonnegative : 0 ≤ epsilon) (deltaNonnegative : 0 ≤ delta)
    (perLabel : ∀ value input, outputEventProbability (bad value input) ≤ epsilon)
    (changes : ∀ database, size database < cap → ∀ queried,
      stepProbability (TrackedLabelChange label database queried) database queried ≤ delta) :
    InstabilityBound (DynamicBad label bad) cap (delta + epsilon) := by
  constructor
  · refine ⟨add_nonneg deltaNonnegative epsilonNonnegative, ?_⟩
    intro database outside bounded queried
    let changed := TrackedLabelChange label database queried
    let newSample : Property Input Output := fun after =>
      DynamicBad label bad after ∧ ¬ changed after
    have included : ∀ after, DynamicBad label bad after → union changed newSample after := by
      intro after inside
      by_cases change : changed after
      · exact Or.inl change
      · exact Or.inr ⟨inside, change⟩
    have sampleBound : stepProbability newSample database queried ≤ epsilon := by
      apply (step_probability_le_output_event newSample database queried
        (bad (label database queried) queried) ?_).trans (perLabel _ _)
      intro sampled inside
      exact (new_dynamic_bad_implies_change_or_sample label bad database queried sampled
        outside inside.1).resolve_left inside.2
    exact (step_probability_mono included database queried).trans
      ((step_probability_union_le changed newSample database queried).trans
        (add_le_add (changes database bounded queried) sampleBound))
  · refine ⟨add_nonneg deltaNonnegative epsilonNonnegative, ?_⟩
    intro database present bounded queried
    have included : ∀ sampled,
        complement (DynamicBad label bad) (query database queried sampled) →
        TrackedLabelChange label database queried (query database queried sampled) :=
      fun sampled lost => lost_dynamic_bad_implies_label_change
        label bad database queried sampled present lost
    have subset : successfulAnswers (complement (DynamicBad label bad)) database queried ⊆
        successfulAnswers (TrackedLabelChange label database queried) database queried := by
      intro sampled member
      exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
        included sampled (Finset.mem_filter.mp member).2⟩
    have probability : stepProbability (complement (DynamicBad label bad)) database queried ≤
        stepProbability (TrackedLabelChange label database queried) database queried := by
      unfold stepProbability
      exact div_le_div_of_nonneg_right (by exact_mod_cast Finset.card_le_card subset)
        (Nat.cast_nonneg _)
    exact (probability.trans (changes database bounded queried)).trans
      (le_add_of_nonneg_right epsilonNonnegative)

end
end HegemonCrypto.SmallWood.SmzaDynamicDatabaseSoundness
