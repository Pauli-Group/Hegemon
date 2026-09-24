import HegemonCrypto.CmsClassicalDatabase

/-! Selected-stage CMS instability, with the independent fixed advice and
the VC-derived prefix included in the input label. This discharges the
database-search part only. The stage router, label coupling, and literal
q38 parser distribution must instantiate it; they are not assumed closed.
Source draft awaiting the authorized serial Luna compiler lane. -/

namespace HegemonCrypto.SmallWood.SmzaFixedAdviceBadCell

set_option linter.unusedSectionVars false

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase

noncomputable section

variable {Input Output : Type*} [Fintype Input] [DecidableEq Input]
  [Fintype Output] [DecidableEq Output] [Inhabited Output] [Nonempty Output]

/-- `bad input` is a fixed set before this selected-stage output is drawn.
Other independent challenge tables may be parameters of `bad`; this table may not. -/
def BadCell (bad : Input → Output → Prop) (database : Database Input Output) : Prop :=
  ∃ input output, database input = some output ∧ bad input output

theorem bad_cell_survives_classical_query (bad : Input → Output → Prop)
    (database : Database Input Output) (selected : Input) (sampled : Output)
    (present : BadCell bad database) :
    BadCell bad (HegemonCrypto.CmsClassicalDatabase.query database selected sampled) := by
  obtain ⟨input, output, recorded, badOutput⟩ := present
  by_cases absent : database selected = none
  · rw [query_of_absent absent]
    have different : input ≠ selected := by
      intro same
      subst input
      rw [absent] at recorded
      contradiction
    exact ⟨input, output, by simpa [HegemonCrypto.FiniteOracleDatabase.insert, different] using recorded, badOutput⟩
  · obtain ⟨old, recordedSelected⟩ := Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recordedSelected]
    exact ⟨input, output, recorded, badOutput⟩

theorem new_bad_cell_uses_selected_output (bad : Input → Output → Prop)
    (database : Database Input Output) (selected : Input) (sampled : Output)
    (notBad : ¬ BadCell bad database)
    (created : BadCell bad (HegemonCrypto.CmsClassicalDatabase.query
      database selected sampled)) : bad selected sampled := by
  by_cases absent : database selected = none
  · rw [query_of_absent absent] at created
    obtain ⟨input, output, recorded, badOutput⟩ := created
    by_cases same : input = selected
    · subst input
      have sameOutput : output = sampled :=
        (Option.some.inj (by simpa [HegemonCrypto.FiniteOracleDatabase.insert] using recorded)).symm
      simpa only [sameOutput] using badOutput
    · exact (notBad ⟨input, output, by simpa [HegemonCrypto.FiniteOracleDatabase.insert, same] using recorded, badOutput⟩).elim
  · obtain ⟨old, recordedSelected⟩ := Option.ne_none_iff_exists'.mp absent
    rw [query_of_recorded recordedSelected] at created
    exact (notBad created).elim

/-- A universal per-prefix cardinal bound is exactly what is needed here.
There is no factor for the number of prefixes, labels, statements, or responses. -/
theorem selected_stage_instability
    (bad : Input → Output → Prop) (queryBound : Nat) (epsilon : Rat)
    (nonnegative : 0 ≤ epsilon)
    (perInput : ∀ input, outputEventProbability (bad input) ≤ epsilon) :
    InstabilityBound (BadCell bad) queryBound epsilon := by
  constructor
  · refine ⟨nonnegative, ?_⟩
    intro database notBad _ selected
    exact (step_probability_le_output_event (BadCell bad) database selected (bad selected)
      (fun sampled created => new_bad_cell_uses_selected_output
        bad database selected sampled notBad created)).trans (perInput selected)
  · refine ⟨nonnegative, ?_⟩
    intro database present _ selected
    have never : ∀ sampled,
        ¬ complement (BadCell bad)
          (HegemonCrypto.CmsClassicalDatabase.query database selected sampled) := by
      intro sampled absent
      exact absent (bad_cell_survives_classical_query bad database selected sampled present)
    rw [step_probability_eq_zero_of_never (complement (BadCell bad)) database selected never]
    exact nonnegative

end

end HegemonCrypto.SmallWood.SmzaFixedAdviceBadCell
