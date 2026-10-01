import SmzaRp04StatementRecordFilter
import SmzaPhysicalStageRecord
import SmzaDynamicDatabaseSoundness

/-!
# Authorization-aware RP04 label transport

This file isolates the algebra needed when a physical RP04 role cell is first
assigned a statement by a nonleaf-only decoder and is then assigned its actual
four-role prefix by a second decoder over that statement's filtered record
relation.  The concrete strict-leaf parser and the concrete RP04 prefix
postprocessor remain separate instantiations.

The disabled constructor is intentional.  After a statement is marked, every
one of its physical targets has the same label, independently of its tree
records.  Consequently an authorized leaf overwrite commutes with the complete
Record split, rather than merely preserving the final bad predicate.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04AuthorizedLabelTransport

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open V8Smz9CoherentVectorMerkle
open SmzaRecordSplitR3 SmzaStageGlobalSplit
open SmzaRp04StatementRecordFilter SmzaDynamicDatabaseSoundness

noncomputable section
set_option autoImplicit false
set_option linter.unusedSimpArgs false
set_option linter.unusedSectionVars false

abbrev Records (Input Output : Type*) :=
  V8Smz9CoherentMerkleGeometry.Records Input Output

/-- A label stored by the indexed role oracle.  The statement is retained in
the active constructor, so marking `x` can be recognized as disabling the old
`x` label without inspecting the tree-derived payload. -/
inductive AuthorizedLabel (Statement Label : Type*) where
  | disabled
  | active (statement : Statement) (label : Label)
deriving DecidableEq, Fintype

/-- The nonleaf decoder chooses one statement.  Only then is `fullLabel` run on
the complete `R_s` relation; in RP04 this second value contains the decoded
tree polynomials and the chronological `PrefixLabels`. -/
def completeFilteredLabel
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (records : Records RawInput RawDigest)
    (target : Target) : AuthorizedLabel Statement Label :=
  match outer (nonleafFilter leafStatement records) target with
  | none => .disabled
  | some statement =>
      if statement ∈ authorized then .disabled
      else .active statement
        (fullLabel statement (oneStatementFilter leafStatement statement records) target)

/-- Inserting an already marked leaf leaves the complete active/disabled label
unchanged.  Both decoder views are reduced to the exact filter equalities. -/
theorem complete_filtered_label_insert_authorized
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement) (output : RawDigest)
    (records : Records RawInput RawDigest) (target : Target) :
    completeFilteredLabel leafStatement outer fullLabel authorized
        (insert (input, output) records) target =
      completeFilteredLabel leafStatement outer fullLabel authorized records target := by
  unfold completeFilteredLabel
  rw [nonleafFilter_insert_leaf leafStatement statement input parsed output records]
  cases selected : outer (nonleafFilter leafStatement records) target with
  | none => rfl
  | some selectedStatement =>
      by_cases fresh : selectedStatement ∈ authorized
      · simp only [fresh, ↓reduceIte]
      · have different : statement ≠ selectedStatement := by
          intro same
          subst selectedStatement
          exact fresh marked
        have sameView := oneStatementFilter_insert_ignored leafStatement
          selectedStatement statement different input parsed output records
        simp [fresh, sameView]

/-- Retained-answer overwriting has the same exact invariance.  The old answer
is not represented as another record. -/
theorem complete_filtered_label_overwrite_authorized
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement) (oldOutput newOutput : RawDigest)
    (records : Records RawInput RawDigest) (target : Target) :
    completeFilteredLabel leafStatement outer fullLabel authorized
        (overwriteRecords records input oldOutput newOutput) target =
      completeFilteredLabel leafStatement outer fullLabel authorized records target := by
  unfold completeFilteredLabel
  rw [nonleafFilter_overwrite_leaf leafStatement statement input parsed
    oldOutput newOutput records]
  cases selected : outer (nonleafFilter leafStatement records) target with
  | none => rfl
  | some selectedStatement =>
      by_cases fresh : selectedStatement ∈ authorized
      · simp only [fresh, ↓reduceIte]
      · have different : statement ≠ selectedStatement := by
          intro same
          subst selectedStatement
          exact fresh marked
        have sameView := oneStatementFilter_overwrite_ignored leafStatement
          selectedStatement statement different input parsed oldOutput newOutput records
        simp [fresh, sameView]

theorem complete_filtered_labels_overwrite_authorized
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement) (oldOutput newOutput : RawDigest)
    (records : Records RawInput RawDigest) :
    (fun target => completeFilteredLabel leafStatement outer fullLabel authorized
      (overwriteRecords records input oldOutput newOutput) target) =
    (fun target => completeFilteredLabel leafStatement outer fullLabel authorized
      records target) := by
  funext target
  exact complete_filtered_label_overwrite_authorized leafStatement outer fullLabel
    authorized statement marked input parsed oldOutput newOutput records target

/-- Therefore the complete Record-slot split itself is identical before and
after an authorized overwrite.  This is the algebraic commutation fact used by
the retained-answer write; it is stronger than event-predicate invariance. -/
theorem split_registers_overwrite_authorized
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    [DecidableEq (AuthorizedLabel Statement Label)]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (statement : Statement)
    (marked : statement ∈ authorized) (input : RawInput)
    (parsed : leafStatement input = some statement) (oldOutput newOutput : RawDigest)
    (records : Records RawInput RawDigest) :
    splitRegisters (Cell := Cell)
        (fun target => completeFilteredLabel leafStatement outer fullLabel authorized
          (overwriteRecords records input oldOutput newOutput) target) =
      splitRegisters
        (fun target => completeFilteredLabel leafStatement outer fullLabel authorized
          records target) := by
  apply congrArg (splitRegisters (Cell := Cell))
  exact complete_filtered_labels_overwrite_authorized leafStatement outer fullLabel
    authorized statement marked input parsed oldOutput newOutput records

def AuthorizedBad {Statement Label Cell : Type*}
    (bad : Statement → Label → Cell → Prop) :
    AuthorizedLabel Statement Label → Cell → Prop
  | .disabled, _ => False
  | .active statement label, cell => bad statement label cell

/-- If the nonleaf selector returns the statement being marked, its new label
is definitionally disabled.  In particular, the old active label still carries
the statement identity needed to recognize this case. -/
theorem complete_filtered_label_marked_statement_disabled
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest) (target : Target)
    (selected : outer (nonleafFilter leafStatement records) target =
      some markedStatement) :
    completeFilteredLabel leafStatement outer fullLabel
        (insert markedStatement authorized) records target = .disabled := by
  simp [completeFilteredLabel, selected]

/-- Marking only removes enabled bad predicates.  This is derived from the
constructors and Finset insertion, not supplied as a projector premise. -/
theorem authorized_bad_mark_mono
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest) (target : Target) (cell : Cell)
    (after : AuthorizedBad bad
      (completeFilteredLabel leafStatement outer fullLabel
        (insert markedStatement authorized) records target) cell) :
    AuthorizedBad bad
      (completeFilteredLabel leafStatement outer fullLabel authorized records target) cell := by
  unfold completeFilteredLabel at after ⊢
  cases selected : outer (nonleafFilter leafStatement records) target with
  | none =>
      simp [completeFilteredLabel, selected, AuthorizedBad] at after
  | some statement =>
      by_cases newlyDisabled : statement ∈ insert markedStatement authorized
      · simp [completeFilteredLabel, selected, newlyDisabled, AuthorizedBad] at after
      · have previouslyFresh : statement ∉ authorized := by
          exact fun present => newlyDisabled (Finset.mem_insert_of_mem present)
        simpa [completeFilteredLabel, selected, newlyDisabled, previouslyFresh,
          AuthorizedBad] using after

/-! ## The exact three-slot mark permutation -/

section MarkPermutation

variable {Target Statement Label Cell : Type*}
variable [DecidableEq (AuthorizedLabel Statement Label)]

/-- `S_new S_old^{-1}` on Record registers.  Each split is involutive, so this
is literally the old-to-new conjugating permutation. -/
def markRegisters
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label) :
    Registers Target (AuthorizedLabel Statement Label) Cell ≃
      Registers Target (AuthorizedLabel Statement Label) Cell :=
  (splitRegisters oldLabel).trans (splitRegisters newLabel)

@[simp] theorem mark_registers_new_cell
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (target : Target) :
    markRegisters oldLabel newLabel registers
        (target, some (newLabel target)) =
      registers (target, some (oldLabel target)) := by
  simp [markRegisters, splitRegisters, reindex, slotSplit]

/-- When a target's label changes, the conjugation is the explicit three-cycle
`new <- old <- plain <- new`; no cell is copied or discarded. -/
theorem mark_registers_old_cell
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (target : Target) (different : oldLabel target ≠ newLabel target) :
    markRegisters oldLabel newLabel registers
        (target, some (oldLabel target)) = registers (target, none) := by
  simp [markRegisters, splitRegisters, reindex, slotSplit,
    Equiv.swap_apply_def, different]

theorem mark_registers_plain_cell
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (target : Target) (different : oldLabel target ≠ newLabel target) :
    markRegisters oldLabel newLabel registers (target, none) =
      registers (target, some (newLabel target)) := by
  simp [markRegisters, splitRegisters, reindex, slotSplit,
    Equiv.swap_apply_def, different, Ne.symm different]

theorem mark_registers_other_labeled_cell
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (target : Target) (label : AuthorizedLabel Statement Label)
    (notOld : label ≠ oldLabel target) (notNew : label ≠ newLabel target) :
    markRegisters oldLabel newLabel registers (target, some label) =
      registers (target, some label) := by
  simp [markRegisters, splitRegisters, reindex, slotSplit,
    Equiv.swap_apply_def, notOld, notNew, Ne.symm notOld, Ne.symm notNew]

def DesignatedIndexedBad
    (labels : Target → AuthorizedLabel Statement Label)
    (bad : Statement → Label → Cell → Prop)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell) : Prop :=
  exists target cell,
    registers (target, some (labels target)) = cell ∧ AuthorizedBad bad (labels target) cell

/-- The exact mark permutation has no good-to-bad component.  The populated
new designated cell is read back from the old designated cell, and the only
semantic premise is the constructor-level monotonicity of the bad predicate. -/
theorem mark_registers_no_good_to_bad
    (oldLabel newLabel : Target → AuthorizedLabel Statement Label)
    (bad : Statement → Label → Cell → Prop)
    (monotone : ∀ target cell,
      AuthorizedBad bad (newLabel target) cell →
        AuthorizedBad bad (oldLabel target) cell)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (after : DesignatedIndexedBad newLabel bad
      (markRegisters oldLabel newLabel registers)) :
    DesignatedIndexedBad oldLabel bad registers := by
  obtain ⟨target, cell, recorded, badCell⟩ := after
  exact ⟨target, cell, by simpa only [mark_registers_new_cell] using recorded,
    monotone target cell badCell⟩

/-- Concrete authorization specialization of the preceding slot theorem.  Its
good-to-bad conclusion has no caller-supplied monotonicity hypothesis. -/
theorem complete_mark_registers_no_good_to_bad
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    [DecidableEq (AuthorizedLabel Statement Label)]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (after : DesignatedIndexedBad
      (fun target => completeFilteredLabel leafStatement outer fullLabel
        (insert markedStatement authorized) records target) bad
      (markRegisters
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          authorized records target)
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          (insert markedStatement authorized) records target)
        registers)) :
    DesignatedIndexedBad
      (fun target => completeFilteredLabel leafStatement outer fullLabel
        authorized records target) bad registers := by
  refine mark_registers_no_good_to_bad _ _ bad ?_ registers after
  intro target cell badAfter
  exact authorized_bad_mark_mono leafStatement outer fullLabel bad authorized
    markedStatement records target cell badAfter

/-! The physical indexed search ranges over every labelled slot, including
old labels.  Its predicate must therefore test the current authorization set
at every slot, rather than treating only the current designated label as
disabled. -/

def AuthorizedIndexedBad
    (authorized : Finset Statement)
    (bad : Target → Statement → Label → Cell → Prop) (target : Target) :
    AuthorizedLabel Statement Label → Cell → Prop
  | .disabled, _ => False
  | .active statement label, cell =>
      statement ∉ authorized ∧ bad target statement label cell

def GlobalIndexedBad
    (authorized : Finset Statement)
    (bad : Target → Statement → Label → Cell → Prop)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell) : Prop :=
  exists target label cell,
    registers (target, some label) = cell ∧
      AuthorizedIndexedBad authorized bad target label cell

theorem authorized_indexed_bad_mark_mono
    [DecidableEq Statement]
    (authorized : Finset Statement) (markedStatement : Statement)
    (bad : Target → Statement → Label → Cell → Prop) (target : Target)
    (label : AuthorizedLabel Statement Label) (cell : Cell)
    (after : AuthorizedIndexedBad (insert markedStatement authorized) bad
      target label cell) :
    AuthorizedIndexedBad authorized bad target label cell := by
  cases label with
  | disabled => exact False.elim after
  | active statement value =>
      exact ⟨fun present => after.1 (Finset.mem_insert_of_mem present), after.2⟩

/-- If marking changes the designated label, the old label necessarily names
the newly marked statement, hence is false under the new authorization set. -/
theorem changed_old_label_not_bad_after_mark
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Target → Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest) (target : Target) (cell : Cell)
    (different :
      completeFilteredLabel leafStatement outer fullLabel authorized records target ≠
        completeFilteredLabel leafStatement outer fullLabel
          (insert markedStatement authorized) records target) :
    ¬ AuthorizedIndexedBad (insert markedStatement authorized) bad target
      (completeFilteredLabel leafStatement outer fullLabel authorized records target) cell := by
  unfold completeFilteredLabel at different ⊢
  cases selected : outer (nonleafFilter leafStatement records) target with
  | none =>
      exact (different (by
        simp [completeFilteredLabel, selected])).elim
  | some statement =>
      by_cases present : statement ∈ authorized
      · have markedPresent : statement ∈ insert markedStatement authorized :=
          Finset.mem_insert_of_mem present
        exact (different (by
          simp [completeFilteredLabel, selected, present, markedPresent])).elim
      · by_cases newlyMarked : statement = markedStatement
        · subst statement
          simp [completeFilteredLabel, selected, present, AuthorizedIndexedBad]
        · have stillFresh : statement ∉ insert markedStatement authorized := by
            simpa [newlyMarked] using present
          exact (different (by
            simp [completeFilteredLabel, selected, present, stillFresh])).elim

/-- Authorization monotonicity for the complete current designated label. -/
theorem complete_current_indexed_bad_mark_mono
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Target → Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest) (target : Target) (cell : Cell)
    (after : AuthorizedIndexedBad (insert markedStatement authorized) bad target
      (completeFilteredLabel leafStatement outer fullLabel
        (insert markedStatement authorized) records target) cell) :
    AuthorizedIndexedBad authorized bad target
      (completeFilteredLabel leafStatement outer fullLabel authorized records target) cell := by
  unfold completeFilteredLabel at after ⊢
  cases selected : outer (nonleafFilter leafStatement records) target with
  | none =>
      simp [completeFilteredLabel, selected, AuthorizedIndexedBad] at after
  | some statement =>
      by_cases presentAfter : statement ∈ insert markedStatement authorized
      · simp [completeFilteredLabel, selected, presentAfter,
          AuthorizedIndexedBad] at after
      · have freshBefore : statement ∉ authorized :=
          fun present => presentAfter (Finset.mem_insert_of_mem present)
        simpa [completeFilteredLabel, selected, presentAfter, freshBefore,
          AuthorizedIndexedBad] using after

/-- Exact no-good-to-bad theorem for the global indexed-cell event used by
search.  The authorization set is checked on every stored active label, so
the old label slot populated by the three-cycle is disabled after marking. -/
theorem complete_mark_registers_no_global_good_to_bad
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    [DecidableEq (AuthorizedLabel Statement Label)]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Target → Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (after : GlobalIndexedBad (insert markedStatement authorized) bad
      (markRegisters
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          authorized records target)
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          (insert markedStatement authorized) records target)
        registers)) :
    GlobalIndexedBad authorized bad registers := by
  obtain ⟨target, label, cell, recorded, badCell⟩ := after
  let oldLabel := fun target => completeFilteredLabel leafStatement outer fullLabel
    authorized records target
  let newLabel := fun target => completeFilteredLabel leafStatement outer fullLabel
    (insert markedStatement authorized) records target
  by_cases isNew : label = newLabel target
  · subst label
    refine ⟨target, oldLabel target, cell, ?_, ?_⟩
    · change (markRegisters oldLabel newLabel registers)
        (target, some (newLabel target)) = cell at recorded
      simpa only [mark_registers_new_cell] using recorded
    · exact complete_current_indexed_bad_mark_mono leafStatement outer fullLabel bad
        authorized markedStatement records target cell badCell
  · by_cases isOld : label = oldLabel target
    · subst label
      have changed : oldLabel target ≠ newLabel target := isNew
      exact False.elim ((changed_old_label_not_bad_after_mark leafStatement outer
        fullLabel bad authorized markedStatement records target cell changed) badCell)
    · refine ⟨target, label, cell, ?_,
        authorized_indexed_bad_mark_mono authorized markedStatement bad target label cell badCell⟩
      change (markRegisters oldLabel newLabel registers)
        (target, some label) = cell at recorded
      simpa only [mark_registers_other_labeled_cell oldLabel newLabel registers target
        label isOld isNew] using recorded

theorem complete_mark_registers_global_good_to_bad_false
    {RawInput RawDigest Statement Target Label Cell : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    [DecidableEq (AuthorizedLabel Statement Label)]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (bad : Target → Statement → Label → Cell → Prop)
    (authorized : Finset Statement) (markedStatement : Statement)
    (records : Records RawInput RawDigest)
    (registers : Registers Target (AuthorizedLabel Statement Label) Cell)
    (good : ¬ GlobalIndexedBad authorized bad registers) :
    ¬ GlobalIndexedBad (insert markedStatement authorized) bad
      (markRegisters
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          authorized records target)
        (fun target => completeFilteredLabel leafStatement outer fullLabel
          (insert markedStatement authorized) records target)
        registers) := by
  intro after
  exact good (complete_mark_registers_no_global_good_to_bad leafStatement outer
    fullLabel bad authorized markedStatement records registers after)

end MarkPermutation

section PhysicalMark

variable {Key Counter Target Statement Label Cell Private : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Target] [Fintype Statement] [Fintype Label]
variable [Fintype Cell] [Fintype Private]
variable [DecidableEq (AuthorizedLabel Statement Label)]

abbrev MarkBasis := StageBasis Key Counter Target
  (AuthorizedLabel Statement Label) Cell Private

abbrev MarkDatabase := Database Key (VectorOutput Counter)

/-- Basis-level `K_mark = S_new S_old^{-1}`.  It is an `Equiv`, hence an
actual permutation/isometry rather than a postulated linear operator. -/
def markBasisPermutation
    (oldLabel newLabel : MarkDatabase (Key := Key) (Counter := Counter) →
      Target → AuthorizedLabel Statement Label) :
    MarkBasis (Key := Key) (Counter := Counter) (Target := Target)
      (Statement := Statement) (Label := Label) (Cell := Cell) (Private := Private) ≃
    MarkBasis (Key := Key) (Counter := Counter) (Target := Target)
      (Statement := Statement) (Label := Label) (Cell := Cell) (Private := Private) :=
  (fullSplit oldLabel).trans (fullSplit newLabel)

/-- The conjugating map preserves total squared mass exactly because it is an
explicit basis equivalence. -/
theorem mark_basis_permutation_mass
    (oldLabel newLabel : MarkDatabase (Key := Key) (Counter := Counter) →
      Target → AuthorizedLabel Statement Label)
    (state : MarkBasis (Key := Key) (Counter := Counter) (Target := Target)
      (Statement := Statement) (Label := Label) (Cell := Cell) (Private := Private) → ℂ) :
    V8Smz9CoherentMerklePartition.mass
      (V8Smz9CoherentMerklePartition.permute
        (markBasisPermutation oldLabel newLabel) state) =
      V8Smz9CoherentMerklePartition.mass state := by
  exact V8Smz9CoherentMerklePartition.permute_mass
    (markBasisPermutation oldLabel newLabel) state

/-- Exact intertwining of the old and new split representations. -/
theorem mark_basis_intertwines
    (oldLabel newLabel : MarkDatabase (Key := Key) (Counter := Counter) →
      Target → AuthorizedLabel Statement Label)
    (basis : MarkBasis (Key := Key) (Counter := Counter) (Target := Target)
      (Statement := Statement) (Label := Label) (Cell := Cell) (Private := Private)) :
    markBasisPermutation oldLabel newLabel (fullSplit oldLabel basis) =
      fullSplit newLabel basis := by
  change fullSplit newLabel (fullSplit oldLabel (fullSplit oldLabel basis)) = _
  rw [SmzaPhysicalStageRecord.physical_full_split_involutive oldLabel basis]

end PhysicalMark

/-! ## Two-pass label-change accounting -/

def OuterChange
    {RawInput RawDigest Statement Target : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (left right : Records RawInput RawDigest) (target : Target) : Prop :=
  outer (nonleafFilter leafStatement left) target ≠
    outer (nonleafFilter leafStatement right) target

def InnerChange
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement)
    (left right : Records RawInput RawDigest) (target : Target) : Prop :=
  exists statement, statement ∉ authorized ∧
    outer (nonleafFilter leafStatement left) target = some statement ∧
    outer (nonleafFilter leafStatement right) target = some statement ∧
    fullLabel statement (oneStatementFilter leafStatement statement left) target ≠
      fullLabel statement (oneStatementFilter leafStatement statement right) target

/-- Any composite-label change is explained by one of the two deterministic
decoder passes.  This is the set inclusion used before the probability union
bound. -/
theorem complete_filtered_label_change_subset
    {RawInput RawDigest Statement Target Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Target → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Target → Label)
    (authorized : Finset Statement)
    (left right : Records RawInput RawDigest) (target : Target)
    (changed : completeFilteredLabel leafStatement outer fullLabel authorized left target ≠
      completeFilteredLabel leafStatement outer fullLabel authorized right target) :
    OuterChange leafStatement outer left right target ∨
      InnerChange leafStatement outer fullLabel authorized left right target := by
  by_cases outerChanged : OuterChange leafStatement outer left right target
  · exact Or.inl outerChanged
  · right
    unfold OuterChange at outerChanged
    have sameOuter := Classical.not_not.mp outerChanged
    cases leftSelected : outer (nonleafFilter leafStatement left) target with
    | none =>
        have rightSelected : outer (nonleafFilter leafStatement right) target = none :=
          sameOuter.symm.trans leftSelected
        exact False.elim (changed (by
          simp [completeFilteredLabel, leftSelected, rightSelected]))
    | some statement =>
        have rightSelected : outer (nonleafFilter leafStatement right) target =
            some statement := sameOuter.symm.trans leftSelected
        by_cases fresh : statement ∉ authorized
        · refine ⟨statement, fresh, leftSelected, rightSelected, ?_⟩
          intro sameFull
          apply changed
          simp [completeFilteredLabel, leftSelected, rightSelected, fresh, sameFull]
        · have present : statement ∈ authorized := Classical.not_not.mp fresh
          exact False.elim (changed (by
            simp [completeFilteredLabel, leftSelected, rightSelected, present]))

def TrackedOuterChange
    {Input Output RawInput RawDigest Statement : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest]
    (recordsOf : Database Input Output → Records RawInput RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Input → Option Statement)
    (database : Database Input Output) (queried : Input)
    (after : Database Input Output) : Prop :=
  exists input, (input = queried ∨ database input ≠ none) ∧
    OuterChange leafStatement outer (recordsOf database) (recordsOf after) input

def TrackedInnerChange
    {Input Output RawInput RawDigest Statement Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (recordsOf : Database Input Output → Records RawInput RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Input → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Input → Label)
    (authorized : Finset Statement)
    (database : Database Input Output) (queried : Input)
    (after : Database Input Output) : Prop :=
  exists input, (input = queried ∨ database input ≠ none) ∧
    InnerChange leafStatement outer fullLabel authorized
      (recordsOf database) (recordsOf after) input

theorem tracked_complete_change_subset
    {Input Output RawInput RawDigest Statement Label : Type*}
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (recordsOf : Database Input Output → Records RawInput RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Input → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Input → Label)
    (authorized : Finset Statement)
    (database : Database Input Output) (queried : Input)
    (after : Database Input Output)
    (changed : TrackedLabelChange
      (fun db input => completeFilteredLabel leafStatement outer fullLabel authorized
        (recordsOf db) input) database queried after) :
    TrackedOuterChange recordsOf leafStatement outer database queried after ∨
      TrackedInnerChange recordsOf leafStatement outer fullLabel authorized
        database queried after := by
  obtain ⟨input, tracked, different⟩ := changed
  rcases complete_filtered_label_change_subset leafStatement outer fullLabel authorized
      (recordsOf database) (recordsOf after) input (Ne.symm different) with
      outerChange | innerChange
  · exact Or.inl ⟨input, tracked, outerChange⟩
  · exact Or.inr ⟨input, tracked, innerChange⟩

/-- Probability wrapper only: two independently established `3T/M` decoder
change bounds give the composite `6T/M` bound.  It assumes neither decoder
bound and contains no RP04 parser-specific claim. -/
theorem step_probability_union_three_three
    {Input Output : Type*}
    [Fintype Output] [DecidableEq Output]
    (composite outerEvent innerEvent : Property Input Output)
    (database : Database Input Output) (queried : Input)
    (cap modulus : Nat)
    (included : ∀ after, composite after → outerEvent after ∨ innerEvent after)
    (outerBound : stepProbability outerEvent database queried ≤
      (3 * cap : Rat) / modulus)
    (innerBound : stepProbability innerEvent database queried ≤
      (3 * cap : Rat) / modulus) :
    stepProbability composite database queried ≤ (6 * cap : Rat) / modulus := by
  by_cases nonempty : Nonempty Output
  · letI : Nonempty Output := nonempty
    calc
      stepProbability composite database queried ≤
          stepProbability (union outerEvent innerEvent) database queried :=
        step_probability_mono included database queried
      _ ≤ stepProbability outerEvent database queried +
          stepProbability innerEvent database queried :=
        step_probability_union_le outerEvent innerEvent database queried
      _ ≤ (3 * cap : Rat) / modulus + (3 * cap : Rat) / modulus :=
        add_le_add outerBound innerBound
      _ = (6 * cap : Rat) / modulus := by ring
  · letI : IsEmpty Output := ⟨fun output => nonempty ⟨output⟩⟩
    simp [stepProbability, successfulAnswers]
    positivity

/-- Concrete two-pass wrapper.  The only probabilistic hypotheses are the two
separately proved decoder-change bounds; the required event inclusion is the
deterministic theorem above. -/
theorem tracked_complete_change_probability_le_six
    {Input Output RawInput RawDigest Statement Label : Type*}
    [Fintype Output] [DecidableEq Output]
    [DecidableEq RawInput] [DecidableEq RawDigest] [DecidableEq Statement]
    (recordsOf : Database Input Output → Records RawInput RawDigest)
    (leafStatement : StatementParser RawInput Statement)
    (outer : Records RawInput RawDigest → Input → Option Statement)
    (fullLabel : Statement → Records RawInput RawDigest → Input → Label)
    (authorized : Finset Statement)
    (database : Database Input Output) (queried : Input)
    (cap modulus : Nat)
    (outerBound : stepProbability
        (TrackedOuterChange recordsOf leafStatement outer database queried)
        database queried ≤ (3 * cap : Rat) / modulus)
    (innerBound : stepProbability
        (TrackedInnerChange recordsOf leafStatement outer fullLabel authorized
          database queried) database queried ≤ (3 * cap : Rat) / modulus) :
    stepProbability
        (TrackedLabelChange
          (fun db input => completeFilteredLabel leafStatement outer fullLabel authorized
            (recordsOf db) input) database queried)
        database queried ≤ (6 * cap : Rat) / modulus := by
  apply step_probability_union_three_three _ _ _ database queried cap modulus
  · intro after changed
    exact tracked_complete_change_subset recordsOf leafStatement outer fullLabel
      authorized database queried after changed
  · exact outerBound
  · exact innerBound

end
end HegemonCrypto.SmallWood.SmzaRp04AuthorizedLabelTransport
