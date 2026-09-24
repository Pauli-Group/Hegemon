import Mathlib.Data.Finset.Card

/-!
# Finite recorded-oracle databases

The compressed-oracle analysis used by the BCS transform reasons about finite recorded maps
from hash inputs to hash outputs.  This module provides that object without importing any
SmallWood-specific syntax or assuming that quantum queries can be read as a classical log.

The results here are deterministic.  They prove the database state-restoration and collision
uniqueness facts used after a compressed-oracle database has been measured.  The quantum lifting
argument that bounds the probability of measuring a bad database is separate.
-/

namespace HegemonCrypto.FiniteOracleDatabase

variable {Input Output : Type*}

/-- A finite oracle table. `none` means that an input is not recorded. -/
abbrev Database (Input Output : Type*) := Input → Option Output

def empty : Database Input Output :=
  fun _ => none

def erase [DecidableEq Input]
    (database : Database Input Output)
    (input : Input) : Database Input Output :=
  fun selected => if selected = input then none else database selected

def insert [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output) : Database Input Output :=
  fun selected => if selected = input then some output else database selected

@[simp]
theorem empty_apply (input : Input) :
    (empty : Database Input Output) input = none := by
  rfl

@[simp]
theorem erase_same [DecidableEq Input]
    (database : Database Input Output)
    (input : Input) :
    erase database input input = none := by
  simp [erase]

@[simp]
theorem erase_other [DecidableEq Input]
    (database : Database Input Output)
    {erased selected : Input}
    (different : selected ≠ erased) :
    erase database erased selected = database selected := by
  simp [erase, different]

/-- Erasing an already absent entry leaves the database unchanged. -/
theorem erase_of_absent [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (absent : database input = none) :
    erase database input = database := by
  funext selected
  by_cases same : selected = input
  · subst selected
    simpa using absent.symm
  · simp [erase, same]

@[simp]
theorem insert_same [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output) :
    insert database input output input = some output := by
  simp [insert]

@[simp]
theorem insert_other [DecidableEq Input]
    (database : Database Input Output)
    {inserted selected : Input}
    (different : selected ≠ inserted)
    (output : Output) :
    insert database inserted output selected = database selected := by
  simp [insert, different]

/--
Deleting a recorded input and reinserting the recorded value restores the database exactly.  This
is the classical state-restoration identity needed by the measured-database extractor.
-/
theorem erase_then_insert_restores [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (recorded : database input = some output) :
    insert (erase database input) input output = database := by
  funext selected
  by_cases same : selected = input
  · subst selected
    simpa using recorded.symm
  · simp [insert, erase, same]

/-- Erasing an entry immediately after inserting it into an absent slot restores the database. -/
theorem insert_then_erase_restores_of_absent [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : database input = none) :
    erase (insert database input output) input = database := by
  funext selected
  by_cases same : selected = input
  · subst selected
    simpa using absent.symm
  · simp [insert, erase, same]

/-- Inserting into one fixed slot is injective in the inserted output. -/
theorem insert_output_injective [DecidableEq Input]
    (database : Database Input Output)
    (input : Input) :
    Function.Injective (insert database input) := by
  intro left right equalDatabases
  have atInput := congrFun equalDatabases input
  simpa using atInput

/-- Inserting into an absent slot cannot leave the database unchanged. -/
theorem insert_ne_of_absent [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : database input = none) :
    insert database input output ≠ database := by
  intro equalDatabases
  have atInput := congrFun equalDatabases input
  simp [absent] at atInput

/-- An absent database cannot equal the result of inserting at its absent slot. -/
theorem ne_insert_of_absent [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : database input = none) :
    database ≠ insert database input output :=
  (insert_ne_of_absent database input output absent).symm

/-- Any database absent at an input differs from every database with that input inserted. -/
theorem absent_ne_insert_at [DecidableEq Input]
    (absentDatabase insertedBase : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : absentDatabase input = none) :
    absentDatabase ≠ insert insertedBase input output := by
  intro equalDatabases
  have atInput := congrFun equalDatabases input
  simp [absent] at atInput

/-- Every database with an inserted record differs from any database absent at that input. -/
theorem insert_at_ne_absent [DecidableEq Input]
    (insertedBase absentDatabase : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : absentDatabase input = none) :
    insert insertedBase input output ≠ absentDatabase :=
  (absent_ne_insert_at absentDatabase insertedBase input output absent).symm

/--
Two insertions into absent slots at the same input are equal exactly when both absent bases and
both inserted outputs are equal.
-/
@[simp]
theorem insert_eq_insert_iff_of_absent [DecidableEq Input]
    (left right : Database Input Output)
    (input : Input)
    (leftOutput rightOutput : Output)
    (leftAbsent : left input = none)
    (rightAbsent : right input = none) :
    insert left input leftOutput = insert right input rightOutput ↔
      left = right ∧ leftOutput = rightOutput := by
  constructor
  · intro equalDatabases
    have outputEqual : leftOutput = rightOutput := by
      have atInput := congrFun equalDatabases input
      simpa using atInput
    have erasedEqual :=
      congrArg (fun database => erase database input) equalDatabases
    change
      erase (insert left input leftOutput) input =
        erase (insert right input rightOutput) input at erasedEqual
    rw [insert_then_erase_restores_of_absent left input leftOutput leftAbsent,
      insert_then_erase_restores_of_absent right input rightOutput rightAbsent]
      at erasedEqual
    exact ⟨erasedEqual, outputEqual⟩
  · rintro ⟨rfl, rfl⟩
    rfl

/-- Replacing one entry twice retains only the final value. -/
theorem insert_shadow [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (first second : Output) :
    insert (insert database input first) input second =
      insert database input second := by
  funext selected
  by_cases same : selected = input <;> simp [insert, same]

/-- Pointwise inclusion of recorded query-answer pairs. -/
def Extends
    (smaller larger : Database Input Output) : Prop :=
  ∀ input output, smaller input = some output → larger input = some output

theorem Extends.refl (database : Database Input Output) :
    Extends database database := by
  intro input output recorded
  exact recorded

theorem Extends.trans
    {first second third : Database Input Output}
    (firstSecond : Extends first second)
    (secondThird : Extends second third) :
    Extends first third := by
  intro input output recorded
  exact secondThird input output (firstSecond input output recorded)

theorem empty_extends (database : Database Input Output) :
    Extends empty database := by
  intro input output recorded
  simp at recorded

/-- Inserting an unrecorded input extends the original database. -/
theorem extends_insert_of_absent [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : database input = none) :
    Extends database (insert database input output) := by
  intro selected recordedOutput recorded
  by_cases same : selected = input
  · subst selected
    rw [absent] at recorded
    contradiction
  · simpa [insert, same] using recorded

/-- Every recorded answer agrees with the selected total oracle. -/
def ConsistentWith
    (oracle : Input → Output)
    (database : Database Input Output) : Prop :=
  ∀ input output, database input = some output → oracle input = output

theorem empty_consistent (oracle : Input → Output) :
    ConsistentWith oracle empty := by
  intro input output recorded
  simp at recorded

theorem consistent_erase [DecidableEq Input]
    {oracle : Input → Output}
    {database : Database Input Output}
    (consistent : ConsistentWith oracle database)
    (input : Input) :
    ConsistentWith oracle (erase database input) := by
  intro selected output recorded
  by_cases same : selected = input
  · subst selected
    simp at recorded
  · exact consistent selected output (by simpa [erase, same] using recorded)

theorem consistent_insert [DecidableEq Input]
    {oracle : Input → Output}
    {database : Database Input Output}
    (consistent : ConsistentWith oracle database)
    (input : Input) :
    ConsistentWith oracle (insert database input (oracle input)) := by
  intro selected output recorded
  by_cases same : selected = input
  · subst selected
    simpa [insert] using recorded
  · exact consistent selected output (by simpa [insert, same] using recorded)

/-- Two distinct recorded inputs with one recorded output form a database collision. -/
def HasCollision
    (database : Database Input Output) : Prop :=
  ∃ left right output,
    left ≠ right ∧
      database left = some output ∧
      database right = some output

def CollisionFree
    (database : Database Input Output) : Prop :=
  ¬HasCollision database

/-- A collision-free database gives each recorded output at most one recorded preimage. -/
theorem input_unique_of_same_recorded_output
    {database : Database Input Output}
    (collisionFree : CollisionFree database)
    {left right : Input}
    {output : Output}
    (leftRecorded : database left = some output)
    (rightRecorded : database right = some output) :
    left = right := by
  by_contra different
  exact collisionFree ⟨left, right, output, different, leftRecorded, rightRecorded⟩

/-- A collision in an oracle-consistent database exposes an actual collision in the oracle. -/
theorem collision_exhibits_oracle_collision
    {oracle : Input → Output}
    {database : Database Input Output}
    (consistent : ConsistentWith oracle database)
    (collision : HasCollision database) :
    ∃ left right,
      left ≠ right ∧ oracle left = oracle right := by
  rcases collision with
    ⟨left, right, output, different, leftRecorded, rightRecorded⟩
  exact ⟨left, right, different,
    (consistent left output leftRecorded).trans
      (consistent right output rightRecorded).symm⟩

section FiniteSupport

variable [Fintype Input]

/-- Inputs explicitly recorded by a finite-domain database. -/
def support
    (database : Database Input Output) : Finset Input :=
  Finset.univ.filter fun input => (database input).isSome

def size
    (database : Database Input Output) : Nat :=
  (support database).card

theorem mem_support_iff
    (database : Database Input Output)
    (input : Input) :
    input ∈ support database ↔ ∃ output, database input = some output := by
  simp [support, Option.isSome_iff_exists]

theorem size_empty :
    size (empty : Database Input Output) = 0 := by
  simp [size, support]

theorem support_erase_subset
    [DecidableEq Input]
    (database : Database Input Output)
    (input : Input) :
    support (erase database input) ⊆ support database := by
  intro selected selectedMembership
  rw [mem_support_iff] at selectedMembership ⊢
  rcases selectedMembership with ⟨output, recorded⟩
  by_cases same : selected = input
  · subst selected
    simp at recorded
  · exact ⟨output, by simpa [erase, same] using recorded⟩

theorem size_erase_le
    [DecidableEq Input]
    (database : Database Input Output)
    (input : Input) :
    size (erase database input) ≤ size database := by
  exact Finset.card_le_card (support_erase_subset database input)

/-- Inserting into an absent slot adds exactly one support element. -/
theorem size_insert_of_absent
    [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (absent : database input = none) :
    size (insert database input output) = size database + 1 := by
  classical
  have supportIdentity :
      support (insert database input output) =
        Insert.insert input (support database) := by
    ext selected
    by_cases same : selected = input
    · subst selected
      simp [support]
    · simp [support, FiniteOracleDatabase.insert, same]
  rw [size, supportIdentity, Finset.card_insert_of_notMem]
  · rfl
  · simp [mem_support_iff, absent]

/-- Erasing a recorded slot removes exactly one support element. -/
theorem size_erase_of_recorded
    [DecidableEq Input]
    (database : Database Input Output)
    (input : Input)
    (output : Output)
    (recorded : database input = some output) :
    size (erase database input) + 1 = size database := by
  have absentAfterErase : erase database input input = none := erase_same database input
  have restored :
      insert (erase database input) input output = database :=
    erase_then_insert_restores database input output recorded
  have insertedSize :=
    size_insert_of_absent (erase database input) input output absentAfterErase
  rw [restored] at insertedSize
  exact insertedSize.symm

end FiniteSupport

end HegemonCrypto.FiniteOracleDatabase
