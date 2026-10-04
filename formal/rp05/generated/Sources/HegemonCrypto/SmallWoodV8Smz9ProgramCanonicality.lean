import HegemonCrypto.SmallWoodV8Smz9RelationProgramComponentsGenerated
import Mathlib.Data.List.Basic

/-!
Canonicality of the exact materialized HGV8RP03 program.  The checks in this module
walk each expression or CSR attempt once.  Their correctness theorems derive the
existing source grammar predicates; generated counts or successful host parsing
are not hypotheses.  Concrete checks use ordinary kernel reduction.
-/

namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

local instance (allow : Bool) (node : Nat) (expression : FieldExpression) :
    Decidable (expression.CanonicalAt allow node) := by
  cases expression <;> unfold FieldExpression.CanonicalAt <;> infer_instance

/-- A running index avoids repeated indexing into the complete expression list. -/
def checkIndexed {α : Type} (predicate : Nat → α → Bool) : Nat → List α → Bool
  | _, [] => true
  | start, value :: rest =>
      predicate start value && checkIndexed predicate (start + 1) rest

theorem checkIndexed_eq_true {α : Type} (predicate : Nat → α → Bool)
    (values : List α) (start : Nat) :
    checkIndexed predicate start values = true ↔
      ∀ index value, values[index]? = some value → predicate (start + index) value = true := by
  induction values generalizing start with
  | nil => simp [checkIndexed]
  | cons head rest ih =>
      rw [checkIndexed, Bool.and_eq_true, ih]
      constructor
      · rintro ⟨headValid, restValid⟩ index value found
        cases index with
        | zero =>
            simp only [List.getElem?_cons_zero, Option.some.injEq] at found
            subst value
            simpa using headValid
        | succ index =>
            simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
              restValid index value found
      · intro allValid
        constructor
        · simpa using allValid 0 head rfl
        · intro index value found
          simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
            allValid (index + 1) value found

def checkExpressionProgram (program : ExpressionProgram) (allowWitnessRows : Bool) : Bool :=
  checkIndexed (fun node expression => decide (expression.CanonicalAt allowWitnessRows node))
      0 program.expressions &&
    program.roots.all (fun root => decide (root < program.expressions.length))

theorem checkExpressionProgram_eq_true (program : ExpressionProgram) (allow : Bool) :
    checkExpressionProgram program allow = true ↔ program.Canonical allow := by
  simp only [checkExpressionProgram, Bool.and_eq_true, checkIndexed_eq_true,
    Nat.zero_add, decide_eq_true_eq, List.all_eq_true, ExpressionProgram.Canonical]

theorem hgv8rp03_nonlinear_expression_program_is_canonical :
    hgv8rp03ProgramComponents.nonlinearExecutable.Canonical true := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

theorem hgv8rp03_csr_expression_program_is_canonical :
    ({ expressions := hgv8rp03ProgramComponents.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical false := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

local instance (count global : Nat) (attempt : CsrExecutableAttempt) :
    Decidable (attempt.Canonical count global) := by
  unfold CsrExecutableAttempt.Canonical
  infer_instance

def familyCounter (counters : List Nat) (family : Nat) : Nat :=
  counters[family]?.getD 0

def incrementFamilyCounter (counters : List Nat) (family : Nat) : List Nat :=
  counters.set family (familyCounter counters family + 1)

def precedingFamilyCount (family : Nat) (attempts : List CsrExecutableAttempt) : Nat :=
  (attempts.filter (fun attempt => attempt.family = family)).length

theorem incrementFamilyCounter_value (counters : List Nat) (updated queried : Nat)
    (inBounds : queried < counters.length) :
    familyCounter (incrementFamilyCounter counters updated) queried =
      familyCounter counters queried + if updated = queried then 1 else 0 := by
  by_cases same : updated = queried
  · subst updated
    simp [incrementFamilyCounter, familyCounter, List.getElem?_set_self inBounds]
  · simp [incrementFamilyCounter, familyCounter, List.getElem?_set_ne same, same]

theorem precedingFamilyCount_take_cons (family index : Nat)
    (head : CsrExecutableAttempt) (rest : List CsrExecutableAttempt) :
    precedingFamilyCount family ((head :: rest).take (index + 1)) =
      precedingFamilyCount family (rest.take index) + if head.family = family then 1 else 0 := by
  by_cases same : head.family = family <;>
    simp [precedingFamilyCount, same, Nat.add_comm]

/--
The cursor verifies the actual global/local attempt indices, term references,
target reference, and the emission required by that attempt's family descriptor.
The only evolving state is 86 counters; it never rescans earlier attempts.
-/
def checkCsrFrom (expressionCount : Nat) (families : List ProgramDescriptor) :
    Nat → List Nat → List CsrExecutableAttempt → Bool
  | _, _, [] => true
  | global, counters, attempt :: rest =>
      decide (attempt.Canonical expressionCount global ∧
        attempt.localIndex = familyCounter counters attempt.family ∧
        (families[attempt.family]?).map (fun descriptor => descriptor.words[2]?) =
          some (some attempt.emission)) &&
      checkCsrFrom expressionCount families (global + 1)
        (counters.set attempt.family (attempt.localIndex + 1)) rest

theorem checkCsrFrom_sound (expressionCount : Nat) (families : List ProgramDescriptor)
    (attempts : List CsrExecutableAttempt) (global : Nat) (counters : List Nat)
    (checked : checkCsrFrom expressionCount families global counters attempts = true)
    (counterCount : counters.length = 86) :
    ∀ index attempt, attempts[index]? = some attempt →
      attempt.Canonical expressionCount (global + index) ∧
      attempt.localIndex = familyCounter counters attempt.family +
        precedingFamilyCount attempt.family (attempts.take index) ∧
      (families[attempt.family]?).map (fun descriptor => descriptor.words[2]?) =
        some (some attempt.emission) := by
  induction attempts generalizing global counters with
  | nil => simp
  | cons head rest ih =>
      simp only [checkCsrFrom, Bool.and_eq_true, decide_eq_true_eq] at checked
      rcases checked with ⟨⟨headCanonical, headLocal, headEmission⟩, restChecked⟩
      intro index attempt found
      cases index with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at found
          subst attempt
          exact ⟨by simpa using headCanonical,
            by simpa [precedingFamilyCount] using headLocal, headEmission⟩
      | succ index =>
          have nextCounterCount : (counters.set head.family (head.localIndex + 1)).length = 86 := by
            simpa using counterCount
          rcases ih (global + 1) (counters.set head.family (head.localIndex + 1))
              restChecked nextCounterCount index attempt found with
            ⟨attemptCanonical, attemptLocal, attemptEmission⟩
          have familyBound : attempt.family < counters.length := by
            simpa [counterCount] using attemptCanonical.2.1
          have update : counters.set head.family (head.localIndex + 1) =
              incrementFamilyCounter counters head.family := by
            simp only [incrementFamilyCounter, headLocal]
          rw [update,
            incrementFamilyCounter_value counters head.family attempt.family familyBound]
              at attemptLocal
          refine ⟨by simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
              using attemptCanonical, ?_, attemptEmission⟩
          rw [precedingFamilyCount_take_cons]
          simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using attemptLocal

def checkCsr (expressionCount : Nat) (families : List ProgramDescriptor)
    (attempts : List CsrExecutableAttempt) : Bool :=
  checkCsrFrom expressionCount families 0 (List.replicate 86 0) attempts

def advanceCsrCounters (counters : List Nat) (attempts : List CsrExecutableAttempt) : List Nat :=
  attempts.foldl (fun state attempt => state.set attempt.family (attempt.localIndex + 1)) counters

theorem advanceCsrCounters_append (counters : List Nat)
    (first rest : List CsrExecutableAttempt) :
    advanceCsrCounters counters (first ++ rest) =
      advanceCsrCounters (advanceCsrCounters counters first) rest := by
  simp only [advanceCsrCounters, List.foldl_append]

theorem checkCsrFrom_append (expressionCount : Nat) (families : List ProgramDescriptor)
    (first rest : List CsrExecutableAttempt) (global : Nat) (counters : List Nat) :
    checkCsrFrom expressionCount families global counters (first ++ rest) =
      (checkCsrFrom expressionCount families global counters first &&
        checkCsrFrom expressionCount families (global + first.length)
          (advanceCsrCounters counters first) rest) := by
  induction first generalizing global counters with
  | nil => simp [checkCsrFrom, advanceCsrCounters]
  | cons head first ih =>
      simp only [List.cons_append, checkCsrFrom, ih, List.length_cons,
        advanceCsrCounters, List.foldl_cons, Bool.and_assoc,
        Nat.add_comm, Nat.add_left_comm]

/-- Compose a checked bounded chunk and its independently checked final state. -/
theorem checkCsrChunk_append (expressionCount : Nat) (families : List ProgramDescriptor)
    (first rest : List CsrExecutableAttempt) (global nextGlobal : Nat)
    (initial final : List Nat)
    (chunkChecked : checkCsrFrom expressionCount families global initial first = true)
    (chunkNextGlobal : global + first.length = nextGlobal)
    (chunkFinal : advanceCsrCounters initial first = final)
    (restChecked : checkCsrFrom expressionCount families nextGlobal final rest = true) :
    checkCsrFrom expressionCount families global initial (first ++ rest) = true := by
  rw [checkCsrFrom_append, chunkChecked, chunkNextGlobal, chunkFinal, restChecked]
  rfl

theorem checkCsr_sound (expressionCount : Nat) (families : List ProgramDescriptor)
    (attempts : List CsrExecutableAttempt)
    (checked : checkCsr expressionCount families attempts = true) :
    ∀ global attempt, attempts[global]? = some attempt →
      attempt.Canonical expressionCount global ∧
      attempt.localIndex =
        ((attempts.take global).filter (fun prior => prior.family = attempt.family)).length ∧
      (families[attempt.family]?).map (fun descriptor => descriptor.words[2]?) =
        some (some attempt.emission) := by
  intro global attempt found
  have result := checkCsrFrom_sound expressionCount families attempts 0
    (List.replicate 86 0) checked (by simp) global attempt found
  have zero : familyCounter (List.replicate 86 0) attempt.family = 0 := by
    simp only [familyCounter, List.getElem?_replicate]
    split <;> rfl
  simpa only [Nat.zero_add, zero, precedingFamilyCount] using result

theorem all_decide_eq_true {α : Type} (values : List α) (predicate : α → Prop)
    [DecidablePred predicate] :
    values.all (fun value => decide (predicate value)) = true ↔
      ∀ value, value ∈ values → predicate value := by
  simp only [List.all_eq_true, decide_eq_true_eq]

def checkDescriptor (descriptor : ProgramDescriptor) : Bool :=
  decide (descriptor.opcode < 65536) && decide (descriptor.words.length < 65536) &&
    descriptor.words.all (fun word => decide (word < 18446744073709551616)) &&
    (asciiBytes descriptor.label).all (fun byte => decide (byte < 128))

theorem checkDescriptor_eq_true (descriptor : ProgramDescriptor) :
    checkDescriptor descriptor = true ↔ descriptorCanonical descriptor := by
  simp only [checkDescriptor, Bool.and_eq_true, List.all_eq_true,
    decide_eq_true_eq, descriptorCanonical, and_assoc]

/-- Convert the descriptor certificate to the original bounded universal predicate. -/
theorem hgv8rp03_descriptors_are_canonical_of_checked
    (checked :
      (hgv8rp03ProgramComponents.publicMapVersionDomain ++
        hgv8rp03ProgramComponents.nonlinearIdentities ++
        hgv8rp03ProgramComponents.linearCsrCompilerFamilies ++
        hgv8rp03ProgramComponents.hashScheduleAndCallRoles ++
        hgv8rp03ProgramComponents.bindingDescriptors).all checkDescriptor = true) :
    ∀ descriptor,
      descriptor ∈ hgv8rp03ProgramComponents.publicMapVersionDomain ++
        hgv8rp03ProgramComponents.nonlinearIdentities ++
        hgv8rp03ProgramComponents.linearCsrCompilerFamilies ++
        hgv8rp03ProgramComponents.hashScheduleAndCallRoles ++
        hgv8rp03ProgramComponents.bindingDescriptors → descriptorCanonical descriptor := by
  intro descriptor membership
  exact (checkDescriptor_eq_true descriptor).mp ((List.all_eq_true.mp checked) descriptor membership)

/-- Assemble the original predicate from exact expression/descriptor facts and the CSR check. -/
theorem hgv8rp03_program_is_canonical_of_checked_csr
    (csrChecked : checkCsr hgv8rp03ProgramComponents.csrExpressions.length
      hgv8rp03ProgramComponents.linearCsrCompilerFamilies
      hgv8rp03ProgramComponents.csrAttempts = true)
    (descriptorChecked :
      (hgv8rp03ProgramComponents.publicMapVersionDomain ++
        hgv8rp03ProgramComponents.nonlinearIdentities ++
        hgv8rp03ProgramComponents.linearCsrCompilerFamilies ++
        hgv8rp03ProgramComponents.hashScheduleAndCallRoles ++
        hgv8rp03ProgramComponents.bindingDescriptors).all checkDescriptor = true) :
    hgv8rp03ProgramComponents.Canonical := by
  rcases exact_program_component_inventory with
    ⟨_, _, nonlinearCount, familyCount, hashCount, _, nonlinearExpressionCount,
      nonlinearRootCount, csrExpressionCount, csrAttemptCount⟩
  rcases exact_program_fixed_identity_fields with ⟨geometry, parameters, bindings⟩
  refine ⟨geometry, parameters, nonlinearCount, familyCount, hashCount,
    nonlinearExpressionCount, nonlinearRootCount,
    hgv8rp03_nonlinear_expression_program_is_canonical, csrExpressionCount,
    hgv8rp03_csr_expression_program_is_canonical, csrAttemptCount,
    checkCsr_sound _ _ _ csrChecked, ?_, bindings, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · decide
  · exact (all_decide_eq_true hgv8rp03ProgramComponents.publicMapVersionDomain
      (fun descriptor => descriptor.opcode ∈ [publicIdentityOpcode, publicRangeOpcode,
        intentZeroRangeOpcode, domainOrMarkerOpcode, compilerNormalizationOpcode])).mp (by decide)
  · exact (all_decide_eq_true hgv8rp03ProgramComponents.nonlinearIdentities
      (fun descriptor => descriptor.opcode = nonlinearIdentityOpcode)).mp (by decide)
  · exact (all_decide_eq_true hgv8rp03ProgramComponents.linearCsrCompilerFamilies
      (fun descriptor => descriptor.opcode = linearCsrFamilyOpcode)).mp (by decide)
  · exact (all_decide_eq_true hgv8rp03ProgramComponents.hashScheduleAndCallRoles
      (fun descriptor => descriptor.opcode = spongeCallOpcode ∨
        descriptor.opcode = compress14CallOpcode)).mp (by decide)
  · exact (all_decide_eq_true hgv8rp03ProgramComponents.bindingDescriptors
      (fun descriptor => bindingDescriptorOpcodeStart ≤ descriptor.opcode ∧
        descriptor.opcode < bindingDescriptorOpcodeStop)).mp (by decide)
  · intro descriptor membership
    apply hgv8rp03_descriptors_are_canonical_of_checked descriptorChecked descriptor
    simpa only [List.mem_append, or_assoc] using membership

theorem rejects_forward_expression_reference :
    checkExpressionProgram { expressions := [.add 0 0], roots := [0] } false = false := by
  decide

theorem rejects_wrong_csr_local_index :
    checkCsr 1 [{ opcode := 0x0501, words := [0, 1, 0], label := "" }]
      [attempt 0 0 1 0 [] 0] = false := by
  decide

theorem rejects_wrong_csr_family_emission :
    checkCsr 1 [{ opcode := 0x0501, words := [0, 1, 0], label := "" }]
      [attempt 0 0 0 1 [] 0] = false := by
  decide

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
