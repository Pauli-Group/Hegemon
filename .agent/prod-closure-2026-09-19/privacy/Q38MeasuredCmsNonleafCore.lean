import HegemonCrypto.CmsQuerySequence
import HegemonCrypto.CmsOracleDatabaseBridge
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule

/-!
An actual measured-CMS semantics for the finite `NonleafProgram` grammar.

An honest classical read is implemented in the standard-oracle coordinates:
decompress the complete CMS state, project the requested total-oracle
coordinate onto one digest, and recompress.  Thus no classical query log or
external oracle table is introduced.  `PublicTrace fuel` is a fixed finite
branch type, independent of the adaptively selected query keys.  Its `none`
constructor is the unique canonical padding once a program has terminated;
all noncanonical branches have the zero state.
-/
namespace HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramPiop
open HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

variable {Input Phase Work Other Result : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

abbrev CmsState (Input Phase Work : Type) :=
  HegemonCrypto.CmsCompressedOracle.State Input DigestRegister Phase Work

/-- A complete standard-oracle measurement branch, returned to the same CMS
state space so that later compressed queries continue on the same database. -/
def measuredReadBranch (input : Input) (answer : DigestRegister)
    (state : CmsState Input Phase Work) : CmsState Input Phase Work :=
  globalDecompress
    (coordinateEventProjection input answer (globalDecompress state))

/-- The exact initialized/reachable invariant needed by classical reads.  It
says only that the standard-oracle presentation has no absent coordinates. -/
def GloballyTotal (state : CmsState Input Phase Work) : Prop :=
  ∀ input, TotalAt input (globalDecompress state)

theorem globally_total_of_total_oracle_simulation
    (state : CmsState Input Phase Work)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister) (Phase := Phase)
      (Workspace := Work))
    (simulation :
      globalDecompress state = totalOracleFamilyState family) :
    GloballyTotal state := by
  intro input
  rw [simulation]
  exact total_oracle_family_state_total_at family input

/-- Projecting one answer cannot create an absent coordinate, including at a
different input. -/
theorem coordinate_projection_total_at
    (selected : Input) (answer : DigestRegister)
    (preserved : Input) (state : CmsState Input Phase Work)
    (total : TotalAt preserved state) :
    TotalAt preserved (coordinateEventProjection selected answer state) := by
  intro basis absent
  unfold coordinateEventProjection
  split
  · exact total basis absent
  · rfl

/-- Decompressing a measured branch returns exactly its standard-oracle
coordinate projection. -/
theorem global_decompress_measured_read_branch
    (input : Input) (answer : DigestRegister)
    (state : CmsState Input Phase Work) :
    globalDecompress (measuredReadBranch input answer state) =
      coordinateEventProjection input answer (globalDecompress state) := by
  exact global_decompress_involutive _

theorem measured_read_branch_globally_total
    (input : Input) (answer : DigestRegister)
    (state : CmsState Input Phase Work)
    (total : GloballyTotal state) :
    GloballyTotal (measuredReadBranch input answer state) := by
  intro preserved
  rw [global_decompress_measured_read_branch]
  exact coordinate_projection_total_at input answer preserved
    (globalDecompress state) (total preserved)

/-- The answer projectors form a complete orthogonal partition whenever the
standard-oracle coordinate is total. -/
theorem coordinate_projection_complete
    (input : Input) (state : CmsState Input Phase Work)
    (total : TotalAt input state) :
    (∑ answer : DigestRegister,
      normSquared (coordinateEventProjection input answer state)) =
      normSquared state := by
  unfold normSquared coordinateEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  cases recorded : basis.database input with
  | none =>
      have zero := total basis recorded
      simp [recorded, zero]
  | some actual =>
      rw [Finset.sum_eq_single actual]
      · simp [recorded]
      · intro candidate _ different
        simp [recorded, Ne.symm different]
      · simp

/-- Exact probability conservation for one measured honest read. -/
theorem measured_read_branch_complete
    (input : Input) (state : CmsState Input Phase Work)
    (total : GloballyTotal state) :
    (∑ answer : DigestRegister,
      normSquared (measuredReadBranch input answer state)) =
      normSquared state := by
  calc
    _ = ∑ answer : DigestRegister,
        normSquared
          (coordinateEventProjection input answer
            (globalDecompress state)) := by
      apply Finset.sum_congr rfl
      intro answer _
      exact decompress_list_preserves_norm_squared
        (Finset.univ : Finset Input).toList _
    _ = normSquared (globalDecompress state) :=
      coordinate_projection_complete input (globalDecompress state)
        (total input)
    _ = normSquared state :=
      decompress_list_preserves_norm_squared
        (Finset.univ : Finset Input).toList state

/- A uniform finite branch type.  `none` means that the program has stopped;
`some (answer, tail)` records one read and the remaining answer trace. -/
@[reducible] def PublicTrace (Output : Type) : Nat → Type
  | 0 => Unit
  | fuel + 1 => Option (Output × PublicTrace Output fuel)

@[reducible] def publicTraceFintype {Output : Type} [Fintype Output] :
    (fuel : Nat) → Fintype (PublicTrace Output fuel)
  | 0 => inferInstance
  | fuel + 1 =>
      letI : Fintype (PublicTrace Output fuel) := publicTraceFintype fuel
      inferInstance

attribute [instance] publicTraceFintype

/-- Terminal public value selected by a padded trace. Invalid or noncanonical
traces return `none`; their state below is exactly zero. -/
def traceResult (fuel : Nat) (program : NonleafProgram Other Result) :
    PublicTrace DigestRegister fuel → Option Result :=
  match fuel, program with
  | 0, .done result => fun _ => some result
  | 0, .read _ _ => fun _ => none
  | _ + 1, .done result => fun trace =>
      match trace with
      | none => some result
      | some _ => none
  | fuel + 1, .read _ next => fun trace =>
      match trace with
      | none => none
      | some (answer, tail) => traceResult fuel (next answer) tail

/-- Actual recursive measured compiler. Query keys may depend on all earlier
answers. Every terminal branch remains an unnormalised vector in the original
CMS state/database space. -/
def traceState (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result) :
    PublicTrace DigestRegister fuel → CmsState Input Phase Work →
      CmsState Input Phase Work :=
  match fuel, program with
  | 0, .done _ => fun _ state => state
  | 0, .read _ _ => fun _ _ => 0
  | _ + 1, .done _ => fun trace state =>
      match trace with
      | none => state
      | some _ => 0
  | fuel + 1, .read input next => fun trace state =>
      match trace with
      | none => 0
      | some (answer, tail) =>
          traceState embed fuel (next answer) tail
            (measuredReadBranch (embed input) answer state)

/-- Executable public instrument branch: the public result and its
unnormalised CMS vector are produced by the same trace recursion. -/
def traceOutcome (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (trace : PublicTrace DigestRegister fuel)
    (state : CmsState Input Phase Work) :
    Option Result × CmsState Input Phase Work :=
  (traceResult fuel program trace,
    traceState embed fuel program trace state)

/-- Additive branch probability for the complete measured compiler.  The
read-count premise is discharged from the concrete program's existing exact
budget; it is not a new oracle-query allowance. -/
theorem trace_state_complete
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (state : CmsState Input Phase Work)
    (total : GloballyTotal state) :
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (traceState embed fuel program trace state)) =
      normSquared state := by
  induction fuel generalizing program state with
  | zero =>
      cases program with
      | done result => simp [traceState, PublicTrace]
      | read input next => simp [NonleafProgram.readCount] at enough
  | succ fuel ih =>
      cases program with
      | done result =>
          have zeroNorm :
              normSquared (0 : CmsState Input Phase Work) = 0 := by
            simp [normSquared]
          simp only [PublicTrace, Fintype.sum_option,
            Fintype.sum_prod_type, traceState, zeroNorm,
            Finset.sum_const_zero, add_zero]
      | read input next =>
          have tailEnough (answer : DigestRegister) :
              NonleafProgram.readCount (next answer) ≤ fuel := by
            have supremum : NonleafProgram.readCount (next answer) ≤
                Finset.univ.sup fun output =>
                  NonleafProgram.readCount (next output) :=
              Finset.le_sup
                (f := fun output : DigestRegister =>
                  NonleafProgram.readCount (next output))
                (Finset.mem_univ answer)
            exact supremum.trans (Nat.le_of_succ_le_succ enough)
          have zeroNorm :
              normSquared (0 : CmsState Input Phase Work) = 0 := by
            simp [normSquared]
          simp only [PublicTrace, Fintype.sum_option, Fintype.sum_prod_type,
            traceState, zeroNorm, zero_add]
          calc
            _ = ∑ answer : DigestRegister,
                normSquared
                  (measuredReadBranch (embed input) answer state) := by
              apply Finset.sum_congr rfl
              intro answer _
              exact ih (next answer) (tailEnough answer)
                (measuredReadBranch (embed input) answer state)
                (measured_read_branch_globally_total _ _ _ total)
            _ = normSquared state :=
              measured_read_branch_complete (embed input) state total

/-- Ready-to-consume form for an initialized CMS execution: the only premise
is the exact simulation equality already maintained by the CMS run. -/
theorem trace_state_complete_of_total_oracle_simulation
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (state : CmsState Input Phase Work)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister) (Phase := Phase)
      (Workspace := Work))
    (simulation :
      globalDecompress state = totalOracleFamilyState family) :
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (traceState embed fuel program trace state)) =
      normSquared state :=
  trace_state_complete embed fuel program enough state
    (globally_total_of_total_oracle_simulation state family simulation)

/-- Fully instantiated raw-CMS endpoint.  Starting from the existing empty
partial-random-oracle state and executing the existing database-independent
query list gives the exact total-oracle simulation required above; it is not
an additional measurement or privacy premise. -/
theorem trace_state_complete_after_raw_run
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (system : PhaseSystem DigestRegister Phase)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := DigestRegister) (Phase := Phase)
      (Workspace := Work)))
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Work) → ℂ)
    (capacity : steps.length ≤ queryBound) :
    let state := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (traceState embed fuel program trace state)) =
      normSquared state := by
  let state := rawRun system queryBound
    (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
    (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
  let family := oracleFamilyRun system steps (fun _oracle => initialRegisters)
  exact trace_state_complete_of_total_oracle_simulation
    embed fuel program enough state family
      (compressed_run_is_uniform_random_oracle_purification
        system queryBound steps initialRegisters capacity)

/-- Exact-budget form: the finite public branch width is the concrete
program's existing `readCount`, so no extra read or support allowance is
introduced. -/
theorem trace_state_complete_after_raw_run_exact_budget
    (embed : Other → Input)
    (program : NonleafProgram Other Result)
    (system : PhaseSystem DigestRegister Phase)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := DigestRegister) (Phase := Phase)
      (Workspace := Work)))
    (initialRegisters :
      RegisterBasis (Input := Input) (Phase := Phase) (Workspace := Work) → ℂ)
    (capacity : steps.length ≤ queryBound) :
    let state := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    (∑ trace : PublicTrace DigestRegister (NonleafProgram.readCount program),
      normSquared (traceState embed (NonleafProgram.readCount program)
        program trace state)) = normSquared state := by
  exact trace_state_complete_after_raw_run embed
    (NonleafProgram.readCount program) program le_rfl system queryBound steps
    initialRegisters capacity

end
end HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
