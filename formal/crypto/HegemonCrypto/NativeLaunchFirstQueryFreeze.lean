import SmzaRp05ExecutableMerkleVerifier
import HegemonCrypto.NativeLaunchAdaptiveHistoryCodec

/-! A stopped interpreter for the actual generic adaptive Program datatype.
It stops BEFORE consulting the oracle at the first matching raw query. Its
priorLog and continuation are calculated from the program and earlier answers.
Only the generic Program/record machinery is reused, not old Merkle acceptance.
Repeated calls and failed completed runs are retained. This is a deterministic
classical causal core, not Rust refinement, online capture of every priorLog,
native source/context/FPP freezing, or QROM security. All launch gates stay open. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchFirstQueryFreeze
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmallWood.SmzaRp05LeafNamespace (RawInput)
open SmallWood.V8SmzaOracleParser (RawDigest)
open NativeLaunchAdaptiveHistoryCodec (Family Role Word sourceFrame)

inductive Stopped (α : Type) where
  | complete : Option α → Log → Stopped α
  | before : Log → RawInput → (RawDigest → Program α) → Stopped α

def priorLog {α : Type} : Stopped α → Log
  | .complete _ log => log
  | .before log _ _ => log

def prepend {α : Type} (call : RawInput × RawDigest) : Stopped α → Stopped α
  | .complete result log => .complete result (call :: log)
  | .before log input next => .before (call :: log) input next

theorem prefix_prepend {α : Type} (call : RawInput × RawDigest) (stopped : Stopped α) :
    priorLog (prepend call stopped) = call :: priorLog stopped := by cases stopped <;> rfl

/-- The matching branch does not evaluate `oracle input`. -/
def stop {α : Type} (oracle : Oracle) (target : RawInput → Bool) : Program α → Stopped α
  | .done result => .complete result []
  | .read input next =>
      if target input = true then .before [] input next
      else prepend (input, oracle input) (stop oracle target (next (oracle input)))

/-- The trigger answer is consulted only to reconstruct the remaining full
execution, after the stopped priorLog/key/continuation already exists. -/
def resume {α : Type} (oracle : Oracle) : Stopped α → Option α × Log
  | .complete result log => (result, log)
  | .before log input next =>
      let below := (next (oracle input)).record oracle
      (below.1, log ++ (input, oracle input) :: below.2)

theorem resume_prepend {α : Type} (oracle : Oracle) (call : RawInput × RawDigest) (stopped : Stopped α) :
    resume oracle (prepend call stopped) = ((resume oracle stopped).1, call :: (resume oracle stopped).2) := by
  cases stopped <;> rfl

theorem record_eq_resume_stop {α : Type} (oracle : Oracle) (target : RawInput → Bool) (program : Program α) :
    program.record oracle = resume oracle (stop oracle target program) := by
  induction program with
  | done result => rfl
  | read input next ih =>
      by_cases hit : target input = true
      · simp only [stop, if_pos hit, resume, Program.record, List.nil_append]
      · simp only [stop, if_neg hit, resume_prepend, Program.record]
        rw [ih (oracle input)]

theorem before_record_decomposition {α : Type} (oracle : Oracle) (target : RawInput → Bool)
    (program : Program α) (before : Log) (input : RawInput) (next : RawDigest → Program α)
    (stopped : stop oracle target program = .before before input next) :
    program.record oracle =
      (((next (oracle input)).record oracle).1,
        before ++ (input, oracle input) :: ((next (oracle input)).record oracle).2) := by
  rw [record_eq_resume_stop oracle target program, stopped]
  rfl

theorem prefix_nonmatching {α : Type} (oracle : Oracle) (target : RawInput → Bool)
    (program : Program α) : ∀ call ∈ priorLog (stop oracle target program), target call.1 ≠ true := by
  induction program with
  | done result => simp [stop, priorLog]
  | read input next ih =>
      by_cases hit : target input = true
      · simp [stop, hit, priorLog]
      · intro call member
        simp only [stop, if_neg hit, prefix_prepend, List.mem_cons] at member
        rcases member with same | below
        · subst call; exact hit
        · exact ih (oracle input) call below

def triggerMatches {α : Type} (target : RawInput → Bool) : Stopped α → Prop
  | .complete _ _ => True
  | .before _ input _ => target input = true

theorem trigger_matches {α : Type} (oracle : Oracle) (target : RawInput → Bool) (program : Program α) :
    triggerMatches target (stop oracle target program) := by
  induction program with
  | done result => trivial
  | read input next ih =>
      by_cases hit : target input = true
      · simpa only [stop, if_pos hit, triggerMatches] using hit
      · simp only [stop, if_neg hit]
        have below := ih (oracle input)
        cases h : stop oracle target (next (oracle input)) with
        | complete result log => trivial
        | before log key continuation =>
            rw [h] at below
            exact below

/-- Agreement is required only at keys ACTUALLY recorded before the first
matching query under H. The entire stopped result, including its continuation,
is identical under G, with no agreement at the trigger or later queries. -/
theorem stop_replay {α : Type} (H G : Oracle) (target : RawInput → Bool) (program : Program α)
    (agree : ∀ call ∈ priorLog (stop H target program), G call.1 = H call.1) :
    stop G target program = stop H target program := by
  induction program with
  | done result => rfl
  | read input next ih =>
      by_cases hit : target input = true
      · simp only [stop, if_pos hit]
      · have atInput : G input = H input := by
          apply agree (input, H input)
          simp only [stop, if_neg hit, prefix_prepend, List.mem_cons, true_or]
        have below : ∀ call ∈ priorLog (stop H target (next (H input))), G call.1 = H call.1 := by
          intro call member
          apply agree call
          simp only [stop, if_neg hit, prefix_prepend, List.mem_cons]
          exact Or.inr member
        simp only [stop, if_neg hit]
        rw [atInput, ih (H input) below]

/-- A callback receives only recorded earlier pairs and the triggering input;
it has no oracle, trigger-answer or continuation parameter. -/
def snapshot {α β : Type} (capture : Log → RawInput → β) : Stopped α → Option β
  | .complete _ _ => none
  | .before before input _ => some (capture before input)

theorem snapshot_replay {α β : Type} (H G : Oracle) (target : RawInput → Bool) (program : Program α)
    (capture : Log → RawInput → β)
    (agree : ∀ call ∈ priorLog (stop H target program), G call.1 = H call.1) :
    snapshot capture (stop G target program) = snapshot capture (stop H target program) := by
  exact congrArg (snapshot capture) (stop_replay H G target program agree)

/-- Literal fixed family/role/payload target across ALL raw u64 counters.
This optional target predicate is classical; the stopped interpreter itself
accepts any executable Boolean key predicate. No counter-zero restriction. -/
noncomputable def sourceTarget (family : Family) (role : Role) (words : List Word) (input : RawInput) : Bool :=
  @decide (∃ counter : Word, input = sourceFrame family role words counter) (Classical.propDecidable _)

theorem every_source_counter_matches (family : Family) (role : Role) (words : List Word) (counter : Word) :
    sourceTarget family role words (sourceFrame family role words counter) = true := by
  simp only [sourceTarget, decide_eq_true_eq]
  exact ⟨counter, rfl⟩

end HegemonCrypto.NativeLaunchFirstQueryFreeze
