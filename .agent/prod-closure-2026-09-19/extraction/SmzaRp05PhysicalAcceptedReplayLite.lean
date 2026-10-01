import SmzaRp05ExecutableMerkleVerifier
import HegemonCrypto.CmsCompressedOracle
import HegemonCrypto.CmsOracleSimulation
import HegemonCrypto.CmsOracleDatabaseBridge

/-!
# Import-light physical branch replay

This module uses only the executable `Program` and core CMS database
semantics. It gives the local read step explicitly as decompress, project on
the measured answer, and recompress. Proving this local interpreter equals
`SmzaRp05PhysicalTerminalRead.physicalReadBranch/Trace` remains a separate
integration obligation; this file neither imports those modules nor assumes
that equality.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

def Branches (decode : RawInput → Output → RawDigest) : Program Result → Type
  | .done _ => PUnit
  | .read raw next => (answer : Output) × Branches decode (next (decode raw answer))

def branchKeys (encode : RawInput → Key) (decode : RawInput → Output → RawDigest) :
    (program : Program Result) → Branches decode program → List Key
  | .done _, _ => []
  | .read raw next, ⟨answer, branch⟩ =>
      encode raw :: branchKeys encode decode (next (decode raw answer)) branch

def answerLog (decode : RawInput → Output → RawDigest) :
    (program : Program Result) → Branches decode program → List (RawInput × Output)
  | .done _, _ => []
  | .read raw next, ⟨answer, branch⟩ =>
      (raw, answer) :: answerLog decode (next (decode raw answer)) branch

def branchResult (decode : RawInput → Output → RawDigest) :
    (program : Program Result) → Branches decode program → Option Result
  | .done result, _ => result
  | .read raw next, ⟨answer, branch⟩ =>
      branchResult decode (next (decode raw answer)) branch

def rawLog (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    List (RawInput × RawDigest) :=
  (answerLog decode program branch).map fun call => (call.1, decode call.1 call.2)

/-- Local one-read model, written only in terms of the cached CMS core. -/
def physicalReadStep (key : Key) (answer : Output)
    (state : State Key Output Phase Work) : State Key Output Phase Work :=
  globalDecompress
    (coordinateEventProjection key answer (globalDecompress state))

def physicalRun (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest) :
    (program : Program Result) → Branches decode program →
      State Key Output Phase Work → State Key Output Phase Work
  | .done _, _, state => state
  | .read raw next, ⟨answer, branch⟩, state =>
      physicalRun encode decode (next (decode raw answer)) branch
        (physicalReadStep (encode raw) answer state)

def ReadAnswers (Output : Type) : List Key → Type
  | [] => PUnit
  | _ :: inputs => Output × ReadAnswers Output inputs

/-- Standard-oracle view of the local physical interpreter. -/
def retainedTrace : (inputs : List Key) →
    (answers : ReadAnswers Output inputs) →
    State Key Output Phase Work → State Key Output Phase Work
  | [], _, state => state
  | key :: inputs, (answer, answers), state =>
      retainedTrace inputs answers (coordinateEventProjection key answer state)

def KnownAt (input : Key) (output : Output)
    (state : State Key Output Phase Work) : Prop :=
  coordinateEventProjection input output state = state

theorem coordinate_event_projection_idempotent
    (input : Key) (output : Output) (state : State Key Output Phase Work) :
    KnownAt input output (coordinateEventProjection input output state) := by
  funext basis
  unfold coordinateEventProjection
  by_cases recorded : basis.database input = some output <;> simp [recorded]

/-- Coordinate answer projectors commute, including when they address the
same key. Conflicting same-key answers project to zero. -/
theorem known_at_coordinate_event_projection
    (input : Key) (output : Output) (otherInput : Key) (otherOutput : Output)
    (state : State Key Output Phase Work) (known : KnownAt input output state) :
    KnownAt input output
      (coordinateEventProjection otherInput otherOutput state) := by
  funext basis
  have knownAtBasis := congrFun known basis
  unfold coordinateEventProjection at knownAtBasis ⊢
  by_cases firstRecorded : basis.database input = some output <;>
    by_cases otherRecorded : basis.database otherInput = some otherOutput
  all_goals simp [firstRecorded, otherRecorded] at knownAtBasis ⊢
  all_goals exact knownAtBasis

theorem retained_trace_preserves_known
    (inputs : List Key) (answers : ReadAnswers Output inputs)
    (state : State Key Output Phase Work) (key : Key) (value : Output)
    (known : KnownAt key value state) :
    KnownAt key value (retainedTrace inputs answers state) := by
  induction inputs generalizing state with
  | nil => simpa [retainedTrace] using known
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      exact ih answers (coordinateEventProjection input answer state)
        (known_at_coordinate_event_projection key value input answer state known)

def branchClaims : (inputs : List Key) →
    ReadAnswers Output inputs → List (Key × Output)
  | [], _ => []
  | input :: inputs, (answer, answers) =>
      (input, answer) :: branchClaims inputs answers

def branchAnswers (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest) :
    (program : Program Result) → (branch : Branches decode program) →
    ReadAnswers Output (branchKeys encode decode program branch)
  | .done _, _ => PUnit.unit
  | .read raw next, ⟨answer, branch⟩ =>
      (answer, branchAnswers encode decode (next (decode raw answer)) branch)

theorem branch_claim_known_at_repeated
    (inputs : List Key) (answers : ReadAnswers Output inputs)
    (state : State Key Output Phase Work) (claim : Key × Output)
    (member : claim ∈ branchClaims inputs answers) :
    KnownAt claim.1 claim.2 (retainedTrace inputs answers state) := by
  induction inputs generalizing state with
  | nil => cases member
  | cons input inputs ih =>
      rcases answers with ⟨answer, answers⟩
      simp only [branchClaims, List.mem_cons] at member
      rcases member with head | tail
      · cases head
        exact retained_trace_preserves_known inputs answers
          (coordinateEventProjection input answer state) input answer
          (coordinate_event_projection_idempotent input answer state)
      · exact ih answers (coordinateEventProjection input answer state) tail

theorem branch_claims_eq_answer_log
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program) :
    branchClaims (branchKeys encode decode program branch)
      (branchAnswers encode decode program branch) =
    (answerLog decode program branch).map (fun call => (encode call.1, call.2)) := by
  induction program with
  | done result => cases branch; rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [branchKeys, branchAnswers, branchClaims, answerLog, List.map_cons]
      rw [ih (decode raw answer) branch]

def basisOracle (encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest)
    (basis : Basis Key Output Phase Work) (fallback : RawDigest) : Oracle :=
  fun raw => match basis.database (encode raw) with
    | none => fallback
    | some answer => decode raw answer

theorem global_decompress_physical_read_step
    (key : Key) (answer : Output) (state : State Key Output Phase Work) :
    globalDecompress (physicalReadStep key answer state) =
      coordinateEventProjection key answer (globalDecompress state) := by
  unfold physicalReadStep
  exact global_decompress_involutive _

theorem global_decompress_physical_run_eq_retainedTrace
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : State Key Output Phase Work) :
    globalDecompress (physicalRun encode decode program branch state) =
      retainedTrace (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) (globalDecompress state) := by
  induction program generalizing state with
  | done result => cases branch; rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      change globalDecompress
          (physicalRun encode decode (next (decode raw answer)) branch
            (physicalReadStep (encode raw) answer state)) = _
      rw [ih, global_decompress_physical_read_step]
      rfl

theorem record_eq_of_branch_answers (_encode : RawInput → Key)
    (decode : RawInput → Output → RawDigest) (program : Program Result)
    (branch : Branches decode program) (oracle : Oracle)
    (agrees : ∀ call ∈ answerLog decode program branch,
      decode call.1 call.2 = oracle call.1) :
    program.record oracle =
      (branchResult decode program branch, rawLog decode program branch) := by
  induction program with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      have current : decode raw answer = oracle raw :=
        agrees (raw, answer) (by simp only [answerLog, List.mem_cons, true_or])
      have later : ∀ call ∈ answerLog decode (next (decode raw answer)) branch,
          decode call.1 call.2 = oracle call.1 := by
        intro call member
        exact agrees call (List.mem_cons_of_mem _ member)
      have tail := ih (decode raw answer) branch later
      simp only [Program.record, branchResult, rawLog, answerLog, List.map_cons]
      rw [← current, tail]
      rfl

/-- Replay any finite physical branch against the oracle extracted from a
nonzero basis of its own standard final view. Repeated encoded keys are
allowed: all read answers are known in the retained standard view, and any
inconsistent repeat annihilates that branch. -/
theorem branch_record_eq_physical_rawLog
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : State Key Output Phase Work)
    (basis : Basis Key Output Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode decode program branch state) basis ≠ 0) :
    program.record (basisOracle encode decode basis fallback) =
      (branchResult decode program branch, rawLog decode program branch) := by
  have agrees : ∀ call ∈ answerLog decode program branch,
      decode call.1 call.2 = basisOracle encode decode basis fallback call.1 := by
    intro call member
    rcases call with ⟨raw, answer⟩
    have claimMember : (encode raw, answer) ∈
        branchClaims (branchKeys encode decode program branch)
          (branchAnswers encode decode program branch) := by
      rw [branch_claims_eq_answer_log]
      exact List.mem_map.mpr ⟨(raw, answer), member, rfl⟩
    have known := branch_claim_known_at_repeated
      (branchKeys encode decode program branch)
      (branchAnswers encode decode program branch) (globalDecompress state)
      (encode raw, answer) claimMember
    have knownFinal : KnownAt (encode raw) answer
        (globalDecompress (physicalRun encode decode program branch state)) := by
      rw [global_decompress_physical_run_eq_retainedTrace]
      exact known
    have knownAtBasis := congrFun knownFinal basis
    have supported : basis.database (encode raw) = some answer := by
      by_contra missing
      unfold coordinateEventProjection at knownAtBasis
      rw [if_neg missing] at knownAtBasis
      exact nonzero knownAtBasis.symm
    simp [basisOracle, supported]
  have replay := record_eq_of_branch_answers encode decode program branch
    (basisOracle encode decode basis fallback) agrees
  exact replay

/-- Existing unit-returning accepted-event specialization. -/
theorem accepted_branch_record_eq_physical_rawLog
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Unit) (branch : Branches decode program)
    (state : State Key Output Phase Work)
    (basis : Basis Key Output Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode decode program branch state) basis ≠ 0)
    (accepted : branchResult decode program branch = some ()) :
    program.record (basisOracle encode decode basis fallback) =
      (some (), rawLog decode program branch) := by
  simpa only [accepted] using
    branch_record_eq_physical_rawLog encode decode program branch state basis
      fallback nonzero

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite
