import SmzaRp05ExecutableMerkleVerifier
import SmzaRp05PhysicalTerminalRead

/-! Adaptive physical interpretation of the executable read-only Program.
Every continuation is selected by the answer measured in that branch, and
the next read acts on that branch's residual CMS state. No functional oracle
is identified with a physical state. Source-only: the finite-key encoder and
raw-digest decoder still require an implementation-specific refinement. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalProgramBridge

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05SuffixReadout SmzaRp05PhysicalTerminalRead
open SmzaRp05PartialReadout
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open V8SmzaOracleParser (RawInput RawDigest)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- This bridge needs only the exact selected-view identity, not the
sequential read-charge or terminal event-distance bounds. Reflections at
unselected keys preserve the selected answer projector. -/
private theorem projection_decompress_at_of_ne
    (selected : Key) (answer : Output) (changed : Key)
    (state : State Key Output Phase Work) (different : selected ≠ changed) :
    coordinateEventProjection selected answer (decompressAt changed state) =
      decompressAt changed (coordinateEventProjection selected answer state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold coordinateEventProjection
  by_cases accepted : target.database selected = some answer
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceAccepted :
        setDatabaseCoordinate target.database changed source selected = some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_pos sourceAccepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceRejected :
        setDatabaseCoordinate target.database changed source selected ≠ some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_neg sourceRejected]
    simp

private theorem projection_decompress_list_of_outside
    (selected : Key) (answer : Output) (inputs : List Key)
    (state : State Key Output Phase Work)
    (outside : ∀ changed ∈ inputs, selected ≠ changed) :
    coordinateEventProjection selected answer (decompressList inputs state) =
      decompressList inputs (coordinateEventProjection selected answer state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : selected ≠ changed := outside changed (by simp)
      have remainingOutside : ∀ input ∈ remaining, selected ≠ input := by
        intro input member
        exact outside input (by simp [member])
      simp only [decompress_list_cons]
      rw [projection_decompress_at_of_ne selected answer changed _ changedOutside]
      rw [ih remainingOutside]

private theorem selected_physical_branch_claim_known
    (keys : List Key) (nodup : keys.Nodup)
    (answers : ReadAnswers (Input := Key) Output keys)
    (state : State Key Output Phase Work)
    (claim : Key × Output) (member : claim ∈ branchClaims keys answers) :
    KnownAt claim.1 claim.2
      (decompressList keys (physicalReadTrace keys answers state)) := by
  have claimKeys : (branchClaims keys answers).map Prod.fst = keys := by
    clear member nodup claim state
    induction keys with
    | nil => rfl
    | cons key keys ih =>
        rcases answers with ⟨answer, answers⟩
        simp [branchClaims, ih answers]
  let claims := branchClaims keys answers
  let compressed := physicalReadTrace keys answers state
  let selected := decompressList keys compressed
  let standard := globalDecompress compressed
  let outside := outsideClaimInputs claims
  have distinct : (claims.map Prod.fst).Nodup := by
    simpa only [claims, claimKeys] using nodup
  have standardEq : standard = decompressList outside selected := by
    have permutation := outside_append_claim_inputs_perm_univ claims distinct
    calc
      standard = decompressList (outside ++ claims.map Prod.fst) compressed := by
        unfold standard globalDecompress
        exact (decompress_list_perm permutation compressed).symm
      _ = decompressList outside (decompressList (claims.map Prod.fst) compressed) :=
        decompress_list_append _ _ _
      _ = decompressList outside selected := by rw [show claims.map Prod.fst = keys from claimKeys]
  have selectedEq : selected = decompressList outside standard := by
    calc
      selected = decompressList outside (decompressList outside selected) :=
        (decompress_list_involutive outside selected).symm
      _ = decompressList outside standard := by rw [← standardEq]
  have knownStandard : KnownAt claim.1 claim.2 standard :=
    physical_read_trace_claim_known keys nodup answers state claim member
  have outsideDisjoint : ∀ changed ∈ outside, claim.1 ≠ changed := by
    intro changed changedMember same
    have unclaimed := outside_claim_inputs_are_unclaimed claims changed changedMember
    have claimed : claim.1 ∈ claims.map Prod.fst :=
      List.mem_map.mpr ⟨claim, member, rfl⟩
    exact unclaimed (by simpa [← same] using claimed)
  change KnownAt claim.1 claim.2 selected
  rw [selectedEq]
  unfold KnownAt
  rw [projection_decompress_list_of_outside
    claim.1 claim.2 outside standard outsideDisjoint]
  rw [knownStandard]

/- `decode raw` may select the relevant counter coordinate of a vector
answer. No injectivity or physical-correctness property is silently assumed. -/
variable (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)

def Branches : Program Result → Type
  | .done _ => PUnit
  | .read raw next => (answer : Output) × Branches (next (decode raw answer))

def branchKeys : (program : Program Result) → Branches decode program → List Key
  | .done _, _ => []
  | .read raw next, ⟨answer, branch⟩ =>
      encode raw :: branchKeys (next (decode raw answer)) branch

def branchAnswers : (program : Program Result) → (branch : Branches decode program) →
    ReadAnswers (Input := Key) Output (branchKeys encode decode program branch)
  | .done _, _ => PUnit.unit
  | .read raw next, ⟨answer, branch⟩ =>
      (answer, branchAnswers (next (decode raw answer)) branch)

/-- Actual physical output values, paired with their original raw addresses. -/
def answerLog : (program : Program Result) → Branches decode program → List (RawInput × Output)
  | .done _, _ => []
  | .read raw next, ⟨answer, branch⟩ =>
      (raw, answer) :: answerLog (next (decode raw answer)) branch

def branchResult : (program : Program Result) → Branches decode program → Option Result
  | .done result, _ => result
  | .read raw next, ⟨answer, branch⟩ =>
      branchResult (next (decode raw answer)) branch

def rawLog (program : Program Result) (branch : Branches decode program) :
    List (RawInput × RawDigest) :=
  (answerLog decode program branch).map fun call => (call.1, decode call.1 call.2)

def physicalRun : (program : Program Result) → Branches decode program →
    State Key Output Phase Work → State Key Output Phase Work
  | .done _, _, state => state
  | .read raw next, ⟨answer, branch⟩, state =>
      physicalRun (next (decode raw answer)) branch
        (physicalReadBranch (encode raw) answer state)

/-- The adaptive interpreter is exactly the existing physical read circuit
on the branch's own adaptive keys, not on an externally supplied schedule. -/
theorem physical_run_eq_read_trace (program : Program Result)
    (branch : Branches decode program) (state : State Key Output Phase Work) :
    physicalRun encode decode program branch state =
      physicalReadTrace (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) state := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      exact ih (decode raw answer) branch (physicalReadBranch (encode raw) answer state)

/-- The generated log is the actual branch-claim list, retaining vector
answers before the scalar raw-digest interpretation. -/
theorem branch_claims_eq_answer_log (program : Program Result)
    (branch : Branches decode program) :
    branchClaims (branchKeys encode decode program branch)
      (branchAnswers encode decode program branch) =
      (answerLog decode program branch).map (fun call => (encode call.1, call.2)) := by
  induction program with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [branchKeys, branchAnswers, branchClaims, answerLog, List.map_cons]
      rw [ih (decode raw answer) branch]

/-- Optional deterministic specialization. The hypothesis concerns only
answers already generated along this branch; it does not equate a fixed
oracle with the quantum state or assert that every branch is consistent. -/
theorem record_eq_of_branch_answers (program : Program Result)
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

/-- Every reported output is known in the partially decompressed physical
branch. This uses the existing no-duplicate-key theorem; duplicate reads are
still interpreted and logged above, but are not silently deduplicated here. -/
theorem branch_answer_known (program : Program Result)
    (branch : Branches decode program)
    (distinct : (branchKeys encode decode program branch).Nodup)
    (state : State Key Output Phase Work) (raw : RawInput) (answer : Output)
    (member : (raw, answer) ∈ answerLog decode program branch) :
    KnownAt (encode raw) answer
      (decompressList (branchKeys encode decode program branch)
        (physicalRun encode decode program branch state)) := by
  rw [physical_run_eq_read_trace]
  apply selected_physical_branch_claim_known
    (branchKeys encode decode program branch) distinct
    (branchAnswers encode decode program branch) state (encode raw, answer)
  rw [branch_claims_eq_answer_log]
  exact List.mem_map.mpr ⟨(raw, answer), member, rfl⟩

/-- Exact raw-X support correspondence on a nonzero basis amplitude after
the claimed-key decompression. This is not a claim of exact support in the
recompressed database; event transport/its loss remains a separate theorem. -/
theorem nonzero_selected_basis_records_answers (program : Program Result)
    (branch : Branches decode program)
    (distinct : (branchKeys encode decode program branch).Nodup)
    (state : State Key Output Phase Work)
    (basis : Basis Key Output Phase Work)
    (nonzero : decompressList (branchKeys encode decode program branch)
      (physicalRun encode decode program branch state) basis ≠ 0) :
    ∀ raw answer, (raw, answer) ∈ answerLog decode program branch →
      basis.database (encode raw) = some answer := by
  intro raw answer member
  have known := congrFun
    (branch_answer_known encode decode program branch distinct state raw answer member) basis
  by_contra missing
  simp only [coordinateEventProjection, if_neg missing] at known
  exact nonzero known.symm

theorem nonzero_selected_basis_supports_raw_log (program : Program Result)
    (branch : Branches decode program)
    (distinct : (branchKeys encode decode program branch).Nodup)
    (state : State Key Output Phase Work) (basis : Basis Key Output Phase Work)
    (nonzero : decompressList (branchKeys encode decode program branch)
      (physicalRun encode decode program branch state) basis ≠ 0)
    (call : RawInput × RawDigest) (member : call ∈ rawLog decode program branch) :
    ∃ answer, basis.database (encode call.1) = some answer ∧
      decode call.1 answer = call.2 := by
  obtain ⟨⟨raw, answer⟩, reported, same⟩ := List.mem_map.mp member
  subst call
  exact ⟨answer, nonzero_selected_basis_records_answers encode decode
    program branch distinct state basis nonzero raw answer reported, rfl⟩

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalProgramBridge
