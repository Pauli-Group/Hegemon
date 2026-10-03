import SmzaRp05ExecutableMerkleVerifier
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentFiniteGroupedProgram

/-! # Oracle agreement from actual program reads

Two deterministic oracles that agree at every input read by a program have
the same recorded result and evaluation. A second lemma obtains that local
agreement from two databases satisfying claims for the same grouped branch.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentBranchOracleAgreement

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches rawLog answerLog)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode claims_supply_grouped_oracle_answers)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentRoleLabels (currentRawInputDecidableEq)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05GroupedSuffix (GroupCounter)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

local instance : DecidableEq RawInput := currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

/-- Equality of oracle answers on the actual left-hand read log is enough
for equality of the complete instrumented result. No right-hand result or
execution equality is assumed. -/
theorem record_eq_of_agrees_on_left_reads
    {Result : Type} (program : Program Result) (left right : Oracle)
    (agrees : ∀ input, (input, left input) ∈ (program.record left).2 →
      left input = right input) :
    program.record left = program.record right := by
  induction program generalizing left right with
  | done result => rfl
  | read input next ih =>
      have headAgree : left input = right input := by
        apply agrees input
        simp [Program.record]
      have tailAgree : ∀ query,
          (query, left query) ∈ ((next (left input)).record left).2 →
            left query = right query := by
        intro query member
        apply agrees query
        simp only [Program.record, List.mem_cons]
        exact Or.inr member
      have tailEq := ih (left input) left right tailAgree
      simp only [Program.record]
      rw [tailEq, headAgree]

/-- Evaluation equality follows from the first projection of the recorded
result; this is still derived from read-by-read oracle agreement. -/
theorem eval_eq_of_agrees_on_left_reads
    {Result : Type} (program : Program Result) (left right : Oracle)
    (agrees : ∀ input, (input, left input) ∈ (program.record left).2 →
      left input = right input) :
    program.eval left = program.eval right := by
  have same := record_eq_of_agrees_on_left_reads program left right agrees
  calc
    program.eval left = (program.record left).1 :=
      (Program.record_result left program).symm
    _ = (program.record right).1 := congrArg Prod.fst same
    _ = program.eval right := Program.record_result right program

/-- Two databases that satisfy the same compressed-claims event for one
grouped branch give the same oracle answers on every read in the actual
program record. This is scoped to that program and branch, not a claim that
the databases are globally equal. -/
theorem same_branch_claims_agree_on_record_reads
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (leftDatabase rightDatabase : Database (Key program) (VectorOutput GroupCounter))
    (leftClaims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      leftDatabase)
    (rightClaimsCorrect : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      rightDatabase)
    (leftFallback rightFallback : RawDigest) :
    ∀ input, (input, finiteGroupedDatabaseOracle program leftDatabase leftFallback input) ∈
      (program.record (finiteGroupedDatabaseOracle program leftDatabase leftFallback)).2 →
      finiteGroupedDatabaseOracle program leftDatabase leftFallback input =
        finiteGroupedDatabaseOracle program rightDatabase rightFallback input := by
  intro input member
  let leftOracle := finiteGroupedDatabaseOracle program leftDatabase leftFallback
  let rightOracle := finiteGroupedDatabaseOracle program rightDatabase rightFallback
  have leftAnswers : ∀ call ∈ answerLog groupedDecode program branch,
      groupedDecode call.1 call.2 = leftOracle call.1 := by
    intro call memberCall
    have answer := claims_supply_grouped_oracle_answers
      (encode := encode program) program branch leftDatabase leftClaims
      leftFallback call memberCall
    cases stored : leftDatabase (encode program call.1) <;>
      simpa [leftOracle, finiteGroupedDatabaseOracle, groupedDecode, stored] using answer
  have replay := SmzaRp05PhysicalAcceptedReplayLite.record_eq_of_branch_answers
    (encode program) groupedDecode program branch leftOracle leftAnswers
  have rawMember : (input, leftOracle input) ∈ rawLog groupedDecode program branch := by
    have rawEq : (program.record leftOracle).2 = rawLog groupedDecode program branch := by
      exact congrArg Prod.snd replay
    rw [← rawEq]
    exact member
  obtain ⟨call, answerMember, pairEq⟩ := List.mem_map.mp rawMember
  have inputEq : call.1 = input := congrArg Prod.fst pairEq
  have answerEq : groupedDecode call.1 call.2 = leftOracle input :=
    congrArg Prod.snd pairEq
  have rightAnswer := claims_supply_grouped_oracle_answers
    (encode := encode program) program branch rightDatabase rightClaimsCorrect
    rightFallback call answerMember
  have rightOracleAnswer : groupedDecode call.1 call.2 = rightOracle call.1 := by
    cases stored : rightDatabase (encode program call.1) <;>
      simpa [rightOracle, finiteGroupedDatabaseOracle, groupedDecode, stored] using rightAnswer
  calc
    leftOracle input = leftOracle call.1 := by rw [inputEq]
    _ = groupedDecode call.1 call.2 := by
      calc
        leftOracle call.1 = leftOracle input := congrArg leftOracle inputEq
        _ = groupedDecode call.1 call.2 := answerEq.symm
    _ = rightOracle call.1 := rightOracleAnswer
    _ = rightOracle input := by rw [inputEq]

/-- Same-branch compressed claims therefore stabilize the producer's
recorded/evaluated transcript across arbitrary database completions. -/
theorem same_branch_claims_stabilize_program
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (leftDatabase rightDatabase : Database (Key program) (VectorOutput GroupCounter))
    (leftClaims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      leftDatabase)
    (rightClaims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      rightDatabase)
    (leftFallback rightFallback : RawDigest) :
    program.record (finiteGroupedDatabaseOracle program leftDatabase leftFallback) =
      program.record (finiteGroupedDatabaseOracle program rightDatabase rightFallback) ∧
    program.eval (finiteGroupedDatabaseOracle program leftDatabase leftFallback) =
      program.eval (finiteGroupedDatabaseOracle program rightDatabase rightFallback) := by
  let leftOracle := finiteGroupedDatabaseOracle program leftDatabase leftFallback
  let rightOracle := finiteGroupedDatabaseOracle program rightDatabase rightFallback
  have agrees := same_branch_claims_agree_on_record_reads program branch
    leftDatabase rightDatabase leftClaims rightClaims leftFallback rightFallback
  exact ⟨record_eq_of_agrees_on_left_reads program leftOracle rightOracle agrees,
    eval_eq_of_agrees_on_left_reads program leftOracle rightOracle agrees⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentBranchOracleAgreement
