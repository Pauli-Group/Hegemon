import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05PhysicalTerminalRead

/-!
# Physical accepted replay uses the terminal read instrument

The executable branch interpreter and the bounded terminal-read theorem use
the same decompress/measure/recompress step. This module identifies their
whole traces, including repeated keys, without adding a proof-carried field.
It does not certify that a particular Rust verifier run produces the branch.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayBridge

open HegemonCrypto.CmsCompressedOracle
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05PhysicalTerminalRead
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

def toTerminalAnswers : (keys : List Key) →
    SmzaRp05PhysicalAcceptedReplayLite.ReadAnswers Output keys →
      SmzaRp05SuffixReadout.ReadAnswers Output keys
  | [], _ => PUnit.unit
  | _ :: rest, (answer, answers) =>
      (answer, toTerminalAnswers rest answers)

theorem physical_read_step_eq_branch (key : Key) (answer : Output)
    (state : State Key Output Phase Work) :
    physicalReadStep key answer state = physicalReadBranch key answer state := by
  rfl

theorem physical_run_eq_terminal_trace
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : State Key Output Phase Work) :
    physicalRun encode decode program branch state =
      physicalReadTrace (branchKeys encode decode program branch)
        (toTerminalAnswers _ (branchAnswers encode decode program branch)) state := by
  induction program generalizing state with
  | done result =>
      cases branch
      rfl
  | read raw next ih =>
      rcases branch with ⟨answer, remaining⟩
      change physicalRun encode decode (next (decode raw answer)) remaining
          (physicalReadStep (encode raw) answer state) =
        physicalReadTrace (branchKeys encode decode
          (next (decode raw answer)) remaining)
          (toTerminalAnswers _ (branchAnswers encode decode
            (next (decode raw answer)) remaining))
          (physicalReadBranch (encode raw) answer state)
      rw [physical_read_step_eq_branch]
      exact ih (decode raw answer) remaining _

end HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayBridge
