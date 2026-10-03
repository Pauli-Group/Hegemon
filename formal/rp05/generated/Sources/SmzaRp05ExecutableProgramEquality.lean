import SmzaRp05PhysicalAcceptedReplayLite

/-! Transport a genuine branch along an equality of executable programs.
No new branch, outcome coupling, or equality of different executions is
assumed: each result below is ordinary dependent equality elimination. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableProgramEquality

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers answerLog physicalRun)
open HegemonCrypto.CmsCompressedOracle (State)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false

variable {Result Key Output Phase Work : Type}

def castProgramBranch
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (same : left = right)
    (branch : Branches decode left) : Branches decode right :=
  cast (congrArg (Branches decode) same) branch

@[simp] theorem branchResult_cast_program
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (same : left = right)
    (branch : Branches decode left) :
    branchResult decode right (castProgramBranch decode left right same branch) =
      branchResult decode left branch := by
  cases same
  rfl

@[simp] theorem answerLog_cast_program
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (same : left = right)
    (branch : Branches decode left) :
    answerLog decode right (castProgramBranch decode left right same branch) =
      answerLog decode left branch := by
  cases same
  rfl

variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output]

@[simp] theorem physicalRun_cast_program
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (same : left = right)
    (branch : Branches decode left) (state : State Key Output Phase Work) :
    physicalRun encode decode right
        (castProgramBranch decode left right same branch) state =
      physicalRun encode decode left branch state := by
  cases same
  rfl

end HegemonCrypto.SmallWood.SmzaRp05ExecutableProgramEquality
