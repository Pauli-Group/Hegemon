import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentExecutedEarlierAdvice

/-! # Fixed earlier advice localized to the active role

An active fixed-table context only replaces the advice table for its own
selected role. Other selected roles retain the current decoder evaluated on
the same grouped database oracle. This dependent family is the common
interface for transporting actual-execution `EarlierReadback` fields through
the fixed-fiber source readbacks.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierReadback

open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05ConditionedExecution (FixedTable)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedAdvice)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice)
open SmzaChallengeStageTargets (Role)

set_option autoImplicit false
set_option linter.unusedSectionVars false

noncomputable section

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- The fixed table is used exactly at the role fixed by `ctx`; advice for all
other selected roles comes from the same current grouped oracle. The equality
transport is required because `AllEarlierTables` is dependent on its role. -/
def currentFixedEarlierAdviceFamily
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (oracle : Oracle) : (selected : Role) → AllEarlierTables ctx.model selected :=
  fun selected =>
    if h : selected = ctx.role then
      h.symm ▸ currentFixedAdvice ctx blockCap fixed
    else
      currentOracleAllAdvice ctx.model oracle selected

@[simp] theorem currentFixedEarlierAdviceFamily_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (oracle : Oracle) :
    currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role =
      currentFixedAdvice ctx blockCap fixed := by
  simp [currentFixedEarlierAdviceFamily]

@[simp] theorem currentFixedEarlierAdviceFamily_other
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (oracle : Oracle) (selected : Role) (notActive : selected ≠ ctx.role) :
    currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected =
      currentOracleAllAdvice ctx.model oracle selected := by
  simp [currentFixedEarlierAdviceFamily, notActive]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierReadback
