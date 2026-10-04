import SmzaRp05ConditionedExecution
import SmzaRp05FilteredReadback
import SmzaRp04StatementRecordFilter

/-! # Ordinary unprogrammable soundness prefixes

This separate syntax models an ordinary QROM adversary prefix: oracle queries
and database-independent private contractions, but no simulator programming,
retained-leaf writes, or authorization marks. It is not a replacement for the
simulator-aware privacy/game model.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessExecution

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsOracleSimulation
open SmzaChallengeStageTargets
open HegemonCrypto.CmsCompressedOracle
open V8Smz9CoherentVectorMerkle
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05FilteredReadback (outsideAuthorizedRecords)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- Syntax for an ordinary unprogrammable prefix. `privateGate` is restricted
to database-independent contractions; the only operation touching oracle
records is the explicitly charged query constructor. -/
inductive OrdinaryPrefix {cap : Nat} : Nat → Nat → Nat → Type _ where
  | nil (budget : Nat) : OrdinaryPrefix (cap := cap) budget budget 0
  | query {finish queries : Nat} (occupied : Nat) (room : occupied < cap)
      (remaining : OrdinaryPrefix (cap := cap) (occupied + 1) finish queries) :
      OrdinaryPrefix (cap := cap) occupied finish (1 + queries)
  | privateGate {finish queries : Nat}
      (budget : Nat) (within : budget ≤ cap)
      (step : DatabaseIndependentContraction
        (Input := Key)
        (Output := SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter))
        (Phase := SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter))
        (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
          (Counter := Counter) (BaseWork := BaseWork)))
      (remaining : OrdinaryPrefix (cap := cap) budget finish queries) :
      OrdinaryPrefix (cap := cap) budget finish queries
variable {cap : Nat}

/-- Reuse all semantic context fields while fixing authorization to empty. -/
def emptyAuthorizationContexts
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) :
    Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  fun role => { contexts role with authorizedOf := fun _ => ∅ }

/-- Embed ordinary prefixes into the existing physical execution skeleton. -/
def compileOrdinary : {start finish queries : Nat} →
    OrdinaryPrefix (Key := Key) (Counter := Counter) (BaseWork := BaseWork)
      (cap := cap) start finish queries →
    PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries
  | _, _, _, .nil budget => PhysicalProgramSkeleton.nil (cap := cap) budget
  | _, _, _, .query occupied room remaining =>
      .query occupied room (compileOrdinary remaining)
  | _, _, _, .privateGate budget within step remaining =>
      .privateGate budget within step (compileOrdinary remaining)

/-- Every compiled ordinary prefix is certified for empty-authorization
contexts; no certificate is an input to this theorem. -/
def compileOrdinary_certified
    (contexts : Role → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork)) :
    {start finish queries : Nat} →
      (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
        (BaseWork := BaseWork) (cap := cap) start finish queries) →
      CertifiedFor (emptyAuthorizationContexts contexts) (compileOrdinary program)
  | _, _, _, .nil budget => CertifiedFor.nil (cap := cap) budget
  | _, _, _, .query occupied room remaining =>
      .query occupied room (compileOrdinary_certified contexts remaining)
  | _, _, _, .privateGate budget within step remaining =>
      .privateGate budget within step
        (by intro role source target nonzero; simp [emptyAuthorizationContexts])
        (compileOrdinary_certified contexts remaining)

/-- The ordinary semantics is the run of its compiled physical skeleton; the
equation is definitional by induction over the syntax. -/
def ordinaryRun {start finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) start finish queries)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork) :=
  match program with
  | .nil _ => state
  | .query _ _ remaining =>
      ordinaryRun remaining
        (HegemonCrypto.CmsQuerySequence.cappedQueryState
          vectorPhaseSystem cap state)
  | .privateGate _ _ step remaining => ordinaryRun remaining (step.apply state)

theorem ordinaryRun_eq_compiled {start finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) start finish queries) (state) :
    ordinaryRun program state = PhysicalProgramSkeleton.run (compileOrdinary program) state := by
  induction program generalizing state with
  | nil budget => rfl
  | query occupied room remaining ih =>
      simp [ordinaryRun, compileOrdinary, PhysicalProgramSkeleton.run, ih]
  | privateGate budget within step remaining ih =>
      simp [ordinaryRun, compileOrdinary, PhysicalProgramSkeleton.run, ih]

/-- With no programmed/authorized statements, the filtered record set is the
whole record set. This identity is specific to the ordinary prefix syntax. -/
theorem outside_empty_authorization_identity
    (ns : SmzaRp05LeafNamespace.Namespace)
    (records : SmzaRp05FilteredReadback.Records) :
    outsideAuthorizedRecords ns ∅ records = records := by
  ext record
  rcases record with ⟨input, digest⟩
  cases leaf : SmzaRp05FilteredReadback.globalLeafStatement ns input <;>
    simp [outsideAuthorizedRecords, SmzaRp04StatementRecordFilter.authorizedFilter,
      SmzaRp04StatementRecordFilter.keepOutsideAuthorized, leaf]

end
end HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessExecution
