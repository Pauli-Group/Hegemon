import SmzaRp05CsrFiniteData
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality
import Lean.Elab.Tactic.Omega

/-!
Finite syntax facts for the SHA-512-pinned HGV8RP05 public CSR program.
No statement- or witness-dependent normalization claim is embedded here.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem csrProgramCanonical :
    ({ expressions := exactCsrExpressions, roots := [] } :
      ExpressionProgram).Canonical false := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

theorem csrAttemptCoordinates :
    ∀ attempt, attempt ∈ exactCsrAttempts →
      (∀ term, term ∈ attempt.terms →
        term.1 < 43904 ∧ term.2 < exactCsrExpressions.length) ∧
      attempt.targetRoot < exactCsrExpressions.length := by
  have checked : exactCsrAttempts.all coordinateAttemptCheck = true := by
    decide
  intro attempt member
  have one := (List.all_eq_true.mp checked) attempt member
  simp only [coordinateAttemptCheck, Bool.and_eq_true_iff] at one
  obtain ⟨terms, target⟩ := one
  constructor
  · intro term termMember
    have termChecked := (List.all_eq_true.mp terms) term termMember
    simpa only [decide_eq_true_eq] using termChecked
  · simpa only [decide_eq_true_eq] using target

def zeroAttempt : CsrExecutableAttempt :=
  attempt 19281 45 0 0 [(41528, 1)] 0

theorem zeroAttemptMember : zeroAttempt ∈ exactCsrAttempts := by
  decide

theorem zeroAttemptTerms : zeroAttempt.terms = [(41528, 1)] := rfl
theorem zeroAttemptTarget : zeroAttempt.targetRoot = 0 := rfl

theorem zeroNode : exactCsrExpressions[0]? = some (.constant 0) := by
  decide

theorem oneNode : exactCsrExpressions[1]? = some (.constant 1) := by
  decide

end HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData
