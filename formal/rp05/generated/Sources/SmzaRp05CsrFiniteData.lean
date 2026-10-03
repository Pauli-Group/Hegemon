import SmzaRp05Components

/-! Finite predicates over the exact SHA-pinned HGV8RP05 CSR program. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData

open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05Components

set_option autoImplicit false

local instance (node : Nat) (expression : FieldExpression) :
    Decidable (expression.CanonicalAt false node) := by
  cases expression <;> unfold FieldExpression.CanonicalAt <;> infer_instance

def canonicalCheck (node : Nat) : Bool :=
  match exactCsrExpressions[node]? with
  | none => false
  | some expression => decide (expression.CanonicalAt false node)

def coordinateAttemptCheck (attempt : CsrExecutableAttempt) : Bool :=
  (attempt.terms.all fun term => decide
    (term.1 < 43904 ∧ term.2 < exactCsrExpressions.length)) &&
  decide (attempt.targetRoot < exactCsrExpressions.length)

end HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData
