import SmzaRp05PublicWords
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials
import HegemonCrypto.SmallWoodV8Smz9CurrentPublicContext

/-!
# RP05 relation DSL and finite-certificate interface

These declarations describe the generated program without importing the
accepted-extraction proof. The semantic consequences remain in
`SmzaRp05RelationRefinement`.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05RelationRefinement

open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
open V8Smz9ProgramPolynomials

-- The enclosing SmallWood namespace also defines a different `Statement`
-- (ProductionConstraintMap). Keep every RP05 DSL binder on the finite
-- preamble carrier, as required by `publicWords` and accepted extraction.
local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

/-- Program data which varies between generated relation artifacts. The
polynomial construction itself is fixed in the refinement module. -/
structure RelationDsl where
  components : RelationProgramComponents
  nonlinearCount : Nat
  linearCount : Statement → Nat
  nonlinearRoot : Fin nonlinearCount → Nat
  nodeDegree : Nat → Nat
  linearWeights : (statement : Statement) →
    Fin (linearCount statement) → Fin 686 → Fin 64 → Goldilocks
  linearTarget : (statement : Statement) →
    Fin (linearCount statement) → Goldilocks

def RelationDsl.width (dsl : RelationDsl) (statement : Statement) : Nat :=
  max dsl.nonlinearCount (dsl.linearCount statement)

def currentPublicWords (statement : Statement) : List Nat :=
  SmzaRp05TracePrefixes.publicWords statement

def csrValues (dsl : RelationDsl) (statement : Statement) : List Nat :=
  (evalExpressionNodes (currentPublicWords statement) []
    dsl.components.csrExpressions).getD []

/-- Coefficient of a packed witness coordinate in one raw executable attempt. -/
def executableCoefficient (dsl : RelationDsl) (statement : Statement)
    (attempt : CsrExecutableAttempt) (index : Fin 43904) : Goldilocks :=
  denseCoefficient (csrValues dsl statement) attempt.terms index

/-- Public target of one raw executable attempt. -/
def executableTarget (dsl : RelationDsl) (statement : Statement)
    (attempt : CsrExecutableAttempt) : Goldilocks :=
  ((csrValues dsl statement).getD attempt.targetRoot 0 : Goldilocks)

/-- Coefficient of a packed coordinate in one normalized PIOP row. -/
def normalizedRowCoefficient (dsl : RelationDsl) (statement : Statement)
    (row : Fin (dsl.linearCount statement)) (index : Fin 43904) : Goldilocks :=
  let coordinate := (finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index
  dsl.linearWeights statement row coordinate.1 coordinate.2

/-- Rust's `tail_source_index(120)`, used only when a public-only equation has
no nonzero coefficients and a nonzero target. -/
def zeroSourceCoefficient (index : Fin 43904) : Goldilocks :=
  if index.val = 41528 then 1 else 0

/-- First and only nonlinear generated certificate. Every conjunct is a
finite statement about the generated expression DAG/root table. -/
structure NonlinearCertificate (dsl : RelationDsl) : Prop where
  nonlinearCountExact : dsl.nonlinearCount = 818
  programCanonical : dsl.components.nonlinearExecutable.Canonical true
  rootsExact : dsl.components.nonlinearExecutable.roots =
    List.ofFn dsl.nonlinearRoot
  degreeCertificate : DegreeCertificate
    dsl.components.nonlinearExecutable.expressions dsl.nodeDegree
  rootDegree : ∀ root, dsl.nodeDegree (dsl.nonlinearRoot root) ≤ 8

/-- Second and only CSR generated certificate. `retainedOrZeroOrFallback` contains no
semantic quantification over witnesses. It is the finite normalization table:
each raw attempt has exactly the coefficients and target of a retained row, or
both its coefficient vector and target are zero, or it is routed through the
canonical zero source cell. The independently retained zero-source row rules
out that last branch for a satisfied candidate. The implication for an
arbitrary witness is derived by linear algebra in the refinement module. -/
structure CsrCertificate (dsl : RelationDsl) : Prop where
  programCanonical :
    ({ expressions := dsl.components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical false
  attemptCoordinates : ∀ attempt, attempt ∈ dsl.components.csrAttempts →
    (∀ term, term ∈ attempt.terms →
      term.1 < 43904 ∧ term.2 < dsl.components.csrExpressions.length) ∧
    attempt.targetRoot < dsl.components.csrExpressions.length
  zeroSourceRow : ∀ statement : Statement,
    ∃ row : Fin (dsl.linearCount statement),
      (∀ index, normalizedRowCoefficient dsl statement row index =
        zeroSourceCoefficient index) ∧ dsl.linearTarget statement row = 0
  retainedOrZeroOrFallback : ∀ (statement : Statement) (attempt : CsrExecutableAttempt),
    attempt ∈ dsl.components.csrAttempts →
      (∃ row : Fin (dsl.linearCount statement),
        (∀ index : Fin 43904,
          executableCoefficient dsl statement attempt index =
            normalizedRowCoefficient dsl statement row index) ∧
        executableTarget dsl statement attempt = dsl.linearTarget statement row) ∨
      ((∀ index : Fin 43904,
          executableCoefficient dsl statement attempt index = 0) ∧
        executableTarget dsl statement attempt = 0) ∨
      ((∀ index : Fin 43904,
          executableCoefficient dsl statement attempt index = 0) ∧
        executableTarget dsl statement attempt ≠ 0 ∧
        ∃ row : Fin (dsl.linearCount statement),
          (∀ index, normalizedRowCoefficient dsl statement row index =
            zeroSourceCoefficient index) ∧
          dsl.linearTarget statement row = executableTarget dsl statement attempt)

/-- The generated module has exactly these two top-level proof clauses. -/
structure GeneratedCertificates (dsl : RelationDsl) : Prop where
  nonlinear : NonlinearCertificate dsl
  csr : CsrCertificate dsl

end
end HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
