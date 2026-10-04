import SmzaRp05NullifierBinding
import SmzaRp05TypedRelation
import Hegemon.Transaction.Poseidon2Width16Kernel

/-! Internal source chunk SmzaRp05NullifierSourceBase. Original declaration bodies and statements are retained. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputDirectionRow)
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

abbrev InitialCell := Fin 2 × Fin 2 × Fin 16
abbrev PublicCell := Fin 2 × Fin 7

def callOf (cell : InitialCell) : Nat :=
  nullifierFirstCall cell.1 + cell.2.1.val

/-- Exact packed positions of the 32 bits, not an unconstrained position
word.  The finite current-program Boolean roots are a separate obligation. -/
def positionTerms (input : Fin 2) (powerNode : Nat → Nat) :
    List (Nat × Nat) :=
  (List.range 32).map fun bit =>
    (rawIndex (inputDirectionRow input.val bit), powerNode bit)

/-- The exact left side of each CSR equation.  `negative` represents -1,
not a semantic witness.  Note rho words 6/7 come from the first note call;
words 8/9 are differences across the second note call. -/
def initialTerms (one negative positive : Nat) (powerNode : Nat → Nat)
    (cell : InitialCell) : List (Nat × Nat) :=
  let input := cell.1
  let block := cell.2.1.val
  let lane := cell.2.2.val
  let head := [(hashInitialIndex (callOf cell) lane, one)]
  let prior := if block = 0 then [] else
    [(hashFinalIndex (nullifierFirstCall input) lane, negative)]
  let source :=
    if lane ≥ 8 then []
    else if block = 0 then
      if lane < 5 then
        [((inputNullifierKeyRow input) * 64 + lane, negative)]
      else if lane = 7 then
        positionTerms input powerNode
      else []
    else if lane < 4 then
      let word := 6 + lane
      let noteCall := inputNoteFirstCall input + word / 8
      let noteLane := word % 8
      if word < 8 then [(hashInitialIndex noteCall noteLane, negative)]
      else [(hashInitialIndex noteCall noteLane, negative),
        (hashFinalIndex (noteCall - 1) noteLane, positive)]
    else []
  head ++ prior ++ source

def initialConstant (cell : InitialCell) : Nat :=
  if cell.2.1.val = 0 then
    if cell.2.2.val = 8 then currentNullifierDomain
    else if cell.2.2.val = 9 then 12
    else if cell.2.2.val = 10 then poseidon2V8SpongeModeMarker
    else if cell.2.2.val = 15 then poseidon2V8SuiteMarker
    else 0
  else if cell.2.2.val = 11 then 1 else 0

/-- Finite syntax only.  In particular, `attemptTerms` fixes the 32 bit
weights and the four note-rho difference coordinates; no frame equality is
a field.  The position-bit Boolean roots are required to lift the 32-bit
field sum to the ordinary Nat preimage. -/
structure InitialCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  oneNode : Nat
  negativeNode : Nat
  positiveNode : Nat
  powerNode : Nat → Nat
  constantNode : InitialCell → Nat
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeRealizes : Realizes components.csrExpressions negativeNode
    (.sub (.constant 0) (.constant 1))
  positiveRealizes : Realizes components.csrExpressions positiveNode
    (.sub (.constant 0) (.sub (.constant 0) (.constant 1)))
  powerRealizes : ∀ bit, bit < 32 →
    Realizes components.csrExpressions (powerNode bit)
      (.sub (.constant 0) (.constant (2 ^ bit)))
  constantRealizes : ∀ cell, Realizes components.csrExpressions
    (constantNode cell) (.constant (initialConstant cell))
  attempt : InitialCell → CsrExecutableAttempt
  member : ∀ cell, attempt cell ∈ components.csrAttempts
  attemptTerms : ∀ cell, (attempt cell).terms =
    initialTerms oneNode negativeNode positiveNode powerNode cell
  attemptTarget : ∀ cell, (attempt cell).targetRoot = constantNode cell

/-- The public nullifier copy is gated by the exact input-active public word.
The target DAG computes that gate times public word 4+i*7+limb. -/
structure PublicCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  activeNode : Fin 2 → Nat
  targetNode : PublicCell → Nat
  activeRealizes : ∀ input, Realizes components.csrExpressions
    (activeNode input) (.publicInput input.val)
  targetRealizes : ∀ cell, Realizes components.csrExpressions
    (targetNode cell)
      (.mul (.publicInput cell.1.val)
        (.publicInput (4 + cell.1.val * 7 + cell.2.val)))
  attempt : PublicCell → CsrExecutableAttempt
  member : ∀ cell, attempt cell ∈ components.csrAttempts
  attemptTerms : ∀ cell, (attempt cell).terms =
    [(hashFinalIndex (nullifierLastCall cell.1) cell.2.val,
      activeNode cell.1)]
  attemptTarget : ∀ cell, (attempt cell).targetRoot = targetNode cell

/-- Finite current nonlinear Boolean roots for the 32 position bits.  These
are needed because a Goldilocks weighted sum alone does not establish that
the Nat position in the twelve-word preimage is below 2^32. -/
structure DirectionCertificate (components : RelationProgramComponents) where
  canonical : components.nonlinearExecutable.Canonical true
  root : Fin 2 → Fin 32 → Nat
  member : ∀ input bit, root input bit ∈ components.nonlinearExecutable.roots
  realizes : ∀ input bit,
    Realizes components.nonlinearExecutable.expressions (root input bit)
      (.mul (.witness (inputDirectionRow input.val bit.val))
        (.sub (.witness (inputDirectionRow input.val bit.val)) (.constant 1)))


end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
