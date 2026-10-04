import SmzaRp05Components
import HegemonCrypto.SmallWoodV8Smz9RelationProgramComponentsGenerated

/-!
# Exact RP05/reference Poseidon node correspondence

This is a finite, directed-edge checker for the same 332 width-16 hash roots
in two distinct canonical programs.  It carries no witness interpretation or
acceptance conclusion.  The edge map is intentionally not a `SourceTerm` tree:
unfolding a shared Poseidon DAG would duplicate its subgraphs exponentially.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

open Hegemon.Transaction.Poseidon2V8RelationProgram

set_option autoImplicit false

def currentExpressions : List FieldExpression := SmzaRp05Components.exactNonlinearExpressions
def referenceExpressions : List FieldExpression :=
  V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions

def mappedNode (node : Nat) : Nat :=
  if node = 1387 then 1460
  else if node = 1390 then 1463
  else if node = 1393 then 1466
  else if 1978 ≤ node then node + 58
  else node

def mappedExpression (f : Nat → Nat) : FieldExpression → FieldExpression
  | .constant value => .constant value
  | .publicWord index => .publicWord index
  | .witnessRow row => .witnessRow row
  | .add left right => .add (f left) (f right)
  | .sub left right => .sub (f left) (f right)
  | .mul left right => .mul (f left) (f right)
  | .neg value => .neg (f value)
  | .inverse value => .inverse (f value)
  | .selectEqual left right equal notEqual =>
      .selectEqual (f left) (f right) (f equal) (f notEqual)
  | .bit value bit => .bit (f value) bit

def expressionChildren : FieldExpression → List Nat
  | .constant _ | .publicWord _ | .witnessRow _ => []
  | .add left right | .sub left right | .mul left right => [left, right]
  | .neg value | .inverse value => [value]
  | .selectEqual left right equal notEqual => [left, right, equal, notEqual]
  | .bit value _ => [value]

def supportedNode (node : Nat) : Prop :=
  node < 1000 ∨ node = 1387 ∨ node = 1390 ∨ node = 1393 ∨
    (1978 ≤ node ∧ node < 7951)

instance (node : Nat) : Decidable (supportedNode node) := by
  unfold supportedNode
  infer_instance

/-- Every child must be in the checked support and precede both parents. -/
def directedEdgeCheck (node : Nat) : Bool :=
  match currentExpressions[node]? with
  | none => false
  | some expression =>
      decide (referenceExpressions[mappedNode node]? =
        some (mappedExpression mappedNode expression)) &&
      (expressionChildren expression).all fun child =>
        decide (supportedNode child ∧ child < node ∧
          mappedNode child < mappedNode node)

def pairedRootCheck (wire : Nat) : Bool :=
  match SmzaRp05Components.exactNonlinearRoots[459 + wire]?,
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearRoots[471 + wire]? with
  | some current, some reference => decide (mappedNode current = reference)
  | _, _ => false

/-! The finite Boolean checks are intentionally separate from any evaluator
lemma. A future checked theorem may consume them to transport field values
node-by-node, then feed the existing RP05 hash-kernel theorem. -/

end HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
