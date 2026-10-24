import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Group.Basic
import Lean.Elab.Tactic.Omega

/-!
Generic algebra for the native HTLC product-occurrence lowering at frozen
commit 7d96a90b0. circuit.rs:300-319 copies output/left/right words into three
occurrence rows and duplicates the last gate in a short final batch;
409-420 checks each lane's multiplication and 503-507 emits its residual.
This model does not prove Rust refinement, canonical modular arithmetic,
graph compilation, SHA-256 semantics, accepted-wire security or release authority.
-/

set_option autoImplicit false

namespace HegemonCrypto.SmallWood.NativeHtlcGraphProducts

/-- Data only: product tuple order is output, left, right. -/
structure ProductGate (α : Type*) where
  output : α
  left : α
  right : α

variable {F α : Type*} [Field F]

def productEquation (assignment : α → F) (gate : ProductGate α) : Prop :=
  assignment gate.output = assignment gate.left * assignment gate.right

/-- The three copy constraints have coefficient one and minus one. -/
def copyConstraints (assignment : α → F) (source : ProductGate α)
    (occurrence : ProductGate F) : Prop :=
  occurrence.output - assignment source.output = 0 ∧
  occurrence.left - assignment source.left = 0 ∧
  occurrence.right - assignment source.right = 0

def productResidual (occurrence : ProductGate F) : F :=
  occurrence.output - occurrence.left * occurrence.right

theorem copy_constraints_iff (assignment : α → F) (source : ProductGate α)
    (occurrence : ProductGate F) :
    copyConstraints assignment source occurrence ↔
      occurrence.output = assignment source.output ∧
      occurrence.left = assignment source.left ∧
      occurrence.right = assignment source.right := by
  simp only [copyConstraints, sub_eq_zero]

theorem copied_product_residual_iff (assignment : α → F)
    (source : ProductGate α) (occurrence : ProductGate F)
    (copies : copyConstraints assignment source occurrence) :
    productResidual occurrence = 0 ↔ productEquation assignment source := by
  obtain ⟨ho, hl, hr⟩ := (copy_constraints_iff _ _ _).mp copies
  simp only [productResidual, ho, hl, hr, sub_eq_zero, productEquation]

/-- Exact lane selector `lane.min(gates.len() - 1)` for a nonempty batch. -/
def paddedIndex {count packing : ℕ} (positive : 0 < count)
    (lane : Fin packing) : Fin count :=
  ⟨min lane.val (count - 1), by omega⟩

theorem padded_index_genuine {count packing : ℕ} (positive : 0 < count)
    (fits : count ≤ packing) (gate : Fin count) :
    paddedIndex positive (⟨gate.val, Nat.lt_of_lt_of_le gate.isLt fits⟩ : Fin packing)
      = gate := by
  apply Fin.ext
  simp only [paddedIndex]
  omega

theorem padded_index_duplicates_last {count packing : ℕ}
    (positive : 0 < count) (lane : Fin packing)
    (lastOrLater : count - 1 ≤ lane.val) :
    (paddedIndex positive lane).val = count - 1 := by
  simp only [paddedIndex]
  exact Nat.min_eq_right lastOrLater

theorem padded_products_iff {count packing : ℕ} (positive : 0 < count)
    (fits : count ≤ packing) (assignment : α → F)
    (gates : Fin count → ProductGate α) :
    (∀ lane : Fin packing,
      productEquation assignment (gates (paddedIndex positive lane))) ↔
    (∀ gate : Fin count, productEquation assignment (gates gate)) := by
  constructor
  · intro allLanes gate
    have h := allLanes ⟨gate.val, Nat.lt_of_lt_of_le gate.isLt fits⟩
    rw [padded_index_genuine positive fits gate] at h
    exact h
  · intro allGates lane
    exact allGates (paddedIndex positive lane)

/-- Copy constraints plus residual checks add no extra condition in padded lanes. -/
theorem copied_padded_residuals_iff {count packing : ℕ}
    (positive : 0 < count) (fits : count ≤ packing)
    (assignment : α → F) (gates : Fin count → ProductGate α)
    (occurrences : Fin packing → ProductGate F)
    (copies : ∀ lane, copyConstraints assignment
      (gates (paddedIndex positive lane)) (occurrences lane)) :
    (∀ lane, productResidual (occurrences lane) = 0) ↔
    (∀ gate, productEquation assignment (gates gate)) := by
  have localEquivalence :
      (∀ lane, productResidual (occurrences lane) = 0) ↔
      (∀ lane : Fin packing, productEquation assignment
        (gates (paddedIndex positive lane))) := by
    constructor
    · intro checks lane
      exact (copied_product_residual_iff _ _ _ (copies lane)).mp (checks lane)
    · intro checks lane
      exact (copied_product_residual_iff _ _ _ (copies lane)).mpr (checks lane)
  exact localEquivalence.trans (padded_products_iff positive fits assignment gates)

theorem copied_padded64_residuals_iff {count : ℕ}
    (positive : 0 < count) (fits : count ≤ 64)
    (assignment : α → F) (gates : Fin count → ProductGate α)
    (occurrences : Fin 64 → ProductGate F)
    (copies : ∀ lane, copyConstraints assignment
      (gates (paddedIndex positive lane)) (occurrences lane)) :
    (∀ lane, productResidual (occurrences lane) = 0) ↔
    (∀ gate, productEquation assignment (gates gate)) :=
  copied_padded_residuals_iff positive fits assignment gates occurrences copies

omit [Field F] in
/-- A deterministic local rule depending only on earlier wire values has a
unique assignment on its finite graph. This does not assert that every Rust
node, including private input/bit/inverse nodes, has such a rule. -/
theorem acyclic_local_equations_unique (nodeCount : ℕ)
    (step : ℕ → (ℕ → F) → F)
    (earlierOnly : ∀ i < nodeCount, ∀ a b : ℕ → F,
      (∀ j < i, a j = b j) → step i a = step i b)
    (a b : ℕ → F)
    (localA : ∀ i < nodeCount, a i = step i a)
    (localB : ∀ i < nodeCount, b i = step i b) :
    ∀ i < nodeCount, a i = b i := by
  intro i
  induction i using Nat.strong_induction_on with
  | h i previous =>
    intro inGraph
    rw [localA i inGraph, localB i inGraph]
    apply earlierOnly i inGraph a b
    intro j earlier
    exact previous j earlier (Nat.lt_trans earlier inGraph)

/-- A source operand is a constant or a canonical wire index. -/
inductive Word (F : Type*) where
  | constant : F → Word F
  | wire : ℕ → Word F

def wordRead (assignment : ℕ → F) : Word F → F
  | .constant value => value
  | .wire index => assignment index

def wordBefore (position : ℕ) : Word F → Prop
  | .constant _ => True
  | .wire index => index < position

omit [Field F] in
theorem word_read_prefix_eq (position : ℕ) (a b : ℕ → F)
    (operand : Word F) (bounded : wordBefore position operand)
    (agrees : ∀ j < position, a j = b j) :
    wordRead a operand = wordRead b operand := by
  cases operand with
  | constant value => rfl
  | wire index => exact agrees index bounded

/-- Input/bit/inverse outputs are fixed seed values here. Accepted constraints
must separately determine bit ranges and inverse nonzero/uniqueness behavior;
this model proves no such determination. Linear and product nodes are evaluated.
-/
inductive SeededNode (F : Type*) where
  | seed : F → SeededNode F
  | add : Word F → Word F → SeededNode F
  | subtract : Word F → Word F → SeededNode F
  | product : Word F → Word F → SeededNode F

def nodeRead (assignment : ℕ → F) : SeededNode F → F
  | .seed value => value
  | .add a b => wordRead assignment a + wordRead assignment b
  | .subtract a b => wordRead assignment a - wordRead assignment b
  | .product a b => wordRead assignment a * wordRead assignment b

def nodeBefore (position : ℕ) : SeededNode F → Prop
  | .seed _ => True
  | .add a b | .subtract a b | .product a b =>
      wordBefore position a ∧ wordBefore position b

theorem node_read_prefix_eq (position : ℕ) (a b : ℕ → F)
    (node : SeededNode F) (bounded : nodeBefore position node)
    (agrees : ∀ j < position, a j = b j) :
    nodeRead a node = nodeRead b node := by
  cases node with
  | seed value => rfl
  | add left right =>
    simp only [nodeRead]
    rw [word_read_prefix_eq position a b left bounded.1 agrees,
      word_read_prefix_eq position a b right bounded.2 agrees]
  | subtract left right =>
    simp only [nodeRead]
    rw [word_read_prefix_eq position a b left bounded.1 agrees,
      word_read_prefix_eq position a b right bounded.2 agrees]
  | product left right =>
    simp only [nodeRead]
    rw [word_read_prefix_eq position a b left bounded.1 agrees,
      word_read_prefix_eq position a b right bounded.2 agrees]

/-- Structural predecessor bounds discharge the earlier-only hypothesis;
both assignments use the same explicit seed values. -/
theorem seeded_graph_equations_unique (nodeCount : ℕ)
    (nodes : ℕ → SeededNode F)
    (bounded : ∀ i < nodeCount, nodeBefore i (nodes i))
    (a b : ℕ → F)
    (localA : ∀ i < nodeCount, a i = nodeRead a (nodes i))
    (localB : ∀ i < nodeCount, b i = nodeRead b (nodes i)) :
    ∀ i < nodeCount, a i = b i := by
  apply acyclic_local_equations_unique nodeCount
    (fun i assignment => nodeRead assignment (nodes i))
    (fun i inGraph x y agrees =>
      node_read_prefix_eq i x y (nodes i) (bounded i inGraph) agrees)
    a b localA localB

end HegemonCrypto.SmallWood.NativeHtlcGraphProducts
