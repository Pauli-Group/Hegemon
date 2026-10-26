import HegemonCrypto.NativeLaunchSparseCoalescing
import HegemonCrypto.NativeHtlcGraphProducts

/-!
Structural lowering component for the private-spend successor.

Source correspondence target: circuits/transaction/src/smallwood_htlc/circuit.rs
Node constructors, linear(), from_graph(), and verify_packed_witness().
The premise checks emitted normalized rows and occurrence residuals, NOT graph
equations. The conclusion gives independent arithmetic node/equality semantics.
Input/Bit/Inverse are explicit arbitrary-assignment seeds; no host evaluation is
assumed. Separate guard lemmas derive Boolean and inverse consequences.

This is a row-segment CSR model, not a proof of Rust BTreeMap/u64/offset-array
refinement. The exact Rust graph, product-batch coverage, range recomposition,
six transaction cases, cryptographic extraction and release remain separate.
No compilation is claimed by the author of this scratch file.
-/

set_option autoImplicit false
set_option maxHeartbeats 1000000

namespace HegemonCrypto.NativePrivateSpendPackedLowering

open HegemonCrypto.NativeLaunchConstraintAdapterBridge
open HegemonCrypto.NativeLaunchSparseCoalescing
namespace Products
export HegemonCrypto.SmallWood.NativeHtlcGraphProducts
  (ProductGate paddedIndex productEquation productResidual
   copy_constraints_iff copied_padded64_residuals_iff)
end Products

noncomputable section
variable {F : Type*} [Field F]

structure Row (F : Type*) where
  terms : List (Word F × F)
  target : F

structure SparseRow (F : Type*) where
  entries : List (Nat × F)
  target : F

/-- Constants move to the RHS; duplicate indices coalesce; zero coefficients
are removed. Only an empty consistent row is omitted. -/
def emit (row : Row F) : Option (SparseRow F) := by
  classical
  let lowered := normalizedLower row.terms
  let rhs := row.target - lowered.2
  exact if lowered.1 = [] ∧ rhs = 0 then none else some ⟨lowered.1, rhs⟩

def emittedHolds (z : Nat → F) : Option (SparseRow F) → Prop
  | none => True
  | some row => sparseEval z row.entries = row.target

def rowHolds (z : Nat → F) (row : Row F) : Prop := emittedHolds z (emit row)

theorem emitted_row_iff (z : Nat → F) (row : Row F) :
    rowHolds z row ↔ normalizedRow z row.terms row.target := by
  classical
  unfold rowHolds emit
  dsimp only
  split_ifs with empty
  · constructor
    · intro _
      change sparseEval z (normalizedLower row.terms).1 =
        row.target - (normalizedLower row.terms).2
      rw [empty.1, sparseEval, empty.2]
    · intro _
      trivial
  · rfl

def copyRow (a b : Word F) : Row F := ⟨[(a, 1), (b, -1)], 0⟩
def bindRow (index : Nat) (value : F) : Row F := ⟨[(.wire index, 1)], value⟩

theorem copy_sound (z : Nat → F) (a b : Word F)
    (h : rowHolds z (copyRow a b)) : read z a = read z b :=
  (normalized_copy_semantics z a b).mp ((emitted_row_iff z _).mp h)

theorem binding_sound (z : Nat → F) (index : Nat) (value : F)
    (h : rowHolds z (bindRow index value)) : z index = value := by
  apply (public_binding_semantics z index value).mp
  exact (normalized_row_iff z _ _).mp ((emitted_row_iff z _).mp h)

/-- Same five constructors as the native graph. Bit/Inverse are not computed
by this model: their wire values may initially be arbitrary field elements. -/
inductive Node (F : Type*) where
  | input : Nat → Node F
  | linear : Word F → Word F → Bool → Node F
  | product : Word F → Word F → Node F
  | bit : Word F → Nat → Node F
  | inverse : Word F → Node F

def nodeRow (index : Nat) : Node F → Option (Row F)
  | .linear a b false => some ⟨[(.wire index, 1), (a, -1), (b, -1)], 0⟩
  | .linear a b true => some ⟨[(.wire index, 1), (a, -1), (b, 1)], 0⟩
  | _ => none

def optionalRowHolds (z : Nat → F) : Option (Row F) → Prop
  | none => True
  | some row => rowHolds z row

/-- Independent arithmetic meaning. Seeds are indexed by canonical wire,
including bit/inverse auxiliaries, not assumed to come from evaluate(). -/
def nodeMeaning (z seeds : Nat → F) (index : Nat) : Node F → Prop
  | .input _ => z index = seeds index
  | .bit _ _ => z index = seeds index
  | .inverse _ => z index = seeds index
  | .linear a b false => z index = read z a + read z b
  | .linear a b true => z index = read z a - read z b
  | .product a b => z index = read z a * read z b

structure Graph (F : Type*) where
  count : Nat
  nodes : Fin count → Node F
  equalities : List (Word F × Word F)
  publicBindings : List (Nat × F)

structure Batch (F : Type*) where
  count : Nat
  positive : 0 < count
  fits : count ≤ 64
  gates : Fin count → Products.ProductGate (Word F)

structure Layout (F : Type*) where
  canonicalRows : Nat
  batchCount : Nat
  batches : Fin batchCount → Batch F

/-- Native layout: after canonical rows, each batch occupies output/left/right
rows, with 64 lanes in each. -/
def occurrenceIndex (layout : Layout F) (batch : Fin layout.batchCount)
    (operand : Nat) (lane : Fin 64) : Nat :=
  (layout.canonicalRows + 3 * batch.val + operand) * 64 + lane.val

def occurrence (layout : Layout F) (z : Nat → F)
    (batch : Fin layout.batchCount) (lane : Fin 64) : Products.ProductGate F :=
  ⟨z (occurrenceIndex layout batch 0 lane),
   z (occurrenceIndex layout batch 1 lane),
   z (occurrenceIndex layout batch 2 lane)⟩

def laneGate (layout : Layout F) (batch : Fin layout.batchCount)
    (lane : Fin 64) : Products.ProductGate (Word F) :=
  (layout.batches batch).gates (Products.paddedIndex (layout.batches batch).positive lane)

/-- Pure structural certificate: every source Product node occurs in a batch.
No assignment, equation satisfaction or cryptographic acceptance occurs here. -/
structure Covers (g : Graph F) (layout : Layout F) : Prop where
  canonicalFits : g.count ≤ layout.canonicalRows * 64
  products : ∀ (i : Fin g.count) (a b : Word F), g.nodes i = .product a b →
    ∃ (batch : Fin layout.batchCount) (gate : Fin (layout.batches batch).count),
      (layout.batches batch).gates gate = ⟨.wire i.val, a, b⟩

/-- Checks of generated CSR row segments and multiplication occurrence rows.
This does not contain nodeMeaning or source product/equality equations. -/
structure LoweredAccepted (g : Graph F) (layout : Layout F) (z : Nat → F) : Prop where
  linear : ∀ i, optionalRowHolds z (nodeRow i.val (g.nodes i))
  equalities : ∀ a b, (a, b) ∈ g.equalities → rowHolds z (copyRow a b)
  padding : ∀ i, g.count ≤ i → i < layout.canonicalRows * 64 → rowHolds z (bindRow i 0)
  publicRows : ∀ i v, (i, v) ∈ g.publicBindings → rowHolds z (bindRow i v)
  copies : ∀ batch lane,
    rowHolds z (copyRow (.wire (occurrenceIndex layout batch 0 lane))
      (laneGate layout batch lane).output) ∧
    rowHolds z (copyRow (.wire (occurrenceIndex layout batch 1 lane))
      (laneGate layout batch lane).left) ∧
    rowHolds z (copyRow (.wire (occurrenceIndex layout batch 2 lane))
      (laneGate layout batch lane).right)
  nonlinear : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0

theorem batch_products_sound (g : Graph F) (layout : Layout F) (z : Nat → F)
    (accepted : LoweredAccepted g layout z) (batch : Fin layout.batchCount) :
    ∀ gate, Products.productEquation (read z) ((layout.batches batch).gates gate) := by
  apply (Products.copied_padded64_residuals_iff
    (layout.batches batch).positive (layout.batches batch).fits
    (read z) (layout.batches batch).gates (occurrence layout z batch) ?_).mp
      (accepted.nonlinear batch)
  intro lane
  apply (Products.copy_constraints_iff _ _ _).mpr
  obtain ⟨out, left, right⟩ := accepted.copies batch lane
  exact ⟨copy_sound z _ _ out, copy_sound z _ _ left, copy_sound z _ _ right⟩

structure StructuralSemantics (g : Graph F) (layout : Layout F) (z : Nat → F) : Prop where
  nodes : ∀ i, nodeMeaning z z i.val (g.nodes i)
  equalities : ∀ a b, (a, b) ∈ g.equalities → read z a = read z b
  padding : ∀ i, g.count ≤ i → i < layout.canonicalRows * 64 → z i = 0
  publicValues : ∀ i v, (i, v) ∈ g.publicBindings → z i = v

/-- Arbitrary-assignment lowering soundness. Input, Bit and Inverse values are
read back from z, while add/sub/product/equality/public/padding facts are proved
from emitted rows. In particular z need not be a host-generated witness. -/
theorem structural_lowering_sound (g : Graph F) (layout : Layout F) (z : Nat → F)
    (covers : Covers g layout) (accepted : LoweredAccepted g layout z) :
    StructuralSemantics g layout z := by
  constructor
  · intro i
    cases nodeEq : g.nodes i with
    | input slot => rfl
    | bit a bitIndex => rfl
    | inverse a => rfl
    | linear a b subtract =>
        have h := accepted.linear i
        rw [nodeEq] at h
        cases subtract with
        | false =>
            exact (normalized_add_semantics z (.wire i.val) a b).mp
              ((emitted_row_iff z _).mp h)
        | true =>
            exact (normalized_sub_semantics z (.wire i.val) a b).mp
              ((emitted_row_iff z _).mp h)
    | product a b =>
        obtain ⟨batch, gate, gateEq⟩ := covers.products i a b nodeEq
        have h := batch_products_sound g layout z accepted batch gate
        rw [gateEq] at h
        exact h
  · intro a b member
    exact copy_sound z a b (accepted.equalities a b member)
  · intro i lower upper
    exact binding_sound z i 0 (accepted.padding i lower upper)
  · intro i v member
    exact binding_sound z i v (accepted.publicRows i v member)

/-- Explicit graph-shape certificate for boolean(bitWire), where subtraction
and multiplication were not constant-folded by the native builder. -/
structure BitGuard (g : Graph F) (bitWire : Fin g.count) where
  source : Word F
  bitIndex : Nat
  isBit : g.nodes bitWire = .bit source bitIndex
  difference : Fin g.count
  multiplication : Fin g.count
  differenceNode : g.nodes difference = .linear (.wire bitWire.val) (.constant 1) true
  multiplicationNode : g.nodes multiplication = .product (.wire bitWire.val) (.wire difference.val)
  zeroEquality : (.wire multiplication.val, .constant 0) ∈ g.equalities

theorem guarded_bit_boolean (g : Graph F) (layout : Layout F) (z : Nat → F)
    (semantics : StructuralSemantics g layout z) (bitWire : Fin g.count)
    (guard : BitGuard g bitWire) : z bitWire.val = 0 ∨ z bitWire.val = 1 := by
  have difference := semantics.nodes guard.difference
  rw [guard.differenceNode] at difference
  have multiplication := semantics.nodes guard.multiplication
  rw [guard.multiplicationNode] at multiplication
  have zero := semantics.equalities _ _ guard.zeroEquality
  change z guard.difference.val = z bitWire.val - 1 at difference
  change z guard.multiplication.val = z bitWire.val * z guard.difference.val at multiplication
  change z guard.multiplication.val = 0 at zero
  rw [multiplication, difference] at zero
  rcases mul_eq_zero.mp zero with h | h
  · exact Or.inl h
  · exact Or.inr (sub_eq_zero.mp h)

structure InverseGuard (g : Graph F) (inverseWire : Fin g.count) where
  source : Word F
  isInverse : g.nodes inverseWire = .inverse source
  multiplication : Fin g.count
  multiplicationNode : g.nodes multiplication = .product source (.wire inverseWire.val)
  oneEquality : (.wire multiplication.val, .constant 1) ∈ g.equalities

theorem guarded_inverse_nonzero (g : Graph F) (layout : Layout F) (z : Nat → F)
    (semantics : StructuralSemantics g layout z) (inverseWire : Fin g.count)
    (guard : InverseGuard g inverseWire) :
    read z guard.source * z inverseWire.val = 1 ∧ read z guard.source ≠ 0 := by
  have multiplication := semantics.nodes guard.multiplication
  rw [guard.multiplicationNode] at multiplication
  have one := semantics.equalities _ _ guard.oneEquality
  change z guard.multiplication.val = read z guard.source * z inverseWire.val at multiplication
  change z guard.multiplication.val = 1 at one
  rw [multiplication] at one
  refine ⟨one, ?_⟩
  intro zero
  rw [zero, zero_mul] at one
  exact zero_ne_one one

/-- End-to-end within this structural model: no semantic-equation premise. -/
theorem accepted_bit_boolean (g : Graph F) (layout : Layout F) (z : Nat → F)
    (covers : Covers g layout) (accepted : LoweredAccepted g layout z)
    (bitWire : Fin g.count) (guard : BitGuard g bitWire) :
    z bitWire.val = 0 ∨ z bitWire.val = 1 :=
  guarded_bit_boolean g layout z (structural_lowering_sound g layout z covers accepted)
    bitWire guard

theorem accepted_inverse_nonzero (g : Graph F) (layout : Layout F) (z : Nat → F)
    (covers : Covers g layout) (accepted : LoweredAccepted g layout z)
    (inverseWire : Fin g.count) (guard : InverseGuard g inverseWire) :
    read z guard.source * z inverseWire.val = 1 ∧ read z guard.source ≠ 0 :=
  guarded_inverse_nonzero g layout z (structural_lowering_sound g layout z covers accepted)
    inverseWire guard

end
end HegemonCrypto.NativePrivateSpendPackedLowering
