import HegemonCrypto.NativePrivateSpendPackedLowering
import HegemonCrypto.NativePrivateSpendLocalSemantics

/-! Uncompiled structural certificate contract for the actual flattened CSR.
No packed assignment occurs in CertificateChecks. The theorem quantifies over
all assignments, not just evaluate()/lower() output. Raw offset safety, graph
origin and execution of the data checker remain explicit source obligations. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCsrCertificate
open NativePrivateSpendPackedLowering NativeLaunchConstraintAdapterBridge
open NativeLaunchSparseCoalescing
noncomputable section
variable {F : Type*} [Field F]

/-- Finite buffers; every row has an actual target. No absent-target default. -/
structure RawCSR (F : Type*) where
  rowCount : Nat
  offsets : Fin (rowCount + 1) → Nat
  entries : List (Nat × F)
  targets : Fin rowCount → F

def beginOffset (csr : RawCSR F) (i : Fin csr.rowCount) : Nat :=
  csr.offsets ⟨i.val, by omega⟩
def endOffset (csr : RawCSR F) (i : Fin csr.rowCount) : Nat :=
  csr.offsets ⟨i.val + 1, by omega⟩
def rawRow (csr : RawCSR F) (i : Fin csr.rowCount) : SparseRow F :=
  ⟨(csr.entries.drop (beginOffset csr i)).take
      (endOffset csr i - beginOffset csr i), csr.targets i⟩

/-- Bounds needed to identify list slices with the actual CSR loops. -/
structure RawWellFormed (csr : RawCSR F) (packedLength : Nat) : Prop where
  startsAtZero : csr.offsets ⟨0, by omega⟩ = 0
  endsAtLength : csr.offsets ⟨csr.rowCount, by omega⟩ = csr.entries.length
  monotone : ∀ i, beginOffset csr i ≤ endOffset csr i
  within : ∀ i, endOffset csr i ≤ csr.entries.length
  indices : ∀ entry ∈ csr.entries, entry.1 < packedLength

def RawSatisfied (csr : RawCSR F) (z : Nat → F) : Prop :=
  ∀ i, sparseEval z (rawRow csr i).entries = (rawRow csr i).target

/-- Fixed exhaustive requests: the checker cannot omit a node/equality/padding
wire/public binding/copy lane by supplying a shorter request list. -/
inductive Request (g : Graph F) (layout : Layout F) where
  | node : Fin g.count → Request g layout
  | equality : Fin g.equalities.length → Request g layout
  | padding : Fin (layout.canonicalRows * 64 - g.count) → Request g layout
  | publicBinding : Fin g.publicBindings.length → Request g layout
  | copy : Fin layout.batchCount → Fin 64 → Fin 3 → Request g layout

def requested (g : Graph F) (layout : Layout F) : Request g layout → Option (Row F)
  | .node i => nodeRow i.val (g.nodes i)
  | .equality i => let e := g.equalities.get i; some (copyRow e.1 e.2)
  | .padding i => some (bindRow (g.count + i.val) 0)
  | .publicBinding i => let e := g.publicBindings.get i; some (bindRow e.1 e.2)
  | .copy batch lane operand =>
    let gate := laneGate layout batch lane
    let source := if operand.val = 0 then gate.output
      else if operand.val = 1 then gate.left else gate.right
    some (copyRow (.wire (occurrenceIndex layout batch operand.val lane)) source)

/-- A citation may reuse a CSR row: soundness needs coverage, not injectivity.
It must preserve the target and the complete multiset of nonzero entries.
This accommodates BTreeMap ordering without assuming insertion-order equality. -/
def RowDataCheck (csr : RawCSR F) (locator : Option (Fin csr.rowCount))
    (expected : Option (Row F)) : Prop :=
  match expected with
  | none => True
  | some r => match emit r with
    | none => True
    | some e => ∃ i, locator = some i ∧
        (rawRow csr i).entries.Perm e.entries ∧ (rawRow csr i).target = e.target

def CertificateChecks (g : Graph F) (layout : Layout F) (csr : RawCSR F)
    (citations : Request g layout → Option (Fin csr.rowCount)) : Prop :=
  ∀ request, RowDataCheck csr (citations request) (requested g layout request)

theorem checked_row_sound (csr : RawCSR F) (z : Nat → F)
    (satisfied : RawSatisfied csr z) (locator : Option (Fin csr.rowCount))
    (expected : Option (Row F)) (check : RowDataCheck csr locator expected) :
    optionalRowHolds z expected := by
  cases expected with
  | none => trivial
  | some r =>
    change emittedHolds z (emit r)
    cases emitted : emit r with
    | none => trivial
    | some e =>
      obtain ⟨i, _, permutation, target⟩ :=
        (show ∃ i, locator = some i ∧
          (rawRow csr i).entries.Perm e.entries ∧ (rawRow csr i).target = e.target from
          by simpa only [RowDataCheck, emitted] using check)
      change sparseEval z e.entries = e.target
      rw [← sparseEval_permutation z permutation, ← target]
      exact satisfied i

/-- Converts checked ROW DATA to the old per-row acceptance structure. Only
actual CSR satisfaction and occurrence residuals mention the adversarial z. -/
theorem certificate_derives_lowered_acceptance
    (g : Graph F) (layout : Layout F) (csr : RawCSR F)
    (citations : Request g layout → Option (Fin csr.rowCount))
    (check : CertificateChecks g layout csr citations) (z : Nat → F)
    (satisfied : RawSatisfied csr z)
    (nonlinear : ∀ batch lane,
      Products.productResidual (occurrence layout z batch lane) = 0) :
    LoweredAccepted g layout z := by
  have checked : ∀ r, optionalRowHolds z (requested g layout r) :=
    fun r => checked_row_sound csr z satisfied (citations r) _ (check r)
  constructor
  · intro i
    exact checked (.node i)
  · intro a b member
    obtain ⟨i, hi⟩ := List.mem_iff_get.mp member
    have h := checked (.equality i)
    simpa only [requested, hi, optionalRowHolds] using h
  · intro i lower upper
    have h := checked (.padding ⟨i - g.count, by omega⟩)
    have indexEq : g.count + (i - g.count) = i := by omega
    simpa only [requested, indexEq, optionalRowHolds] using h
  · intro i v member
    obtain ⟨j, hj⟩ := List.mem_iff_get.mp member
    have h := checked (.publicBinding j)
    simpa only [requested, hj, optionalRowHolds] using h
  · intro batch lane
    exact ⟨by simpa [requested, optionalRowHolds] using checked (.copy batch lane 0),
      by simpa [requested, optionalRowHolds] using checked (.copy batch lane 1),
      by simpa [requested, optionalRowHolds] using checked (.copy batch lane 2)⟩
  · exact nonlinear

/-- Coverage is PURE GRAPH DATA, separately checked by extracting Product nodes
and comparing their triples with the complete ordered batch list. It is not a
premise asserting that the desired source equations hold for z. -/
theorem certified_raw_csr_implies_structural_semantics
    (g : Graph F) (layout : Layout F) (csr : RawCSR F)
    (citations : Request g layout → Option (Fin csr.rowCount))
    (check : CertificateChecks g layout csr citations) (coverage : Covers g layout)
    (z : Nat → F) (satisfied : RawSatisfied csr z)
    (nonlinear : ∀ batch lane,
      Products.productResidual (occurrence layout z batch lane) = 0) :
    StructuralSemantics g layout z :=
  structural_lowering_sound g layout z coverage
    (certificate_derives_lowered_acceptance g layout csr citations check z satisfied nonlinear)

/-- Actual source allocates arr::<77>() before any range gadget. Checking this
finite list identity binds precisely the first 77 canonical wire indices. -/
def public77 (pub : Fin 77 → F) : List (Nat × F) :=
  List.ofFn (fun i : Fin 77 => (i.val, pub i))

theorem certified_public77 (g : Graph F) (layout : Layout F) (z : Nat → F)
    (semantics : StructuralSemantics g layout z) (pub : Fin 77 → F)
    (bindingData : g.publicBindings = public77 pub) :
    ∀ i : Fin 77, z i.val = pub i := by
  intro i
  apply semantics.publicValues i.val (pub i)
  rw [bindingData]
  exact List.mem_ofFn.mpr ⟨i, rfl⟩

theorem certified_intent_projection (g : Graph F) (layout : Layout F) (z : Nat → F)
    (semantics : StructuralSemantics g layout z) (pub : Fin 77 → F)
    (bindingData : g.publicBindings = public77 pub) :
    (fun i : Fin 54 => z (NativePrivateSpendLocalSemantics.intentSource i).val) =
      NativePrivateSpendLocalSemantics.intentProjection pub := by
  funext i
  exact certified_public77 g layout z semantics pub bindingData
    (NativePrivateSpendLocalSemantics.intentSource i)

/-- Geometry of the inspected fixed source, not an assertion that Rust produced
these values. The runtime checker must bind these data before use. -/
theorem fixed_geometry_arithmetic :
    (676622 + 63) / 64 = 10573 ∧ 10573 * 64 - 676622 = 50 ∧
    10573 + 3 * 5210 = 26203 ∧ 26203 * 64 = 1676992 ∧
    13112 + 58 - 1 = 13169 := by norm_num

end
end HegemonCrypto.NativePrivateSpendCsrCertificate
