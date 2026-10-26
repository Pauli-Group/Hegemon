import HegemonCrypto.NativePrivateSpendQ58CurrentPublicFactorizationBase
import HegemonCrypto.NativePrivateSpendHtlcRecipient
import HegemonCrypto.NativePrivateSpendMerkleContinuation

/-! Current relation-to-source join. Certificates below contain only CSR row,
product-row, graph and operation data; none contains assignment validity or a
semantic-output law. G3 must still derive Satisfies on the recovered assignment
from its actual accepted execution. This module does not assume that seam. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics
open NativePrivateSpendPackedLowering NativePrivateSpendCsrCertificate
open NativePrivateSpendArithmeticTopology NativePrivateSpendLocalSemantics
open NativePrivateSpendG1SourceComposition NativePrivateSpendHtlcRecipient
open NativePrivateSpendCurrentSourceCallContract NativePrivateSpendRoleBridge
open NativeLaunchConstraintAdapterBridge
namespace Current
export HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening
  (Row Lane Check Batch Values Relation Satisfies csrValue)
end Current
noncomputable section
variable [Fact (Nat.Prime modulus)]

def wordIndex (row : Current.Row) (lane : Current.Lane) : Nat :=
  row.val * 64 + lane.val

/-- The single concrete packed assignment, including product occurrence rows.
Out-of-range indices are zero; authenticated graph data must stay in range. -/
def sourceAssignment (values : Current.Values) (index : Nat) : K :=
  if h : index / 64 < 26210 then
    values ⟨index / 64, h⟩ ⟨index % 64, Nat.mod_lt _ (by decide)⟩
  else 0

theorem sourceAssignment_lookup (values : Current.Values)
    (row : Current.Row) (lane : Current.Lane) :
    sourceAssignment values (wordIndex row lane) = values row lane := by
  have quotient : (row.val * 64 + lane.val) / 64 = row.val := by omega
  have remainder : (row.val * 64 + lane.val) % 64 = lane.val := by omega
  simp [sourceAssignment, wordIndex, quotient, remainder]

def sourceTerms (terms : List ((Current.Row × Current.Lane) × K)) :
    List (Nat × K) := terms.map fun term => (wordIndex term.1.1 term.1.2, term.2)

theorem sourceTerms_eval (values : Current.Values)
    (terms : List ((Current.Row × Current.Lane) × K)) :
    sparseEval (sourceAssignment values) (sourceTerms terms) =
      Current.csrValue terms values := by
  induction terms with
  | nil => rfl
  | cons term rest ih =>
      let head : K := values term.1.1 term.1.2
      let tail : K := Current.csrValue rest values
      change term.2 * sourceAssignment values (wordIndex term.1.1 term.1.2) +
        sparseEval (sourceAssignment values) (sourceTerms rest) =
        term.2 * head + tail
      have lookup : sourceAssignment values (wordIndex term.1.1 term.1.2) = head :=
        sourceAssignment_lookup values term.1.1 term.1.2
      have restEq : sparseEval (sourceAssignment values) (sourceTerms rest) = tail := ih
      exact congrArg₂ (fun (head tail : K) => term.2 * head + tail) lookup restEq

/-- All equalities are between immutable row/address data. Row requests and
coverage remain exhaustive through the existing CertificateChecks/Covers. -/
structure RelationCertificate (relation : Current.Relation)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K) where
  checkIndex : Fin csr.rowCount → Current.Check
  entries : ∀ i, (rawRow csr i).entries = sourceTerms (relation.csr (checkIndex i))
  targets : ∀ i, (rawRow csr i).target = relation.target (checkIndex i)
  batchIndex : Fin layout.batchCount → Current.Batch
  products : ∀ batch (operand : Fin 3) lane,
    occurrenceIndex layout batch operand.val lane =
      wordIndex (relation.batch (batchIndex batch) operand) lane
  citations : Request g layout → Option (Fin csr.rowCount)
  rows : CertificateChecks g layout csr citations
  coverage : Covers g layout

theorem relation_derives_structural_semantics (relation : Current.Relation)
    (values : Current.Values) (valid : Current.Satisfies relation values)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr) :
    StructuralSemantics g layout (sourceAssignment values) := by
  apply certified_raw_csr_implies_structural_semantics g layout csr
    certificate.citations certificate.rows certificate.coverage
  · intro i
    rw [certificate.entries i, certificate.targets i, sourceTerms_eval]
    exact valid.linear (certificate.checkIndex i)
  · intro batch lane
    change sourceAssignment values (occurrenceIndex layout batch 0 lane) -
      sourceAssignment values (occurrenceIndex layout batch 1 lane) *
        sourceAssignment values (occurrenceIndex layout batch 2 lane) = 0
    have product0 : occurrenceIndex layout batch 0 lane =
        wordIndex (relation.batch (certificate.batchIndex batch) 0) lane :=
      certificate.products batch (0 : Fin 3) lane
    have product1 : occurrenceIndex layout batch 1 lane =
        wordIndex (relation.batch (certificate.batchIndex batch) 1) lane :=
      certificate.products batch (1 : Fin 3) lane
    have product2 : occurrenceIndex layout batch 2 lane =
        wordIndex (relation.batch (certificate.batchIndex batch) 2) lane :=
      certificate.products batch (2 : Fin 3) lane
    rw [product0, product1, product2]
    simp only [sourceAssignment_lookup]
    exact sub_eq_zero.mpr (valid.multiply (certificate.batchIndex batch) lane)

/-- Common77, unique branch, integer balance, exact Final intent and HTLC
recipient/payout/height consequences use exactly the same recovered values. -/
theorem relation_current_main_and_recipients (relation : Current.Relation)
    (values : Current.Values) (valid : Current.Satisfies relation values)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (pub : Fin 77 → K) (r : Roles) (v : RouteRoles) (amounts : Fin 5 → Word K)
    (binding : SourceBinding g pub r v amounts) (w : Nat → Word K)
    (recipients : RecipientChecked g r v w) :
    MainSourceConsequences (sourceAssignment values) pub r v amounts ∧
    (natural (sourceAssignment values) (v.modes 4) = 1 →
      SelectedRecipient (sourceAssignment values) w recipients.who r.claimAuthority r.claimRecipient) ∧
    (natural (sourceAssignment values) (v.modes 5) = 1 →
      SelectedRecipient (sourceAssignment values) w recipients.who r.refundAuthority r.refundRecipient) := by
  exact g1_with_recipients g layout (sourceAssignment values)
    (relation_derives_structural_semantics relation values valid g layout csr certificate)
    pub r v amounts binding w recipients

/-- Both exact output commitment calls are kept, including value-zero outputs.
There is no positive-value filter in the source public77 commitment interface. -/
theorem relation_output_commitment (relation : Current.Relation)
    (values : Current.Values) (valid : Current.Satisfies relation values)
    (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (pub : Fin 77 → K) (binding : g.publicBindings = public77 pub)
    (slot : Fin 2) (call : OutputNoteCall g slot) (lane : Fin 7) :
    pub ⟨39 + 7*slot.val + lane.val, by omega⟩ =
      (NativePrivateSpendSpongeBridge.spongeNaturals (sourceAssignment values)
        (1 : K) (List.ofFn call.note) |>.getD lane.val 0 : K) := by
  exact output_note_commitment g layout (sourceAssignment values)
    (relation_derives_structural_semantics relation values valid g layout csr certificate)
    pub binding slot call lane

/-- Operation data for circuit.rs's Approval guards. The fields are graph
locators and operation certificates, not Boolean/signer/value conclusions. -/
structure ApprovalChecked (g : Graph K) (r : Roles) (v : RouteRoles)
    (inputValue outputValue : Word K) where
  beforeBits : ∀ i, BooleanData g (r.approved i)
  signerBits : ∀ i, BooleanData g (r.signer i)
  signerCount : Word K
  signerSum : ThreeSumChecked g r.signer signerCount
  oneSigner : GateData g (v.modes 1) signerCount (.constant 1)
  overlap : Fin 3 → Word K
  overlapMul : ∀ i, MulData g (r.approved i) (r.signer i) (overlap i)
  disjoint : ∀ i, GateData g (v.modes 1) (overlap i) (.constant 0)
  nextAdd : ∀ i, AddData g (r.approved i) (r.signer i) (r.next i)
  inputZero : GateData g (v.modes 1) inputValue (.constant 0)
  outputZero : GateData g (v.modes 1) outputValue (.constant 0)

structure ApprovalConsequences (z : Nat → K) (r : Roles)
    (inputValue outputValue : Word K) : Prop where
  beforeBits : ∀ i, read z (r.approved i) = 0 ∨ read z (r.approved i) = 1
  signerBits : ∀ i, read z (r.signer i) = 0 ∨ read z (r.signer i) = 1
  oneSigner : (read z (r.signer 0) + read z (r.signer 1)) + read z (r.signer 2) = 1
  disjoint : ∀ i, read z (r.approved i) * read z (r.signer i) = 0
  next : ∀ i, read z (r.next i) = read z (r.approved i) + read z (r.signer i)
  inputZero : natural z inputValue = 0
  outputZero : natural z outputValue = 0

theorem approval_consequences (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (v : RouteRoles)
    (inputValue outputValue : Word K)
    (checked : ApprovalChecked g r v inputValue outputValue)
    (selected : natural z (v.modes 1) = 1) :
    ApprovalConsequences z r inputValue outputValue := by
  have signerSum := three_sum_sound g layout z sem _ _ checked.signerSum
  have count := selected_gate g layout z sem _ _ _ checked.oneSigner selected
  refine ⟨fun i => boolean_sound g layout z sem _ (checked.beforeBits i),
    fun i => boolean_sound g layout z sem _ (checked.signerBits i), ?_, ?_,
    fun i => add_sound g layout z sem (checked.nextAdd i), ?_, ?_⟩
  · exact signerSum.symm.trans count
  · intro i
    have zero := selected_gate g layout z sem _ _ _ (checked.disjoint i) selected
    rw [mul_sound g layout z sem (checked.overlapMul i)] at zero
    exact zero
  · have zero := selected_gate g layout z sem _ _ _ checked.inputZero selected
    simpa only [natural, NativeLaunchConstraintAdapterBridge.read, ZMod.val_zero] using congrArg ZMod.val zero
  · have zero := selected_gate g layout z sem _ _ _ checked.outputZero selected
    simpa only [natural, NativeLaunchConstraintAdapterBridge.read, ZMod.val_zero] using congrArg ZMod.val zero

/-- The Approval credential is input1's exact key hash, gated by the actual
product approval*signer[i]. No policy membership equation is a field. -/
structure ApprovalSignerChecked (g : Graph K) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) where
  who : NativePrivateSpendSymbolicBridge.DigestWords
  single : NativePrivateSpendSpongeBridge.SpongeChecked g (0x48534b4156320001 : K)
    (List.ofFn (NativePrivateSpendSelectedNullifier.key w (1 : Fin 2)) ++ [.constant 0,.constant 0]) who
  selectors : Fin 3 → Word K
  products : ∀ i, MulData g (v.modes 1) (r.signer i) (selectors i)
  policy : ∀ i lane, GateData g (selectors i) (who lane)
    (r.tags ⟨7*i.val+lane.val, by omega⟩)

theorem approval_selected_signer (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) (checked : ApprovalSignerChecked g r v w)
    (approval : natural z (v.modes 1) = 1) (slot : Fin 3)
    (signer : read z (r.signer slot) = 1) :
    SpongeEquation z (0x48534b4156320001 : K)
      (List.ofFn (NativePrivateSpendSelectedNullifier.key w (1 : Fin 2)) ++ [.constant 0,.constant 0]) checked.who ∧
    (∀ lane, read z (checked.who lane) = read z (r.tags ⟨7*slot.val+lane.val, by omega⟩)) := by
  have approvalOne : read z (v.modes 1) = 1 := by
    rw [← natural_cast z (v.modes 1), approval, Nat.cast_one]
  have selected := mul_sound g layout z sem (checked.products slot)
  rw [approvalOne, signer, one_mul] at selected
  have selectedNat : natural z (checked.selectors slot) = 1 := by
    simpa only [natural, ZMod.val_one] using congrArg ZMod.val selected
  exact ⟨source_sponge g layout z sem _ _ _ checked.single,
    fun lane => selected_gate g layout z sem _ _ _ (checked.policy slot lane) selectedNat⟩
end
end HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics
