import HegemonCrypto.NativePrivateSpendCurrentAppendReadback
import HegemonCrypto.NativePrivateSpendCurrentFinalHistory

/-! Native append-data to source history, or an actual current NOTE/COMPFF
Merkle collision. Native premises contain raw note tables, append positions,
chronological prefix stages and snapshot roots only. Previous-note equality,
Approval lineage and Final authorization are derived, never native premises.
The native table/frontier interpretation remains the explicit PR205 F1
implementation boundary, with current evaluator equations checked separately. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentApprovalTransition NativePrivateSpendCurrentFinalHistory
open NativePrivateSpendCurrentAppendReadback NativePrivateSpendCurrentMerklePath
open NativePrivateSpendCurrentChronologicalApprovalHistory
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
open NativePrivateSpendSelectedNullifier NativePrivateSpendMerkleContinuation
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Current source-bound root/table at a native chronological prefix. Every
field is graph/locator data or an ordinary native append/readback fact. The
anchor may be a retained historical prefix, not the latest output root. -/
structure NativeSnapshot (outputs : List Produced) (source : SourceApproval) where
  «public» : Fin 77 → K
  publicBinding : source.graph.publicBindings = NativePrivateSpendCsrCertificate.public77 «public»
  merkle : ∀ slot : Fin 2, MerkleChecked source.graph source.inputWords slot
  anchorPrefix : List Produced
  prefixBefore : anchorPrefix.IsPrefix outputs
  prefixAppend : RawAppendTrace anchorPrefix
  table : RawNoteTable anchorPrefix
  root : (fromLog 32 0 (anchorPrefix.map table.note)).root =
    List.ofFn fun lane : Fin 7 => («public» ⟨17 + lane.val, by omega⟩).val
  earlier : ∀ parent ∈ anchorPrefix, parent.stage < source.stage

/-- The failure retains the actual prefix table and two actual opening paths
at the current source position; its effective hash inputs are not invented. -/
def SnapshotCollision (outputs : List Produced) (source : SourceApproval)
    (snapshot : NativeSnapshot outputs source) (slot : Fin 2) : Prop :=
  ∃ path, Nonempty (PathCollision currentPathHash
    (sourceLeaf (sourceAssignment source.packed) source.inputWords slot)
    (openingAt (snapshot.anchorPrefix.map snapshot.table.note)
      (natural (sourceAssignment source.packed) (position source.inputWords slot)))
    (sourcePath source.graph (sourceAssignment source.packed) source.inputWords slot
      (snapshot.merkle slot) 32 (by omega)) path)

theorem approval_snapshot_readback_or_collision (outputs : List Produced)
    (source : SatisfiedApproval)
    (snapshot : NativeSnapshot outputs source.val) :
    NativeReadback outputs source ∨ SnapshotCollision outputs source.val snapshot 0 := by
  classical
  by_cases occupied : (sourceRecord source.val).occupied = true
  · let data := source.val
    let z := sourceAssignment data.packed
    have sem := relation_derives_structural_semantics data.relation data.packed source.property.1
      data.graph data.layout data.csr data.certificate
    have one : natural z (NativePrivateSpendSelectedNullifier.occupied data.inputWords (0 : Fin 2)) = 1 := by
      have field := (source_occupied data).mp occupied
      rw [data.recordBinding.occupied] at field
      simpa only [natural, ZMod.val_one] using congrArg ZMod.val field
    rcases source_native_raw_readback_or_collision data.graph data.layout z sem snapshot.«public»
      snapshot.publicBinding data.inputWords 0 (snapshot.merkle 0) one snapshot.anchorPrefix snapshot.table
      snapshot.prefixAppend data.stage snapshot.earlier snapshot.root with raw | collision
    · left
      intro _
      rcases raw with empty | ⟨parent, member, positionEq, earlier, valueEq, ownerEq⟩
      · exact Or.inl empty
      · refine Or.inr ⟨parent, snapshot.prefixBefore.subset member, ?_, earlier, valueEq, ownerEq⟩
        change (if (sourceRecord source.val).occupied then
          some (natural z (position data.inputWords (0 : Fin 2))) else none) = some parent.position
        rw [occupied, if_pos rfl, positionEq]
    · exact Or.inr collision
  · exact Or.inl (fun active => False.elim (occupied active))

theorem final_snapshot_readback_or_collision (outputs : List Produced)
    (final : SourceFinal) (valid : FinalValid final)
    (snapshot : NativeSnapshot outputs final.source) :
    FinalNativeReadback outputs final ∨ SnapshotCollision outputs final.source snapshot 1 := by
  let source := final.source
  let z := sourceAssignment source.packed
  have sem := relation_derives_structural_semantics source.relation source.packed valid.1
    source.graph source.layout source.csr source.certificate
  have occupied := (final_source_facts final valid).2.1
  rcases source_native_raw_readback_or_collision source.graph source.layout z sem snapshot.«public»
    snapshot.publicBinding source.inputWords 1 (snapshot.merkle 1) occupied snapshot.anchorPrefix snapshot.table
    snapshot.prefixAppend source.stage snapshot.earlier snapshot.root with raw | collision
  · left
    rcases raw with empty | ⟨parent, member, _, earlier, value, owner⟩
    · exact Or.inl empty
    · exact Or.inr ⟨parent, snapshot.prefixBefore.subset member, earlier, value, owner⟩
  · exact Or.inr collision

/-- All relation-valid source outputs, including zero-value approvals, with
raw native snapshots. No constructor supplies predecessor field equality,
an authorized bitmap, a successful replay or a lineage. -/
inductive NativeSourceTrace : List Produced → Prop where
  | empty : NativeSourceTrace []
  | reward {outputs} (before : NativeSourceTrace outputs) (output : RewardOutput)
      (positive : 0 < output.value) (position : output.position = outputs.length) :
      NativeSourceTrace (outputs ++ [.reward output])
  | other {outputs} (before : NativeSourceTrace outputs) (output : OtherOutput)
      (position : output.position = outputs.length) : NativeSourceTrace (outputs ++ [.other output])
  | approval {outputs} (before : NativeSourceTrace outputs) (source : SatisfiedApproval)
      (position : source.val.outputPosition = outputs.length)
      (snapshot : NativeSnapshot outputs source.val) : NativeSourceTrace (outputs ++ [.approval source])

theorem native_trace_raw_append {outputs : List Produced} (trace : NativeSourceTrace outputs) :
    RawAppendTrace outputs := by
  induction trace with
  | empty => exact .empty
  | reward before output positive position ih => exact .append ih (.reward output) position
  | other before output position ih => exact .append ih (.other output) position
  | approval before source position snapshot ih => exact .append ih (.approval source) position

def CurrentNativeMerkleBad (outputs : List Produced) : Prop :=
  ∃ source : SatisfiedApproval, Produced.approval source ∈ outputs ∧
    ∃ «prefix» : List Produced, ∃ snapshot : NativeSnapshot «prefix» source.val,
      (∀ parent ∈ «prefix», parent ∈ outputs) ∧ SnapshotCollision «prefix» source.val snapshot 0

theorem native_merkle_bad_mono (before after : List Produced)
    (included : ∀ parent ∈ before, parent ∈ after) (bad : CurrentNativeMerkleBad before) :
    CurrentNativeMerkleBad after := by
  rcases bad with ⟨source, present, «prefix», snapshot, members, collision⟩
  exact ⟨source, included _ present, «prefix», snapshot,
    fun parent member => included parent (members parent member), collision⟩

/-- This is the hard history join: readback failure becomes a concrete current
Merkle collision; otherwise the same native output stream becomes SourceTrace. -/
theorem native_trace_source_history_or_merkle_bad {outputs : List Produced}
    (trace : NativeSourceTrace outputs) : SourceTrace outputs ∨ CurrentNativeMerkleBad outputs := by
  induction trace with
  | empty => exact Or.inl .empty
  | reward before output positive position ih =>
    rcases ih with source | bad
    · exact Or.inl (.reward source output positive position)
    · exact Or.inr (native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)
  | other before output position ih =>
    rcases ih with source | bad
    · exact Or.inl (.other source output position)
    · exact Or.inr (native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)
  | @approval «prefix» before source position snapshot ih =>
    rcases ih with history | bad
    · rcases approval_snapshot_readback_or_collision «prefix» source snapshot with readback | collision
      · exact Or.inl (.approval history source position readback)
      · exact Or.inr ⟨source, by simp, «prefix», snapshot,
          fun parent member => List.mem_append_left _ member, collision⟩
    · exact Or.inr (native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)

/-- Complete G1 mathematical endpoint under the disclosed native append-word
interpretation. Neither G3 accepted witness nor desired history success is a
premise. Every unsuccessful good-arm join returns an actual primitive event. -/
theorem current_native_final_authorization_or_failure (outputs : List Produced)
    (trace : NativeSourceTrace outputs) (final : SourceFinal) (valid : FinalValid final)
    (snapshot : NativeSnapshot outputs final.source) :
    FinalAuthorized outputs final ∨ CurrentHistoryBad outputs ∨ FinalHistoryBad outputs final ∨
      CurrentNativeMerkleBad outputs ∨ SnapshotCollision outputs final.source snapshot 1 := by
  rcases native_trace_source_history_or_merkle_bad trace with history | failure
  · rcases final_snapshot_readback_or_collision outputs final valid snapshot with readback | collision
    · rcases current_relation_history_final_authorization outputs history final valid readback with
        authorized | historyBad | finalBad
      · exact Or.inl authorized
      · exact Or.inr (Or.inl historyBad)
      · exact Or.inr (Or.inr (Or.inl finalBad))
    · exact Or.inr (Or.inr (Or.inr (Or.inr collision)))
  · exact Or.inr (Or.inr (Or.inr (Or.inl failure)))
end
end HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin
