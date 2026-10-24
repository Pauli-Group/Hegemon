import HegemonCrypto.NativePrivateSpendCurrentCanonicalHash
import HegemonCrypto.NativePrivateSpendCurrentNativeHistoryJoin
import SmzaRoleDomainConditioning
import HegemonCrypto.Goldilocks

/-! Additional canonical G1 game adapter. Original qualified G1 sources and
all native/history/Final arms are unchanged. Native comparison paths retain
their actual PathAt witness; no broad arbitrary-list collision advantage is
assumed. Source interpretation retains the disclosed F1 trust contract. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter
open NativePrivateSpendCurrentNativeHistoryJoin NativePrivateSpendCurrentAppendReadback
open NativePrivateSpendCurrentApprovalTransition
open NativePrivateSpendCurrentMerklePath NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentChronologicalApprovalHistory NativePrivateSpendCurrentProtocolHistory
open NativePrivateSpendCurrentFinalHistory NativePrivateSpendCurrentSixCaseSemantics
open NativePrivateSpendCurrentAcceptedHistory NativePrivateSpendCurrentEvaluatorIdentity
open NativePrivateSpendCurrentSpongeEvaluatorIdentity NativePrivateSpendSymbolicBridge
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
open NativePrivateSpendSelectedNullifier NativePrivateSpendMerkleContinuation
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open NativePrivateSpendCurrentCanonicalHash
open NativePrivateSpendCurrentRoleGames NativePrivateSpendCompffPrimitiveGames
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open scoped BigOperators Classical
noncomputable section

attribute [local irreducible] currentPathHash
  HegemonCrypto.SmallWood.MerkleExtraction.rootFromPath
  Hegemon.Transaction.Poseidon2V8SemanticSpecification.poseidon2V8Sponge
  Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives.compress14

private theorem field_words_good {n : Nat} (words : Fin n → K) :
    GoodWords n (List.ofFn fun i => (words i).val) := by
  constructor
  · exact List.length_ofFn
  · intro word present
    rcases List.mem_ofFn.mp present with ⟨i, rfl⟩
    exact ZMod.val_lt (words i)

theorem digest_naturals_good (z : Nat → K) (words : DigestWords) :
    GoodWords 7 (digestNaturals z words) := field_words_good (fun i => read z (words i))

theorem source_leaf_good (z : Nat → K) (w : Nat → Word K) (slot : Fin 2) :
    GoodWords 18 (sourceLeaf z w slot) := by
  have same : sourceLeaf z w slot =
      List.ofFn (fun i : Fin 18 => (read z (noteWords w slot i)).val) := by
    exact List.map_ofFn (f := noteWords w slot)
      (g := fun word : Word K => (read z word).val)
  exact same.symm ▸ field_words_good (fun i => read z (noteWords w slot i))

private theorem ofFn_getD_reconstruct (xs : List Nat) (n : Nat)
    (h : xs.length = n) :
    (List.ofFn fun i : Fin n => xs.getD i.val 0) = xs := by
  subst n
  calc
    _ = List.ofFn (fun i : Fin xs.length => xs[i.val]) := by
      apply congrArg List.ofFn
      funext i
      exact List.getD_eq_getElem xs 0 i.isLt
    _ = xs := List.ofFn_getElem

/-- The real default is a fixed-message bare SINGLE sponge target. -/
theorem native_empty_owner_eq : nativeEmptyOwner =
    poseidon2V8Sponge currentSourceSingleKeyDomain [1, 0, 0, 0, 0, 0, 0] := by
  change (List.ofFn fun i : Fin 7 =>
    (poseidon2V8Sponge currentSourceSingleKeyDomain [1, 0, 0, 0, 0, 0, 0]).getD i.val 0) = _
  exact ofFn_getD_reconstruct _ 7 (sponge_canonical _ _).1

private theorem empty_identity_lt (i : Fin 7) :
    nativeEmptyIdentityWord i < fieldModulus := by
  let xs := poseidon2V8Sponge currentSourceSingleKeyDomain [1, 0, 0, 0, 0, 0, 0]
  have good : GoodWords 7 xs := sponge_canonical _ _
  have bound : i.val < xs.length := by rw [good.1]; exact i.isLt
  change xs.getD i.val 0 < fieldModulus
  exact (congrArg (fun x : Nat => x < fieldModulus)
    (List.getD_eq_getElem xs 0 bound)).mpr (good.2 _ (List.getElem_mem bound))

theorem empty_note_good : GoodWords 18 emptyNote := by
  constructor
  · simp only [emptyNote, List.length_ofFn]
  · intro word present
    unfold emptyNote at present
    rcases List.mem_ofFn.mp present with ⟨i, rfl⟩
    split
    · exact empty_identity_lt _
    · split
      · exact empty_identity_lt _
      · exact (by decide : 0 < fieldModulus)

theorem opening_at_good (notes : List (List Nat))
    (good : ∀ note ∈ notes, GoodWords 18 note) (index : Nat) :
    GoodWords 18 (openingAt notes index) := by
  unfold openingAt
  by_cases bound : index < notes.length
  · rw [if_pos bound, List.getD_eq_getElem notes emptyNote bound]
    exact good _ (List.getElem_mem bound)
  · rw [if_neg bound]
    exact empty_note_good

theorem current_hash_good (input : HashInput (List Nat) Digest) :
    GoodWords 7 (currentPathHash input) := by
  cases input with
  | leaf words =>
    rw [currentPathHash_leaf_eq]
    exact sponge_canonical _ _
  | node left right =>
    rw [currentPathHash_node_eq]
    exact compff_canonical _ _ _

theorem root_from_path_good (leaf : List Nat) (path : AuthenticationPath Digest) :
    GoodWords 7 (rootFromPath currentPathHash leaf path) := by
  cases path with
  | nil =>
    rw [rootFromPath_nil_eq]
    exact current_hash_good _
  | cons step tail =>
    cases step with
    | mk sibling side =>
      cases side with
      | left => rw [rootFromPath_cons_left_eq]; exact current_hash_good _
      | right => rw [rootFromPath_cons_right_eq]; exact current_hash_good _

def GoodPath (path : AuthenticationPath Digest) : Prop :=
  ∀ step ∈ path, GoodWords 7 step.sibling

private theorem good_path_cons (step : AuthenticationStep Digest)
    (path : AuthenticationPath Digest) (head : GoodWords 7 step.sibling)
    (tail : GoodPath path) : GoodPath (step :: path) := by
  intro item present
  rcases List.mem_cons.mp present with rfl | present
  · exact head
  · exact tail item present

section SourcePath
/-- The fixed modulus prime certificate is already proved in Goldilocks. -/
local instance currentSourcePathPrimeFact : Fact (Nat.Prime modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

theorem source_path_good (g : Graph K) (z : Nat → K) (w : Nat → Word K)
    (slot : Fin 2) (checked : MerkleChecked g w slot) (count : Nat) (bound : count ≤ 32) :
    GoodPath (sourcePath g z w slot checked count bound) := by
  induction count with
  | zero => intro step present; cases present
  | succ count ih =>
    have smaller : count ≤ 32 := by omega
    let level : Fin 32 := ⟨count, by omega⟩
    have same : sourcePath g z w slot checked (count + 1) bound =
        sourceStep g z w slot checked level :: sourcePath g z w slot checked count smaller := rfl
    rw [same]
    exact good_path_cons _ _ (digest_naturals_good z (siblingWords w slot level)) (ih smaller)
end SourcePath

theorem tree_root_good (tree : Tree) : GoodWords 7 tree.root := by
  cases tree with
  | leaf position payload => exact current_hash_good (.leaf payload)
  | node left right => exact current_hash_good (.node left.root right.root)

theorem native_path_good {tree : Tree} {position : Nat} {payload : List Nat}
    {path : AuthenticationPath Digest} (native : PathAt tree position payload path) : GoodPath path := by
  induction native with
  | leaf position payload => intro step present; cases present
  | @left left right position payload path child ih =>
    exact good_path_cons _ _ (tree_root_good right) ih
  | @right left right position payload path child ih =>
    exact good_path_cons _ _ (tree_root_good left) ih

def GoodInput : HashInput (List Nat) Digest → Prop
  | .leaf payload => GoodWords 18 payload
  | .node left right => GoodWords 7 left ∧ GoodWords 7 right

private theorem ordered_input_good (step : AuthenticationStep Digest) (child : Digest)
    (sibling : GoodWords 7 step.sibling) (root : GoodWords 7 child) :
    GoodInput (orderedInput step child) := by
  cases step with
  | mk siblingWords direction =>
    cases direction with
    | left => exact ⟨root, sibling⟩
    | right => exact ⟨sibling, root⟩

theorem effective_inputs_good (leaf : List Nat) (path : AuthenticationPath Digest)
    (leafGood : GoodWords 18 leaf) (pathGood : GoodPath path) :
    ∀ input ∈ effectiveInputs currentPathHash leaf path, GoodInput input := by
  induction path with
  | nil =>
    intro input present
    have same : input = .leaf leaf := List.mem_singleton.mp present
    exact same.symm ▸ leafGood
  | cons step tail ih =>
    intro input present
    rcases List.mem_cons.mp present with rfl | present
    · exact ordered_input_good step _ (pathGood step (List.mem_cons_self (a := step) (l := tail)))
        (root_from_path_good leaf tail)
    · exact ih (fun item member => pathGood item (List.mem_cons_of_mem step member)) input present

/-- Canonical words are the exact effective operands, with no ignored suffix
or padding difference available to win either collision game. -/
abbrev CanonicalWords (n : Nat) := { words : List Nat // GoodWords n words }
abbrev CanonicalNode := CanonicalWords 7 × CanonicalWords 7

/-- Seven fresh CURRENT games required by the literal G1 bad arms. -/
inductive GameOutput where
  | note (left right : CanonicalWords 18)
  | merkle (left right : CanonicalNode)
  | ordinaryAccumulator (recipient : CanonicalWords 7) (input : AccumulatorOwnerInput)
  | valueAccumulator (value : ValueOwnerInput) (input : AccumulatorOwnerInput)
  | accumulator (left right : AccumulatorOwnerInput)
  | accumulatorHtlc (input : AccumulatorOwnerInput) (htlc : HtlcOwnerInput)
  | knownSingleAccumulator (input : AccumulatorOwnerInput)

def GameOutput.kind : GameOutput → Fin 7
  | .note _ _ => 0
  | .merkle _ _ => 1
  | .ordinaryAccumulator _ _ => 2
  | .valueAccumulator _ _ => 3
  | .accumulator _ _ => 4
  | .accumulatorHtlc _ _ => 5
  | .knownSingleAccumulator _ => 6

def GameWin : GameOutput → Prop
  | .note left right => left.val ≠ right.val ∧
      poseidon2V8Sponge 1 left.val = poseidon2V8Sponge 1 right.val
  | .merkle left right => (left.1.val, left.2.val) ≠ (right.1.val, right.2.val) ∧
      P.compress14 4 left.1.val left.2.val = P.compress14 4 right.1.val right.2.val
  | .ordinaryAccumulator recipient input => ordinaryRecipientAccumulatorClaw recipient.val input
  | .valueAccumulator value input => valueAccumulatorClaw (value, input)
  | .accumulator left right => accumulatorCollision (left, right)
  | .accumulatorHtlc input htlc => accumulatorHtlcClaw (input, htlc)
  | .knownSingleAccumulator input => accumulatorOwner input =
      poseidon2V8Sponge currentSourceSingleKeyDomain [1, 0, 0, 0, 0, 0, 0]

theorem canonical_collision_game {leftLeaf rightLeaf : List Nat}
    {leftPath rightPath : AuthenticationPath Digest}
    (collision : PathCollision currentPathHash leftLeaf rightLeaf leftPath rightPath)
    (leftGood : ∀ input ∈ effectiveInputs currentPathHash leftLeaf leftPath, GoodInput input)
    (rightGood : ∀ input ∈ effectiveInputs currentPathHash rightLeaf rightPath, GoodInput input) :
    ∃ output : GameOutput, GameWin output := by
  have leftCanonical := leftGood collision.leftInput collision.leftUsed
  have rightCanonical := rightGood collision.rightInput collision.rightUsed
  rcases collision with ⟨left, right, _, _, different, sameKind, sameDigest⟩
  cases left with
  | leaf left =>
    cases right with
    | leaf right =>
      refine ⟨.note ⟨left, leftCanonical⟩ ⟨right, rightCanonical⟩, ?_, ?_⟩
      · intro same; exact different (congrArg HashInput.leaf same)
      · exact (currentPathHash_leaf_eq left).symm.trans
          (sameDigest.trans (currentPathHash_leaf_eq right))
    | node first second => cases sameKind
  | node first second =>
    cases right with
    | leaf right => cases sameKind
    | node third fourth =>
      refine ⟨.merkle (⟨first, leftCanonical.1⟩, ⟨second, leftCanonical.2⟩)
        (⟨third, rightCanonical.1⟩, ⟨fourth, rightCanonical.2⟩), ?_, ?_⟩
      · intro same
        exact different (congrArg₂ HashInput.node (Prod.mk.inj same).1 (Prod.mk.inj same).2)
      · exact (currentPathHash_node_eq first second).symm.trans
          (sameDigest.trans (currentPathHash_node_eq third fourth))


section Source
variable [Fact (Nat.Prime modulus)]

theorem raw_notes_good (outputs : List Produced) (table : RawNoteTable outputs) :
    ∀ note ∈ outputs.map table.note, GoodWords 18 note := by
  intro note present
  rcases List.mem_map.mp present with ⟨output, member, rfl⟩
  exact ⟨table.exactWords output member, fun word present => table.canonical output member word present⟩

/-- Actual native tree membership is retained in this additional predicate. -/
def CanonicalSnapshotCollision (outputs : List Produced) (source : SourceApproval)
    (snapshot : NativeSnapshot outputs source) (slot : Fin 2) : Prop :=
  ∃ path, PathAt (fromLog 32 0 (snapshot.anchorPrefix.map snapshot.table.note))
    (natural (sourceAssignment source.packed) (position source.inputWords slot))
    (openingAt (snapshot.anchorPrefix.map snapshot.table.note)
      (natural (sourceAssignment source.packed) (position source.inputWords slot))) path ∧
    Nonempty (PathCollision currentPathHash
      (sourceLeaf (sourceAssignment source.packed) source.inputWords slot)
      (openingAt (snapshot.anchorPrefix.map snapshot.table.note)
        (natural (sourceAssignment source.packed) (position source.inputWords slot)))
      (sourcePath source.graph (sourceAssignment source.packed) source.inputWords slot
        (snapshot.merkle slot) 32 (by omega)) path)

/-- A comparison result carrying exactly the native path from path_from_log. -/
structure CanonicalComparison (g : Graph K) (z : Nat → K) (w : Nat → Word K)
    (slot : Fin 2) (checked : MerkleChecked g w slot) (notes : List (List Nat)) where
  path : AuthenticationPath Digest
  nativeAt : PathAt (fromLog 32 0 notes) (natural z (position w slot))
    (openingAt notes (natural z (position w slot))) path
  comparison : Comparison (sourceLeaf z w slot)
    (openingAt notes (natural z (position w slot)))
    (PathCollision currentPathHash (sourceLeaf z w slot)
      (openingAt notes (natural z (position w slot)))
      (sourcePath g z w slot checked 32 (by omega)) path)

def canonical_snapshot_comparison (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (binding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (checked : MerkleChecked g w slot)
    (active : natural z (occupied w slot) = 1) (notes : List (List Nat))
    (nativeRoot : (fromLog 32 0 notes).root =
      List.ofFn fun lane : Fin 7 => (pub ⟨17 + lane.val, by omega⟩).val) :
    CanonicalComparison g z w slot checked notes := by
  have within := (occupied_merkle_root g layout z sem pub binding w slot checked).2.2.1
  let existence := path_from_log 32 0 (natural z (position w slot)) notes
    (Nat.zero_le _) (by simpa using within)
  let path := Classical.choose existence
  have witness := Classical.choose_spec existence
  have indices := path_at_index 32 0 notes witness
  have sameSides : pathSides (sourcePath g z w slot checked 32 (by omega)) = pathSides path := by
    apply side_index_injective
    · rw [source_path_length, indices.1]
    · rw [← source_position_is_path_index g layout z sem w slot checked]
      simpa using indices.2.symm
  have sourceOpens := occupied_source_opens g layout z sem pub binding w slot checked active
  have nativeOpens := path_at_opens witness
  rw [nativeRoot] at nativeOpens
  refine ⟨path, witness, compare_paths currentPathHash _ _ _ _ sameSides ?_⟩
  exact sourceOpens.2.trans nativeOpens.2.symm

theorem canonical_source_native_raw_readback_or_collision (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (binding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (checked : MerkleChecked g w slot)
    (active : natural z (occupied w slot) = 1) (outputs : List Produced)
    (table : RawNoteTable outputs) (appendTrace : RawAppendTrace outputs) (stage : Nat)
    (earlier : ∀ parent ∈ outputs, parent.stage < stage)
    (nativeRoot : (fromLog 32 0 (outputs.map table.note)).root =
      List.ofFn fun lane : Fin 7 => (pub ⟨17 + lane.val, by omega⟩).val) :
    RawInputReadback outputs stage (natural z (position w slot))
      (natural z (noteWords w slot 0))
      (digestNaturals z (outputOwnerWords (noteWords w slot))) ∨
    ∃ path, PathAt (fromLog 32 0 (outputs.map table.note))
      (natural z (position w slot))
      (openingAt (outputs.map table.note) (natural z (position w slot))) path ∧
      Nonempty (PathCollision currentPathHash (sourceLeaf z w slot)
      (openingAt (outputs.map table.note) (natural z (position w slot)))
      (sourcePath g z w slot checked 32 (by omega)) path) := by
  classical
  obtain ⟨path, witness, comparison⟩ := canonical_snapshot_comparison g layout z sem pub
    binding w slot checked active (outputs.map table.note) nativeRoot
  cases comparison with
  | collision collision => exact Or.inr ⟨path, witness, ⟨collision⟩⟩
  | equal words =>
    left
    let index := natural z (position w slot)
    by_cases occupiedIndex : index < outputs.length
    · let parent := outputs[index]'occupiedIndex
      have member : parent ∈ outputs := List.getElem_mem occupiedIndex
      have lookup : openingAt (outputs.map table.note) index = table.note parent := by
        have bound : index < (outputs.map table.note).length := by
          simpa only [List.length_map] using occupiedIndex
        unfold openingAt
        rw [if_pos bound]
        exact (List.getD_eq_getElem (outputs.map table.note) emptyNote bound).trans
          (List.getElem_map table.note (h := bound))
      have equalWords : sourceLeaf z w slot = table.note parent := words.trans lookup
      have positionEq : parent.position = index := by
        have positions := congrArg (fun xs : List Nat => xs.getD index 0)
          (raw_append_positions appendTrace)
        simpa only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem,
          List.length_map, List.length_range, occupiedIndex, List.getElem_map, List.getElem_range,
          Option.getD_some, parent] using positions
      refine Or.inr ⟨parent, member, positionEq, earlier parent member, ?_, ?_⟩
      · exact (source_leaf_value z w slot).symm.trans
          ((congrArg payloadValue equalWords).trans (table.value parent member))
      · exact (source_leaf_owner z w slot).symm.trans
          ((congrArg payloadOwner equalWords).trans (table.owner parent member))
    · have default : openingAt (outputs.map table.note) index = emptyNote := by
        simp only [openingAt, List.length_map, if_neg occupiedIndex]
      exact Or.inl ((source_leaf_owner z w slot).symm.trans
        ((congrArg payloadOwner (words.trans default)).trans empty_note_owner))

theorem canonical_approval_snapshot_readback_or_collision (outputs : List Produced)
    (source : SatisfiedApproval)
    (snapshot : NativeSnapshot outputs source.val) :
    NativeReadback outputs source ∨ CanonicalSnapshotCollision outputs source.val snapshot 0 := by
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
    rcases canonical_source_native_raw_readback_or_collision data.graph data.layout z sem snapshot.«public»
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

theorem canonical_final_snapshot_readback_or_collision (outputs : List Produced)
    (final : SourceFinal) (valid : FinalValid final)
    (snapshot : NativeSnapshot outputs final.source) :
    FinalNativeReadback outputs final ∨ CanonicalSnapshotCollision outputs final.source snapshot 1 := by
  let source := final.source
  let z := sourceAssignment source.packed
  have sem := relation_derives_structural_semantics source.relation source.packed valid.1
    source.graph source.layout source.csr source.certificate
  have occupied := (final_source_facts final valid).2.1
  rcases canonical_source_native_raw_readback_or_collision source.graph source.layout z sem snapshot.«public»
    snapshot.publicBinding source.inputWords 1 (snapshot.merkle 1) occupied snapshot.anchorPrefix snapshot.table
    snapshot.prefixAppend source.stage snapshot.earlier snapshot.root with raw | collision
  · left
    rcases raw with empty | ⟨parent, member, _, earlier, value, owner⟩
    · exact Or.inl empty
    · exact Or.inr ⟨parent, snapshot.prefixBefore.subset member, earlier, value, owner⟩
  · exact Or.inr collision

def CanonicalCurrentNativeMerkleBad (outputs : List Produced) : Prop :=
  ∃ source : SatisfiedApproval, Produced.approval source ∈ outputs ∧
    ∃ «prefix» : List Produced, ∃ snapshot : NativeSnapshot «prefix» source.val,
      (∀ parent ∈ «prefix», parent ∈ outputs) ∧ CanonicalSnapshotCollision «prefix» source.val snapshot 0

theorem canonical_native_merkle_bad_mono (before after : List Produced)
    (included : ∀ parent ∈ before, parent ∈ after) (bad : CanonicalCurrentNativeMerkleBad before) :
    CanonicalCurrentNativeMerkleBad after := by
  rcases bad with ⟨source, present, «prefix», snapshot, members, collision⟩
  exact ⟨source, included _ present, «prefix», snapshot,
    fun parent member => included parent (members parent member), collision⟩

/-- This is the hard history join: readback failure becomes a concrete current
Merkle collision; otherwise the same native output stream becomes SourceTrace. -/
theorem canonical_native_trace_source_history_or_merkle_bad {outputs : List Produced}
    (trace : NativeSourceTrace outputs) : SourceTrace outputs ∨ CanonicalCurrentNativeMerkleBad outputs := by
  induction trace with
  | empty => exact Or.inl .empty
  | reward before output positive position ih =>
    rcases ih with source | bad
    · exact Or.inl (.reward source output positive position)
    · exact Or.inr (canonical_native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)
  | other before output position ih =>
    rcases ih with source | bad
    · exact Or.inl (.other source output position)
    · exact Or.inr (canonical_native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)
  | @approval «prefix» before source position snapshot ih =>
    rcases ih with history | bad
    · rcases canonical_approval_snapshot_readback_or_collision «prefix» source snapshot with readback | collision
      · exact Or.inl (.approval history source position readback)
      · exact Or.inr ⟨source, by simp, «prefix», snapshot,
          fun parent member => List.mem_append_left _ member, collision⟩
    · exact Or.inr (canonical_native_merkle_bad_mono _ _
        (fun parent member => List.mem_append_left _ member) bad)

/-- Complete G1 mathematical endpoint under the disclosed native append-word
interpretation. Neither G3 accepted witness nor desired history success is a
premise. Every unsuccessful good-arm join returns an actual primitive event. -/
theorem canonical_current_final_authorization_or_failure (outputs : List Produced)
    (trace : NativeSourceTrace outputs) (final : SourceFinal) (valid : FinalValid final)
    (snapshot : NativeSnapshot outputs final.source) :
    FinalAuthorized outputs final ∨ CurrentHistoryBad outputs ∨ FinalHistoryBad outputs final ∨
      CanonicalCurrentNativeMerkleBad outputs ∨ CanonicalSnapshotCollision outputs final.source snapshot 1 := by
  rcases canonical_native_trace_source_history_or_merkle_bad trace with history | failure
  · rcases canonical_final_snapshot_readback_or_collision outputs final valid snapshot with readback | collision
    · rcases current_relation_history_final_authorization outputs history final valid readback with
        authorized | historyBad | finalBad
      · exact Or.inl authorized
      · exact Or.inr (Or.inl historyBad)
      · exact Or.inr (Or.inr (Or.inl finalBad))
    · exact Or.inr (Or.inr (Or.inr (Or.inr collision)))
  · exact Or.inr (Or.inr (Or.inr (Or.inl failure)))

/-- Both sides retain canonical effective operands from the actual source
path and the actual chronological native PathAt witness. -/
theorem canonical_snapshot_collision_game (outputs : List Produced) (source : SourceApproval)
    (snapshot : NativeSnapshot outputs source) (slot : Fin 2)
    (bad : CanonicalSnapshotCollision outputs source snapshot slot) :
    ∃ output : GameOutput, GameWin output := by
  rcases bad with ⟨path, native, ⟨collision⟩⟩
  exact canonical_collision_game collision
    (effective_inputs_good _ _ (source_leaf_good _ _ _) (source_path_good _ _ _ _ _ _ _))
    (effective_inputs_good _ _
      (opening_at_good _ (raw_notes_good snapshot.anchorPrefix snapshot.table) _)
      (native_path_good native))

/-- Arbitrary source recipients have seven canonical field words. A SINGLE
key preimage is neither supplied nor inferred. -/
theorem produced_ordinary_good (parent : Produced) (recipient : Digest)
    (originEq : parent.origin = some (.ordinary recipient)) : GoodWords 7 recipient := by
  cases parent with
  | reward reward => cases originEq
  | approval source => cases originEq
  | other output =>
    have origin : output.origin = .ordinary recipient := Option.some.inj originEq
    unfold OtherOutput.origin at origin
    dsimp only at origin
    split at origin
    · exact (OwnerOrigin.ordinary.inj origin) ▸ digest_naturals_good
        (sourceAssignment output.source.packed) output.originData.recipient1
    · split at origin
      · cases origin
      · exact (OwnerOrigin.ordinary.inj origin) ▸ digest_naturals_good
          (sourceAssignment output.source.packed) output.originData.recipient0

theorem origin_failure_game (parent : Produced) (origin : OwnerOrigin)
    (input : AccumulatorOwnerInput) (originEq : parent.origin = some origin)
    (failure : AccumulatorOriginFailure origin input) :
    ∃ output : GameOutput, GameWin output := by
  cases origin with
  | ordinary recipient =>
    exact ⟨.ordinaryAccumulator ⟨recipient, produced_ordinary_good parent recipient originEq⟩
      input, failure⟩
  | value value => exact ⟨.valueAccumulator value input, failure⟩
  | accumulator prior => exact ⟨.accumulator prior input, failure⟩
  | htlc htlc => exact ⟨.accumulatorHtlc input htlc, failure⟩

theorem current_history_bad_game (outputs : List Produced) (bad : CurrentHistoryBad outputs) :
    ∃ output : GameOutput, GameWin output := by
  rcases bad with ⟨source, _, empty | ⟨parent, _, origin, originEq, failure⟩⟩
  · exact ⟨.knownSingleAccumulator (consumerInput source), empty.trans native_empty_owner_eq⟩
  · exact origin_failure_game parent origin (consumerInput source) originEq failure

theorem final_history_bad_game (outputs : List Produced) (final : SourceFinal)
    (bad : FinalHistoryBad outputs final) : ∃ output : GameOutput, GameWin output := by
  rcases bad with empty | ⟨parent, _, origin, originEq, failure⟩
  · exact ⟨.knownSingleAccumulator (finalInput final), empty.trans native_empty_owner_eq⟩
  · exact origin_failure_game parent origin (finalInput final) originEq failure

theorem canonical_native_merkle_bad_game (outputs : List Produced)
    (bad : CanonicalCurrentNativeMerkleBad outputs) :
    ∃ output : GameOutput, GameWin output := by
  rcases bad with ⟨source, _, «prefix», snapshot, _, collision⟩
  exact canonical_snapshot_collision_game «prefix» source.val snapshot 0 collision

/-- Coverage is derived from the G1 join. No caller inclusion, injectivity,
authorized history, key preimage or game probability premise appears here. -/
theorem canonical_current_final_failure_game (outputs : List Produced)
    (trace : NativeSourceTrace outputs) (final : SourceFinal) (valid : FinalValid final)
    (snapshot : NativeSnapshot outputs final.source) (failure : ¬ FinalAuthorized outputs final) :
    ∃ output : GameOutput, GameWin output := by
  rcases canonical_current_final_authorization_or_failure outputs trace final valid snapshot with
    authorized | history | finalBad | nativeBad | snapshotBad
  · exact False.elim (failure authorized)
  · exact current_history_bad_game outputs history
  · exact final_history_bad_game outputs final finalBad
  · exact canonical_native_merkle_bad_game outputs nativeBad
  · exact canonical_snapshot_collision_game outputs final.source snapshot 1 snapshotBad

/-- Data at one original outcome after source extraction/native interpretation.
F1 supplies the same source/native append relation, not an authorization or
failure-coverage assertion. No physical acceptance-to-witness theorem is
asserted by this G1-only adapter. -/
structure SourceOutcome where
  outputs : List Produced
  trace : NativeSourceTrace outputs
  final : SourceFinal
  valid : FinalValid final
  snapshot : NativeSnapshot outputs final.source

def SourceOutcome.unauthorized (outcome : SourceOutcome) : Prop :=
  ¬ FinalAuthorized outcome.outputs outcome.final

/-- A deterministic mathematical readout on the SAME source outcome. Choice
selects only a proved concrete typed game witness; no efficiency/cost claim
is made for this readout. Fresh advantages must refer to these current games. -/
def sourceGameReadout (outcome : SourceOutcome) : Option GameOutput :=
  if bad : outcome.unauthorized then
    some (Classical.choose (canonical_current_final_failure_game outcome.outputs outcome.trace
      outcome.final outcome.valid outcome.snapshot bad))
  else none

theorem source_game_readout_wins (outcome : SourceOutcome) (bad : outcome.unauthorized) :
    ∃ output, sourceGameReadout outcome = some output ∧ GameWin output := by
  let witness := canonical_current_final_failure_game outcome.outputs outcome.trace
    outcome.final outcome.valid outcome.snapshot bad
  refine ⟨Classical.choose witness, ?_, Classical.choose_spec witness⟩
  exact dif_pos bad

/-- Kinds 0..6 are NOTE18, COMPFF-Merkle, raw-recipient/accumulator,
value/accumulator, accumulator collision, accumulator/HTLC, and the actual
known SINGLE target. None is an old key-only, zero-target or raw-compressor
game under a new name. -/
def sourceGameEvent (kind : Fin 7) (outcome : SourceOutcome) : Prop :=
  ∃ output, sourceGameReadout outcome = some output ∧ output.kind = kind ∧ GameWin output

theorem source_game_coverage (outcome : SourceOutcome) (bad : outcome.unauthorized) :
    ∃ kind : Fin 7, sourceGameEvent kind outcome := by
  obtain ⟨output, readout, win⟩ := source_game_readout_wins outcome bad
  exact ⟨output.kind, output, readout, rfl, win⟩

namespace Union
export HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
  (eventProjection finiteNormSquared same_execution_event_union_bound)
end Union

/-- Exact generic PR205 same-state union applied to derived G1 coverage.
The supplied source-outcome family and amplitudes are unchanged; there is no
conditioning or independent sampling within this source-outcome theorem. -/
theorem same_execution_current_g1_failure_mass_le_game_sum
    {Basis : Type*} [Fintype Basis] (outcomes : Basis → SourceOutcome) (state : Basis → ℂ) :
    Union.finiteNormSquared
        (Union.eventProjection (fun basis => (outcomes basis).unauthorized) state) ≤
      ∑ kind : Fin 7, Union.finiteNormSquared
        (Union.eventProjection (fun basis => sourceGameEvent kind (outcomes basis)) state) := by
  have monotone : Union.finiteNormSquared
        (Union.eventProjection (fun basis => (outcomes basis).unauthorized) state) ≤
      Union.finiteNormSquared
        (Union.eventProjection (fun basis => ∃ kind, sourceGameEvent kind (outcomes basis)) state) := by
    unfold Union.finiteNormSquared Union.eventProjection
    apply Finset.sum_le_sum
    intro basis _
    by_cases bad : (outcomes basis).unauthorized
    · simp only [if_pos bad, if_pos (source_game_coverage (outcomes basis) bad)]
      exact le_rfl
    · simp only [if_neg bad, Complex.normSq_zero]
      exact Complex.normSq_nonneg _
  exact monotone.trans (Union.same_execution_event_union_bound
    (fun kind basis => sourceGameEvent kind (outcomes basis)) state)

/-- Conditional G7 composition component. Seven explicit fresh CURRENT
readout advantages are required. This theorem supplies neither those bounds
nor a numerical cryptographic security level, efficient extraction contract,
Rust equivalence or production authorization. -/
theorem same_execution_current_g1_failure_mass_le_current_advantages
    {Basis : Type*} [Fintype Basis] (outcomes : Basis → SourceOutcome) (state : Basis → ℂ)
    (advantages : Fin 7 → ℝ)
    (games : ∀ kind : Fin 7, Union.finiteNormSquared
      (Union.eventProjection (fun basis => sourceGameEvent kind (outcomes basis)) state) ≤
        advantages kind) :
    Union.finiteNormSquared
      (Union.eventProjection (fun basis => (outcomes basis).unauthorized) state) ≤
        ∑ kind : Fin 7, advantages kind :=
  (same_execution_current_g1_failure_mass_le_game_sum outcomes state).trans
    (Finset.sum_le_sum fun kind _ => games kind)

end Source
end
end HegemonCrypto.NativePrivateSpendCurrentG1CanonicalGameAdapter
