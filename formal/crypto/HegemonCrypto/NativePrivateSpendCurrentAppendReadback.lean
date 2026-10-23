import HegemonCrypto.NativePrivateSpendCurrentMerklePath
import HegemonCrypto.NativePrivateSpendCurrentChronologicalApprovalHistory
import SmzaRp05LedgerMerkleBinding

/-! Current NOTE/COMPFF append-snapshot comparison. The tree and canonical
path are constructed from the actual ordered output stream, including
value-zero outputs. The native boundary is raw output-word correspondence,
the historical snapshot root, and chronological append order. No lineage or
authorized bitmap is supplied. The source opening is derived from current
graph gates; a mismatch returns actual effective hash inputs. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentAppendReadback
open NativePrivateSpendCurrentMerklePath NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentChronologicalApprovalHistory NativePrivateSpendCurrentProtocolHistory
open NativePrivateSpendCurrentEvaluatorIdentity NativePrivateSpendCurrentSpongeEvaluatorIdentity
open NativePrivateSpendPackedLowering NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
open NativePrivateSpendSelectedNullifier NativePrivateSpendMerkleContinuation
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Native source coinbase helper: extension lanes 10..12 carry identity4..6,
authorization lanes14..17 carry identity0..3; every other word is zero. -/
def emptyNote : List Nat := List.ofFn fun word : Fin 18 =>
  if h : 10 ≤ word.val ∧ word.val < 13 then
    nativeEmptyIdentityWord ⟨word.val - 6, by omega⟩
  else if 14 ≤ word.val then
    nativeEmptyIdentityWord ⟨word.val - 14, by omega⟩
  else 0

def ownerIndex (lane : Fin 7) : Nat :=
  if lane.val < 4 then 14 + lane.val else 6 + lane.val

def payloadOwner (payload : List Nat) : Digest :=
  List.ofFn fun lane : Fin 7 => payload.getD (ownerIndex lane) 0

def payloadValue (payload : List Nat) : Nat := payload.getD 0 0

omit [Fact (Nat.Prime modulus)] in
theorem empty_note_owner : payloadOwner emptyNote = nativeEmptyOwner := by
  unfold payloadOwner nativeEmptyOwner
  apply congrArg List.ofFn
  funext lane
  fin_cases lane <;> simp [emptyNote, ownerIndex, List.getD_eq_getElem?_getD]

omit [Fact (Nat.Prime modulus)] in
theorem empty_note_value : payloadValue emptyNote = 0 := by
  simp [payloadValue, emptyNote, List.getD_eq_getElem?_getD]

omit [Fact (Nat.Prime modulus)] in
theorem source_leaf_value (z : Nat → K) (w : Nat → Word K) (slot : Fin 2) :
    payloadValue (sourceLeaf z w slot) = natural z (noteWords w slot 0) := by
  simp [payloadValue, sourceLeaf, decoded, natural,
    List.getD_eq_getElem?_getD]

omit [Fact (Nat.Prime modulus)] in
theorem source_leaf_owner (z : Nat → K) (w : Nat → Word K) (slot : Fin 2) :
    payloadOwner (sourceLeaf z w slot) =
      digestNaturals z (outputOwnerWords (noteWords w slot)) := by
  apply congrArg List.ofFn
  funext lane
  have bound : ownerIndex lane < 18 := by
    have laneBound := lane.isLt
    unfold ownerIndex
    split <;> omega
  have noteBound : ownerIndex lane < (List.ofFn (noteWords w slot)).length := by
    simpa only [List.length_ofFn] using bound
  have leafBound : ownerIndex lane < (sourceLeaf z w slot).length := by
    simpa only [sourceLeaf, decoded, List.length_map, List.length_ofFn] using bound
  have lookup : (sourceLeaf z w slot).getD (ownerIndex lane) 0 =
      (read z (noteWords w slot ⟨ownerIndex lane, bound⟩)).val :=
    (List.getD_eq_getElem (sourceLeaf z w slot) 0 leafBound).trans
      ((List.getElem_map (fun word : Word K => (read z word).val)
        (l := List.ofFn (noteWords w slot)) (h := leafBound)).trans
        (congrArg (fun word : Word K => (read z word).val)
          (List.getElem_ofFn (f := noteWords w slot) noteBound)))
  exact lookup

structure RawNoteTable (outputs : List Produced) where
  note : Produced → List Nat
  exactWords : ∀ output ∈ outputs, (note output).length = 18
  canonical : ∀ output ∈ outputs, ∀ word ∈ note output, word < modulus
  value : ∀ output ∈ outputs, payloadValue (note output) = output.value
  owner : ∀ output ∈ outputs, payloadOwner (note output) = output.owner

def openingAt (notes : List (List Nat)) (position : Nat) : List Nat :=
  if position < notes.length then notes.getD position emptyNote else emptyNote

inductive Tree where
  | leaf (position : Nat) (payload : List Nat)
  | node (left right : Tree)

def Tree.root : Tree → Digest
  | .leaf _ payload => currentPathHash (.leaf payload)
  | .node left right => currentPathHash (.node left.root right.root)

def fromLog : Nat → Nat → List (List Nat) → Tree
  | 0, base, notes => .leaf base (openingAt notes base)
  | depth + 1, base, notes =>
      .node (fromLog depth base notes) (fromLog depth (base + 2 ^ depth) notes)

inductive PathAt : Tree → Nat → List Nat → AuthenticationPath Digest → Prop where
  | leaf (position : Nat) (payload : List Nat) :
      PathAt (.leaf position payload) position payload []
  | left {left right : Tree} {position : Nat} {payload : List Nat}
      {path : AuthenticationPath Digest} (child : PathAt left position payload path) :
      PathAt (.node left right) position payload (⟨right.root, .left⟩ :: path)
  | right {left right : Tree} {position : Nat} {payload : List Nat}
      {path : AuthenticationPath Digest} (child : PathAt right position payload path) :
      PathAt (.node left right) position payload (⟨left.root, .right⟩ :: path)

omit [Fact (Nat.Prime modulus)] in
theorem path_at_opens {tree : Tree} {position : Nat} {payload : List Nat}
    {path : AuthenticationPath Digest} (witness : PathAt tree position payload path) :
    OpensAt currentPathHash tree.root (pathSides path) payload path := by
  induction witness with
  | leaf position payload => exact ⟨rfl, rfl⟩
  | left child ih =>
    refine ⟨rfl, ?_⟩
    simp only [rootFromPath, Tree.root, ih.2]
  | right child ih =>
    refine ⟨rfl, ?_⟩
    simp only [rootFromPath, Tree.root, ih.2]

omit [Fact (Nat.Prime modulus)] in
theorem path_from_log (depth base position : Nat) (notes : List (List Nat))
    (lower : base ≤ position) (upper : position < base + 2 ^ depth) :
    ∃ path, PathAt (fromLog depth base notes) position (openingAt notes position) path := by
  induction depth generalizing base with
  | zero =>
    have equal : position = base := by omega
    subst position
    exact ⟨[], .leaf base (openingAt notes base)⟩
  | succ depth ih =>
    have width : 2 ^ (depth + 1) = 2 ^ depth + 2 ^ depth := by
      simp [pow_succ, Nat.mul_two]
    by_cases left : position < base + 2 ^ depth
    · obtain ⟨path, child⟩ := ih base lower left
      exact ⟨⟨(fromLog depth (base + 2 ^ depth) notes).root, .left⟩ :: path, .left child⟩
    · have lowerRight : base + 2 ^ depth ≤ position := Nat.le_of_not_lt left
      have upperRight : position < base + 2 ^ depth + 2 ^ depth := by
        rw [width] at upper
        omega
      obtain ⟨path, child⟩ := ih (base + 2 ^ depth) lowerRight upperRight
      exact ⟨⟨(fromLog depth base notes).root, .right⟩ :: path, .right child⟩

omit [Fact (Nat.Prime modulus)] in
theorem side_index_bound (sides : List ChildSide) :
    sideIndex sides < 2 ^ sides.length := by
  induction sides with
  | nil => simp [sideIndex]
  | cons side tail ih =>
    cases side <;> simp only [sideIndex, List.length_cons, pow_succ]
    all_goals omega

omit [Fact (Nat.Prime modulus)] in
theorem side_index_injective {left right : List ChildSide}
    (lengths : left.length = right.length) (indices : sideIndex left = sideIndex right) :
    left = right := by
  induction left generalizing right with
  | nil => simpa using lengths.symm
  | cons head tail ih =>
    cases right with
    | nil => simp at lengths
    | cons other rest =>
      have tailLengths : tail.length = rest.length := by simpa using lengths
      have leftBound := side_index_bound tail
      have rightBound := side_index_bound rest
      cases head <;> cases other <;> simp only [sideIndex] at indices
      · exact congrArg (List.cons .left) (ih tailLengths indices)
      · rw [tailLengths] at leftBound
        omega
      · rw [tailLengths] at indices
        omega
      · have equal : sideIndex tail = sideIndex rest := by
          rw [tailLengths] at indices
          omega
        exact congrArg (List.cons .right) (ih tailLengths equal)

omit [Fact (Nat.Prime modulus)] in
theorem path_at_index (depth base : Nat) (notes : List (List Nat))
    {position : Nat} {payload : List Nat} {path : AuthenticationPath Digest}
    (witness : PathAt (fromLog depth base notes) position payload path) :
    (pathSides path).length = depth ∧ base + sideIndex (pathSides path) = position := by
  induction depth generalizing base position payload path with
  | zero =>
    cases witness
    simp [pathSides, sideIndex]
  | succ depth ih =>
    cases witness with
    | left child =>
      obtain ⟨length, index⟩ := ih base child
      simpa [pathSides, sideIndex, length] using And.intro (congrArg Nat.succ length) index
    | right child =>
      obtain ⟨length, index⟩ := ih (base + 2 ^ depth) child
      have pathLength := length
      simp only [pathSides, List.length_map] at pathLength
      constructor
      · simpa [pathSides] using congrArg Nat.succ length
      · simpa [pathSides, sideIndex, pathLength, Nat.add_assoc] using index

/-- The only native-root interpretation input is the concrete chronological
output table's current-hash snapshot root. A successful source path is not
postulated: it is derived above from the satisfying current graph. -/
def source_snapshot_words_or_collision (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (pub : Fin 77 → K)
    (binding : g.publicBindings = NativePrivateSpendCsrCertificate.public77 pub)
    (w : Nat → Word K) (slot : Fin 2) (checked : MerkleChecked g w slot)
    (active : natural z (occupied w slot) = 1) (notes : List (List Nat))
    (nativeRoot : (fromLog 32 0 notes).root =
      List.ofFn fun lane : Fin 7 => (pub ⟨17 + lane.val, by omega⟩).val) :
    Σ path, Comparison (sourceLeaf z w slot)
      (openingAt notes (natural z (position w slot)))
      (PathCollision currentPathHash (sourceLeaf z w slot)
        (openingAt notes (natural z (position w slot)))
        (sourcePath g z w slot checked 32 (by omega)) path) := by
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
  refine ⟨path, compare_paths currentPathHash _ _ _ _ sameSides ?_⟩
  exact sourceOpens.2.trans nativeOpens.2.symm

/-- Raw append metadata only. In particular this type has no satisfying
assignment, previous-note readback, accumulator or lineage premise. -/
inductive RawAppendTrace : List Produced → Prop where
  | empty : RawAppendTrace []
  | append {outputs} (before : RawAppendTrace outputs) (output : Produced)
      (position : output.position = outputs.length) : RawAppendTrace (outputs ++ [output])

theorem raw_append_positions {outputs : List Produced} (trace : RawAppendTrace outputs) :
    outputs.map Produced.position = List.range outputs.length := by
  induction trace with
  | empty => rfl
  | append before output position ih =>
    simp only [List.map_append, List.map_cons, List.map_nil, position, ih,
      List.length_append, List.length_cons, List.length_nil, List.range_succ]

def RawInputReadback (outputs : List Produced) (stage position value : Nat)
    (owner : Digest) : Prop :=
  owner = nativeEmptyOwner ∨ ∃ parent ∈ outputs,
    parent.position = position ∧ parent.stage < stage ∧
    value = parent.value ∧ owner = parent.owner

/-- From the same source position and current-hash native snapshot, obtain
the actual earlier output's raw fields or a default empty owner, or return
the concrete effective-input Merkle collision. No positive-input filter. -/
theorem source_native_raw_readback_or_collision (g : Graph K) (layout : Layout K)
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
    ∃ path, Nonempty (PathCollision currentPathHash (sourceLeaf z w slot)
      (openingAt (outputs.map table.note) (natural z (position w slot)))
      (sourcePath g z w slot checked 32 (by omega)) path) := by
  classical
  obtain ⟨path, comparison⟩ := source_snapshot_words_or_collision g layout z sem pub
    binding w slot checked active (outputs.map table.note) nativeRoot
  cases comparison with
  | collision witness => exact Or.inr ⟨path, ⟨witness⟩⟩
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

end
end HegemonCrypto.NativePrivateSpendCurrentAppendReadback
