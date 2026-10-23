import Std
import Lean.Elab.Tactic.Omega

/-!
Literal byte-layout and raw-address partition for Native HTLC SMZC leaves.
This proves framing and address injectivity only. It makes no assertion about
SHA-512, QROM security, zero knowledge, Rust refinement, or release authority.
-/
namespace Hegemon.Crypto.NativeHtlcLeaf

set_option autoImplicit false
set_option maxRecDepth 4096
abbrev Byte := UInt8
abbrev Bytes (n : Nat) := Fin n → Byte

def concat {m n : Nat} (left : Bytes m) (right : Bytes n) : Bytes (m + n) :=
  fun i => if h : i.val < m then left ⟨i.val, h⟩
    else right ⟨i.val - m, by have bound := i.isLt; omega⟩

@[simp] theorem concat_left {m n : Nat} (left : Bytes m) (right : Bytes n)
    (i : Fin m) : concat left right (i.castAdd n) = left i := by
  simp only [concat, Fin.val_castAdd, dif_pos i.isLt]

@[simp] theorem concat_right {m n : Nat} (left : Bytes m) (right : Bytes n)
    (i : Fin n) : concat left right (i.natAdd m) = right i := by
  have no : ¬ m + i.val < m := by omega
  simp [concat, no]

theorem concat_to_list {m n : Nat} (left : Bytes m) (right : Bytes n) :
    List.ofFn (concat left right) = List.ofFn left ++ List.ofFn right := by
  rw [List.ofFn_add]
  congr 1
  · congr 1
    funext i
    simp [concat, i.isLt]
  · congr 1
    funext i
    exact concat_right left right i

theorem bytes_to_list_injective {n : Nat} {left right : Bytes n}
    (same : List.ofFn left = List.ofFn right) : left = right := by
  funext i
  have leftBound : i.val < (List.ofFn left).length := by rw [List.length_ofFn]; exact i.isLt
  have rightBound : i.val < (List.ofFn right).length := by rw [List.length_ofFn]; exact i.isLt
  have equal := congrArg (fun xs : List Byte => xs[i.val]?) same
  simpa [List.getElem?_ofFn, i.isLt] using equal

def profile : List Byte := "hegemon.smallwood.native-htlc.smzc.sha512.profile.v1".toUTF8.data.toList
def leafDomain : List Byte := "hegemon.smallwood.strict-zk.merkle-leaf.htlc.v1".toUTF8.data.toList

theorem literal_domain_lengths : profile.length = 52 ∧ leafDomain.length = 47 := by decide

def encodeLE (width value : Nat) : List Byte :=
  List.ofFn fun i : Fin width => UInt8.ofNat ((value / (256 ^ i.val)) % 256)

@[simp] theorem encodeLE_length (width value : Nat) :
    (encodeLE width value).length = width := List.length_ofFn

abbrev frameBytes : Nat := 123
abbrev fixedHeadBytes : Nat := 731
abbrev tapeOffset : Nat := 739
abbrev tapeBytes : Nat := 64
abbrev tailBytes : Nat := 1184
abbrev rawLeafBytes : Nat := 1987
abbrev leafPayloadWords : Nat := 232

abbrev Statement := Bytes 576
abbrev Salt := Bytes 32
abbrev IndexBytes := Bytes 8
abbrev Tape := Bytes tapeBytes
abbrev Payload := Bytes 1176
abbrev Head := Bytes fixedHeadBytes
abbrev Tail := Bytes tailBytes
abbrev Leaf := Bytes rawLeafBytes

theorem exact_leaf_layout :
    24 + 52 + 47 = frameBytes ∧
    frameBytes + 576 + 32 = fixedHeadBytes ∧
    fixedHeadBytes + 8 = tapeOffset ∧
    tapeOffset + tapeBytes + tailBytes = rawLeafBytes ∧
    576 + 32 + 8 + tapeBytes + 1176 = 8 * leafPayloadWords := by decide

def fixedHeadList (statement : Statement) (salt : Salt) : List Byte :=
  encodeLE 8 profile.length ++ profile ++
  encodeLE 8 leafDomain.length ++ leafDomain ++
  encodeLE 8 leafPayloadWords ++ List.ofFn statement ++ List.ofFn salt

theorem fixed_head_length (statement : Statement) (salt : Salt) :
    (fixedHeadList statement salt).length = fixedHeadBytes := by
  simp only [fixedHeadList, List.length_append, encodeLE_length, List.length_ofFn]
  have domains := literal_domain_lengths
  rw [domains.1, domains.2]

def fixedHead (statement : Statement) (salt : Salt) : Head :=
  fun i => (fixedHeadList statement salt)[i.val]'(by rw [fixed_head_length]; exact i.isLt)

def frameTail (payload : Payload) : Tail :=
  concat payload (fun _ : Fin 8 => 0)

def indexedLeaf (head : Head) (index : IndexBytes) (tape : Tape) (tail : Tail) : Leaf :=
  concat head (concat index (concat tape tail))

def indexProjection (leaf : Leaf) : IndexBytes :=
  fun i => leaf ⟨fixedHeadBytes + i.val, by have b := i.isLt; unfold fixedHeadBytes rawLeafBytes; omega⟩

def tapeProjection (leaf : Leaf) : Tape :=
  fun i => leaf ⟨tapeOffset + i.val, by have b := i.isLt; unfold tapeOffset rawLeafBytes tapeBytes at *; omega⟩

theorem indexed_leaf_index (head : Head) (index : IndexBytes)
    (tape : Tape) (tail : Tail) : indexProjection (indexedLeaf head index tape tail) = index := by
  funext i
  have position : (⟨fixedHeadBytes + i.val, by have b := i.isLt; unfold fixedHeadBytes rawLeafBytes; omega⟩ : Fin rawLeafBytes) =
      (i.castAdd (tapeBytes + tailBytes)).natAdd fixedHeadBytes := by
    apply Fin.ext
    rfl
  unfold indexProjection indexedLeaf
  rw [position, concat_right, concat_left]

theorem indexed_leaf_tape (head : Head) (index : IndexBytes)
    (tape : Tape) (tail : Tail) : tapeProjection (indexedLeaf head index tape tail) = tape := by
  funext i
  have position : (⟨tapeOffset + i.val, by have b := i.isLt; unfold tapeOffset rawLeafBytes tapeBytes at *; omega⟩ : Fin rawLeafBytes) =
      ((i.castAdd tailBytes).natAdd 8).natAdd fixedHeadBytes := by
    apply Fin.ext
    simp only [Fin.val_natAdd, Fin.val_castAdd]
    unfold tapeOffset fixedHeadBytes
    omega
  unfold tapeProjection indexedLeaf
  rw [position, concat_right, concat_right, concat_left]

theorem indexed_leaf_tape_injective (head : Head) (index : IndexBytes) (tail : Tail)
    {left right : Tape} (same : indexedLeaf head index left tail = indexedLeaf head index right tail) :
    left = right := by
  have projected := congrArg tapeProjection same
  simpa only [indexed_leaf_tape] using projected

def sourceLeaf (statement : Statement) (salt : Salt) (index : IndexBytes)
    (tape : Tape) (payload : Payload) : Leaf :=
  indexedLeaf (fixedHead statement salt) index tape (frameTail payload)

theorem source_leaf_tape_projection (statement : Statement) (salt : Salt)
    (index : IndexBytes) (tape : Tape) (payload : Payload) :
    tapeProjection (sourceLeaf statement salt index tape payload) = tape :=
  indexed_leaf_tape _ _ _ _

theorem source_leaf_raw_length (statement : Statement) (salt : Salt)
    (index : IndexBytes) (tape : Tape) (payload : Payload) :
    (List.ofFn (sourceLeaf statement salt index tape payload)).length = 1987 :=
  List.length_ofFn

/-- Every bounded nonleaf raw string explicitly excludes the current 1987-byte
leaf length. A historical 2511-byte exclusion is a different partition. -/
abbrev OtherRawInput (bound : Nat) :=
  { input : List Byte // input.length ≤ bound ∧ input.length ≠ rawLeafBytes }
abbrev FullRawInput (bound : Nat) := Leaf ⊕ OtherRawInput bound

def rawBytes {bound : Nat} : FullRawInput bound → List Byte
  | .inl leaf => List.ofFn leaf
  | .inr other => other.val

theorem raw_bytes_injective (bound : Nat) {left right : FullRawInput bound}
    (same : rawBytes left = rawBytes right) : left = right := by
  cases left with
  | inl left =>
    cases right with
    | inl right => exact congrArg Sum.inl (bytes_to_list_injective same)
    | inr right =>
      have lengths := congrArg List.length same
      have bad : right.val.length = rawLeafBytes := by simpa only [rawBytes, List.length_ofFn] using lengths.symm
      exact False.elim (right.property.2 bad)
  | inr left =>
    cases right with
    | inl right =>
      have lengths := congrArg List.length same
      have bad : left.val.length = rawLeafBytes := by simpa only [rawBytes, List.length_ofFn] using lengths
      exact False.elim (left.property.2 bad)
    | inr right => exact congrArg Sum.inr (Subtype.ext same)

theorem fixed_head_to_list (statement : Statement) (salt : Salt) :
    List.ofFn (fixedHead statement salt) = fixedHeadList statement salt := by
  apply List.ext_getElem
  · rw [List.length_ofFn, fixed_head_length]
  · intro i leftBound rightBound
    simp only [List.getElem_ofFn, fixedHead]

/-- Exact source SHA-512 frame, including little-endian length words and a zero
counter. The 1176-byte payload contains the committed/masking count words. -/
def sourceRawFrame (statement : Statement) (salt : Salt) (index : IndexBytes)
    (tape : Tape) (payload : Payload) : List Byte :=
  encodeLE 8 profile.length ++ profile ++
  encodeLE 8 leafDomain.length ++ leafDomain ++
  encodeLE 8 leafPayloadWords ++ List.ofFn statement ++ List.ofFn salt ++
  List.ofFn index ++ List.ofFn tape ++ List.ofFn payload ++ encodeLE 8 0

theorem zero_counter_bytes : (List.ofFn (fun _ : Fin 8 => (0 : Byte))) = encodeLE 8 0 := by
  congr 1
  funext i
  simp

theorem source_leaf_exact_frame (statement : Statement) (salt : Salt)
    (index : IndexBytes) (tape : Tape) (payload : Payload) :
    List.ofFn (sourceLeaf statement salt index tape payload) =
      sourceRawFrame statement salt index tape payload := by
  unfold sourceLeaf indexedLeaf
  rw [concat_to_list (fixedHead statement salt) (concat index (concat tape (frameTail payload)))]
  rw [concat_to_list index (concat tape (frameTail payload))]
  rw [concat_to_list tape (frameTail payload)]
  have tail : List.ofFn (frameTail payload) = List.ofFn payload ++ encodeLE 8 0 := by
    unfold frameTail
    rw [concat_to_list payload (fun _ : Fin 8 => 0), zero_counter_bytes]
  rw [tail, fixed_head_to_list]
  simp only [fixedHeadList, sourceRawFrame, List.append_assoc]

theorem source_frame_length (statement : Statement) (salt : Salt)
    (index : IndexBytes) (tape : Tape) (payload : Payload) :
    (sourceRawFrame statement salt index tape payload).length = rawLeafBytes := by
  rw [← source_leaf_exact_frame]
  exact List.length_ofFn

theorem indexed_leaf_index_and_tape_injective (head : Head) (tail : Tail)
    {leftIndex rightIndex : IndexBytes} {leftTape rightTape : Tape}
    (same : indexedLeaf head leftIndex leftTape tail =
      indexedLeaf head rightIndex rightTape tail) :
    leftIndex = rightIndex ∧ leftTape = rightTape := by
  constructor
  · have projected := congrArg indexProjection same
    simpa only [indexed_leaf_index] using projected
  · have projected := congrArg tapeProjection same
    simpa only [indexed_leaf_tape] using projected

/-- Lists at the exact leaf length reconstruct the complete finite input;
no padding, default bytes, or truncated coordinates are introduced. -/
def leafOfList (input : List Byte) (exactLength : input.length = rawLeafBytes) : Leaf :=
  fun i => input[i.val]'(by rw [exactLength]; exact i.isLt)

theorem leaf_of_list_preserves_bytes (input : List Byte)
    (exactLength : input.length = rawLeafBytes) :
    List.ofFn (leafOfList input exactLength) = input := by
  apply List.ext_getElem
  · rw [List.length_ofFn, exactLength]
  · intro i leftBound rightBound
    simp only [List.getElem_ofFn, leafOfList]

def classify (bound : Nat) (input : List Byte) (bounded : input.length ≤ bound) : FullRawInput bound :=
  if exactLength : input.length = rawLeafBytes then
    .inl (leafOfList input exactLength)
  else .inr ⟨input, bounded, exactLength⟩

theorem classify_preserves_bytes (bound : Nat) (input : List Byte)
    (bounded : input.length ≤ bound) : rawBytes (classify bound input bounded) = input := by
  by_cases exactLength : input.length = rawLeafBytes
  · simp only [classify, dif_pos exactLength, rawBytes, leaf_of_list_preserves_bytes]
  · simp only [classify, dif_neg exactLength, rawBytes]

abbrev HistoricalRp05OtherRawInput (bound : Nat) :=
  { input : List Byte // input.length ≤ bound ∧ input.length ≠ 2511 }

def historicalRp05PartitionRawBytes {bound : Nat} : Leaf ⊕ HistoricalRp05OtherRawInput bound → List Byte
  | .inl leaf => List.ofFn leaf
  | .inr other => other.val

/-- Reusing the historical 2511-byte complement duplicates each current 1987-byte
leaf under the opposite sum tag. This is a mathematical address alias, not a
SHA-512 collision and not a claimed implementation exploit. -/
theorem historical_rp05_complement_duplicates_current_leaf (bound : Nat)
    (largeEnough : rawLeafBytes ≤ bound) :
    ¬ (∀ {left right : Leaf ⊕ HistoricalRp05OtherRawInput bound},
      historicalRp05PartitionRawBytes left = historicalRp05PartitionRawBytes right → left = right) := by
  intro injective
  let leaf : Leaf := fun _ => 0
  let duplicate : HistoricalRp05OtherRawInput bound := ⟨List.ofFn leaf,
    by simpa only [List.length_ofFn] using largeEnough,
    by rw [List.length_ofFn]; decide⟩
  have same : historicalRp05PartitionRawBytes (bound := bound) (.inl leaf) =
      historicalRp05PartitionRawBytes (bound := bound) (.inr duplicate) := rfl
  have impossible := injective same
  cases impossible

/-- The concrete Rust u64 little-endian index coordinate; the finite bound prevents any
host usize truncation from entering this formal byte construction. -/
def encodedIndex (index : Fin (2 ^ 64)) : IndexBytes :=
  fun i => UInt8.ofNat ((index.val / (256 ^ i.val)) % 256)

theorem encoded_index_is_u64_le (index : Fin (2 ^ 64)) :
    List.ofFn (encodedIndex index) = encodeLE 8 index.val := rfl

theorem encoded_source_index_projection (statement : Statement) (salt : Salt)
    (index : Fin (2 ^ 64)) (tape : Tape) (payload : Payload) :
    indexProjection (sourceLeaf statement salt (encodedIndex index) tape payload) = encodedIndex index :=
  indexed_leaf_index _ _ _ _

theorem encoded_source_exact_frame (statement : Statement) (salt : Salt)
    (index : Fin (2 ^ 64)) (tape : Tape) (payload : Payload) :
    List.ofFn (sourceLeaf statement salt (encodedIndex index) tape payload) =
      encodeLE 8 profile.length ++ profile ++
      encodeLE 8 leafDomain.length ++ leafDomain ++
      encodeLE 8 leafPayloadWords ++ List.ofFn statement ++ List.ofFn salt ++
      encodeLE 8 index.val ++ List.ofFn tape ++ List.ofFn payload ++ encodeLE 8 0 := by
  rw [source_leaf_exact_frame]
  simp only [sourceRawFrame, encoded_index_is_u64_le]

theorem literal_length_words_are_u64_le :
    encodeLE 8 52 = [52,0,0,0,0,0,0,0] ∧
    encodeLE 8 47 = [47,0,0,0,0,0,0,0] ∧
    encodeLE 8 232 = [232,0,0,0,0,0,0,0] := by decide

end Hegemon.Crypto.NativeHtlcLeaf
