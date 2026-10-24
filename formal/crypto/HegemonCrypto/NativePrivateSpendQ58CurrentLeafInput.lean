import HegemonCrypto.SmallWoodV8Smz9HonestFinalGame
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting

/-! The current SMZD leaf primitive input has 2054 bytes. Its 512-bit nonce
occupies bytes 806..869: 150 framing, 616 statement, 32 salt and 8 index bytes
precede it; 1184 payload/counter bytes follow. We instantiate the actual finite
byte geometry, not the legacy 1407-byte or RP05 2511-byte summand.

The semantic byte framing below is source-interpreted, as in PR205. This module
proves nonce mass and a collision-exact common physical address partition. It
does not prove complete public transcript simulation or OS RNG refinement. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLeafInput

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9RuntimeDistribution
open V8Smz9HonestFinalGame (RawTuple rawTupleBytes raw_tuple_bytes_injective)
open V8Smz9HonestWholeViewGames (InputSampler)
open V8Smz9MixedMaskCompiler
open scoped Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def leafBytes : Nat := 2054
def tapeOffset : Nat := 806
def tailBytes : Nat := 1184
abbrev LeafIndex := Fin 8388608
abbrev CurrentLeafInput := Fin leafBytes → HegemonCrypto.CanonicalBytes.Byte
abbrev CurrentLeafHead := Fin tapeOffset → HegemonCrypto.CanonicalBytes.Byte
abbrev CurrentLeafTail := Fin tailBytes → HegemonCrypto.CanonicalBytes.Byte
abbrev CurrentFixedHead := Fin 798 → HegemonCrypto.CanonicalBytes.Byte

theorem current_leaf_layout :
    8 + 70 + 8 + 56 + 8 + 77*8 + 4*8 + 8 = tapeOffset ∧
      tapeOffset + 64 + tailBytes = leafBytes ∧
      (1 + 140 + 1 + 5)*8 + 8 = tailBytes := by decide

def tapedLeaf (head : CurrentLeafHead) (tape : LeafTape)
    (tail : CurrentLeafTail) : CurrentLeafInput :=
  Fin.append head (Fin.append tape tail)

def tapeProjection (input : CurrentLeafInput) : LeafTape :=
  fun byte => input (Fin.natAdd tapeOffset (Fin.castAdd tailBytes byte))

theorem current_tape_projection (head : CurrentLeafHead) (tape : LeafTape)
    (tail : CurrentLeafTail) : tapeProjection (tapedLeaf head tape tail) = tape := by
  funext byte
  simp only [tapeProjection, tapedLeaf, Fin.append_right, Fin.append_left]

theorem taped_leaf_injective (head : CurrentLeafHead) (tail : CurrentLeafTail) :
    Function.Injective (fun tape => tapedLeaf head tape tail) := by
  intro left right same
  simpa only [current_tape_projection] using congrArg tapeProjection same

def indexBytes (index : LeafIndex) : Fin 8 → HegemonCrypto.CanonicalBytes.Byte := fun byte =>
  (encodeLE 8 index.val).get ⟨byte.val, by simpa only [encodeLE_length] using byte.isLt⟩

def indexedLeaf (head : CurrentFixedHead) (index : LeafIndex)
    (tape : LeafTape) (tail : CurrentLeafTail) : CurrentLeafInput :=
  Fin.append head (Fin.append (indexBytes index) (Fin.append tape tail))

theorem indexed_leaf_tape (head : CurrentFixedHead) (index : LeafIndex)
    (tape : LeafTape) (tail : CurrentLeafTail) :
    tapeProjection (indexedLeaf head index tape tail) = tape := by
  funext byte
  have position : Fin.natAdd tapeOffset (Fin.castAdd tailBytes byte) =
      Fin.natAdd 798 (Fin.natAdd 8 (Fin.castAdd tailBytes byte)) := by
    apply Fin.ext
    simp only [Fin.val_natAdd, Fin.val_castAdd, tapeOffset]
    omega
  unfold tapeProjection
  rw [position]
  simp only [indexedLeaf, Fin.append_right, Fin.append_left]

def indexProjection (input : CurrentLeafInput) : LeafIndex :=
  ⟨decodeLE (List.ofFn fun byte : Fin 8 =>
      input (Fin.natAdd 798 (Fin.castAdd 1248 byte))) % 8388608,
    Nat.mod_lt _ (by norm_num)⟩

theorem indexed_leaf_index (head : CurrentFixedHead) (index : LeafIndex)
    (tape : LeafTape) (tail : CurrentLeafTail) :
    indexProjection (indexedLeaf head index tape tail) = index := by
  apply Fin.ext
  have bytes : List.ofFn (indexBytes index) = encodeLE 8 index.val := by
    apply List.ext_get
    · simp only [List.length_ofFn, encodeLE_length]
    · intro n leftBound rightBound
      simp only [List.get_ofFn, indexBytes]
      rfl
  change decodeLE (List.ofFn fun byte : Fin 8 =>
    indexedLeaf head index tape tail
      (Fin.natAdd 798 (Fin.castAdd (64 + tailBytes) byte))) % 8388608 = index.val
  simp only [indexedLeaf, Fin.append_right, Fin.append_left]
  rw [bytes, decodeLE_encodeLE]
  have fits : index.val < 256 ^ 8 := by
    have bound := index.isLt
    change index.val < 8388608 at bound
    omega
  rw [Nat.mod_eq_of_lt fits, Nat.mod_eq_of_lt index.isLt]

def currentProfile : List HegemonCrypto.CanonicalBytes.Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,110,97,116,105,118,101,45,112,114,105,118,97,116,101,45,115,112,101,110,100,46,115,109,122,100,46,99,111,109,112,102,102,48,49,46,115,104,97,53,49,50,46,112,114,111,102,105,108,101,46,118,50]

def currentLeafRole : List HegemonCrypto.CanonicalBytes.Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,115,116,114,105,99,116,45,122,107,46,109,101,114,107,108,101,45,108,101,97,102,46,112,114,105,118,97,116,101,45,115,112,101,110,100,46,118,49]

/-- Current source framing before index and nonce. The statement is exactly
77 canonical field words (616 bytes); salt is four raw u64 words (32 bytes). -/
def fixedHeadBytes (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) : List HegemonCrypto.CanonicalBytes.Byte :=
  encodeLE 8 70 ++ currentProfile ++ encodeLE 8 56 ++ currentLeafRole ++
    encodeLE 8 237 ++ List.ofFn statement ++ List.ofFn salt

theorem fixed_head_length (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) :
    (fixedHeadBytes statement salt).length = 798 := by
  simp only [fixedHeadBytes, List.length_append, encodeLE_length, List.length_ofFn]
  decide

def fixedHead (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) : CurrentFixedHead :=
  fun byte => (fixedHeadBytes statement salt).get
    ⟨byte.val, by rw [fixed_head_length]; exact byte.isLt⟩

/-- The row/mask payload has 147 u64 words: count140, 140 rows, count5,
five masks. Counter zero occupies the last eight bytes. -/
def frameTail (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) : CurrentLeafTail :=
  Fin.append payload (fun _ : Fin 8 => 0)

def sourceLeafInput (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) : CurrentLeafInput :=
  indexedLeaf (fixedHead statement salt) index tape (frameTail payload)

theorem source_leaf_tape (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) :
    tapeProjection (sourceLeafInput statement salt payload index tape) = tape :=
  indexed_leaf_tape _ _ _ _

theorem source_leaf_index (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) :
    indexProjection (sourceLeafInput statement salt payload index tape) = index :=
  indexed_leaf_index _ _ _ _

theorem source_leaf_literal_bytes (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) :
    List.ofFn (sourceLeafInput statement salt payload index tape) =
      fixedHeadBytes statement salt ++ List.ofFn (indexBytes index) ++
        List.ofFn tape ++ List.ofFn payload ++ List.replicate 8 0 := by
  have head : List.ofFn (fixedHead statement salt) = fixedHeadBytes statement salt := by
    apply List.ext_getElem
    · simp only [List.length_ofFn, fixed_head_length]
    · intro byte leftBound rightBound
      simp only [List.getElem_ofFn, fixedHead, List.get_eq_getElem]
  change List.ofFn (n := 798 + (8 + (64 + 1184)))
      (Fin.append (fixedHead statement salt)
        (Fin.append (indexBytes index) (Fin.append tape
          (Fin.append payload (fun _ : Fin 8 => 0))))) = _
  simp only [List.ofFn_fin_append, head, List.ofFn_const, List.append_assoc]

/-- A shared physical byte oracle. The nonleaf complement excludes exactly
2054 bytes, including malformed and historical requests of that length. -/
abbrev CurrentOtherRawInput (bound : Nat) :=
  { input : RawTuple bound // input.1.val ≠ leafBytes }
abbrev CurrentFullRawInput (bound : Nat) := CurrentLeafInput ⊕ CurrentOtherRawInput bound

def rawBytes {bound : Nat} : CurrentFullRawInput bound → List HegemonCrypto.CanonicalBytes.Byte
  | .inl leaf => List.ofFn leaf
  | .inr other => rawTupleBytes other.val

theorem raw_bytes_injective (bound : Nat) : Function.Injective (@rawBytes bound) := by
  intro left right same
  cases left with
  | inl left =>
      cases right with
      | inl right =>
          exact congrArg Sum.inl (List.ofFn_injective same)
      | inr right =>
          have lengths := congrArg List.length same
          have bad : right.val.1.val = leafBytes := by
            simpa only [rawBytes, rawTupleBytes, List.length_ofFn] using lengths.symm
          exact False.elim (right.property bad)
  | inr left =>
      cases right with
      | inl right =>
          have lengths := congrArg List.length same
          have bad : left.val.1.val = leafBytes := by
            simpa only [rawBytes, rawTupleBytes, List.length_ofFn] using lengths
          exact False.elim (left.property bad)
      | inr right =>
          exact congrArg Sum.inr (Subtype.ext (raw_tuple_bytes_injective bound same))

/-- Classification is by byte length, never by an assumed independent role. -/
def classify {bound : Nat} (input : RawTuple bound) : CurrentFullRawInput bound :=
  if same : input.1.val = leafBytes then
    .inl (fun index => input.2 ⟨index.val, by rw [same]; exact index.isLt⟩)
  else .inr ⟨input, same⟩

theorem classify_preserves_bytes {bound : Nat} (input : RawTuple bound) :
    rawBytes (classify input) = rawTupleBytes input := by
  rcases input with ⟨⟨size, bounded⟩, bytes⟩
  by_cases same : size = leafBytes
  · subst size
    simp [classify, rawBytes, rawTupleBytes]
  · simp [classify, rawBytes, rawTupleBytes, same]

def leafSampler (bound : Nat) (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) : InputSampler (CurrentFullRawInput bound) where
  Coins := LeafTape
  finite := inferInstance
  inhabited := inferInstance
  input := fun tape => Sum.inl (sourceLeafInput statement salt payload index tape)

theorem leaf_sampler_exact_mass (bound : Nat) (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) :
    pmfMap (uniformFintypePMF (leafSampler bound statement salt payload index).Coins)
      (leafSampler bound statement salt payload index).input
      ((leafSampler bound statement salt payload index).input tape) = (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  change pmfMap (uniformFintypePMF LeafTape)
      (fun coin => (Sum.inl (sourceLeafInput statement salt payload index coin) :
        CurrentFullRawInput bound))
      (Sum.inl (sourceLeafInput statement salt payload index tape)) = _
  rw [pmfMap_apply]
  simp only [uniformFintypePMF_apply, tsum_fintype]
  rw [Finset.sum_eq_single_of_mem tape (Finset.mem_univ tape)]
  · simp only [ite_true, leaf_tape_cardinality, Nat.cast_pow, Nat.cast_ofNat]
  · intro other _ different
    rw [if_neg]
    intro same
    have leafSame : sourceLeafInput statement salt payload index tape =
        sourceLeafInput statement salt payload index other := Sum.inl.inj same
    have tapeSame : tape = other := by
      simpa only [source_leaf_tape] using congrArg tapeProjection leafSame
    exact different tapeSame.symm

theorem leaf_sampler_mass (bound : Nat) (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex)
    (input : CurrentFullRawInput bound) :
    pmfMap (uniformFintypePMF (leafSampler bound statement salt payload index).Coins)
      (leafSampler bound statement salt payload index).input input ≤ (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  by_cases present : ∃ tape, input = (leafSampler bound statement salt payload index).input tape
  · obtain ⟨tape, rfl⟩ := present
    exact (leaf_sampler_exact_mass bound statement salt payload index tape).le
  · rw [pmfMap_apply]
    have outside : ∀ tape, input ≠ (leafSampler bound statement salt payload index).input tape :=
      by simpa using present
    simp only [if_neg (outside _), tsum_zero]
    exact bot_le

variable {Work : Type} [Fintype Work]

/-- Current fresh-leaf instruction. Payload/statement/salt may depend on
preceding history; the 64-byte tape is sampled inside this instruction. -/
def currentLeaf (bound : Nat) (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex)
    (next : LeafTape → DigestRegister → MixedProgram (CurrentFullRawInput bound) Work) :
    MixedProgram (CurrentFullRawInput bound) Work :=
  .freshInput (leafSampler bound statement salt payload index) next

theorem current_leaf_preserves_mass (bound : Nat) (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (payload : Fin 1176 → HegemonCrypto.CanonicalBytes.Byte) (index : LeafIndex)
    (next : LeafTape → DigestRegister → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ tape output, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tape output)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (currentLeaf bound statement salt payload index next) :=
  ⟨leaf_sampler_mass bound statement salt payload index, remaining⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLeafInput
