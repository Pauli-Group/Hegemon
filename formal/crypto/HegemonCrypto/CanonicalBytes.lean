import Mathlib.Data.List.Basic

namespace HegemonCrypto
namespace CanonicalBytes

abbrev Byte := Fin 256

def decodeLE : List Byte -> Nat
  | [] => 0
  | byte :: rest => byte.val + 256 * decodeLE rest

def readFixed (count : Nat) (input : List Byte) : Option (List Byte × List Byte) :=
  if count <= input.length then
    some (input.take count, input.drop count)
  else
    none

@[simp] theorem readFixed_append
    {count : Nat}
    {pre suffix : List Byte}
    (length_eq : pre.length = count) :
    readFixed count (pre ++ suffix) = some (pre, suffix) := by
  simp [readFixed, length_eq]

theorem readFixed_sound
    {count : Nat}
    {input pre suffix : List Byte}
    (decoded : readFixed count input = some (pre, suffix)) :
    pre.length = count ∧ input = pre ++ suffix := by
  simp only [readFixed] at decoded
  split at decoded
  · cases decoded
    constructor
    · simp_all
    · exact (List.take_append_drop count input).symm
  · contradiction

theorem readFixed_exact
    {count : Nat}
    {input pre suffix : List Byte}
    (decoded : readFixed count input = some (pre, suffix)) :
    input = pre ++ suffix :=
  (readFixed_sound decoded).2

def readByte (input : List Byte) : Option (Byte × List Byte) :=
  match input with
  | [] => none
  | byte :: rest => some (byte, rest)

theorem readByte_cons (byte : Byte) (rest : List Byte) :
    readByte (byte :: rest) = some (byte, rest) := by
  rfl

theorem readByte_sound
    {input : List Byte} {byte : Byte} {rest : List Byte}
    (decoded : readByte input = some (byte, rest)) :
    input = byte :: rest := by
  cases input with
  | nil => simp [readByte] at decoded
  | cons head tail =>
      simp only [readByte, Option.some.injEq, Prod.mk.injEq] at decoded
      exact congrArg₂ List.cons decoded.1 decoded.2

def encodeLE (width value : Nat) : List Byte :=
  (List.range width).map fun index =>
    ⟨(value / 256 ^ index) % 256, Nat.mod_lt _ (by decide)⟩

theorem encodeLE_length (width value : Nat) :
    (encodeLE width value).length = width := by
  simp [encodeLE]

def byteListValues (bytes : List Byte) : List Nat :=
  bytes.map Fin.val

structure PrefixCodec (Value : Type) where
  encode : Value -> List Byte
  decode : List Byte -> Option (Value × List Byte)
  canonical : Value -> Prop
  decode_encode : ∀ value suffix,
    canonical value -> decode (encode value ++ suffix) = some (value, suffix)
  decode_sound : ∀ {input value suffix},
    decode input = some (value, suffix) ->
      canonical value ∧ input = encode value ++ suffix

namespace PrefixCodec

variable {α β : Type}

def fixed (count : Nat) : PrefixCodec (List Byte) where
  encode := id
  decode := readFixed count
  canonical := fun bytes => bytes.length = count
  decode_encode := by
    intro value suffix canonical
    exact readFixed_append canonical
  decode_sound := by
    intro input value suffix decoded
    exact readFixed_sound decoded

def pair (left : PrefixCodec α) (right : PrefixCodec β) :
    PrefixCodec (α × β) where
  encode := fun value => left.encode value.1 ++ right.encode value.2
  decode := fun input => do
    let (leftValue, afterLeft) ← left.decode input
    let (rightValue, suffix) ← right.decode afterLeft
    some ((leftValue, rightValue), suffix)
  canonical := fun value => left.canonical value.1 ∧ right.canonical value.2
  decode_encode := by
    intro value suffix canonical
    rw [List.append_assoc]
    rw [left.decode_encode value.1 (right.encode value.2 ++ suffix) canonical.1]
    simp [right.decode_encode value.2 suffix canonical.2]
  decode_sound := by
    intro input value suffix decoded
    cases leftResult : left.decode input with
    | none => simp [leftResult] at decoded
    | some leftPair =>
        rcases leftPair with ⟨leftValue, afterLeft⟩
        cases rightResult : right.decode afterLeft with
        | none => simp [leftResult, rightResult] at decoded
        | some rightPair =>
            rcases rightPair with ⟨rightValue, finalSuffix⟩
            simp [leftResult, rightResult] at decoded
            rcases decoded with ⟨value_eq, suffix_eq⟩
            subst value
            subst suffix
            rcases left.decode_sound leftResult with ⟨leftCanonical, input_eq⟩
            rcases right.decode_sound rightResult with
              ⟨rightCanonical, after_left_eq⟩
            constructor
            · exact ⟨leftCanonical, rightCanonical⟩
            · rw [input_eq, after_left_eq, List.append_assoc]

def xmap
    (codec : PrefixCodec α)
    (toValue : α -> β)
    (fromValue : β -> α)
    (leftInverse : ∀ value, fromValue (toValue value) = value)
    (rightInverse : ∀ value, toValue (fromValue value) = value) :
    PrefixCodec β where
  encode := fun value => codec.encode (fromValue value)
  decode := fun input => do
    let (value, suffix) ← codec.decode input
    some (toValue value, suffix)
  canonical := fun value => codec.canonical (fromValue value)
  decode_encode := by
    intro value suffix canonical
    rw [codec.decode_encode (fromValue value) suffix canonical]
    simp [rightInverse]
  decode_sound := by
    intro input value suffix decoded
    cases rawResult : codec.decode input with
    | none => simp [rawResult] at decoded
    | some rawPair =>
        rcases rawPair with ⟨rawValue, finalSuffix⟩
        simp [rawResult] at decoded
        rcases decoded with ⟨value_eq, suffix_eq⟩
        subst value
        subst suffix
        rcases codec.decode_sound rawResult with ⟨canonical, input_eq⟩
        constructor
        · simpa [leftInverse] using canonical
        · simpa [leftInverse] using input_eq

def refine
    (codec : PrefixCodec α)
    (predicate : α -> Prop)
    [DecidablePred predicate] : PrefixCodec α where
  encode := codec.encode
  decode := fun input => do
    let (value, suffix) ← codec.decode input
    if predicate value then some (value, suffix) else none
  canonical := fun value => codec.canonical value ∧ predicate value
  decode_encode := by
    intro value suffix canonical
    rw [codec.decode_encode value suffix canonical.1]
    simp [canonical.2]
  decode_sound := by
    intro input value suffix decoded
    cases codecResult : codec.decode input with
    | none => simp [codecResult] at decoded
    | some codecPair =>
        rcases codecPair with ⟨decodedValue, finalSuffix⟩
        simp [codecResult] at decoded
        rcases decoded with ⟨predicate_holds, value_eq, suffix_eq⟩
        subst value
        subst suffix
        rcases codec.decode_sound codecResult with ⟨canonical, input_eq⟩
        exact ⟨⟨canonical, predicate_holds⟩, input_eq⟩

def option (codec : PrefixCodec α) : PrefixCodec (Option α) where
  encode := fun value =>
    match value with
    | none => [0]
    | some payload => [1] ++ codec.encode payload
  decode := fun input => do
    let (tag, afterTag) ← readByte input
    if tag = (0 : Byte) then
      some (none, afterTag)
    else if tag = (1 : Byte) then
      let (payload, suffix) ← codec.decode afterTag
      some (some payload, suffix)
    else
      none
  canonical := fun value =>
    match value with
    | none => True
    | some payload => codec.canonical payload
  decode_encode := by
    intro value suffix canonical
    cases value with
    | none => simp [readByte]
    | some payload =>
        simp [readByte]
        rw [codec.decode_encode payload suffix canonical]
        rfl
  decode_sound := by
    intro input value suffix decoded
    cases tagResult : readByte input with
    | none => simp [tagResult] at decoded
    | some tagPair =>
        rcases tagPair with ⟨tag, afterTag⟩
        by_cases tag_zero : tag = (0 : Byte)
        · simp [tagResult, tag_zero] at decoded
          rcases decoded with ⟨value_eq, suffix_eq⟩
          subst value
          subst suffix
          constructor
          · trivial
          · have input_eq := readByte_sound tagResult
            simpa [tag_zero] using input_eq
        · by_cases tag_one : tag = (1 : Byte)
          · simp [tagResult, tag_one] at decoded
            cases payloadResult : codec.decode afterTag with
            | none => simp [payloadResult] at decoded
            | some payloadPair =>
                rcases payloadPair with ⟨payload, finalSuffix⟩
                simp [payloadResult] at decoded
                rcases decoded with ⟨value_eq, suffix_eq⟩
                subst value
                subst suffix
                rcases codec.decode_sound payloadResult with
                  ⟨canonical, after_tag_eq⟩
                constructor
                · exact canonical
                · have input_eq := readByte_sound tagResult
                  rw [input_eq, tag_one, after_tag_eq]
                  rfl
          · simp [tagResult, tag_zero, tag_one] at decoded

end PrefixCodec

end CanonicalBytes
end HegemonCrypto
