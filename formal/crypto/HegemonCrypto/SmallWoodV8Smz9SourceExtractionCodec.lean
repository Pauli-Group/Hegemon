import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument
import Mathlib.Data.List.OfFn
import Mathlib.Data.List.GetD

/-!
An explicit bounded-byte serialization of the actual source extraction trace.
No one-hot basis indexed by the range of all traces is used. Source input-byte
length is an explicit resource: the raw wrapper parser has no small upper bound.
The register-size result does not prove a polynomial-time reversible algorithm.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec

open HegemonCrypto.CanonicalBytes
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open scoped Classical

local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq

set_option maxRecDepth 5000
set_option maxHeartbeats 1000000

abbrev Trace := ExtractionTrace RawInput

/-- Unary length words are deliberately simple and injective, with linear
overhead. A zero continues the word and a one terminates it. -/
def encodeLength (length : Nat) : List Byte := List.replicate length 0 ++ [1]

def decodeLength : List Byte → Option (Nat × List Byte)
  | [] => none
  | byte :: rest =>
      if byte = 0 then do
        let (length, suffix) ← decodeLength rest
        some (length + 1, suffix)
      else if byte = 1 then some (0, rest) else none

theorem decode_length_encode (length : Nat) (suffix : List Byte) :
    decodeLength (encodeLength length ++ suffix) = some (length, suffix) := by
  induction length with
  | zero => simp [encodeLength, decodeLength]
  | succ length induction =>
      change ((decodeLength (encodeLength length ++ suffix)).bind
        fun pair => some (pair.1 + 1, pair.2)) = some (length + 1, suffix)
      rw [induction]
      rfl

theorem encode_length_size (length : Nat) : (encodeLength length).length = length + 1 := by
  simp [encodeLength]

def encodeBlob (bytes : List Byte) : List Byte := encodeLength bytes.length ++ bytes

def decodeBlob (input : List Byte) : Option (List Byte × List Byte) := do
  let (length, afterLength) ← decodeLength input
  readFixed length afterLength

theorem decode_blob_encode (bytes suffix : List Byte) :
    decodeBlob (encodeBlob bytes ++ suffix) = some (bytes, suffix) := by
  rw [encodeBlob, List.append_assoc]
  simp only [decodeBlob, decode_length_encode]
  exact readFixed_append rfl

theorem encode_blob_size (bytes : List Byte) : (encodeBlob bytes).length = 2 * bytes.length + 1 := by
  simp only [encodeBlob, List.length_append, encode_length_size]
  omega

def decodeMany {Value : Type*}
    (decode : List Byte → Option (Value × List Byte)) :
    Nat → List Byte → Option (List Value × List Byte)
  | 0, input => some ([], input)
  | count + 1, input => do
      let (value, afterValue) ← decode input
      let (values, suffix) ← decodeMany decode count afterValue
      some (value :: values, suffix)

theorem decode_many_encode {Value : Type*}
    (encode : Value → List Byte) (decode : List Byte → Option (Value × List Byte))
    (values : List Value) (suffix : List Byte)
    (roundtrip : ∀ value ∈ values, ∀ rest,
      decode (encode value ++ rest) = some (value, rest)) :
    decodeMany decode values.length ((values.map encode).flatten ++ suffix) =
      some (values, suffix) := by
  induction values with
  | nil => rfl
  | cons value values induction =>
      simp only [List.length_cons, List.map_cons, List.flatten_cons, List.append_assoc,
        decodeMany]
      rw [roundtrip value (by simp)]
      dsimp only [Bind.bind, Option.bind]
      rw [induction (by intro item member; exact roundtrip item (by simp [member]))]

/-- At zero fuel only the explicit budget marker fits. At positive fuel a
record keeps its exact raw bytes and at most two ordered children. -/
def Fits (inputBytes : Nat) : Nat → Trace → Prop
  | 0, trace => trace = .budget
  | _ + 1, .missing => True
  | _ + 1, .budget => True
  | fuel + 1, .record input children =>
      input.length ≤ inputBytes ∧ children.length ≤ 2 ∧
        ∀ child ∈ children, Fits inputBytes fuel child

def ForestFits (inputBytes fuel : Nat) (traces : List Trace) : Prop :=
  ∀ trace ∈ traces, Fits inputBytes fuel trace

/-- Tags zero/one distinguish missing/budget. A record uses tag two, a
length-delimited raw input, an exact child count, and the ordered child encodings. -/
def encodeTrace : Nat → Trace → List Byte
  | 0, _ => [1]
  | _ + 1, .missing => [0]
  | _ + 1, .budget => [1]
  | fuel + 1, .record input children =>
      2 :: (encodeBlob input ++ encodeLength children.length ++
        (children.map (encodeTrace fuel)).flatten)

def decodeTrace : Nat → List Byte → Option (Trace × List Byte)
  | 0, input => match input with
      | [] => none
      | byte :: suffix => if byte = 1 then some (.budget, suffix) else none
  | fuel + 1, input => match input with
      | [] => none
      | byte :: rest =>
          if byte = 0 then some (.missing, rest)
          else if byte = 1 then some (.budget, rest)
          else if byte = 2 then do
            let (rawInput, afterInput) ← decodeBlob rest
            let (childCount, afterCount) ← decodeLength afterInput
            let (children, suffix) ← decodeMany (decodeTrace fuel) childCount afterCount
            some (.record rawInput children, suffix)
          else none

def encodeForest (fuel : Nat) (traces : List Trace) : List Byte :=
  encodeLength traces.length ++ (traces.map (encodeTrace fuel)).flatten

def decodeForest (fuel : Nat) (input : List Byte) : Option (List Trace × List Byte) := do
  let (count, afterCount) ← decodeLength input
  decodeMany (decodeTrace fuel) count afterCount

theorem decode_trace_encode (inputBytes fuel : Nat) (trace : Trace)
    (fits : Fits inputBytes fuel trace) (suffix : List Byte) :
    decodeTrace fuel (encodeTrace fuel trace ++ suffix) = some (trace, suffix) := by
  induction fuel generalizing trace suffix with
  | zero =>
      have same : trace = .budget := fits
      subst trace
      simp [encodeTrace, decodeTrace]
  | succ fuel induction =>
      cases trace with
      | missing => simp [encodeTrace, decodeTrace]
      | budget => simp [encodeTrace, decodeTrace]
      | record input children =>
          have childFits := fits.2.2
          have childrenRoundtrip := decode_many_encode (encodeTrace fuel) (decodeTrace fuel)
            children suffix (by intro child member rest; exact induction child (childFits child member) rest)
          simp only [encodeTrace, List.cons_append, decodeTrace, List.append_assoc]
          simp only [show (2 : Byte) ≠ 0 by decide, show (2 : Byte) ≠ 1 by decide,
            if_false, if_true]
          rw [decode_blob_encode]
          dsimp only [Bind.bind, Option.bind]
          rw [decode_length_encode]
          dsimp only [Bind.bind, Option.bind]
          rw [childrenRoundtrip]

theorem decode_forest_encode (inputBytes fuel : Nat) (traces : List Trace)
    (fits : ForestFits inputBytes fuel traces) (suffix : List Byte) :
    decodeForest fuel (encodeForest fuel traces ++ suffix) = some (traces, suffix) := by
  rw [encodeForest, List.append_assoc]
  simp only [decodeForest, decode_length_encode]
  apply decode_many_encode
  intro trace member rest
  exact decode_trace_encode inputBytes fuel trace (fits trace member) rest

theorem encode_forest_injective (inputBytes fuel : Nat) (left right : List Trace)
    (leftFits : ForestFits inputBytes fuel left) (rightFits : ForestFits inputBytes fuel right)
    (same : encodeForest fuel left = encodeForest fuel right) : left = right := by
  have leftDecoded := decode_forest_encode inputBytes fuel left leftFits []
  have rightDecoded := decode_forest_encode inputBytes fuel right rightFits []
  simp only [List.append_nil] at leftDecoded rightDecoded
  rw [same, rightDecoded] at leftDecoded
  exact (congrArg Prod.fst (Option.some.inj leftDecoded)).symm

/-- Counts every literal node on a fitting trace; the zero-fuel fitting trace
is exactly one budget marker, never a silently truncated record. -/
def nodeCount : Nat → Trace → Nat
  | 0, _ => 1
  | _ + 1, .missing => 1
  | _ + 1, .budget => 1
  | fuel + 1, .record _ children => 1 + (children.map (nodeCount fuel)).sum

def payloadByteCount : Nat → Trace → Nat
  | 0, _ => 0
  | _ + 1, .missing => 0
  | _ + 1, .budget => 0
  | fuel + 1, .record input children =>
      input.length + (children.map (payloadByteCount fuel)).sum

def binaryNodeBudget : Nat → Nat
  | 0 => 1
  | fuel + 1 => 1 + 2 * binaryNodeBudget fuel

theorem binary_node_budget_positive (fuel : Nat) : 1 ≤ binaryNodeBudget fuel := by
  cases fuel <;> simp [binaryNodeBudget]

theorem binary_node_budget_closed (fuel : Nat) : binaryNodeBudget fuel + 1 = 2 ^ (fuel + 1) := by
  induction fuel with
  | zero => rfl
  | succ fuel induction =>
      rw [binaryNodeBudget, pow_succ]
      omega

theorem logarithmic_fuel_node_budget (domainLog : Nat) :
    binaryNodeBudget (domainLog + 3) + 1 = 16 * 2 ^ domainLog := by
  rw [binary_node_budget_closed, show domainLog + 3 + 1 = domainLog + 4 by omega, pow_add]
  norm_num
  omega

theorem sum_map_le_length_mul {Value : Type*} (values : List Value) (cost : Value → Nat)
    (bound : Nat) (bounded : ∀ value ∈ values, cost value ≤ bound) :
    (values.map cost).sum ≤ values.length * bound := by
  induction values with
  | nil => simp
  | cons value values induction =>
      have head := bounded value (by simp)
      have tail := induction (by intro item member; exact bounded item (by simp [member]))
      simp only [List.map_cons, List.sum_cons, List.length_cons, Nat.add_mul, Nat.one_mul]
      omega

theorem node_count_le (inputBytes fuel : Nat) (trace : Trace)
    (fits : Fits inputBytes fuel trace) : nodeCount fuel trace ≤ binaryNodeBudget fuel := by
  induction fuel generalizing trace with
  | zero => simp [nodeCount, binaryNodeBudget]
  | succ fuel induction =>
      cases trace with
      | missing => exact binary_node_budget_positive _
      | budget => exact binary_node_budget_positive _
      | record input children =>
          have total := sum_map_le_length_mul children (nodeCount fuel) (binaryNodeBudget fuel)
            (by intro child member; exact induction child (fits.2.2 child member))
          have arity := fits.2.1
          simp only [nodeCount, binaryNodeBudget]
          nlinarith

theorem payload_byte_count_le (inputBytes fuel : Nat) (trace : Trace)
    (fits : Fits inputBytes fuel trace) :
    payloadByteCount fuel trace ≤ inputBytes * binaryNodeBudget fuel := by
  induction fuel generalizing trace with
  | zero => simp [payloadByteCount]
  | succ fuel induction =>
      cases trace with
      | missing => simp [payloadByteCount]
      | budget => simp [payloadByteCount]
      | record input children =>
          have total := sum_map_le_length_mul children (payloadByteCount fuel)
            (inputBytes * binaryNodeBudget fuel)
            (by intro child member; exact induction child (fits.2.2 child member))
          have bytes := fits.1
          have arity := fits.2.1
          have boundedTotal := total.trans (Nat.mul_le_mul_right
            (inputBytes * binaryNodeBudget fuel) arity)
          simp only [payloadByteCount, binaryNodeBudget]
          nlinarith

theorem forest_node_payload_bounds (inputBytes fuel targetCount : Nat) (traces : List Trace)
    (fits : ForestFits inputBytes fuel traces) (count : traces.length ≤ targetCount) :
    (traces.map (nodeCount fuel)).sum ≤ targetCount * binaryNodeBudget fuel ∧
      (traces.map (payloadByteCount fuel)).sum ≤
        targetCount * inputBytes * binaryNodeBudget fuel := by
  constructor
  · have total := sum_map_le_length_mul traces (nodeCount fuel) (binaryNodeBudget fuel)
      (by intro trace member; exact node_count_le inputBytes fuel trace (fits trace member))
    nlinarith
  · have total := sum_map_le_length_mul traces (payloadByteCount fuel)
      (inputBytes * binaryNodeBudget fuel)
      (by intro trace member; exact payload_byte_count_le inputBytes fuel trace (fits trace member))
    exact total.trans (by simpa only [Nat.mul_assoc] using
      Nat.mul_le_mul_right (inputBytes * binaryNodeBudget fuel) count)

theorem encode_trace_size_le (inputBytes fuel : Nat) (trace : Trace)
    (fits : Fits inputBytes fuel trace) :
    (encodeTrace fuel trace).length ≤ (2 * inputBytes + 5) * binaryNodeBudget fuel := by
  induction fuel generalizing trace with
  | zero => simp [encodeTrace, binaryNodeBudget]
  | succ fuel induction =>
      have positive := binary_node_budget_positive fuel
      cases trace with
      | missing =>
          simp only [encodeTrace, List.length_cons, List.length_nil, binaryNodeBudget]
          nlinarith
      | budget =>
          simp only [encodeTrace, List.length_cons, List.length_nil, binaryNodeBudget]
          nlinarith
      | record input children =>
          have total := sum_map_le_length_mul children
            (fun child => (encodeTrace fuel child).length)
            ((2 * inputBytes + 5) * binaryNodeBudget fuel)
            (by intro child member; exact induction child (fits.2.2 child member))
          have bytes := fits.1
          have arity := fits.2.1
          have boundedTotal := total.trans (Nat.mul_le_mul_right
            ((2 * inputBytes + 5) * binaryNodeBudget fuel) arity)
          have flattened : (children.map (encodeTrace fuel)).flatten.length =
              (children.map fun child => (encodeTrace fuel child).length).sum := by
            simp only [List.length_flatten, List.map_map, Function.comp_def]
          simp only [encodeTrace, List.length_cons, List.length_append,
            encode_blob_size, encode_length_size, flattened, binaryNodeBudget]
          nlinarith

def forestByteBudget (inputBytes fuel targetCount : Nat) : Nat :=
  1 + targetCount * (1 + (2 * inputBytes + 5) * binaryNodeBudget fuel)

theorem encode_forest_size_le (inputBytes fuel targetCount : Nat) (traces : List Trace)
    (fits : ForestFits inputBytes fuel traces) (count : traces.length ≤ targetCount) :
    (encodeForest fuel traces).length ≤ forestByteBudget inputBytes fuel targetCount := by
  have total := sum_map_le_length_mul traces
    (fun trace => (encodeTrace fuel trace).length)
    ((2 * inputBytes + 5) * binaryNodeBudget fuel)
    (by intro trace member; exact encode_trace_size_le inputBytes fuel trace (fits trace member))
  have boundedTotal := total.trans (Nat.mul_le_mul_right
    ((2 * inputBytes + 5) * binaryNodeBudget fuel) count)
  have flattened : (traces.map (encodeTrace fuel)).flatten.length =
      (traces.map fun trace => (encodeTrace fuel trace).length).sum := by
    simp only [List.length_flatten, List.map_map, Function.comp_def]
  simp only [encodeForest, List.length_append, encode_length_size, flattened, forestByteBudget]
  nlinarith

/-- The actual grammar's child LIST, including duplicate edges, has arity at
most two. A Finset child-cardinality bound alone would not suffice here. -/
theorem source_next_list_arity (stage : SourceStage) (input : RawInput)
    (edges : List (SourceStage × RawDigest)) (decoded : sourceNext stage input = some edges) :
    edges.length ≤ 2 := by
  cases parsed : parseSource input with
  | none => simp [sourceNext, parsed] at decoded
  | some value =>
      simp only [sourceNext, parsed, Option.bind_some] at decoded
      cases stage with
      | tree depth =>
          cases depth <;> cases value <;> cases decoded <;> simp
      | decs =>
          cases value <;> cases decoded
          simp
      | piopGamma =>
          cases value <;> cases decoded
          simp

theorem source_extract_fits (records : Records RawInput RawDigest) (inputBytes fuel : Nat)
    (recordBytes : ∀ record ∈ records, record.1.length ≤ inputBytes)
    (stage : SourceStage) (target : RawDigest) :
    Fits inputBytes fuel (extract sourceNext records fuel stage target) := by
  induction fuel generalizing stage target with
  | zero => rfl
  | succ fuel induction =>
      simp only [extract]
      cases selected : selectedInput sourceNext records stage target with
      | none => trivial
      | some input =>
          cases decoded : sourceNext stage input with
          | none => simp only [decoded, Fits]
          | some edges =>
              simp only [decoded, Fits]
              refine ⟨recordBytes (input, target)
                (selected_input_recorded sourceNext records stage target input selected), ?_, ?_⟩
              · simpa only [List.length_map] using source_next_list_arity stage input edges decoded
              · intro child member
                obtain ⟨edge, _, rfl⟩ := List.mem_map.mp member
                exact induction edge.1 edge.2

theorem source_forest_fits (records : Records RawInput RawDigest) (inputBytes fuel : Nat)
    (recordBytes : ∀ record ∈ records, record.1.length ≤ inputBytes)
    (targets : List (SourceStage × RawDigest)) :
    ForestFits inputBytes fuel (extractTargets sourceNext records fuel targets) := by
  intro trace member
  obtain ⟨target, _, rfl⟩ := List.mem_map.mp member
  exact source_extract_fits records inputBytes fuel recordBytes target.1 target.2

theorem source_forest_byte_bound (records : Records RawInput RawDigest)
    (inputBytes fuel targetCount : Nat)
    (recordBytes : ∀ record ∈ records, record.1.length ≤ inputBytes)
    (targets : List (SourceStage × RawDigest)) (count : targets.length ≤ targetCount) :
    (encodeForest fuel (extractTargets sourceNext records fuel targets)).length ≤
      forestByteBudget inputBytes fuel targetCount := by
  apply encode_forest_size_le inputBytes fuel targetCount _
    (source_forest_fits records inputBytes fuel recordBytes targets)
  simpa only [extractTargets, List.length_map] using count

theorem actual_fuel_node_budgets : binaryNodeBudget 25 = 67108863 ∧
    binaryNodeBudget 26 = 134217727 := by decide

/-- For N=2^23 and the actual fuel26, register bytes are O(targetCount*N*inputBytes).
No bound polynomial in arbitrary, unconstrained fuel is asserted. -/
theorem actual_fuel_byte_budget (inputBytes targetCount : Nat) :
    forestByteBudget inputBytes 26 targetCount =
      1 + targetCount * (1 + (2 * inputBytes + 5) * (16 * 8388608 - 1)) := by
  rw [forestByteBudget, actual_fuel_node_budgets.2]

def padBytes (capacity : Nat) (bytes : List Byte) : List Byte :=
  bytes ++ List.replicate (capacity - bytes.length) 0

theorem pad_bytes_length (capacity : Nat) (bytes : List Byte) (bounded : bytes.length ≤ capacity) :
    (padBytes capacity bytes).length = capacity := by
  simp only [padBytes, List.length_append, List.length_replicate]
  omega

def byteRegister (capacity : Nat) (bytes : List Byte) : Fin capacity → Byte :=
  fun index => (padBytes capacity bytes).getD index.val 0

theorem byte_register_roundtrip (capacity : Nat) (bytes : List Byte)
    (bounded : bytes.length ≤ capacity) :
    List.ofFn (byteRegister capacity bytes) = padBytes capacity bytes := by
  apply List.ext_getElem
  · simp only [List.length_ofFn, pad_bytes_length capacity bytes bounded]
  · intro index leftBound rightBound
    simp only [List.getElem_ofFn, byteRegister]
    exact List.getD_eq_getElem _ _ rightBound

/-- Exactly eight XOR bits per serialized byte, independently of the number
of possible traces or databases. -/
abbrev BitRegister (capacity : Nat) := Fin capacity × Fin 8 → ZMod 2

theorem bit_register_coordinate_count (capacity : Nat) :
    Fintype.card (Fin capacity × Fin 8) = 8 * capacity := by
  simp [Nat.mul_comm]

def encodeRegister (fuel capacity : Nat) (traces : List Trace) : BitRegister capacity :=
  fun index => byteBits (byteRegister capacity (encodeForest fuel traces) index.1) index.2

def registerBytes (capacity : Nat) (register : BitRegister capacity) : List Byte :=
  List.ofFn fun index => byteBits.symm (fun bit => register (index, bit))

def decodeRegister (fuel capacity : Nat) (register : BitRegister capacity) : Option (List Trace) :=
  (decodeForest fuel (registerBytes capacity register)).map Prod.fst

theorem decode_register_encode (inputBytes fuel capacity : Nat) (traces : List Trace)
    (fits : ForestFits inputBytes fuel traces)
    (bounded : (encodeForest fuel traces).length ≤ capacity) :
    decodeRegister fuel capacity (encodeRegister fuel capacity traces) = some traces := by
  have bytes : registerBytes capacity (encodeRegister fuel capacity traces) =
      padBytes capacity (encodeForest fuel traces) := by
    simp only [registerBytes, encodeRegister, Equiv.symm_apply_apply]
    exact byte_register_roundtrip capacity _ bounded
  rw [decodeRegister, bytes]
  rw [padBytes, decode_forest_encode inputBytes fuel traces fits]
  rfl

def BoundedForest (inputBytes fuel targetCount : Nat) :=
  { traces : List Trace // ForestFits inputBytes fuel traces ∧ traces.length ≤ targetCount }

def boundedForestEmbedding (inputBytes fuel targetCount : Nat) :
    BoundedForest inputBytes fuel targetCount ↪
      BitRegister (forestByteBudget inputBytes fuel targetCount) where
  toFun traces := encodeRegister fuel _ traces.val
  inj' := by
    intro left right same
    change encodeRegister fuel _ left.val = encodeRegister fuel _ right.val at same
    apply Subtype.ext
    have leftDecoded := decode_register_encode inputBytes fuel _ left.val left.property.1
      (encode_forest_size_le inputBytes fuel targetCount _ left.property.1 left.property.2)
    have rightDecoded := decode_register_encode inputBytes fuel _ right.val right.property.1
      (encode_forest_size_le inputBytes fuel targetCount _ right.property.1 right.property.2)
    rw [same, rightDecoded] at leftDecoded
    exact (Option.some.inj leftDecoded).symm

/-- A reusable adapter for scalar or vector source-label ranges. Its only
premises are actual fitting/length facts, not existence of an unspecified encoding. -/
def rangeForestEmbedding {Index : Type*} (inputBytes fuel targetCount : Nat)
    (label : Index → List Trace)
    (fits : ∀ index, ForestFits inputBytes fuel (label index))
    (count : ∀ index, (label index).length ≤ targetCount) :
    Set.range label ↪ BitRegister (forestByteBudget inputBytes fuel targetCount) :=
  (⟨fun value => (⟨value.val, by
      obtain ⟨index, same⟩ := value.property
      rw [← same]
      exact ⟨fits index, count index⟩⟩ : BoundedForest inputBytes fuel targetCount),
    by
      intro left right same
      apply Subtype.ext
      exact congrArg (fun forest : BoundedForest inputBytes fuel targetCount => forest.val) same⟩ :
      Set.range label ↪ BoundedForest inputBytes fuel targetCount).trans
    (boundedForestEmbedding inputBytes fuel targetCount)

section ActualSourceLabels

variable {Key Output Target : Type*} [Fintype Key] [DecidableEq Key]
  [Fintype Output] [DecidableEq Output]

/-- A literal finite-universe maximum of raw key BYTE lengths. This is not an
ordinal code for keys, and computing this maximum efficiently is not claimed. -/
def keyByteBudget (keyBytes : Key → RawInput) : Nat :=
  Finset.univ.sup (fun key => (keyBytes key).length)

omit [DecidableEq Key] in
theorem key_bytes_le_budget (keyBytes : Key → RawInput) (key : Key) :
    (keyBytes key).length ≤ keyByteBudget keyBytes := by
  exact Finset.le_sup (f := fun selected => (keyBytes selected).length) (Finset.mem_univ key)

omit [DecidableEq Key] in
theorem raw_records_input_bytes (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (database : HegemonCrypto.FiniteOracleDatabase.Database Key Output) (inputBytes : Nat)
    (keyBound : ∀ key, (keyBytes key).length ≤ inputBytes) :
    ∀ record ∈ rawRecords keyBytes outputBytes database, record.1.length ≤ inputBytes := by
  intro record member
  obtain ⟨pair, _, same⟩ := Finset.mem_image.mp member
  rw [← same]
  exact keyBound pair.1

def actualSourceLabelEmbedding (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (inputBytes fuel targetCount : Nat) (targets : Target → List (SourceStage × RawDigest))
    (keyBound : ∀ key, (keyBytes key).length ≤ inputBytes)
    (targetBound : ∀ target, (targets target).length ≤ targetCount) :
    Set.range (fun pair : Target × HegemonCrypto.FiniteOracleDatabase.Database Key Output =>
      sourceLabel keyBytes outputBytes fuel (targets pair.1) pair.2) ↪
      BitRegister (forestByteBudget inputBytes fuel targetCount) :=
  rangeForestEmbedding inputBytes fuel targetCount _
    (fun pair => source_forest_fits _ inputBytes fuel
      (raw_records_input_bytes keyBytes outputBytes pair.2 inputBytes keyBound) (targets pair.1))
    (fun pair => by simpa only [sourceLabel, extractTargets, List.length_map] using targetBound pair.1)

/-- The raw-byte bound can be derived from the actual finite key universe; no
assumed finite-label or one-hot answer encoding is needed. -/
def finiteKeySourceLabelEmbedding (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (fuel targetCount : Nat) (targets : Target → List (SourceStage × RawDigest))
    (targetBound : ∀ target, (targets target).length ≤ targetCount) :
    Set.range (fun pair : Target × HegemonCrypto.FiniteOracleDatabase.Database Key Output =>
      sourceLabel keyBytes outputBytes fuel (targets pair.1) pair.2) ↪
      BitRegister (forestByteBudget (keyByteBudget keyBytes) fuel targetCount) :=
  actualSourceLabelEmbedding keyBytes outputBytes (keyByteBudget keyBytes) fuel targetCount targets
    (key_bytes_le_budget keyBytes) targetBound

end ActualSourceLabels

end HegemonCrypto.SmallWood.V8Smz9SourceExtractionCodec
