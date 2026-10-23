import HegemonCrypto.NativePrivateSpendQ58CurrentFullStageEnvelope
import SmzaRp05ExecutableMerklePaths
import SmzaRecordedTracePath

/-! Current compact-Merkle source proposal. A successful ordinary 58-opening,
23-level program constructs all leaf paths in its own recorded execution.
The complete COMPFF01 frame and all 77 public-binding words are retained.
This module is not a full-verifier or PIOP acceptance theorem. Its prior-cut
endpoint reports a missing prior path or a raw-record collision explicitly.
No successful extraction, table agreement, or path certificate is an input.
SOURCE PROPOSAL ONLY: ordinary native kernel acceptance remains required.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCompactMerkle

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier
open SmzaRp05LeafNamespace (LegacyLeafCanonical)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath
open V8SmzaOracleParser (RawDigest Stage)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

abbrev RawInput := List Byte


/-- Public-context bytes, not a successful-proof or witness certificate. -/
structure Namespace where
  binding : List Byte
  bindingLength : binding.length = 616
  bindingCanonical : ∀ i : Fin 77, V8SmzaOracleParser.wordAt binding i.val <
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus

def Namespace.canonicalPreamble (ns : Namespace) (bytes : List Byte) : Bool :=
  decide (bytes = ns.binding)

theorem Namespace.canonicalLength (ns : Namespace) (bytes : List Byte)
    (checked : ns.canonicalPreamble bytes = true) : bytes.length = 616 := by
  have same : bytes = ns.binding := of_decide_eq_true checked
  simpa only [same] using ns.bindingLength

structure CurrentLeaf (ns : Namespace) (salt : List Byte) where
  preamble : List Byte
  legacyPayload : List Byte
  preambleCanonical : ns.canonicalPreamble preamble = true
  legacyCanonical : LegacyLeafCanonical salt legacyPayload

def CurrentLeaf.normalized {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) : V8SmzaOracleParser.Payload :=
  ⟨.leaf, leaf.preamble ++ leaf.legacyPayload⟩

theorem CurrentLeaf.preamble_length {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) : leaf.preamble.length = 616 :=
  ns.canonicalLength leaf.preamble leaf.preambleCanonical

theorem CurrentLeaf.legacy_payload_length {ns : Namespace} {salt : List Byte}
    (leaf : CurrentLeaf ns salt) : leaf.legacyPayload.length = 1280 :=
  leaf.legacyCanonical.2.1

def encodeLeaf (binding legacyPayload : List Byte) : RawInput :=
  NativePrivateSpendQ58CurrentFullStageEnvelope.frame (NativePrivateSpendQ58CurrentFullStageEnvelope.roleName .leaf) 237 (binding ++ legacyPayload)

def nodeInput (left right : RawDigest) : RawInput := NativePrivateSpendQ58CurrentFullStageEnvelope.nodeInput left right

def rootInput (salt binding : List Byte) (root : RawDigest) : RawInput :=
  NativePrivateSpendQ58CurrentFullStageEnvelope.rootInput ⟨salt, binding⟩ root

structure Slot where
  index : Nat
  hash : RawDigest
  remaining : List RawDigest

abbrev State := Fin 58 → Slot

def siblingIndex (index : Nat) : Nat :=
  if index % 2 = 0 then index + 1 else index - 1

def sibling? (state : State) (index : Nat) : Option RawDigest :=
  ((List.ofFn state).find? (fun slot => decide (slot.index = siblingIndex index))).map
    Slot.hash

def duplicateConsistent (state : State) : Bool := decide
  (∀ i j : Fin 58, (state i).index = (state j).index → (state i).hash = (state j).hash)

def selectedSibling (state : State) (j : Fin 58) :
    Option (RawDigest × List RawDigest) :=
  let own := state j
  match sibling? state own.index with
  | some sibling => some (sibling, own.remaining)
  | none => match own.remaining with
    | [] => none
    | sibling :: rest => some (sibling, rest)

/-- Consuming one absent sibling is ordinary verifier computation. -/
def nextSlot (state : State) (j : Fin 58) : Program Slot :=
  let own := state j
  match selectedSibling state j with
  | none => .done none
  | some (sibling, remaining) =>
      let input := if own.index % 2 = 0 then nodeInput own.hash sibling
        else nodeInput sibling own.hash
      (ask input).bind fun parent =>
        .done (some ⟨own.index / 2, parent, remaining⟩)

theorem next_slot_index (oracle : Oracle) (state : State) (j : Fin 58)
    (result : Slot) (succeeded : (nextSlot state j).eval oracle = some result) :
    result.index = (state j).index / 2 := by
  cases selected : selectedSibling state j with
  | none => simp [nextSlot, selected, Program.eval] at succeeded
  | some pair =>
      rcases pair with ⟨sibling, remaining⟩
      have same :
          (⟨(state j).index / 2,
            oracle (if (state j).index % 2 = 0 then nodeInput (state j).hash sibling
              else nodeInput sibling (state j).hash), remaining⟩ : Slot) = result :=
        Option.some.inj (by
          simpa [nextSlot, selected, ask, Program.bind, Program.eval] using succeeded)
      rw [← same]

/-- A node query's presence and returned label follow from execution.
The sibling is calculated by the verifier, not supplied as a path premise. -/
theorem next_slot_query_recorded (oracle : Oracle) (state : State) (j : Fin 58)
    (result : Slot) (succeeded : (nextSlot state j).eval oracle = some result) :
    ∃ sibling remaining,
      selectedSibling state j = some (sibling, remaining) ∧
      let input := if (state j).index % 2 = 0 then nodeInput (state j).hash sibling
        else nodeInput sibling (state j).hash
      result.hash = oracle input ∧
        ((nextSlot state j).record oracle).2 = [(input, result.hash)] := by
  cases selected : selectedSibling state j with
  | none => simp [nextSlot, selected, Program.eval] at succeeded
  | some pair =>
      rcases pair with ⟨sibling, remaining⟩
      refine ⟨sibling, remaining, rfl, ?_⟩
      have same :
          (⟨(state j).index / 2,
            oracle (if (state j).index % 2 = 0 then nodeInput (state j).hash sibling
              else nodeInput sibling (state j).hash), remaining⟩ : Slot) = result :=
        Option.some.inj (by
          simpa [nextSlot, selected, ask, Program.bind, Program.eval] using succeeded)
      rw [← same]
      exact ⟨rfl, by simp [nextSlot, selected, ask, Program.bind, Program.record]⟩

def level (state : State) : Program State :=
  if duplicateConsistent state then sequence 58 (nextSlot state) else .done none

def levels : Nat → State → Program State
  | 0, state => .done (some state)
  | depth + 1, state => (level state).bind (levels depth)

theorem level_index (oracle : Oracle) (state result : State)
    (succeeded : (level state).eval oracle = some result) (j : Fin 58) :
    (result j).index = (state j).index / 2 := by
  by_cases valid : duplicateConsistent state = true
  · have all : (sequence 58 (nextSlot state)).eval oracle = some result := by
      simpa [level, valid] using succeeded
    exact next_slot_index oracle state j (result j)
      (sequence_pointwise oracle 58 (nextSlot state) result all j)
  · simp [level, valid, Program.eval] at succeeded

/-- The source index recurrence is now derived from the executable program,
not assumed as a loop certificate. In particular this applies at depth 23. -/
theorem levels_index (oracle : Oracle) (depth : Nat) (state result : State)
    (succeeded : (levels depth state).eval oracle = some result) (j : Fin 58) :
    (result j).index = (state j).index / 2 ^ depth := by
  induction depth generalizing state with
  | zero =>
      have equal : state = result := Option.some.inj succeeded
      simp [← equal]
  | succ depth ih =>
      have composed : ((level state).eval oracle).bind (fun middle =>
          (levels depth middle).eval oracle) = some result := by
        simpa only [levels, Program.eval_bind] using succeeded
      cases stepped : (level state).eval oracle with
      | none => simp [stepped] at composed
      | some middle =>
          have later : (levels depth middle).eval oracle = some result := by
            simpa only [stepped, Option.bind_some] using composed
          rw [ih middle later, level_index oracle state middle stepped j]
          simp [Nat.div_div_eq_div_mul, pow_succ, Nat.mul_comm]

/-- Expected compact-path count, calculated before any leaf query. -/
def expectedLength (indices : Fin 58 → Nat) (j : Fin 58) (depth : Nat) : Nat :=
  ((List.range depth).filter fun d => !((List.ofFn indices).any fun index =>
    decide (index / 2 ^ d = siblingIndex (indices j / 2 ^ d)))).length

structure Input where
  salt : List Byte
  binding : List Byte
  indices : Fin 58 → Nat
  payloads : Fin 58 → List Byte
  paths : Fin 58 → List RawDigest
  pendingXofFailure : Bool

def shapeValid (ns : Namespace) (input : Input) : Bool :=
  ns.canonicalPreamble input.binding && decide
    (input.salt.length = 32 ∧
      (∀ j, input.indices j < 8388608) ∧
      (∀ i j : Fin 58, i.val < j.val → input.indices i < input.indices j) ∧
      (∀ j, (input.paths j).length = expectedLength input.indices j 23))

def initialSlot (ns : Namespace) (input : Input) (j : Fin 58) : Program Slot :=
  let raw := encodeLeaf input.binding (input.payloads j)
  if ns.canonicalPreamble input.binding = true then
    if LegacyLeafCanonical input.salt (input.payloads j) then
      if V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j then
        (ask raw).bind fun hash =>
          .done (some ⟨input.indices j, hash, input.paths j⟩)
      else .done none
    else .done none
  else .done none

theorem initial_slot_index (ns : Namespace) (oracle : Oracle) (input : Input)
    (j : Fin 58) (result : Slot)
    (succeeded : (initialSlot ns input j).eval oracle = some result) :
    result.index = input.indices j := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · have same :
            (⟨input.indices j, oracle (encodeLeaf input.binding (input.payloads j)),
              input.paths j⟩ : Slot) = result := Option.some.inj (by
                simpa [initialSlot, binding, payload, index, ask, Program.bind, Program.eval]
                  using succeeded)
        rw [← same]
      · simp [initialSlot, binding, payload, index, Program.eval] at succeeded
    · simp [initialSlot, binding, payload, Program.eval] at succeeded
  · simp [initialSlot, binding, Program.eval] at succeeded

def finalValid (state : State) : Bool := decide
  (∀ j : Fin 58, (state j).remaining = [] ∧ (state j).hash = (state 0).hash)

/-- Only ordinary path-exhaustion and common-root guards precede root hashing. -/
def finish (input : Input) (state : State) : Program RawDigest :=
  if finalValid state then ask (rootInput input.salt input.binding (state 0).hash)
  else .done none

def merkleProgram (ns : Namespace) (input : Input) : Program RawDigest :=
  if shapeValid ns input then
    (sequence 58 (initialSlot ns input)).bind fun initial =>
      (levels 23 initial).bind (finish input)
  else .done none

/-- Deferred field-XOF rejection is independent of the recorder. -/
def acceptedResult (ns : Namespace) (oracle : Oracle) (input : Input) : Option RawDigest :=
  if input.pendingXofFailure then none else (merkleProgram ns input).eval oracle

def accepts (ns : Namespace) (oracle : Oracle) (input : Input) : Bool :=
  (acceptedResult ns oracle input).isSome

def recordedAttempt (ns : Namespace) (oracle : Oracle) (input : Input) :
    Option RawDigest × Log :=
  let attempt := (merkleProgram ns input).record oracle
  (if input.pendingXofFailure then none else attempt.1, attempt.2)

theorem acceptance_independent_of_instrumentation
    (ns : Namespace) (oracle : Oracle) (input : Input) :
    (recordedAttempt ns oracle input).1 = acceptedResult ns oracle input := by
  simp only [recordedAttempt, acceptedResult, Program.record_result]

theorem accepted_pending_xof_is_false (ns : Namespace) (oracle : Oracle)
    (input : Input) (accepted : accepts ns oracle input = true) :
    input.pendingXofFailure = false := by
  cases pending : input.pendingXofFailure with
  | false => rfl
  | true => simp [accepts, acceptedResult, pending] at accepted

theorem recorded_attempt_call (ns : Namespace) (oracle : Oracle) (input : Input)
    (call : RawInput × RawDigest)
    (member : call ∈ (recordedAttempt ns oracle input).2) : call.2 = oracle call.1 :=
  Program.recorded_call oracle (merkleProgram ns input) call member

/-- This is the actual wrapper target equation, not root_digest = hash_mt. -/
theorem successful_finish (oracle : Oracle) (input : Input) (state : State)
    (target : RawDigest) (succeeded : (finish input state).eval oracle = some target) :
    (∀ j : Fin 58, (state j).remaining = [] ∧ (state j).hash = (state 0).hash) ∧
      target = oracle (rootInput input.salt input.binding (state 0).hash) := by
  by_cases valid : finalValid state = true
  · refine ⟨of_decide_eq_true valid, ?_⟩
    have same : oracle (rootInput input.salt input.binding (state 0).hash) = target :=
      Option.some.inj (by simpa [finish, valid, ask, Program.bind, Program.eval] using succeeded)
    exact same.symm
  · simp [finish, valid, Program.eval] at succeeded

/-- Eliminate successful execution itself; no supplied final-state or
common-root certificate is required. The target is the wrapper hash. -/
theorem accepted_has_executed_common_root (ns : Namespace) (oracle : Oracle)
    (input : Input) (target : RawDigest)
    (accepted : acceptedResult ns oracle input = some target) :
    input.pendingXofFailure = false ∧
      ∃ initial final : State,
        (sequence 58 (initialSlot ns input)).eval oracle = some initial ∧
        (levels 23 initial).eval oracle = some final ∧
        (∀ j : Fin 58, (final j).remaining = [] ∧ (final j).hash = (final 0).hash) ∧
        target = oracle (rootInput input.salt input.binding (final 0).hash) := by
  have pending : input.pendingXofFailure = false := by
    cases h : input.pendingXofFailure with
    | false => rfl
    | true => simp [acceptedResult, h] at accepted
  refine ⟨pending, ?_⟩
  have ran : (merkleProgram ns input).eval oracle = some target := by
    simpa [acceptedResult, pending] using accepted
  by_cases shape : shapeValid ns input = true
  · have composed :
        ((sequence 58 (initialSlot ns input)).eval oracle).bind (fun initial =>
          ((levels 23 initial).eval oracle).bind (fun final =>
            (finish input final).eval oracle)) = some target := by
      simpa [merkleProgram, shape, Program.eval_bind] using ran
    cases started : (sequence 58 (initialSlot ns input)).eval oracle with
    | none => simp [started] at composed
    | some initial =>
        cases reduced : (levels 23 initial).eval oracle with
        | none => simp [started, reduced] at composed
        | some final =>
            have finished : (finish input final).eval oracle = some target := by
              simpa only [started, reduced, Option.bind_some] using composed
            have facts := successful_finish oracle input final target finished
            exact ⟨initial, final, rfl, reduced, facts.1, facts.2⟩
  · simp [merkleProgram, shape, Program.eval] at ran

/-- The full 23-level index invariant and common-root check, obtained only
from a successful uninstrumented run. No loop certificate is an argument. -/
theorem accepted_final_indices_and_root (ns : Namespace) (oracle : Oracle)
    (input : Input) (target : RawDigest)
    (accepted : acceptedResult ns oracle input = some target) :
    ∃ final : State,
      (∀ j, (final j).index = input.indices j / 2 ^ 23) ∧
      (∀ j, (final j).remaining = [] ∧ (final j).hash = (final 0).hash) ∧
      target = oracle (rootInput input.salt input.binding (final 0).hash) := by
  obtain ⟨_, initial, final, started, reduced, complete, targetEq⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  refine ⟨final, ?_, complete, targetEq⟩
  intro j
  rw [levels_index oracle 23 initial final reduced j,
    initial_slot_index ns oracle input j (initial j)
      (sequence_pointwise oracle 58 (initialSlot ns input) initial started j)]

private def logRecords (log : Log) : RawRecords := log.toFinset

private theorem global_normalized_leaf_roundtrip (ns : Namespace)
    (salt : List Byte) (leaf : CurrentLeaf ns salt) :
    NativePrivateSpendQ58CurrentFullStageEnvelope.rawPayload
      (encodeLeaf leaf.preamble leaf.legacyPayload) = some leaf.normalized := by
  have length : (leaf.preamble ++ leaf.legacyPayload).length = 1896 := by
    rw [List.length_append, leaf.preamble_length, leaf.legacy_payload_length]
  exact NativePrivateSpendQ58CurrentFullStageEnvelope.raw_payload_frame .leaf 237
    (leaf.preamble ++ leaf.legacyPayload) (by decide) (by omega) length

private theorem recorded_path_mono
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (left right : RawRecords) (included : left ⊆ right)
    (stage : Stage) (target : RawDigest) (path : List Nat) (leaf : RawInput)
    (recorded : RecordedPath next left stage target path leaf) :
    RecordedPath next right stage target path leaf := by
  induction recorded with
  | here stage target input member valid =>
      exact RecordedPath.here stage target input (included member) valid
  | step stage target input edges index childStage childTarget rest leaf
      member parsed edge below ih =>
      exact RecordedPath.step stage target input edges index childStage childTarget
        rest leaf (included member) parsed edge ih

theorem node_parser_roundtrip (depth : Nat) (left right : RawDigest) :
    NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext (.tree (depth + 1))
      (nodeInput left right) = some [(.tree depth, left), (.tree depth, right)] :=
  NativePrivateSpendQ58CurrentFullStageEnvelope.node_constructor_edges depth left right

theorem root_parser_roundtrip (salt binding : List Byte) (root : RawDigest)
    (saltLength : salt.length = 32) (bindingLength : binding.length = 616) :
    NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext .root
      (rootInput salt binding root) = some [(.tree 23, root)] := by
  have parsed := NativePrivateSpendQ58CurrentFullStageEnvelope.raw_payload_frame .root 89
    (salt ++ List.ofFn root ++ binding) (by decide)
    (by simp [saltLength, bindingLength])
    (by simp [NativePrivateSpendQ58CurrentFullStageEnvelope.payloadBytes,
      saltLength, bindingLength])
  have rootRead := digest_at_prefix_ofFn salt binding root
  rw [saltLength] at rootRead
  simp only [NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext,
    rootInput, NativePrivateSpendQ58CurrentFullStageEnvelope.rootInput,
    parsed, Option.bind_some, NativePrivateSpendQ58CurrentFullStageEnvelope.payloadNext]
  rw [List.append_assoc, rootRead]

theorem logRecords_mono (left right : Log) (included : left ⊆ right) :
    logRecords left ⊆ logRecords right := by
  intro call member
  exact List.mem_toFinset.mpr (included (List.mem_toFinset.mp member))

theorem initial_slot_recorded_path (ns : Namespace) (oracle : Oracle)
    (input : Input) (j : Fin 58) (result : Slot)
    (succeeded : (initialSlot ns input j).eval oracle = some result) :
    RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
      (logRecords ((initialSlot ns input j).record oracle).2)
      (.tree 0) result.hash [] (encodeLeaf input.binding (input.payloads j)) := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · have same :
            (⟨input.indices j, oracle (encodeLeaf input.binding (input.payloads j)),
              input.paths j⟩ : Slot) = result := Option.some.inj (by
                simpa [initialSlot, binding, payload, index, ask, Program.bind, Program.eval]
                  using succeeded)
        rw [← same]
        let leaf : CurrentLeaf ns input.salt :=
          ⟨input.binding, input.payloads j, binding, payload⟩
        have parsed := global_normalized_leaf_roundtrip ns input.salt leaf
        dsimp only [leaf, CurrentLeaf.normalized] at parsed
        apply RecordedPath.here
        · simp [initialSlot, binding, payload, index, ask, Program.bind, Program.record,
            logRecords]
        · unfold NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          rw [parsed]
          rfl
      · simp [initialSlot, binding, payload, index, Program.eval] at succeeded
    · simp [initialSlot, binding, payload, Program.eval] at succeeded
  · simp [initialSlot, binding, Program.eval] at succeeded

/-- One executing node extends its own ordinal's path. These are induction
invariants, not additional acceptance checks. The public endpoint below
constructs them from the leaf queries and sequential execution. -/
theorem next_slot_extends_path (oracle : Oracle)
    (records : RawRecords) (state : State) (j : Fin 58) (result : Slot)
    (succeeded : (nextSlot state j).eval oracle = some result)
    (supported : logRecords ((nextSlot state j).record oracle).2 ⊆ records)
    (coordinate : SmzaQ38McaSourceBinding.Position) (depth : Nat) (leaf : RawInput)
    (index : (state j).index = coordinate.val / 2 ^ depth)
    (below : RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath coordinate depth) leaf) :
    RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree (depth + 1)) result.hash
      (SmzaRp05FilteredReadback.indexPath coordinate (depth + 1)) leaf := by
  obtain ⟨sibling, remaining, _selected, output, recorded⟩ :=
    next_slot_query_recorded oracle state j result succeeded
  by_cases even : (state j).index % 2 = 0
  · have bit : coordinate.val.testBit depth = false := by
      rw [Nat.testBit_eq_decide_div_mod_eq, ← index, even]
      decide
    have member : (nodeInput (state j).hash sibling, result.hash) ∈ records := by
      apply supported
      simp only [if_pos even] at recorded
      simp [logRecords, recorded]
    rw [SmzaRp05FilteredReadback.indexPath, bit]
    exact RecordedPath.step _ _ _ _ 0 _ _ _ _ member
      (node_parser_roundtrip depth (state j).hash sibling) rfl below
  · have odd : (state j).index % 2 = 1 := by omega
    have bit : coordinate.val.testBit depth = true := by
      rw [Nat.testBit_eq_decide_div_mod_eq, ← index, odd]
      decide
    have member : (nodeInput sibling (state j).hash, result.hash) ∈ records := by
      apply supported
      simp only [if_neg even] at recorded
      simp [logRecords, recorded]
    rw [SmzaRp05FilteredReadback.indexPath, bit]
    exact RecordedPath.step _ _ _ _ 1 _ _ _ _ member
      (node_parser_roundtrip depth sibling (state j).hash) rfl below

theorem level_extends_paths (oracle : Oracle)
    (records : RawRecords) (state result : State)
    (succeeded : (level state).eval oracle = some result)
    (supported : logRecords ((level state).record oracle).2 ⊆ records)
    (coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (leaves : Fin 58 → RawInput)
    (indices : ∀ j, (state j).index = (coordinates j).val / 2 ^ depth)
    (below : ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) depth) (leaves j)) :
    ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree (depth + 1)) (result j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) (depth + 1)) (leaves j) := by
  by_cases valid : duplicateConsistent state = true
  · have ran : (sequence 58 (nextSlot state)).eval oracle = some result := by
      simpa [level, valid] using succeeded
    intro j
    apply next_slot_extends_path oracle records state j (result j)
      (sequence_pointwise oracle 58 (nextSlot state) result ran j)
      _ (coordinates j) depth (leaves j) (indices j) (below j)
    exact (logRecords_mono _ _
      (sequence_log_subset oracle 58 (nextSlot state) result ran j)).trans
        (by simpa [level, valid] using supported)
  · simp [level, valid, Program.eval] at succeeded

theorem levels_extend_paths (oracle : Oracle)
    (records : RawRecords) (steps : Nat) (state result : State)
    (succeeded : (levels steps state).eval oracle = some result)
    (supported : logRecords ((levels steps state).record oracle).2 ⊆ records)
    (coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position)
    (depth : Nat) (leaves : Fin 58 → RawInput)
    (indices : ∀ j, (state j).index = (coordinates j).val / 2 ^ depth)
    (below : ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree depth) (state j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) depth) (leaves j)) :
    ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree (depth + steps)) (result j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) (depth + steps)) (leaves j) := by
  induction steps generalizing state depth with
  | zero =>
      have equal : state = result := Option.some.inj succeeded
      simpa [equal] using below
  | succ steps ih =>
      have composed : ((level state).eval oracle).bind (fun middle =>
          (levels steps middle).eval oracle) = some result := by
        simpa only [levels, Program.eval_bind] using succeeded
      cases stepped : (level state).eval oracle with
      | none => simp [stepped] at composed
      | some middle =>
          have later : (levels steps middle).eval oracle = some result := by
            simpa only [stepped, Option.bind_some] using composed
          have firstSupport : logRecords ((level state).record oracle).2 ⊆ records :=
            (logRecords_mono _ _
              (Program.bind_log_left oracle (level state) (levels steps) middle stepped)).trans
              supported
          have laterSupport : logRecords ((levels steps middle).record oracle).2 ⊆ records :=
            (logRecords_mono _ _
              (Program.bind_log_right oracle (level state) (levels steps) middle stepped)).trans
              supported
          have nextIndices : ∀ j, (middle j).index = (coordinates j).val / 2 ^ (depth + 1) := by
            intro j
            rw [level_index oracle state middle stepped j, indices j,
              Nat.div_div_eq_div_mul, pow_succ]
          have nextPaths := level_extends_paths oracle records state middle stepped
            firstSupport coordinates depth leaves indices below
          have paths := ih (state := middle) (depth := depth + 1)
            later laterSupport nextIndices nextPaths
          simpa only [Nat.add_assoc, Nat.add_comm 1 steps] using paths

theorem accepted_shape_valid (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : RawDigest) (accepted : acceptedResult ns oracle input = some target) :
    shapeValid ns input = true := by
  by_cases shape : shapeValid ns input = true
  · exact shape
  · simp [acceptedResult, merkleProgram, shape, Program.eval] at accepted

-- Do not normalize the concrete 58-by-23 execution while matching the
-- abstract bind/sequence lemmas below. This changes elaboration only.
attribute [local irreducible] merkleProgram SmzaRp05ExecutableMerkleVerifier.sequence levels initialSlot finish

private theorem merkle_log_parts (ns : Namespace) (oracle : Oracle) (input : Input)
    (initial final : State) (shape : shapeValid ns input = true)
    (started : (sequence 58 (initialSlot ns input)).eval oracle = some initial)
    (reduced : (levels 23 initial).eval oracle = some final) :
    logRecords ((sequence 58 (initialSlot ns input)).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 ∧
      logRecords ((levels 23 initial).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 ∧
      logRecords ((finish input final).record oracle).2 ⊆
        logRecords (recordedAttempt ns oracle input).2 := by
  let continuation : State → Program RawDigest :=
    fun state => (levels 23 state).bind (finish input)
  have top : merkleProgram ns input =
      (sequence 58 (initialSlot ns input)).bind continuation := by
    simp [merkleProgram, shape, continuation]
  have first : logRecords ((sequence 58 (initialSlot ns input)).record oracle).2 ⊆
      logRecords (recordedAttempt ns oracle input).2 := by
    change _ ⊆ logRecords ((merkleProgram ns input).record oracle).2
    rw [top]
    exact logRecords_mono _ _ (Program.bind_log_left oracle
      (sequence 58 (initialSlot ns input)) continuation initial started)
  have rest : logRecords (((levels 23 initial).bind (finish input)).record oracle).2 ⊆
      logRecords (recordedAttempt ns oracle input).2 := by
    change _ ⊆ logRecords ((merkleProgram ns input).record oracle).2
    rw [top]
    exact logRecords_mono _ _ (Program.bind_log_right oracle
      (sequence 58 (initialSlot ns input)) continuation initial started)
  refine ⟨first, ?_, ?_⟩
  · exact (logRecords_mono _ _ (Program.bind_log_left oracle
      (levels 23 initial) (finish input) final reduced)).trans rest
  · exact (logRecords_mono _ _ (Program.bind_log_right oracle
      (levels 23 initial) (finish input) final reduced)).trans rest

/-- Rewrite the existing Boolean's own decision procedure, rather than
synthesizing and unifying a second finite-forall decision procedure. -/
private theorem shape_valid_data (ns : Namespace) (input : Input)
    (shape : shapeValid ns input = true) :
    ns.canonicalPreamble input.binding = true ∧ input.salt.length = 32 ∧
      ∀ j, input.indices j < 8388608 := by
  simp only [shapeValid, Bool.and_eq_true, decide_eq_true_eq] at shape
  exact ⟨shape.1, shape.2.1, shape.2.2.1⟩

private theorem finish_records_root (oracle : Oracle) (input : Input) (state : State)
    (complete : ∀ j : Fin 58, (state j).remaining = [] ∧ (state j).hash = (state 0).hash) :
    (rootInput input.salt input.binding (state 0).hash,
      oracle (rootInput input.salt input.binding (state 0).hash)) ∈
        logRecords ((finish input state).record oracle).2 := by
  have valid : finalValid state = true := by
    simp only [finalValid, decide_eq_true_eq]
    exact complete
  simp [finish, valid, ask, Program.record, logRecords]

-- Keep the public theorem's execution and record-relation wrappers opaque
-- during elaboration. Their explicit reductions above have already been
-- packaged into helper theorems; unfolding them here expands the full run.
attribute [local irreducible] recordedAttempt acceptedResult logRecords

private theorem executed_tree_paths (ns : Namespace) (oracle : Oracle)
    (input : Input) (records : RawRecords) (initial final : State)
    (started : (sequence 58 (initialSlot ns input)).eval oracle = some initial)
    (reduced : (levels 23 initial).eval oracle = some final)
    (firstSupport : logRecords ((sequence 58 (initialSlot ns input)).record oracle).2 ⊆ records)
    (levelSupport : logRecords ((levels 23 initial).record oracle).2 ⊆ records)
    (coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position)
    (coordinateEq : ∀ j, (coordinates j).val = input.indices j) :
    ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree 23) (final j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j)) := by
  let leaves : Fin 58 → RawInput := fun j => encodeLeaf input.binding (input.payloads j)
  have initialIndices : ∀ j, (initial j).index = (coordinates j).val / 2 ^ 0 := by
    intro j
    simpa [coordinateEq j] using initial_slot_index ns oracle input j (initial j)
      (sequence_pointwise oracle 58 (initialSlot ns input) initial started j)
  have initialPaths : ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree 0)
      (initial j).hash (SmzaRp05FilteredReadback.indexPath (coordinates j) 0) (leaves j) := by
    intro j
    apply recorded_path_mono NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext _ records
      ((logRecords_mono _ _ (sequence_log_subset oracle 58
        (initialSlot ns input) initial started j)).trans firstSupport)
    exact initial_slot_recorded_path ns oracle input j (initial j)
      (sequence_pointwise oracle 58 (initialSlot ns input) initial started j)
  have treePaths := levels_extend_paths oracle records 23 initial final reduced
    levelSupport coordinates 0 leaves initialIndices initialPaths
  intro j
  simpa only [Nat.zero_add] using treePaths j

private theorem recorded_single_child
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (records : RawRecords) (stage : Stage) (target : RawDigest)
    (input : RawInput) (childStage : Stage) (childTarget : RawDigest)
    (rest : List Nat) (leaf : RawInput)
    (recorded : (input, target) ∈ records)
    (parsed : next stage input = some [(childStage, childTarget)])
    (below : RecordedPath next records childStage childTarget rest leaf) :
    RecordedPath next records stage target (0 :: rest) leaf := by
  exact RecordedPath.step stage target input [(childStage, childTarget)]
    0 childStage childTarget rest leaf recorded parsed rfl below

private theorem append_recorded_root (input : Input)
    (records : RawRecords) (target : RawDigest) (final : State)
    (coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position) (j : Fin 58)
    (saltLength : input.salt.length = 32)
    (bindingLength : input.binding.length = 616)
    (sameRoot : (final j).hash = (final 0).hash)
    (rootRecorded : (rootInput input.salt input.binding (final 0).hash, target) ∈ records)
    (below : RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records (.tree 23) (final j).hash
      (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j))) :
    RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records .root target
      (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j)) := by
  rw [sameRoot] at below
  have parsed : NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext .root
      (rootInput input.salt input.binding (final 0).hash) =
      some [(.tree 23, (final 0).hash)] :=
    root_parser_roundtrip input.salt input.binding (final 0).hash
      saltLength bindingLength
  exact recorded_single_child NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext records .root target
    (rootInput input.salt input.binding (final 0).hash) (.tree 23) (final 0).hash
    (SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
    (encodeLeaf input.binding (input.payloads j)) rootRecorded parsed below

/-- Public deterministic endpoint. Canonical paths are constructed from one
successful ordinary execution and that very execution's independently
instrumented log. No path, log-membership, collision-freedom, or extraction
certificate is an input. This is the Merkle phase, not the full verifier. -/
theorem accepted_recorded_paths (ns : Namespace) (oracle : Oracle) (input : Input)
    (target : RawDigest) (accepted : acceptedResult ns oracle input = some target) :
    ∃ coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ∀ j, RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
        (logRecords (recordedAttempt ns oracle input).2) .root target
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (encodeLeaf input.binding (input.payloads j)) := by
  have shape := accepted_shape_valid ns oracle input target accepted
  obtain ⟨bindingCanonical, saltLength, indexBounds⟩ := shape_valid_data ns input shape
  let coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position :=
    fun j => ⟨input.indices j, indexBounds j⟩
  let records := logRecords (recordedAttempt ns oracle input).2
  obtain ⟨_, initial, final, started, reduced, complete, targetEq⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  obtain ⟨firstSupport, levelSupport, finishSupport⟩ :=
    merkle_log_parts ns oracle input initial final shape started reduced
  have treePaths := executed_tree_paths ns oracle input records initial final
    started reduced firstSupport levelSupport coordinates (fun _ => rfl)
  have rootRecorded :
      (rootInput input.salt input.binding (final 0).hash, target) ∈ records := by
    apply finishSupport
    rw [targetEq]
    exact finish_records_root oracle input final complete
  refine ⟨coordinates, fun _ => rfl, ?_⟩
  intro j
  exact append_recorded_root input records target final coordinates j
    saltLength (ns.canonicalLength input.binding bindingCanonical)
    (complete j).2 rootRecorded (treePaths j)

/-- Each successful initial leaf read supplies the exact format and index
guards evaluated by the ordinary program, not a caller certificate. -/
theorem initial_slot_leaf_checks (ns : Namespace) (oracle : Oracle)
    (input : Input) (j : Fin 58) (result : Slot)
    (succeeded : (initialSlot ns input j).eval oracle = some result) :
    ns.canonicalPreamble input.binding = true ∧
      LegacyLeafCanonical input.salt (input.payloads j) ∧
      V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j := by
  by_cases binding : ns.canonicalPreamble input.binding = true
  · by_cases payload : LegacyLeafCanonical input.salt (input.payloads j)
    · by_cases index : V8SmzaOracleParser.wordAt (input.payloads j) 4 = input.indices j
      · exact ⟨binding, payload, index⟩
      · simp [initialSlot, binding, payload, index, Program.eval] at succeeded
    · simp [initialSlot, binding, payload, Program.eval] at succeeded
  · simp [initialSlot, binding, Program.eval] at succeeded

/-- Successful ordinary execution yields 58 canonical current leaves and
their recorded paths, including the opened-index equality. -/
theorem accepted_recorded_canonical_leaves (ns : Namespace) (oracle : Oracle)
    (input : Input) (target : RawDigest)
    (accepted : acceptedResult ns oracle input = some target) :
    ∃ coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ∀ j, ∃ leaf : CurrentLeaf ns input.salt,
        leaf.preamble = input.binding ∧
        leaf.legacyPayload = input.payloads j ∧
        V8SmzaOracleParser.wordAt leaf.legacyPayload 4 = (coordinates j).val ∧
        RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          (logRecords (recordedAttempt ns oracle input).2) .root target
          (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
          (encodeLeaf leaf.preamble leaf.legacyPayload) := by
  obtain ⟨coordinates, coordinateEq, paths⟩ :=
    accepted_recorded_paths ns oracle input target accepted
  obtain ⟨_, initial, _, started, _, _, _⟩ :=
    accepted_has_executed_common_root ns oracle input target accepted
  refine ⟨coordinates, coordinateEq, ?_⟩
  intro j
  obtain ⟨binding, payload, index⟩ := initial_slot_leaf_checks ns oracle input j
    (initial j) (sequence_pointwise oracle 58 (initialSlot ns input) initial started j)
  let leaf : CurrentLeaf ns input.salt :=
    ⟨input.binding, input.payloads j, binding, payload⟩
  refine ⟨leaf, rfl, rfl, ?_, ?_⟩
  · exact index.trans (coordinateEq j).symm
  · exact paths j

/-- Same-execution readback. Raw collision freedom is an explicit bad-event
alternative, not a cryptographic assumption or an acceptance premise. -/
theorem accepted_own_trace_readback_or_collision
    (ns : Namespace) (oracle : Oracle) (input : Input) (target : RawDigest)
    (accepted : acceptedResult ns oracle input = some target) :
    ¬RecordsCollisionFree (logRecords (recordedAttempt ns oracle input).2) ∨
    ∃ coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (V8Smz9CoherentMerkleGeometry.extract
          NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          (logRecords (recordedAttempt ns oracle input).2) 25 .root target) =
            some (encodeLeaf input.binding (input.payloads j)) := by
  by_cases collisionFree : RecordsCollisionFree
      (logRecords (recordedAttempt ns oracle input).2)
  · right
    obtain ⟨coordinates, same, paths⟩ := accepted_recorded_paths ns oracle input target accepted
    refine ⟨coordinates, same, ?_⟩
    intro j
    exact recorded_path_readback NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
      (logRecords (recordedAttempt ns oracle input).2) collisionFree .root target
      (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
      (encodeLeaf input.binding (input.payloads j)) (paths j) 25
      (by rw [List.length_cons, SmzaRp05FilteredReadback.index_path_length]; decide)
  · exact Or.inl collisionFree

/-- A prior cut is queried independently of the opened indices. Success of
this phase cannot imply that earlier records contain the whole tree.
Consequently each missing prior path is retained as a concrete bad arm.
The successful arm derives all 58 prior readbacks from the ordinary run's
indices and input bytes; it assumes neither the readbacks nor their values. -/
theorem accepted_prior_readback_or_missing_path_or_collision
    (ns : Namespace) (oracle : Oracle) (input : Input) (target : RawDigest)
    (prior : RawRecords) (accepted : acceptedResult ns oracle input = some target) :
    ¬RecordsCollisionFree prior ∨
    ∃ coordinates : Fin 58 → SmzaQ38McaSourceBinding.Position,
      (∀ j, (coordinates j).val = input.indices j) ∧
      ((∃ j, ¬RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          prior .root target
          (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
          (encodeLeaf input.binding (input.payloads j))) ∨
       (∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
          (V8Smz9CoherentMerkleGeometry.extract
            NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext prior 25 .root target) =
              some (encodeLeaf input.binding (input.payloads j)))) := by
  by_cases collisionFree : RecordsCollisionFree prior
  · right
    obtain ⟨coordinates, same, _paths⟩ := accepted_recorded_paths ns oracle input target accepted
    refine ⟨coordinates, same, ?_⟩
    by_cases missing : ∃ j, ¬RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
        prior .root target
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (encodeLeaf input.binding (input.payloads j))
    · exact Or.inl missing
    · right
      intro j
      have present : RecordedPath NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
          prior .root target
          (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
          (encodeLeaf input.binding (input.payloads j)) := by
        by_contra absent
        exact missing ⟨j, absent⟩
      exact recorded_path_readback NativePrivateSpendQ58CurrentFullStageEnvelope.rawNext
        prior collisionFree .root target
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (encodeLeaf input.binding (input.payloads j)) present 25
        (by rw [List.length_cons, SmzaRp05FilteredReadback.index_path_length]; decide)
  · exact Or.inl collisionFree

end

end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCompactMerkle
