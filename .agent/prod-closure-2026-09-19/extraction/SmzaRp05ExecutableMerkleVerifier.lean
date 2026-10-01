import SmzaRp05LeafNamespace

/-!
# Executable RP05 compact-Merkle verifier core

SOURCE-ONLY, NOT COMPILED. This is a deterministic oracle program, not a
definition of acceptance by `RecordedPath`, `AcceptedChecks`, or successful
instrumentation. `accepts` runs the uninstrumented interpreter. `record`
is a separate interpreter and `record_result` proves its erasure property.

The core implements 38 leaves, 23 non-deduplicating levels, compact sibling
reuse, duplicate-subtree consistency, exact path exhaustion, and common-root
checking. Inputs are untrusted legacy leaf payloads and compact paths, not
certified paths. A successful result is the hash_mt wrapper output. Pending
XOF failure is rejected. Source encodings use the current raw v2 leaf frame
and the unchanged current node/root frames; no proof-wire field is added.

Scope: the Merkle phase only. The companion ExecutableMerklePaths module
derives canonical RecordedPath from successful execution and this program's
own log, including node/root parser roundtrips. Exact equality to the
receipt classifier's candidate arrays remains separate. The current
sampler, PIOP reconstruction, and five/twelve scalar stages have NOT yet
been composed into this program. Thus `accepts` is Merkle-phase acceptance,
not full RP05/Rust acceptance or an extraction endpoint.

The first-sibling lookup is equivalent to Rust's BTreeMap lookup only after
the explicit duplicate guard succeeds. The path-length guard is computed
from the original selected indices, as in expected_compact_merkle_auth_path_lengths.
No machine-instruction Rust refinement is claimed.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier

open HegemonCrypto.CanonicalBytes
open SmzaRp05LeafNamespace
open V8SmzaOracleParser (RawDigest)
set_option autoImplicit false

abbrev Oracle := RawInput → RawDigest
abbrev Log := List (RawInput × RawDigest)

/-- The ordinary program has no recording or extraction operation. -/
inductive Program (α : Type) where
  | done : Option α → Program α
  | read : RawInput → (RawDigest → Program α) → Program α

def Program.bind {α β : Type} : Program α → (α → Program β) → Program β
  | .done none, _ => .done none
  | .done (some value), next => next value
  | .read input next, cont => .read input (fun output => (next output).bind cont)

def Program.eval {α : Type} (oracle : Oracle) : Program α → Option α
  | .done result => result
  | .read input next => (next (oracle input)).eval oracle

/-- Instrumentation retains failed prefixes as well as successful runs. -/
def Program.record {α : Type} (oracle : Oracle) : Program α → Option α × Log
  | .done result => (result, [])
  | .read input next =>
      let below := (next (oracle input)).record oracle
      (below.1, (input, oracle input) :: below.2)

theorem Program.record_result {α : Type} (oracle : Oracle) (program : Program α) :
    (program.record oracle).1 = program.eval oracle := by
  induction program with
  | done result => rfl
  | read input next ih => exact ih (oracle input)

theorem Program.recorded_call {α : Type} (oracle : Oracle) (program : Program α)
    (call : RawInput × RawDigest) (member : call ∈ (program.record oracle).2) :
    call.2 = oracle call.1 := by
  induction program with
  | done result => simp [Program.record] at member
  | read input next ih =>
      simp only [Program.record, List.mem_cons] at member
      rcases member with equal | below
      · subst call
        rfl
      · exact ih (oracle input) below

theorem Program.eval_bind {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) :
    (program.bind next).eval oracle =
      (program.eval oracle).bind (fun value => (next value).eval oracle) := by
  induction program with
  | done result => cases result <;> rfl
  | read input cont ih => exact ih (oracle input)

def ask (input : RawInput) : Program RawDigest :=
  .read input (fun output => .done (some output))

/-- Fixed order, retaining all 38 positions even when subtree indices merge. -/
def sequence {α : Type} : (count : Nat) → (Fin count → Program α) →
    Program (Fin count → α)
  | 0, _ => .done (some Fin.elim0)
  | count + 1, entries => (entries 0).bind fun first =>
      (sequence count (fun i => entries i.succ)).bind fun rest =>
        .done (some (Fin.cons first rest))

theorem sequence_pointwise {α : Type} (oracle : Oracle) (count : Nat)
    (entries : Fin count → Program α) (result : Fin count → α)
    (succeeded : (sequence count entries).eval oracle = some result) :
    ∀ j, (entries j).eval oracle = some (result j) := by
  induction count with
  | zero =>
      intro j
      exact Fin.elim0 j
  | succ count ih =>
      have composed : ((entries 0).eval oracle).bind (fun first =>
          ((sequence count (fun i => entries i.succ)).eval oracle).bind (fun rest =>
            some (Fin.cons first rest))) = some result := by
        simpa only [sequence, Program.eval_bind, Program.eval] using succeeded
      cases firstRead : (entries 0).eval oracle with
      | none => simp [firstRead] at composed
      | some first =>
          cases restRead : (sequence count (fun i => entries i.succ)).eval oracle with
          | none => simp [firstRead, restRead] at composed
          | some rest =>
              have equal : Fin.cons first rest = result := Option.some.inj (by
                simpa only [firstRead, restRead, Option.bind_some] using composed)
              intro j
              rw [← equal]
              exact Fin.cases (by simpa using firstRead)
                (fun i => by simpa using ih (fun i => entries i.succ) rest restRead i) j

def nodeInput (left right : RawDigest) : RawInput :=
  V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName .node)
    (List.ofFn left ++ List.ofFn right)

def rootInput (salt binding : List Byte) (root : RawDigest) : RawInput :=
  V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName .root)
    (salt ++ List.ofFn root ++ binding)

structure Slot where
  index : Nat
  hash : RawDigest
  remaining : List RawDigest

abbrev State := Fin 38 → Slot

def siblingIndex (index : Nat) : Nat :=
  if index % 2 = 0 then index + 1 else index - 1

def sibling? (state : State) (index : Nat) : Option RawDigest :=
  ((List.ofFn state).find? (fun slot => decide (slot.index = siblingIndex index))).map
    Slot.hash

def duplicateConsistent (state : State) : Bool := decide
  (∀ i j : Fin 38, (state i).index = (state j).index → (state i).hash = (state j).hash)

def selectedSibling (state : State) (j : Fin 38) :
    Option (RawDigest × List RawDigest) :=
  let own := state j
  match sibling? state own.index with
  | some sibling => some (sibling, own.remaining)
  | none => match own.remaining with
    | [] => none
    | sibling :: rest => some (sibling, rest)

/-- Consuming one absent sibling is ordinary verifier computation. -/
def nextSlot (state : State) (j : Fin 38) : Program Slot :=
  let own := state j
  match selectedSibling state j with
  | none => .done none
  | some (sibling, remaining) =>
      let input := if own.index % 2 = 0 then nodeInput own.hash sibling
        else nodeInput sibling own.hash
      (ask input).bind fun parent =>
        .done (some ⟨own.index / 2, parent, remaining⟩)

theorem next_slot_index (oracle : Oracle) (state : State) (j : Fin 38)
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
theorem next_slot_query_recorded (oracle : Oracle) (state : State) (j : Fin 38)
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
  if duplicateConsistent state then sequence 38 (nextSlot state) else .done none

def levels : Nat → State → Program State
  | 0, state => .done (some state)
  | depth + 1, state => (level state).bind (levels depth)

theorem level_index (oracle : Oracle) (state result : State)
    (succeeded : (level state).eval oracle = some result) (j : Fin 38) :
    (result j).index = (state j).index / 2 := by
  by_cases valid : duplicateConsistent state = true
  · have all : (sequence 38 (nextSlot state)).eval oracle = some result := by
      simpa [level, valid] using succeeded
    exact next_slot_index oracle state j (result j)
      (sequence_pointwise oracle 38 (nextSlot state) result all j)
  · simp [level, valid, Program.eval] at succeeded

/-- The source index recurrence is now derived from the executable program,
not assumed as a loop certificate. In particular this applies at depth 23. -/
theorem levels_index (oracle : Oracle) (depth : Nat) (state result : State)
    (succeeded : (levels depth state).eval oracle = some result) (j : Fin 38) :
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
def expectedLength (indices : Fin 38 → Nat) (j : Fin 38) (depth : Nat) : Nat :=
  ((List.range depth).filter fun d => !((List.ofFn indices).any fun index =>
    decide (index / 2 ^ d = siblingIndex (indices j / 2 ^ d)))).length

structure Input where
  salt : List Byte
  binding : List Byte
  indices : Fin 38 → Nat
  payloads : Fin 38 → List Byte
  paths : Fin 38 → List RawDigest
  pendingXofFailure : Bool

def shapeValid (ns : Namespace) (input : Input) : Bool :=
  ns.canonicalPreamble input.binding && decide
    (input.salt.length = 32 ∧
      (∀ j, input.indices j < 8388608) ∧
      (∀ i j : Fin 38, i.val < j.val → input.indices i < input.indices j) ∧
      (∀ j, (input.paths j).length = expectedLength input.indices j 23))

def initialSlot (ns : Namespace) (input : Input) (j : Fin 38) : Program Slot :=
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
    (j : Fin 38) (result : Slot)
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
  (∀ j : Fin 38, (state j).remaining = [] ∧ (state j).hash = (state 0).hash)

/-- Only ordinary path-exhaustion and common-root guards precede root hashing. -/
def finish (input : Input) (state : State) : Program RawDigest :=
  if finalValid state then ask (rootInput input.salt input.binding (state 0).hash)
  else .done none

def merkleProgram (ns : Namespace) (input : Input) : Program RawDigest :=
  if shapeValid ns input then
    (sequence 38 (initialSlot ns input)).bind fun initial =>
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
    (∀ j : Fin 38, (state j).remaining = [] ∧ (state j).hash = (state 0).hash) ∧
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
        (sequence 38 (initialSlot ns input)).eval oracle = some initial ∧
        (levels 23 initial).eval oracle = some final ∧
        (∀ j : Fin 38, (final j).remaining = [] ∧ (final j).hash = (final 0).hash) ∧
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
        ((sequence 38 (initialSlot ns input)).eval oracle).bind (fun initial =>
          ((levels 23 initial).eval oracle).bind (fun final =>
            (finish input final).eval oracle)) = some target := by
      simpa [merkleProgram, shape, Program.eval_bind] using ran
    cases started : (sequence 38 (initialSlot ns input)).eval oracle with
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
      (sequence_pointwise oracle 38 (initialSlot ns input) initial started j)]

end HegemonCrypto.SmallWood.SmzaRp05ExecutableMerkleVerifier
