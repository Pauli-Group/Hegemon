import HegemonCrypto.SmallWoodV8Smz9CurrentPrivacyComposition

/-! Finite request-circuit compilation for the current physical privacy game.
The mutable oracle is represented by a fixed baseline plus a retained update
register. Every logical read, including an honest read or an override hit,
uses two actual baseline queries. No experiment-distance field is accepted.

This is not yet a compilation theorem for the complete adaptive Rust prover.
In particular a request-phase label is not evidence that the source prover's
measurement, serialization or transcript algorithm implements that phase.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentRepeatedPrivacy

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9CurrentPublicContext V8Smz9CurrentPrivacyComposition
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9PrivacyGameComposition
open V8Smz9CurrentPrivacyGame V8Smz9EagerOracleGame V8Smz9EagerPrivacy
open V8Smz9ZeroKnowledge V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy
open V8Smz9JointAlgebraicLaw V8Smz9RuntimeDistribution
open V8Smz9HonestHybrid (DecsFullCoefficients DecsGamma)
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 3000
set_option backward.isDefEq.respectTransparency false

section RetainedLog

variable {Input : Type*} [DecidableEq Input]

abbrev UpdateCell (Input : Type*) := Option (Input × DigestRegister)
abbrev UpdateBuffer (Input : Type*) (capacity : Nat) := Fin capacity → UpdateCell Input

/-- Later entries take precedence. This reads the retained record register,
not the baseline oracle and not uncharged oracle-correlated advice. -/
def lookupPrefix (entries : Nat → UpdateCell Input) (input : Input) : Nat → Option DigestRegister
  | 0 => none
  | count + 1 => match entries count with
    | none => lookupPrefix entries input count
    | some (address, answer) => if address = input then some answer else lookupPrefix entries input count

theorem lookup_prefix_congr (left right : Nat → UpdateCell Input) (input : Input) (count : Nat)
    (agree : ∀ index, index < count → left index = right index) :
    lookupPrefix left input count = lookupPrefix right input count := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simp only [lookupPrefix, agree count (Nat.lt_succ_self count)]
      have previous := ih (fun index bound => agree index (Nat.lt_succ_of_lt bound))
      cases right count with
      | none => exact previous
      | some pair => split <;> simp only [previous]

theorem fresh_record_overrides_previous_lookup
    (entries : Nat → UpdateCell Input) (count : Nat) (address input : Input) (answer : DigestRegister) :
    lookupPrefix (Function.update entries count (some (address, answer))) input (count + 1) =
      if address = input then some answer else lookupPrefix entries input count := by
  have previous := lookup_prefix_congr
    (Function.update entries count (some (address, answer))) entries input count
    (fun index bounded => Function.update_of_ne (Nat.ne_of_lt bounded) _ _)
  simp only [lookupPrefix, Function.update_self, previous]

def bufferEntries {capacity : Nat} (buffer : UpdateBuffer Input capacity) : Nat → UpdateCell Input :=
  fun index => if bound : index < capacity then buffer ⟨index, bound⟩ else none

def bufferLookup {capacity : Nat} (buffer : UpdateBuffer Input capacity) (input : Input) :
    Option DigestRegister := lookupPrefix (bufferEntries buffer) input capacity

/-- Writing to a fresh slot is a permutation: swap the empty symbol with the
new record and retain every other slot. This is not irreversible Function.update
presented as a unitary operation. -/
def writeBufferEquiv {capacity : Nat} (slot : Fin capacity) (address : Input) (answer : DigestRegister) :
    UpdateBuffer Input capacity ≃ UpdateBuffer Input capacity :=
  Equiv.piCongrRight fun index => if index = slot
    then Equiv.swap none (some (address, answer)) else Equiv.refl _

theorem fresh_buffer_write_records {capacity : Nat} (slot : Fin capacity)
    (address : Input) (answer : DigestRegister) (buffer : UpdateBuffer Input capacity)
    (fresh : buffer slot = none) :
    writeBufferEquiv slot address answer buffer slot = some (address, answer) := by
  simp [writeBufferEquiv, fresh]

theorem buffer_write_preserves_other_slots {capacity : Nat} (slot index : Fin capacity)
    (different : index ≠ slot) (address : Input) (answer : DigestRegister)
    (buffer : UpdateBuffer Input capacity) :
    writeBufferEquiv slot address answer buffer index = buffer index := by
  simp [writeBufferEquiv, different]

/-- Adaptive record addresses and outputs are reversible controls from a retained
classical history register. The history is unchanged, so the inverse knows the
same write permutation. No quantum state is inspected as a classical function. -/
def writeBufferFromHistory {History : Type*} {capacity : Nat}
    (select : History → Fin capacity × Input × DigestRegister) :
    (History × UpdateBuffer Input capacity) ≃ (History × UpdateBuffer Input capacity) where
  toFun state := (state.1,
    writeBufferEquiv (select state.1).1 (select state.1).2.1 (select state.1).2.2 state.2)
  invFun state := (state.1,
    (writeBufferEquiv (select state.1).1 (select state.1).2.1 (select state.1).2.2).symm state.2)
  left_inv state := by rcases state with ⟨history, buffer⟩; simp
  right_inv state := by rcases state with ⟨history, buffer⟩; simp

theorem history_controlled_fresh_write {History : Type*} {capacity : Nat}
    (select : History → Fin capacity × Input × DigestRegister)
    (history : History) (buffer : UpdateBuffer Input capacity)
    (fresh : buffer (select history).1 = none) :
    (writeBufferFromHistory select (history, buffer)).1 = history ∧
      (writeBufferFromHistory select (history, buffer)).2 (select history).1 =
        some ((select history).2.1, (select history).2.2) :=
  ⟨rfl, fresh_buffer_write_records _ _ _ _ fresh⟩

end RetainedLog

section MutableBasis

variable {Input Updates Work : Type*}

abbrev RetainedWorkspace (Updates Work : Type*) := DigestRegister × Updates × Work
abbrev RetainedBasis (Input Updates Work : Type*) := QueryBasis Input DigestRegister (RetainedWorkspace Updates Work)

def swapAnswerScratch : RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work where
  toFun b := (b.1, b.2.2.1, b.2.1, b.2.2.2.1, b.2.2.2.2)
  invFun b := (b.1, b.2.2.1, b.2.1, b.2.2.2.1, b.2.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; rfl
  right_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; rfl

def baselineIntoScratch (oracle : Input → DigestRegister) :
    RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work where
  toFun b := (b.1, b.2.1, b.2.2.1 + oracle b.1, b.2.2.2.1, b.2.2.2.2)
  invFun b := (b.1, b.2.1, b.2.2.1 - oracle b.1, b.2.2.2.1, b.2.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp

/-- An oracle-independent controlled answer. The lookup can inspect only the
retained register and current address. It never receives the baseline function. -/
def answerFromRetainedRegister (lookup : Updates → Input → Option DigestRegister) :
    RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work where
  toFun b := (b.1, b.2.1 + (lookup b.2.2.2.1 b.1).getD b.2.2.1,
    b.2.2.1, b.2.2.2.1, b.2.2.2.2)
  invFun b := (b.1, b.2.1 - (lookup b.2.2.2.1 b.1).getD b.2.2.1,
    b.2.2.1, b.2.2.2.1, b.2.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp

def mutableQueryBasis (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister) :
    RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work :=
  ((baselineIntoScratch oracle).trans (answerFromRetainedRegister lookup)).trans
    (baselineIntoScratch oracle).symm

theorem mutable_query_on_clean_scratch
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (input : Input) (answer : DigestRegister) (updates : Updates) (work : Work) :
    mutableQueryBasis lookup oracle (input, answer, 0, updates, work) =
      (input, answer + (lookup updates input).getD (oracle input), 0, updates, work) := by
  simp [mutableQueryBasis, baselineIntoScratch, answerFromRetainedRegister]

theorem mutable_query_inverse_preserves_scratch
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (basis : RetainedBasis Input Updates Work) :
    ((mutableQueryBasis lookup oracle).symm basis).2.2.1 = basis.2.2.1 := by
  rcases basis with ⟨input, answer, scratch, updates, work⟩
  simp [mutableQueryBasis, baselineIntoScratch, answerFromRetainedRegister]

theorem baseline_scratch_query_is_one_raw_query (oracle : Input → DigestRegister) :
    (baselineIntoScratch oracle : RetainedBasis Input Updates Work ≃ _) =
      (swapAnswerScratch.trans (oracleQueryBasisEquiv oracle)).trans swapAnswerScratch := by
  apply Equiv.ext
  intro basis
  rcases basis with ⟨input, answer, scratch, updates, work⟩
  rfl

theorem baseline_scratch_inverse_is_same_xor_query (oracle : Input → DigestRegister) :
    (baselineIntoScratch oracle : RetainedBasis Input Updates Work ≃ _).symm =
      baselineIntoScratch oracle := by
  apply Equiv.ext
  intro basis
  change (basis.1, basis.2.1, basis.2.2.1 - oracle basis.1, basis.2.2.2.1, basis.2.2.2.2) = _
  rw [sub_eq_add_neg, digest_register_neg_eq_self]
  rfl

theorem mutable_query_is_two_raw_queries
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister) :
    (mutableQueryBasis lookup oracle : RetainedBasis Input Updates Work ≃ _) =
      ((((swapAnswerScratch.trans (oracleQueryBasisEquiv oracle)).trans
        ((swapAnswerScratch.trans (answerFromRetainedRegister lookup)).trans swapAnswerScratch)).trans
        (oracleQueryBasisEquiv oracle)).trans swapAnswerScratch) := by
  rw [mutableQueryBasis, baseline_scratch_inverse_is_same_xor_query,
    baseline_scratch_query_is_one_raw_query]
  apply Equiv.ext
  intro basis
  rfl

/-- A recorded abort can pad the remaining fixed schedule with identity logical
reads. Both baseline calls are still made and charged; no branch is postselected. -/
theorem halted_mutable_read_is_identity (oracle : Input → DigestRegister)
    (input : Input) (answer : DigestRegister) (updates : Updates) (work : Work) :
    mutableQueryBasis (fun _ _ => some 0) oracle (input, answer, 0, updates, work) =
      (input, answer, 0, updates, work) := by
  simpa using mutable_query_on_clean_scratch (fun _ _ => some 0) oracle input answer updates work

def updateRegisterEquiv (update : Updates ≃ Updates) :
    RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work where
  toFun b := (b.1, b.2.1, b.2.2.1, update b.2.2.2.1, b.2.2.2.2)
  invFun b := (b.1, b.2.1, b.2.2.1, update.symm b.2.2.2.1, b.2.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, scratch, updates, work⟩; simp

end MutableBasis

section PhysicalCompiler

variable {Input Updates Work : Type*} [Fintype Input] [DecidableEq Input]
variable [Fintype Updates] [Fintype Work]

abbrev RetainedState := State (Input := Input) (Output := DigestRegister)
  (Workspace := RetainedWorkspace Updates Work)
abbrev RetainedGate := RetainedState (Input := Input) (Updates := Updates) (Work := Work) ≃ₗᵢ[ℂ]
  RetainedState (Input := Input) (Updates := Updates) (Work := Work)

def liftRetainedBasis (permutation : RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work) :
    RetainedGate (Input := Input) (Updates := Updates) (Work := Work) :=
  LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ permutation

def ScratchClean (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) : Prop :=
  ∀ basis, basis.2.2.1 ≠ 0 → state basis = 0

def KeepsScratchClean (gate : RetainedGate (Input := Input) (Updates := Updates) (Work := Work)) : Prop :=
  ∀ state, ScratchClean state → ScratchClean (gate state)

omit [DecidableEq Input] in
theorem scratch_preserving_permutation_keeps_clean
    (permutation : RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work)
    (preserves : ∀ basis, (permutation.symm basis).2.2.1 = basis.2.2.1) :
    KeepsScratchClean (liftRetainedBasis permutation) := by
  intro state clean basis outside
  change state (permutation.symm basis) = 0
  apply clean
  simpa only [preserves] using outside

omit [DecidableEq Input] in
theorem mutable_gate_keeps_scratch_clean
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister) :
    KeepsScratchClean (liftRetainedBasis (mutableQueryBasis (Work := Work) lookup oracle)) :=
  scratch_preserving_permutation_keeps_clean _ (mutable_query_inverse_preserves_scratch lookup oracle)

omit [DecidableEq Input] in
theorem retained_write_keeps_scratch_clean (update : Updates ≃ Updates) :
    KeepsScratchClean (liftRetainedBasis (updateRegisterEquiv (Input := Input) (Work := Work) update)) :=
  scratch_preserving_permutation_keeps_clean _ (fun _ => rfl)

omit [DecidableEq Input] in
theorem lift_retained_basis_trans
    (first second : RetainedBasis Input Updates Work ≃ RetainedBasis Input Updates Work) :
    liftRetainedBasis (first.trans second) = (liftRetainedBasis first).trans (liftRetainedBasis second) := by
  ext state basis
  rfl

omit [DecidableEq Input] in
theorem lift_retained_basis_raw_query (oracle : Input → DigestRegister) :
    liftRetainedBasis (oracleQueryBasisEquiv oracle) =
      (query oracle : RetainedGate (Input := Input) (Updates := Updates) (Work := Work)) := rfl

def mutablePrepare : RetainedGate (Input := Input) (Updates := Updates) (Work := Work) :=
  liftRetainedBasis swapAnswerScratch

def mutableMiddle (lookup : Updates → Input → Option DigestRegister) :
    RetainedGate (Input := Input) (Updates := Updates) (Work := Work) :=
  (mutablePrepare.trans (liftRetainedBasis (answerFromRetainedRegister lookup))).trans mutablePrepare

omit [DecidableEq Input] in
theorem compiled_mutable_query_is_physical
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    liftRetainedBasis (mutableQueryBasis lookup oracle) state =
      mutablePrepare (query oracle (mutableMiddle lookup (query oracle (mutablePrepare state)))) := by
  rw [mutable_query_is_two_raw_queries]
  simp only [lift_retained_basis_trans, lift_retained_basis_raw_query,
    mutablePrepare, mutableMiddle, LinearIsometryEquiv.trans_apply]

inductive RequestPhase where
  | beginRequest | leafBatch | publicTranscript | finishRequest | publicAbort
  deriving DecidableEq

/-- A finite coherent schedule. Phase gates are oracle-independent physical
operations on the retained registers, not callbacks allowed to inspect a state
or oracle as classical data. Honest reads have explicit address preparation and
answer-recording operations and pass through the same charged mutable query.
-/
inductive RequestGrammar (Input Updates Work : Type*) [Fintype Input]
    [Fintype Updates] [Fintype Work] where
  | done
  | localGate (gate : RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
      (next : RequestGrammar Input Updates Work)
  | mutableRead (next : RequestGrammar Input Updates Work)
  | honestRead
      (prepare record : RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
      (next : RequestGrammar Input Updates Work)
  | retainedWrite (update : Updates ≃ Updates) (next : RequestGrammar Input Updates Work)
  | requestPhase (request : Nat) (phase : RequestPhase)
      (gate : RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
      (next : RequestGrammar Input Updates Work)

def logicalReadCount : RequestGrammar Input Updates Work → Nat
  | .done => 0
  | .localGate _ next => logicalReadCount next
  | .mutableRead next => logicalReadCount next + 1
  | .honestRead _ _ next => logicalReadCount next + 1
  | .retainedWrite _ next => logicalReadCount next
  | .requestPhase _ _ _ next => logicalReadCount next

def requestEventTrace : RequestGrammar Input Updates Work → List (Nat × RequestPhase)
  | .done => []
  | .localGate _ next => requestEventTrace next
  | .mutableRead next => requestEventTrace next
  | .honestRead _ _ next => requestEventTrace next
  | .retainedWrite _ next => requestEventTrace next
  | .requestPhase request phase _ next => (request, phase) :: requestEventTrace next

structure CompiledRequestCircuit (Input Updates Work : Type*) [Fintype Input]
    [Fintype Updates] [Fintype Work] where
  prepare : RetainedGate (Input := Input) (Updates := Updates) (Work := Work)
  afterQueries : List (RetainedGate (Input := Input) (Updates := Updates) (Work := Work))

def prependGate (gate : RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
    (circuit : CompiledRequestCircuit Input Updates Work) : CompiledRequestCircuit Input Updates Work :=
  ⟨gate.trans circuit.prepare, circuit.afterQueries⟩

def prependMutableQuery (lookup : Updates → Input → Option DigestRegister)
    (circuit : CompiledRequestCircuit Input Updates Work) : CompiledRequestCircuit Input Updates Work :=
  ⟨mutablePrepare, mutableMiddle lookup :: mutablePrepare.trans circuit.prepare :: circuit.afterQueries⟩

def compileRequestGrammar (lookup : Updates → Input → Option DigestRegister) :
    RequestGrammar Input Updates Work → CompiledRequestCircuit Input Updates Work
  | .done => ⟨LinearIsometryEquiv.refl ℂ _, []⟩
  | .localGate gate next => prependGate gate (compileRequestGrammar lookup next)
  | .mutableRead next => prependMutableQuery lookup (compileRequestGrammar lookup next)
  | .honestRead prepare record next => prependGate prepare
      (prependMutableQuery lookup (prependGate record (compileRequestGrammar lookup next)))
  | .retainedWrite update next => prependGate (liftRetainedBasis (updateRegisterEquiv update))
      (compileRequestGrammar lookup next)
  | .requestPhase _ _ gate next => prependGate gate (compileRequestGrammar lookup next)

/-- Direct physical semantics of the request grammar. The same baseline is
threaded through every operation; updates are genuine register permutations. -/
def runRequestGrammar (lookup : Updates → Input → Option DigestRegister)
    (oracle : Input → DigestRegister) : RequestGrammar Input Updates Work →
      RetainedState (Input := Input) (Updates := Updates) (Work := Work) →
        RetainedState (Input := Input) (Updates := Updates) (Work := Work)
  | .done, state => state
  | .localGate gate next, state => runRequestGrammar lookup oracle next (gate state)
  | .mutableRead next, state => runRequestGrammar lookup oracle next
      (liftRetainedBasis (mutableQueryBasis lookup oracle) state)
  | .honestRead prepare record next, state => runRequestGrammar lookup oracle next
      (record (liftRetainedBasis (mutableQueryBasis lookup oracle) (prepare state)))
  | .retainedWrite update next, state => runRequestGrammar lookup oracle next
      (liftRetainedBasis (updateRegisterEquiv update) state)
  | .requestPhase _ _ gate next, state => runRequestGrammar lookup oracle next (gate state)

/-- Ordinary physical hygiene, not a privacy or admission receipt: local
operations must preserve the clean scratch subspace. Mutable reads and actual
retained-register writes already have their preservation proofs above. -/
def GrammarScratchSafe : RequestGrammar Input Updates Work → Prop
  | .done => True
  | .localGate gate next => KeepsScratchClean gate ∧ GrammarScratchSafe next
  | .mutableRead next => GrammarScratchSafe next
  | .honestRead prepare record next =>
      KeepsScratchClean prepare ∧ KeepsScratchClean record ∧ GrammarScratchSafe next
  | .retainedWrite _ next => GrammarScratchSafe next
  | .requestPhase _ _ gate next => KeepsScratchClean gate ∧ GrammarScratchSafe next

omit [DecidableEq Input] in
theorem safe_request_grammar_preserves_clean_scratch
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (grammar : RequestGrammar Input Updates Work) (safe : GrammarScratchSafe grammar)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work))
    (clean : ScratchClean state) : ScratchClean (runRequestGrammar lookup oracle grammar state) := by
  induction grammar generalizing state with
  | done => exact clean
  | localGate gate next ih => exact ih safe.2 _ (safe.1 _ clean)
  | mutableRead next ih => exact ih safe _ (mutable_gate_keeps_scratch_clean lookup oracle _ clean)
  | honestRead prepare record next ih =>
      exact ih safe.2.2 _ (safe.2.1 _ (mutable_gate_keeps_scratch_clean lookup oracle _ (safe.1 _ clean)))
  | retainedWrite update next ih => exact ih safe _ (retained_write_keeps_scratch_clean update _ clean)
  | requestPhase request phase gate next ih => exact ih safe.2 _ (safe.1 _ clean)

def runCompiledCircuit (circuit : CompiledRequestCircuit Input Updates Work)
    (oracle : Input → DigestRegister)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    RetainedState (Input := Input) (Updates := Updates) (Work := Work) :=
  circuit.afterQueries.foldl (fun current gate => gate (query oracle current)) (circuit.prepare state)

omit [DecidableEq Input] in
theorem compiled_grammar_executes_same_physical_program
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (grammar : RequestGrammar Input Updates Work)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    runCompiledCircuit (compileRequestGrammar lookup grammar) oracle state =
      runRequestGrammar lookup oracle grammar state := by
  induction grammar generalizing state with
  | done => rfl
  | localGate gate next ih => exact ih (gate state)
  | mutableRead next ih =>
      simp only [compileRequestGrammar, prependMutableQuery, runCompiledCircuit,
        List.foldl_cons, LinearIsometryEquiv.trans_apply, runRequestGrammar]
      rw [← compiled_mutable_query_is_physical]
      exact ih _
  | honestRead prepare record next ih =>
      simp only [compileRequestGrammar, prependGate, prependMutableQuery, runCompiledCircuit,
        List.foldl_cons, LinearIsometryEquiv.trans_apply, runRequestGrammar]
      rw [← compiled_mutable_query_is_physical]
      exact ih _
  | retainedWrite update next ih => exact ih (liftRetainedBasis (updateRegisterEquiv update) state)
  | requestPhase request phase gate next ih => exact ih (gate state)

omit [DecidableEq Input] in
theorem compiled_raw_query_count (lookup : Updates → Input → Option DigestRegister)
    (grammar : RequestGrammar Input Updates Work) :
    (compileRequestGrammar lookup grammar).afterQueries.length = 2 * logicalReadCount grammar := by
  induction grammar with
  | done => rfl
  | localGate gate next ih => exact ih
  | mutableRead next ih => simp only [compileRequestGrammar, prependMutableQuery, List.length_cons,
      logicalReadCount, ih]; omega
  | honestRead prepare record next ih => simp only [compileRequestGrammar, prependGate,
      prependMutableQuery, List.length_cons, logicalReadCount, ih]; omega
  | retainedWrite update next ih => exact ih
  | requestPhase request phase gate next ih => exact ih

def compiledSteps (circuit : CompiledRequestCircuit Input Updates Work) :
    Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work) :=
  fun index => circuit.afterQueries.getD index (LinearIsometryEquiv.refl ℂ _)

omit [DecidableEq Input] in
theorem run_after_query_list_is_counted_circuit (oracle : Input → DigestRegister)
    (gates : List (RetainedGate (Input := Input) (Updates := Updates) (Work := Work)))
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    gates.foldl (fun current gate => gate (query oracle current)) state =
      run oracle (fun index => gates.getD index (LinearIsometryEquiv.refl ℂ _)) state gates.length := by
  induction gates generalizing state with
  | nil => rfl
  | cons first rest ih =>
      rw [List.foldl_cons, ih]
      symm
      have shifted := query_run_shift oracle
        (fun index => (first :: rest).getD index (LinearIsometryEquiv.refl ℂ _)) state rest.length
      simpa [List.getD_eq_getElem?_getD] using shifted

omit [DecidableEq Input] in
theorem compiled_grammar_is_current_game_circuit
    (lookup : Updates → Input → Option DigestRegister) (oracle : Input → DigestRegister)
    (grammar : RequestGrammar Input Updates Work)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    let circuit := compileRequestGrammar lookup grammar
    run oracle (compiledSteps circuit) (circuit.prepare state) circuit.afterQueries.length =
      runRequestGrammar lookup oracle grammar state := by
  have compiled := compiled_grammar_executes_same_physical_program lookup oracle grammar state
  dsimp only
  unfold compiledSteps
  rw [← run_after_query_list_is_counted_circuit]
  exact compiled

/-- The baseline table is supplied once and persists through the entire suffix.
Logical updates are in the retained register and are consulted by every read. -/
def compiledRequestProgram (circuit : CompiledRequestCircuit Input Updates Work)
    (next : LifetimeProgram Input DigestRegister (RetainedWorkspace Updates Work)) :
    LifetimeProgram Input DigestRegister (RetainedWorkspace Updates Work) :=
  .localGate circuit.prepare (compileQuantumCircuit (compiledSteps circuit) circuit.afterQueries.length next)

theorem compiled_request_program_continues_state
    (circuit : CompiledRequestCircuit Input Updates Work)
    (next : LifetimeProgram Input DigestRegister (RetainedWorkspace Updates Work))
    (oracle : Input → DigestRegister)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    (runLifetime (compiledRequestProgram circuit next) oracle state).state =
      (runLifetime next oracle
        (run oracle (compiledSteps circuit) (circuit.prepare state) circuit.afterQueries.length)).state := by
  exact compiled_quantum_circuit_continues_state oracle (compiledSteps circuit)
    (circuit.prepare state) circuit.afterQueries.length next

theorem compiled_request_program_continues_baseline
    (circuit : CompiledRequestCircuit Input Updates Work)
    (next : LifetimeProgram Input DigestRegister (RetainedWorkspace Updates Work))
    (oracle : Input → DigestRegister)
    (state : RetainedState (Input := Input) (Updates := Updates) (Work := Work)) :
    (runLifetime (compiledRequestProgram circuit next) oracle state).oracle =
      (runLifetime next oracle
        (run oracle (compiledSteps circuit) (circuit.prepare state) circuit.afterQueries.length)).oracle := by
  exact compiled_quantum_circuit_continues_oracle oracle (compiledSteps circuit)
    (circuit.prepare state) circuit.afterQueries.length next

/-- A literal block of honest reads. A phase annotation alone never earns the
claim that N source hashes were executed; this constructor contains all N reads. -/
def literalHonestReads
    (prepare record : Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work)) :
    Nat → RequestGrammar Input Updates Work → RequestGrammar Input Updates Work
  | 0, next => next
  | count + 1, next => .honestRead (prepare 0) (record 0)
      (literalHonestReads (fun index => prepare (index + 1))
        (fun index => record (index + 1)) count next)

omit [DecidableEq Input] in
theorem literal_honest_read_count
    (prepare record : Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
    (count : Nat) (next : RequestGrammar Input Updates Work) :
    logicalReadCount (literalHonestReads prepare record count next) = logicalReadCount next + count := by
  induction count generalizing prepare record with
  | zero => simp only [literalHonestReads, Nat.add_zero]
  | succ count ih => simp only [literalHonestReads, logicalReadCount, ih]; omega

def currentLeafReadBatch (request : Nat)
    (prepare record : Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
    (next : RequestGrammar Input Updates Work) : RequestGrammar Input Updates Work :=
  .requestPhase request .leafBatch (LinearIsometryEquiv.refl ℂ _)
    (literalHonestReads prepare record (2 ^ 23) next)

omit [DecidableEq Input] in
theorem current_leaf_batch_has_all_reads (request : Nat)
    (prepare record : Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
    (next : RequestGrammar Input Updates Work) :
    logicalReadCount (currentLeafReadBatch request prepare record next) = logicalReadCount next + 8388608 := by
  change logicalReadCount (literalHonestReads prepare record (2 ^ 23) next) = _
  rw [literal_honest_read_count]
  norm_num

omit [DecidableEq Input] in
theorem current_leaf_batch_compiler_charges_all_raw_calls
    (lookup : Updates → Input → Option DigestRegister) (request : Nat)
    (prepare record : Nat → RetainedGate (Input := Input) (Updates := Updates) (Work := Work))
    (next : RequestGrammar Input Updates Work) :
    (compileRequestGrammar lookup (currentLeafReadBatch request prepare record next)).afterQueries.length =
      2 * logicalReadCount next + 16777216 := by
  rw [compiled_raw_query_count, current_leaf_batch_has_all_reads]
  omega

end PhysicalCompiler

section CurrentPivot

variable {Other Updates Work : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Updates] [DecidableEq Updates] [Fintype Work] [DecidableEq Work]

abbrev CurrentRequestGrammar := RequestGrammar (LeafInput ⊕ Other) Updates Work
abbrev RequestContinuation := PublicContinuation (Other := Other) (Output := DigestRegister)
  (Workspace := RetainedWorkspace Updates Work)
abbrev RequestPublicStage := PublicStage (Other := Other) (Output := DigestRegister)
  (Workspace := RetainedWorkspace Updates Work)
abbrev RequestStageGenerator := PublicStageGenerator (Other := Other) (Output := DigestRegister)
  (Workspace := RetainedWorkspace Updates Work)

/-- A public-context grammar factory may choose later controls from retained
public history. It has no pivot-hidden-tape argument. Both adjacent experiments
use this same factory, lookup and initial retained register/state. -/
abbrev CurrentGrammarFactory :=
  (labels : LeafIndex → DigestRegister) → (response : DecsFullCoefficients Goldilocks) →
    (stage : RequestPublicStage (Other := Other) (Updates := Updates) (Work := Work)) →
    (transcript : PiopCoefficients Goldilocks) → (context : EagerContext stage.points) →
    OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context)) →
      CurrentRequestGrammar (Other := Other) (Updates := Updates) (Work := Work)

def compiledPublicContinuation
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (grammar : CurrentRequestGrammar (Other := Other) (Updates := Updates) (Work := Work))
    (continuation : RequestContinuation (Other := Other) (Updates := Updates) (Work := Work)) :
    RequestContinuation (Other := Other) (Updates := Updates) (Work := Work) :=
  let circuit := compileRequestGrammar lookup grammar
  { continuation with
    initial := circuit.prepare continuation.initial
    normalized := (circuit.prepare.norm_map continuation.initial).trans continuation.normalized
    steps := compiledSteps circuit
    queries := circuit.afterQueries.length }

omit [DecidableEq Other] [DecidableEq Updates] [DecidableEq Work] in
theorem compiled_public_continuation_query_count
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (grammar : CurrentRequestGrammar (Other := Other) (Updates := Updates) (Work := Work))
    (continuation : RequestContinuation (Other := Other) (Updates := Updates) (Work := Work)) :
    (compiledPublicContinuation lookup grammar continuation).queries = 2 * logicalReadCount grammar :=
  compiled_raw_query_count lookup grammar

/-- Preserve the actual public compiler/point-sampler Option, geometry, selector
and source continuation data while replacing the future circuit with the compiled
request grammar. No failed branch is deleted or resampled. -/
def compiledRequestStages
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work)) :
    RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work) :=
  fun labels response => (stages labels response).map fun stage =>
    { stage with
      continuation := fun transcript context visible =>
        compiledPublicContinuation lookup (grammars labels response stage transcript context visible)
          (stage.continuation transcript context visible) }

omit [DecidableEq Other] [DecidableEq Updates] [DecidableEq Work] in
theorem compiled_request_stages_preserve_public_abort
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work))
    (labels : LeafIndex → DigestRegister) (response : DecsFullCoefficients Goldilocks)
    (aborted : stages labels response = none) :
    compiledRequestStages lookup stages grammars labels response = none := by
  simp only [compiledRequestStages, aborted, Option.map_none]

omit [DecidableEq Other] [DecidableEq Updates] [DecidableEq Work] in
theorem compiled_request_stage_query_budget
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work))
    (budget : Nat)
    (bounded : ∀ labels response stage, stages labels response = some stage →
      ∀ transcript context visible, logicalReadCount (grammars labels response stage transcript context visible) ≤ budget) :
    ∀ labels response stage, compiledRequestStages lookup stages grammars labels response = some stage →
      ∀ transcript context visible, (stage.continuation transcript context visible).queries ≤ 2 * budget := by
  intro labels response stage selected
  cases original : stages labels response with
  | none => simp only [compiledRequestStages, original, Option.map_none] at selected
            cases selected
  | some previous =>
      simp only [compiledRequestStages, original, Option.map_some, Option.some.injEq] at selected
      cases selected
      intro transcript context visible
      change (compiledPublicContinuation lookup
        (grammars labels response previous transcript context visible)
        (previous.continuation transcript context visible)).queries ≤ _
      rw [compiled_public_continuation_query_count]
      exact Nat.mul_le_mul_left 2 (bounded labels response previous original transcript context visible)

/-- The full endpoint is the *executed* current randomized-label source, with
the entire future request grammar compiled into the same physical continuation.
It is not an arbitrary acceptance probability attached to a request label. -/
def fullCurrentRequestExperiment
    (statement : V8PublicStatement) (witness : List Nat)
    (batching : (LeafIndex → DigestRegister) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → DigestRegister) → DecsGamma Goldilocks)
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work))
    (salt : SaltBytes) (failure : ℝ) : ℝ :=
  executedChronologicalAcceptance statement batching gamma (compiledRequestStages lookup stages grammars)
    (packingValues witness) salt failure

def publicCurrentRequestExperiment
    (statement : V8PublicStatement)
    (batching : (LeafIndex → DigestRegister) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → DigestRegister) → DecsGamma Goldilocks)
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work))
    (salt : SaltBytes) (failure : ℝ) : ℝ :=
  generatedPublicReferenceAcceptance statement batching gamma (compiledRequestStages lookup stages grammars)
    salt failure

/-- A derived concrete request-pivot bound. The suffix may contain arbitrarily
many finite request phases, retained writes, coherent raw reads and explicitly
compiled honest reads. Its entire baseline-query cost is charged. This theorem
does not assume an adjacent game-distance inequality or a witness-validity receipt:
the ordinary current-domain premise is the existing exact public/packed acceptance
contract. Honest typed-to-packed completeness remains a separate obligation. -/
theorem compiled_request_suffix_current_adjacency
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : (LeafIndex → DigestRegister) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → DigestRegister) → DecsGamma Goldilocks)
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (stages : RequestStageGenerator (Other := Other) (Updates := Updates) (Work := Work))
    (grammars : CurrentGrammarFactory (Other := Other) (Updates := Updates) (Work := Work))
    (salt : SaltBytes) (failure : ℝ) (budget : Nat)
    (bounded : ∀ labels response stage, stages labels response = some stage →
      ∀ transcript context visible, logicalReadCount (grammars labels response stage transcript context visible) ≤ budget) :
    |fullCurrentRequestExperiment statement witness batching gamma lookup stages grammars salt failure -
      publicCurrentRequestExperiment statement batching gamma lookup stages grammars salt failure| ≤
        hiddenPatchLoss (2 * budget) :=
  executed_chronological_source_to_public_reference_bound statement publicValues witness domain
    batching gamma (compiledRequestStages lookup stages grammars) salt failure (2 * budget)
    (compiled_request_stage_query_budget lookup stages grammars budget bounded)

theorem compiled_request_suffix_loss_closed_form (budget : Nat) :
    hiddenPatchLoss (2 * budget) = 8 * (budget : ℝ) / (2 ^ 256 : ℝ) := by
  rw [current_hidden_patch_loss_closed_form]
  push_cast
  ring

end CurrentPivot

section HonestLeafCosts

def currentLeafEvents (attempts : Nat) : Nat := attempts * (2 ^ 23)

theorem current_leaf_events_exact (attempts : Nat) : currentLeafEvents attempts = attempts * 8388608 := rfl

/-- External adaptive-reprogramming envelope after substituting the actual
512-bit fresh tape and every full leaf-batch event. `otherQueries` includes all
other honest and adversarial raw calls; read-after-program contributes R more.
This is a defined numerical envelope, not a certified published quantum theorem. -/
def currentHonestLeafExternalEnvelope (attempts otherQueries : Nat) : ℝ :=
  let events := currentLeafEvents attempts
  (events : ℝ) * Real.sqrt ((otherQueries + events : Nat) : ℝ) / (2 ^ 256 : ℝ) +
    (events : ℝ) * ((otherQueries + events : Nat) : ℝ) / (2 ^ 513 : ℝ)

theorem actual_source_leaf_event_max_mass
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes) (index : LeafIndex) (input : LeafInput) :
    pmfMap (uniformFintypePMF LeafTape)
      (sourceLeafInput (canonicalLeafHeader salt)
        (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 index) index) input ≤
      (2 ^ 512 : ℝ≥0∞)⁻¹ :=
  original_current_leaf_input_max_mass values base masks salt index input

end HonestLeafCosts

end
end HegemonCrypto.SmallWood.V8Smz9CurrentRepeatedPrivacy
