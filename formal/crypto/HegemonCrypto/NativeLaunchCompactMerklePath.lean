import HegemonCrypto.CanonicalBytes

/-!
Executable compact Merkle reconstruction and ordinary-path extraction.
Source: smallwood_engine.rs:12196–12342, 14061–14111 at ef8784fcf
(runtime identical to f3b16e920). Proof fields below are erased invariants
constructed by initial/advance; no path-fold test is added to acceptance.
The native SHA-512 node hash uses ordered children without level/index.
Its exact byte framing is a separate obligation. Leaf hashing, input shape
(including sortedness, ranges and expected compact lengths), Rust refinement,
original committed-tree provenance, chronology and QROM security remain open.
-/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchCompactMerklePath

variable {D : Type}

def parent (node : D → D → D) (index : Nat) (hash sibling : D) : D :=
  if index % 2 = 0 then node hash sibling else node sibling hash

def siblingIndex (index : Nat) : Nat :=
  if index % 2 = 0 then index + 1 else index - 1

/-- Ordinary authentication-path fold, retaining the progressively divided index. -/
def walk (node : D → D → D) : Nat → D → List D → Nat × D
  | index, hash, [] => (index, hash)
  | index, hash, sibling :: rest =>
      walk node (index / 2) (parent node index hash sibling) rest

theorem walk_append (node : D → D → D) (path tail : List D) (index : Nat) (hash : D) :
    walk node index hash (path ++ tail) =
      walk node (walk node index hash path).1 (walk node index hash path).2 tail := by
  induction path generalizing index hash with
  | nil => rfl
  | cons sibling rest ih => exact ih (index / 2) (parent node index hash sibling)

theorem walk_index (node : D → D → D) (path : List D) (index : Nat) (hash : D) :
    (walk node index hash path).1 = index / 2 ^ path.length := by
  induction path generalizing index hash with
  | nil => simp [walk]
  | cons sibling rest ih =>
      simp only [walk, List.length_cons]
      rw [ih, Nat.div_div_eq_div_mul, pow_succ, Nat.mul_comm 2]

structure Opening (D : Type) where
  index : Nat
  hash : D
  compact : List D

/-- One entry per ORIGINAL opening. Equal current indices never merge states.
The first four fields are data: index, hash, cursor, and the expanded sibling
list, which is model instrumentation. Only the last three proof fields erase. -/
structure State (node : D → D → D) (opening : Opening D) (level : Nat) where
  index : Nat
  hash : D
  cursor : Nat
  siblings : List D
  length_eq : siblings.length = level
  folded_eq : walk node opening.index opening.hash siblings = (index, hash)
  cursor_le : cursor ≤ opening.compact.length

def initial (node : D → D → D) (opening : Opening D) : State node opening 0 :=
  ⟨opening.index, opening.hash, 0, [], rfl, rfl, Nat.zero_le _⟩

/-- Every successful step appends the sibling actually used by the source loop. -/
def advance (node : D → D → D) {opening : Opening D} {level : Nat}
    (state : State node opening level) (sibling : D) (cursor : Nat)
    (bound : cursor ≤ opening.compact.length) : State node opening (level + 1) where
  index := state.index / 2
  hash := parent node state.index state.hash sibling
  cursor := cursor
  siblings := state.siblings ++ [sibling]
  length_eq := by simp [state.length_eq]
  folded_eq := by rw [walk_append, state.folded_eq]; rfl
  cursor_le := bound

/-- Association-list implementation of the current-index map. -/
def lookup (index : Nat) : List (Nat × D) → Option D
  | [] => none
  | (key, hash) :: rest => if index = key then some hash else lookup index rest

/-- Reject inconsistent duplicates, preserving the same mapping on consistent ones. -/
def buildTable [DecidableEq D] : List (Nat × D) → Option (List (Nat × D))
  | [] => some []
  | (index, hash) :: rest => do
      let table ← buildTable rest
      match lookup index table with
      | none => some ((index, hash) :: table)
      | some previous => if previous = hash then some table else none

/-- The sibling is reused if present; otherwise exactly this opening's cursor
is read and incremented. No compact entries are shared after ancestor merges. -/
def step (node : D → D → D) {opening : Opening D} {level : Nat}
    (table : List (Nat × D)) (state : State node opening level) :
    Option (State node opening (level + 1)) :=
  match lookup (siblingIndex state.index) table with
  | some sibling => some (advance node state sibling state.cursor state.cursor_le)
  | none =>
      if available : state.cursor < opening.compact.length then
        some (advance node state opening.compact[state.cursor] (state.cursor + 1) (by omega))
      else none

/-- Finite, dependent Option traversal. Dependency ties every returned state
to its original opening; it imposes no runtime test. -/
def sequenceFin : {count : Nat} → {β : Fin count → Type} →
    ((i : Fin count) → Option (β i)) → Option ((i : Fin count) → β i)
  | 0, _, _ => some (fun i => Fin.elim0 i)
  | _ + 1, _, f => do
      let first ← f 0
      let rest ← sequenceFin (fun i => f i.succ)
      some (Fin.cases first rest)

def runLevels [DecidableEq D] (node : D → D → D) {count : Nat}
    (openings : Fin count → Opening D) :
    (depth : Nat) → Option ((i : Fin count) → State node (openings i) depth)
  | 0 => some (fun i => initial node (openings i))
  | depth + 1 => do
      let states ← runLevels node openings depth
      let table ← buildTable (List.ofFn (fun i => ((states i).index, (states i).hash)))
      sequenceFin (fun i => step node table (states i))

structure Result (node : D → D → D) {count : Nat}
    (openings : Fin count → Opening D) (depth : Nat) where
  root : D
  states : (i : Fin count) → State node (openings i) depth
  nonempty : 0 < count
  exhausted : ∀ i, (states i).cursor = (openings i).compact.length
  agrees : ∀ i, (states i).hash = root

/-- Final acceptance has precisely cursor exhaustion, nonempty openings,
and agreement of roots. Shape/leaf-hash checks precede this modeled loop. -/
def reconstruct [DecidableEq D] (node : D → D → D) {count : Nat}
    (openings : Fin count → Opening D) (depth : Nat) : Option (Result node openings depth) := do
  let states ← runLevels node openings depth
  if exhausted : ∀ i, (states i).cursor = (openings i).compact.length then
    if nonempty : 0 < count then
      let root := (states ⟨0, nonempty⟩).hash
      if agrees : ∀ i, (states i).hash = root then
        some ⟨root, states, nonempty, exhausted, agrees⟩
      else none
    else none
  else none

theorem state_index_quotient (node : D → D → D) {opening : Opening D} {level : Nat}
    (state : State node opening level) : state.index = opening.index / 2 ^ level := by
  have h := walk_index node state.siblings opening.index opening.hash
  rw [state.folded_eq, state.length_eq] at h
  exact h

/-- A successful run yields a full ordinary path for EACH original opening,
folding its original leaf hash to the common root. All supplied compact
entries are consumed by the checked per-opening cursor. No hash assumption. -/
theorem successful_extraction [DecidableEq D] (node : D → D → D) {count depth : Nat}
    (openings : Fin count → Opening D) (result : Result node openings depth)
    (_success : reconstruct node openings depth = some result) (i : Fin count) :
    (result.states i).siblings.length = depth ∧
    (result.states i).index = (openings i).index / 2 ^ depth ∧
    walk node (openings i).index (openings i).hash (result.states i).siblings =
      ((openings i).index / 2 ^ depth, result.root) ∧
    (result.states i).cursor = (openings i).compact.length ∧
    (openings i).compact.take (result.states i).cursor = (openings i).compact := by
  refine ⟨(result.states i).length_eq, state_index_quotient node (result.states i), ?_,
    result.exhausted i, ?_⟩
  · rw [(result.states i).folded_eq, state_index_quotient, result.agrees]
  · rw [result.exhausted, List.take_length]

theorem native_depth23_extraction [DecidableEq D] (node : D → D → D) {count : Nat}
    (openings : Fin count → Opening D) (result : Result node openings 23)
    (success : reconstruct node openings 23 = some result) (i : Fin count) :
    (result.states i).siblings.length = 23 ∧
    walk node (openings i).index (openings i).hash (result.states i).siblings =
      ((openings i).index / 2 ^ 23, result.root) ∧
    (result.states i).cursor = (openings i).compact.length := by
  have h := successful_extraction node openings result success i
  exact ⟨h.1, h.2.2.1, h.2.2.2.1⟩

/-- Root-only entry point: the sole execution hypothesis starts reconstruction
from `initial`, not an externally provided invariant-bearing state. -/
theorem accepted_root_extraction [DecidableEq D] (node : D → D → D) {count depth : Nat}
    (openings : Fin count → Opening D) (root : D)
    (accepted : (reconstruct node openings depth).map (fun result => result.root) = some root) :
    0 < count ∧ ∃ paths : Fin count → List D, ∃ cursors : Fin count → Nat,
      ∀ i, (paths i).length = depth ∧
        walk node (openings i).index (openings i).hash (paths i) =
          ((openings i).index / 2 ^ depth, root) ∧
        cursors i = (openings i).compact.length ∧
        (openings i).compact.take (cursors i) = (openings i).compact := by
  cases execution : reconstruct node openings depth with
  | none => simp [execution] at accepted
  | some result =>
      have root_eq : result.root = root := by simpa [execution] using accepted
      refine ⟨result.nonempty, (fun i => (result.states i).siblings),
        (fun i => (result.states i).cursor), ?_⟩
      intro i
      have h := successful_extraction node openings result execution i
      exact ⟨h.1, root_eq ▸ h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩

end HegemonCrypto.NativeLaunchCompactMerklePath
