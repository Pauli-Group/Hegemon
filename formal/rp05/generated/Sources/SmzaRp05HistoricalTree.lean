import SmzaRp05HistoricalEmptyBridge

/-!
# Indexed historical note tree (source-only)

An append log fixes the leaf opening at each historical position.  Positions
at or beyond that log's length contain the known zero opening.  The binary
tree below is a pure depth-32 reconstruction of that snapshot.  Its path
relation constructs the canonical default path for an unoccupied position,
including positions that a later append may occupy.  A separate source
refinement must identify this reconstructed root/path with the actual native
frontier and proof readback at the same historical anchor.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05HistoricalTree

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open HegemonCrypto.SmallWood.SmzaRp05HistoricalEmptyBridge

set_option autoImplicit false

def openingAt (log : List V8NoteOpening) (position : Nat) : V8NoteOpening :=
  if position < log.length then log.getD position knownEmptyOpening
  else knownEmptyOpening

theorem opening_at_unoccupied (log : List V8NoteOpening) (position : Nat)
    (unoccupied : log.length ≤ position) :
    openingAt log position = knownEmptyOpening := by
  simp [openingAt, Nat.not_lt.mpr unoccupied]

inductive IndexedTree where
  | leaf (position : Nat) (opening : V8NoteOpening)
  | node (left right : IndexedTree)

def IndexedTree.root : IndexedTree → Digest
  | .leaf _ opening => rp05PathHash (.leaf (exactV8NoteWords opening))
  | .node left right => rp05PathHash (.node left.root right.root)

def fromLog : Nat → Nat → List V8NoteOpening → IndexedTree
  | 0, base, log => .leaf base (openingAt log base)
  | depth + 1, base, log =>
      .node (fromLog depth base log)
        (fromLog depth (base + 2 ^ depth) log)

/-- A root-first authentication path to the leaf at its numeric position. -/
inductive PathAt : IndexedTree → Nat → V8NoteOpening →
    AuthenticationPath Digest → Prop where
  | leaf (position : Nat) (opening : V8NoteOpening) :
      PathAt (.leaf position opening) position opening []
  | left {left right : IndexedTree} {position : Nat}
      {opening : V8NoteOpening} {path : AuthenticationPath Digest}
      (child : PathAt left position opening path) :
      PathAt (.node left right) position opening
        (⟨right.root, .left⟩ :: path)
  | right {left right : IndexedTree} {position : Nat}
      {opening : V8NoteOpening} {path : AuthenticationPath Digest}
      (child : PathAt right position opening path) :
      PathAt (.node left right) position opening
        (⟨left.root, .right⟩ :: path)

theorem path_at_opens {tree : IndexedTree} {position : Nat}
    {opening : V8NoteOpening} {path : AuthenticationPath Digest}
    (pathWitness : PathAt tree position opening path) :
    OpensAt rp05PathHash tree.root (pathSides path)
      (exactV8NoteWords opening) path := by
  induction pathWitness with
  | leaf position opening =>
      exact ⟨rfl, rfl⟩
  | left child ih =>
      refine ⟨rfl, ?_⟩
      simp only [rootFromPath, IndexedTree.root, ih.2]
  | right child ih =>
      refine ⟨rfl, ?_⟩
      simp only [rootFromPath, IndexedTree.root, ih.2]

/-- The path comes from the append log, rather than being postulated by an
adversarial position flag. -/
theorem path_from_log (depth base position : Nat)
    (log : List V8NoteOpening)
    (lower : base ≤ position)
    (upper : position < base + 2 ^ depth) :
    ∃ path, PathAt (fromLog depth base log) position
      (openingAt log position) path := by
  induction depth generalizing base with
  | zero =>
      have eq : position = base := by omega
      subst position
      exact ⟨[], .leaf base (openingAt log base)⟩
  | succ depth ih =>
      have width : 2 ^ (depth + 1) = 2 ^ depth + 2 ^ depth := by
        simp [pow_succ, Nat.mul_two]
      by_cases leftSide : position < base + 2 ^ depth
      · rcases ih base lower leftSide with ⟨path, child⟩
        exact ⟨⟨(fromLog depth (base + 2 ^ depth) log).root,
          .left⟩ :: path, .left child⟩
      · have lowerRight : base + 2 ^ depth ≤ position :=
          Nat.le_of_not_lt leftSide
        have upperRight : position < base + 2 ^ depth + 2 ^ depth := by
          rw [width] at upper
          omega
        rcases ih (base + 2 ^ depth) lowerRight upperRight with
          ⟨path, child⟩
        exact ⟨⟨(fromLog depth base log).root, .right⟩ :: path,
          .right child⟩

/-- Concrete canonical default path at an unoccupied depth-32 position of
this historical append log. -/
theorem unoccupied_historical_default_path
    (log : List V8NoteOpening) (position : Nat)
    (unoccupied : log.length ≤ position)
    (inTree : position < 2 ^ merkleDepth) :
    ∃ path, PathAt (fromLog merkleDepth 0 log) position
        knownEmptyOpening path ∧
      OpensAt rp05PathHash (fromLog merkleDepth 0 log).root
        (pathSides path) (exactV8NoteWords knownEmptyOpening) path := by
  rcases path_from_log merkleDepth 0 position log (Nat.zero_le _)
      (by simpa using inTree) with ⟨path, pathWitness⟩
  rw [opening_at_unoccupied log position unoccupied] at pathWitness
  exact ⟨path, pathWitness, path_at_opens pathWitness⟩

/-- Apply the concrete append-log default path to one extracted accepted
opening. `acceptedRoot` and `acceptedSides` are the exact source readback
obligations: they bind the accepted proof's path to this log's historical root
and numerical position. Canonical field-word evidence is separate. -/
theorem accepted_unoccupied_position_zero_or_collision
    (log : List V8NoteOpening) (position : Nat)
    (opening : V8NoteOpening) (acceptedPath : AuthenticationPath Digest)
    (unoccupied : log.length ≤ position)
    (inTree : position < 2 ^ merkleDepth)
    (acceptedRoot :
      rootFromPath rp05PathHash (exactV8NoteWords opening) acceptedPath =
        (fromLog merkleDepth 0 log).root)
    (acceptedSides : ∀ defaultPath,
      PathAt (fromLog merkleDepth 0 log) position knownEmptyOpening defaultPath →
      pathSides acceptedPath = pathSides defaultPath)
    (acceptedCanonical :
      CanonicalEffectivePath (exactV8NoteWords opening) acceptedPath)
    (defaultCanonical : ∀ defaultPath,
      PathAt (fromLog merkleDepth 0 log) position knownEmptyOpening defaultPath →
      CanonicalEffectivePath
        (exactV8NoteWords knownEmptyOpening) defaultPath) :
    (opening.value = 0 ∧ opening.assetId = 0) ∨
      ∃ defaultPath,
        Nonempty (CanonicalRp05PathCollision
          (exactV8NoteWords opening) (exactV8NoteWords knownEmptyOpening)
          acceptedPath defaultPath) := by
  rcases unoccupied_historical_default_path log position unoccupied inTree with
    ⟨defaultPath, pathWitness, defaultOpens⟩
  let sameSides := acceptedSides defaultPath pathWitness
  have acceptedOpens : OpensAt rp05PathHash
      (fromLog merkleDepth 0 log).root (pathSides defaultPath)
      (exactV8NoteWords opening) acceptedPath :=
    ⟨sameSides, acceptedRoot⟩
  let atAnchor : HistoricalEmptyAt opening := {
    root := (fromLog merkleDepth 0 log).root
    sides := pathSides defaultPath
    acceptedPath := acceptedPath
    defaultPath := defaultPath
    accepted := acceptedOpens
    canonicalDefault := defaultOpens
    acceptedEffective := acceptedCanonical
    defaultEffective := defaultCanonical defaultPath pathWitness
  }
  rcases historical_empty_zero_or_path_collision opening atAnchor with
    zero | collision
  · exact Or.inl zero
  · exact Or.inr ⟨defaultPath, collision⟩

end HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
