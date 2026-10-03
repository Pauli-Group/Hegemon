import SmzaRp05SupplyClosurePositionJoin
import SmzaRp05SupplyClosureOutputHistory

/-! All effective comparator inputs are canonical field-word strings.
Accepted note/sibling coordinates come from packed canonicality; historical
coordinates come from the extracted output log and the fixed empty opening.
Every intermediate digest is an actual seven-word permutation projection. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDecodedPath
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding

set_option autoImplicit false

theorem kernel_output_length (state : List Nat) :
    (Hegemon.Transaction.Poseidon2Width16Kernel.permutation state).length = 16 := by
  unfold Hegemon.Transaction.Poseidon2Width16Kernel.permutation
    Hegemon.Transaction.Poseidon2Width16Kernel.externalRoundConstantsTerminal
  simp only [List.foldl_cons, List.foldl_nil]
  exact Hegemon.Transaction.Poseidon2Width16Kernel.external_round_length _ _

theorem kernel_digest_exact (state : List Nat) :
    ExactWords 7 ((Hegemon.Transaction.Poseidon2Width16Kernel.permutation state).take 7) := by
  constructor
  · simp [kernel_output_length]
  · intro value member
    obtain ⟨index, bound, same⟩ := List.mem_iff_getElem.mp
      (List.mem_of_mem_take member)
    have indexBound : index < 16 := by simpa [kernel_output_length] using bound
    have canonical := kernel_permutation_word_canonical state ⟨index, indexBound⟩
    change (Hegemon.Transaction.Poseidon2Width16Kernel.permutation state).getD index 0 <
      fieldModulus at canonical
    rw [List.getD_eq_getElem _ _ bound, same] at canonical
    exact canonical

theorem sponge_digest_exact (domain : Nat) (words : List Nat) :
    ExactWords 7 (poseidon2V8Sponge domain words) := by
  dsimp only [poseidon2V8Sponge]
  generalize countEq : Nat.max 1
    ((words.length + Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
      Hegemon.Transaction.Poseidon2Width16Kernel.rate) = count
  cases count with
  | zero =>
      have positive : 1 ≤ Nat.max 1
          ((words.length + Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
            Hegemon.Transaction.Poseidon2Width16Kernel.rate) := Nat.le_max_left _ _
      rw [countEq] at positive
      omega
  | succ count =>
      simp only [List.range_succ, List.foldl_append,
        List.foldl_cons, List.foldl_nil]
      dsimp only [poseidon2V8AbsorbBlock]
      exact kernel_digest_exact _

theorem compress_digest_exact (domain : Nat) (left right : Digest) :
    ExactWords 7 (poseidon2V8Compress14 domain left right) :=
  kernel_digest_exact _

theorem path_root_exact (leaf : List Nat) (path : AuthenticationPath Digest) :
    ExactWords 7 (rootFromPath rp05PathHash leaf path) := by
  cases path with
  | nil => exact sponge_digest_exact _ _
  | cons step tail =>
      cases side : step.childSide <;>
        simp only [rootFromPath, side, rp05PathHash] <;>
        exact compress_digest_exact _ _ _

theorem effective_path_canonical (leaf : List Nat)
    (leafExact : ExactWords 18 leaf) (path : AuthenticationPath Digest)
    (siblings : ∀ step ∈ path, ExactWords 7 step.sibling) :
    CanonicalEffectivePath leaf path := by
  induction path with
  | nil =>
      intro input member
      have equal : input = .leaf leaf := by simpa [effectiveInputs] using member
      subst input
      exact leafExact
  | cons step tail ih =>
      intro input member
      rcases List.mem_cons.mp member with equal | member
      · subst input
        have sibling := siblings step (by simp)
        have child := path_root_exact leaf tail
        cases side : step.childSide <;>
          simp [orderedInput, side, CanonicalEffectiveInput, child, sibling]
      · exact ih (fun step member => siblings step (by simp [member])) input member

theorem projected_note_words_exact {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (call : Nat) :
    ExactWords 18 (exactV8NoteWords (projectNote packed call)) := by
  change ExactWords 18 ((List.range 18).map (spongeSourceWord packed call))
  exact exact_words_range_map 18 _
    (fun word _ => sponge_source_word_canonical accepted.2.1 call word)

theorem known_empty_words_exact : ExactWords 18 (exactV8NoteWords knownEmptyOpening) := by
  have identity := sponge_digest_exact 0x4853_4b41_5632_0001 [1, 0, 0, 0, 0, 0, 0]
  change ExactWords 7 currentKnownEmptyIdentity at identity
  constructor
  · simp [exactV8NoteWords, knownEmptyOpening, currentKnownEmptyOpening,
      identity.1]
  · intro word member
    change word ∈ (((([0, 0] ++ [0, 0, 0, 0]) ++ [0, 0, 0, 0]) ++
      (currentKnownEmptyIdentity.drop 4 ++ [0])) ++
      currentKnownEmptyIdentity.take 4) at member
    rcases List.mem_append.mp member with previous | auth
    · rcases List.mem_append.mp previous with previous | random
      · have zero : word = 0 := by simpa using previous
        subst word; decide
      · rcases List.mem_append.mp random with identityWord | zero
        · exact identity.2 word (List.mem_of_mem_drop identityWord)
        · have eq : word = 0 := by simpa using zero
          subst word; decide
    · exact identity.2 word (List.mem_of_mem_take auth)

theorem opening_at_exact (log : List V8NoteOpening)
    (canonical : ∀ opening ∈ log, ExactWords 18 (exactV8NoteWords opening))
    (position : Nat) : ExactWords 18 (exactV8NoteWords (openingAt log position)) := by
  unfold openingAt
  split
  next bound =>
    rw [List.getD_eq_getElem _ _ bound]
    exact canonical _ (List.getElem_mem bound)
  next _ => exact known_empty_words_exact

theorem indexed_root_exact (tree : IndexedTree) : ExactWords 7 tree.root := by
  cases tree with
  | leaf position opening =>
      change ExactWords 7 (poseidon2V8Sponge poseidon2V8NoteDomain
        (exactV8NoteWords opening))
      exact sponge_digest_exact _ _
  | node left right =>
      change ExactWords 7 (poseidon2V8Compress14 poseidon2V8MerkleDomain left.root right.root)
      exact compress_digest_exact _ _ _

theorem historical_siblings_exact {tree : IndexedTree} {position : Nat}
    {opening : V8NoteOpening} {path : AuthenticationPath Digest}
    (witness : PathAt tree position opening path) :
    ∀ step ∈ path, ExactWords 7 step.sibling := by
  induction witness with
  | leaf position opening => simp
  | left child ih =>
      intro step member
      rcases List.mem_cons.mp member with rfl | member
      · exact indexed_root_exact _
      · exact ih step member
  | right child ih =>
      intro step member
      rcases List.mem_cons.mp member with rfl | member
      · exact indexed_root_exact _
      · exact ih step member

theorem historical_path_canonical (log : List V8NoteOpening)
    (canonical : ∀ opening ∈ log, ExactWords 18 (exactV8NoteWords opening))
    (position : Nat) (path : AuthenticationPath Digest)
    (witness : PathAt (fromLog merkleDepth 0 log) position
      (openingAt log position) path) :
    CanonicalEffectivePath (exactV8NoteWords (openingAt log position)) path :=
  effective_path_canonical _ (opening_at_exact log canonical position) path
    (historical_siblings_exact witness)

theorem decoded_siblings_exact (position : Nat) (siblings : List Digest)
    (canonical : ∀ digest ∈ siblings, ExactWords 7 digest)
    (count : Nat) (bound : count ≤ siblings.length) :
    ∀ step ∈ decodedPath position siblings count, ExactWords 7 step.sibling := by
  induction count with
  | zero => simp [decodedPath]
  | succ count ih =>
      intro step member
      rcases List.mem_cons.mp member with rfl | member
      · have indexBound : count < siblings.length := by omega
        change ExactWords 7 (siblings.getD count [])
        rw [List.getD_eq_getElem _ _ indexBound]
        exact canonical _ (List.getElem_mem indexBound)
      · exact ih (by omega) step member

theorem accepted_path_canonical {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    CanonicalEffectivePath
      (exactV8NoteWords (projectNote packed (SmzaRp05NoteFrameCertificate.noteCall input)))
      (decodedPath (projectPosition packed input.val)
        (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings merkleDepth) := by
  have siblings := SmzaRp05AcceptedInputShape.accepted_siblings_exact
    accepted statement input.val
  apply effective_path_canonical _ (projected_note_words_exact accepted _) _
  exact decoded_siblings_exact (projectPosition packed input.val)
    (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings
    siblings.2 merkleDepth (by rw [siblings.1]; decide)

theorem accepted_output_log_canonical (records : List AcceptedOutputRecord)
    (accepted : ∀ record ∈ records, program.AcceptsPacked record.1 record.2) :
    ∀ opening ∈ extractedOutputLog records, ExactWords 18 (exactV8NoteWords opening) := by
  intro opening member
  obtain ⟨record, recordMember, outputMember⟩ := List.mem_flatMap.mp member
  obtain ⟨slot, slotMember, rfl⟩ := List.mem_map.mp outputMember
  exact projected_note_words_exact (accepted record recordMember) _

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
