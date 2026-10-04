import SmzaRp05SupplyClosureDecodedPath
import SmzaRp05SupplyClosureHistoryJoin

/-! Numeric positions determine root-first path sides.  Both representations
are derived here: the packed one from the accepted Boolean direction rows,
and the historical one from the indexed append tree. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosurePositionJoin

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDecodedPath
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

set_option autoImplicit false

def sideIndex : List ChildSide → Nat
  | [] => 0
  | .left :: tail => sideIndex tail
  | .right :: tail => 2 ^ tail.length + sideIndex tail

theorem side_index_bound (sides : List ChildSide) :
    sideIndex sides < 2 ^ sides.length := by
  induction sides with
  | nil => simp [sideIndex]
  | cons side tail ih =>
      cases side <;> simp only [sideIndex, List.length_cons, pow_succ]
      all_goals omega

theorem side_index_injective {left right : List ChildSide}
    (lengths : left.length = right.length)
    (indices : sideIndex left = sideIndex right) : left = right := by
  induction left generalizing right with
  | nil => simpa using lengths.symm
  | cons head tail ih =>
      cases right with
      | nil => simp at lengths
      | cons other rest =>
          have tailLengths : tail.length = rest.length := by simpa using lengths
          have leftBound := side_index_bound tail
          have rightBound := side_index_bound rest
          cases head <;> cases other <;>
            simp only [sideIndex] at indices
          · exact congrArg (List.cons .left) (ih tailLengths indices)
          · rw [tailLengths] at leftBound
            omega
          · rw [tailLengths] at indices
            omega
          · have equal : sideIndex tail = sideIndex rest := by
              rw [tailLengths] at indices
              omega
            exact congrArg (List.cons .right) (ih tailLengths equal)

theorem historical_path_index (depth base : Nat) (log : List V8NoteOpening)
    {position : Nat} {opening : V8NoteOpening} {path : AuthenticationPath Digest}
    (witness : PathAt (fromLog depth base log) position opening path) :
    (pathSides path).length = depth ∧
      base + sideIndex (pathSides path) = position := by
  induction depth generalizing base position opening path with
  | zero =>
      cases witness
      simp [pathSides, sideIndex]
  | succ depth ih =>
      cases witness with
      | left child =>
          obtain ⟨length, index⟩ := ih base child
          simpa [pathSides, sideIndex, length] using And.intro
            (congrArg Nat.succ length) index
      | right child =>
          obtain ⟨length, index⟩ := ih (base + 2 ^ depth) child
          have pathLength := length
          simp only [pathSides, List.length_map] at pathLength
          constructor
          · simpa [pathSides] using congrArg Nat.succ length
          · simpa [pathSides, sideIndex, pathLength, Nat.add_assoc] using index

def sourceSides (digit : Nat → Nat) : Nat → List ChildSide
  | 0 => []
  | count + 1 =>
      (if digit count = 0 then .left else .right) :: sourceSides digit count

theorem source_sides_length (digit : Nat → Nat) (count : Nat) :
    (sourceSides digit count).length = count := by
  induction count with
  | zero => rfl
  | succ count ih => simp [sourceSides, ih]

theorem source_sides_index (digit : Nat → Nat) (count : Nat)
    (boolean : ∀ bit, bit < count → digit bit = 0 ∨ digit bit = 1) :
    sideIndex (sourceSides digit count) =
      ((List.range count).map fun bit => 2 ^ bit * digit bit).sum := by
  induction count with
  | zero => simp [sourceSides, sideIndex]
  | succ count ih =>
      have previous := ih (fun bit bound => boolean bit (by omega))
      rcases boolean count (by omega) with zero | one
      · simp [sourceSides, zero, sideIndex, List.range_succ, previous]
      · simp [sourceSides, one, sideIndex, source_sides_length,
          List.range_succ, previous, Nat.add_comm]

theorem accepted_decoded_sides
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (siblings : List Digest) (count : Nat) (bound : count ≤ 32) :
    pathSides (decodedPath (projectPosition packed input.val) siblings count) =
      sourceSides (directionWord packed input.val) count := by
  induction count with
  | zero => rfl
  | succ count ih =>
      have bit := SmzaRp05AcceptedInputShape.accepted_position_bit_orientation
        SmzaRp05CurrentNullifierCertificates.directionCertificate
        accepted statement input ⟨count, by omega⟩
      change (projectPosition packed input.val / 2 ^ count) % 2 =
        directionWord packed input.val count at bit
      simp only [decodedPath, pathSides, List.map_cons, sourceSides]
      rw [bit]
      exact congrArg (List.cons _) (ih (by omega))

theorem accepted_same_position_sides
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (log : List V8NoteOpening) (opening : V8NoteOpening)
    (historicalPath : AuthenticationPath Digest)
    (historical : PathAt (fromLog merkleDepth 0 log)
      (projectPosition packed input.val) opening historicalPath) :
    pathSides (decodedPath (projectPosition packed input.val)
      (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings merkleDepth) =
        pathSides historicalPath := by
  have history := historical_path_index merkleDepth 0 log historical
  rw [accepted_decoded_sides accepted statement input _ _ (by decide)]
  apply side_index_injective
  · rw [source_sides_length, history.1]
  · rw [source_sides_index]
    · simpa [projectPosition, merkleDepth] using history.2.symm
    · intro bit bound
      rcases SmzaRp05NullifierSource.accepted_direction_bit_boolean
        SmzaRp05CurrentNullifierCertificates.directionCertificate
        accepted input ⟨bit, bound⟩ with zero | one
      · exact Or.inl (by simpa [directionWord, packedWord] using zero)
      · exact Or.inr (by simpa [directionWord, packedWord] using one)

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosurePositionJoin
