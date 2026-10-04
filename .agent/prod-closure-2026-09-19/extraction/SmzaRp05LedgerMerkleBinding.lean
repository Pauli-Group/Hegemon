import HegemonCrypto.SmallWoodMerkleExtraction
import Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-!
Constructive comparison of two RP05 openings at one root and one position.
The reported collision contains actual effective leaf words or ordered child
digests from the two supplied paths.  This does not identify a ledger creator
by itself: the canonical historical path and the accepted path must still be
connected to the append-only creator log and the same retained root.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding

open HegemonCrypto.SmallWood.MerkleExtraction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option autoImplicit false

def orderedInput {Payload Digest : Type*}
    (step : AuthenticationStep Digest) (child : Digest) :
    HashInput Payload Digest :=
  match step.childSide with
  | .left => .node child step.sibling
  | .right => .node step.sibling child

def isLeafInput {Payload Digest : Type*} : HashInput Payload Digest → Bool
  | .leaf _ => true
  | .node _ _ => false

@[simp] theorem ordered_input_not_leaf {Payload Digest : Type*}
    (step : AuthenticationStep Digest) (child : Digest) :
    isLeafInput (orderedInput step child : HashInput Payload Digest) = false := by
  cases side : step.childSide <;> simp [isLeafInput, orderedInput, side]

/-- Every element is an input actually hashed on this path, with the leaf
payload first at the bottom and the ordered node inputs above it. -/
def effectiveInputs {Payload Digest : Type*}
    (hash : HashInput Payload Digest → Digest) (leaf : Payload) :
    AuthenticationPath Digest → List (HashInput Payload Digest)
  | [] => [.leaf leaf]
  | step :: remaining =>
      orderedInput step (rootFromPath hash leaf remaining) ::
        effectiveInputs hash leaf remaining

structure PathCollision {Payload Digest : Type*}
    (hash : HashInput Payload Digest → Digest)
    (leftLeaf rightLeaf : Payload)
    (leftPath rightPath : AuthenticationPath Digest) where
  leftInput : HashInput Payload Digest
  rightInput : HashInput Payload Digest
  leftUsed : leftInput ∈ effectiveInputs hash leftLeaf leftPath
  rightUsed : rightInput ∈ effectiveInputs hash rightLeaf rightPath
  different : leftInput ≠ rightInput
  sameKind : isLeafInput leftInput = isLeafInput rightInput
  sameDigest : hash leftInput = hash rightInput

universe u v

/-- Data-bearing comparison result.  The equality is a proof field of one
constructor, rather than a `Prop` supplied as a `Sum` type argument. -/
inductive Comparison {Payload : Type u} (left right : Payload)
    (Collision : Type v) : Type (max u v) where
  | equal (same : left = right) : Comparison left right Collision
  | collision (witness : Collision) : Comparison left right Collision

private theorem ordered_input_child_eq
    {Payload Digest : Type*}
    (leftStep rightStep : AuthenticationStep Digest)
    (leftChild rightChild : Digest)
    (sameSide : leftStep.childSide = rightStep.childSide)
    (sameInput : (orderedInput leftStep leftChild : HashInput Payload Digest) =
      orderedInput rightStep rightChild) :
    leftChild = rightChild := by
  cases leftStep with
  | mk leftSibling leftSide =>
    cases rightStep with
    | mk rightSibling rightSide =>
      cases leftSide <;> cases rightSide <;>
        simp_all [orderedInput]

/-- Recursively compare the actual hash inputs, beginning at the common
root.  A first unequal pair with equal digest is returned immediately;
otherwise equal node inputs expose equal child digests and recursion reaches
the leaves.  No global hash-injectivity premise is used. -/
def compare_paths
    {Payload Digest : Type*}
    [DecidableEq Payload] [DecidableEq Digest]
    (hash : HashInput Payload Digest → Digest)
    (leftLeaf rightLeaf : Payload)
    (leftPath rightPath : AuthenticationPath Digest)
    (sameSides : pathSides leftPath = pathSides rightPath)
    (sameRoot : rootFromPath hash leftLeaf leftPath =
      rootFromPath hash rightLeaf rightPath) :
    Comparison leftLeaf rightLeaf
      (PathCollision hash leftLeaf rightLeaf leftPath rightPath) := by
  induction leftPath generalizing rightPath with
  | nil =>
      cases rightPath with
      | nil =>
          by_cases sameLeaf : leftLeaf = rightLeaf
          · exact Comparison.equal sameLeaf
          · exact Comparison.collision {
              leftInput := .leaf leftLeaf
              rightInput := .leaf rightLeaf
              leftUsed := by simp [effectiveInputs]
              rightUsed := by simp [effectiveInputs]
              different := by simpa using sameLeaf
              sameKind := rfl
              sameDigest := by simpa [rootFromPath] using sameRoot
            }
      | cons step rest =>
          simp [pathSides] at sameSides
  | cons leftStep leftRest inductionHypothesis =>
      cases rightPath with
      | nil =>
          simp [pathSides] at sameSides
      | cons rightStep rightRest =>
          have sideEq : leftStep.childSide = rightStep.childSide :=
            (List.cons.inj sameSides).1
          have restSides : pathSides leftRest = pathSides rightRest :=
            (List.cons.inj sameSides).2
          let leftChild := rootFromPath hash leftLeaf leftRest
          let rightChild := rootFromPath hash rightLeaf rightRest
          have nodeDigest :
              hash (orderedInput leftStep leftChild) =
                hash (orderedInput rightStep rightChild) := by
            cases leftSide : leftStep.childSide <;>
              cases rightSide : rightStep.childSide <;>
                simpa [rootFromPath, orderedInput, leftChild, rightChild,
                  leftSide, rightSide] using sameRoot
          by_cases sameNode :
              (orderedInput leftStep leftChild : HashInput Payload Digest) =
                orderedInput rightStep rightChild
          · have childEq : leftChild = rightChild :=
              ordered_input_child_eq leftStep rightStep leftChild rightChild
                sideEq sameNode
            rcases inductionHypothesis rightRest restSides childEq with equal | collision
            · exact Comparison.equal equal
            · exact Comparison.collision {
                leftInput := collision.leftInput
                rightInput := collision.rightInput
                leftUsed := by simp [effectiveInputs, collision.leftUsed]
                rightUsed := by simp [effectiveInputs, collision.rightUsed]
                different := collision.different
                sameKind := collision.sameKind
                sameDigest := collision.sameDigest
              }
          · exact Comparison.collision {
              leftInput := orderedInput leftStep leftChild
              rightInput := orderedInput rightStep rightChild
              leftUsed := by simp [effectiveInputs, leftChild]
              rightUsed := by simp [effectiveInputs, rightChild]
              different := sameNode
              sameKind := by simp
              sameDigest := nodeDigest
            }

def compare_accepted_openings
    {Payload Digest : Type*}
    [DecidableEq Payload] [DecidableEq Digest]
    (hash : HashInput Payload Digest → Digest)
    (root : Digest) (sides : List ChildSide)
    (leftLeaf rightLeaf : Payload)
    (leftPath rightPath : AuthenticationPath Digest)
    (left : OpensAt hash root sides leftLeaf leftPath)
    (right : OpensAt hash root sides rightLeaf rightPath) :
    Comparison leftLeaf rightLeaf
      (PathCollision hash leftLeaf rightLeaf leftPath rightPath) :=
  compare_paths hash leftLeaf rightLeaf leftPath rightPath
    (left.1.trans right.1.symm) (left.2.trans right.2.symm)

/-- Both constructors use the actual RP05 Poseidon evaluators, including
all seven words of each ordered Merkle child digest. -/
def rp05PathHash : HashInput (List Nat) Digest → Digest
  | .leaf words => poseidon2V8Sponge poseidon2V8NoteDomain words
  | .node left right =>
      poseidon2V8Compress14 poseidon2V8MerkleDomain left right

theorem rp05_leaf_hash_is_note_commitment (note : V8NoteOpening) :
    rp05PathHash (.leaf (exactV8NoteWords note)) =
      exactV8NoteCommitment note := rfl

def accepted_rp05_note_words_or_effective_collision
    (root : Digest) (sides : List ChildSide)
    (left right : V8NoteOpening)
    (leftPath rightPath : AuthenticationPath Digest)
    (leftOpening : OpensAt rp05PathHash root sides
      (exactV8NoteWords left) leftPath)
    (rightOpening : OpensAt rp05PathHash root sides
      (exactV8NoteWords right) rightPath) :
    Comparison (exactV8NoteWords left) (exactV8NoteWords right)
      (PathCollision rp05PathHash (exactV8NoteWords left)
        (exactV8NoteWords right) leftPath rightPath) :=
  compare_accepted_openings rp05PathHash root sides
    (exactV8NoteWords left) (exactV8NoteWords right)
    leftPath rightPath leftOpening rightOpening

/-- A path is source-canonical when every *evaluated* node input really has
two seven-word child digests.  This rules out vacuous distinctions in extra
list words ignored by the width-16 compression frame.  The accepted source
and canonical historical tree must each supply this ordinary format fact. -/
def CanonicalEffectiveInput : HashInput (List Nat) Digest → Prop
  | .leaf words => ExactWords 18 words
  | .node left right => ExactWords 7 left ∧ ExactWords 7 right

def CanonicalEffectivePath (leaf : List Nat)
    (path : AuthenticationPath Digest) : Prop :=
  ∀ input, input ∈ effectiveInputs rp05PathHash leaf path →
    CanonicalEffectiveInput input

structure CanonicalRp05PathCollision
    (leftLeaf rightLeaf : List Nat)
    (leftPath rightPath : AuthenticationPath Digest) where
  witness : PathCollision rp05PathHash leftLeaf rightLeaf leftPath rightPath
  leftExact : CanonicalEffectiveInput witness.leftInput
  rightExact : CanonicalEffectiveInput witness.rightInput

def accepted_rp05_canonical_notes_or_collision
    (root : Digest) (sides : List ChildSide)
    (left right : V8NoteOpening)
    (leftPath rightPath : AuthenticationPath Digest)
    (leftOpening : OpensAt rp05PathHash root sides
      (exactV8NoteWords left) leftPath)
    (rightOpening : OpensAt rp05PathHash root sides
      (exactV8NoteWords right) rightPath)
    (leftCanonical : CanonicalEffectivePath (exactV8NoteWords left) leftPath)
    (rightCanonical : CanonicalEffectivePath (exactV8NoteWords right) rightPath) :
    Comparison (exactV8NoteWords left) (exactV8NoteWords right)
      (CanonicalRp05PathCollision (exactV8NoteWords left)
        (exactV8NoteWords right) leftPath rightPath) := by
  rcases accepted_rp05_note_words_or_effective_collision root sides
    left right leftPath rightPath leftOpening rightOpening with equal | collision
  · exact Comparison.equal equal
  · exact Comparison.collision {
      witness := collision
      leftExact := leftCanonical collision.leftInput collision.leftUsed
      rightExact := rightCanonical collision.rightInput collision.rightUsed
    }

end HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
