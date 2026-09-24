import HegemonCrypto.FiniteOracleDatabase
import Mathlib.Data.List.Basic

/-!
# SmallWood Merkle opening extraction

This file proves the information-theoretic part of binary Merkle commitment binding.  The tree is
parameterized by one domain-tagged hash on either a leaf payload or an ordered pair of child
digests.  If that hash has no collision, two accepted openings at the same binary index and root
must expose the same leaf payload.

The result deliberately does not assume a generic `CommitmentBinding` proposition.  Its sole
cryptographic premise is injectivity of the tagged hash on the concrete inputs reached by the
opening paths.  A computational security theorem can replace this pointwise premise with the event
that no SHA-512 collision occurs in the adversary's compressed-oracle database.
-/

namespace HegemonCrypto.SmallWood.MerkleExtraction

/-- Domain-separated inputs to the binary Merkle hash. -/
inductive HashInput (Payload Digest : Type*)
  | leaf : Payload -> HashInput Payload Digest
  | node : Digest -> Digest -> HashInput Payload Digest
deriving DecidableEq, Repr

/-- Position of the child digest relative to its sibling. -/
inductive ChildSide
  | left
  | right
deriving DecidableEq, Repr

structure AuthenticationStep (Digest : Type*) where
  sibling : Digest
  childSide : ChildSide
deriving DecidableEq, Repr

abbrev AuthenticationPath (Digest : Type*) := List (AuthenticationStep Digest)

/--
Root-to-leaf path representation.  The head contains the sibling immediately below the root; the
recursive tail is evaluated first, then the head combines that child digest with its sibling.
-/
def rootFromPath
    {Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (leaf : Payload) :
    AuthenticationPath Digest -> Digest
  | [] => hash (.leaf leaf)
  | step :: remaining =>
      let child := rootFromPath hash leaf remaining
      match step.childSide with
      | .left => hash (.node child step.sibling)
      | .right => hash (.node step.sibling child)

def pathSides
    {Digest : Type*}
    (path : AuthenticationPath Digest) : List ChildSide :=
  path.map AuthenticationStep.childSide

def OpensAt
    {Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (root : Digest)
    (sides : List ChildSide)
    (leaf : Payload)
    (path : AuthenticationPath Digest) : Prop :=
  pathSides path = sides ∧ rootFromPath hash leaf path = root

/--
With a collision-free tagged hash, an accepted opening at one fixed binary index determines one
leaf payload.  Siblings may differ a priori; equality of the root forces equality recursively.
-/
theorem leaf_unique_of_same_root_and_sides
    {Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (hashInjective : Function.Injective hash)
    {leftLeaf rightLeaf : Payload}
    {leftPath rightPath : AuthenticationPath Digest}
    (sameSides : pathSides leftPath = pathSides rightPath)
    (sameRoot :
      rootFromPath hash leftLeaf leftPath =
        rootFromPath hash rightLeaf rightPath) :
    leftLeaf = rightLeaf := by
  induction leftPath generalizing rightPath with
  | nil =>
      cases rightPath with
      | nil =>
          have inputEqual := hashInjective sameRoot
          exact HashInput.leaf.inj inputEqual
      | cons rightStep rightRemaining =>
          simp [pathSides] at sameSides
  | cons leftStep leftRemaining inductionHypothesis =>
      cases rightPath with
      | nil =>
          simp [pathSides] at sameSides
      | cons rightStep rightRemaining =>
          have headSide :
              leftStep.childSide = rightStep.childSide := by
            exact List.cons.inj sameSides |>.1
          have tailSides :
              pathSides leftRemaining = pathSides rightRemaining := by
            exact List.cons.inj sameSides |>.2
          cases leftStep with
          | mk leftSibling leftSide =>
              cases rightStep with
              | mk rightSibling rightSide =>
                  cases leftSide <;> cases rightSide
                  · have inputEqual := hashInjective sameRoot
                    have childEqual :
                        rootFromPath hash leftLeaf leftRemaining =
                          rootFromPath hash rightLeaf rightRemaining :=
                      HashInput.node.inj inputEqual |>.1
                    exact inductionHypothesis tailSides childEqual
                  · contradiction
                  · contradiction
                  · have inputEqual := hashInjective sameRoot
                    have childEqual :
                        rootFromPath hash leftLeaf leftRemaining =
                          rootFromPath hash rightLeaf rightRemaining :=
                      HashInput.node.inj inputEqual |>.2
                    exact inductionHypothesis tailSides childEqual

/-- Two accepted openings at the same root and index expose the same leaf payload. -/
theorem accepted_openings_have_unique_leaf
    {Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (hashInjective : Function.Injective hash)
    {root : Digest}
    {sides : List ChildSide}
    {leftLeaf rightLeaf : Payload}
    {leftPath rightPath : AuthenticationPath Digest}
    (leftOpening : OpensAt hash root sides leftLeaf leftPath)
    (rightOpening : OpensAt hash root sides rightLeaf rightPath) :
    leftLeaf = rightLeaf := by
  exact leaf_unique_of_same_root_and_sides hash hashInjective
    (leftOpening.1.trans rightOpening.1.symm)
    (leftOpening.2.trans rightOpening.2.symm)

/--
Contrapositive form used in the extraction reduction: two different leaves accepted at one root
and binary index exhibit a collision in the tagged hash.
-/
theorem different_accepted_leaves_exhibit_hash_collision
    {Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    {root : Digest}
    {sides : List ChildSide}
    {leftLeaf rightLeaf : Payload}
    {leftPath rightPath : AuthenticationPath Digest}
    (differentLeaves : leftLeaf ≠ rightLeaf)
    (leftOpening : OpensAt hash root sides leftLeaf leftPath)
    (rightOpening : OpensAt hash root sides rightLeaf rightPath) :
    ∃ leftInput rightInput,
      leftInput ≠ rightInput ∧ hash leftInput = hash rightInput := by
  by_contra noCollision
  have hashInjective : Function.Injective hash := by
    intro leftInput rightInput sameDigest
    by_contra differentInput
    exact noCollision ⟨leftInput, rightInput, differentInput, sameDigest⟩
  exact differentLeaves
    (accepted_openings_have_unique_leaf hash hashInjective leftOpening rightOpening)

/-!
## Multi-opening extraction

The deployed verifier opens many leaves under one root.  Modelling the batch as a function over an
index type avoids any accidental dependence on list order or duplicate-elimination details.
-/

structure MultiOpening
    (Index Payload Digest : Type*)
    (hash : HashInput Payload Digest -> Digest)
    (root : Digest) where
  sides : Index -> List ChildSide
  leaf : Index -> Payload
  path : Index -> AuthenticationPath Digest
  accepted : ∀ index,
    OpensAt hash root (sides index) (leaf index) (path index)

/-- At fixed coordinates, one collision-free Merkle root determines the whole opened leaf map. -/
theorem accepted_multi_openings_have_unique_leaves
    {Index Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (hashInjective : Function.Injective hash)
    {root : Digest}
    (left right : MultiOpening Index Payload Digest hash root)
    (sameCoordinates : left.sides = right.sides) :
    left.leaf = right.leaf := by
  funext index
  exact accepted_openings_have_unique_leaf hash hashInjective
    (left.accepted index)
    (by
      simpa [sameCoordinates] using right.accepted index)

/--
If two accepted multi-openings at the same coordinates disagree anywhere, they expose one concrete
tagged-hash collision.
-/
theorem different_accepted_multi_openings_exhibit_hash_collision
    {Index Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    {root : Digest}
    (left right : MultiOpening Index Payload Digest hash root)
    (sameCoordinates : left.sides = right.sides)
    (differentLeaves : left.leaf ≠ right.leaf) :
    ∃ leftInput rightInput,
      leftInput ≠ rightInput ∧ hash leftInput = hash rightInput := by
  by_contra noCollision
  have hashInjective : Function.Injective hash := by
    intro leftInput rightInput sameDigest
    by_contra differentInput
    exact noCollision ⟨leftInput, rightInput, differentInput, sameDigest⟩
  exact differentLeaves
    (accepted_multi_openings_have_unique_leaves hash hashInjective
      left right sameCoordinates)

end HegemonCrypto.SmallWood.MerkleExtraction
