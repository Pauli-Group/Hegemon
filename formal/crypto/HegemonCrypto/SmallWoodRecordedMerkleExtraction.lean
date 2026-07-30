import HegemonCrypto.FiniteOracleDatabase
import HegemonCrypto.SmallWoodMerkleExtraction

/-!
# Recorded-query Merkle extraction

The SmallWood extractor does not invert a Merkle root or recover every leaf.  It scans the
measured random-oracle database and retains leaves for which the leaf hash and every node on one
root path were actually queried.  This file formalizes that deterministic operation.

The central theorem is local: in a collision-free recorded database, one root and one binary
coordinate determine at most one recorded payload.  Consequently all recorded openings can be
completed to one total oracle by assigning a fixed fallback payload to unopened coordinates.
No cryptographic assumption appears below; computational security later bounds the event that
the measured SHA-512 database contains a collision or omits an oracle claim used by an accepted
compiled proof.
-/

namespace HegemonCrypto.SmallWood.RecordedMerkleExtraction

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.MerkleExtraction

variable {Payload Digest Coordinate : Type*}

/--
An authentication path whose leaf and internal-node hashes are all present in one measured
oracle database.  The side list is root-to-leaf, matching `MerkleExtraction.pathSides`.
-/
inductive RecordedOpening
    (database : Database (HashInput Payload Digest) Digest) :
    Payload -> List ChildSide -> Digest -> Prop
  | leaf
      (payload : Payload)
      (digest : Digest)
      (recorded : database (.leaf payload) = some digest) :
      RecordedOpening database payload [] digest
  | left
      {payload : Payload}
      {sides : List ChildSide}
      {child sibling root : Digest}
      (childOpening : RecordedOpening database payload sides child)
      (recorded : database (.node child sibling) = some root) :
      RecordedOpening database payload (.left :: sides) root
  | right
      {payload : Payload}
      {sides : List ChildSide}
      {child sibling root : Digest}
      (childOpening : RecordedOpening database payload sides child)
      (recorded : database (.node sibling child) = some root) :
      RecordedOpening database payload (.right :: sides) root

/--
Every recorded opening determines one ordinary authentication path under any total hash oracle
consistent with the measured database.
-/
theorem recorded_opening_to_opens_at
    {database : Database (HashInput Payload Digest) Digest}
    {hash : HashInput Payload Digest -> Digest}
    (consistent : ConsistentWith hash database)
    {payload : Payload}
    {sides : List ChildSide}
    {root : Digest}
    (opening : RecordedOpening database payload sides root) :
    ∃ path : AuthenticationPath Digest,
      OpensAt hash root sides payload path := by
  induction opening with
  | leaf digest recorded =>
      refine ⟨[], ?_⟩
      constructor
      · rfl
      · simpa [rootFromPath] using consistent _ digest recorded
  | left childOpening recorded inductionHypothesis =>
      rename_i childSides childDigest siblingDigest parentDigest
      obtain ⟨childPath, childAccepted⟩ := inductionHypothesis
      refine
        ⟨{ sibling := siblingDigest,
           childSide := .left } :: childPath, ?_⟩
      constructor
      · simpa [pathSides] using congrArg (List.cons ChildSide.left) childAccepted.1
      · simp only [rootFromPath]
        rw [childAccepted.2]
        exact consistent _ _ recorded
  | right childOpening recorded inductionHypothesis =>
      rename_i childSides childDigest siblingDigest parentDigest
      obtain ⟨childPath, childAccepted⟩ := inductionHypothesis
      refine
        ⟨{ sibling := siblingDigest,
           childSide := .right } :: childPath, ?_⟩
      constructor
      · simpa [pathSides] using congrArg (List.cons ChildSide.right) childAccepted.1
      · simp only [rootFromPath]
        rw [childAccepted.2]
        exact consistent _ _ recorded

/--
Collision-free recorded hashing gives position binding directly on the measured database.  The
proof never assumes that a finite hash is globally injective.
-/
theorem recorded_opening_payload_unique
    {database : Database (HashInput Payload Digest) Digest}
    (collisionFree : CollisionFree database)
    {leftPayload rightPayload : Payload}
    {sides : List ChildSide}
    {root : Digest}
    (leftOpening :
      RecordedOpening database leftPayload sides root)
    (rightOpening :
      RecordedOpening database rightPayload sides root) :
    leftPayload = rightPayload := by
  induction leftOpening generalizing rightPayload with
  | leaf root leftRecorded =>
      cases rightOpening with
      | leaf _ rightRecorded =>
          have sameInput :
              HashInput.leaf leftPayload =
                HashInput.leaf rightPayload :=
            input_unique_of_same_recorded_output
              collisionFree leftRecorded rightRecorded
          exact HashInput.leaf.inj sameInput
  | left leftChildOpening leftRecorded inductionHypothesis =>
      cases rightOpening with
      | left rightChildOpening rightRecorded =>
          have sameInput :
              HashInput.node _ _ = HashInput.node _ _ :=
            input_unique_of_same_recorded_output
              collisionFree leftRecorded rightRecorded
          have sameChild :
              _ = _ :=
            (HashInput.node.inj sameInput).1
          subst sameChild
          exact inductionHypothesis rightChildOpening
  | right leftChildOpening leftRecorded inductionHypothesis =>
      cases rightOpening with
      | right rightChildOpening rightRecorded =>
          have sameInput :
              HashInput.node _ _ = HashInput.node _ _ :=
            input_unique_of_same_recorded_output
              collisionFree leftRecorded rightRecorded
          have sameChild :
              _ = _ :=
            (HashInput.node.inj sameInput).2
          subst sameChild
          exact inductionHypothesis rightChildOpening

/-- A concrete payload is recorded at one root and coordinate. -/
def RecordedAt
    (database : Database (HashInput Payload Digest) Digest)
    (root : Digest)
    (sides : Coordinate -> List ChildSide)
    (coordinate : Coordinate)
    (payload : Payload) : Prop :=
  RecordedOpening database payload (sides coordinate) root

/--
The canonical extracted payload is the unique recorded payload when one exists, and a fixed
fallback otherwise.  Choice does not enter the trusted statement: uniqueness below proves that
every accepted recorded opening has exactly this value.
-/
noncomputable def extractedPayload
    (fallback : Payload)
    (database : Database (HashInput Payload Digest) Digest)
    (root : Digest)
    (sides : Coordinate -> List ChildSide)
    (coordinate : Coordinate) : Payload := by
  classical
  exact
    if present :
        ∃ payload, RecordedAt database root sides coordinate payload then
      Classical.choose present
    else
      fallback

theorem recorded_at_extracted_payload
    (fallback : Payload)
    {database : Database (HashInput Payload Digest) Digest}
    (collisionFree : CollisionFree database)
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    {coordinate : Coordinate}
    {payload : Payload}
    (recorded : RecordedAt database root sides coordinate payload) :
    extractedPayload fallback database root sides coordinate = payload := by
  let present :
      ∃ selected,
        RecordedAt database root sides coordinate selected :=
    ⟨payload, recorded⟩
  rw [extractedPayload, dif_pos present]
  exact recorded_opening_payload_unique collisionFree
    (Classical.choose_spec present) recorded

/-- Total oracle obtained from every leaf recorded under one root. -/
noncomputable def extractedOracle
    (fallback : Payload)
    (database : Database (HashInput Payload Digest) Digest)
    (root : Digest)
    (sides : Coordinate -> List ChildSide) :
    Coordinate -> Payload :=
  fun coordinate =>
    extractedPayload fallback database root sides coordinate

/-- Every recorded opening agrees with the canonical total extracted oracle. -/
theorem recorded_at_extracted_oracle
    (fallback : Payload)
    {database : Database (HashInput Payload Digest) Digest}
    (collisionFree : CollisionFree database)
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    {coordinate : Coordinate}
    {payload : Payload}
    (recorded : RecordedAt database root sides coordinate payload) :
    extractedOracle fallback database root sides coordinate = payload :=
  recorded_at_extracted_payload fallback collisionFree recorded

end HegemonCrypto.SmallWood.RecordedMerkleExtraction
