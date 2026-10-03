import HegemonCrypto.SmallWoodMerkleExtraction

/-!
# Accumulated SmallWood Merkle extraction

The BCS extractor observes authenticated leaves across several rewound verifier
executions.  A theorem about one multi-opening is therefore insufficient: the
extractor needs one database that remains consistent as new coordinates are
opened.

This module proves the exact deterministic statement.  At one fixed root and
one fixed coordinate-to-path map, every accepted opening accumulated over any
number of rounds assigns the same payload to a coordinate, unless the tagged
Merkle hash has a collision.
-/

namespace HegemonCrypto.SmallWood.AccumulatedMerkleExtraction

open HegemonCrypto.SmallWood.MerkleExtraction

/-- One accepted leaf learned during one extractor rewind. -/
structure AcceptedLeaf
    (Coordinate Payload Digest : Type*)
    (hash : HashInput Payload Digest -> Digest)
    (root : Digest)
    (sides : Coordinate -> List ChildSide) where
  coordinate : Coordinate
  leaf : Payload
  path : AuthenticationPath Digest
  accepted : OpensAt hash root (sides coordinate) leaf path

/-- A payload is present in the accumulated extractor database at `coordinate`. -/
def ExtractedAt
    {Coordinate Payload Digest : Type*}
    {hash : HashInput Payload Digest -> Digest}
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    (trace : List (AcceptedLeaf Coordinate Payload Digest hash root sides))
    (coordinate : Coordinate)
    (payload : Payload) : Prop :=
  ∃ record ∈ trace,
    record.coordinate = coordinate ∧ record.leaf = payload

/--
Every accumulated accepted opening at one coordinate has one unique payload
under collision-free tagged hashing.
-/
theorem extracted_at_unique
    {Coordinate Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (hashInjective : Function.Injective hash)
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    {trace : List (AcceptedLeaf Coordinate Payload Digest hash root sides)}
    {coordinate : Coordinate}
    {leftPayload rightPayload : Payload}
    (leftExtracted : ExtractedAt trace coordinate leftPayload)
    (rightExtracted : ExtractedAt trace coordinate rightPayload) :
    leftPayload = rightPayload := by
  obtain ⟨leftRecord, _leftMember, leftCoordinate, leftLeaf⟩ := leftExtracted
  obtain ⟨rightRecord, _rightMember, rightCoordinate, rightLeaf⟩ := rightExtracted
  subst leftPayload
  subst rightPayload
  have sameSides :
      sides leftRecord.coordinate = sides rightRecord.coordinate := by
    rw [leftCoordinate, rightCoordinate]
  exact accepted_openings_have_unique_leaf hash hashInjective
    leftRecord.accepted
    (by simpa [sameSides] using rightRecord.accepted)

/--
If an accumulated trace assigns two different payloads to one coordinate, it
constructively exposes a collision in the exact tagged Merkle hash input.
-/
theorem inconsistent_extracted_database_exhibits_hash_collision
    {Coordinate Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    {trace : List (AcceptedLeaf Coordinate Payload Digest hash root sides)}
    {coordinate : Coordinate}
    {leftPayload rightPayload : Payload}
    (differentPayloads : leftPayload ≠ rightPayload)
    (leftExtracted : ExtractedAt trace coordinate leftPayload)
    (rightExtracted : ExtractedAt trace coordinate rightPayload) :
    ∃ leftInput rightInput,
      leftInput ≠ rightInput ∧ hash leftInput = hash rightInput := by
  obtain ⟨leftRecord, _leftMember, leftCoordinate, leftLeaf⟩ := leftExtracted
  obtain ⟨rightRecord, _rightMember, rightCoordinate, rightLeaf⟩ := rightExtracted
  have recordLeavesDifferent : leftRecord.leaf ≠ rightRecord.leaf := by
    intro sameLeaves
    apply differentPayloads
    rw [← leftLeaf, ← rightLeaf, sameLeaves]
  have sameSides :
      sides leftRecord.coordinate = sides rightRecord.coordinate := by
    rw [leftCoordinate, rightCoordinate]
  exact different_accepted_leaves_exhibit_hash_collision hash
    recordLeavesDifferent leftRecord.accepted
    (by simpa [sameSides] using rightRecord.accepted)

/-- Collision freedom makes the accumulated database a well-defined finite map. -/
def AccumulatedDatabaseConsistent
    {Coordinate Payload Digest : Type*}
    {hash : HashInput Payload Digest -> Digest}
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    (trace : List (AcceptedLeaf Coordinate Payload Digest hash root sides)) : Prop :=
  ∀ coordinate leftPayload rightPayload,
    ExtractedAt trace coordinate leftPayload ->
    ExtractedAt trace coordinate rightPayload ->
      leftPayload = rightPayload

theorem accumulated_database_consistent_of_hash_injective
    {Coordinate Payload Digest : Type*}
    (hash : HashInput Payload Digest -> Digest)
    (hashInjective : Function.Injective hash)
    {root : Digest}
    {sides : Coordinate -> List ChildSide}
    (trace : List (AcceptedLeaf Coordinate Payload Digest hash root sides)) :
    AccumulatedDatabaseConsistent trace := by
  intro coordinate leftPayload rightPayload leftExtracted rightExtracted
  exact extracted_at_unique hash hashInjective leftExtracted rightExtracted

end HegemonCrypto.SmallWood.AccumulatedMerkleExtraction
