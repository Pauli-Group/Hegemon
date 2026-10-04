import SmzaRp05ActualEventRecertification
import SmzaRp05FilteredCollision
import SmzaRp05AdaptiveFilteredCollision

/-! The actual-event recertification interface for the collision predicate on
records outside the current authorization set. This is the filtered event
used by the same physical prefix; it is not collision over all raw records. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionEventSpec

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open SmzaRp05ActualEventRecertification
open SmzaRp05AdaptiveFilteredCollision
open SmzaRp05FilteredCollision
open SmzaRp05FilteredReadback
open V8Smz9CoherentMerkleInstrument
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05LeafNamespace
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

abbrev RawInput := V8SmzaOracleParser.RawInput

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

def filteredCollisionBase
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (authorized : Finset (List Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  filteredRawCollision ns authorized keyBytes counter

private theorem filteredCollisionBound_nonnegative (cap : Nat) :
    0 ≤ (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ) := by
  positivity

private theorem filteredCollision_instability
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (cap : Nat) (authorized : Finset (List Byte)) :
    RealInstabilityBound (filteredCollisionBase ns keyBytes counter authorized) cap
      (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ) := by
  simpa [filteredCollisionBase] using
    (filtered_raw_collision_instability ns authorized keyBytes counter cap).toReal

private theorem filteredCollision_mark_mono
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (database : Database Key (VectorOutput Counter))
    (after : filteredCollisionBase ns keyBytes counter
      (insert statement authorized) database) :
    filteredCollisionBase ns keyBytes counter authorized database := by
  simpa [filteredCollisionBase] using
    (filtered_raw_collision_mark_monotone ns authorized statement
      keyBytes counter database after)

private theorem filteredCollision_marked_write
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (marked : statement ∈ authorized) (key : Key)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (left right : Database Key (VectorOutput Counter))
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    (filteredCollisionBase ns keyBytes counter authorized left ↔
      filteredCollisionBase ns keyBytes counter authorized right) := by
  simpa [filteredCollisionBase] using
    (filtered_raw_collision_iff_of_eq_off_authorized_key ns authorized statement
      keyBytes counter key marked parsed left right sameOutside)

private theorem filteredCollision_empty_false
    (ns : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (authorized : Finset (List Byte)) :
    ¬ filteredCollisionBase ns keyBytes counter authorized
      (empty : Database Key (VectorOutput Counter)) := by
  unfold filteredCollisionBase filteredRawCollision
  apply Classical.not_not.mpr
  intro left right digest leftMember _
  have rawMember := filtered_raw_records_subset_raw ns authorized
    keyBytes counter (empty : Database Key (VectorOutput Counter)) leftMember
  simp [rawRecords] at rawMember

/-- Recertified same-prefix filtered-collision event. -/
def filteredCollisionEventSpec
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) : EventSpec ctx cap where
  base := fun authorized database =>
    filteredCollisionBase ctx.leafNamespace ctx.keyBytes ctx.counter authorized database
  bound := (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ)
  bound_nonnegative := filteredCollisionBound_nonnegative cap
  instability := by
    intro authorized
    exact filteredCollision_instability ctx.leafNamespace ctx.keyBytes
      ctx.counter cap authorized
  mark_mono := by
    intro authorized statement database after
    have eqInsert :
        @Insert.insert (List Byte) (Finset (List Byte))
          (@Finset.instInsert (List Byte) (fun a b => instDecidableEqList a b))
          statement authorized = insert statement authorized := by
      ext candidate
      simp only [Finset.mem_insert]
    change filteredCollisionBase ctx.leafNamespace ctx.keyBytes ctx.counter
        (@Insert.insert (List Byte) (Finset (List Byte))
          (@Finset.instInsert (List Byte) (fun a b => instDecidableEqList a b))
          statement authorized) database at after
    rw [eqInsert] at after
    exact filteredCollision_mark_mono ctx.leafNamespace ctx.keyBytes
      ctx.counter authorized statement database after
  marked_write := by
    intro authorized statement marked key parsed left right sameOutside
    exact filteredCollision_marked_write ctx.leafNamespace ctx.keyBytes
      ctx.counter authorized statement marked key parsed left right sameOutside
  empty_false := by
    intro authorized
    exact filteredCollision_empty_false ctx.leafNamespace ctx.keyBytes
      ctx.counter authorized

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionEventSpec
