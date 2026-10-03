import SmzaRp05CurrentFilteredCollisionEventSpec
import SmzaRp05ActiveFiberEvent

/-! The accepted classifier's one-statement, challenge-erased collision is
contained in the counted collision event on the same active fiber. Fixed
challenge entries do not create the collision charged by this theorem. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionReadback

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ConditionedExecution
open SmzaRp05ActiveFiberEvent
open SmzaRp05FilteredReadback
open SmzaRp05FilteredCollision
open SmzaRp05ChallengeRecordErasure
open SmzaRp04StatementRecordFilter
open SmzaRecordedTracePath
open SmzaChallengeStageTargets (Role)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Erasing challenge records and retaining one fresh statement can only
remove records from the outside-authorization collision relation. -/
theorem fresh_erased_collision_implies_filtered_collision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (database : Database Key (VectorOutput Counter))
    (authorized : Finset (List Byte)) (statement : List Byte)
    (fresh : statement ∉ authorized)
    (collision : ¬ RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement
        (eraseChallengeRecords
          (rawRecords keyBytes (vectorOutputBytes counter) database)))) :
    filteredRawCollision ns authorized keyBytes counter database := by
  intro free
  apply collision
  have freshFree := fresh_records_collision_free ns statement authorized fresh
    (rawRecords keyBytes (vectorOutputBytes counter) database) free
  apply recordsCollisionFree_mono _ freshFree
  intro record member
  obtain ⟨erasedMember, retained⟩ := Finset.mem_filter.mp member
  exact Finset.mem_filter.mpr ⟨(Finset.mem_filter.mp erasedMember).1, retained⟩

set_option diagnostics true in
/-- The collision arm on the merged database is charged on its exact sparse
active database, after eliminating the fixed challenge entries. -/
theorem fresh_erased_merged_collision_implies_active_filtered_collision
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (fresh : statement ∉ authorized)
    (collision : ¬ RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ctx.leafNamespace) statement
        (eraseChallengeRecords
          (rawRecords ctx.keyBytes (vectorOutputBytes ctx.counter)
            (mergeFixedActive ctx blockCap fixed active))))) :
    filteredRawCollision ctx.leafNamespace authorized
      (fun key => ctx.keyBytes key.val) ctx.counter active := by
  have recordsEq := erase_merged_records_eq_active_records ctx blockCap fixed active
  have collisionEq := congrArg
    (fun records => ¬ RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ctx.leafNamespace) statement records))
    recordsEq
  exact fresh_erased_collision_implies_filtered_collision
    (Key := SmzaRoleDomainConditioning.ActiveKey ctx.role blockCap ctx.keyBytes)
    (Counter := Counter) ctx.leafNamespace
    (fun key => ctx.keyBytes key.val) ctx.counter active authorized statement fresh
    (collisionEq.mp collision)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFilteredCollisionReadback
