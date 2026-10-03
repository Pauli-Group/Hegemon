import SmzaRp05AcceptedGlobalQueryReadback
import SmzaRp05ExecutablePcsClosureLvcsAlgebraRows
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05Q38CurrentRebinding

/-! Bind the source's 406-node DECS point vector to the exact q38 positions
authenticated by same-run global readback. -/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMcaPositionBinding

open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaQ38McaSourceBinding (Position)
open SmzaRp05Q38CurrentRebinding (smz9EvaluationPoint)
open SmzaRp05DecsPointProjection (fieldPoint fieldPoints)

set_option autoImplicit false

/-- Successful source `fieldPoints 406 indexes` is pointwise the current
q38 MCA evaluation map at every retained authenticated position. -/
theorem pcs_stages_position_binding
    (ns : SmzaRp05LeafNamespace.Namespace) (pending : Bool)
    (hPiop : V8SmzaOracleParser.RawDigest)
    (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List HegemonCrypto.CanonicalBytes.Byte)
    (statementBinding : List Nat) (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (paths : List (List V8SmzaOracleParser.RawDigest))
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle) (hashFpp : V8SmzaOracleParser.RawDigest)
    (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding statementBinding
      tapes paths oracle hashFpp finalPending)
    (positions : Fin 38 → Position)
    (positionIndexes : ∀ j, (positions j).val = stages.indexes.getD j.val 0) :
    ∀ j, stages.decsPoints.getD j.val 0 = smz9EvaluationPoint (positions j) := by
  have pointsSuccess : fieldPoints 406 stages.indexes = some stages.decsPoints :=
    stages.pointsBuilt
  simp only [fieldPoints] at pointsSuccess
  obtain ⟨pointCount, pointAt⟩ :=
    SmzaRp05ExecutablePcsClosureLvcsAlgebra.mapM_success_entry
      stages.indexes (fieldPoint 406) stages.decsPoints 0 0 pointsSuccess
  have indexCount : stages.indexes.length = 38 := by
    have queryExact := SmzaRp05ExecutablePcsClosureSampling.query_program_exact
      pending stages.openingDigest oracle
    have queryResultSuccess :
        SmzaRp05ExecutablePcsClosure.queryResult pending
          (SmzaRp05ExecutableChallengeStage.scan oracle 50 []
            (SmzaRp05ExecutableChallengeStage.counterKeys
              SmallWoodTranscript.decsFixedSamplingDomain 50 stages.openingDigest)) =
          some (stages.indexes, stages.sampledPending) := by
      rw [← queryExact]
      exact stages.queryExecuted
    unfold SmzaRp05ExecutablePcsClosure.queryResult at queryResultSuccess
    dsimp only at queryResultSuccess
    split at queryResultSuccess
    · rename_i selectedLength
      have selectedEq := Option.some.inj queryResultSuccess
      have indexesEq := congrArg Prod.fst selectedEq
      have lengthEq := congrArg List.length indexesEq
      simpa using lengthEq.symm.trans selectedLength
    · cases queryResultSuccess
  intro j
  have sourceAt := pointAt j.val (by simp [indexCount])
  have sourcePoint : fieldPoint 406 (stages.indexes.getD j.val 0) =
      some (smz9EvaluationPoint (positions j)) := by
    rw [← positionIndexes j]
    exact SmzaRp05Q38CurrentRebinding.current_field_point_matches_source
      (positions j)
  have valueEq := Option.some.inj (sourceAt.symm.trans sourcePoint)
  exact valueEq

end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureMcaPositionBinding
