import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05FinalProgramMiddleExecution
import SmzaRp05ExecutablePcsClosureStatement

/-! An accepted actual grouped branch supplies an accepted verifier execution
and the verifier's retained nonchallenge records. The oracle and record set
are constructed from its claim database, not provided as independent replay
or transcript certificates. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedVerifierReplay

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers branchClaims rawLog)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaChallengeStageTargets (parseStageQuery)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8SmzaOracleParser (RawDigest)

noncomputable section
set_option autoImplicit false

/-- Extract the very same verifier execution from an accepted producer/verifier
branch. Repeated queries are permitted; consistency is precisely membership
of that branch's claims in this database. -/
theorem accepted_grouped_claims_supply_verifier_replay
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    (fallback : RawDigest) :
    let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle program database fallback
    let records := rawRecords
      (fun key => groupRepresentative (included program key))
      (vectorOutputBytes groupZero) database
    ∃ wire,
      producer.eval oracle = some wire ∧
      (verifierProgram ns dsl statement pending nonce wire).eval oracle = some () ∧
      ∀ call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2,
        parseStageQuery call.1 = none → call ∈ records := by
  let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  obtain ⟨sameRecord, retained⟩ :=
    actual_program_grouped_claims_replay_and_retain program branch database claims fallback
  have actualRecord : program.record oracle =
      (branchResult groupedDecode program branch, rawLog groupedDecode program branch) :=
    sameRecord
  have actualAccepted : program.eval oracle = some () := by
    calc
      program.eval oracle = (program.record oracle).1 := by simp [Program.record_result]
      _ = branchResult groupedDecode program branch := congrArg Prod.fst actualRecord
      _ = some () := accepted
  obtain ⟨wire, producerSuccess, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (fun wire => verifierProgram ns dsl statement pending nonce wire) () actualAccepted
  refine ⟨wire, producerSuccess, verifierAccepted, ?_⟩
  intro call member notChallenge
  apply retained call ?_ notChallenge
  have splitRecord := Program.record_bind_success oracle producer
    (fun wire => verifierProgram ns dsl statement pending nonce wire) wire producerSuccess
  have splitLog : rawLog groupedDecode program branch =
      (producer.record oracle).2 ++
        ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 := by
    calc
      rawLog groupedDecode program branch = (program.record oracle).2 := by rw [actualRecord]
      _ = _ := congrArg Prod.snd splitRecord
  rw [splitLog]
  exact List.mem_append.mpr (Or.inr member)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedVerifierReplay
