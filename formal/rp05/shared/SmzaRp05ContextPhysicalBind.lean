import SmzaRp05ContextExtractionAccounting

/-! Exact physical decomposition of a context-output producer and verifier.

The finite key universe/encoder is held fixed for the ENTIRE composed program.
The verifier starts from the producer's actual unnormalized physical state.
There is no oracle reset, conditional independence or incoming-unit assumption.
This closes the local bind transport only. The accepted extraction/event
classifier on this shared ambient key space is still required for H2.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ContextPhysicalBind

open HegemonCrypto.CmsCompressedOracle
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult answerLog physicalRun physicalReadStep)
open SmzaRp05ContextExtractionAccounting (ProducedContext contextProducingVerifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 16000
set_option maxHeartbeats 1000000

variable {Key Output Phase Work : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase]
  [Fintype Work] [DecidableEq Work]

/-- Every accepted bind branch has an exact successful prefixBranch and suffixBranch,
including its complete answer log and its unnormalized physical amplitude. -/
theorem accepted_bind_physical_decomposition {α β : Type}
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (program : Program α) (next : α → Program β)
    (branch : Branches decode (program.bind next)) (result : β)
    (accepted : branchResult decode (program.bind next) branch = some result)
    (initial : State Key Output Phase Work) :
    ∃ (value : α) (prefixBranch : Branches decode program)
        (suffixBranch : Branches decode (next value)),
      branchResult decode program prefixBranch = some value ∧
      branchResult decode (next value) suffixBranch = some result ∧
      answerLog decode (program.bind next) branch =
        answerLog decode program prefixBranch ++ answerLog decode (next value) suffixBranch ∧
      physicalRun encode decode (program.bind next) branch initial =
        physicalRun encode decode (next value) suffixBranch
          (physicalRun encode decode program prefixBranch initial) := by
  induction program generalizing initial with
  | done outcome =>
      cases outcome with
      | none => cases branch; cases accepted
      | some value => exact ⟨value, PUnit.unit, branch, rfl, accepted, rfl, rfl⟩
  | read raw tail ih =>
      rcases branch with ⟨answer, tailBranch⟩
      have acceptedTail :
          branchResult decode ((tail (decode raw answer)).bind next) tailBranch =
            some result := accepted
      obtain ⟨value, prefixBranch, suffixBranch, prefixAccepted, suffixAccepted, logs, states⟩ :=
        ih (decode raw answer) tailBranch acceptedTail
          (physicalReadStep (encode raw) answer initial)
      refine ⟨value, ⟨answer, prefixBranch⟩, suffixBranch, prefixAccepted, suffixAccepted, ?_, states⟩
      simpa only [Program.bind, answerLog, List.cons_append] using
        congrArg (List.cons (raw, answer)) logs

/-- Instantiation for the actual context-producing target introduced in H2.
The arbitrary encoder can be the single all-branches finite encoder of the
WHOLE contextProducingVerifierProgram; it is not replaced at the split. -/
theorem accepted_context_output_physical_decomposition
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (producer : Program ProducedContext)
    (branch : Branches decode (contextProducingVerifierProgram producer))
    (accepted : branchResult decode (contextProducingVerifierProgram producer) branch = some ())
    (initial : State Key Output Phase Work) :
    ∃ (produced : ProducedContext) (prefixBranch : Branches decode producer)
        (suffixBranch : Branches decode
          (SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
            produced.statement produced.pending produced.nonce produced.wire)),
      branchResult decode producer prefixBranch = some produced ∧
      branchResult decode
        (SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
          produced.statement produced.pending produced.nonce produced.wire) suffixBranch = some () ∧
      answerLog decode (contextProducingVerifierProgram producer) branch =
        answerLog decode producer prefixBranch ++ answerLog decode
          (SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
            produced.statement produced.pending produced.nonce produced.wire) suffixBranch ∧
      physicalRun encode decode (contextProducingVerifierProgram producer) branch initial =
        physicalRun encode decode
          (SmzaRp05ExecutablePcsClosureStatement.verifierProgram produced.ns currentDsl
            produced.statement produced.pending produced.nonce produced.wire) suffixBranch
          (physicalRun encode decode producer prefixBranch initial) :=
  accepted_bind_physical_decomposition encode decode producer _ branch () accepted initial

open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05PhysicalAcceptedReplayLite (branchKeys branchAnswers branchClaims rawLog)
open SmzaRp05CurrentFiniteGroupedProgram (included)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaChallengeStageTargets (parseStageQuery)

/-- Actual replay on the all-branches ambient finite key universe of the
composed program. The produced value can contain an oracle-adaptive context.
The suffix's nonchallenge calls are retained in the SAME database's records.
No per-context key embedding or independent postselected oracle is used. -/
theorem accepted_bind_grouped_claims_replay {α β : Type}
    (producer : Program α) (continuation : α → Program β)
    (branch : Branches groupedDecode (producer.bind continuation)) (result : β)
    (accepted : branchResult groupedDecode (producer.bind continuation) branch = some result)
    (database : Database (SmzaRp05CurrentFiniteGroupedProgram.Key
      (producer.bind continuation)) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (SmzaRp05CurrentFiniteGroupedProgram.encode (producer.bind continuation))
          groupedDecode (producer.bind continuation) branch)
        (branchAnswers (SmzaRp05CurrentFiniteGroupedProgram.encode (producer.bind continuation))
          groupedDecode (producer.bind continuation) branch)) database)
    (fallback : RawDigest) :
    let program := producer.bind continuation
    let oracle := finiteGroupedDatabaseOracle program database fallback
    let records := rawRecords
      (fun key => groupRepresentative (included program key))
      (vectorOutputBytes groupZero) database
    ∃ value, producer.eval oracle = some value ∧
      (continuation value).eval oracle = some result ∧
      ∀ call ∈ ((continuation value).record oracle).2,
        parseStageQuery call.1 = none → call ∈ records := by
  let program := producer.bind continuation
  let oracle := finiteGroupedDatabaseOracle program database fallback
  obtain ⟨sameRecord, retained⟩ :=
    actual_program_grouped_claims_replay_and_retain program branch database claims fallback
  have actualRecord : program.record oracle =
      (branchResult groupedDecode program branch, rawLog groupedDecode program branch) :=
    sameRecord
  have actualAccepted : program.eval oracle = some result := by
    calc
      program.eval oracle = (program.record oracle).1 := by simp [Program.record_result]
      _ = branchResult groupedDecode program branch := congrArg Prod.fst actualRecord
      _ = some result := accepted
  obtain ⟨value, producerSuccess, continuationAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      continuation result actualAccepted
  refine ⟨value, producerSuccess, continuationAccepted, ?_⟩
  intro call member notChallenge
  apply retained call ?_ notChallenge
  have splitRecord := Program.record_bind_success oracle producer continuation value producerSuccess
  have splitLog : rawLog groupedDecode program branch =
      (producer.record oracle).2 ++ ((continuation value).record oracle).2 := by
    calc
      rawLog groupedDecode program branch = (program.record oracle).2 := by rw [actualRecord]
      _ = _ := congrArg Prod.snd splitRecord
  rw [splitLog]
  exact List.mem_append.mpr (Or.inr member)

end
end HegemonCrypto.SmallWood.SmzaRp05ContextPhysicalBind
