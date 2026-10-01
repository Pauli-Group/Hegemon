import SmzaRp05PhysicalPcsRecordRetention

/-!
# Same-run PCS `hash_fpp` record retention

The `hash_fpp` query is part of the actual PCS program continuation.  This
file lifts its record through that continuation and then through the already
proved PCS/verifier/accepted-physical-run chronology.  No externally supplied
retention relation is assumed.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalHashFppRecordRetention

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure
  (pcsProgram queryProgram widths deltas nativeFiveMcaGate406 currentTwelveLvcsGate406)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableChallengeStage (PostMerkle postMerkleProgram)
open SmzaRp05PcsWireProjection (DecodedMiddleWire fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun branchResult rawLog basisOracle)
open HegemonCrypto.CmsCompressedOracle (State Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open HegemonCrypto.SmallWood (Goldilocks)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

attribute [local irreducible]
  SmzaRp05PcsWireProjection.reconstructedHeadsAll
  SmzaRp05PcsWireProjection.decsOpeningInput
  SmzaRp05DecsPointProjection.fieldPoints
  SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
  SmzaRp05PcsMerklePayload.makeMerkleInput
  SmzaRp05ExecutableChallengeStage.postMerkleProgram
  SmzaRp05DecsResponseProjection.hashFppProgram
  SmzaRp05ExecutablePcsClosure.queryProgram

/-- Once the containing PCS program succeeds with these exact stage records,
every query/response record made by `stages.hashProgram` occurs in that
successful PCS program's ordered record. -/
theorem pcs_hash_fpp_records_retained
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decs : DecodedDecsResponseFields)
    (points : List Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (hashFpp : RawDigest) (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (executed : (pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths).eval oracle = some (hashFpp, finalPending)) :
    ∀ raw output,
      (raw, output) ∈ (stages.hashProgram.record oracle).2 →
      (raw, output) ∈
        ((pcsProgram ns pending hPiop wire decs points salt binding
          statementBinding tapes paths).record oracle).2 := by
  let afterPost : List Nat → List (List Goldilocks) → List Goldilocks →
      PostMerkle → Program (RawDigest × Bool) := fun indexes rows decsPoints post =>
    match SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
        (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows post)
        (decsPoints.map SmzaRp05ExecutableRestore.toWord)
        140 368 statementBinding with
    | none => .done none
    | some hashProgram =>
        match SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
            (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows post)
            (decsPoints.map SmzaRp05ExecutableRestore.toWord)
            140 368 with
        | none => .done none
        | some polynomials =>
            if nativeFiveMcaGate406 salt tapes indexes
                (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                (SmzaRp05PcsHashFppMiddle.gammaRows post) decs.maskingEvals
                (decsPoints.map SmzaRp05ExecutableRestore.toWord) polynomials then
              hashProgram.bind fun digest => .done (some (digest, post.pending))
            else .done none
  let afterQuery : List Nat × Bool → Program (RawDigest × Bool) :=
    fun (indexes, sampledPending) =>
      match SmzaRp05DecsPointProjection.fieldPoints 406 indexes with
      | none => .done none
      | some decsPoints =>
          match SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
              wire.pcs points decsPoints wire.rowScalars 64 widths deltas
              2 368 140 38 with
          | none => .done none
          | some rows =>
              if currentTwelveLvcsGate406 stages.heads
                  (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
                  points decsPoints rows then
                match SmzaRp05PcsMerklePayload.makeMerkleInput salt binding
                    sampledPending indexes rows decs.maskingEvals tapes paths with
                | none => .done none
                | some input =>
                    (postMerkleProgram ns input).bind (afterPost indexes rows decsPoints)
              else .done none
  have programForm :
      pcsProgram ns pending hPiop wire decs points salt binding statementBinding
        tapes paths =
      (ask stages.openingInput).bind fun openingDigest =>
      (queryProgram pending openingDigest).bind afterQuery := by
    unfold pcsProgram
    rw [stages.headsBuilt]
    dsimp only
    rw [stages.openingBuilt]
    congr 1
  have opened := executed
  rw [programForm] at opened
  obtain ⟨openingDigest, openingRead, afterOpening⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (ask stages.openingInput) _ (hashFpp, finalPending) opened
  have openingEq : openingDigest = stages.openingDigest :=
    Option.some.inj (openingRead.symm.trans stages.openingRead)
  subst openingDigest
  obtain ⟨queryPair, queryRead, afterQueryEval⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (queryProgram pending stages.openingDigest) _ (hashFpp, finalPending) afterOpening
  have queryEq : queryPair = (stages.indexes, stages.sampledPending) :=
    Option.some.inj (queryRead.symm.trans stages.queryExecuted)
  subst queryPair
  have afterQuerySuccess :
      (afterQuery (stages.indexes, stages.sampledPending)).eval oracle =
        some (hashFpp, finalPending) := by
    simpa [afterQuery, stages.pointsBuilt, stages.rowsBuilt] using afterQueryEval
  have gate : currentTwelveLvcsGate406 stages.heads
      (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
      points stages.decsPoints stages.rows := by
    by_contra h
    simp [Program.eval, afterQuery, stages.pointsBuilt, stages.rowsBuilt, h]
      at afterQuerySuccess
  have hashTail :
      (stages.hashProgram.record oracle).2 ⊆
        ((afterQuery (stages.indexes, stages.sampledPending)).record oracle).2 := by
    have afterQueryEq :
        afterQuery (stages.indexes, stages.sampledPending) =
          (postMerkleProgram ns stages.merkleInput).bind
            (afterPost stages.indexes stages.rows stages.decsPoints) := by
      simp [afterQuery, stages.pointsBuilt, stages.rowsBuilt, gate,
        stages.inputBuilt]
    have afterPostEq :
        afterPost stages.indexes stages.rows stages.decsPoints stages.post =
          stages.hashProgram.bind fun digest => .done (some (digest, stages.post.pending)) := by
      have afterPostEval :
          (afterPost stages.indexes stages.rows stages.decsPoints stages.post).eval oracle =
            some (hashFpp, finalPending) := by
        have bindSuccess := afterQuerySuccess
        rw [afterQueryEq] at bindSuccess
        obtain ⟨actualPost, postRead, continuation⟩ :=
          SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (postMerkleProgram ns stages.merkleInput)
            (afterPost stages.indexes stages.rows stages.decsPoints)
            (hashFpp, finalPending) bindSuccess
        have postEq : actualPost = stages.post :=
          Option.some.inj (postRead.symm.trans stages.postExecuted)
        subst actualPost
        exact continuation
      have hashProgramEq :
          SmzaRp05DecsResponseProjection.hashFppProgram stages.post.root decs
            (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
            (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 statementBinding =
          some stages.hashProgram := stages.responseBuilt
      have restoredExists : ∃ polynomials,
          SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
            (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
            (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
            some polynomials := by
        have responseBuilt := stages.responseBuilt
        unfold SmzaRp05DecsResponseProjection.hashFppProgram
          at responseBuilt
        unfold SmzaRp05DecsResponseProjection.responseTranscriptWords
          at responseBuilt
        cases h : SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
            (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
            (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
            (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 with
        | none => simp [h] at responseBuilt
        | some polynomials => exact ⟨polynomials, rfl⟩
      obtain ⟨polynomials, polynomialsEq⟩ := restoredExists
      have nativeGate : nativeFiveMcaGate406 salt tapes stages.indexes
          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post) decs.maskingEvals
          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) polynomials := by
        by_contra h
        simp [Program.eval, afterPost, hashProgramEq, polynomialsEq, h] at afterPostEval
      simp [afterPost, hashProgramEq, polynomialsEq, nativeGate]
    rw [afterQueryEq]
    have postContinuation := Program.bind_log_right oracle
      (postMerkleProgram ns stages.merkleInput)
      (afterPost stages.indexes stages.rows stages.decsPoints)
      stages.post stages.postExecuted
    intro call member
    apply postContinuation
    rw [afterPostEq]
    exact Program.bind_log_left oracle stages.hashProgram
      (fun digest => .done (some (digest, stages.post.pending))) hashFpp stages.hashExecuted member
  have queryLogIncluded := Program.bind_log_right oracle
    (queryProgram pending stages.openingDigest) afterQuery
    (stages.indexes, stages.sampledPending) stages.queryExecuted
  have openingLogIncluded := Program.bind_log_right oracle
    (ask stages.openingInput)
    (fun openingDigest => (queryProgram pending openingDigest).bind afterQuery)
    stages.openingDigest stages.openingRead
  intro raw output member
  have inAfterQuery := hashTail member
  have inQuery := queryLogIncluded inAfterQuery
  have inOpening := openingLogIncluded inQuery
  rw [programForm]
  exact inOpening

/-- The actual PCS hash program's record is retained in the verifier record
of the same successful `ExecutionStages` run. -/
theorem execution_hash_fpp_records_retained_in_verifier
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement pending
      statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (transcriptSuccess :
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).eval oracle = some transcript) :
    ∀ call,
      call ∈ (pcs.hashProgram.record oracle).2 →
      call ∈ ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire).record oracle).2 := by
  have pcsSuccess := execution.pcsExecuted
  have pcsRetained := pcs_hash_fpp_records_retained ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs pcsSuccess
  have verifierRetained :=
    SmzaRp05PhysicalPcsRecordRetention.execution_pcs_records_retained_in_verifier
      ns dsl statement pending nonce wire oracle transcript execution transcriptSuccess
  intro call member
  exact verifierRetained call (pcsRetained call.1 call.2 member)

/-- The actual `hash_fpp` program record is contained in the raw records of
the same nonzero accepted physical branch.  The branch split identifies the
verifier suffix, and the PCS-to-verifier containment above follows its
successful source binds. -/
theorem accepted_physical_run_hash_fpp_records_in_raw_log
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype RawDigest] [DecidableEq RawDigest] [AddCommGroup RawDigest]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key) (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire))
    (state : State Key RawDigest Phase Work)
    (basis : Basis Key RawDigest Phase Work) (fallback : RawDigest)
    (nonzero : globalDecompress
      (physicalRun encode (fun (_ : RawInput) (answer : RawDigest) => answer)
        (producer.bind fun wire =>
          SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
            pending nonce wire) branch state) basis ≠ 0)
    (accepted : branchResult (fun (_ : RawInput) (answer : RawDigest) => answer)
      (producer.bind fun wire =>
        SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire) branch = some ()) :
    ∃ wire, ∃ transcript,
      ∃ execution : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement pending
        statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback) transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        wire.tapes wire.paths
        (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
          basis fallback)
        execution.hashFpp execution.pcsPending,
      producer.eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback) = some wire ∧
      (SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire).eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback) = some () ∧
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).eval
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer) basis fallback) =
        some transcript ∧
      ∀ call,
        call ∈ (pcs.hashProgram.record
          (basisOracle encode (fun (_ : RawInput) (answer : RawDigest) => answer)
            basis fallback)).2 →
        call ∈ rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
          (producer.bind fun wire =>
            SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
              pending nonce wire) branch := by
  let decode : RawInput → RawDigest → RawDigest :=
    fun (_ : RawInput) (answer : RawDigest) => answer
  let oracle := basisOracle encode decode basis fallback
  obtain ⟨wire, producerSuccess, verifierAccepted, rawSplit, _eventDichotomy⟩ :=
    SmzaRp05PhysicalProducerVerifierPrefix.accepted_physical_producer_prefix_dichotomy
      encode producer ns dsl statement pending nonce branch state basis fallback
      nonzero accepted
  obtain ⟨transcript, transcriptSuccess, _clean, _hashEq, _finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
      statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement) nonce wire
      oracle verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement
      pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement) nonce wire oracle
      transcript transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages ns
      execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending execution.pcsExecuted
  have retained := execution_hash_fpp_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution pcs transcriptSuccess
  refine ⟨wire, transcript, execution, pcs, producerSuccess, verifierAccepted,
    transcriptSuccess, ?_⟩
  intro call member
  have inVerifier := retained call member
  change call ∈ rawLog (fun (_ : RawInput) (answer : RawDigest) => answer)
    (producer.bind fun wire =>
      SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
        pending nonce wire) branch
  rw [rawSplit]
  exact List.mem_append.mpr (Or.inr inVerifier)

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalHashFppRecordRetention
