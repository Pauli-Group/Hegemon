import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedEventJoin

/-! Actual accepted invalid branch to literal events on its SAME sparse DB.
The source label, geometry, LVCS identities, scalar readouts and PIOP checks
are DERIVED from ordinary current acceptance reconstructed from actual branch
claims. The response is read from the actual parsed final PIOP frame; there
is no unfiltered any-preimage selector or desired certificate premise.
SOURCE ONLY. Stage vector/sampler inclusion and final weighted adaptive-claim
mass composition remain separate; this file does not assert G3 closure. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSameDatabaseEventJoin
open Polynomial V8Smz9PiopSoundness
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaChallengeStageTargets (Role)
open scoped Classical
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages verifierProgram)
end E
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation Satisfies)
end C
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation
  (Decoded decodedValues candidate fully_satisfied_implies_current_relation)
end D
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Counter zero Key decode keyBytes)
end G
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)
end A
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims (live activeClaims fixedCompatible)
end AC
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay (claimOracle)
end Q
namespace P
export NativePrivateSpendQ58PartitionTransport (FixedTable)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (RawDigest rawNext)
end F
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (fppLabel traceInput)
end T
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (calculatedCandidate labelFromInputs)
end S
namespace L
export NativePrivateSpendQ58CurrentActualTraceLabel
  (sourceRecords accepted_current_claimed_fiber_traces_calculate_source_or_named_bad)
end L
namespace R
export NativePrivateSpendQ58CurrentRecoveryGeometry
  (RecoveryGeometry MatrixBad SmallSupportBad geometry_has_identities_or_literal_lvcs_event)
end R
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin
  (CurrentLvcsRootEvent actualCombinationPolynomial combinationPolynomial)
end V
namespace B
export NativePrivateSpendQ58CurrentAcceptedEventJoin (PiopBad)
end B
namespace PR
export NativePrivateSpendQ58CurrentPiopRecordJoin (rawResponse current_final_raw_response)
end PR
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

private theorem current_matrix_event_of_affine {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width)
    (matrix : V8Smz9PiopSoundness.Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system
      (V8Smz9PiopSoundness.maskSum candidate) matrix) :
    matrix ∈ NativePrivateSpendQ58CurrentPiopEvents.currentMatrixEvent candidate :=
  Finset.mem_filter.mpr ⟨Finset.mem_univ matrix, affine⟩

theorem actual_geometry_has_current_witness_or_lvcs_or_piop_event
    (ns : M.Namespace) (relation : C.Relation) (pending : Bool) (nonce : Fin (2^32))
    (wire : E.Wire) (oracle : Oracle) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript)
    (records : RawRecords)
    (geometry : R.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs records) :
    (∃ source : D.Decoded, C.Satisfies relation (D.decodedValues source)) ∨
      V.CurrentLvcsRootEvent geometry.source stages.opening stages.decoded.pcs
        geometry.heads geometry.coordinates ∨
      B.PiopBad relation geometry.source stages.matrix
        (PR.rawResponse (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript)) stages.opening := by
  rcases R.geometry_has_identities_or_literal_lvcs_event ns wire stages.decoded
      stages.opening stages.pcs records geometry with identities | lvcs
  · have actualHeads := NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_heads_are_lvcs_heads
      ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
    have headsEq : geometry.heads = stages.pcs.heads :=
      Option.some.inj (geometry.headsBuilt.symm.trans actualHeads)
    have actualIdentities : ∀ combination,
        V.actualCombinationPolynomial stages.decoded.pcs stages.pcs.heads combination =
          V.combinationPolynomial geometry.source stages.opening combination := by
      intro combination
      rw [← headsEq]
      exact identities combination
    obtain ⟨witnessReadout, nonlinearReadout, linearReadout⟩ :=
      NativePrivateSpendQ58CurrentScalarEventBridge.current_same_execution_scalar_agreement
        ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs
        geometry.source stages.decodedEq stages.pcsExecuted actualIdentities
    have checks := NativePrivateSpendQ58CurrentScalarChecks.current_opened_scalars_derive_piop_checks
      relation geometry.source stages.matrix stages.opening stages.decoded.piop
      witnessReadout nonlinearReadout linearReadout
    have responseEq : PR.rawResponse (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript) =
        NativePrivateSpendQ58CurrentPiopRestoration.response relation stages.matrix stages.opening stages.decoded.piop := by
      exact (congrArg
        (fun value : E.Transcript => PR.rawResponse
          (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput value))
        stages.reconstructed).symm.trans
          (PR.current_final_raw_response relation stages.matrix stages.opening stages.decoded.piop
            stages.pcs.hashFpp stages.finalPending)
    have actualChecks : NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks
        (D.candidate relation geometry.source) stages.matrix
        (PR.rawResponse (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript)) stages.opening := by
      rw [responseEq]
      exact checks
    by_cases satisfied : PiopExtraction.FullySatisfied (D.candidate relation geometry.source).system
    · exact Or.inl ⟨geometry.source, D.fully_satisfied_implies_current_relation relation geometry.source satisfied⟩
    · by_cases affine : PiopExtraction.AffineBatchAccepts (D.candidate relation geometry.source).system
          (maskSum (D.candidate relation geometry.source)) stages.matrix
      · have matrixBad : B.PiopBad relation geometry.source stages.matrix
            (PR.rawResponse (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript)) stages.opening := by
          with_reducible
            unfold B.PiopBad
            exact Or.inl ⟨satisfied,
              current_matrix_event_of_affine (D.candidate relation geometry.source) stages.matrix affine⟩
        exact Or.inr (Or.inr matrixBad)
      · have openingBad : B.PiopBad relation geometry.source stages.matrix
            (PR.rawResponse (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript)) stages.opening := by
          with_reducible
            unfold B.PiopBad
            exact Or.inr ⟨affine, actualChecks⟩
        exact Or.inr (Or.inr openingBad)
  · exact Or.inr (Or.inl lvcs)

theorem accepted_invalid_current_branch_has_same_database_literal_event
    (producer : Program E.Wire) (ns : M.Namespace) (relation : C.Relation)
    (pending : Bool) (nonce : Fin (2^32))
    (branch : Branches G.decode (producer.bind (E.verifierProgram ns relation pending nonce)))
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := G.Counter)
      (AC.live (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps))
    (compatible : AC.fixedCompatible (producer.bind (E.verifierProgram ns relation pending nonce))
      selected GF.currentRoleCaps fixed branch)
    (database : Database (A.ActiveKey
      (AC.live (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps))
      (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (AC.activeClaims
      (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps branch) database)
    (fallback : F.RawDigest)
    (accepted : branchResult G.decode (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ())
    (invalid : ¬∃ source : D.Decoded, C.Satisfies relation (D.decodedValues source)) :
    let program := producer.bind (E.verifierProgram ns relation pending nonce)
    let oracle := Q.claimOracle program (A.merge (AC.live program selected GF.currentRoleCaps) fixed database) fallback
    let raw := rawRecords (fun key : A.ActiveKey (AC.live program selected GF.currentRoleCaps) => G.keyBytes program key.val)
      (vectorOutputBytes G.zero) database
    let records := L.sourceRecords raw
    ∃ wire, producer.eval oracle = some wire ∧
      (¬RecordsCollisionFree records ∨
        ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
          transcript.pending = false ∧
          (R.MatrixBad records stages.pcs ∨ R.SmallSupportBad records stages.pcs ∨
            ∃ geometry : R.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs records,
              S.calculatedCandidate (T.fppLabel selected (G.keyBytes program) fixed G.decode
                (extract F.rawNext raw 26 .fpp stages.pcs.hashFpp)) = some geometry.source ∧
              (V.CurrentLvcsRootEvent geometry.source stages.opening stages.decoded.pcs
                geometry.heads geometry.coordinates ∨
                B.PiopBad relation geometry.source stages.matrix
                  (PR.rawResponse (T.traceInput (extract F.rawNext raw 27 .piop wire.hPiop))) stages.opening))) := by
  obtain ⟨wire, produced, result⟩ := L.accepted_current_claimed_fiber_traces_calculate_source_or_named_bad
    producer ns relation pending nonce branch selected piopSelected fixed compatible database claims fallback accepted
  refine ⟨wire, produced, ?_⟩
  rcases result with collision | ⟨transcript, stages, clean, matrixLabel, _openingLabel,
      _openingTarget, finalFrame, recovery⟩
  · exact Or.inl collision
  · apply Or.inr
    refine ⟨transcript, stages, clean, ?_⟩
    rcases recovery with matrix | small | ⟨geometry, candidate⟩
    · exact Or.inl matrix
    · exact Or.inr (Or.inl small)
    · apply Or.inr; apply Or.inr
      refine ⟨geometry, ?_, ?_⟩
      · rw [matrixLabel]
        exact candidate
      · rcases actual_geometry_has_current_witness_or_lvcs_or_piop_event
          ns relation pending nonce wire _ transcript stages _ geometry with witness | lvcs | piop
        · exact (invalid witness).elim
        · exact Or.inl lvcs
        · apply Or.inr
          rw [finalFrame]
          exact piop

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSameDatabaseEventJoin
