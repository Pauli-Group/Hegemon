import HegemonCrypto.NativePrivateSpendQ58CurrentLvcsEventJoin

/-! Current PCS acceptance to computed recovery geometry or literal bad
events. Every field of RecoveryGeometry is a derived output. The final caller
supplies actual program acceptance, never a desired geometry certificate. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRecoveryGeometry
open NativePrivateSpendQ58CurrentExecutableVerifier
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9McaRecovery V8Smz9McaDecoder NativeHtlcUniversalMatrix
open SmzaRp05PcsWireProjection SmzaRp05LvcsWireProjection
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport
  (currentPoint priorData priorMasks
    pcs_execution_has_prior_support_or_named_bad_arm stages_pcs_pending_false)
end L
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery
  (Position PriorBad actualView actualSample pcs_current_point_injective
    supported_sample_recovers_or_matrix_or_small_support)
end O
namespace R
export NativePrivateSpendQ58CurrentRecovery (support decoded)
end R
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded)
end D
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin
  (discrepancy actualCombinationPolynomial combinationPolynomial
   executed_recovered_current_discrepancy_roots current_combinations_equal_or_literal_root_event)
end V
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace encodeLeaf)
end M
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F

def MatrixBad (prior : RawRecords) (output : PcsOutput) : Prop :=
  BadMatrix L.currentPoint 13172 360448 (O.actualView prior output).data
    (O.actualView prior output).masks (O.actualView prior output).coefficients

def SmallSupportBad (prior : RawRecords) (output : PcsOutput) : Prop :=
  ∃ coordinates : Fin 58 → O.Position, ∃ distinct : Function.Injective coordinates,
    (∀ j, (coordinates j).val = output.indexes.getD j.val 0) ∧
    (R.support L.currentPoint (O.actualView prior output)).card < 360448 ∧
    (O.actualSample coordinates distinct).val ⊆
      R.support L.currentPoint (O.actualView prior output)

structure RecoveryGeometry (ns : M.Namespace) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (output : PcsOutput)
    (prior : RawRecords) where
  source : D.Decoded
  calculated : R.decoded L.currentPoint (O.actualView prior output) = some source
  sourceDataDegree : ∀ row, (source.data row).natDegree ≤ 13172
  coordinates : Fin 58 → O.Position
  distinct : Function.Injective coordinates
  indicesEq : ∀ j, (coordinates j).val = output.indexes.getD j.val 0
  supported : Finset.univ.image coordinates ⊆ R.support L.currentPoint (O.actualView prior output)
  readbacks : ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
    (extract F.rawNext prior 25 .root output.root) =
      some (M.encodeLeaf output.input.binding (output.input.payloads j))
  heads : FMatrix
  headsBuilt : reconstructAllHeads decoded.pcs (List.ofFn (points opening)) decoded.rowScalars
    64 widths deltas 2 13115 = some heads
  roots : ∀ combination j, (V.discrepancy source opening decoded.pcs heads combination).eval
    (L.currentPoint (coordinates j)) = 0

/-- The direct recovery success arm is strengthened by actual sampled
coordinates, path readout and the twelve derived LVCS root equations. -/
theorem pcs_execution_has_geometry_or_named_bad_event
    (ns : M.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (prior : RawRecords)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output)
    (clean : output.pending = false) :
    O.PriorBad ns decoded oracle output prior ∨ MatrixBad prior output ∨
      SmallSupportBad prior output ∨
      Nonempty (RecoveryGeometry ns wire decoded opening output prior) := by
  by_cases collision : ¬ RecordsCollisionFree prior
  · exact Or.inl (Or.inr (Or.inr (Or.inl collision)))
  have free : RecordsCollisionFree prior := not_not.mp collision
  rcases L.pcs_execution_has_prior_support_or_named_bad_arm
      ns pending wire decoded opening oracle output executed clean prior with
    absent | responseCollision | priorCollision | ⟨coordinates, distinct, indicesEq, paths⟩
  · exact Or.inl (Or.inl absent)
  · exact Or.inl (Or.inr (Or.inl responseCollision))
  · exact Or.inl (Or.inr (Or.inr (Or.inl priorCollision)))
  · by_cases missing : ∃ j, ¬ RecordedPath F.rawNext prior .root output.root
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (M.encodeLeaf output.input.binding (output.input.payloads j))
    · exact Or.inl (Or.inr (Or.inr (Or.inr ⟨coordinates, distinct, indicesEq, missing⟩)))
    have recorded : ∀ j, RecordedPath F.rawNext prior .root output.root
        (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (M.encodeLeaf output.input.binding (output.input.payloads j)) := by
      intro j
      exact not_not.mp (fun denied => missing ⟨j, denied⟩)
    have readbacks : ∀ j, readPath (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (extract F.rawNext prior 25 .root output.root) =
          some (M.encodeLeaf output.input.binding (output.input.payloads j)) := by
      intro j
      exact recorded_path_readback F.rawNext prior free .root output.root _
        _ (recorded j) 25 (by simp only [List.length_cons, SmzaRp05FilteredReadback.index_path_length]; decide)
    have supported : Finset.univ.image coordinates ⊆ R.support L.currentPoint (O.actualView prior output) := by
      rcases paths with impossible | support
      · exact (missing impossible).elim
      · exact support
    have injective := O.pcs_current_point_injective ns pending wire decoded opening oracle
      output executed coordinates indicesEq
    cases calculated : R.decoded L.currentPoint (O.actualView prior output) with
    | none =>
        have result := O.supported_sample_recovers_or_matrix_or_small_support
          (O.actualView prior output) injective coordinates distinct supported
        rcases result with recovered | matrix | small
        · obtain ⟨source, decoderEq, _⟩ := recovered
          rw [calculated] at decoderEq
          cases decoderEq
        · exact Or.inr (Or.inl matrix)
        · exact Or.inr (Or.inr (Or.inl ⟨coordinates, distinct, indicesEq, small⟩))
    | some source =>
        have degrees := decoded_source_agrees_and_has_bounded_degree L.currentPoint injective
          13172 (R.support L.currentPoint (O.actualView prior output))
          (L.priorData prior output.root) (L.priorMasks prior output.root) source calculated
        obtain ⟨heads, headsBuilt, roots⟩ :=
          V.executed_recovered_current_discrepancy_roots ns pending wire decoded opening
            oracle output executed prior source calculated coordinates indicesEq supported readbacks
        exact Or.inr (Or.inr (Or.inr
          ⟨⟨source, calculated, degrees.2.2.2, coordinates, distinct,
            indicesEq, supported, readbacks, heads, headsBuilt, roots⟩⟩))

/-- Pointwise completeness: any derived current geometry either gives all
twelve actual polynomial identities or produces one literal nonzero
discrepancy vanishing at all58 actual sampled positions. -/
theorem geometry_has_identities_or_literal_lvcs_event
    (ns : M.Namespace) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (output : PcsOutput) (prior : RawRecords)
    (geometry : RecoveryGeometry ns wire decoded opening output prior) :
    (∀ combination, V.actualCombinationPolynomial decoded.pcs geometry.heads combination =
      V.combinationPolynomial geometry.source opening combination) ∨
    NativePrivateSpendQ58CurrentLvcsEventJoin.CurrentLvcsRootEvent
      geometry.source opening decoded.pcs geometry.heads geometry.coordinates := by
  exact V.current_combinations_equal_or_literal_root_event geometry.source opening
    decoded.pcs geometry.heads geometry.coordinates geometry.roots

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRecoveryGeometry
