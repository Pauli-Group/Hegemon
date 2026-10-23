import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedSourceWitnessOrBad
import HegemonCrypto.NativePrivateSpendQ58CurrentCausalSourceJoin

/-! The actual current source witness supplies G1 semantics on exactly its
calculated packed assignment. No detached satisfying witness is substituted.
The pipeline, producer result, PCS output, recovery geometry and decoder
identity remain in the conclusion. Retained F1 interprets original graph/CSR
and native chronology data; no efficient extraction theorem is asserted. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSameSourceSemanticJoin
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches)
namespace J
export NativePrivateSpendQ58CurrentCanonicalSourceClassifier
  (root sourceOracle records SourceWitness Choice accepted_source_witness_or_chosen_role)
end J
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages)
end E
namespace X
export NativePrivateSpendQ58CurrentSourceSelectorTransport (SourceView)
end X
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues)
end D
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (decode)
end G
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry)
end RG
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance sourcePrimeFact : Fact (Nat.Prime HegemonCrypto.NativePrivateSpendLocalSemantics.modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

variable (producer : Program E.Wire)
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (nonce : Fin (2^32))
local notation "Root" => J.root producer ns relation nonce
variable (branch : Branches (Output := V8Smz9CoherentVectorMerkle.VectorOutput
      NativePrivateSpendQ58CurrentConstructorGrouping.Counter) (Result := Unit) G.decode
      (J.root producer ns relation nonce))
    (view : X.SourceView (J.root producer ns relation nonce))
local notation "OracleAt" => J.sourceOracle producer ns relation nonce branch view

def recoveredAssignment (source : D.Decoded) : Nat → Goldilocks :=
  HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.sourceAssignment (D.decodedValues source)

def NativeSemanticSource
    (branch : Branches (Output := V8Smz9CoherentVectorMerkle.VectorOutput
      NativePrivateSpendQ58CurrentConstructorGrouping.Counter) (Result := Unit) G.decode
      (J.root producer ns relation nonce))
    (view : X.SourceView (J.root producer ns relation nonce))
    (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks) : Prop :=
  ∃ wire, producer.eval (J.sourceOracle producer ns relation nonce branch view) = some wire ∧
      ∃ transcript, ∃ stages : E.ExecutionStages ns relation false nonce wire (J.sourceOracle producer ns relation nonce branch view) transcript,
        transcript.pending = false ∧
        ∃ geometry : RG.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs
            (J.records producer ns relation nonce view),
          NativePrivateSpendQ58CurrentRecovery.decoded
            NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint
            (NativePrivateSpendQ58CurrentOrdinaryRecovery.actualView
              (J.records producer ns relation nonce view) stages.pcs) = some geometry.source ∧
          HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.Current.Satisfies relation
            (D.decodedValues geometry.source) ∧
          HegemonCrypto.NativePrivateSpendPackedLowering.StructuralSemantics
            graph layout (recoveredAssignment geometry.source)

/-- G3's actual SAME-source witness supplies the G1 relation/assignment
interpretation on its produced trace, with no supplied validity premise. -/
theorem actual_source_witness_supplies_same_native_semantics
    (branch : Branches (Output := V8Smz9CoherentVectorMerkle.VectorOutput
      NativePrivateSpendQ58CurrentConstructorGrouping.Counter) (Result := Unit) G.decode
      (J.root producer ns relation nonce))
    (view : X.SourceView (J.root producer ns relation nonce))
    (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks)
    (csr : HegemonCrypto.NativePrivateSpendCsrCertificate.RawCSR Goldilocks)
    (certificate : HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.RelationCertificate
      relation graph layout csr)
    (witness : J.SourceWitness producer ns relation nonce branch view) :
    NativeSemanticSource producer ns relation nonce branch view graph layout := by
  obtain ⟨wire, produced, transcript, stages, clean, geometry, _identities, _full, valid⟩ := witness
  refine ⟨wire, produced, transcript, stages, clean, geometry, geometry.calculated, valid, ?_⟩
  exact HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.relation_derives_structural_semantics
    relation (D.decodedValues geometry.source) valid graph layout csr certificate

/-- The actual accepted source classifier is consumed directly: its
unconditional same-trace witness arm becomes native semantics, and every
literal current collision/bad-role arm remains explicit. Missing raw claims
must still be charged on the unchanged original physical branch. -/
theorem actual_accepted_source_has_native_semantics_or_named_bad
    (branch : Branches (Output := V8Smz9CoherentVectorMerkle.VectorOutput
      NativePrivateSpendQ58CurrentConstructorGrouping.Counter) (Result := Unit) G.decode
      (J.root producer ns relation nonce))
    (view : X.SourceView (J.root producer ns relation nonce))
    (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks)
    (csr : HegemonCrypto.NativePrivateSpendCsrCertificate.RawCSR Goldilocks)
    (certificate : HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.RelationCertificate
      relation graph layout csr)
    (consistent : NativePrivateSpendQ58CurrentSourceCompletion.Consistent
      (NativePrivateSpendQ58CurrentClaimReplay.fullClaims Root branch))
    (claims : NativePrivateSpendQ58CurrentSourceCompletion.SourceClaims Root branch view)
    (accepted : SmzaRp05PhysicalAcceptedReplayLite.branchResult G.decode Root branch = some ()) :
    ¬ SmzaRecordedTracePath.RecordsCollisionFree (J.records producer ns relation nonce view) ∨
      (∃ role, J.Choice producer ns relation nonce branch role view) ∨
      NativeSemanticSource producer ns relation nonce branch view graph layout := by
  rcases J.accepted_source_witness_or_chosen_role producer ns relation nonce branch view
      consistent claims accepted with collision | chosen | witness
  · exact Or.inl collision
  · exact Or.inr (Or.inl chosen)
  · exact Or.inr (Or.inr (actual_source_witness_supplies_same_native_semantics
      producer ns relation nonce branch view graph layout csr certificate witness))

/-- Any canonical readout on those exact same records and PCS output returns
that same source. This is deterministic decoder identity, not a new extractor
or a witness/outcome validity assumption. -/
theorem same_records_decoder_identifies_source
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (wire : E.Wire) (decoded : NativePrivateSpendQ58CurrentExecutableVerifier.DecodedFields)
    (opening : NativePrivateSpendQ58CurrentExecutableVerifier.Opening)
    (output : NativePrivateSpendQ58CurrentExecutableVerifier.PcsOutput)
    (records : SmzaRp05FilteredDecoderInstability.RawRecords)
    (geometry : RG.RecoveryGeometry ns wire decoded opening output records)
    (source : D.Decoded)
    (readout : NativePrivateSpendQ58CurrentRecovery.decoded
      NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint
      (NativePrivateSpendQ58CurrentOrdinaryRecovery.actualView records output) = some source) :
    source = geometry.source ∧ recoveredAssignment source = recoveredAssignment geometry.source := by
  have same : source = geometry.source := Option.some.inj (readout.symm.trans geometry.calculated)
  exact ⟨same, congrArg recoveredAssignment same⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSameSourceSemanticJoin
