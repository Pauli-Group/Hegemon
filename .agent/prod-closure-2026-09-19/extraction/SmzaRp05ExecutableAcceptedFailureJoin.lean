import SmzaRp05ExecutablePcsClosureSampling

/-!
# Deterministic public-prefix join to retained BEFORE records

Run the whole public verifier before private X-copy. Its actual recorded
queries are appended to the retained earlier public log. Acceptance creates
the reconstructed transcript, all ordinary stage outputs, and the AFTER
query. If an earlier preimage of h_piop was retained and this one combined
record relation is collision-free, that earlier input is the literal final
input of the computed transcript. Retention and collision failures remain
explicit alternatives; neither is supplied as a reconstruction certificate.

The returned stages can be frozen into the public workspace before X-copy.
The later private suffix replays only challenge-role reads. This theorem
does not identify a sparse database with its partially decompressed image.
The physical instrument must charge the public prefix and account for
retention/collision events. Native restoration-to-FiveMcaChecks and
TwelveLvcsChecks, causal filtered-trace readback and role-vector decoding
remain necessary before constructing AcceptedFailureWitness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableAcceptedFailureJoin

open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript finalInput)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
noncomputable section

def publicRecords (earlier prefixLog : Log) :
    V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest := by
  classical
  exact (earlier ++ prefixLog).toFinset

def retentionFailure (earlier : Log) (digest : RawDigest) : Prop :=
  ¬ ∃ input, (input, digest) ∈ earlier

/-- The AFTER query is derived from ordinary acceptance, then transported
only through inclusion in an explicitly supplied common record relation.
This intermediate theorem makes the measurement-retention boundary visible. -/
theorem accepted_prefix_in_common_records (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (records : V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest)
    (prefixRecorded : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 →
        call ∈ records)
    (accepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ()) :
    ∃ transcript,
      Nonempty (ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript) ∧
      transcript.pendingXofFailure = false ∧
      (finalInput transcript, wire.hPiop) ∈ records := by
  obtain ⟨transcript, stages, clean, _equal, recorded⟩ :=
    SmzaRp05ExecutablePcsClosureStatement.accepted_current_statement_has_stages
      ns dsl statement pending nonce wire oracle accepted
  exact ⟨transcript, stages, clean, prefixRecorded _ recorded⟩

/-- No final log-inclusion premise: the common relation contains the actual
prefix log by construction. On the good branch its BEFORE input is computed
reconstruction, not an independently supplied array or success certificate. -/
theorem accepted_prefix_retention_or_collision_or_reconstruction
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (earlier : Log)
    (accepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ()) :
    retentionFailure earlier wire.hPiop ∨
    ¬ RecordsCollisionFree (publicRecords earlier
      ((verifierProgram ns dsl statement pending nonce wire).record oracle).2) ∨
    ∃ transcript,
      Nonempty (ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript) ∧
      transcript.pendingXofFailure = false ∧
      (finalInput transcript, wire.hPiop) ∈ earlier := by
  classical
  by_cases retained : ∃ input, (input, wire.hPiop) ∈ earlier
  · by_cases collisionFree : RecordsCollisionFree (publicRecords earlier
        ((verifierProgram ns dsl statement pending nonce wire).record oracle).2)
    · obtain ⟨before, beforeRecorded⟩ := retained
      obtain ⟨transcript, stages, clean, afterRecorded⟩ :=
        accepted_prefix_in_common_records ns dsl statement pending nonce wire oracle
          (publicRecords earlier
            ((verifierProgram ns dsl statement pending nonce wire).record oracle).2)
          (by intro call member; simp only [publicRecords, List.mem_toFinset,
            List.mem_append]; exact Or.inr member) accepted
      have beforeInCommon : (before, wire.hPiop) ∈ publicRecords earlier
          ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 := by
        simp only [publicRecords, List.mem_toFinset, List.mem_append]
        exact Or.inl beforeRecorded
      have same := collisionFree before (finalInput transcript) wire.hPiop
        beforeInCommon afterRecorded
      exact Or.inr (Or.inr ⟨transcript, stages, clean, same ▸ beforeRecorded⟩)
    · exact Or.inr (Or.inl collisionFree)
  · exact Or.inl retained

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableAcceptedFailureJoin
