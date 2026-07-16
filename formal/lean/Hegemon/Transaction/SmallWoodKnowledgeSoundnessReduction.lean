namespace Hegemon
namespace Transaction
namespace SmallWoodKnowledgeSoundnessReduction

universe uStatement uProof uTranscript uOpenings uRows uWitness

structure ProtocolModel
    (Statement : Type uStatement)
    (Proof : Type uProof)
    (Transcript : Type uTranscript)
    (Openings : Type uOpenings)
    (Rows : Type uRows)
    (Witness : Type uWitness) where
  verifies : Statement → Proof → Bool
  transcriptOf : Statement → Proof → Transcript
  openingsOf : Statement → Proof → Openings
  rowsOf : Statement → Proof → Rows
  extract : Statement → Proof → Option Witness
  relation : Statement → Witness → Prop
  statementBindingAccepted : Statement → Proof → Prop
  transcriptAccepted : Statement → Transcript → Prop
  openingsAccepted : Statement → Transcript → Openings → Prop
  rowsAccepted : Statement → Openings → Rows → Prop

structure PrimitiveFailurePredicates
    (Statement : Type uStatement)
    (Proof : Type uProof) where
  merkleOrCommitmentHashCollision : Statement → Proof → Prop
  transcriptRandomOracleFailure : Statement → Proof → Prop
  pcsOpeningBindingFailure : Statement → Proof → Prop
  airPolynomialSoundnessFailure : Statement → Proof → Prop
  witnessExtractionFailure : Statement → Proof → Prop

def ProtocolSoundnessFailure
    {Statement : Type uStatement}
    {Proof : Type uProof}
    (failures : PrimitiveFailurePredicates Statement Proof)
    (statement : Statement)
    (proof : Proof) : Prop :=
  failures.merkleOrCommitmentHashCollision statement proof
    ∨ failures.transcriptRandomOracleFailure statement proof
    ∨ failures.pcsOpeningBindingFailure statement proof
    ∨ failures.airPolynomialSoundnessFailure statement proof
    ∨ failures.witnessExtractionFailure statement proof

structure KnowledgeSoundnessReduction
    {Statement : Type uStatement}
    {Proof : Type uProof}
    {Transcript : Type uTranscript}
    {Openings : Type uOpenings}
    {Rows : Type uRows}
    {Witness : Type uWitness}
    (model : ProtocolModel Statement Proof Transcript Openings Rows Witness)
    (failures : PrimitiveFailurePredicates Statement Proof) : Prop where
  verifierToStatementBinding :
    ∀ statement proof,
      model.verifies statement proof = true →
        model.statementBindingAccepted statement proof
          ∨ failures.merkleOrCommitmentHashCollision statement proof
  statementBindingToTranscript :
    ∀ statement proof,
      model.statementBindingAccepted statement proof →
        model.transcriptAccepted statement (model.transcriptOf statement proof)
          ∨ failures.transcriptRandomOracleFailure statement proof
  transcriptToPcsOpenings :
    ∀ statement proof,
      model.transcriptAccepted statement (model.transcriptOf statement proof) →
        model.openingsAccepted statement
            (model.transcriptOf statement proof)
            (model.openingsOf statement proof)
          ∨ failures.pcsOpeningBindingFailure statement proof
  pcsOpeningsToAirRows :
    ∀ statement proof,
      model.openingsAccepted statement
          (model.transcriptOf statement proof)
          (model.openingsOf statement proof) →
        model.rowsAccepted statement
            (model.openingsOf statement proof)
            (model.rowsOf statement proof)
          ∨ failures.airPolynomialSoundnessFailure statement proof
  airRowsToWitness :
    ∀ statement proof,
      model.rowsAccepted statement
          (model.openingsOf statement proof)
          (model.rowsOf statement proof) →
        (exists witness,
            model.extract statement proof = some witness
              ∧ model.relation statement witness)
          ∨ failures.witnessExtractionFailure statement proof

theorem accepted_protocol_yields_witness_or_named_failure
    {Statement : Type uStatement}
    {Proof : Type uProof}
    {Transcript : Type uTranscript}
    {Openings : Type uOpenings}
    {Rows : Type uRows}
    {Witness : Type uWitness}
    {model : ProtocolModel Statement Proof Transcript Openings Rows Witness}
    {failures : PrimitiveFailurePredicates Statement Proof}
    (reduction : KnowledgeSoundnessReduction model failures)
    {statement : Statement}
    {proof : Proof}
    (accepted : model.verifies statement proof = true) :
    (exists witness,
        model.extract statement proof = some witness
          ∧ model.relation statement witness)
      ∨ ProtocolSoundnessFailure failures statement proof := by
  rcases reduction.verifierToStatementBinding statement proof accepted with
    statementBound | hashFailure
  · rcases reduction.statementBindingToTranscript statement proof statementBound with
      transcriptAccepted | transcriptFailure
    · rcases reduction.transcriptToPcsOpenings statement proof transcriptAccepted with
        openingsAccepted | pcsFailure
      · rcases reduction.pcsOpeningsToAirRows statement proof openingsAccepted with
          rowsAccepted | airFailure
        · rcases reduction.airRowsToWitness statement proof rowsAccepted with
            witness | extractionFailure
          · exact Or.inl witness
          · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr extractionFailure))))
        · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl airFailure))))
      · exact Or.inr (Or.inr (Or.inr (Or.inl pcsFailure)))
    · exact Or.inr (Or.inr (Or.inl transcriptFailure))
  · exact Or.inr (Or.inl hashFailure)

theorem accepted_protocol_yields_witness_outside_named_failures
    {Statement : Type uStatement}
    {Proof : Type uProof}
    {Transcript : Type uTranscript}
    {Openings : Type uOpenings}
    {Rows : Type uRows}
    {Witness : Type uWitness}
    {model : ProtocolModel Statement Proof Transcript Openings Rows Witness}
    {failures : PrimitiveFailurePredicates Statement Proof}
    (reduction : KnowledgeSoundnessReduction model failures)
    {statement : Statement}
    {proof : Proof}
    (accepted : model.verifies statement proof = true)
    (noFailure : ¬ ProtocolSoundnessFailure failures statement proof) :
    exists witness,
      model.extract statement proof = some witness
        ∧ model.relation statement witness := by
  rcases accepted_protocol_yields_witness_or_named_failure reduction accepted with
    witness | failure
  · exact witness
  · exact False.elim (noFailure failure)

end SmallWoodKnowledgeSoundnessReduction
end Transaction
end Hegemon
