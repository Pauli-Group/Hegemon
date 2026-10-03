import SmzaRp05AcceptedQ38AgreementBridge

/-! The current-map decoder's exact twelve identities close the algebraic
part of extraction: the same source rows satisfy the relation, or the
candidate is invalid and the actual PIOP challenges lie in their named bad
events. Source head and scalar readbacks must be supplied by the executable
verifier bridges; this module does not assume an accepted witness. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAlgebraicClosure

open SmzaRp05TracePrefixes
open SmzaRp05AcceptedExtraction
open SmzaRp05AcceptedQ38AgreementBridge
open SmzaQ38Recovery (RecoveredRows packedFromRows)
open SmzaQ38OpeningFieldReadback (ClaimedHeadsReconstructed)
open SmzaRp04ChronologicalAlgebra
open V8Smz9PiopSoundness (Matrix Opening ClaimedTranscript)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

theorem exact_current_claims_force_relation_or_piop_failure
    {model : RelationModel} (refinement : RelationRefinement model)
    (statement : Statement) (rows : RecoveredRows)
    (matrix : Matrix (model.width statement)) (response : ClaimedTranscript)
    (opening : Opening) (message : OpeningMessage)
    (statementValid : refinement.StatementValid statement)
    (heads : ClaimedHeadsReconstructed (baseOpeningPoints opening.1)
      message.claimed message.witness message.masks message.partials)
    (combinations : ∀ combination, message.claimed combination =
      SmzaQ38LvcsOpening.rowCombination rows (baseOpeningPoints opening.1) combination)
    (scalars : refinement.ScalarChecks statement rows matrix response opening message) :
    refinement.AcceptsPacked statement (packedFromRows rows) ∨
      (¬ PiopExtraction.FullySatisfied (model.recoveredCandidate statement rows).system ∧
        (matrix ∈ piopMatrixBadEvent (model.recoveredCandidate statement rows) ∨
         opening ∈ piopOpeningBadEvent (model.recoveredCandidate statement rows)
           matrix response)) := by
  classical
  by_cases valid : refinement.AcceptsPacked statement (packedFromRows rows)
  · exact Or.inl valid
  · refine Or.inr ⟨?_, ?_⟩
    · intro satisfied
      exact valid (refinement.fullySatisfiedAccepts statement rows statementValid satisfied)
    · have columns := current_heads_force_reconstructed_columns rows
        (baseOpeningPoints opening.1) message.claimed message.witness message.masks
        message.partials heads combinations
      have accepts := refinement.openingAcceptsOfReadback statement rows matrix
        response opening message columns scalars
      exact opening_acceptance_is_matrix_or_opening_bad
        (model.recoveredCandidate statement rows) matrix response opening accepts

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAlgebraicClosure
