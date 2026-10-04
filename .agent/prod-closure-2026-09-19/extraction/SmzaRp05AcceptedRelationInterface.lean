import SmzaRp05RelationModelCore
import SmzaQ38OpeningFieldReadbackR3
import SmzaRp04ChronologicalAlgebra

/-! The algebraic relation-refinement record, independent of accepted traces. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedExtraction

open SmzaRp05TracePrefixes SmzaRp05StatementNamespace
open SmzaQ38Recovery V8Smz9PiopSoundness V8Smz9EagerSimulator
open V8Smz9AdaptiveFiniteAccounting
open SmzaRp04ChronologicalAlgebra

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

/-- The minimal relation-specific algebra/refinement boundary. `ScalarChecks`
is intended to be the exact conjunction reconstructed from the generated CSR,
not an alias for `OpeningAccepts` or for the final extraction conclusion. -/
structure RelationRefinement (model : RelationModel) where
  StatementValid : Statement → Prop
  AcceptsPacked : Statement → List Nat → Prop
  ScalarChecks : (statement : Statement) → RecoveredRows →
    Matrix (model.width statement) → ClaimedTranscript → Opening →
    OpeningMessage → Prop
  openingAcceptsOfReadback :
    ∀ (statement : Statement) (rows : RecoveredRows)
      (matrix : Matrix (model.width statement)) (response : ClaimedTranscript)
      (opening : Opening) (message : OpeningMessage),
      reconstructedColumnEvaluations (baseOpeningPoints opening.1)
          message.witness message.masks message.partials =
        (fun openingIndex column =>
          (SmzaQ38LvcsOpening.recoveredColumn rows column).eval
            (baseOpeningPoints opening.1 openingIndex)) →
      ScalarChecks statement rows matrix response opening message →
      OpeningAccepts (model.recoveredCandidate statement rows)
        matrix response opening
  fullySatisfiedAccepts :
    ∀ (statement : Statement) (rows : RecoveredRows),
      StatementValid statement →
      PiopExtraction.FullySatisfied
          (model.recoveredCandidate statement rows).system →
        AcceptsPacked statement (packedFromRows rows)

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedExtraction
