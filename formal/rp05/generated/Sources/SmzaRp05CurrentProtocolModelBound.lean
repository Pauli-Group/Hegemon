import SmzaRp05GeneratedCertificates
import SmzaRp05ConcreteSuffix
import SmzaRp05RelationRefinement

/-! Concrete ex-ante width and grouped-table caps for the current source.
These facts discharge structural inputs of the accepted-execution endpoint;
they do not add a security or event-probability assumption. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentProtocolModelBound

open SmzaRp05Components
open SmzaRp05DegreeCertificateData
open SmzaRp05CsrNormalization
open SmzaRp05GeneratedCertificates
open SmzaRp05RelationRefinement
open SmzaRp05ConcreteSuffix
open SmzaChallengeStageTargets (Role)

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1600000

theorem current_csr_attempt_count : program.csrAttempts.length = 20588 := by
  rfl

theorem current_model_within_protocol :
    ModelWithinProtocol (relationModel currentDsl certificates) := by
  intro statement
  change (normalizedDsl program nonlinearRoot nodeDegree).width statement ≤ 20588
  exact normalized_dsl_width_le_attempt_bound program nonlinearRoot nodeDegree
    20588 (by decide) (le_of_eq current_csr_attempt_count) statement

theorem current_protocol_positive_caps :
    0 < protocolBlockCap .decsMatrix ∧
      0 < protocolBlockCap .piopMatrix ∧
      0 < protocolBlockCap .piopOpening := by
  obtain ⟨decs, matrix, opening, _sample⟩ := protocol_block_caps_exact
  rw [decs, matrix, opening]
  decide

end HegemonCrypto.SmallWood.SmzaRp05CurrentProtocolModelBound
