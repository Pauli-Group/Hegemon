import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05ExecutablePcsClosureOpening

/-! # Current executed opening readback

This bridge exposes the current-profile opening sampler's actual raw-oracle
answers from a successful assembled execution. It does not use the historical
role-frame advice constructor: the input words are the literal current
`openingFieldInputs`, and the successful nonce is the one retained by
`ExecutionStages`.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedEarlierReadback

open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureOpening (DecodedAt)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open V8Smz9PiopSoundness (Opening)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
noncomputable section

/-- A clean accepted `ExecutionStages` value determines the same-oracle
first-success opening scan. Every nonce before the selected proof nonce has
an executed six-word read that fails the typed opening decoder; the selected
nonce's executed read decodes to the `opening` stored by that very run. -/
theorem execution_stages_readback_current_opening
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript)
    (openingClean : stages.openingPending = false) :
    ∃ before after,
      List.range 16 = before ++ nonce.val :: after ∧
      (∀ earlier, earlier ∈ before →
        DecodedAt oracle wire.hPiop earlier none) ∧
      DecodedAt oracle wire.hPiop nonce.val (some stages.opening) := by
  exact SmzaRp05ExecutablePcsClosureOpening.canonical_opening_clean
    pending nonce wire.hPiop oracle stages.opening stages.openingPending
    stages.openingExecuted openingClean |>.2

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedEarlierReadback
