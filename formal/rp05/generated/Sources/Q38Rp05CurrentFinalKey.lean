import Q38Rp05CurrentNonleafCompiler
/-!
# Current SMZA physical-request component

This source module contains one declaration layer of the complete RP05
request. Definitions and proof statements are preserved unchanged.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewFinalInput
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped Classical
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- The final transcript hash has 3113 words under the current SMZA profile.
Its 25029-byte input cannot alias a current 2511-byte leaf. -/
def currentFinalKey (bound : Nat) (largeEnough : 25029 ≤ bound)
    (hashFpp : DigestRegister) (coefficients : Q) :
    Rp05OtherRawInput bound :=
  let words := (sourceFinalWords (sourceDigestPrefix hashFpp)
    coefficients).map Fin.val
  rp05SourceCounterKey bound SmallWoodTranscript.piopTranscriptDomain words
    (by simp only [words, List.length_map, source_final_word_count]
        have role : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
        rw [role]
        omega)
    (by simp only [words, List.length_map, source_final_word_count]
        have role : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
        rw [role]
        decide) ⟨0, by norm_num⟩

theorem current_final_key_is_literal_input
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (hashFpp : DigestRegister) (coefficients : Q) :
    rp05RawBytes (.inr (currentFinalKey bound largeEnough hashFpp coefficients)) =
      counterInput (rp05SourcePrefix SmallWoodTranscript.piopTranscriptDomain
        ((sourceFinalWords (sourceDigestPrefix hashFpp) coefficients).map Fin.val))
        ⟨0, by norm_num⟩ := by
  simpa [currentFinalKey] using
    (rp05_source_counter_key_is_literal_input bound
      SmallWoodTranscript.piopTranscriptDomain
      ((sourceFinalWords (sourceDigestPrefix hashFpp) coefficients).map Fin.val)
      (by
        simp only [List.length_map, source_final_word_count]
        have role : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
        rw [role]
        omega)
      (by
        simp only [List.length_map, source_final_word_count]
        have role : SmallWoodTranscript.piopTranscriptDomain.length = 40 := by decide
        rw [role]
        decide)
      ⟨0, by norm_num⟩)

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
