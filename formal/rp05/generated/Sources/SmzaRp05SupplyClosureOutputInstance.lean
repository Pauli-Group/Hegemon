import SmzaRp05SupplyClosureOutputFrame
import SmzaRp05DirectCsrCertificate

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputInstance

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputFrame

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem cell_member (cell : NoteCell) (bound : boundCell cell) :
    exactAttempt cell ∈ program.csrAttempts := by
  have lift573 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0573) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 573) (by decide)) member
  have lift574 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0574) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 574) (by decide)) member
  have lift575 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0575) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 575) (by decide)) member
  change exactAttempt cell ∈ exactCsrAttempts
  rcases cell with ⟨output, block, lane⟩
  fin_cases output <;> fin_cases block <;> fin_cases lane
  all_goals try (simp_all [boundCell])
  all_goals
    first
    | apply lift573
      decide
    | apply lift574
      decide
    | apply lift575
      decide

private theorem target_realizes (cell : NoteCell) :
    Realizes program.csrExpressions (expectedTarget cell)
      (.constant (expectedConstant cell)) := by
  rcases cell with ⟨output, block, lane⟩
  fin_cases output <;> fin_cases block <;> fin_cases lane <;>
    exact Realizes.constant (by decide +revert)

def certificate : Certificate program where
  canonical := SmzaRp05DirectCsrCertificate.certificate.csrCanonicalWithRows
  one := SmzaRp05DirectCsrCertificate.certificate.oneRealizes
  negative := SmzaRp05DirectCsrCertificate.certificate.derivedMinusOneRealizes
  target := target_realizes
  attempt := fun cell _ => exactAttempt cell
  member := cell_member
  exactTerms := by intro cell bound; rfl
  exactTarget := by intro cell bound; rfl

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputInstance
