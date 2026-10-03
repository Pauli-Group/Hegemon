import SmzaRp05NoteFrameCertificate
import SmzaRp05Components
import SmzaRp05DirectCsrCertificate

/-! Finite RP05 note-source certificate candidate for the SHA-pinned fixture.
These `decide` checks must still be run by the serial Lean lane. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NoteFrameInstance

open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05Components
open Hegemon.Transaction.Poseidon2V8RelationProgram

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem exact_member : ∀ cell : NoteCell, ∀ _ : boundCell cell,
    exactAttempt cell ∈
      HegemonCrypto.SmallWood.SmzaRp05Components.program.csrAttempts := by
  have lift492 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0492) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 492) (by decide)) member
  have lift493 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0493) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 493) (by decide)) member
  have lift494 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0494) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 494) (by decide)) member
  intro cell bound
  change exactAttempt cell ∈ exactCsrAttempts
  rcases cell with ⟨input, block, lane⟩
  fin_cases input <;> fin_cases block <;> fin_cases lane
  all_goals try (simp_all [boundCell])
  all_goals
    first
    | apply lift492
      decide
    | apply lift493
      decide
    | apply lift494
      decide

def certificate : Certificate
    HegemonCrypto.SmallWood.SmzaRp05Components.program where
  canonical := SmzaRp05DirectCsrCertificate.certificate.csrCanonicalWithRows
  one := SmzaRp05DirectCsrCertificate.certificate.oneRealizes
  negative := SmzaRp05DirectCsrCertificate.certificate.derivedMinusOneRealizes
  target := by
    intro cell
    rcases cell with ⟨input, block, lane⟩
    fin_cases input <;> fin_cases block <;> fin_cases lane <;>
      exact Realizes.constant (by decide)
  attempt := fun cell _ => exactAttempt cell
  member := exact_member
  exactTerms := by intro cell bound; rfl
  exactTarget := by intro cell bound; rfl

end HegemonCrypto.SmallWood.SmzaRp05NoteFrameInstance
