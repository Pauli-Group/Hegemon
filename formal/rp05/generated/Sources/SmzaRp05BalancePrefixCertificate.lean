import SmzaRp05Components
import SmzaRp04BalanceCore

/-! Finite, source-pinned first-1244-node balance prefix for the current RP05
nonlinear DAG. This is only one field of `BalanceCertificate`. -/
namespace HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components (attempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
  (densePrivateAddress denseDigitAddress denseTopAddress)

set_option autoImplicit false
set_option maxRecDepth 10000

theorem rp05_prefix_eq_rp04 :
    SmzaRp05Components.exactNonlinearExpressions.take 1244 =
      SmzaRp04Components.exactNonlinearExpressions.take 1244 := by
  decide

theorem nonlinearPrefix :
    SmzaRp05Components.program.nonlinearExecutable.expressions.take 1244 =
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions.take 1244 := by
  exact rp05_prefix_eq_rp04.trans SmzaRp04BalanceCore.nonlinear_prefix_eq

theorem baseRoots : ∀ root, root < 1244 →
    root ∈ SmzaRp04Components.exactNonlinearRoots →
      root ∈ SmzaRp05Components.program.nonlinearExecutable.roots := by
  have checked : SmzaRp04Components.exactNonlinearRoots.all
      (fun root => decide (root < 1244 →
        root ∈ SmzaRp05Components.exactNonlinearRoots)) = true := by
    decide
  intro root bound member
  change root ∈ SmzaRp05Components.exactNonlinearRoots
  exact (decide_eq_true_eq.mp
    ((List.all_eq_true.mp checked) root member)) bound

theorem csrPrefix :
    SmzaRp05Components.program.csrExpressions.take 192 =
      SmzaRp04Components.exactCsrExpressions.take 192 := by
  decide

private def noteBridgeAttempt (note word : Nat) : CsrExecutableAttempt :=
  attempt
    (if note < 2 then 15759 + 39 * note + word
      else 18337 + 39 * (note - 2) + word)
    (if note < 2 then 14 else 23)
    (39 * (note % 2) + word) 0
    [(hashInitialIndex ([1, 38, 75, 78].getD note 0) word, 1),
      (densePrivateAddress note + 64 * word, 160)] 0

theorem noteBridges : ∀ note, note < 4 → ∀ word, word < 2 →
    ∃ row ∈ SmzaRp05Components.program.csrAttempts,
      row.terms =
        [(hashInitialIndex ([1, 38, 75, 78].getD note 0) word, 1),
          (densePrivateAddress note + 64 * word, 160)] ∧
      row.targetRoot = 0 := by
  intro note noteBound word wordBound
  refine ⟨noteBridgeAttempt note word, ?_, rfl, rfl⟩
  have inOneChunk :
      noteBridgeAttempt note word ∈ SmzaRp05Components.exactCsrAttemptsChunk0492 ∨
      noteBridgeAttempt note word ∈ SmzaRp05Components.exactCsrAttemptsChunk0493 ∨
      noteBridgeAttempt note word ∈ SmzaRp05Components.exactCsrAttemptsChunk0573 ∨
      noteBridgeAttempt note word ∈ SmzaRp05Components.exactCsrAttemptsChunk0574 := by
    interval_cases note <;> interval_cases word <;> decide
  simp only [SmzaRp05Components.program, SmzaRp05Components.exactCsrAttempts,
    List.mem_flatten]
  rcases inOneChunk with member | member | member | member
  · exact ⟨SmzaRp05Components.exactCsrAttemptsChunk0492, by simp, member⟩
  · exact ⟨SmzaRp05Components.exactCsrAttemptsChunk0493, by simp, member⟩
  · exact ⟨SmzaRp05Components.exactCsrAttemptsChunk0573, by simp, member⟩
  · exact ⟨SmzaRp05Components.exactCsrAttemptsChunk0574, by simp, member⟩

private def denseReconstructionAttempt (value : Nat) : CsrExecutableAttempt :=
  attempt (15624 + value) 6 value 0
    ((densePrivateAddress value, 1) ::
      ((List.range 30).map (fun digit => (denseDigitAddress value digit, 160 + digit)) ++
        [(denseTopAddress value, 191)])) 0

theorem denseReconstructions : ∀ value, value < 4 →
    ∃ row ∈ SmzaRp05Components.program.csrAttempts,
      row.terms = (densePrivateAddress value, 1) ::
        ((List.range 30).map (fun digit => (denseDigitAddress value digit, 160 + digit)) ++
          [(denseTopAddress value, 191)]) ∧
      row.targetRoot = 0 := by
  intro value valueBound
  refine ⟨denseReconstructionAttempt value, ?_, rfl, rfl⟩
  have inChunk : denseReconstructionAttempt value ∈
      SmzaRp05Components.exactCsrAttemptsChunk0488 := by
    interval_cases value <;> decide
  simp only [SmzaRp05Components.program, SmzaRp05Components.exactCsrAttempts,
    List.mem_flatten]
  exact ⟨SmzaRp05Components.exactCsrAttemptsChunk0488, by simp, inChunk⟩

end HegemonCrypto.SmallWood.SmzaRp05BalancePrefixCertificate
