import SmzaRp05AdaptivePhysicalReadBound

/-! Structural read accounting for the actual answer-adaptive source Program.
The finite output alphabet gives a worst-path read count. Every branch is
covered; neither its measured answers nor an assumed certified skeleton are
inputs. The resulting count must still be charged to the security-game budget.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05SourceReadSchedule

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05AdaptivePhysicalReadBound
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

set_option autoImplicit false
set_option linter.unusedSectionVars false
noncomputable section

variable {Counter Key Result : Type}
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Key] [DecidableEq Key]

def readBudget (decode : RawInput → VectorOutput Counter → RawDigest) :
    Program Result → Nat
  | .done _ => 0
  | .read raw next =>
      (Finset.univ.sup fun answer : VectorOutput Counter =>
        readBudget decode (next (decode raw answer))).succ

theorem readsAtMost_mono
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) {small large : Nat}
    (within : small ≤ large) (bound : ReadsAtMost decode small program) :
    ReadsAtMost decode large program := by
  induction program generalizing small large with
  | done result => cases large <;> trivial
  | read raw next ih =>
      cases small with
      | zero => exact False.elim bound
      | succ small =>
          cases large with
          | zero => omega
          | succ large =>
              intro answer
              exact ih (decode raw answer) (Nat.le_of_succ_le_succ within) (bound answer)

theorem source_reads_within_budget
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) :
    ReadsAtMost decode (readBudget decode program) program := by
  induction program with
  | done result => change True; trivial
  | read raw next ih =>
      intro answer
      exact readsAtMost_mono decode (next (decode raw answer))
        (Finset.le_sup (Finset.mem_univ answer)) (ih (decode raw answer))

theorem source_reads_within_finite_address_space
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) :
    ReadsWithinKeys encode decode (Finset.univ : Finset Key).toList program := by
  induction program with
  | done result => change True; trivial
  | read raw next ih =>
      exact ⟨by simp, fun answer => ih (decode raw answer)⟩

end
end HegemonCrypto.SmallWood.SmzaRp05SourceReadSchedule
