import SmzaRp04FourRoleLedger

/-!
# RP05 fresh-extraction numerical ledger

The local q38 densities are unchanged: the repaired relation has the same
686 rows, degree eight, six PIOP openings and degree-405 recovery problem.
This file checks the revised two-pass transport coefficient, not the
accepted-execution event inclusion or a concrete primitive hardness claim.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05SecurityLedger

open SmzaRp04FourRoleLedger Mca38SeparateStageLedger

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

def freshExtractionLoss (queries : Nat) : Rat :=
  12 * (queries : Rat)^2 * fourRoleLocalLoss +
    (9806 * (queries : Rat)^3 + 2 * (queries : Rat)) / (2 : Rat)^512

def conservativeEnvelope (queries : Nat) : Rat :=
  24 * (queries : Rat)^2 * (matrixError + (1 / 128 : Rat)^38) +
    (9806 * (queries : Rat)^3 + 2 * (queries : Rat)) / (2 : Rat)^512

/-- Direct terminal-database extraction: four dynamic-role projectors, one
filtered collision event, and one readout of all known verifier/role cells.
This definition does not itself establish their execution interpretation. -/
def terminalExtractionLoss (queries : Nat) : Rat :=
  6 * (queries : Rat)^2 * fourRoleLocalLoss +
    (150 * (queries : Rat)^3 + 2 * (queries : Rat)) / (2 : Rat)^512

theorem terminal_extraction_loss_le_retained_envelope (queries : Nat) :
    terminalExtractionLoss queries ≤ freshExtractionLoss queries := by
  have localNonnegative : (0 : Rat) ≤ fourRoleLocalLoss := by
    unfold fourRoleLocalLoss
    exact add_nonneg
      (add_nonneg
        (add_nonneg (source_only_role_loss_nonnegative .decsMatrix)
          (source_only_role_loss_nonnegative .piopMatrix))
        (source_only_role_loss_nonnegative .piopOpening))
      (source_only_role_loss_nonnegative .decsSample)
  have cubicNonnegative : (0 : Rat) ≤ (queries : Rat)^3 := by positivity
  unfold terminalExtractionLoss freshExtractionLoss
  have localBound : 6 * (queries : Rat)^2 * fourRoleLocalLoss ≤
      12 * (queries : Rat)^2 * fourRoleLocalLoss := by nlinarith
  have remainderBound :
      (150 * (queries : Rat)^3 + 2 * (queries : Rat)) / (2 : Rat)^512 ≤
        (9806 * (queries : Rat)^3 + 2 * (queries : Rat)) / (2 : Rat)^512 := by
    apply div_le_div_of_nonneg_right _ (by positivity)
    nlinarith
  exact add_le_add localBound remainderBound

theorem fresh_extraction_loss_le_envelope (queries : Nat) :
    freshExtractionLoss queries ≤ conservativeEnvelope queries := by
  have bound := mul_le_mul_of_nonneg_left
    four_role_local_loss_le_two_mca_envelope
    (show (0 : Rat) ≤ 12 * (queries : Rat)^2 by positivity)
  unfold freshExtractionLoss conservativeEnvelope
  nlinarith

theorem conservative_envelope_mono {left right : Nat} (bound : left ≤ right) :
    conservativeEnvelope left ≤ conservativeEnvelope right := by
  have castBound : (left : Rat) ≤ (right : Rat) := by exact_mod_cast bound
  have matrixNonnegative : (0 : Rat) ≤ matrixError := by
    unfold matrixError
    positivity
  unfold conservativeEnvelope
  gcongr

theorem maximum_envelope_below_130_bits :
    conservativeEnvelope (3 * 2^64) < 1 / (2 : Rat)^130 := by
  norm_num [conservativeEnvelope, matrixError]

theorem fresh_extraction_loss_below_130_bits (queries : Nat)
    (bounded : queries ≤ 3 * 2^64) :
    freshExtractionLoss queries < 1 / (2 : Rat)^130 :=
  lt_of_le_of_lt
    ((fresh_extraction_loss_le_envelope queries).trans
      (conservative_envelope_mono bounded))
    maximum_envelope_below_130_bits

theorem terminal_extraction_loss_below_130_bits (queries : Nat)
    (bounded : queries ≤ 3 * 2^64) :
    terminalExtractionLoss queries < 1 / (2 : Rat)^130 :=
  lt_of_le_of_lt (terminal_extraction_loss_le_retained_envelope queries)
    (fresh_extraction_loss_below_130_bits queries bounded)

/-- Numerical room for a genuine final-readout event transport.  This is
only arithmetic: the operator/event theorem must separately justify its
factor two and `4 k^2 / |Y|` term.  It does not assert that an accepted
execution has already been connected to either event. -/
def readoutTransportLoss (queries : Nat) : Rat :=
  2 * terminalExtractionLoss queries +
    4 * (queries : Rat)^2 / (2 : Rat)^512

/-- The actual physical-readout transport coefficient fits the reserved
term, including the zero-query/empty-read case. -/
theorem physical_readout_coefficient_le (reads queries : Nat)
    (withinBudget : reads ≤ queries) :
    2 * (reads : Rat)^2 + 2 * (reads : Rat) ≤
      4 * (queries : Rat)^2 := by
  have nonnegative : (0 : Rat) ≤ (reads : Rat) := by positivity
  have order : (reads : Rat) ≤ (queries : Rat) := by
    exact_mod_cast withinBudget
  have squareOrder : (reads : Rat)^2 ≤ (queries : Rat)^2 := by
    nlinarith
  have linearLeSquare : (reads : Rat) ≤ (reads : Rat)^2 := by
    by_cases zero : reads = 0
    · simp [zero]
    · have one : (1 : Rat) ≤ (reads : Rat) := by
        exact_mod_cast Nat.one_le_iff_ne_zero.mpr zero
      nlinarith
  nlinarith

theorem readout_transport_loss_le_fresh (queries : Nat) :
    readoutTransportLoss queries ≤ freshExtractionLoss queries := by
  have squareNonnegative : (0 : Rat) ≤ (queries : Rat)^2 := by positivity
  have linearLeSquare : (queries : Rat) ≤ (queries : Rat)^2 := by
    by_cases zero : queries = 0
    · simp [zero]
    · have one : (1 : Rat) ≤ (queries : Rat) := by
        exact_mod_cast Nat.one_le_iff_ne_zero.mpr zero
      nlinarith
  have squareLeCube : (queries : Rat)^2 ≤ (queries : Rat)^3 := by
    by_cases zero : queries = 0
    · simp [zero]
    · have one : (1 : Rat) ≤ (queries : Rat) := by
        exact_mod_cast Nat.one_le_iff_ne_zero.mpr zero
      have product := mul_nonneg squareNonnegative (sub_nonneg.mpr one)
      nlinarith
  have residual :
      2 * (150 * (queries : Rat)^3 + 2 * (queries : Rat)) +
          4 * (queries : Rat)^2 ≤
        9806 * (queries : Rat)^3 + 2 * (queries : Rat) := by
    nlinarith
  unfold readoutTransportLoss terminalExtractionLoss freshExtractionLoss
  have divided := div_le_div_of_nonneg_right residual
    (show (0 : Rat) ≤ (2 : Rat)^512 by positivity)
  nlinarith

theorem readout_transport_loss_below_130_bits (queries : Nat)
    (bounded : queries ≤ 3 * 2^64) :
    readoutTransportLoss queries < 1 / (2 : Rat)^130 :=
  lt_of_le_of_lt (readout_transport_loss_le_fresh queries)
    (fresh_extraction_loss_below_130_bits queries bounded)

end
end HegemonCrypto.SmallWood.SmzaRp05SecurityLedger
