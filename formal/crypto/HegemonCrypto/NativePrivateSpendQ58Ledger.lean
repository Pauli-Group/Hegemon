/- Draft private-spend degree-13169 finite recovery instantiation.
Kernel check pending. No source/chronology/QROM bridge is asserted. -/
import HegemonCrypto.NativePrivateSpendQ58Parameters
import Mathlib.Tactic.GCongr
import Mathlib.Tactic.Linarith

/-!
# Exact q58 HTLC arithmetic ledger

These theorems are rational inequalities only. Applying them to accepted
executions requires the new universal line-count proof, actual role-event
densities, and a quantum compressed-oracle/whole-view transport. None of those
bridges is postulated or proved by this arithmetic file.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Ledger

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000
set_option exponentiation.threshold 1024

def modulus : ℚ := 18446744069414584321

def falling (n : ℚ) : ℕ → ℚ
  | 0 => 1
  | q + 1 => falling n q * (n - q)

/-- Response-universal matrix loss, conditional on the separate new count. -/
def matrixLoss : ℚ := 140 * 16441269970829 / modulus^5
def sampleLoss : ℚ := falling 360447 58 / falling 8388608 58
def piopMatrixLoss : ℚ := 1 / modulus^5
def piopOpeningLoss : ℚ :=
  falling 138 6 / (falling (modulus - 64) 6 - 414 * modulus^5)
def lvcsLoss : ℚ := 12 * falling 13169 58 / falling 8388608 58

def localLoss : ℚ :=
  matrixLoss + sampleLoss + piopMatrixLoss + piopOpeningLoss + lvcsLoss

/-- Proposed two-pass transport coefficients, not an execution theorem. -/
def freshLoss (queries : ℕ) : ℚ :=
  12 * (queries : ℚ)^2 * localLoss +
    (9806 * (queries : ℚ)^3 + 2 * (queries : ℚ)) / (2 : ℚ)^512

def ordinaryLoss (queries depth : ℕ) : ℚ :=
  6 * (queries : ℚ)^2 * localLoss +
    (168 * (queries : ℚ)^3 + 16 * (depth : ℚ)) / (2 : ℚ)^512

theorem exact_local_positive : 0 < localLoss := by
  norm_num [localLoss, matrixLoss, sampleLoss, piopMatrixLoss,
    piopOpeningLoss, lvcsLoss, modulus, falling]

theorem exact_local_below_263_bits : localLoss < 1 / (2 : ℚ)^263 := by
  norm_num [localLoss, matrixLoss, sampleLoss, piopMatrixLoss,
    piopOpeningLoss, lvcsLoss, modulus, falling]

theorem fresh_loss_mono {a b : ℕ} (bounded : a ≤ b) :
    freshLoss a ≤ freshLoss b := by
  have castBound : (a : ℚ) ≤ (b : ℚ) := by exact_mod_cast bounded
  have nonnegative := exact_local_positive.le
  unfold freshLoss
  gcongr

theorem fresh_maximum_below_128_bits :
    freshLoss (3 * 2^64) < 1 / (2 : ℚ)^128 := by
  have upper := mul_lt_mul_of_pos_left exact_local_below_263_bits
    (show (0 : ℚ) < 12 * ((3 * 2^64 : ℕ) : ℚ)^2 by norm_num)
  unfold freshLoss
  norm_num at upper ⊢
  linarith

theorem fresh_below_128_bits (queries : ℕ) (bounded : queries ≤ 3 * 2^64) :
    freshLoss queries < 1 / (2 : ℚ)^128 :=
  lt_of_le_of_lt (fresh_loss_mono bounded) fresh_maximum_below_128_bits

theorem ordinary_maximum_below_129_bits :
    ordinaryLoss (3 * 2^64) (3 * 2^64) < 1 / (2 : ℚ)^129 := by
  have upper := mul_lt_mul_of_pos_left exact_local_below_263_bits
    (show (0 : ℚ) < 6 * ((3 * 2^64 : ℕ) : ℚ)^2 by norm_num)
  unfold ordinaryLoss
  norm_num at upper ⊢
  linarith

end HegemonCrypto.SmallWood.NativePrivateSpendQ58Ledger
