import HegemonCrypto.NativePrivateSpendQ58CurrentGeometry
import HegemonCrypto.NativePrivateSpendQ58Ledger
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-! Arithmetic successor for degree13172, not a density or accepted-execution
theorem. The matrix numerator is useful only after its current-degree universal
count is proved. The historical degree13169 count is never reinterpreted here.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLedger
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option exponentiation.threshold 1024

abbrev modulus := NativePrivateSpendQ58Ledger.modulus
abbrev falling := NativePrivateSpendQ58Ledger.falling
abbrev fieldXofBlocks := V8Smz9RawCounterCompiler.digestCallCap

def matrixLoss : ℚ := 140 * 16445033384594 / modulus ^ 5
def sampleLoss : ℚ := falling 360447 58 / falling 8388608 58
def piopMatrixLoss : ℚ := 1 / modulus ^ 5
def piopOpeningLoss : ℚ :=
  falling 138 6 / (falling (modulus - 64) 6 - 414 * modulus ^ 5)
def lvcsLoss : ℚ := 12 * falling 13172 58 / falling 8388608 58
def localLoss : ℚ :=
  matrixLoss + sampleLoss + piopMatrixLoss + piopOpeningLoss + lvcsLoss

/-- Transport coefficients are parameters. Their bounds below are conditions,
not assertions about the current physical source or its request count. -/
def freshLoss (queries passFactor transportCoefficient : ℕ) : ℚ :=
  (passFactor : ℚ) * (queries : ℚ) ^ 2 * localLoss +
    ((transportCoefficient : ℚ) * (queries : ℚ) ^ 3 + 2 * (queries : ℚ)) / (2 : ℚ) ^ 512

theorem exact_local_positive : 0 < localLoss := by
  norm_num [localLoss, matrixLoss, sampleLoss, piopMatrixLoss,
    piopOpeningLoss, lvcsLoss, modulus, NativePrivateSpendQ58Ledger.modulus,
    falling, NativePrivateSpendQ58Ledger.falling]

theorem exact_local_below_263_bits : localLoss < 1 / (2 : ℚ) ^ 263 := by
  norm_num [localLoss, matrixLoss, sampleLoss, piopMatrixLoss,
    piopOpeningLoss, lvcsLoss, modulus, NativePrivateSpendQ58Ledger.modulus,
    falling, NativePrivateSpendQ58Ledger.falling]

theorem fresh_loss_mono {a b passA passB coefficientA coefficientB : ℕ}
    (queriesBound : a ≤ b) (passBound : passA ≤ passB)
    (coefficientBound : coefficientA ≤ coefficientB) :
    freshLoss a passA coefficientA ≤ freshLoss b passB coefficientB := by
  have castQueries : (a : ℚ) ≤ (b : ℚ) := by exact_mod_cast queriesBound
  have castPass : (passA : ℚ) ≤ (passB : ℚ) := by exact_mod_cast passBound
  have castCoefficient : (coefficientA : ℚ) ≤ (coefficientB : ℚ) :=
    by exact_mod_cast coefficientBound
  have nonnegative := exact_local_positive.le
  unfold freshLoss
  gcongr

theorem proposed_maximum_below_128_bits :
    freshLoss (3 * 2 ^ 64) 12 9806 < 1 / (2 : ℚ) ^ 128 := by
  have upper := mul_lt_mul_of_pos_left exact_local_below_263_bits
    (show (0 : ℚ) < 12 * ((3 * 2 ^ 64 : ℕ) : ℚ) ^ 2 by norm_num)
  unfold freshLoss
  norm_num at upper ⊢
  linarith

theorem fresh_below_128_bits (queries passFactor transportCoefficient : ℕ)
    (queryBound : queries ≤ 3 * 2 ^ 64) (passBound : passFactor ≤ 12)
    (coefficientBound : transportCoefficient ≤ 9806) :
    freshLoss queries passFactor transportCoefficient < 1 / (2 : ℚ) ^ 128 :=
  lt_of_le_of_lt (fresh_loss_mono queryBound passBound coefficientBound)
    proposed_maximum_below_128_bits

def decsMatrixWords : Nat := 5 * 140
def piopMatrixWords : Nat := 5 * max 5210 1344594
def proverMerkleReads : Nat := 2 ^ 23 + (2 ^ 23 - 1)
def verifierMerkleReads : Nat := 58 * (23 + 1)
def proverReadCap : Nat :=
  proverMerkleReads + 2 + fieldXofBlocks decsMatrixWords +
    1 + fieldXofBlocks piopMatrixWords + 1 +
    (16 + 1) * fieldXofBlocks 6 + 1 + fieldXofBlocks 80
def verifierReadCap : Nat :=
  verifierMerkleReads + 1 + fieldXofBlocks decsMatrixWords +
    1 + fieldXofBlocks piopMatrixWords + 1 +
    (16 + 1) * fieldXofBlocks 6 + 1 + fieldXofBlocks 80
def verifierTraceReadCap : Nat := verifierReadCap + 1 + fieldXofBlocks piopMatrixWords

theorem exact_current_source_counters :
    piopMatrixWords = 6722970 ∧ fieldXofBlocks piopMatrixWords = 840376 ∧
    proverReadCap = 17617787 ∧ verifierReadCap = 841963 ∧
    verifierTraceReadCap = 1682340 := by
  norm_num [piopMatrixWords, proverReadCap, verifierReadCap, verifierTraceReadCap,
    proverMerkleReads, verifierMerkleReads, decsMatrixWords, fieldXofBlocks,
    V8Smz9RawCounterCompiler.digestCallCap]

end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLedger
