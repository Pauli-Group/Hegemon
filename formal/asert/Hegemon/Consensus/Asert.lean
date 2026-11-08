import Std

/-!
Executable mathematical model for the ASERT-only Bitcoin80 upgrade.

General results below cover the mathematical clamp, signed Q16 split, and
height activation. Generated cases compare this independent Nat/Int model with
production Rust. They do not prove a general refinement of Rust fixed-width
operations, compiler correctness, timestamp authenticity, branch ancestry,
cryptographic security, mining liveness, or production release authority.
-/

namespace Hegemon.Consensus.Asert

set_option exponentiation.threshold 512

def maxU64 : Nat := 2^64 - 1
def maxI128 : Int := 2^127 - 1
def minI128 : Int := -(2^127)
def powLimit : Nat := 8388607 * 2^(8*29)
def inI128 (value : Int) : Bool := decide (minI128 ≤ value ∧ value ≤ maxI128)

def targetToCompact (target : Nat) : Nat :=
  let exponent := ((List.range 33).find? (fun e => target < 2^(8*e))).getD 33
  let mantissa := if exponent ≤ 3 then target * 2^(8*(3-exponent))
    else target / 2^(8*(exponent-3))
  if 8388608 ≤ mantissa then (exponent+1)*16777216 + mantissa/256
  else exponent*16777216 + mantissa

def compactTarget (bits : Nat) : Option Nat :=
  let exponent := bits / 16777216
  let mantissa := bits % 16777216
  if exponent > 32 ∨ mantissa = 0 ∨ mantissa ≥ 8388608 then none else
  let target := if exponent ≤ 3 then mantissa / 2^(8*(3-exponent))
    else mantissa * 2^(8*(exponent-3))
  if target = 0 ∨ target > powLimit ∨ targetToCompact target ≠ bits then none else some target

/-- The first division follows Rust/BCH truncation toward zero. -/
def fixedExponent (deviation : Int) (halfLife : Nat) : Int :=
  (deviation * 65536).tdiv (Int.ofNat halfLife)

/-- Euclidean division by a positive power of two is the arithmetic right shift. -/
def integralExponent (exponent : Int) : Int := exponent / 65536
def fractionalExponent (exponent : Int) : Nat := (exponent % 65536).toNat

def polynomialFactor (fraction : Nat) : Nat :=
  65536 + (195766423245049*fraction + 971821376*fraction*fraction
    + 5127*fraction*fraction*fraction + 2^47) / 2^48

def clampTarget (limit target : Nat) : Nat := min limit (max 1 target)

def shiftedProduct (product : Nat) (shift : Int) : Nat :=
  if shift ≥ 256 then powLimit
  else if shift ≤ -272 then 0
  else if shift ≥ 0 then product * 2^(shift.toNat)
  else product / 2^((-shift).toNat)

def scaledTarget (reference : Nat) (exponent : Int) : Nat :=
  clampTarget powLimit (shiftedProduct
    (reference * polynomialFactor (fractionalExponent exponent))
    (integralExponent exponent - 16))

inductive Rejection where
  | invalidParameters | invalidAnchor | invalidCompactTarget | arithmeticOverflow
  deriving Repr, DecidableEq

structure Input where
  anchorHeight : Nat
  anchorParentTimestamp : Nat
  anchorBits : Nat
  parentHeight : Nat
  parentTimestamp : Nat
  spacing : Nat := 60000
  halfLife : Nat := 3600000
  deriving Repr

def nextBits (input : Input) : Except Rejection Nat :=
  if input.spacing = 0 ∨ input.halfLife = 0 then .error .invalidParameters
  else if input.anchorHeight = 0 ∨ input.parentHeight < input.anchorHeight
    ∨ input.parentHeight = maxU64 then .error .invalidAnchor
  else match compactTarget input.anchorBits with
    | none => .error .invalidCompactTarget
    | some target =>
      let ideal := Int.ofNat (input.spacing * (input.parentHeight - input.anchorHeight + 1))
      let elapsed := Int.ofNat input.parentTimestamp - Int.ofNat input.anchorParentTimestamp
      let deviation := elapsed - ideal
      if !(inI128 ideal && inI128 deviation && inI128 (deviation * 65536)) then
        .error .arithmeticOverflow
      else .ok (targetToCompact (scaledTarget target (fixedExponent deviation input.halfLife)))

def asertActive (activation height : Nat) : Bool := decide (2 ≤ activation ∧ activation ≤ height)

theorem clampTarget_positive (limit target : Nat) (h : 0 < limit) :
    0 < clampTarget limit target := by unfold clampTarget; omega

theorem clampTarget_le_limit (limit target : Nat) :
    clampTarget limit target ≤ limit := by unfold clampTarget; omega

theorem scaledTarget_positive (reference : Nat) (exponent : Int) :
    0 < scaledTarget reference exponent := by
  apply clampTarget_positive
  decide

theorem scaledTarget_le_limit (reference : Nat) (exponent : Int) :
    scaledTarget reference exponent ≤ powLimit := by
  apply clampTarget_le_limit

theorem exponentSplit_reconstruct (exponent : Int) :
    integralExponent exponent * 65536 + exponent % 65536 = exponent := by
  unfold integralExponent
  omega

theorem fractionalExponent_bound (exponent : Int) :
    fractionalExponent exponent < 65536 := by
  unfold fractionalExponent
  omega

theorem activation_before (activation height : Nat) (h : height < activation) :
    asertActive activation height = false := by
  simp [asertActive]
  omega

theorem activation_at (activation : Nat) (h : 2 ≤ activation) :
    asertActive activation activation = true := by simp [asertActive, h]

theorem genesis_legacy (activation : Nat) : asertActive activation 0 = false := by
  simp [asertActive]
  omega

theorem invalid_activation_legacy (activation height : Nat) (h : activation < 2) :
    asertActive activation height = false := by simp [asertActive]; omega

theorem negative_deviation_truncation : fixedExponent (-1) 3600000 = 0 := by decide
theorem negative_exponent_split :
    integralExponent (-1) = -1 ∧ fractionalExponent (-1) = 65535 := by decide

theorem exact_schedule_keeps_target :
    nextBits ⟨19, 1000000, 439041101, 19, 1060000, 60000, 3600000⟩ = .ok 439041101 := by rfl

theorem half_life_lag_doubles_target :
    nextBits ⟨19, 1000000, 439041101, 19, 4660000, 60000, 3600000⟩ = .ok 441874586 := by rfl

end Hegemon.Consensus.Asert
