import Mathlib.Data.ZMod.Basic
import Mathlib.Algebra.Field.ZMod
import Mathlib.Tactic.LinearCombination
import Mathlib.Tactic.FinCases
import Mathlib.Tactic.NormNum
import Lean.Elab.Tactic.Omega

/-!
Local semantic consequences of the private-spend source equations.
No native acceptance, CSR correspondence, hash semantics or ledger origin is
assumed proved here. All value/range inputs are natural representatives with
explicit bounds. The only algebraic field premise is primality of the fixed
Goldilocks modulus, already proved in HegemonCrypto/Goldilocks.lean; this small
component deliberately does not import that module's production model.
Six branches are numbered exactly as in private_spend/circuit.rs:110.
The file was drafted without a Lean invocation; kernel checking is pending.
-/

set_option autoImplicit false
set_option maxHeartbeats 1000000

namespace HegemonCrypto.NativePrivateSpendLocalSemantics

def modulus : Nat := 18446744069414584321
def heightBound : Nat := 2^48
def valueBound : Nat := 2^56
abbrev K := ZMod modulus
instance : NeZero modulus := ⟨by decide⟩

abbrev Branch := Fin 6
def ordinary : Branch := 0
def approval : Branch := 1
def treasuryFinal : Branch := 2
def lock : Branch := 3
def claim : Branch := 4
def refund : Branch := 5

def total (s : Branch → Nat) : Nat :=
  s 0 + s 1 + s 2 + s 3 + s 4 + s 5

theorem small_cast_injective (a b : Nat) (ha : a < modulus) (hb : b < modulus)
    (same : (a : K) = (b : K)) : a = b := by
  have values := congrArg ZMod.val same
  simpa only [ZMod.val_natCast, Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] using values

section Field
variable [Fact (Nat.Prime modulus)]

theorem boolean_from_source_product (s : Nat) (canonical : s < modulus)
    (equation : (s : K) * ((s : K) - 1) = 0) : s = 0 ∨ s = 1 := by
  rcases mul_eq_zero.mp equation with zero | one
  · exact Or.inl (small_cast_injective s 0 canonical (by decide) zero)
  · exact Or.inr (small_cast_injective s 1 canonical (by decide) (sub_eq_zero.mp one))

/-- These are the six Boolean product equations and one sum equation emitted
by the source, not an assumption that a branch was correctly selected. -/
structure SelectorEquations (s : Branch → Nat) : Prop where
  canonical : ∀ i, s i < modulus
  boolean : ∀ i, (s i : K) * ((s i : K) - 1) = 0
  sum : (s 0 : K) + (s 1 : K) + (s 2 : K) + (s 3 : K) + (s 4 : K) + (s 5 : K) = 1

theorem selectors_integer_sum (s : Branch → Nat) (h : SelectorEquations s) :
    total s = 1 := by
  have b0 : s 0 ≤ 1 := by
    rcases boolean_from_source_product (s 0) (h.canonical 0) (h.boolean 0) with h0 | h0 <;> omega
  have b1 : s 1 ≤ 1 := by
    rcases boolean_from_source_product (s 1) (h.canonical 1) (h.boolean 1) with h1 | h1 <;> omega
  have b2 : s 2 ≤ 1 := by
    rcases boolean_from_source_product (s 2) (h.canonical 2) (h.boolean 2) with h2 | h2 <;> omega
  have b3 : s 3 ≤ 1 := by
    rcases boolean_from_source_product (s 3) (h.canonical 3) (h.boolean 3) with h3 | h3 <;> omega
  have b4 : s 4 ≤ 1 := by
    rcases boolean_from_source_product (s 4) (h.canonical 4) (h.boolean 4) with h4 | h4 <;> omega
  have b5 : s 5 ≤ 1 := by
    rcases boolean_from_source_product (s 5) (h.canonical 5) (h.boolean 5) with h5 | h5 <;> omega
  have bound : total s < modulus := by unfold total modulus; omega
  apply small_cast_injective (total s) 1 bound (by decide)
  simpa only [total, Nat.cast_add, Nat.cast_one] using h.sum

theorem unique_selected_branch (s : Branch → Nat) (h : SelectorEquations s) :
    ∃! branch : Branch, s branch = 1 := by
  have sum := selectors_integer_sum s h
  have bits : ∀ i, s i = 0 ∨ s i = 1 :=
    fun i => boolean_from_source_product (s i) (h.canonical i) (h.boolean i)
  have existsBranch : ∃ i : Branch, s i = 1 := by
    by_contra absent
    have b0 := bits 0
    have b1 := bits 1
    have b2 := bits 2
    have b3 := bits 3
    have b4 := bits 4
    have b5 := bits 5
    have n0 : s 0 ≠ 1 := fun eq => absent ⟨0, eq⟩
    have n1 : s 1 ≠ 1 := fun eq => absent ⟨1, eq⟩
    have n2 : s 2 ≠ 1 := fun eq => absent ⟨2, eq⟩
    have n3 : s 3 ≠ 1 := fun eq => absent ⟨3, eq⟩
    have n4 : s 4 ≠ 1 := fun eq => absent ⟨4, eq⟩
    have n5 : s 5 ≠ 1 := fun eq => absent ⟨5, eq⟩
    unfold total at sum
    omega
  obtain ⟨i, selected⟩ := existsBranch
  refine ⟨i, selected, ?_⟩
  intro j alsoSelected
  unfold total at sum
  fin_cases i <;> fin_cases j <;> simp_all <;> omega

/-- Source field balance becomes exact integer conservation; both sides fit
well below Goldilocks even with two full 56-bit outputs and a 56-bit fee. -/
theorem integer_conservation (input0 input1 output0 output1 fee : Nat)
    (hi0 : input0 < valueBound) (hi1 : input1 < valueBound)
    (ho0 : output0 < valueBound) (ho1 : output1 < valueBound) (hf : fee < valueBound)
    (balance : (input0 : K) + (input1 : K) = (output0 : K) + (output1 : K) + (fee : K)) :
    input0 + input1 = output0 + output1 + fee := by
  have leftBound : input0 + input1 < modulus := by
    unfold valueBound at hi0 hi1
    unfold modulus
    omega
  have rightBound : output0 + output1 + fee < modulus := by
    unfold valueBound at ho0 ho1 hf
    unfold modulus
    omega
  apply small_cast_injective _ _ leftBound rightBound
  simpa only [Nat.cast_add] using balance

/-- A 48-bit witness for timeout-reference-14 rules out modular wrap. -/
theorem lock_slack_integer (reference timeout slack : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (equation : (timeout : K) - (reference : K) - 14 = (slack : K)) :
    timeout = reference + 14 + slack := by
  have lt : timeout < modulus := by unfold heightBound at ht; unfold modulus; omega
  have rt : reference + 14 + slack < modulus := by
    unfold heightBound at hr hs
    unfold modulus
    omega
  apply small_cast_injective _ _ lt rt
  rw [Nat.cast_add, Nat.cast_add]
  linear_combination equation

/-- The common route admits parents through reference+12; inclusion is parent+1.
The private Lock's 14-block margin therefore survives the entire shared window. -/
theorem lock_safe_at_inclusion (reference timeout slack actualParent : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (equation : (timeout : K) - (reference : K) - 14 = (slack : K))
    (window : reference ≤ actualParent ∧ actualParent ≤ reference + 12) :
    actualParent + 1 < timeout := by
  have exactSlack := lock_slack_integer reference timeout slack hr ht hs equation
  omega

theorem refund_slack_integer (reference timeout slack : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (equation : (reference : K) - (timeout : K) = (slack : K)) :
    reference = timeout + slack := by
  have lt : reference < modulus := by unfold heightBound at hr; unfold modulus; omega
  have rt : timeout + slack < modulus := by
    unfold heightBound at ht hs
    unfold modulus
    omega
  apply small_cast_injective _ _ lt rt
  rw [Nat.cast_add]
  linear_combination equation

theorem refund_mature_at_inclusion (reference timeout slack actualParent : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (equation : (reference : K) - (timeout : K) = (slack : K))
    (referenceNotFuture : reference ≤ actualParent) : timeout ≤ actualParent := by
  have exactSlack := refund_slack_integer reference timeout slack hr ht hs equation
  omega

/-- The range output is a bounded slack for the actual gated source expression.
Selection is a branch condition, not a semantic correctness premise. -/
theorem selected_lock_safe_at_inclusion (s : Branch → Nat)
    (selected : s 3 = 1) (reference timeout slack actualParent : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (rangeEquation : (s 3 : K) * ((timeout : K) - (reference : K) - 14) = (slack : K))
    (window : reference ≤ actualParent ∧ actualParent ≤ reference + 12) :
    actualParent + 1 < timeout := by
  have ungated := rangeEquation
  rw [selected, Nat.cast_one, one_mul] at ungated
  exact lock_safe_at_inclusion reference timeout slack actualParent hr ht hs ungated window

theorem selected_refund_mature_at_inclusion (s : Branch → Nat)
    (selected : s 5 = 1) (reference timeout slack actualParent : Nat)
    (hr : reference < heightBound) (ht : timeout < heightBound) (hs : slack < heightBound)
    (rangeEquation : (s 5 : K) * ((reference : K) - (timeout : K)) = (slack : K))
    (referenceNotFuture : reference ≤ actualParent) : timeout ≤ actualParent := by
  have ungated := rangeEquation
  rw [selected, Nat.cast_one, one_mul] at ungated
  exact refund_mature_at_inclusion reference timeout slack actualParent hr ht hs ungated referenceNotFuture

/-- Derive claim+refund=1 from a selected unlock branch and the source selector
equations, then cancel the actual source payout gate. -/
theorem unlocked_full_payout (s : Branch → Nat) (selectors : SelectorEquations s)
    (selected : s 4 = 1 ∨ s 5 = 1) (input0 output0 : Nat)
    (hi : input0 < valueBound) (ho : output0 < valueBound)
    (gate : ((s 4 : K) + (s 5 : K)) * ((output0 : K) - (input0 : K)) = 0) :
    output0 = input0 := by
  have sum := selectors_integer_sum s selectors
  have unlocked : s 4 + s 5 = 1 := by unfold total at sum; omega
  have fieldUnlocked : (s 4 : K) + (s 5 : K) = 1 := by
    rw [← Nat.cast_add, unlocked, Nat.cast_one]
  rw [fieldUnlocked, one_mul] at gate
  apply small_cast_injective output0 input0
  · unfold valueBound at ho; unfold modulus; omega
  · unfold valueBound at hi; unfold modulus; omega
  · exact sub_eq_zero.mp gate

theorem unlock_fee_and_change (s : Branch → Nat) (selectors : SelectorEquations s)
    (selected : s 4 = 1 ∨ s 5 = 1) (input0 input1 output0 output1 fee : Nat)
    (hi0 : input0 < valueBound) (hi1 : input1 < valueBound)
    (ho0 : output0 < valueBound) (ho1 : output1 < valueBound) (hf : fee < valueBound)
    (balance : (input0 : K) + (input1 : K) = (output0 : K) + (output1 : K) + (fee : K))
    (gate : ((s 4 : K) + (s 5 : K)) * ((output0 : K) - (input0 : K)) = 0) :
    output0 = input0 ∧ input1 = output1 + fee := by
  have payout := unlocked_full_payout s selectors selected input0 output0 hi0 ho0 gate
  have conservation := integer_conservation input0 input1 output0 output1 fee hi0 hi1 ho0 ho1 hf balance
  exact ⟨payout, by omega⟩

end Field

/-- Exact source projection: [0,8), [24], [25,32), [39,77). -/
def intentSource (i : Fin 54) : Fin 77 :=
  ⟨if i.val < 8 then i.val else if i.val = 8 then 24
    else if i.val < 16 then i.val + 16 else i.val + 23, by
      have bound := i.isLt
      split_ifs <;> omega⟩

def intentProjection {A : Type*} (pub : Fin 77 → A) : Fin 54 → A :=
  fun i => pub (intentSource i)

theorem intent_projection_injective : Function.Injective intentSource := by
  intro a b same
  have values := congrArg Fin.val same
  unfold intentSource at values
  dsimp only at values
  split_ifs at values <;> apply Fin.ext <;> omega

theorem intent_excludes_reference_and_accumulator_nullifier (i : Fin 54) :
    ((intentSource i).val < 8 ∨ 24 ≤ (intentSource i).val) ∧
    ((intentSource i).val < 32 ∨ 39 ≤ (intentSource i).val) := by
  have bound := i.isLt
  unfold intentSource
  dsimp only
  split_ifs <;> omega

theorem final_gate_binds_exact_intent (pub : Fin 77 → K) (intent : Fin 54 → K)
    (finalSelector : K) (selected : finalSelector = 1)
    (gates : ∀ i, finalSelector * (intent i - pub (intentSource i)) = 0) :
    intent = intentProjection pub := by
  funext i
  have gate := gates i
  rw [selected, one_mul] at gate
  exact sub_eq_zero.mp gate

abbrev Digest7 := Fin 7 → K

/-- Full seven-coordinate gate cancellation, with no first-limb shortcut. -/
theorem full_authority_gate (selector : K) (selected : selector = 1) (a b : Digest7)
    (gates : ∀ i, selector * (a i - b i) = 0) : a = b := by
  funext i
  have gate := gates i
  rw [selected, one_mul] at gate
  exact sub_eq_zero.mp gate

theorem differing_authority_limb (a b : Digest7) (i : Fin 7) (different : a i ≠ b i) : a ≠ b := by
  intro same
  exact different (congrFun same i)

/-- Source-owned successor domains; these constants do not assert hash binding. -/
def ordinaryOwnerDomain : Nat := 0x50534f574e520001
def dummyNullifierDomain : Nat := 0x5053444e554c0001
def htlcPolicyDomain : Nat := 0x505348504f4c0001
def htlcOwnerDomain : Nat := 0x5053484f574e0001
def accumulatorDomain : Nat := 0x5053414343550001
def intentDomain : Nat := 0x5053494e544e0001

end HegemonCrypto.NativePrivateSpendLocalSemantics
