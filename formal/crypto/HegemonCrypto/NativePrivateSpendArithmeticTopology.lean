import HegemonCrypto.NativePrivateSpendPackedLowering
import HegemonCrypto.NativePrivateSpendLocalSemantics
import Mathlib.Tactic.LinearCombination

/-! Data-only arithmetic topology certificates. No certificate
mentions an assignment or requires its desired arithmetic equations. Inputs and
Bit/Inverse auxiliaries remain arbitrary values of the satisfying packed vector.
The actual Rust role map, certificate checker and CSR binding are still open. -/
set_option autoImplicit false
set_option maxHeartbeats 2000000
namespace HegemonCrypto.NativePrivateSpendArithmeticTopology
open NativePrivateSpendPackedLowering NativeLaunchConstraintAdapterBridge
open NativePrivateSpendLocalSemantics
noncomputable section
variable [Fact (Nat.Prime modulus)]

/-- Actual arithmetic operation or one of operation()'s constant-folding cases. -/
def AddData (g : Graph K) (a b out : Word K) : Prop :=
  (∃ i, g.nodes i = .linear a b false ∧ out = .wire i.val) ∨
  (a = .constant 0 ∧ out = b) ∨ (b = .constant 0 ∧ out = a) ∨
  ∃ x y, a = .constant x ∧ b = .constant y ∧ out = .constant (x + y)
def SubData (g : Graph K) (a b out : Word K) : Prop :=
  (∃ i, g.nodes i = .linear a b true ∧ out = .wire i.val) ∨
  (b = .constant 0 ∧ out = a) ∨
  ∃ x y, a = .constant x ∧ b = .constant y ∧ out = .constant (x - y)
def MulData (g : Graph K) (a b out : Word K) : Prop :=
  (∃ i, g.nodes i = .product a b ∧ out = .wire i.val) ∨
  (a = .constant 0 ∧ out = .constant 0) ∨
  (b = .constant 0 ∧ out = .constant 0) ∨
  (a = .constant 1 ∧ out = b) ∨ (b = .constant 1 ∧ out = a) ∨
  ∃ x y, a = .constant x ∧ b = .constant y ∧ out = .constant (x * y)

variable (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z)
include layout sem

theorem add_sound {a b out : Word K} (h : AddData g a b out) :
    NativeLaunchConstraintAdapterBridge.read z out = NativeLaunchConstraintAdapterBridge.read z a + NativeLaunchConstraintAdapterBridge.read z b := by
  rcases h with ⟨i, hn, ho⟩ | ⟨ha, ho⟩ | ⟨hb, ho⟩ | ⟨x, y, ha, hb, ho⟩
  · have h := sem.nodes i
    rw [hn] at h
    simpa only [ho, nodeMeaning, NativeLaunchConstraintAdapterBridge.read] using h
  all_goals simp_all [NativeLaunchConstraintAdapterBridge.read]

theorem sub_sound {a b out : Word K} (h : SubData g a b out) :
    NativeLaunchConstraintAdapterBridge.read z out = NativeLaunchConstraintAdapterBridge.read z a - NativeLaunchConstraintAdapterBridge.read z b := by
  rcases h with ⟨i, hn, ho⟩ | ⟨hb, ho⟩ | ⟨x, y, ha, hb, ho⟩
  · have h := sem.nodes i
    rw [hn] at h
    simpa only [ho, nodeMeaning, NativeLaunchConstraintAdapterBridge.read] using h
  all_goals simp_all [NativeLaunchConstraintAdapterBridge.read]

theorem mul_sound {a b out : Word K} (h : MulData g a b out) :
    NativeLaunchConstraintAdapterBridge.read z out = NativeLaunchConstraintAdapterBridge.read z a * NativeLaunchConstraintAdapterBridge.read z b := by
  rcases h with ⟨i, hn, ho⟩ | ⟨ha, ho⟩ | ⟨hb, ho⟩ |
    ⟨ha, ho⟩ | ⟨hb, ho⟩ | ⟨x, y, ha, hb, ho⟩
  · have h := sem.nodes i
    rw [hn] at h
    simpa only [ho, nodeMeaning, NativeLaunchConstraintAdapterBridge.read] using h
  all_goals simp_all [NativeLaunchConstraintAdapterBridge.read]

/-- Works for Input selectors as well as Bit auxiliaries. -/
structure BooleanData (g : Graph K) (source : Word K) where
  difference : Word K
  product : Word K
  subtract : SubData g source (.constant 1) difference
  multiply : MulData g source difference product
  zero : (product, .constant 0) ∈ g.equalities

theorem boolean_equation (source : Word K) (c : BooleanData g source) :
    NativeLaunchConstraintAdapterBridge.read z source * (NativeLaunchConstraintAdapterBridge.read z source - 1) = 0 := by
  have hs := sub_sound g layout z sem c.subtract
  have hm := mul_sound g layout z sem c.multiply
  have hz := sem.equalities _ _ c.zero
  rw [hm, hs] at hz
  exact hz

theorem boolean_sound (source : Word K) (c : BooleanData g source) :
    NativeLaunchConstraintAdapterBridge.read z source = 0 ∨ NativeLaunchConstraintAdapterBridge.read z source = 1 := by
  rcases mul_eq_zero.mp (boolean_equation g layout z sem source c) with h | h
  · exact Or.inl h
  · exact Or.inr (sub_eq_zero.mp h)

/-- Direct model of range(): ordered Bit nodes, Boolean guards, each actual
scaled term, the zero-start prefixes chain and final graph equality. -/
structure RangeData (g : Graph K) (source : Word K) (width : Nat) where
  bits : Fin width → Fin g.count
  isBit : ∀ i, g.nodes (bits i) = .bit source i.val
  guards : ∀ i, BooleanData g (.wire (bits i).val)
  scaled : Fin width → Word K
  prefixes : Fin (width + 1) → Word K
  start : prefixes ⟨0, by omega⟩ = .constant 0
  scale : ∀ i, MulData g (.wire (bits i).val) (.constant ((2 : K)^i.val)) (scaled i)
  accumulate : ∀ i, AddData g
    (prefixes ⟨i.val, by omega⟩) (scaled i) (prefixes ⟨i.val + 1, by omega⟩)
  finish : (source, prefixes ⟨width, by omega⟩) ∈ g.equalities

/-- Integer interpretation of a Boolean field value, never host bit extraction. -/
def bitNat (x : K) : Nat := if x = 1 then 1 else 0

omit layout sem in theorem bitNat_cases (x : K) : bitNat x = 0 ∨ bitNat x = 1 := by
  unfold bitNat
  split_ifs <;> simp

omit layout sem in theorem bitNat_cast (x : K) (h : x = 0 ∨ x = 1) : (bitNat x : K) = x := by
  rcases h with h | h <;> simp [bitNat, h]

def recompose (bits : Nat → Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => recompose bits n + bits n * 2^n

omit [Fact (Nat.Prime modulus)] layout sem in theorem recompose_bound (bits : Nat → Nat) (boolean : ∀ i, bits i = 0 ∨ bits i = 1)
    (n : Nat) : recompose bits n < 2^n := by
  induction n with
  | zero => simp [recompose]
  | succ n ih =>
    rcases boolean n with h | h <;> simp only [recompose, h, zero_mul, one_mul,
      add_zero, pow_succ] <;> omega

def rangeBits (source : Word K) (width : Nat) (c : RangeData g source width)
    (i : Nat) : Nat :=
  if h : i < width then bitNat (z (c.bits ⟨i, h⟩).val) else 0

theorem range_prefix (source : Word K) (width : Nat) (c : RangeData g source width)
    (n : Nat) (within : n ≤ width) :
    NativeLaunchConstraintAdapterBridge.read z (c.prefixes ⟨n, by omega⟩) = (recompose (rangeBits g z source width c) n : K) := by
  induction n with
  | zero =>
    rw [c.start]
    rfl
  | succ n ih =>
    have hn : n < width := by omega
    let i : Fin width := ⟨n, hn⟩
    have add := add_sound g layout z sem (c.accumulate i)
    have scale := mul_sound g layout z sem (c.scale i)
    have bit := bitNat_cast (z (c.bits i).val)
      (boolean_sound g layout z sem (.wire (c.bits i).val) (c.guards i))
    have prior := ih (by omega)
    simp only [recompose, Nat.cast_add, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat]
    rw [add, prior, scale]
    simp only [NativeLaunchConstraintAdapterBridge.read, rangeBits, dif_pos hn]
    rw [bit]

theorem range_witness (source : Word K) (width : Nat) (c : RangeData g source width) :
    ∃ value : Nat, value < 2^width ∧ (value : K) = NativeLaunchConstraintAdapterBridge.read z source := by
  refine ⟨recompose (rangeBits g z source width c) width, ?_, ?_⟩
  · apply recompose_bound
    intro i
    unfold rangeBits
    split_ifs
    · exact bitNat_cases _
    · exact Or.inl rfl
  · have final := sem.equalities _ _ c.finish
    rw [range_prefix g layout z sem source width c width (by omega)] at final
    exact final.symm

def natural (z : Nat → K) (w : Word K) : Nat := (NativeLaunchConstraintAdapterBridge.read z w).val

omit layout sem in theorem natural_cast (w : Word K) : (natural z w : K) = NativeLaunchConstraintAdapterBridge.read z w :=
  ZMod.natCast_zmod_val _

theorem range_natural_bound (source : Word K) (width : Nat)
    (c : RangeData g source width) (fits : 2^width ≤ modulus) :
    natural z source < 2^width := by
  obtain ⟨v, bound, eq⟩ := range_witness g layout z sem source width c
  have vp : v < modulus := bound.trans_le fits
  have same := congrArg ZMod.val eq
  simp only [ZMod.val_natCast, Nat.mod_eq_of_lt vp] at same
  change (NativeLaunchConstraintAdapterBridge.read z source).val < 2^width
  rw [← same]
  exact bound

/-- The sum loop starts at zero; all six concrete modes are checked, in order. -/
structure SelectorData (g : Graph K) (modes : Fin 6 → Word K) where
  guards : ∀ i, BooleanData g (modes i)
  prefixes : Fin 7 → Word K
  start : prefixes 0 = .constant 0
  add : ∀ i : Fin 6, AddData g (prefixes ⟨i.val, by omega⟩)
    (modes i) (prefixes ⟨i.val + 1, by omega⟩)
  finish : (prefixes 6, .constant 1) ∈ g.equalities

theorem selector_field_sum (modes : Fin 6 → Word K) (c : SelectorData g modes) :
    NativeLaunchConstraintAdapterBridge.read z (modes 0) + NativeLaunchConstraintAdapterBridge.read z (modes 1) + NativeLaunchConstraintAdapterBridge.read z (modes 2) +
      NativeLaunchConstraintAdapterBridge.read z (modes 3) + NativeLaunchConstraintAdapterBridge.read z (modes 4) + NativeLaunchConstraintAdapterBridge.read z (modes 5) = 1 := by
  have h0 := add_sound g layout z sem (c.add 0)
  have h1 := add_sound g layout z sem (c.add 1)
  have h2 := add_sound g layout z sem (c.add 2)
  have h3 := add_sound g layout z sem (c.add 3)
  have h4 := add_sound g layout z sem (c.add 4)
  have h5 := add_sound g layout z sem (c.add 5)
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 1) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 0) + NativeLaunchConstraintAdapterBridge.read z (modes 0) at h0
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 2) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 1) + NativeLaunchConstraintAdapterBridge.read z (modes 1) at h1
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 3) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 2) + NativeLaunchConstraintAdapterBridge.read z (modes 2) at h2
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 4) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 3) + NativeLaunchConstraintAdapterBridge.read z (modes 3) at h3
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 5) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 4) + NativeLaunchConstraintAdapterBridge.read z (modes 4) at h4
  change NativeLaunchConstraintAdapterBridge.read z (c.prefixes 6) = NativeLaunchConstraintAdapterBridge.read z (c.prefixes 5) + NativeLaunchConstraintAdapterBridge.read z (modes 5) at h5
  have last := sem.equalities _ _ c.finish
  rw [h5, h4, h3, h2, h1, h0, c.start] at last
  simpa only [NativeLaunchConstraintAdapterBridge.read, zero_add] using last

theorem selector_equations_from_topology (modes : Fin 6 → Word K)
    (c : SelectorData g modes) : SelectorEquations (fun i => natural z (modes i)) := by
  constructor
  · intro i
    exact ZMod.val_lt _
  · intro i
    rw [natural_cast z (modes i)]
    exact boolean_equation g layout z sem (modes i) (c.guards i)
  · rw [natural_cast z (modes 0), natural_cast z (modes 1),
      natural_cast z (modes 2), natural_cast z (modes 3),
      natural_cast z (modes 4), natural_cast z (modes 5)]
    exact selector_field_sum g layout z sem modes c

theorem unique_mode_from_topology (modes : Fin 6 → Word K) (c : SelectorData g modes) :
    ∃! i : Fin 6, natural z (modes i) = 1 :=
  unique_selected_branch _ (selector_equations_from_topology g layout z sem modes c)

/-- Indices0/1=input values,2/3=outputs,4=fee. These are role WORDS, not
caller-provided integer witnesses. Their intended source identity must be bound. -/
structure BalanceData (g : Graph K) (values : Fin 5 → Word K) where
  ranges : ∀ i, RangeData g (values i) 56
  left : Word K
  rightFirst : Word K
  right : Word K
  addLeft : AddData g (values 0) (values 1) left
  addRightFirst : AddData g (values 2) (values 3) rightFirst
  addFee : AddData g rightFirst (values 4) right
  equal : (left, right) ∈ g.equalities

theorem integer_balance_from_topology (values : Fin 5 → Word K)
    (c : BalanceData g values) :
    natural z (values 0) + natural z (values 1) =
      natural z (values 2) + natural z (values 3) + natural z (values 4) := by
  have bounds : ∀ i, natural z (values i) < valueBound := by
    intro i
    exact range_natural_bound g layout z sem (values i) 56 (c.ranges i)
      (by norm_num [modulus])
  apply integer_conservation _ _ _ _ _ (bounds 0) (bounds 1) (bounds 2) (bounds 3) (bounds 4)
  rw [natural_cast z (values 0), natural_cast z (values 1),
    natural_cast z (values 2), natural_cast z (values 3),
    natural_cast z (values 4)]
  have left := add_sound g layout z sem c.addLeft
  have rightFirst := add_sound g layout z sem c.addRightFirst
  have right := add_sound g layout z sem c.addFee
  have eq := sem.equalities _ _ c.equal
  linear_combination eq - left + rightFirst + right

/-- Source `gate(selector,a,b)`, including constant-folded operations. -/
structure GateData (g : Graph K) (selector a b : Word K) where
  difference : Word K
  product : Word K
  subtract : SubData g a b difference
  multiply : MulData g selector difference product
  zero : (product, .constant 0) ∈ g.equalities

theorem gate_equation (selector a b : Word K) (c : GateData g selector a b) :
    NativeLaunchConstraintAdapterBridge.read z selector * (NativeLaunchConstraintAdapterBridge.read z a - NativeLaunchConstraintAdapterBridge.read z b) = 0 := by
  have hs := sub_sound g layout z sem c.subtract
  have hm := mul_sound g layout z sem c.multiply
  have hz := sem.equalities _ _ c.zero
  rw [hm, hs] at hz
  exact hz

/-- Both bounded heights and the gated slack are tied to their actual words. -/
structure LockData (g : Graph K) (selector reference timeout : Word K) where
  referenceRange : RangeData g reference 48
  timeoutRange : RangeData g timeout 48
  difference : Word K
  shifted : Word K
  slack : Word K
  subtractReference : SubData g timeout reference difference
  subtractMargin : SubData g difference (.constant 14) shifted
  gate : MulData g selector shifted slack
  slackRange : RangeData g slack 48

theorem lock_safe_from_topology (selector reference timeout : Word K)
    (c : LockData g selector reference timeout) (selected : natural z selector = 1)
    (actualParent : Nat)
    (window : natural z reference ≤ actualParent ∧ actualParent ≤ natural z reference + 12) :
    actualParent + 1 < natural z timeout := by
  have bound (w : Word K) (r : RangeData g w 48) : natural z w < heightBound :=
    range_natural_bound g layout z sem w 48 r (by norm_num [modulus])
  apply lock_safe_at_inclusion _ _ _ actualParent
    (bound reference c.referenceRange) (bound timeout c.timeoutRange)
    (bound c.slack c.slackRange) ?_ window
  have selectedField : NativeLaunchConstraintAdapterBridge.read z selector = 1 := by
    rw [← natural_cast z selector, selected, Nat.cast_one]
  have difference := sub_sound g layout z sem c.subtractReference
  have shifted := sub_sound g layout z sem c.subtractMargin
  have gate := mul_sound g layout z sem c.gate
  simp only [natural_cast]
  rw [gate, selectedField, one_mul, shifted, difference]
  simp only [NativeLaunchConstraintAdapterBridge.read]


/-- Supports direct inverse=1 and impossible inverse-of-zero folded cases. -/
structure InverseData (g : Graph K) (source : Word K) where
  inverse : Fin g.count
  isInverse : g.nodes inverse = .inverse source
  product : Word K
  multiply : MulData g source (.wire inverse.val) product
  one : (product, .constant 1) ∈ g.equalities

theorem inverse_nonzero_from_topology (source : Word K) (c : InverseData g source) :
    NativeLaunchConstraintAdapterBridge.read z source * z c.inverse.val = 1 ∧ NativeLaunchConstraintAdapterBridge.read z source ≠ 0 := by
  have product := mul_sound g layout z sem c.multiply
  have one := sem.equalities _ _ c.one
  have h : NativeLaunchConstraintAdapterBridge.read z source * z c.inverse.val = 1 := by
    rw [product] at one
    exact one
  refine ⟨h, ?_⟩
  intro zero
  rw [zero, zero_mul] at h
  exact zero_ne_one h

structure RefundData (g : Graph K) (selector reference timeout : Word K) where
  referenceRange : RangeData g reference 48
  timeoutRange : RangeData g timeout 48
  difference : Word K
  slack : Word K
  subtract : SubData g reference timeout difference
  gate : MulData g selector difference slack
  slackRange : RangeData g slack 48

theorem refund_mature_from_topology (selector reference timeout : Word K)
    (c : RefundData g selector reference timeout) (selected : natural z selector = 1)
    (actualParent : Nat) (referenceNotFuture : natural z reference ≤ actualParent) :
    natural z timeout ≤ actualParent := by
  have bound (w : Word K) (r : RangeData g w 48) : natural z w < heightBound :=
    range_natural_bound g layout z sem w 48 r (by norm_num [modulus])
  apply refund_mature_at_inclusion _ _ _ actualParent
    (bound reference c.referenceRange) (bound timeout c.timeoutRange)
    (bound c.slack c.slackRange) ?_ referenceNotFuture
  have selectedField : NativeLaunchConstraintAdapterBridge.read z selector = 1 := by
    rw [← natural_cast z selector, selected, Nat.cast_one]
  have difference := sub_sound g layout z sem c.subtract
  have gate := mul_sound g layout z sem c.gate
  simp only [natural_cast]
  rw [gate, selectedField, one_mul, difference]

/-- Exact coordinate-level source gate pattern, tied to the current projection. -/
structure IntentData (g : Graph K) (selector : Word K)
    (pub : Fin 77 → Word K) (intent : Fin 54 → Word K) where
  gates : ∀ i, GateData g selector (intent i) (pub (intentSource i))

theorem exact_intent_from_topology (selector : Word K)
    (pub : Fin 77 → Word K) (intent : Fin 54 → Word K)
    (c : IntentData g selector pub intent) (selected : natural z selector = 1) :
    (fun i => NativeLaunchConstraintAdapterBridge.read z (intent i)) = intentProjection (fun i => NativeLaunchConstraintAdapterBridge.read z (pub i)) := by
  have selectedField : NativeLaunchConstraintAdapterBridge.read z selector = 1 := by
    rw [← natural_cast z selector, selected, Nat.cast_one]
  exact final_gate_binds_exact_intent _ _ _ selectedField
    (fun i => gate_equation g layout z sem selector _ _ (c.gates i))


omit sem in theorem accepted_arithmetic_from_topology
    (coverage : Covers g layout) (accepted : LoweredAccepted g layout z)
    (modes : Fin 6 → Word K) (selectors : SelectorData g modes)
    (values : Fin 5 → Word K) (balance : BalanceData g values) :
    (∃! i : Fin 6, natural z (modes i) = 1) ∧
    natural z (values 0) + natural z (values 1) =
      natural z (values 2) + natural z (values 3) + natural z (values 4) := by
  have semantics := structural_lowering_sound g layout z coverage accepted
  exact ⟨unique_mode_from_topology g layout z semantics modes selectors,
    integer_balance_from_topology g layout z semantics values balance⟩

end
end HegemonCrypto.NativePrivateSpendArithmeticTopology
