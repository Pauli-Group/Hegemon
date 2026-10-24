import HegemonCrypto.NativePrivateSpendSymbolicBridge

/-! Exact current rate8 sponge framing and block chaining. Uncompiled source.
No caller-provided output law: each absorption is finite AddData/Word equality,
and each permutation consists of the previous operation-derived certificate. -/
namespace HegemonCrypto.NativePrivateSpendSpongeBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendPackedLowering
open NativePrivateSpendCsrCertificate NativePrivateSpendArithmeticTopology
open NativePrivateSpendLocalSemantics NativeLaunchConstraintAdapterBridge
namespace Kernel
export Hegemon.Transaction.Poseidon2Width16Kernel (fieldAdd permutation)
end Kernel
namespace T
export HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement (StateMatches cast_fieldAdd)
end T
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

/-- Empty messages still have one permutation, as in the native source. -/
def blockCount (length : Nat) : Nat := max 1 ((length+7)/8)

def spongeFrame (domain : K) (length : Nat) : State := fun lane =>
  .constant (if lane.val = 8 then domain else if lane.val = 9 then (length : K)
    else if lane.val = 10 then (0x53504f4e47455631 : K)
    else if lane.val = 15 then (0x4845475f50323136 : K) else 0)

def messageValue (z : Nat → K) (message : List (Word K)) (i : Nat) : K :=
  read z (message.getD i (.constant 0))

/-- Only additions for lanes actually carrying a message are required.
Absent payload lanes and all untouched capacity lanes are exact Word copies. -/
def AbsorbChecked (g : Graph K) (message : List (Word K)) (block : Nat)
    (last : Bool) (input output : State) : Prop :=
  ∀ lane : Fin 16,
    if lane.val < 8 ∧ 8*block+lane.val < message.length then
      AddData g (input lane) (message.getD (8*block+lane.val) (.constant 0)) (output lane)
    else if lane.val = 11 ∧ last = true then
      AddData g (input lane) (.constant 1) (output lane)
    else output lane = input lane

def absorbField (message : Nat → K) (length block : Nat) (last : Bool)
    (input : Nat → K) (lane : Nat) : K :=
  if lane < 8 ∧ 8*block+lane < length then input lane + message (8*block+lane)
  else if lane = 11 ∧ last = true then input lane + 1 else input lane

theorem checked_absorb_equation (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (message : List (Word K)) (block : Nat)
    (last : Bool) (input output : State) (checked : AbsorbChecked g message block last input output)
    (lane : Fin 16) :
    stateValue z output lane.val =
      absorbField (messageValue z message) message.length block last (stateValue z input) lane.val := by
  have h := checked lane
  unfold AbsorbChecked at checked
  unfold absorbField
  split_ifs with occupied marker
  · have step : AddData g (input lane) (message.getD (8*block+lane.val) (.constant 0)) (output lane) := by
      simpa only [if_pos occupied] using h
    simpa only [stateValue, words, dif_pos lane.isLt, messageValue] using
      add_sound g layout z sem step
  · have step : AddData g (input lane) (.constant 1) (output lane) := by
      simpa only [if_neg occupied, if_pos marker] using h
    simpa only [stateValue, words, dif_pos lane.isLt, NativeLaunchConstraintAdapterBridge.read] using
      add_sound g layout z sem step
  · have same : output lane = input lane := by
      simpa only [if_neg occupied, if_neg marker] using h
    simp only [stateValue, words, dif_pos lane.isLt, same]

def absorbNaturals (message : Nat → Nat) (length block : Nat) (last : Bool)
    (input : List Nat) : List Nat :=
  (List.range 16).map (fun lane =>
    if lane < 8 ∧ 8*block+lane < length then
      Kernel.fieldAdd (input.getD lane 0) (message (8*block+lane))
    else if lane = 11 ∧ last = true then Kernel.fieldAdd (input.getD lane 0) 1
    else input.getD lane 0)

omit [Fact (Nat.Prime modulus)] in
theorem absorbNaturals_length (message : Nat → Nat) (length block : Nat)
    (last : Bool) (input : List Nat) :
    (absorbNaturals message length block last input).length = 16 := by simp [absorbNaturals]

theorem checked_absorb_matches (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (message : List (Word K)) (block : Nat)
    (last : Bool) (input output : State) (checked : AbsorbChecked g message block last input output)
    (values : List Nat) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output)
      (absorbNaturals (fun i => (messageValue z message i).val) message.length block last values) := by
  constructor
  intro i hi
  rw [checked_absorb_equation g layout z sem message block last input output checked ⟨i,hi⟩]
  simp only [absorbNaturals, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range hi, Option.map_some, Option.getD_some]
  unfold absorbField
  split_ifs
  · simp only [HegemonCrypto.SmallWood.toGoldilocks, T.cast_fieldAdd, matched.lane i hi]
    change (values.getD i 0 : K) + messageValue z message (8*block+i) =
      (values.getD i 0 : K) + ((messageValue z message (8*block+i)).val : K)
    exact congrArg (fun x : K => (values.getD i 0 : K) + x)
      (ZMod.natCast_zmod_val (messageValue z message (8*block+i))).symm
  · simp only [HegemonCrypto.SmallWood.toGoldilocks, T.cast_fieldAdd, matched.lane i hi]
    rfl
  · exact matched.lane i hi

structure BlockChecked (g : Graph K) (message : List (Word K)) (block : Nat)
    (last : Bool) (input output : State) where
  absorbed : State
  absorb : AbsorbChecked g message block last input absorbed
  permutation : ChainChecked g permutationSchedule absorbed output

def runBlock (message : Nat → Nat) (length block : Nat) (last : Bool)
    (values : List Nat) : List Nat :=
  Kernel.permutation (absorbNaturals message length block last values)

theorem checked_block_matches (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (message : List (Word K)) (block : Nat)
    (last : Bool) (input output : State) (checked : BlockChecked g message block last input output)
    (values : List Nat) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output)
      (runBlock (fun i => (messageValue z message i).val) message.length block last values) :=
  checked_permutation_refines_kernel g layout z sem checked.absorbed output checked.permutation
    _ (absorbNaturals_length _ _ _ _ _)
    (checked_absorb_matches g layout z sem message block last input checked.absorbed checked.absorb values matched)

/-- A countdown makes exactly the final block carry the source lane11 marker. -/
inductive SpongeChain (g : Graph K) (message : List (Word K)) :
    Nat → Nat → State → State → Prop
  | nil (first : Nat) (state : State) : SpongeChain g message first 0 state state
  | cons {first count : Nat} {input middle output : State}
      (block : BlockChecked g message first (decide (count = 0)) input middle)
      (tail : SpongeChain g message (first+1) count middle output) :
      SpongeChain g message first (count+1) input output

def runBlocks (message : Nat → Nat) (length : Nat) : Nat → Nat → List Nat → List Nat
  | _, 0, values => values
  | first, count+1, values =>
      runBlocks message length (first+1) count
        (runBlock message length first (decide (count=0)) values)

theorem checked_blocks_match (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (message : List (Word K))
    {first count : Nat} {input output : State} (checked : SpongeChain g message first count input output)
    (values : List Nat) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output)
      (runBlocks (fun i => (messageValue z message i).val) message.length first count values) := by
  induction checked generalizing values with
  | nil first state => exact matched
  | @cons first count input middle output block tail ih =>
      exact ih _ (checked_block_matches g layout z sem message first (decide (count=0))
        input middle block values matched)

structure SpongeChecked (g : Graph K) (domain : K)
    (message : List (Word K)) (role : DigestWords) where
  input : State
  output : State
  frame : input = spongeFrame domain message.length
  chain : SpongeChain g message 0 (blockCount message.length) input output
  roleWords : ∀ lane : Fin 7, role lane = output ⟨lane.val,by omega⟩

/-- Pure algorithmic definition: source frame + exact block absorption/marker +
the old pinned permutation. It does not mention the output role or acceptance. -/
def spongeNaturals (z : Nat → K) (domain : K) (message : List (Word K)) : List Nat :=
  runBlocks (fun i => (messageValue z message i).val) message.length 0
    (blockCount message.length) (stateNaturals z (spongeFrame domain message.length))

theorem packed_sponge_role (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (domain : K) (message : List (Word K)) (role : DigestWords)
    (checked : SpongeChecked g domain message role) (lane : Fin 7) :
    read z (role lane) = (spongeNaturals z domain message |>.getD lane.val 0 : K) := by
  have sem := citation_data_structural g layout csr data coverage z linear products
  have h := checked_blocks_match g layout z sem message checked.chain
    (stateNaturals z checked.input) (stateNaturals_matches z checked.input)
  have value := h.lane lane.val (by omega)
  change stateValue z checked.output lane.val =
    (runBlocks (fun i => (messageValue z message i).val) message.length 0
      (blockCount message.length) (stateNaturals z checked.input) |>.getD lane.val 0 : K) at value
  rw [checked.frame] at value
  have lhs : stateValue z checked.output lane.val =
      read z (checked.output ⟨lane.val,by omega⟩) := by
    change read z (words checked.output lane.val) = _
    unfold words
    rw [dif_pos (show lane.val < 16 by omega)]
  rw [checked.roleWords lane]
  exact lhs.symm.trans value

/-- Direct common-case semantic core for the same arbitrary accepted assignment,
ready to join the role equations above; no separately assumed selector/balance law. -/
theorem packed_selector_and_balance (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (modes : Fin 6 → Word K) (selectors : SelectorData g modes)
    (values : Fin 5 → Word K) (balance : BalanceData g values) :
    (∃! branch : Fin 6, natural z (modes branch) = 1) ∧
      natural z (values 0) + natural z (values 1) =
        natural z (values 2) + natural z (values 3) + natural z (values 4) := by
  have sem := citation_data_structural g layout csr data coverage z linear products
  exact ⟨unique_mode_from_topology g layout z sem modes selectors,
    integer_balance_from_topology g layout z sem values balance⟩

end
end HegemonCrypto.NativePrivateSpendSpongeBridge
