import HegemonCrypto.NativePrivateSpendCsrCertificate
import HegemonCrypto.NativePrivateSpendArithmeticTopology
import HegemonCrypto.SmallWoodV8Smz9Poseidon2TemplateRefinement

-- SERIAL_OPTION_BEGIN
set_option Elab.async false
-- SERIAL_OPTION_END

/-! Current COMPFF01 symbolic bridge: the unchanged permutation certificate is
followed by seven field-add certificates using the original left operand. This
source change requires a fresh kernel check; historical V15 raw-output receipts
do not certify it. Downstream joins and concrete graph instantiation remain
separate obligations. No hash-security or acceptance-to-semantics axiom. -/
namespace HegemonCrypto.NativePrivateSpendSymbolicBridge
open NativePrivateSpendPackedLowering NativePrivateSpendCsrCertificate
open NativePrivateSpendArithmeticTopology NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
namespace T
export HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
  (p4 m4 externalField partialSum internalField diagonal replaceZero externalStep
   internalStep externalRoundField internalRoundField StateMatches externalField_congr
   externalField_cast_kernel external_step_refines internal_step_refines)
end T
namespace Kernel
export Hegemon.Transaction.Poseidon2Width16Kernel
  (internalMatrixDiagonal externalLinearLayer externalRound internalRound permutation
   externalRoundConstantsInitial internalRoundConstants externalRoundConstantsTerminal
   external_linear_layer_length external_round_length internal_round_length)
end Kernel
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

inductive Operation where
  | add | sub | mul

instance : DecidableEq Operation
  | .add, .add => isTrue rfl
  | .add, .sub => isFalse (fun h => Operation.noConfusion h)
  | .add, .mul => isFalse (fun h => Operation.noConfusion h)
  | .sub, .add => isFalse (fun h => Operation.noConfusion h)
  | .sub, .sub => isTrue rfl
  | .sub, .mul => isFalse (fun h => Operation.noConfusion h)
  | .mul, .add => isFalse (fun h => Operation.noConfusion h)
  | .mul, .sub => isFalse (fun h => Operation.noConfusion h)
  | .mul, .mul => isTrue rfl

def Operation.matches (op : Operation) (g : Graph K) (a b out : Word K) : Prop :=
  match op with
  | .add => AddData g a b out
  | .sub => SubData g a b out
  | .mul => MulData g a b out

def Operation.apply (op : Operation) (a b : K) : K :=
  match op with
  | .add => a + b
  | .sub => a - b
  | .mul => a * b


/-- Includes every zero/one/constant fold in current Word.operation.
The hypotheses are finite node/Word equalities, not equations about z. -/
theorem matched_operation_sound (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (op : Operation) (a b out : Word K)
    (checked : op.matches g a b out) :
    read z out = op.apply (read z a) (read z b) := by
  cases op with
  | add => exact add_sound g layout z sem checked
  | sub => exact sub_sound g layout z sem checked
  | mul => exact mul_sound g layout z sem checked


inductive Expression where
  | input : Nat → Expression
  | constant : K → Expression
  | operation : Operation → Expression → Expression → Expression

def evaluate (input : Nat → K) : Expression → K
  | .input i => input i
  | .constant k => k
  | .operation op a b => op.apply (evaluate input a) (evaluate input b)

/-- A finite operation derivation, which may share child declarations in Lean.
Its leaves are actual source Word locators, never host witness values. -/
inductive Realizes (g : Graph K) (input : Nat → Word K) : Expression → Word K → Prop
  | input (i : Nat) : Realizes g input (.input i) (input i)
  | constant (k : K) : Realizes g input (.constant k) (.constant k)
  | operation {op : Operation} {a b : Expression} {wa wb out : Word K}
      (left : Realizes g input a wa) (right : Realizes g input b wb)
      (checked : op.matches g wa wb out) :
      Realizes g input (.operation op a b) out


theorem realizes_sound (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (input : Nat → Word K)
    {expression : Expression} {out : Word K} (checked : Realizes g input expression out) :
    read z out = evaluate (fun i => read z (input i)) expression := by
  induction checked with
  | input i => rfl
  | constant k => rfl
  | @operation op a b wa wb out left right checked ihLeft ihRight =>
      rw [matched_operation_sound g layout z sem op wa wb out checked, ihLeft, ihRight]
      rfl


abbrev State := Fin 16 → Word K

def words (state : State) (i : Nat) : Word K :=
  if h : i < 16 then state ⟨i,h⟩ else .constant 0

def stateValue (z : Nat → K) (state : State) (i : Nat) : K := read z (words state i)

def addE (a b : Expression) : Expression := .operation .add a b
def mulE (a b : Expression) : Expression := .operation .mul a b

def powerSeven (x : Expression) : Expression :=
  let x2 := mulE x x
  let x4 := mulE x2 x2
  let x6 := mulE x4 x2
  mulE x6 x


@[simp] theorem evaluate_add (input : Nat → K) (a b : Expression) :
    evaluate input (addE a b) = evaluate input a + evaluate input b := rfl


@[simp] theorem evaluate_mul (input : Nat → K) (a b : Expression) :
    evaluate input (mulE a b) = evaluate input a * evaluate input b := rfl


@[simp] theorem evaluate_constant (input : Nat → K) (k : K) :
    evaluate input (.constant k) = k := rfl


@[simp] theorem evaluate_input (input : Nat → K) (i : Nat) :
    evaluate input (.input i) = input i := rfl



theorem evaluate_powerSeven (input : Nat → K) (x : Expression) :
    evaluate input (powerSeven x) = (evaluate input x)^7 := by
  simp only [powerSeven, evaluate_mul]
  ring


/-- Exactly the source's left-associated four-word total. -/
def p4E (input : Nat → Expression) (q c : Nat) : Expression :=
  addE (input (4*q+c))
    (addE (addE (addE (input (4*q)) (input (4*q+1))) (input (4*q+2))) (input (4*q+3)))

def m4E (x0 x1 x2 x3 : Expression) (row : Nat) : Expression :=
  let t01 := addE x0 x1
  let t23 := addE x2 x3
  let total := addE t01 t23
  match row with
  | 0 => addE (addE total x1) t01
  | 1 => addE (addE total x1) (addE x2 x2)
  | 2 => addE (addE total x3) t23
  | 3 => addE (addE total x3) (addE x0 x0)
  | _ => .constant 0

def externalE (input : Nat → Expression) (lane : Nat) : Expression :=
  let c := lane % 4
  m4E (p4E input 0 c) (p4E input 1 c) (p4E input 2 c) (p4E input 3 c) (lane / 4)


theorem evaluate_p4 (values : Nat → K) (input : Nat → Expression) (q c : Nat) :
    evaluate values (p4E input q c) = T.p4 (fun i => evaluate values (input i)) q c := by
  simp only [p4E, evaluate_add, T.p4]
  rfl



theorem evaluate_m4 (values : Nat → K) (x0 x1 x2 x3 : Expression) (row : Nat) :
    evaluate values (m4E x0 x1 x2 x3 row) =
      T.m4 (evaluate values x0) (evaluate values x1) (evaluate values x2) (evaluate values x3) row := by
  let a := addE x0 x1
  let b := addE x2 x3
  let t := addE a b
  have h01 : evaluate values a = evaluate values x0 + evaluate values x1 :=
    evaluate_add values x0 x1
  have h23 : evaluate values b = evaluate values x2 + evaluate values x3 :=
    evaluate_add values x2 x3
  have ht : evaluate values t =
      (evaluate values x0 + evaluate values x1) +
        (evaluate values x2 + evaluate values x3) :=
    (evaluate_add values a b).trans
      (congrArg₂ (fun (u v : K) => u + v) h01 h23)
  have ht1 : evaluate values (addE t x1) =
      ((evaluate values x0 + evaluate values x1) +
        (evaluate values x2 + evaluate values x3)) + evaluate values x1 :=
    (evaluate_add values t x1).trans
      (congrArg₂ (fun (u v : K) => u + v) ht rfl)
  have ht3 : evaluate values (addE t x3) =
      ((evaluate values x0 + evaluate values x1) +
        (evaluate values x2 + evaluate values x3)) + evaluate values x3 :=
    (evaluate_add values t x3).trans
      (congrArg₂ (fun (u v : K) => u + v) ht rfl)
  rcases row with _ | (_ | (_ | (_ | row)))
  · exact (evaluate_add values (addE t x1) a).trans
      (congrArg₂ (fun (u v : K) => u + v) ht1 h01)
  · exact (evaluate_add values (addE t x1) (addE x2 x2)).trans
      (congrArg₂ (fun (u v : K) => u + v) ht1 (evaluate_add values x2 x2))
  · exact (evaluate_add values (addE t x3) b).trans
      (congrArg₂ (fun (u v : K) => u + v) ht3 h23)
  · exact (evaluate_add values (addE t x3) (addE x0 x0)).trans
      (congrArg₂ (fun (u v : K) => u + v) ht3 (evaluate_add values x0 x0))
  · exact evaluate_constant values (0 : K)



theorem evaluate_external (values : Nat → K) (input : Nat → Expression) (lane : Nat) :
    evaluate values (externalE input lane) = T.externalField (fun i => evaluate values (input i)) lane := by
  simp only [externalE, evaluate_m4, evaluate_p4, T.externalField]


/-- Source fold starts from zero; its first addition folds to the first word. -/
def sumE (input : Nat → Expression) : Nat → Expression
  | 0 => input 0
  | n+1 => addE (sumE input n) (input (n+1))


theorem evaluate_sum (values : Nat → K) (input : Nat → Expression) (n : Nat) :
    evaluate values (sumE input n) = T.partialSum (fun i => evaluate values (input i)) n := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [sumE, evaluate_add, ih, T.partialSum]; exact add_comm _ _


def internalE (input : Nat → Expression) (lane : Nat) : Expression :=
  addE (mulE (input lane) (.constant (Kernel.internalMatrixDiagonal.getD lane 0 : K)))
    (sumE input 15)


theorem evaluate_internal (values : Nat → K) (input : Nat → Expression) (lane : Nat) :
    evaluate values (internalE input lane) = T.internalField (fun i => evaluate values (input i)) lane := by
  simp only [internalE, evaluate_add, evaluate_mul, evaluate_constant, evaluate_sum,
    T.internalField, T.diagonal]
  rfl


inductive Round where
  | initial
  | external : List Nat → Round
  | internal : Nat → Round

def roundExpression : Round → Nat → Expression
  | .initial => externalE Expression.input
  | .external constants => externalE (fun i => powerSeven (addE (.input i) (.constant (constants.getD i 0 : K))))
  | .internal constant => internalE (fun i => if i = 0 then
      powerSeven (addE (.input 0) (.constant (constant : K))) else .input i)

def roundField : Round → (Nat → K) → Nat → K
  | .initial => T.externalField
  | .external constants => fun input => T.externalStep input constants
  | .internal constant => fun input => T.internalStep input constant

def roundKernel : Round → List Nat → List Nat
  | .initial => Kernel.externalLinearLayer
  | .external constants => fun input => Kernel.externalRound input constants
  | .internal constant => fun input => Kernel.internalRound input constant


theorem evaluate_round (values : Nat → K) (round : Round) (lane : Nat) :
    evaluate values (roundExpression round lane) = roundField round values lane := by
  cases round with
  | initial => simpa only [roundExpression, roundField, evaluate_input] using
      evaluate_external values Expression.input lane
  | external constants =>
      simp only [roundExpression, roundField, evaluate_external, evaluate_powerSeven,
        evaluate_add, evaluate_input, evaluate_constant, T.externalStep, T.externalRoundField]
      rfl
  | internal constant =>
      simp only [roundExpression, roundField, evaluate_internal, T.internalStep, T.internalRoundField]
      congr 1
      funext i
      by_cases h : i = 0
      · subst i
        simp only [T.replaceZero, if_true, evaluate_powerSeven,
          evaluate_add, evaluate_input, evaluate_constant]
        rfl
      · simp only [T.replaceZero, if_neg h, evaluate_input]


/-- Per-lane finite operation derivations. No output-value premise. -/
def RoundChecked (g : Graph K) (round : Round) (input output : State) : Prop :=
  ∀ lane : Fin 16, Realizes g (words input) (roundExpression round lane.val) (output lane)


theorem checked_round_equation (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (round : Round) (input output : State)
    (checked : RoundChecked g round input output) (lane : Fin 16) :
    stateValue z output lane.val = roundField round (stateValue z input) lane.val := by
  have h := realizes_sound g layout z sem (words input) (checked lane)
  rw [evaluate_round] at h
  change read z (output lane) = roundField round (stateValue z input) lane.val at h
  have lhs : stateValue z output lane.val = read z (output lane) := by
    change read z (words output lane.val) = read z (output lane)
    unfold words
    rw [dif_pos lane.isLt]
  exact lhs.trans h



omit [Fact (Nat.Prime modulus)] in
theorem round_kernel_shape (round : Round) (values : List Nat) (_shape : values.length = 16) :
    (roundKernel round values).length = 16 := by
  cases round with
  | initial => exact Kernel.external_linear_layer_length values
  | external constants => exact Kernel.external_round_length values constants
  | internal constant => exact Kernel.internal_round_length values constant



/-- Compose the checked graph equation with unchanged PR205 kernel algebra. -/
theorem checked_round_refines_kernel (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (round : Round) (input output : State)
    (checked : RoundChecked g round input output) (values : List Nat)
    (shape : values.length = 16) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output) (roundKernel round values) := by
  have next : T.StateMatches (roundField round (stateValue z input)) (roundKernel round values) := by
    cases round with
    | initial =>
        constructor
        intro i hi
        exact (T.externalField_congr _ _ matched.lane ⟨i,hi⟩).trans
          (T.externalField_cast_kernel values ⟨i,hi⟩).symm
    | external constants => exact T.external_step_refines _ values constants matched
    | internal constant => exact T.internal_step_refines _ values constant shape matched
  constructor
  intro i hi
  exact (checked_round_equation g layout z sem round input output checked ⟨i,hi⟩).trans (next.lane i hi)


inductive ChainChecked (g : Graph K) : List Round → State → State → Prop
  | nil (state : State) : ChainChecked g [] state state
  | cons {round : Round} {rounds : List Round} {input middle output : State}
      (step : RoundChecked g round input middle)
      (tail : ChainChecked g rounds middle output) :
      ChainChecked g (round :: rounds) input output

def runKernel (rounds : List Round) (values : List Nat) : List Nat :=
  rounds.foldl (fun state round => roundKernel round state) values


theorem checked_chain_refines_kernel (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) {rounds : List Round} {input output : State}
    (checked : ChainChecked g rounds input output) (values : List Nat)
    (shape : values.length = 16) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output) (runKernel rounds values) := by
  induction checked generalizing values with
  | nil state => exact matched
  | @cons round rounds input middle output step tail ih =>
      exact ih (roundKernel round values) (round_kernel_shape round values shape)
        (checked_round_refines_kernel g layout z sem round input middle step values shape matched)


def permutationSchedule : List Round :=
  [.initial] ++ Kernel.externalRoundConstantsInitial.map Round.external ++
    Kernel.internalRoundConstants.map Round.internal ++
    Kernel.externalRoundConstantsTerminal.map Round.external


omit [Fact (Nat.Prime modulus)] in
theorem run_permutationSchedule (values : List Nat) :
    runKernel permutationSchedule values = Kernel.permutation values := by
  simp only [runKernel, permutationSchedule, List.foldl_append, List.foldl_cons,
    List.foldl_nil, List.foldl_map, roundKernel, Kernel.permutation]



theorem checked_permutation_refines_kernel (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (input output : State)
    (checked : ChainChecked g permutationSchedule input output) (values : List Nat)
    (shape : values.length = 16) (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output) (Kernel.permutation values) := by
  simpa only [run_permutationSchedule] using
    checked_chain_refines_kernel g layout z sem checked values shape matched


/-- Current replay binary record: five little-endian u64s. Byte decoding remains
in the disclosed native/data interpretation boundary. Tag3 coordinate order is
(batch,lane,operand), matching request-citations.bin, not batch/operand/lane. -/
structure CitationRecord where
  tag : Nat
  a : Nat
  b : Nat
  c : Nat
  row : Nat

def requestCoordinates {g : Graph K} {layout : Layout K} : Request g layout → Nat × Nat × Nat × Nat
  | .node i => (0,i.val,0,0)
  | .equality i => (1,i.val,0,0)
  | .padding i => (2,i.val,0,0)
  | .copy batch lane operand => (3,batch.val,lane.val,operand.val)
  | .publicBinding i => (4,i.val,0,0)

def citationLocator (csr : RawCSR K) (record : CitationRecord) : Option (Fin csr.rowCount) :=
  if h : record.row < csr.rowCount then some ⟨record.row,h⟩ else none

/-- Finite row identities checked against the actual CSR, not a source-semantic
conclusion. All Request constructors are covered by the dependent function. -/
structure CitationData (g : Graph K) (layout : Layout K) (csr : RawCSR K) where
  record : Request g layout → CitationRecord
  coordinates : ∀ request, ((record request).tag,(record request).a,
    (record request).b,(record request).c) = requestCoordinates request
  rowCanonical : ∀ request, (record request).row < csr.rowCount ∨
    (record request).row = 2^64-1
  checked : ∀ request, RowDataCheck csr (citationLocator csr (record request))
    (requested g layout request)


theorem citation_data_structural (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0) :
    StructuralSemantics g layout z :=
  certified_raw_csr_implies_structural_semantics g layout csr
    (fun request => citationLocator csr (data.record request)) data.checked coverage z linear products



/-- End-to-end algebraic adapter for ANY satisfying packed assignment. Its
premises are normalized-CSR/product acceptance and finite data certificates. -/
theorem packed_checked_permutation (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (input output : State) (checked : ChainChecked g permutationSchedule input output)
    (values : List Nat) (shape : values.length = 16)
    (matched : T.StateMatches (stateValue z input) values) :
    T.StateMatches (stateValue z output) (Kernel.permutation values) :=
  checked_permutation_refines_kernel g layout z
    (citation_data_structural g layout csr data coverage z linear products)
    input output checked values shape matched



/-- Canonical input representatives are read from arbitrary z, never a serialized
host witness. This removes any caller-supplied initial-value equation. -/
def stateNaturals (z : Nat → K) (input : State) : List Nat :=
  (List.range 16).map (fun i => (stateValue z input i).val)


theorem stateNaturals_length (z : Nat → K) (input : State) :
    (stateNaturals z input).length = 16 := by simp [stateNaturals]



theorem stateNaturals_matches (z : Nat → K) (input : State) :
    T.StateMatches (stateValue z input) (stateNaturals z input) := by
  constructor
  intro i hi
  simp only [stateNaturals, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range hi, Option.map_some, Option.getD_some]
  change stateValue z input i = ((stateValue z input i).val : K)
  exact (ZMod.natCast_zmod_val (stateValue z input i)).symm



theorem packed_permutation_lane (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (input output : State) (checked : ChainChecked g permutationSchedule input output)
    (lane : Fin 16) :
    read z (output lane) =
      (Kernel.permutation (stateNaturals z input) |>.getD lane.val 0 : K) := by
  have h := packed_checked_permutation g layout csr data coverage z linear products
    input output checked (stateNaturals z input) (stateNaturals_length z input)
    (stateNaturals_matches z input)
  have hLane := h.lane lane.val lane.isLt
  change stateValue z output lane.val =
    (Kernel.permutation (stateNaturals z input) |>.getD lane.val 0 : K) at hLane
  have lhs : stateValue z output lane.val = read z (output lane) := by
    change read z (words output lane.val) = read z (output lane)
    unfold words
    rw [dif_pos lane.isLt]
  exact lhs.symm.trans hLane


abbrev DigestWords := Fin 7 → Word K

def compressFrame (domain : K) (left right : DigestWords) : State := fun lane =>
  if h : lane.val < 7 then left ⟨lane.val,h⟩
  else if h2 : lane.val < 14 then right ⟨lane.val-7,by omega⟩
  else if lane.val = 14 then .constant domain
  else .constant (0x434f4d5046463031 : K)

/-- Fresh COMPFF01 domain/left7/right7/mode frame. The seven digest words
are the raw permutation output plus the ORIGINAL left operand. All fields
are syntax/finite operation data independent of z. -/
structure CompressChecked (g : Graph K) (domain : K)
    (left right role : DigestWords) where
  input : State
  output : State
  inputFrame : input = compressFrame domain left right
  permutation : ChainChecked g permutationSchedule input output
  outputAdds : ∀ lane : Fin 7,
    AddData g (output ⟨lane.val,by omega⟩) (left lane) (role lane)


theorem packed_compress_role (g : Graph K) (layout : Layout K) (csr : RawCSR K)
    (data : CitationData g layout csr) (coverage : Covers g layout) (z : Nat → K)
    (linear : RawSatisfied csr z)
    (products : ∀ batch lane, Products.productResidual (occurrence layout z batch lane) = 0)
    (domain : K) (left right role : DigestWords)
    (checked : CompressChecked g domain left right role) (lane : Fin 7) :
    read z (role lane) =
      (Kernel.permutation (stateNaturals z (compressFrame domain left right))
        |>.getD lane.val 0 : K) + read z (left lane) := by
  have sem := citation_data_structural g layout csr data coverage z linear products
  have add := add_sound g layout z sem (checked.outputAdds lane)
  have h := packed_permutation_lane g layout csr data coverage z linear products
    checked.input checked.output checked.permutation ⟨lane.val,by omega⟩
  have permutation : read z (checked.output ⟨lane.val,by omega⟩) =
      (Kernel.permutation (stateNaturals z (compressFrame domain left right))
        |>.getD lane.val 0 : K) := by
    simpa only [checked.inputFrame] using h
  exact add.trans (congrArg (fun x : K => x + read z (left lane)) permutation)


end
end HegemonCrypto.NativePrivateSpendSymbolicBridge
