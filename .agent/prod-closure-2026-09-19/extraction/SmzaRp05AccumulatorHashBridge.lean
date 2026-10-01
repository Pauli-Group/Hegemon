import SmzaRp05AuthSourceBridge
import HegemonCrypto.SmallWoodV8Smz9SemanticPoseidonKernelBinding
import HegemonCrypto.SmallWoodV8Smz9AccumulatorSponge
import SmzaRp05AccumulatorFrameLookup

/-!
Current-program hash transport. Source draft: not compiled in this session.
Certificates consist of finite syntax/root/CSR facts, never hash equalities
or implications quantified over witnesses. The reference expression DAG is
used only to identify the unchanged width16 permutation; its acceptance
predicate does not occur.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex rawIndex)
open V8Smz9SemanticDecoder (packedWord packed_word_canonical)
open V8Smz9ProgramPolynomials
open V8Smz9SemanticDenseRange (canonical_nat_cast_injective)
open V8Smz9SemanticCryptographicLinks
open V8Smz9SemanticPoseidonKernelBinding
open V8Smz9Poseidon2TemplateRefinement
open SmzaRp05TypedRelation
open SmzaRp05AuthSourceBridge
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

abbrev F := HegemonCrypto.SmallWood.Goldilocks

/-- 332 finite syntactic recurrences, covering both groups and every hash
wire. The same term is realized at the current root and reference kernel
node, allowing changed node numbering and changed surrounding AUTH code. -/
structure KernelCertificate (components : RelationProgramComponents) where
  canonical : components.nonlinearExecutable.Canonical true
  root : Fin 2 → Fin 166 → Nat
  term : Fin 2 → Fin 166 → SourceTerm
  member : ∀ group wire, root group wire ∈ components.nonlinearExecutable.roots
  current : ∀ group wire,
    Realizes components.nonlinearExecutable.expressions (root group wire)
      (.sub (.witness (hashRow group.val wire.val)) (term group wire))
  reference : ∀ group wire,
    Realizes V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions
      (hashRootPair group.val wire.val).2 (term group wire)

theorem accepted_hash_recurrence {components : RelationProgramComponents}
    (certificate : KernelCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {group wire lane : Nat} (groupBound : group < 2) (wireBound : wire < 166)
    (laneBound : lane < 64) :
    laneField packed lane (hashRow group wire) =
      fieldAt V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions
        (fun n => (publicWords.getD n 0 : F)) (laneField packed lane)
        (hashRootPair group wire).2 := by
  let g : Fin 2 := ⟨group, groupBound⟩
  let w : Fin 166 := ⟨wire, wireBound⟩
  obtain ⟨values, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) (certificate.member g w)
  have source := fieldAt_refines_source components.nonlinearExecutable publicWords
    (packedWitnessLaneRows packed lane) values certificate.canonical evaluated
    (certificate.root g w) (certificate.canonical.2 _ (certificate.member g w))
  rw [fieldAt_of_realizes (certificate.current g w)] at source
  have rhsZero : (values.getD (certificate.root g w) 0 : F) = 0 := by
    simp only [List.getD_eq_getElem?_getD, zero, Option.getD_some]
    norm_num
  rw [rhsZero] at source
  rw [fieldAt_of_realizes (certificate.reference g w)]
  exact sub_eq_zero.mp source

theorem accepted_hash_call_final_refines_kernel {components : RelationProgramComponents}
    (certificate : KernelCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    (HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord packed
      (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) : F) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call) |>.getD limb 0 : F) := by
  have groupBound : call / 64 < 2 := by omega
  have laneBound : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have initial : StateMatches
      (fun i => laneField packed (call%64) (283+182*(call/64)+i))
      (packedInitialState packed call) := by
    constructor
    intro i bound
    rw [laneField_eq_packedWord packed _ _ (by omega)]
    simp only [packedInitialState, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range bound, Option.map_some, Option.getD_some]
    congr 2
    simp [Poseidon2V8DecoderRefinement.hashInitialIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.packingFactor, Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
  have final := hash_recurrence_refines_kernel (fun n => (publicWords.getD n 0 : F))
    (laneField packed (call%64)) groupBound
    (fun _ bound => accepted_hash_recurrence certificate accepted groupBound bound laneBound)
    (packedInitialState packed call) initial ⟨limb,limbBound⟩
  rw [laneField_eq_packedWord packed _ _ (by omega)] at final
  have indexEq : (449+182*(call/64)+limb)*64+call%64 =
      Poseidon2V8DecoderRefinement.hashFinalIndex call limb := by
    simp [Poseidon2V8DecoderRefinement.hashFinalIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.hashFinalRowOffset, Poseidon2V8DecoderRefinement.packingFactor,
      Nat.mul_add, Nat.mul_comm, Nat.add_assoc]
    omega
  simpa only [indexEq] using final
theorem accepted_hash_call_final_eq_kernel {components : RelationProgramComponents}
    (certificate : KernelCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord packed
      (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) =
      (Poseidon2Width16Kernel.permutation (packedInitialState packed call)).getD limb 0 := by
  have callGroup : call / 64 < 2 := by omega
  have callLane : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have indexBound : Poseidon2V8DecoderRefinement.hashFinalIndex call limb <
      Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount := by
    simp only [Poseidon2V8DecoderRefinement.hashFinalIndex,
      Poseidon2V8DecoderRefinement.hashRowStart, Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Poseidon2V8DecoderRefinement.hashFinalRowOffset, Poseidon2V8DecoderRefinement.packingFactor,
      Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount]
    omega
  have packedBound := (HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.canonical_packed_coordinate
    accepted.2.1 indexBound).2
  exact HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.canonical_nat_cast_injective
    packedBound (kernel_permutation_word_canonical (packedInitialState packed call) ⟨limb,limbBound⟩)
    (accepted_hash_call_final_refines_kernel certificate accepted callBound limbBound)

def packedFinalState (packed : List Nat) (call : Nat) : List Nat :=
  (List.range 16).map fun limb => packedWord packed (hashFinalIndex call limb)

private theorem packedFinalState_getElemD (packed : List Nat) (call lane : Nat)
    (laneBound : lane < 16) :
    (packedFinalState packed call)[lane]?.getD 0 =
      packed[hashFinalIndex call lane]?.getD 0 := by
  simp only [packedFinalState, List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some, packedWord,
    List.getD_eq_getElem?_getD]

private theorem packedFinalState_getD (packed : List Nat) (call lane : Nat)
    (laneBound : lane < 16) :
    (packedFinalState packed call).getD lane 0 = packed.getD (hashFinalIndex call lane) 0 := by
  simpa only [List.getD_eq_getElem?_getD] using
    packedFinalState_getElemD packed call lane laneBound

private theorem permutation_length (input : List Nat) :
    (Poseidon2Width16Kernel.permutation input).length = 16 := by
  simp [Poseidon2Width16Kernel.permutation,
    Poseidon2Width16Kernel.externalRoundConstantsTerminal,
    Poseidon2Width16Kernel.width]

theorem accepted_hash_call_state {components : RelationProgramComponents}
    (certificate : KernelCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {call : Nat} (bound : call < 128) :
    Poseidon2Width16Kernel.permutation (packedInitialState packed call) =
      packedFinalState packed call := by
  apply List.ext_getElem
  · simp [packedFinalState, permutation_length]
  · intro limb leftBound rightBound
    have limbBound : limb < 16 := by simpa [permutation_length] using leftBound
    have equal := accepted_hash_call_final_eq_kernel certificate accepted bound limbBound
    have equal' := equal.symm
    rw [List.getD_eq_getElem _ _ leftBound] at equal'
    simpa [packedFinalState, List.getElem_map, List.getElem_range] using equal'

/-- Compose accepted current hash traces with the three exact source frames.
These are initial-state/source equations, not assumed digest equations.
The CSR frame adapter below is responsible for supplying them. -/
theorem accepted_accumulator_sponge {components : RelationProgramComponents}
    (certificate : KernelCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (first : Nat) (schedule : first = 100 ∨ first = 103)
    (inputs : List Nat) (shape : inputs.length = 23)
    (initial : packedInitialState packed first =
      V8Smz9AccumulatorSponge.accumulatorFirstFrame inputs)
    (middle : packedInitialState packed (first + 1) =
      V8Smz9AccumulatorSponge.accumulatorMiddleFrame inputs
        (packedFinalState packed first))
    (last : packedInitialState packed (first + 2) =
      V8Smz9AccumulatorSponge.accumulatorLastFrame inputs
        (packedFinalState packed (first + 1))) :
    poseidon2V8Sponge poseidon2V8AccumulatorDomain inputs =
      (packedFinalState packed (first + 2)).take digestWords := by
  apply V8Smz9AccumulatorSponge.accumulator_sponge_of_frame_chain
    inputs (packedFinalState packed first) (packedFinalState packed (first + 1))
    (packedFinalState packed (first + 2)) shape
    (by simp [packedFinalState]) (by simp [packedFinalState])
  · rw [← initial]
    exact accepted_hash_call_state certificate accepted (by omega)
  · rw [← middle]
    exact accepted_hash_call_state certificate accepted (by omega)
  · rw [← last]
    exact accepted_hash_call_state certificate accepted (by omega)


/-- Fixed mode-binding compression cells, exactly calls107/108. -/
abbrev BoundCell := Fin 2 × Fin 16

def boundSource (cell : BoundCell) : Option Nat :=
  if cell.2.val < 5 then some (97 * 64 + cell.2.val)
  else if cell.2.val < 7 then none
  else if cell.2.val < 14 then
    if cell.1.val = 0 then some (hashFinalIndex 102 (cell.2.val - 7))
    else some (109 * 64 + cell.2.val - 7)
  else none

def boundConstant (cell : BoundCell) : Nat :=
  if cell.2.val = 14 then 0x484d_4244_5632_0001
  else if cell.2.val = 15 then 0x4845_475f_5032_3136
  else 0

/-- All32 fixed native bound-authorization input cells, including the two
zero key-padding limbs, domain, suite, current digest and selected-secondary
vector. The latter's mode selection is the separately checked local AUTH
equation; this certificate does not replace that equation. -/
structure BoundFrameCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  oneNode : Nat
  negativeNode : Nat
  constantNode : BoundCell → Nat
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeRealizes : Realizes components.csrExpressions negativeNode
    (.sub (.constant 0) (.constant 1))
  constantRealizes : ∀ cell, Realizes components.csrExpressions (constantNode cell)
    (.constant (boundConstant cell))
  attempt : BoundCell → CsrExecutableAttempt
  member : ∀ cell, attempt cell ∈ components.csrAttempts
  terms : ∀ cell, (attempt cell).terms =
    (hashInitialIndex (107 + cell.1.val) cell.2.val, oneNode) ::
      ((boundSource cell).toList.map fun index => (index, negativeNode))
  target : ∀ cell, (attempt cell).targetRoot = constantNode cell

private theorem realizes_bound {expressions : List FieldExpression}
    {node : Nat} {term : SourceTerm} (realizes : Realizes expressions node term) :
    node < expressions.length := by
  induction realizes with
  | constant found => exact (List.getElem?_eq_some_iff.mp found).1
  | publicInput found => exact (List.getElem?_eq_some_iff.mp found).1
  | witness found => exact (List.getElem?_eq_some_iff.mp found).1
  | add found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
  | sub found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
  | mul found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1

private theorem csr_realizes_value {components : RelationProgramComponents}
    (canonical : ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions = some values)
    {node : Nat} {term : SourceTerm}
    (realizes : Realizes components.csrExpressions node term) :
    (values.getD node 0 : F) =
      term.eval (fun i => (publicWords.getD i 0 : F)) (fun _ => 0) := by
  have source := fieldAt_refines_source
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values canonical evaluated node (realizes_bound realizes)
  rw [fieldAt_of_realizes realizes] at source
  simpa using source.symm

def boundFrame (packed : List Nat) (which : Fin 2) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 5 then packed.getD (97 * 64 + lane) 0
    else if lane < 7 then 0
    else if lane < 14 then
      if which.val = 0 then packed.getD (hashFinalIndex 102 (lane - 7)) 0
      else packed.getD (109 * 64 + lane - 7) 0
    else if lane = 14 then 0x484d_4244_5632_0001
    else 0x4845_475f_5032_3136

private theorem boundFrame_word_bounded (packed : List Nat)
    (packedBound : ∀ index, packed.getD index 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (which : Fin 2) (lane : Fin 16) :
    (boundFrame packed which).getD lane.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  by_cases hwhich : which.val = 0
  · fin_cases lane <;> simp [boundFrame, hwhich] <;>
      first | exact packedBound _ | decide
  · fin_cases lane <;> simp [boundFrame, hwhich] <;>
      first | exact packedBound _ | decide

theorem accepted_bound_frame_word {components : RelationProgramComponents}
    (certificate : BoundFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (cell : BoundCell) :
    packed.getD (hashInitialIndex (107 + cell.1.val) cell.2.val) 0 =
      (boundFrame packed cell.1).getD cell.2.val 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD certificate.oneNode 0 : F) = 1 := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      certificate.oneRealizes
  have negative : (values.getD certificate.negativeNode 0 : F) = -1 := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      certificate.negativeRealizes
  have constant : (values.getD (certificate.constantNode cell) 0 : F) =
      (boundConstant cell : F) := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      (certificate.constantRealizes cell)
  have equation := V8Smz9SemanticDenseRange.accepted_csr_attempt_field_equality
    (attempts _ (certificate.member cell))
  rw [certificate.terms cell, certificate.target cell] at equation
  have cellBound := cell.2.isLt
  have targetBound : (boundFrame packed cell.1).getD cell.2.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    exact boundFrame_word_bounded packed
      (packed_word_canonical accepted.2.1) cell.1 cell.2
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 _) targetBound
  simp only [boundFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range cellBound, Option.map_some, Option.getD_some]
  simp only [V8Smz9SemanticDenseRange.csrFieldSum, boundSource] at equation
  simp only [packedWord, List.getD_eq_getElem?_getD]
  split_ifs at equation ⊢ <;>
    simp_all [List.map, Option.toList, boundConstant] <;>
    split_ifs at equation ⊢ <;> simp_all <;>
      first | omega | linear_combination equation

theorem accepted_bound_initial_state {components : RelationProgramComponents}
    (certificate : BoundFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedInitialState packed (107 + which.val) = boundFrame packed which := by
  apply List.ext_getElem
  · simp [packedInitialState, boundFrame]
  · intro lane hleft hright
    have bound : lane < 16 := by simpa [packedInitialState] using hleft
    have word := accepted_bound_frame_word certificate accepted (which, ⟨lane, bound⟩)
    simpa [packedInitialState, boundFrame, packedWord, List.getD_eq_getElem,
      bound] using word

/-- The full seven-word digest is the actual domain-separated compress14
permutation output. It is derived from accepted current roots and fixed CSR
sources, rather than supplied as a semantic certificate field. -/
theorem accepted_bound_authorization_digest {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (frame : BoundFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (which : Fin 2) :
    (packedFinalState packed (107 + which.val)).take 7 =
      (Poseidon2Width16Kernel.permutation (boundFrame packed which)).take 7 := by
  have trace := accepted_hash_call_state kernel accepted
    (call := 107 + which.val) (by have := which.isLt; omega)
  rw [accepted_bound_initial_state frame accepted which] at trace
  exact congrArg (List.take 7) trace.symm


/-! ## Call106 value-lock compression -/

/-- The current RP05 source constant `AUTH_VALUE_LOCK_DOMAIN`. -/
def authValueLockDomain : Nat := 0x4856_4c4b_5632_0001

/-- One of the sixteen fixed call106 input cells. -/
abbrev ValueLockCell := Fin 16

/-- The exact current source of a call106 input lane.  Lanes0..6 are the
policy root at raw rows122..128; lanes7..13 are the intent digest at raw
rows129..135.  The final two lanes are constants. -/
def valueLockSource (lane : ValueLockCell) : Option Nat :=
  if lane.val < 7 then some (rawIndex (122 + lane.val))
  else if lane.val < 14 then some (rawIndex (129 + lane.val - 7))
  else none

def valueLockConstant (lane : ValueLockCell) : Nat :=
  if lane.val = 14 then authValueLockDomain
  else if lane.val = 15 then poseidon2V8SuiteMarker
  else 0

/-- Finite syntax/CSR certificate for every call106 initial-state cell.
It contains only expression-DAG realizations and membership of the exact
`source - target = 0` attempts; no digest equality is assumed. -/
structure ValueLockFrameCertificate (components : RelationProgramComponents) where
  canonical : ({ expressions := components.csrExpressions, roots := [] } :
    ExpressionProgram).Canonical true
  oneNode : Nat
  negativeNode : Nat
  constantNode : ValueLockCell → Nat
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeRealizes : Realizes components.csrExpressions negativeNode
    (.sub (.constant 0) (.constant 1))
  constantRealizes : ∀ lane, Realizes components.csrExpressions (constantNode lane)
    (.constant (valueLockConstant lane))
  attempt : ValueLockCell → CsrExecutableAttempt
  member : ∀ lane, attempt lane ∈ components.csrAttempts
  terms : ∀ lane, (attempt lane).terms =
    (hashInitialIndex 106 lane.val, oneNode) ::
      ((valueLockSource lane).toList.map fun index => (index, negativeNode))
  target : ∀ lane, (attempt lane).targetRoot = constantNode lane

/-- The exact semantic call106 frame named independently of generated node
numbering. -/
def valueLockFrame (packed : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 7 then packed.getD (rawIndex (122 + lane)) 0
    else if lane < 14 then packed.getD (rawIndex (129 + lane - 7)) 0
    else if lane = 14 then authValueLockDomain
    else poseidon2V8SuiteMarker

private theorem valueLockFrame_word_bounded (packed : List Nat)
    (packedBound : ∀ index, packed.getD index 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (lane : ValueLockCell) :
    (valueLockFrame packed).getD lane.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  fin_cases lane <;> simp [valueLockFrame] <;>
    first | exact packedBound _ | decide

def valueLockPolicyRoot (packed : List Nat) : List Nat :=
  (List.range 7).map fun limb => packed.getD (rawIndex (122 + limb)) 0

def valueLockIntentDigest (packed : List Nat) : List Nat :=
  (List.range 7).map fun limb => packed.getD (rawIndex (129 + limb)) 0

/-- Acceptance plus the finite CSR artifact fixes each call106 initial cell
to the live policy-root/intent/domain/suite frame. -/
theorem accepted_value_lock_frame_word {components : RelationProgramComponents}
    (certificate : ValueLockFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (lane : ValueLockCell) :
    packed.getD (hashInitialIndex 106 lane.val) 0 =
      (valueLockFrame packed).getD lane.val 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD certificate.oneNode 0 : F) = 1 := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      certificate.oneRealizes
  have negative : (values.getD certificate.negativeNode 0 : F) = -1 := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      certificate.negativeRealizes
  have constant : (values.getD (certificate.constantNode lane) 0 : F) =
      (valueLockConstant lane : F) := by
    simpa [SourceTerm.eval] using csr_realizes_value certificate.canonical evaluated
      (certificate.constantRealizes lane)
  have equation := V8Smz9SemanticDenseRange.accepted_csr_attempt_field_equality
    (attempts _ (certificate.member lane))
  rw [certificate.terms lane, certificate.target lane] at equation
  have laneBound := lane.isLt
  have targetBound : (valueLockFrame packed).getD lane.val 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    exact valueLockFrame_word_bounded packed
      (packed_word_canonical accepted.2.1) lane
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 _) targetBound
  simp only [valueLockFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range laneBound, Option.map_some, Option.getD_some]
  simp only [V8Smz9SemanticDenseRange.csrFieldSum, valueLockSource] at equation
  simp only [packedWord, List.getD_eq_getElem?_getD]
  split_ifs at equation ⊢ <;>
    simp_all [List.map, Option.toList, valueLockConstant,
      authValueLockDomain] <;>
    split_ifs at equation ⊢ <;> simp_all <;>
      first | omega | linear_combination equation

/-- Accepted call106 starts from the exact live value-lock frame. -/
theorem accepted_value_lock_initial_state {components : RelationProgramComponents}
    (certificate : ValueLockFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    packedInitialState packed 106 = valueLockFrame packed := by
  apply List.ext_getElem
  · simp [packedInitialState, valueLockFrame]
  · intro lane leftBound rightBound
    have laneBound : lane < 16 := by simpa [packedInitialState] using leftBound
    have word := accepted_value_lock_frame_word certificate accepted
      ⟨lane, laneBound⟩
    simpa [packedInitialState, valueLockFrame, packedWord,
      List.getD_eq_getElem, laneBound] using word

/-- The accepted call106 final digest is exactly the live one-call
`compress14(policyRoot, intentDigest)` value. -/
theorem accepted_value_lock_compress14 {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (frame : ValueLockFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    (packedFinalState packed 106).take 7 =
      poseidon2V8Compress14 authValueLockDomain
        (valueLockPolicyRoot packed) (valueLockIntentDigest packed) := by
  have trace := accepted_hash_call_state kernel accepted
    (call := 106) (by decide)
  rw [accepted_value_lock_initial_state frame accepted] at trace
  calc
    (packedFinalState packed 106).take 7 =
        (Poseidon2Width16Kernel.permutation (valueLockFrame packed)).take 7 :=
      congrArg (List.take 7) trace.symm
    _ = poseidon2V8Compress14 authValueLockDomain
        (valueLockPolicyRoot packed) (valueLockIntentDigest packed) := by
      unfold poseidon2V8Compress14
      apply congrArg (fun state =>
        (Poseidon2Width16Kernel.permutation state).take 7)
      apply List.map_congr_left
      intro lane member
      have laneBound : lane < 16 := List.mem_range.mp member
      interval_cases lane <;>
        simp [valueLockPolicyRoot, valueLockIntentDigest,
          authValueLockDomain, digestWords,
          List.getD_eq_getElem?_getD]

/-- Row108 is not a free digest: the existing direct-copy CSR equation
connects every limb to call106, whose accepted trace is the exact value-lock
compression above. -/
theorem accepted_value_lock_vector_word {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (frame : ValueLockFrameCertificate components)
    (direct : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (limb : Fin 7) :
    packed.getD (108 * 64 + limb.val) 0 =
      (poseidon2V8Compress14 authValueLockDomain
        (valueLockPolicyRoot packed) (valueLockIntentDigest packed)).getD limb.val 0 := by
  have copied := accepted_current_direct_word direct accepted
    (.valueLockDigest limb)
  have copiedFinal : packed.getD (108 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 106 limb.val) 0 := by
    simpa [CurrentDirectWord.sourceIndex, CurrentDirectWord.targetIndex] using copied
  have digest := congrArg (fun words : List Nat => words.getD limb.val 0)
    (accepted_value_lock_compress14 kernel frame accepted)
  exact copiedFinal.trans (by
    simpa [packedFinalState, packedWord, digestWords,
      List.getD_eq_getElem?_getD, List.getElem?_take, limb.isLt] using digest)


/-- The concrete23-word codec is read from the same raw witness coordinates
already fixed by CurrentAbsorbCertificate. -/
def accumulatorInputs (packed : List Nat) (next : Bool) : List Nat :=
  List.ofFn (if next then typedNextAccumulatorWords packed
    else typedCurrentAccumulatorWords packed)

private theorem accumulatorInputs_getD (packed : List Nat) (next : Bool)
    (word : Fin 23) :
    (accumulatorInputs packed next).getD word.val 0 =
      (if next then typedNextAccumulatorWords packed word
       else typedCurrentAccumulatorWords packed word) := by
  cases next with
  | false =>
    change (List.ofFn (typedCurrentAccumulatorWords packed)).getD word.val 0 = _
    exact HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.ofFn_getD _ word
  | true =>
    change (List.ofFn (typedNextAccumulatorWords packed)).getD word.val 0 = _
    exact HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.ofFn_getD _ word

def accumulatorCall (next : Bool) : Nat := if next then 103 else 100

def accumulatorFrame (packed : List Nat) (next : Bool) (block : Nat) : List Nat :=
  let inputs := accumulatorInputs packed next
  if block = 0 then V8Smz9AccumulatorSponge.accumulatorFirstFrame inputs
  else if block = 1 then V8Smz9AccumulatorSponge.accumulatorMiddleFrame inputs
    (packedFinalState packed (accumulatorCall next))
  else V8Smz9AccumulatorSponge.accumulatorLastFrame inputs
    (packedFinalState packed (accumulatorCall next + 1))

/-- Every cell of all six accumulator initial states follows from the actual
absorbed-word and frame CSR equations. Only fixed finite coordinates occur. -/
theorem accepted_accumulator_frame_word {components : RelationProgramComponents}
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (next : Bool) (block lane : Nat) (blockBound : block < 3) (laneBound : lane < 16) :
    packed.getD (hashInitialIndex (accumulatorCall next + block) lane) 0 =
      (accumulatorFrame packed next block).getD lane 0 := by
  have packedCanonical := packed_word_canonical accepted.2.1
  have expectedBound : (accumulatorFrame packed next block).getD lane 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    cases next <;> interval_cases block <;> interval_cases lane <;>
      simp [accumulatorFrame, accumulatorInputs, accumulatorCall,
        V8Smz9AccumulatorSponge.accumulatorFirstFrame,
        V8Smz9AccumulatorSponge.accumulatorMiddleFrame,
        V8Smz9AccumulatorSponge.accumulatorLastFrame,
        packedFinalState, packedWord, typedCurrentAccumulatorWords,
        typedNextAccumulatorWords, List.getD_eq_getElem?_getD,
        Poseidon2Width16Kernel.fieldAdd,
        poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker]
    all_goals first
      | exact Nat.mod_lt _ (by decide)
      | exact packedCanonical _
      | decide
  apply canonical_nat_cast_injective (packedCanonical _) expectedBound
  by_cases active : lane < 8 ∧ block * 8 + lane < 23
  · let word : Fin 23 := ⟨block * 8 + lane, active.2⟩
    let source : WitnessAbsorbWord :=
      if next then .nextAccumulator word else .currentAccumulator word
    have equation := accepted_current_witness_absorb_word absorbed accepted source
    cases next with
    | false =>
      interval_cases block <;> interval_cases lane
      all_goals try omega
      all_goals simp [source, word, absorbedWord, WitnessAbsorbWord.firstCall,
        WitnessAbsorbWord.word, WitnessAbsorbWord.targetIndex,
        List.getD_eq_getElem?_getD] at equation
      all_goals norm_num [accumulatorFrame, accumulatorCall]
      all_goals first
        | rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.firstFrame_getElemD
            (accumulatorInputs packed false) _ (by omega)]
        | (rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.middleFrame_getElemD
            (accumulatorInputs packed false) (packedFinalState packed 100) _ (by omega)];
           rw [packedFinalState_getD packed 100 _ (by omega)])
        | (rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.lastFrame_getElemD
            (accumulatorInputs packed false) (packedFinalState packed 101) _ (by omega)];
           rw [packedFinalState_getD packed 101 _ (by omega)])
      all_goals have inputRead := accumulatorInputs_getD packed false word
      all_goals simp only [word] at inputRead
      all_goals rw [inputRead]
      all_goals simp [typedCurrentAccumulatorWords, WitnessAbsorbWord.targetIndex,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] at equation ⊢
      all_goals simp only [packedWord, List.getD_eq_getElem?_getD]
      all_goals first
        | exact equation
        | linear_combination equation
    | true =>
      interval_cases block <;> interval_cases lane
      all_goals try omega
      all_goals simp [source, word, absorbedWord, WitnessAbsorbWord.firstCall,
        WitnessAbsorbWord.word, WitnessAbsorbWord.targetIndex,
        List.getD_eq_getElem?_getD] at equation
      all_goals norm_num [accumulatorFrame, accumulatorCall]
      all_goals first
        | rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.firstFrame_getElemD
            (accumulatorInputs packed true) _ (by omega)]
        | (rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.middleFrame_getElemD
            (accumulatorInputs packed true) (packedFinalState packed 103) _ (by omega)];
           rw [packedFinalState_getD packed 103 _ (by omega)])
        | (rw [HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.lastFrame_getElemD
            (accumulatorInputs packed true) (packedFinalState packed 104) _ (by omega)];
           rw [packedFinalState_getD packed 104 _ (by omega)])
      all_goals have inputRead := accumulatorInputs_getD packed true word
      all_goals simp only [word] at inputRead
      all_goals rw [inputRead]
      all_goals simp [typedNextAccumulatorWords, WitnessAbsorbWord.targetIndex,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] at equation ⊢
      all_goals simp only [packedWord, List.getD_eq_getElem?_getD]
      all_goals first
        | exact equation
        | linear_combination equation
  · let family : CurrentSpongeFamily :=
      if next then .nextAccumulator else .currentAccumulator
    let cell : CurrentFrameWord :=
      { family := family, block := block, lane := ⟨lane, laneBound⟩
        blockBound := by cases next <;> simpa [family, CurrentSpongeFamily.blockCount]
        isFrame := by
          have : 8 ≤ lane ∨ 23 ≤ block * 8 + lane := by omega
          cases next <;> simpa [family, CurrentSpongeFamily.wordCount] using this }
    have equation := accepted_current_frame_word frames accepted cell
    cases next <;> interval_cases block <;> interval_cases lane
    all_goals try omega
    all_goals try norm_num [cell, family, accumulatorFrame, accumulatorInputs, accumulatorCall,
        V8Smz9AccumulatorSponge.accumulatorFirstFrame,
        V8Smz9AccumulatorSponge.accumulatorMiddleFrame,
        V8Smz9AccumulatorSponge.accumulatorLastFrame,
        packedFinalState, packedWord, CurrentFrameWord.difference,
        CurrentFrameWord.expected, CurrentSpongeFamily.firstCall,
        CurrentSpongeFamily.wordCount, CurrentSpongeFamily.blockCount,
        CurrentSpongeFamily.domain, spongeModeMarker, suiteMarker,
        poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker,
        List.getD_eq_getElem?_getD,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] at equation
    all_goals try simp [accumulatorFrame, accumulatorInputs,
      accumulatorCall, V8Smz9AccumulatorSponge.accumulatorFirstFrame,
      V8Smz9AccumulatorSponge.accumulatorMiddleFrame,
      V8Smz9AccumulatorSponge.accumulatorLastFrame, packedFinalState,
      packedWord, poseidon2V8SpongeModeMarker,
      poseidon2V8SuiteMarker, List.getD_eq_getElem?_getD,
      List.getElem?_map,
      V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd]
    all_goals linear_combination equation

theorem accepted_accumulator_initial_state {components : RelationProgramComponents}
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (next : Bool) (block : Nat) (bound : block < 3) :
    packedInitialState packed (accumulatorCall next + block) =
      accumulatorFrame packed next block := by
  apply List.ext_getElem
  · cases next <;> interval_cases block <;>
      simp [packedInitialState, accumulatorFrame,
        V8Smz9AccumulatorSponge.accumulatorFirstFrame,
        V8Smz9AccumulatorSponge.accumulatorMiddleFrame,
        V8Smz9AccumulatorSponge.accumulatorLastFrame]
  · intro lane leftBound rightBound
    have laneBound : lane < 16 := by simpa [packedInitialState] using leftBound
    have equal := accepted_accumulator_frame_word absorbed frames accepted
      next block lane bound laneBound
    simpa [packedInitialState, packedWord, List.getD_eq_getElem, laneBound,
      rightBound] using equal

/-- Current acceptance implies the actual23-word accumulator hash for
calls100..102 and103..105. No accumulator digest equality is a premise. -/
theorem accepted_actual_accumulator_digest {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components) {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (next : Bool) :
    poseidon2V8Sponge poseidon2V8AccumulatorDomain (accumulatorInputs packed next) =
      (packedFinalState packed (accumulatorCall next + 2)).take digestWords := by
  apply accepted_accumulator_sponge kernel accepted (accumulatorCall next)
    (by cases next <;> simp [accumulatorCall]) (accumulatorInputs packed next)
    (by simp [accumulatorInputs])
  · simpa [accumulatorFrame] using
      accepted_accumulator_initial_state absorbed frames accepted next 0 (by decide)
  · simpa [accumulatorFrame] using
      accepted_accumulator_initial_state absorbed frames accepted next 1 (by decide)
  · simpa [accumulatorFrame] using
      accepted_accumulator_initial_state absorbed frames accepted next 2 (by decide)



def bindingKey (packed : List Nat) : List Nat :=
  (List.range 7).map fun limb => if limb < 5 then packed.getD (97 * 64 + limb) 0 else 0

def bindingRight (packed : List Nat) (which : Fin 2) : List Nat :=
  if which.val = 0 then (packedFinalState packed 102).take 7
  else (List.range 7).map fun limb => packed.getD (109 * 64 + limb) 0

theorem accepted_bound_compress14 {components : RelationProgramComponents}
    (kernel : KernelCertificate components) (frame : BoundFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (which : Fin 2) :
    (packedFinalState packed (107 + which.val)).take 7 =
      poseidon2V8Compress14 0x484d_4244_5632_0001
        (bindingKey packed) (bindingRight packed which) := by
  rw [accepted_bound_authorization_digest kernel frame accepted which]
  unfold poseidon2V8Compress14
  apply congrArg (fun state => (Poseidon2Width16Kernel.permutation state).take 7)
  apply List.map_congr_left
  intro lane member
  have laneBound : lane < 16 := List.mem_range.mp member
  fin_cases which <;> interval_cases lane <;>
    simp [bindingKey, bindingRight, packedFinalState, packedWord,
      digestWords, poseidon2V8SuiteMarker,
      List.getD_eq_getElem?_getD]

/-- The current authorization digest binds the real23-word accumulator hash
and the exact five-word secret plus two canonical zero padding words. -/
theorem accepted_current_authorization_digest {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    (bound : BoundFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    (packedFinalState packed 107).take 7 =
      poseidon2V8Compress14 0x484d_4244_5632_0001 (bindingKey packed)
        (poseidon2V8Sponge poseidon2V8AccumulatorDomain
          (List.ofFn (typedCurrentAccumulatorWords packed))) := by
  have compressed := accepted_bound_compress14 kernel bound accepted (0 : Fin 2)
  have accumulator := accepted_actual_accumulator_digest kernel absorbed frames accepted false
  change poseidon2V8Sponge poseidon2V8AccumulatorDomain
      (List.ofFn (typedCurrentAccumulatorWords packed)) =
    (packedFinalState packed 102).take 7 at accumulator
  simpa only [Fin.val_zero, Nat.add_zero, bindingRight, if_pos rfl, ite_true,
    ← accumulator] using compressed


end
end HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
