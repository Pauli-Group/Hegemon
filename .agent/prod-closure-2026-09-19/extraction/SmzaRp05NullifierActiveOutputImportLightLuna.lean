import SmzaRp05NullifierSourceInitialStatesImportLight
import SmzaRp05NullifierSourceCsrBase

/-! Active RP05 public-output bridge over the checked import-light
initial-state theorem. This duplicates only the small two-absorb-step proof,
not the older source-initial-state or absorb import chain. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashFinalIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

private theorem list_sixteen_eq_local (state : List Nat)
    (shape : state.length = 16) :
    state = (List.range 16).map (fun lane => state.getD lane 0) := by
  apply List.ext_getElem (by simp [shape])
  intro lane leftBound rightBound
  simp only [List.getElem_map, List.getElem_range]
  exact (List.getD_eq_getElem state 0 leftBound).symm

private theorem first_absorb_local (inputs : List Nat)
    (shape : inputs.length = 12) :
    poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
      poseidon2V8InitialState 0 =
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation
      (firstFrame inputs) := by
  simp [poseidon2V8AbsorbBlock, poseidon2V8InitialState,
    poseidon2V8SeedFirstBlock, currentNullifierDomain,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.width,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate,
    shape, firstFrame, List.range_succ, List.replicate_succ, List.getD]

private theorem last_absorb_local (inputs state : List Nat)
    (shape : inputs.length = 12) (stateShape : state.length = 16) :
    poseidon2V8AbsorbBlock currentNullifierDomain inputs 2 state 1 =
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.permutation
        (lastFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq_local state stateShape]
  simp [poseidon2V8AbsorbBlock,
    _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate,
    shape, lastFrame, List.range_succ, List.getD]

/-- The checked first/last source-state bridge plus accepted permutation rows
fix the complete seven-word output of the exact two-block RP05 sponge. -/
theorem accepted_nullifier_digest_of_import_light_initial_states
    {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2)
    (firstInitial : packedInitialState packed (nullifierFirstCall input) =
      firstFrame (nullifierPreimage packed input))
    (lastInitial : packedInitialState packed (nullifierLastCall input) =
      lastFrame (nullifierPreimage packed input)
        (packedFinalState packed (nullifierFirstCall input))) :
    liveNullifierDigest packed input =
      (packedFinalState packed (nullifierLastCall input)).take 7 := by
  let inputs := nullifierPreimage packed input
  have shape : inputs.length = 12 := nullifier_preimage_length packed input
  have firstState := accepted_hash_call_state kernel accepted
    (call := nullifierFirstCall input) (by fin_cases input <;> decide)
  have lastState := accepted_hash_call_state kernel accepted
    (call := nullifierLastCall input) (by fin_cases input <;> decide)
  rw [firstInitial] at firstState
  rw [lastInitial] at lastState
  have firstShape :
      (packedFinalState packed (nullifierFirstCall input)).length = 16 := by
    simp [packedFinalState]
  have expanded : poseidon2V8Sponge currentNullifierDomain inputs =
      (poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
        (poseidon2V8AbsorbBlock currentNullifierDomain inputs 2
          poseidon2V8InitialState 0) 1).take 7 := by
    simp [poseidon2V8Sponge, shape,
      _root_.Hegemon.Transaction.Poseidon2Width16Kernel.rate,
      digestWords, List.range_succ]
  unfold liveNullifierDigest
  rw [expanded, first_absorb_local inputs shape, firstState,
    last_absorb_local inputs _ shape firstShape, lastState]

/-- The public-certificate source equality is stated only for active slots. -/
private theorem accepted_active_public_nullifier_word_local
    {components : RelationProgramComponents}
    (certificate : PublicCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7)
    (active : publicWords.getD input.val 0 = 1) :
    publicWords.getD (4 + input.val * 7 + limb.val) 0 =
      packed.getD (hashFinalIndex (nullifierLastCall input) limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have gate : (values.getD (certificate.activeNode input) 0 : Goldilocks) = 1 := by
    have gateSource := csr_node_value certificate.canonical evaluated
      (certificate.activeRealizes input)
    change (values.getD (certificate.activeNode input) 0 : Goldilocks) =
      (publicWords.getD input.val 0 : Goldilocks) at gateSource
    rw [active] at gateSource
    exact gateSource
  have target :
      (values.getD (certificate.targetNode (input, limb)) 0 : Goldilocks) =
        (publicWords.getD (4 + input.val * 7 + limb.val) 0 : Goldilocks) := by
    have targetSource := csr_node_value certificate.canonical evaluated
      (certificate.targetRealizes (input, limb))
    change (values.getD (certificate.targetNode (input, limb)) 0 : Goldilocks) =
      (publicWords.getD input.val 0 : Goldilocks) *
        (publicWords.getD (4 + input.val * 7 + limb.val) 0 : Goldilocks) at targetSource
    rw [active] at targetSource
    simpa only [Nat.cast_one, one_mul] using targetSource
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.member (input, limb)))
  rw [certificate.attemptTerms (input, limb),
    certificate.attemptTarget (input, limb)] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, gate, target, one_mul, add_zero] at equation
  exact canonical_nat_cast_injective
    ((canonical_public_coordinate accepted.1
      (by
        have hi := input.isLt
        have hl := limb.isLt
        norm_num [publicStatementWordCount]
        omega)).2)
    (packed_word_canonical accepted.2.1
      (hashFinalIndex (nullifierLastCall input) limb.val))
    equation.symm

/-- End-to-end output readback from accepted certificates, with the checked
initial-state result derived internally rather than assumed. -/
theorem accepted_active_public_nullifier_import_light
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
    (kernel : KernelCertificate components)
    (direction : DirectionCertificate components)
    (publicCopy : PublicCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1)
    (limb : Fin 7) :
    publicWords.getD (4 + input.val * 7 + limb.val) 0 =
      (liveNullifierDigest packed input).getD limb.val 0 := by
  have copied := accepted_active_public_nullifier_word_local
    publicCopy accepted input limb active
  obtain ⟨firstInitial, lastInitial⟩ :=
    accepted_nullifier_initial_states_import_light initial kernel direction accepted input
  have digest := congrArg (fun words : List Nat => words.getD limb.val 0)
    (accepted_nullifier_digest_of_import_light_initial_states
      kernel accepted input firstInitial lastInitial)
  exact copied.trans (by
    simpa [packedFinalState, packedWord, List.getD_eq_getElem?_getD,
      List.getElem?_take, limb.isLt] using digest.symm)

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
