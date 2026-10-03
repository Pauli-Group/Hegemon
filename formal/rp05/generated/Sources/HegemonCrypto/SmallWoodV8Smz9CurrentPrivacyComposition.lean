import HegemonCrypto.SmallWoodV8Smz9CurrentPublicContext

/-! Generated current-program mask chronology and explicit physical lifetime
experiments. Adaptive honest-hash reprogramming is an external theorem premise
about these experiments, not a project axiom or a stored probability field. -/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9CurrentPublicContext
open V8Smz9EagerPrivacy V8Smz9CurrentProgramPiop V8Smz9CurrentProgramOpeningBinding
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator V8Smz9EagerOracleGame
open V8Smz9PrivacyGameComposition V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option backward.isDefEq.respectTransparency false

section SharedLifetime

variable {Input Output Workspace : Type*}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [AddGroup Output]
variable [Fintype Workspace]

abbrev LifetimeState := State (Input := Input) (Output := Output) (Workspace := Workspace)

/-- The same table and quantum workspace survive each ordinary query, honest
classical read, programming event and public abort. Local gates cannot read it. -/
inductive LifetimeProgram (Input Output Workspace : Type*)
    [Fintype Input] [Fintype Output] [AddGroup Output] [Fintype Workspace] where
  | done
  | abort
  | localGate (gate : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
      (next : LifetimeProgram Input Output Workspace)
  | quantumQuery (next : LifetimeProgram Input Output Workspace)
  | honestRead (input : Input) (next : Output → LifetimeProgram Input Output Workspace)
  | program (input : Input) (output : Output) (next : LifetimeProgram Input Output Workspace)
  | programTable (entries : Input → Option Output) (next : LifetimeProgram Input Output Workspace)

structure LifetimeResult (Input Output Workspace : Type*)
    [Fintype Input] [Fintype Output] [AddGroup Output] [Fintype Workspace] where
  oracle : Input → Output
  state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)
  aborted : Bool
  quantumQueries : Nat
  honestReads : Nat
  programmedPoints : Nat

def runLifetime (program : LifetimeProgram Input Output Workspace) (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    LifetimeResult Input Output Workspace :=
  match program with
  | .done => ⟨oracle, state, false, 0, 0, 0⟩
  | .abort => ⟨oracle, state, true, 0, 0, 0⟩
  | .localGate gate next => runLifetime next oracle (gate state)
  | .quantumQuery next =>
      let result := runLifetime next oracle (query oracle state)
      { result with quantumQueries := result.quantumQueries + 1 }
  | .honestRead input next =>
      let result := runLifetime (next (oracle input)) oracle state
      { result with honestReads := result.honestReads + 1 }
  | .program input output next =>
      let result := runLifetime next (Function.update oracle input output) state
      { result with programmedPoints := result.programmedPoints + 1 }
  | .programTable entries next =>
      let result := runLifetime next (fun input => (entries input).getD (oracle input)) state
      { result with programmedPoints := result.programmedPoints +
        (Finset.univ.filter (fun input => (entries input).isSome)).card }

theorem run_lifetime_preserves_norm (program : LifetimeProgram Input Output Workspace)
    (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    ‖(runLifetime program oracle state).state‖ = ‖state‖ := by
  induction program generalizing oracle state with
  | done => rfl
  | abort => rfl
  | localGate gate next ih => simpa only [runLifetime, ih] using gate.norm_map state
  | quantumQuery next ih => simpa only [runLifetime, ih] using (query oracle).norm_map state
  | honestRead input next ih => exact ih (oracle input) oracle state
  | program input output next ih => exact ih (Function.update oracle input output) state
  | programTable entries next ih => exact ih (fun input => (entries input).getD (oracle input)) state

theorem lifetime_abort_retains_table_and_state (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (runLifetime .abort oracle state).oracle = oracle ∧
      (runLifetime .abort oracle state).state = state ∧
      (runLifetime .abort oracle state).aborted = true := ⟨rfl, rfl, rfl⟩

theorem lifetime_programming_preserves_previous_other_entries
    (oracle : Input → Output) (input other : Input) (output : Output)
    (different : other ≠ input)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (runLifetime (.program input output .done) oracle state).oracle other = oracle other := by
  simp only [runLifetime, Function.update_of_ne different]

def lifetimeObservation (failure : ℝ) (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis Input Output Workspace))
    (result : LifetimeResult Input Output Workspace) : ℝ :=
  if result.aborted then failure else born event result.state

theorem lifetime_observation_of_not_aborted
    (failure : ℝ) (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis Input Output Workspace))
    (result : LifetimeResult Input Output Workspace) (notAborted : result.aborted = false) :
    lifetimeObservation failure event result = born event result.state := by
  simp only [lifetimeObservation, notAborted, Bool.false_eq_true, if_false]

theorem lifetime_table_program_abort_projection (entries : Input → Option Output)
    (next : LifetimeProgram Input Output Workspace) (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (runLifetime (.programTable entries next) oracle state).aborted =
      (runLifetime next (fun input => (entries input).getD (oracle input)) state).aborted := rfl

theorem lifetime_local_done_state
    (gate : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (runLifetime (.localGate gate .done) oracle state).state = gate state := rfl

/-- One random oracle draw for the entire lifetime. Hybrid choice does not
resample it, and private coins do not inspect it before program execution. -/
def lifetimeAcceptance {Coins : Type*} [Fintype Coins] [Nonempty Coins]
    (program : Coins → LifetimeProgram Input Output Workspace)
    (initial : Coins → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (failure : ℝ) (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis Input Output Workspace)) : ℝ :=
  uniformAverage fun oracle : Input → Output =>
    uniformAverage fun coins : Coins =>
      lifetimeObservation failure event (runLifetime (program coins) oracle (initial coins))

theorem lifetime_observation_is_probability
    (program : LifetimeProgram Input Output Workspace) (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (normalized : ‖state‖ = 1) (failure : ℝ) (failureBounds : 0 ≤ failure ∧ failure ≤ 1)
    (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis Input Output Workspace)) :
    0 ≤ lifetimeObservation failure event (runLifetime program oracle state) ∧
      lifetimeObservation failure event (runLifetime program oracle state) ≤ 1 := by
  unfold lifetimeObservation
  split
  · exact failureBounds
  · constructor
    · unfold born
      positivity
    · have bound := event_projection_norm_sq_le event (runLifetime program oracle state).state
      simpa only [born, run_lifetime_preserves_norm, normalized, one_pow] using bound

/-- This counts all oracle exposures, not just the adversary's coherent calls. -/
def lifetimeOracleExposures (result : LifetimeResult Input Output Workspace) : Nat :=
  result.quantumQueries + result.honestReads

theorem lifetime_programs_share_updated_table (oracle : Input → Output)
    (first second : Input) (left right : Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    (runLifetime (.program first left (.program second right .done)) oracle state).oracle =
      Function.update (Function.update oracle first left) second right := rfl

theorem lifetime_quantum_query_is_charged (next : LifetimeProgram Input Output Workspace)
    (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    lifetimeOracleExposures (runLifetime (.quantumQuery next) oracle state) =
      lifetimeOracleExposures (runLifetime next oracle (query oracle state)) + 1 := by
  simp only [lifetimeOracleExposures, runLifetime]
  omega

theorem lifetime_honest_read_is_charged (input : Input)
    (next : Output → LifetimeProgram Input Output Workspace) (oracle : Input → Output)
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) :
    lifetimeOracleExposures (runLifetime (.honestRead input next) oracle state) =
      lifetimeOracleExposures (runLifetime (next (oracle input)) oracle state) + 1 := by
  simp only [lifetimeOracleExposures, runLifetime]
  omega

omit [DecidableEq Input] in
/-- The two-query leaf-domain simulation charges both adversarial coherent
queries and all honest raw-oracle calls over the same whole lifetime. -/
theorem lifetime_two_query_simulation_budget
    (result : LifetimeResult Input Output Workspace) (budget : Nat)
    (bounded : lifetimeOracleExposures result ≤ budget) :
    2 * result.quantumQueries + 2 * result.honestReads ≤ 2 * budget := by
  simpa only [lifetimeOracleExposures, Nat.mul_add] using Nat.mul_le_mul_left 2 bounded

/-- Compile the existing full-oracle circuit without resetting either table or
state at its continuation boundary. -/
def compileQuantumCircuit
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (count : Nat) (next : LifetimeProgram Input Output Workspace) : LifetimeProgram Input Output Workspace :=
  match count with
  | 0 => next
  | count + 1 => .quantumQuery (.localGate (steps 0)
      (compileQuantumCircuit (fun index => steps (index + 1)) count next))

omit [DecidableEq Input] in
theorem query_run_shift (oracle : Input → Output)
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) (count : Nat) :
    run oracle steps state (count + 1) =
      run oracle (fun index => steps (index + 1)) (steps 0 (query oracle state)) count := by
  induction count with
  | zero => rfl
  | succ count ih =>
      change steps (count + 1) (query oracle (run oracle steps state (count + 1))) = _
      rw [ih]
      rfl

theorem compiled_quantum_circuit_continues_state (oracle : Input → Output)
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (count : Nat) (next : LifetimeProgram Input Output Workspace) :
    (runLifetime (compileQuantumCircuit steps count next) oracle state).state =
      (runLifetime next oracle (run oracle steps state count)).state := by
  induction count generalizing steps state with
  | zero => rfl
  | succ count ih =>
      simp only [compileQuantumCircuit, runLifetime]
      rw [ih, query_run_shift]

theorem compiled_quantum_circuit_continues_oracle (oracle : Input → Output)
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (count : Nat) (next : LifetimeProgram Input Output Workspace) :
    (runLifetime (compileQuantumCircuit steps count next) oracle state).oracle =
      (runLifetime next oracle (run oracle steps state count)).oracle := by
  induction count generalizing steps state with
  | zero => rfl
  | succ count ih =>
      simp only [compileQuantumCircuit, runLifetime]
      rw [ih, query_run_shift]

theorem compiled_quantum_circuit_continues_abort (oracle : Input → Output)
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (count : Nat) (next : LifetimeProgram Input Output Workspace) :
    (runLifetime (compileQuantumCircuit steps count next) oracle state).aborted =
      (runLifetime next oracle (run oracle steps state count)).aborted := by
  induction count generalizing steps state with
  | zero => rfl
  | succ count ih =>
      simp only [compileQuantumCircuit, runLifetime]
      rw [ih, query_run_shift]

theorem compiled_quantum_circuit_query_count (oracle : Input → Output)
    (steps : Nat → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (state : LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace)) (count : Nat) :
    (runLifetime (compileQuantumCircuit steps count .done) oracle state).quantumQueries = count := by
  induction count generalizing steps state with
  | zero => rfl
  | succ count ih => simp only [compileQuantumCircuit, runLifetime, ih]

end SharedLifetime

theorem uniform_average_comm {A B : Type*} [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (value : A → B → ℝ) :
    uniformAverage (fun a => uniformAverage (value a)) =
      uniformAverage (fun b => uniformAverage (fun a => value a b)) := by
  unfold uniformAverage
  simp only [Finset.mul_sum]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro b _
  apply Finset.sum_congr rfl
  intro a _
  ring

theorem uniform_average_const {A : Type*} [Fintype A] [Nonempty A] (value : ℝ) :
    uniformAverage (fun _ : A => value) = value := by
  simp only [uniformAverage, ← Finset.sum_mul, pmf_real_weights_sum, one_mul]

theorem joint_mask_real_transport
    (gamma : DecsGamma Goldilocks) (heads : PiopCoefficients Goldilocks → LvcsCommittedHeads Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks)
    (unmasked : DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks)
    (observe : JointMaskCoins Goldilocks → JointMaskOutputs Goldilocks → ℝ) :
    uniformAverage (fun coins => observe coins (jointMaskForward gamma heads tails unmasked coins)) =
      uniformAverage (fun output => observe (jointMaskInverse gamma heads tails unmasked output) output) := by
  let equivalence := jointPiopDecsMaskEquiv gamma heads tails unmasked
  have transported := uniform_average_equiv equivalence
    (fun output => observe (equivalence.symm output) output)
  simpa only [equivalence, jointPiopDecsMaskEquiv, Equiv.coe_fn_mk, Equiv.symm_mk,
    joint_mask_inverse_after_forward] using transported

/-- The full old Q/M masks remain observable throughout the chronological
permutation. This can retain the entire physical lifetime state and oracle. -/
theorem chronological_joint_mask_real_transport
    {Base Labels : Type*} [Fintype Base] [Nonempty Base] [Fintype Labels] [Nonempty Labels]
    (gamma : Labels → DecsGamma Goldilocks)
    (heads : Base → PiopCoefficients Goldilocks → LvcsCommittedHeads Goldilocks)
    (tails : Base → LvcsRandomTailCoins Goldilocks)
    (unmasked : Base → Labels → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks)
    (observe : Base → Labels → JointMaskCoins Goldilocks → JointMaskOutputs Goldilocks → ℝ) :
    uniformAverage (fun base => uniformAverage (fun masks => uniformAverage (fun labels =>
      observe base labels masks (jointMaskForward (gamma labels) (heads base) (tails base)
        (unmasked base labels) masks)))) =
    uniformAverage (fun labels => uniformAverage (fun output => uniformAverage (fun base =>
      observe base labels (jointMaskInverse (gamma labels) (heads base) (tails base)
        (unmasked base labels) output) output))) := by
  simp_rw [uniform_average_comm (fun masks labels => observe _ labels masks
    (jointMaskForward (gamma labels) (heads _) (tails _) (unmasked _ labels) masks))]
  rw [uniform_average_comm]
  apply congrArg uniformAverage
  funext labels
  simp_rw [joint_mask_real_transport]
  exact uniform_average_comm _

def currentJointHeads (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : PiopCoefficients Goldilocks) :
    LvcsCommittedHeads Goldilocks :=
  physicalHeads (sourceWitnessPolynomials values base.1) masks base.2.1

def currentJointUnmasked (statement : V8PublicStatement)
    (batching : DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (response : DecsFullCoefficients Goldilocks) : PiopCoefficients Goldilocks :=
  currentResponseCoefficients (statementParameters statement (batching response))
    (sourceWitnessPolynomials values base.1) 0

theorem current_joint_inverse_recovers_source_masks
    (statement : V8PublicStatement)
    (batching : DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (gamma : DecsGamma Goldilocks) (output : JointMaskOutputs Goldilocks) :
    (jointMaskInverse gamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement batching values base) output).1 =
      currentRecoveredMasksAtCoins (statementParameters statement (batching output.1))
        values output.2 base.1 := rfl

/-- The inverse old DECS mask and every all-index raw leaf suffix agree with
the current physical serializer, not with a separately supplied suffix map. -/
theorem current_joint_inverse_recovers_source_suffix
    (statement : V8PublicStatement)
    (batching : DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (gamma : DecsGamma Goldilocks) (output : JointMaskOutputs Goldilocks) :
    let masks := jointMaskInverse gamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement batching values base) output
    fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 =
      currentSourceSuffix (statementParameters statement (batching output.1)) values gamma output.1 output.2 base := rfl

/-- In the chronological source experiment the suffix really uses the originally
sampled Q and M, before their exact inverse-coordinate representation is used. -/
theorem current_forward_source_suffix_matches
    (statement : V8PublicStatement)
    (batching : DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (gamma : DecsGamma Goldilocks) (masks : JointMaskCoins Goldilocks) :
    let output := jointMaskForward gamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement batching values base) masks
    fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 =
      currentSourceSuffix (statementParameters statement (batching output.1)) values gamma output.1 output.2 base := by
  have recovered := current_joint_inverse_recovers_source_suffix statement batching values base gamma
    (jointMaskForward gamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement batching values base) masks)
  simpa only [joint_mask_inverse_after_forward] using recovered

/-- Although the inverse expressions mention the newly drawn targets through
D and PIOP batching, the full original leaf payload is target-independent. -/
theorem current_forward_suffix_is_target_independent
    (statement : V8PublicStatement)
    (leftBatching rightBatching : DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (leftGamma rightGamma : DecsGamma Goldilocks) (masks : JointMaskCoins Goldilocks) :
    let left := jointMaskForward leftGamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement leftBatching values base) masks
    let right := jointMaskForward rightGamma (currentJointHeads values base) base.2.2
      (currentJointUnmasked statement rightBatching values base) masks
    currentSourceSuffix (statementParameters statement (leftBatching left.1)) values leftGamma left.1 left.2 base =
      currentSourceSuffix (statementParameters statement (rightBatching right.1)) values rightGamma right.1 right.2 base :=
  (current_forward_source_suffix_matches statement leftBatching values base leftGamma masks).symm.trans
    (current_forward_source_suffix_matches statement rightBatching values base rightGamma masks)

/-- The actual original all-index source payload leaves exactly the fresh
512-bit tape coordinate free. This is a point-mass theorem, not the external
adaptive quantum reprogramming theorem. -/
theorem original_current_leaf_input_max_mass
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes) (index : LeafIndex) (input : LeafInput) :
    pmfMap (uniformFintypePMF LeafTape)
      (sourceLeafInput (canonicalLeafHeader salt)
        (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 index) index) input ≤
      (2 ^ 512 : ℝ≥0∞)⁻¹ :=
  fresh_leaf_input_max_mass (Fin.append (canonicalLeafHeader salt) (indexBytes index))
    (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2 index) input

section CurrentGeneratedGames

variable {Other Output Workspace : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Output] [DecidableEq Output] [AddGroup Output]
variable [Fintype Workspace] [DecidableEq Workspace]

def sourceLeafProgramEntries (targets : LeafIndex → Output) (programmed : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix) (tapes : TapeTable) :
    LeafInput ⊕ Other → Option Output :=
  Sum.elim (fun input => if input ∈ sourcePatchSupport programmed header suffix tapes
    then some (targets (rawInputIndex input)) else none) (fun _ => none)

omit [Fintype Other] [DecidableEq Other] [Fintype Output] [DecidableEq Output] [AddGroup Output] in
theorem source_table_program_is_full_source_overlay
    (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (programmed : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix) (tapes : TapeTable) :
    (fun input => (sourceLeafProgramEntries targets programmed header suffix tapes input).getD
      (Sum.elim oldLeaf other input)) =
      fullSourceOverlay oldLeaf other targets programmed header suffix tapes := by
  funext input
  cases input with
  | inl input =>
      simp only [sourceLeafProgramEntries, fullSourceOverlay, sourceOverlay, Sum.elim_inl]
      split <;> rfl
  | inr input => rfl

omit [DecidableEq Output] [DecidableEq Workspace] in
/-- Exact operator-level embedding of the current source leaf table into the
shared lifetime. The arbitrary next program receives the updated same table. -/
theorem compiled_source_table_continues_current_circuit
    (oldLeaf : LeafInput → Output) (other : Other → Output)
    (targets : LeafIndex → Output) (programmed : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix) (tapes : TapeTable)
    (steps : Nat → PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace))
    (initial : PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace))
    (count : Nat) (next : LifetimeProgram (LeafInput ⊕ Other) Output Workspace) :
    (runLifetime (.programTable (sourceLeafProgramEntries targets programmed header suffix tapes)
      (compileQuantumCircuit steps count next)) (Sum.elim oldLeaf other) initial).state =
    (runLifetime next (fullSourceOverlay oldLeaf other targets programmed header suffix tapes)
      (run (fullSourceOverlay oldLeaf other targets programmed header suffix tapes) steps initial count)).state := by
  simp only [runLifetime, source_table_program_is_full_source_overlay,
    compiled_quantum_circuit_continues_state]

/-- Compile the actual physical branch, including its final tape-dependent local
gate. No new oracle or initial quantum state is introduced at the splice. -/
def executedAtomicProgram
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (programmed : Finset LeafIndex) (programTapes padded : TapeTable) :
    LifetimeProgram (LeafInput ⊕ Other) Output Workspace :=
  .programTable (sourceLeafProgramEntries reference.targets programmed
    reference.header reference.suffix programTapes)
    (compileQuantumCircuit reference.steps reference.queries (.localGate (reference.post padded) .done))

def executedAtomicObservation
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (programmed : Finset LeafIndex) (programTapes padded : TapeTable) : ℝ :=
  lifetimeObservation 0 (reference.event padded)
    (runLifetime (executedAtomicProgram reference programmed programTapes padded)
      (Sum.elim reference.oldLeaf reference.other) reference.initial)

set_option maxRecDepth 1000 in
set_option maxHeartbeats 200000 in
theorem executed_atomic_observation_is_source_born
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace))
    (programmed : Finset LeafIndex) (programTapes padded : TapeTable) :
    executedAtomicObservation reference programmed programTapes padded =
      born (reference.event padded) (reference.post padded
        (run (fullSourceOverlay reference.oldLeaf reference.other reference.targets programmed
          reference.header reference.suffix programTapes)
          reference.steps reference.initial reference.queries)) := by
  have stateEqual := compiled_source_table_continues_current_circuit
    reference.oldLeaf reference.other reference.targets programmed reference.header reference.suffix
    programTapes reference.steps reference.initial reference.queries
    (.localGate (reference.post padded) .done)
  have noAbort : (runLifetime (executedAtomicProgram reference programmed programTapes padded)
      (Sum.elim reference.oldLeaf reference.other) reference.initial).aborted = false := by
    unfold executedAtomicProgram
    rw [lifetime_table_program_abort_projection, compiled_quantum_circuit_continues_abort]
    rfl
  unfold executedAtomicObservation
  rw [lifetime_observation_of_not_aborted _ _ _ noAbort]
  unfold executedAtomicProgram
  rw [stateEqual]
  rw [lifetime_local_done_state]
  congr 1

/-- This is the finite current source experiment executed by the shared-table
program, not a supplied equality between unnamed game probabilities. -/
def executedFullSourceAcceptance (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) : ℝ :=
  (∑ padded : TapeTable, executedAtomicObservation reference Finset.univ
    (mergeTapes opened visible (splitTapes opened padded).2) padded) / (Fintype.card TapeTable : ℝ)

theorem executed_full_source_is_current_experiment (opened : Finset LeafIndex)
    (visible : OpenedTapes (Tape := LeafTape) opened)
    (reference : AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace)) :
    executedFullSourceAcceptance opened visible reference =
      fullProgrammedAcceptance opened visible reference := by
  unfold executedFullSourceAcceptance fullProgrammedAcceptance
  apply finite_average_congr
  intro padded
  exact executed_atomic_observation_is_source_born _ _ _ _

/-- The exact source-context branch can therefore be spliced to the existing
public reference using its proved source binding. This does not assert that an
entire adaptive honest prover has already been compiled to this branch. -/
theorem executed_current_source_to_public_reference_bound
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (fullSuffix : LeafIndex → LeafSuffix)
    (suffixMatches : ∀ index ∈ openedOrEmpty (contextSelection context),
      fullSuffix index = publicSuffix points selected context index)
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) :
    |executedFullSourceAcceptance (openedOrEmpty (contextSelection context)) visible
        (completedAtomicReference points selected salt labels context continuation fullSuffix) -
      referenceAcceptance (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
        (publicAtomicReference points selected salt labels context continuation))| ≤
      hiddenPatchLoss continuation.queries := by
  rw [executed_full_source_is_current_experiment]
  exact completed_table_to_public_reference_bound points selected salt labels context continuation
    fullSuffix suffixMatches visible

/-- A successful public point-sampler branch. The continuation is a complete
physical circuit, chosen from public context and visible tapes only. -/
structure PublicStage where
  points : Fin 6 → Goldilocks
  admissible : Smz9WitnessInterpolationAdmissible points
  pointsNonzero : ∀ opening, points opening ≠ 0
  selected : Function.Injective (smz9LvcsSelectedBlockMap points)
  packingCardNonzero : (64 : Goldilocks) ≠ 0
  nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks))
  fallback : LvcsAdmissibleTargets points
  choose : PiopCoefficients Goldilocks → IndexChooser points
  continuation : PiopCoefficients Goldilocks →
    CurrentContinuationFactory (Other := Other) (Output := Output) (Workspace := Workspace) points

abbrev PublicStageGenerator := (LeafIndex → Output) → DecsFullCoefficients Goldilocks →
  Option (PublicStage (Other := Other) (Output := Output) (Workspace := Workspace))

/-- Compose the actual encoded-statement compiler guard before the public
point-sampler stage, with neither failure conditioned away. -/
def guardedPublicStageGenerator (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace)) :
    PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace) :=
  fun labels response => match compileStatementParameters statement (batching labels response) with
    | none => none
    | some _ => stage labels response

omit [DecidableEq Other] [DecidableEq Output] [AddGroup Output] [DecidableEq Workspace] in
theorem current_public_compiler_failure_is_stage_abort
    (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (labels : LeafIndex → Output) (response : DecsFullCoefficients Goldilocks)
    (failed : compileStatementParameters statement (batching labels response) = none) :
    guardedPublicStageGenerator statement batching stage labels response = none := by
  simp only [guardedPublicStageGenerator, failed]

def generatedSourceObservation (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ)
    (base : SourceRemainingCoins Goldilocks) (labels : LeafIndex → Output)
    (output : JointMaskOutputs Goldilocks) : ℝ :=
  match stage labels output.1 with
  | none => failure
  | some publicStage => sourceContextAcceptance
      (statementParameters statement (batching labels output.1)) publicStage.points publicStage.selected
      (gamma labels) output.1 output.2 (publicStage.choose output.2) values base salt labels
      (publicStage.continuation output.2)

def generatedPublicObservation (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (salt : SaltBytes) (failure : ℝ) (labels : LeafIndex → Output)
    (output : JointMaskOutputs Goldilocks) : ℝ :=
  match stage labels output.1 with
  | none => failure
  | some publicStage => currentPublicReferenceAcceptance
      (statementParameters statement (batching labels output.1)) publicStage.points publicStage.selected
      (gamma labels) output.1 output.2 (publicStage.choose output.2) salt labels
      (publicStage.continuation output.2)

/-- The current source mixture with its physical branch made explicit as an
executed program. Its previous table/state come from the same public continuation;
only the genuinely fresh hidden tape half is averaged inside each branch. -/
def executedGeneratedSourceObservation (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ)
    (base : SourceRemainingCoins Goldilocks) (labels : LeafIndex → Output)
    (output : JointMaskOutputs Goldilocks) : ℝ :=
  match stage labels output.1 with
  | none => failure
  | some publicStage =>
      let parameters := statementParameters statement (batching labels output.1)
      let context := currentSourceContext parameters publicStage.points publicStage.selected
        (gamma labels) output.1 output.2 (publicStage.choose output.2) values base
      uniformAverage fun visiblePadding : TapeTable =>
        let opened := openedOrEmpty (contextSelection context)
        let visible := (splitTapes opened visiblePadding).1
        executedFullSourceAcceptance opened visible
          (completedAtomicReference publicStage.points publicStage.selected salt labels context
            (publicStage.continuation output.2 context visible)
            (currentSourceSuffix parameters values (gamma labels) output.1 output.2 base))

theorem executed_generated_source_observation_is_current_game
    (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ)
    (base : SourceRemainingCoins Goldilocks) (labels : LeafIndex → Output)
    (output : JointMaskOutputs Goldilocks) :
    executedGeneratedSourceObservation statement batching gamma stage values salt failure base labels output =
      generatedSourceObservation statement batching gamma stage values salt failure base labels output := by
  cases chosen : stage labels output.1 with
  | none => simp only [executedGeneratedSourceObservation, generatedSourceObservation, chosen]
  | some publicStage =>
      simp only [executedGeneratedSourceObservation, generatedSourceObservation, chosen,
        sourceContextAcceptance, executed_full_source_is_current_experiment]

/-- Chronological randomized-label source: remaining W/PCS/LVCS coins, then
old Q/M masks, then fresh labels. The raw Q/M response is actually computed. -/
def chronologicalRandomizedAcceptance (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ) : ℝ :=
  uniformAverage fun base : SourceRemainingCoins Goldilocks =>
    uniformAverage fun masks : JointMaskCoins Goldilocks =>
      uniformAverage fun labels : LeafIndex → Output =>
        generatedSourceObservation statement batching gamma stage values salt failure base labels
          (jointMaskForward (gamma labels) (currentJointHeads values base) base.2.2
            (currentJointUnmasked statement (batching labels) values base) masks)

/-- No equality field or oracle reset: this chronological experiment computes
the original source masks and actually executes each physical continuation. -/
def executedChronologicalAcceptance (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ) : ℝ :=
  uniformAverage fun base : SourceRemainingCoins Goldilocks =>
    uniformAverage fun masks : JointMaskCoins Goldilocks =>
      uniformAverage fun labels : LeafIndex → Output =>
        executedGeneratedSourceObservation statement batching gamma stage values salt failure base labels
          (jointMaskForward (gamma labels) (currentJointHeads values base) base.2.2
            (currentJointUnmasked statement (batching labels) values base) masks)

theorem executed_chronological_source_is_generated_game
    (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ) :
    executedChronologicalAcceptance statement batching gamma stage values salt failure =
      chronologicalRandomizedAcceptance statement batching gamma stage values salt failure := by
  simp only [executedChronologicalAcceptance, chronologicalRandomizedAcceptance,
    executed_generated_source_observation_is_current_game]

def generatedPublicReferenceAcceptance (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (salt : SaltBytes) (failure : ℝ) : ℝ :=
  uniformAverage fun labels : LeafIndex → Output => uniformAverage fun output : JointMaskOutputs Goldilocks =>
    generatedPublicObservation statement batching gamma stage salt failure labels output

theorem current_chronological_masks_to_public_outputs
    (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ) :
    chronologicalRandomizedAcceptance statement batching gamma stage values salt failure =
      uniformAverage (fun labels : LeafIndex → Output => uniformAverage (fun output : JointMaskOutputs Goldilocks =>
        uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
          generatedSourceObservation statement batching gamma stage values salt failure base labels output))) :=
  chronological_joint_mask_real_transport gamma (currentJointHeads values) (fun base => base.2.2)
    (fun base labels => currentJointUnmasked statement (batching labels) values base)
    (fun base labels _ output => generatedSourceObservation statement batching gamma stage values salt failure
      base labels output)

/-- The derived current-game bound is applied after transporting Q/M, not before
erasing their correlated source inputs. Both public sampler aborts are retained. -/
theorem generated_randomized_source_to_public_reference_bound
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (salt : SaltBytes) (failure : ℝ) (queryBound : ℕ)
    (queriesBounded : ∀ labels response publicStage,
      stage labels response = some publicStage → ∀ transcript context visible,
        (publicStage.continuation transcript context visible).queries ≤ queryBound) :
    |chronologicalRandomizedAcceptance statement batching gamma stage (packingValues witness) salt failure -
      generatedPublicReferenceAcceptance statement batching gamma stage salt failure| ≤ hiddenPatchLoss queryBound := by
  rw [current_chronological_masks_to_public_outputs]
  apply uniform_average_difference_le
  intro labels
  apply uniform_average_difference_le
  intro output
  cases selectedStage : stage labels output.1 with
  | none =>
      simp only [generatedSourceObservation, generatedPublicObservation, selectedStage,
        uniform_average_const, sub_self, abs_zero]
      unfold hiddenPatchLoss
      positivity
  | some publicStage =>
      simp only [generatedSourceObservation, generatedPublicObservation, selectedStage]
      exact canonical_statement_current_privacy_bound statement publicValues witness domain
        (batching labels output.1) publicStage.points publicStage.admissible publicStage.pointsNonzero
        publicStage.selected publicStage.packingCardNonzero publicStage.nodesInjective (gamma labels)
        output.1 output.2 publicStage.fallback (publicStage.choose output.2) salt labels
        (publicStage.continuation output.2) queryBound
        (queriesBounded labels output.1 publicStage selectedStage output.2)

/-- The whole generated chronological randomized-label experiment, with every
physical continuation executed, has the current public-reference bound. The
honest-to-randomized transition remains separate and explicitly external. -/
theorem executed_chronological_source_to_public_reference_bound
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (salt : SaltBytes) (failure : ℝ) (queryBound : ℕ)
    (queriesBounded : ∀ labels response publicStage,
      stage labels response = some publicStage → ∀ transcript context visible,
        (publicStage.continuation transcript context visible).queries ≤ queryBound) :
    |executedChronologicalAcceptance statement batching gamma stage (packingValues witness) salt failure -
      generatedPublicReferenceAcceptance statement batching gamma stage salt failure| ≤ hiddenPatchLoss queryBound := by
  rw [executed_chronological_source_is_generated_game]
  exact generated_randomized_source_to_public_reference_bound statement publicValues witness domain
    batching gamma stage salt failure queryBound queriesBounded

/-- This is the explicit external adaptive-reprogramming boundary. The honest
side executes a finite shared-table quantum/classical program; the randomized
side is the generated current chronological experiment defined above. No claim
that input entropy alone establishes this premise is made. -/
theorem honest_current_public_privacy_bound
    {Coins : Type*} [Fintype Coins] [Nonempty Coins]
    (honestProgram : Coins → LifetimeProgram (LeafInput ⊕ Other) Output Workspace)
    (initial : Coins → LifetimeState (Input := LeafInput ⊕ Other) (Output := Output) (Workspace := Workspace))
    (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis (LeafInput ⊕ Other) Output Workspace))
    (statement : V8PublicStatement) (publicValues witness : List Nat)
    (domain : CanonicalPublicPackedDomain statement publicValues witness)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (salt : SaltBytes) (failure : ℝ) (queryBound : ℕ)
    (queriesBounded : ∀ labels response publicStage,
      stage labels response = some publicStage → ∀ transcript context visible,
        (publicStage.continuation transcript context visible).queries ≤ queryBound)
    (reprogrammingLoss : ℝ)
    (externalHonestReprogramming :
      |lifetimeAcceptance honestProgram initial failure event -
        chronologicalRandomizedAcceptance statement batching gamma stage (packingValues witness) salt failure| ≤
          reprogrammingLoss) :
    |lifetimeAcceptance honestProgram initial failure event -
      generatedPublicReferenceAcceptance statement batching gamma stage salt failure| ≤
        reprogrammingLoss + hiddenPatchLoss queryBound := by
  have currentBound := generated_randomized_source_to_public_reference_bound statement publicValues witness domain
    batching gamma stage salt failure queryBound queriesBounded
  exact (abs_sub_le _
    (chronologicalRandomizedAcceptance statement batching gamma stage (packingValues witness) salt failure) _).trans
      (add_le_add externalHonestReprogramming currentBound)

/-- A fresh public sampler failure stays the same actual observation on both
sides, including after the old mask variables have been permuted. -/
theorem generated_public_abort_is_identical
    (statement : V8PublicStatement)
    (batching : (LeafIndex → Output) → DecsFullCoefficients Goldilocks → Fin 5 → Nat → Goldilocks)
    (gamma : (LeafIndex → Output) → DecsGamma Goldilocks)
    (stage : PublicStageGenerator (Other := Other) (Output := Output) (Workspace := Workspace))
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes) (failure : ℝ)
    (base : SourceRemainingCoins Goldilocks) (labels : LeafIndex → Output)
    (output : JointMaskOutputs Goldilocks) (aborted : stage labels output.1 = none) :
    generatedSourceObservation statement batching gamma stage values salt failure base labels output = failure ∧
      generatedPublicObservation statement batching gamma stage salt failure labels output = failure := by
  simp only [generatedSourceObservation, generatedPublicObservation, aborted, and_self]

end CurrentGeneratedGames

theorem real_hybrid_chain_bound (acceptance loss : Nat → ℝ) (count : Nat)
    (step : ∀ index, index < count → |acceptance index - acceptance (index + 1)| ≤ loss index) :
    |acceptance 0 - acceptance count| ≤ ∑ index ∈ Finset.range count, loss index := by
  induction count with
  | zero => simp
  | succ count ih =>
      have previous := ih (fun index bounded => step index (Nat.lt_succ_of_lt bounded))
      have last := step count (Nat.lt_succ_self count)
      rw [Finset.sum_range_succ]
      exact (abs_sub_le _ (acceptance count) _).trans (add_le_add previous last)

section RepeatedPhysical

variable {Input Output Workspace Coins : Type*}
variable [Fintype Input] [DecidableEq Input] [Fintype Output] [AddGroup Output]
variable [Fintype Workspace] [Fintype Coins] [Nonempty Coins]

/-- Repeated hybrid composition for the actual executed lifetime programs.
Every hybrid starts with the same single uniform table and private-coin space;
the execution keeps all previous updates. Adjacent bounds must be proved for
these complete programs, not for independently restarted proof invocations. -/
theorem shared_lifetime_hybrid_composition
    (programs : Nat → Coins → LifetimeProgram Input Output Workspace)
    (initial : Coins → LifetimeState (Input := Input) (Output := Output) (Workspace := Workspace))
    (failure : ℝ) (event : Finset (V8Smz9HiddenLeafQrom.QueryBasis Input Output Workspace))
    (loss : Nat → ℝ) (count : Nat)
    (adjacent : ∀ index, index < count →
      |lifetimeAcceptance (programs index) initial failure event -
        lifetimeAcceptance (programs (index + 1)) initial failure event| ≤ loss index) :
    |lifetimeAcceptance (programs 0) initial failure event -
      lifetimeAcceptance (programs count) initial failure event| ≤
        ∑ index ∈ Finset.range count, loss index :=
  real_hybrid_chain_bound (fun index => lifetimeAcceptance (programs index) initial failure event)
    loss count adjacent

end RepeatedPhysical

end
end HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
