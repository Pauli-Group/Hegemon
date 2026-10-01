import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleGeometry
import HegemonCrypto.CmsFullOperatorProof
import HegemonCrypto.CmsQuerySequence
import HegemonCrypto.CmsFinitePhaseSystem
import Mathlib.Algebra.BigOperators.Fin

/-!
# Reversible extraction and concrete CMS partition operators

The answer register is updated by a basis permutation, with the raw database
and arbitrary workspace retained. The source extraction partition is obtained
from the literal finite raw-byte database, not a measured classical query log.
The quantitative theorem below uses the existing explicit CMS kernel proof.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFullOperatorProof HegemonCrypto.CmsQuerySequence
open V8Smz9CoherentMerkleGeometry

noncomputable section

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000
set_option exponentiation.threshold 1024

local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq

/-- Little-endian binary digits of a literal byte. -/
def byteBits : HegemonCrypto.CanonicalBytes.Byte ≃ (Fin 8 → ZMod 2) :=
  (finCongr (by norm_num : 256 = 2 ^ 8)).trans
    ((finFunctionFinEquiv (m := 2) (n := 8)).symm.trans
      (Equiv.piCongrRight fun _ => (ZMod.finEquiv 2).toEquiv))

/-- Literal 64-byte outputs and the existing 512-bit XOR oracle register.
The flattened bit position is `8 * byteIndex + bitIndex`. -/
def rawDigestBits : RawDigest ≃ V8Smz9HiddenLeafQrom.DigestRegister :=
  (Equiv.piCongrRight fun _ : Fin 64 => byteBits).trans
    ((Equiv.curry (Fin 64) (Fin 8) (ZMod 2)).symm.trans
      (Equiv.arrowCongr (finProdFinEquiv : Fin 64 × Fin 8 ≃ Fin (64 * 8)) (Equiv.refl _)))

open HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9HiddenLeafQrom

/-- The full Walsh character pairing on the actual XOR digest group. -/
def digestCharacter (phase : DigestRegister) : AddChar DigestRegister ℂ where
  toFun output := ∏ bit : Fin 512, zmodComplexCharacter (modulus := 2) (phase bit * output bit)
  map_zero_eq_one' := by simp
  map_add_eq_mul' := by
    intro left right
    simp only [Pi.add_apply, mul_add, AddChar.map_add_eq_mul, Finset.prod_mul_distrib]

theorem digest_character_single (phase : DigestRegister) (bit : Fin 512) :
    digestCharacter phase (Pi.single bit 1) = zmodComplexCharacter (phase bit) := by
  simp only [digestCharacter, AddChar.coe_mk]
  rw [Finset.prod_eq_single bit]
  · simp
  · intro selected _ different
    simp [Ne.symm different]
  · simp

theorem digest_character_injective : Function.Injective digestCharacter := by
  intro left right same
  funext bit
  apply zmod_complex_character_injective
  simpa only [digest_character_single] using
    DFunLike.congr_fun same (Pi.single bit 1)

theorem digest_character_zero : digestCharacter 0 = 0 := by
  ext output
  simp [digestCharacter]

def digestPhaseSystem : PhaseSystem DigestRegister DigestRegister where
  character := digestCharacter
  zeroPhase := 0
  character_zero := digest_character_zero
  character_nonzero _ different same :=
    different (digest_character_injective (same.trans digest_character_zero.symm))

/-- Unique phase labels span all 512-bit output dimensions. -/
def digestCompletePhaseSystem : CompletePhaseSystem DigestRegister DigestRegister where
  system := digestPhaseSystem
  characterInjective := digest_character_injective
  phaseDimension := rfl

section Reversible

variable {Input Output Phase Target Answer Workspace : Type*}
variable [AddGroup Answer]

/-- Compute the complete encoded extraction answer reversibly. Targets, input,
phase, raw database and the entire private workspace are unchanged. -/
def extractionEquiv (value : Target → Database Input Output → Answer) :
    Basis Input Output Phase (Target × Answer × Workspace) ≃
      Basis Input Output Phase (Target × Answer × Workspace) where
  toFun b := { b with workspace :=
    (b.workspace.1, b.workspace.2.1 + value b.workspace.1 b.database, b.workspace.2.2) }
  invFun b := { b with workspace :=
    (b.workspace.1, b.workspace.2.1 - value b.workspace.1 b.database, b.workspace.2.2) }
  left_inv b := by cases b; simp
  right_inv b := by cases b; simp

def extractionLinearEquiv (value : Target → Database Input Output → Answer) :
    State Input Output Phase (Target × Answer × Workspace) ≃ₗ[ℂ]
      State Input Output Phase (Target × Answer × Workspace) where
  toFun state := state ∘ (extractionEquiv value).symm
  invFun state := state ∘ extractionEquiv value
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem extraction_clean_answer (value : Target → Database Input Output → Answer)
    (input : Input) (phase : Phase) (target : Target) (database : Database Input Output)
    (workspace : Workspace) :
    extractionEquiv value
        { input := input, phase := phase, database := database, workspace := (target, 0, workspace) } =
      { input := input, phase := phase, database := database,
        workspace := (target, value target database, workspace) } := by
  simp [extractionEquiv]

theorem extraction_xor_is_involutive {Index : Type*}
    (value : Target → Database Input Output → (Index → ZMod 2))
    (basis : Basis Input Output Phase (Target × (Index → ZMod 2) × Workspace)) :
    (extractionEquiv value).symm basis = extractionEquiv value basis := by
  have negSame : -(value basis.workspace.1 basis.database) = value basis.workspace.1 basis.database := by
    funext bit
    exact ZMod.neg_eq_self_mod_two _
  change { basis with workspace := (basis.workspace.1,
    basis.workspace.2.1 - value basis.workspace.1 basis.database, basis.workspace.2.2) } = _
  rw [sub_eq_add_neg, negSame]
  rfl

variable [Fintype Input] [Fintype Output] [Fintype Phase]
variable [Fintype Target] [Fintype Answer] [Fintype Workspace]

/-- Complex-linear bijection and exact Hilbert norm preservation establish
unitarity, including superposed targets and entangled workspace. -/
theorem extraction_preserves_squared_norm
    (value : Target → Database Input Output → Answer)
    (state : State Input Output Phase (Target × Answer × Workspace)) :
    normSquared (extractionLinearEquiv value state) = normSquared state := by
  exact (extractionEquiv value).symm.sum_comp (fun basis => Complex.normSq (state basis))

end Reversible

section RawDatabase

variable {Key Output : Type*} [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output]

/-- All and only recorded pairs, expressed as literal raw input/output bytes. -/
def rawRecords (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (database : Database Key Output) : Records RawInput RawDigest :=
  (Finset.univ.filter fun pair : Key × Output => database pair.1 = some pair.2).image
    (fun pair => (keyBytes pair.1, outputBytes pair.2))

omit [DecidableEq Key] in
theorem raw_records_card_le (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (database : Database Key Output) : (rawRecords keyBytes outputBytes database).card ≤ size database := by
  have pairCard : (Finset.univ.filter fun pair : Key × Output => database pair.1 = some pair.2).card =
      size database := by
    apply Finset.card_bij (fun pair _ => pair.1)
    · intro pair member
      exact (mem_support_iff database pair.1).mpr ⟨pair.2, (Finset.mem_filter.mp member).2⟩
    · intro left leftMem right rightMem same
      apply Prod.ext same
      exact Option.some.inj (((Finset.mem_filter.mp leftMem).2.symm.trans
        (congrArg database same)).trans (Finset.mem_filter.mp rightMem).2)
    · intro key member
      obtain ⟨output, recorded⟩ := (mem_support_iff database key).mp member
      exact ⟨(key, output), Finset.mem_filter.mpr ⟨Finset.mem_univ _, recorded⟩, rfl⟩
  exact (Finset.card_image_le).trans pairCard.le

theorem raw_records_insert (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (database : Database Key Output) (key : Key) (output : Output)
    (absent : database key = none) :
    rawRecords keyBytes outputBytes (FiniteOracleDatabase.insert database key output) =
      Insert.insert (keyBytes key, outputBytes output) (rawRecords keyBytes outputBytes database) := by
  have pairs : (Finset.univ.filter fun pair : Key × Output =>
      FiniteOracleDatabase.insert database key output pair.1 = some pair.2) =
      Insert.insert (key, output) (Finset.univ.filter fun pair : Key × Output =>
        database pair.1 = some pair.2) := by
    ext pair
    rcases pair with ⟨selected, value⟩
    by_cases same : selected = key
    · subst selected
      simp [FiniteOracleDatabase.insert, absent, Prod.mk.injEq, eq_comm]
    · simp [FiniteOracleDatabase.insert, same, Prod.mk.injEq]
  simp only [rawRecords, pairs, Finset.image_insert]

def sourceLabel (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (database : Database Key Output) :=
  extractTargets sourceNext (rawRecords keyBytes outputBytes database) fuel targets

/-- Any fixed Boolean test of the complete source extraction is an actual CMS
database property. This includes missingness and deterministic completed views. -/
def sourceProperty (keyBytes : Key → RawInput) (outputBytes : Output → RawDigest)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest))
    (test : List (ExtractionTrace RawInput) → Prop) : Property Key Output :=
  fun database => test (sourceLabel keyBytes outputBytes fuel targets database)

theorem source_step_change_bound (keyBytes : Key → RawInput) (outputBytes : Output ≃ RawDigest)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound) (database : Database Key Output)
    (recordBudget : size database < queryBound) (key : Key) (event : Property Key Output)
    (changed : ∀ output, event (query database key output) →
      sourceLabel keyBytes outputBytes fuel targets (query database key output) ≠
        sourceLabel keyBytes outputBytes fuel targets database) :
    stepProbability event database key ≤ (3 * queryBound : ℚ) / (2 ^ 512 : ℚ) := by
  by_cases absent : database key = none
  · have subset : (successfulAnswers event database key).image outputBytes ⊆
        changedOutputs sourceNext (rawRecords keyBytes outputBytes database)
          (keyBytes key) fuel targets := by
      intro digest member
      obtain ⟨output, success, rfl⟩ := Finset.mem_image.mp member
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      have changes := changed output (Finset.mem_filter.mp success).2
      simpa only [query_of_absent absent, sourceLabel,
        raw_records_insert keyBytes outputBytes database key output absent] using changes
    have cardBound : (successfulAnswers event database key).card ≤
        (changedOutputs sourceNext (rawRecords keyBytes outputBytes database)
          (keyBytes key) fuel targets).card := by
      rw [← Finset.card_image_of_injective _ outputBytes.injective]
      exact Finset.card_le_card subset
    have outputCard := Fintype.card_congr outputBytes
    calc
      stepProbability event database key ≤
          uniformChangeProbability sourceNext (rawRecords keyBytes outputBytes database)
            (keyBytes key) fuel targets := by
        unfold stepProbability uniformChangeProbability
        rw [outputCard]
        exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound) (by positivity)
      _ ≤ _ := source_classical_instability_three_t _ _ _ _ queryBound
        (lt_of_le_of_lt (raw_records_card_le keyBytes outputBytes database) recordBudget) targetBudget
  · rw [step_probability_eq_zero_of_never event database key]
    · positivity
    · intro output eventTrue
      apply changed output eventTrue
      simp [query, absent]

/-- Both directions are proved from changed-output counting for the actual
source parser. No extraction-probability or operator-norm premise is supplied. -/
theorem source_property_instability (keyBytes : Key → RawInput) (outputBytes : Output ≃ RawDigest)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound)
    (test : List (ExtractionTrace RawInput) → Prop) :
    InstabilityBound (sourceProperty keyBytes outputBytes fuel targets test) queryBound
      ((3 * queryBound : ℚ) / (2 ^ 512 : ℚ)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside recordBudget key
    apply source_step_change_bound keyBytes outputBytes fuel targets queryBound targetBudget
      database recordBudget key _
    intro output accepted same
    apply outside
    simpa only [sourceProperty, same] using accepted
  · refine ⟨by positivity, ?_⟩
    intro database inside recordBudget key
    apply source_step_change_bound keyBytes outputBytes fuel targets queryBound targetBudget
      database recordBudget key _
    intro output rejected same
    apply rejected
    simpa only [sourceProperty, same] using inside

end RawDatabase

section CompleteSourceInstrument

variable {Key Target Workspace : Type*} [Fintype Key] [DecidableEq Key] [Fintype Target]

/-- The finite set of full source traces attainable on this finite raw universe.
Finiteness is symbolic; no full oracle table or extraction tree is enumerated. -/
def SourceLabelRange (keyBytes : Key → RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) :=
  Set.range (fun pair : Target × Database Key DigestRegister =>
    sourceLabel keyBytes rawDigestBits.symm fuel (targets pair.1) pair.2)

instance (keyBytes : Key → RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) :
    Fintype (SourceLabelRange keyBytes fuel targets) :=
  Fintype.ofSurjective
    (fun pair : Target × Database Key DigestRegister =>
      (⟨sourceLabel keyBytes rawDigestBits.symm fuel (targets pair.1) pair.2,
        ⟨pair, rfl⟩⟩ : SourceLabelRange keyBytes fuel targets))
    (by rintro ⟨value, ⟨pair, rfl⟩⟩; exact ⟨pair, rfl⟩)

def sourceRangeValue (keyBytes : Key → RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (target : Target)
    (database : Database Key DigestRegister) : SourceLabelRange keyBytes fuel targets :=
  ⟨sourceLabel keyBytes rawDigestBits.symm fuel (targets target) database,
    ⟨(target, database), rfl⟩⟩

/-- A faithful, finite XOR encoding of the whole selected trace. This deliberately
makes no efficient-register or gate-count claim. -/
def sourceOneHotValue (keyBytes : Key → RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (target : Target)
    (database : Database Key DigestRegister) :
    SourceLabelRange keyBytes fuel targets → ZMod 2 :=
  Pi.single (sourceRangeValue keyBytes fuel targets target database) 1

omit [DecidableEq Key] [Fintype Target] in
theorem source_one_hot_is_faithful (keyBytes : Key → RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest))
    (leftTarget rightTarget : Target) (left right : Database Key DigestRegister)
    (same : sourceOneHotValue keyBytes fuel targets leftTarget left =
      sourceOneHotValue keyBytes fuel targets rightTarget right) :
    sourceLabel keyBytes rawDigestBits.symm fuel (targets leftTarget) left =
      sourceLabel keyBytes rawDigestBits.symm fuel (targets rightTarget) right := by
  by_contra different
  have differentRange : sourceRangeValue keyBytes fuel targets leftTarget left ≠
      sourceRangeValue keyBytes fuel targets rightTarget right := by
    intro equal
    exact different (congrArg Subtype.val equal)
  have atLeft := congrFun same (sourceRangeValue keyBytes fuel targets leftTarget left)
  simp [sourceOneHotValue, differentRange] at atLeft

def sourceExtractionEquiv (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) :
    Basis Key DigestRegister DigestRegister
      (Target × (SourceLabelRange keyBytes fuel targets → ZMod 2) × Workspace) ≃
    Basis Key DigestRegister DigestRegister
      (Target × (SourceLabelRange keyBytes fuel targets → ZMod 2) × Workspace) :=
  extractionEquiv (sourceOneHotValue keyBytes fuel targets)

end CompleteSourceInstrument

section ConcreteCrossing

variable {Key Phase Workspace : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- A source-specific physical-kernel bound. The output group is literal 512-bit
XOR, decoded to bytes by an explicit bit-position equivalence. Arbitrary private
workspace is retained by the CMS kernel. -/
theorem source_projected_query_bound
    (keyBytes : Key ↪ RawInput)
    (system : PhaseSystem V8Smz9HiddenLeafQrom.DigestRegister Phase)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound)
    (test : List (ExtractionTrace RawInput) → Prop)
    (state : State Key V8Smz9HiddenLeafQrom.DigestRegister Phase Workspace) :
    normSquared (projectedQueryState system
      (sourceProperty keyBytes rawDigestBits.symm fuel targets test) queryBound state) ≤
      (18 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  rw [norm_squared_projected_query_state_eq_full_projected_norm]
  have bound := full_projected_norm_le_source_norm system
    (sourceProperty keyBytes rawDigestBits.symm fuel targets test) queryBound state
    (source_property_instability keyBytes rawDigestBits.symm fuel targets queryBound targetBudget test).toReal
  rw [full_source_norm_eq_norm_squared] at bound
  convert bound using 1
  push_cast
  ring

end ConcreteCrossing

section PartitionCommutator

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Diagonal sign unitary for one Boolean coarsening of an extraction label. -/
def partitionReflection (property : Property Input Output)
    (state : State Input Output Phase Workspace) : State Input Output Phase Workspace :=
  fun basis => if property basis.database then -state basis else state basis

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase] [DecidableEq Workspace] in
theorem partition_reflection_preserves_norm (property : Property Input Output)
    (state : State Input Output Phase Workspace) :
    normSquared (partitionReflection property state) = normSquared state := by
  apply Finset.sum_congr rfl
  intro basis _
  by_cases accepted : property basis.database <;> simp [partitionReflection, accepted]

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Workspace] [DecidableEq Workspace] in
theorem partition_reflection_preserves_bounded (property : Property Input Output)
    (bound : ℕ) (state : State Input Output Phase Workspace) (bounded : BoundedState bound state) :
    BoundedState bound (partitionReflection property state) := by
  have commutes : project (fun _ => True) bound (partitionReflection property state) =
      partitionReflection property (project (fun _ => True) bound state) := by
    funext basis
    by_cases accepted : property basis.database <;>
      by_cases within : size basis.database ≤ bound <;>
      simp [project, partitionReflection, accepted, within]
  exact commutes.trans (congrArg (partitionReflection property) bounded)

/-- The concrete CMS query between the two bounded-database projections. This
equals `queryState` on every state bounded strictly below the global cap. -/
def boundedQuery (system : PhaseSystem Output Phase) (queryBound : ℕ)
    (state : State Input Output Phase Workspace) : State Input Output Phase Workspace :=
  project (fun _ => True) queryBound
    (queryState system queryBound (project (fun _ => True) queryBound state))

theorem bounded_query_eq_query (system : PhaseSystem Output Phase) (queryBound bound : ℕ)
    (state : State Input Output Phase Workspace) (below : bound < queryBound)
    (bounded : BoundedState bound state) :
    boundedQuery system queryBound state = queryState system queryBound state := by
  unfold boundedQuery
  rw [bounded_state_mono below.le bounded]
  exact bounded_state_mono (Nat.succ_le_iff.mpr below)
    (query_state_bounded_succ_of_bounded system queryBound bound state below bounded)

def reflectionCommutator (system : PhaseSystem Output Phase) (property : Property Input Output)
    (queryBound : ℕ) (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  partitionReflection property (boundedQuery system queryBound state) -
    boundedQuery system queryBound (partitionReflection property state)

/-- Exact matrix identity, not an assumed commutator estimate. -/
theorem reflection_commutator_eq_crossings
    (system : PhaseSystem Output Phase) (property : Property Input Output)
    (queryBound : ℕ) (state : State Input Output Phase Workspace) :
    reflectionCommutator system property queryBound state =
      fun basis => -2 * (projectedQueryState system property queryBound state basis -
        projectedQueryState system (complement property) queryBound state basis) := by
  funext target
  unfold reflectionCommutator partitionReflection boundedQuery projectedQueryState project queryState
  by_cases targetBound : size target.database ≤ queryBound
  · by_cases targetProperty : property target.database
    · simp only [targetBound, targetProperty, complement, not_true_eq_false, and_self,
        and_false, if_true, if_false, Pi.sub_apply, sub_zero]
      rw [← Finset.sum_neg_distrib, ← Finset.sum_sub_distrib, Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro source _
      by_cases sourceBound : size source.database ≤ queryBound <;>
        by_cases sourceProperty : property source.database <;>
        (simp [sourceBound, sourceProperty]; try ring)
    · simp only [targetBound, targetProperty, complement, not_false_eq_true, and_self,
        and_false, if_true, if_false, Pi.sub_apply, zero_sub]
      rw [← Finset.sum_sub_distrib, ← Finset.sum_neg_distrib, Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro source _
      by_cases sourceBound : size source.database ≤ queryBound <;>
        by_cases sourceProperty : property source.database <;>
        (simp [sourceBound, sourceProperty]; try ring)
  · simp [targetBound]

theorem crossing_difference_norm (system : PhaseSystem Output Phase) (property : Property Input Output)
    (queryBound : ℕ) (state : State Input Output Phase Workspace) :
    normSquared (fun basis => projectedQueryState system property queryBound state basis -
      projectedQueryState system (complement property) queryBound state basis) =
      normSquared (projectedQueryState system property queryBound state) +
        normSquared (projectedQueryState system (complement property) queryBound state) := by
  unfold normSquared
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro basis _
  by_cases accepted : property basis.database <;>
    simp [projectedQueryState, project, complement, accepted]

/-- Genuine quantitative commutator theorem for every Boolean partition. The
constant 48 is conservative: the two source energies are bounded separately. -/
theorem reflection_commutator_bound (system : PhaseSystem Output Phase)
    (property : Property Input Output) (queryBound : ℕ)
    (state : State Input Output Phase Workspace) {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    normSquared (reflectionCommutator system property queryBound state) ≤
      48 * bound * normSquared state := by
  have double : complement (complement property) = property := by
    funext database
    exact propext not_not
  have reverse : RealInstabilityBound (complement property) queryBound bound := by
    constructor
    · simpa only [double] using instability.2
    · simpa only [double] using instability.1
  have forwardBound := full_projected_norm_le_source_norm system property queryBound state instability
  have reverseBound := full_projected_norm_le_source_norm system (complement property) queryBound state reverse
  rw [full_source_norm_eq_norm_squared,
    ← norm_squared_projected_query_state_eq_full_projected_norm] at forwardBound reverseBound
  rw [reflection_commutator_eq_crossings]
  have scale : normSquared (fun basis => (-2 : ℂ) *
      (projectedQueryState system property queryBound state basis -
        projectedQueryState system (complement property) queryBound state basis)) =
      4 * normSquared (fun basis => projectedQueryState system property queryBound state basis -
        projectedQueryState system (complement property) queryBound state basis) := by
    unfold normSquared
    rw [Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro basis _
    rw [Complex.normSq_mul]
    norm_num
  rw [scale, crossing_difference_norm]
  nlinarith

/-- The cutoff disappears from both query orders on strict reachable support. -/
theorem reflection_commutator_is_actual_query
    (system : PhaseSystem Output Phase) (property : Property Input Output)
    (queryBound bound : ℕ) (state : State Input Output Phase Workspace)
    (below : bound < queryBound) (bounded : BoundedState bound state) :
    reflectionCommutator system property queryBound state =
      partitionReflection property (queryState system queryBound state) -
        queryState system queryBound (partitionReflection property state) := by
  unfold reflectionCommutator
  rw [bounded_query_eq_query system queryBound bound state below bounded,
    bounded_query_eq_query system queryBound bound _ below
      (partition_reflection_preserves_bounded property bound state bounded)]

end PartitionCommutator

section SourceEndpoint

variable {Key Workspace : Type*} [Fintype Key] [DecidableEq Key]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- A completely proved source-specific physical commutator endpoint for any
fixed Boolean observation of the complete framed-graph extraction. It is not
the multi-answer-register extraction commutator theorem. -/
theorem source_actual_reflection_commutator_bound
    (keyBytes : Key ↪ RawInput) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound supportBound : ℕ)
    (targetBudget : targets.length ≤ queryBound) (below : supportBound < queryBound)
    (test : List (ExtractionTrace RawInput) → Prop)
    (state : State Key DigestRegister DigestRegister Workspace)
    (bounded : BoundedState supportBound state) :
    normSquared (partitionReflection (sourceProperty keyBytes rawDigestBits.symm fuel targets test)
        (queryState digestPhaseSystem queryBound state) -
      queryState digestPhaseSystem queryBound
        (partitionReflection (sourceProperty keyBytes rawDigestBits.symm fuel targets test) state)) ≤
      (144 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  rw [← reflection_commutator_is_actual_query digestPhaseSystem _ queryBound supportBound state below bounded]
  have bound := reflection_commutator_bound digestPhaseSystem
    (sourceProperty keyBytes rawDigestBits.symm fuel targets test) queryBound state
    (source_property_instability keyBytes rawDigestBits.symm fuel targets queryBound targetBudget test).toReal
  convert bound using 1
  push_cast
  ring

end SourceEndpoint

end

end HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument
