import SmzaStageVectorInstability
import SmzaOnlineAssemblyR6

/-! The selected-stage trace bound controls the actual permutation of Record
slots, including a full counter-vector CMS call. Unlike an additive answer
register, Record labels need not form a group. Fixed other-stage advice is
allowed only in deterministic trace postprocessing. -/
namespace HegemonCrypto.SmallWood.SmzaStageControlledSplit

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsClassicalDatabase
open V8Smz9CoherentMerklePartition V8Smz9CoherentMerkleInstrument
open V8Smz9HiddenLeafQrom V8Smz9CoherentVectorMerkle
open SmzaRecordSplitR3 SmzaOnlineAssemblyActiveR6
open SmzaChallengeStageTargets SmzaFixedAdvicePrefix SmzaStageVectorInstability

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

variable {Key Counter Target Label Cell Private Advice : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

abbrev PhysicalBasis (Key Counter Target Label Cell Private : Type*) :=
  Basis Key (VectorOutput Counter) (VectorOutput Counter)
    (Private × Registers Target Label Cell)

def registerPermutation
    (permutations : Database Key (VectorOutput Counter) →
      Registers Target Label Cell ≃ Registers Target Label Cell) :
    PhysicalBasis Key Counter Target Label Cell Private ≃
      PhysicalBasis Key Counter Target Label Cell Private where
  toFun basis := { basis with workspace := (basis.workspace.1, permutations basis.database basis.workspace.2) }
  invFun basis := { basis with workspace := (basis.workspace.1, (permutations basis.database).symm basis.workspace.2) }
  left_inv basis := by cases basis; simp
  right_inv basis := by cases basis; simp

def restrictedSplit (selected : Finset Target)
    (labels : Database Key (VectorOutput Counter) → Target → Label) :
    PhysicalBasis Key Counter Target Label Cell Private ≃
      PhysicalBasis Key Counter Target Label Cell Private :=
  registerPermutation fun database => restrictedSplitRegisters selected (labels database)

def labels (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput → V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (database : Database Key (VectorOutput Counter)) (target : Target) : Label :=
  enrichedLabel next role fuel code advice
    (rawRecords keyBytes (vectorOutputBytes counter) database) (targetBytes target)

def PrefixRange (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter) (queries : List V8SmzaOracleParser.RawInput) :=
  Set.range (stageVectorTrace next role fuel keyBytes counter queries)

instance (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter) (queries : List V8SmzaOracleParser.RawInput) :
    Fintype (PrefixRange next role fuel keyBytes counter queries) :=
  Fintype.ofSurjective
    (fun database : Database Key (VectorOutput Counter) =>
      (⟨stageVectorTrace next role fuel keyBytes counter queries database, ⟨database, rfl⟩⟩ :
        PrefixRange next role fuel keyBytes counter queries))
    (by rintro ⟨value, ⟨database, rfl⟩⟩; exact ⟨database, rfl⟩)

def prefixValue (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter) (queries : List V8SmzaOracleParser.RawInput)
    (database : Database Key (VectorOutput Counter)) :
    PrefixRange next role fuel keyBytes counter queries :=
  ⟨stageVectorTrace next role fuel keyBytes counter queries database, ⟨database, rfl⟩⟩

omit [DecidableEq Key] in
theorem restricted_slots_equal_of_prefix_equal
    (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput → V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (selected : Finset Target)
    (left right : Database Key (VectorOutput Counter))
    (same : stageVectorTrace next role fuel keyBytes counter (selected.toList.map targetBytes) left =
      stageVectorTrace next role fuel keyBytes counter (selected.toList.map targetBytes) right) :
    restrictedSplitRegisters (Cell := Cell) selected
        (labels next role fuel keyBytes targetBytes counter code advice left) =
      restrictedSplitRegisters selected
        (labels next role fuel keyBytes targetBytes counter code advice right) := by
  apply restricted_split_eq_of_labels_agree
  intro target member
  exact fixed_advice_postprocessing_preserves_prefix_equality next role fuel code advice
    _ _ (selected.toList.map targetBytes) same (targetBytes target)
    (List.mem_map.mpr ⟨target, Finset.mem_toList.mpr member, rfl⟩)

variable [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Private]

theorem prefix_sign_is_reflection
    (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter) (queries : List V8SmzaOracleParser.RawInput) (cap : Nat)
    (selection : PrefixRange next role fuel keyBytes counter queries → Bool)
    (state : PhysicalBasis Key Counter Target Label Cell Private → ℂ) :
    signCommutator (fun basis => prefixValue next role fuel keyBytes counter queries basis.database)
        (boundedKernel vectorPhaseSystem cap) selection state =
      reflectionCommutator vectorPhaseSystem
        (fun database => selection (prefixValue next role fuel keyBytes counter queries database) = true)
        cap state := by
  have signed : ∀ vector : PhysicalBasis Key Counter Target Label Cell Private → ℂ,
      signedState (fun basis => prefixValue next role fuel keyBytes counter queries basis.database)
          selection vector = partitionReflection
          (fun database => selection (prefixValue next role fuel keyBytes counter queries database) = true)
          vector := by
    intro vector
    funext basis
    cases chosen : selection (prefixValue next role fuel keyBytes counter queries basis.database) <;>
      simp [signedState, labelSign, partitionReflection, chosen]
  unfold signCommutator reflectionCommutator
  rw [bounded_kernel_apply, signed, signed, bounded_kernel_apply]

omit [Fintype Cell] [Fintype Private] in
theorem restricted_same_prefix_kernel
    (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput → V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (selected : Finset Target) (cap : Nat)
    (source target : PhysicalBasis Key Counter Target Label Cell Private)
    (same : prefixValue next role fuel keyBytes counter (selected.toList.map targetBytes) source.database =
      prefixValue next role fuel keyBytes counter (selected.toList.map targetBytes) target.database) :
    boundedKernel vectorPhaseSystem cap
        (restrictedSplit selected (labels next role fuel keyBytes targetBytes counter code advice) source)
        (restrictedSplit selected (labels next role fuel keyBytes targetBytes counter code advice) target) =
      boundedKernel vectorPhaseSystem cap source target := by
  have registers := restricted_slots_equal_of_prefix_equal (Cell := Cell)
    next role fuel keyBytes targetBytes counter code advice selected
    source.database target.database (congrArg Subtype.val same)
  simp [boundedKernel, kernel, restrictedSplit, registerPermutation, registers, Prod.ext_iff]

/-- Full controlled Record-slot permutation, not a caller-supplied operator
estimate. The 576 coefficient is independent of label and counter cardinality. -/
theorem selected_stage_restricted_split_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput → V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (selected : Finset Target) (cap : Nat) (targetBound : selected.card ≤ cap)
    (state : PhysicalBasis Key Counter Target Label Cell Private → ℂ) :
    normSquared
      (permute (restrictedSplit selected (labels next role fuel keyBytes targetBytes counter code advice))
          (boundedQuery vectorPhaseSystem cap state) -
        boundedQuery vectorPhaseSystem cap
          (permute (restrictedSplit selected (labels next role fuel keyBytes targetBytes counter code advice)) state)) ≤
      (576 * cap / (2^512 : ℝ)) * normSquared state := by
  have queryBound : (selected.toList.map targetBytes).length ≤ cap := by simpa using targetBound
  have result := full_permutation_commutator_bound
    (fun basis : PhysicalBasis Key Counter Target Label Cell Private =>
      prefixValue next role fuel keyBytes counter (selected.toList.map targetBytes) basis.database)
    (boundedKernel vectorPhaseSystem cap)
    (restrictedSplit selected (labels next role fuel keyBytes targetBytes counter code advice))
    (by intro basis; rfl)
    (restricted_same_prefix_kernel next role fuel keyBytes targetBytes counter code advice selected cap)
    (48 * (((3*cap : Rat)/(2^512 : Rat)) : ℝ)) (by
      intro selection vector
      rw [prefix_sign_is_reflection]
      apply reflection_commutator_bound vectorPhaseSystem _ cap vector
      have instability := stage_vector_value_instability next children role fuel keyBytes counter
        (selected.toList.map targetBytes) cap queryBound
        (prefixValue next role fuel keyBytes counter (selected.toList.map targetBytes))
        (fun _ _ equal => Subtype.ext equal) (fun value => selection value = true)
      simpa only [Rat.cast_div] using instability.toReal) state
  rw [bounded_kernel_apply, bounded_kernel_apply] at result
  change normSquared _ ≤ 4 * (48 * (((3*cap : Rat)/(2^512 : Rat)) : ℝ)) * normSquared state at result
  convert result using 1
  push_cast
  ring

end
end HegemonCrypto.SmallWood.SmzaStageControlledSplit
