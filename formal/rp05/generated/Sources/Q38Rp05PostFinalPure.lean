import Q38Rp05WholePrivacy
import Q38OpenedRows
import Q38JointSimulatorR2
import Q38RemainingAlgebra
import HegemonCrypto.SmallWoodV8Smz9PostFinalProgram
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler
import HegemonCrypto.SmallWoodV8Smz9SourceIndexSampler
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch
import HegemonCrypto.SmallWoodV8Smz9WholeViewObservation
import HegemonCrypto.SmallWoodV8Smz9ZeroKnowledge
import Q38Rp05ChronologicalAlgebra
import Q38Rp05RequestCompiler
import Q38Rp05AdaptiveOpening
import Q38Rp05CurrentDisjointCoset

/-!
# Pure q38 post-final data and byte construction

Exact shared q38 sampling, public reconstruction, and SMZA serialization declarations
used by the historical and current request programs. Moving these declarations does not
alter their semantics and does not establish endpoint privacy or production authority.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler

open HegemonCrypto.CanonicalBytes HegemonCrypto.SmallWoodProofWire
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9SourceIndexSampler
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram
open HegemonCrypto.SmallWood.V8Smz9PostFinalSerializer
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaOpenedRows
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

def indexedPoints (indices : Fin 38 → LeafIndex) : Fin 38 → Goldilocks :=
  fun opening => HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset.indexedPoint
    (indices opening)

abbrev IndexedTargets (points : Fin 6 → Goldilocks) :=
  { indices : Fin 38 → LeafIndex //
    Function.Injective indices ∧ TailAdmissible points (indexedPoints indices) }

def targetValues {points : Fin 6 → Goldilocks}
    (targets : IndexedTargets points) : Targets points :=
  ⟨indexedPoints targets.val, targets.property.2⟩

def collectIndices : List FieldWord → List LeafIndex → List LeafIndex
  | [], selected => selected
  | candidate :: rest, selected =>
      if selected.length = 38 then selected else
      if candidate.val < (goldilocksModulus / 8388608) * 8388608 then
        let index : LeafIndex := ⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩
        if index ∈ selected then collectIndices rest selected
        else collectIndices rest (selected.concat index)
      else collectIndices rest selected

theorem collect_indices_nodup (candidates : List FieldWord)
    (selected : List LeafIndex) (nodup : selected.Nodup) :
    (collectIndices candidates selected).Nodup := by
  induction candidates generalizing selected with
  | nil => exact nodup
  | cons candidate rest ih =>
      simp only [collectIndices]
      split
      · exact nodup
      · split
        · split
          · exact ih _ nodup
          · exact ih _ (List.Nodup.concat (by assumption) nodup)
        · exact ih _ nodup

def sortedIndices (candidates : List FieldWord) : List LeafIndex :=
  (collectIndices candidates []).mergeSort (fun left right => decide (left.val ≤ right.val))

theorem sorted_indices_nodup (candidates : List FieldWord) :
    (sortedIndices candidates).Nodup :=
  (collect_indices_nodup candidates [] (by simp)).mergeSort

theorem indexed_targets_admissible (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points) (indices : Fin 38 → LeafIndex)
    (indicesDistinct : Function.Injective indices) :
    TailAdmissible points (indexedPoints indices) := by
  have targetsDistinct : Function.Injective (indexedPoints indices) :=
    HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset.current_point_injective.comp
      indicesDistinct
  have outside : ∀ opening (node : Fin 406),
      indexedPoints indices opening ≠ (node.val : Goldilocks) :=
    fun opening node =>
      HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset.current_domain_point_avoids_node
        (indices opening) node
  exact admissibleOfDistinct points pointsDistinct _ targetsDistinct outside

def sampledTargets (points : Fin 6 → Goldilocks)
    (pointsDistinct : Function.Injective points)
    (candidates : List FieldWord) : Option (IndexedTargets points) :=
  let indices := sortedIndices candidates
  if enough : indices.length = 38 then
    let selected : Fin 38 → LeafIndex := fun index => indices.get (index.cast enough.symm)
    let selectedDistinct : Function.Injective selected := by
      intro left right same
      have equal := (sorted_indices_nodup candidates).injective_get same
      exact Fin.ext (congrArg (fun index : Fin indices.length => index.val) equal)
    some ⟨selected, selectedDistinct,
      indexed_targets_admissible points pointsDistinct selected selectedDistinct⟩
  else none

theorem sampled_targets_are_admissible {points : Fin 6 → Goldilocks}
    (pointsDistinct : Function.Injective points) (candidates : List FieldWord)
    (targets : IndexedTargets points)
    (_selected : sampledTargets points pointsDistinct candidates = some targets) :
    TailAdmissible points (indexedPoints targets.val) := by
  exact targets.property.2


def openingWords (digest : DigestRegister)
    (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Earlier Goldilocks) : List Nat :=
  sourceDigestWords digest ++
    (List.ofFn fun combination : Fin 12 =>
      (List.ofFn fun column : Fin 368 => fromGoldilocks (heads combination column)) ++
      (List.ofFn fun tail : Fin 38 => fromGoldilocks (tails combination tail))).flatten

theorem opening_word_count (digest : DigestRegister)
    (heads : Fin 12 → Fin 368 → Goldilocks) (tails : Earlier Goldilocks) :
    (openingWords digest heads tails).length = 4880 := by
  simp only [openingWords, List.length_append, source_digest_word_count,
    List.length_flatten, List.map_ofFn, Function.comp_def, List.length_ofFn,
    List.sum_ofFn, Finset.sum_const, Finset.card_univ, Fintype.card_fin,
    smul_eq_mul]


structure SelectionResult (points : Fin 6 → Goldilocks) where
  transcriptDigest : DigestRegister
  fieldCandidates : Option (List FieldWord)
  targets : Option (IndexedTargets points)
  pendingFailure : Bool


def publicMaskOpenings (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (points : Fin 6 → Goldilocks)
    (transcript : Q) (witness : WitnessOpeningView Goldilocks) :
    MaskOpeningValues Goldilocks :=
  (fun opening polynomial =>
    recoverNonlinearMaskOpening canonicalPacking
      (coefficientPolynomial (transcript.1 polynomial))
      (∑ root, nonlinearGamma dsl statement parameters polynomial root *
        nonlinearScalar dsl statement (witness opening) root)
      (points opening),
  fun opening polynomial =>
    recoverLinearMaskOpening canonicalPacking
      (∑ row, linearGamma dsl statement parameters polynomial row *
        dsl.linearTarget statement row) (transcript.2 polynomial)
      (currentLinearWeights dsl statement parameters polynomial)
      (sourcePackingLagrange canonicalPacking) (witness opening) (points opening))

def combinationHeads (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (points : Fin 6 → Goldilocks)
    (transcript : Q) (witness : WitnessOpeningView Goldilocks)
    (pcs : SourcePcsView Goldilocks) : PublicCombinationHeads Goldilocks :=
  reconstructedCombinationHeads points witness
    (publicMaskOpenings dsl statement parameters points transcript witness) pcs


/-- The exact public field carrier serialized by profile 9.  Every high matrix
is a projection of the already-published D or Q response. -/
structure Fields where
  rowScalars : Fin 6 → Fin 696 → Goldilocks
  partialEvaluations : Fin 6 → Fin 40 → Goldilocks
  combinationTails : Fin 12 → Fin 38 → Goldilocks
  subsetEvaluations : Fin 38 → Fin 128 → Goldilocks
  decsMaskEvaluations : Fin 38 → Fin 5 → Goldilocks
  decsHighs : Fin 5 → Fin 368 → Goldilocks
  nonlinearHighs : Fin 5 → Fin 483 → Goldilocks
  linearHighs : Fin 5 → Fin 126 → Goldilocks

def fields (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (targets : IndexedTargets opening.points) (view : RemainingView Goldilocks) : Fields :=
  let masks := publicMaskOpenings dsl statement parameters opening.points transcript view.1
  let rows := reconstruct opening.points (computed_opening_selected_rank opening)
    (combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1)
    view.2.2.1 (indexedPoints targets.val) view.2.2.2
  {
    rowScalars := sourceRowScalars view.1 masks
    partialEvaluations := sourcePartialEvaluations view.2.1
    combinationTails := view.2.2.1
    subsetEvaluations := view.2.2.2
    decsMaskEvaluations := recoverMasks gamma reply (indexedPoints targets.val) rows
    decsHighs := fun polynomial coefficient => reply polynomial (Fin.natAdd 38 coefficient)
    nonlinearHighs := fun polynomial coefficient =>
      transcript.1 polynomial (Fin.natAdd 6 coefficient)
    linearHighs := fun polynomial coefficient => transcript.2 polynomial (Fin.natAdd 6 coefficient)
  }

def compactPathLevels : List (List DigestRegister) →
    (Fin 38 → Nat) → Fin 38 → List DigestRegister
  | [], _ => fun _ => []
  | level :: rest, indices =>
      let later := compactPathLevels rest (fun opening => indices opening / 2)
      fun opening =>
        let sibling := sourceSibling (indices opening)
        if sibling ∈ Finset.univ.image indices then later opening
        else level.getD sibling 0 :: later opening

theorem compact_path_levels_length_le (levels : List (List DigestRegister))
    (indices : Fin 38 → Nat) (opening : Fin 38) :
    (compactPathLevels levels indices opening).length ≤ levels.length := by
  induction levels generalizing indices with
  | nil => simp [compactPathLevels]
  | cons level rest ih =>
      simp only [compactPathLevels]
      split
      · have h := ih (fun i => indices i / 2)
        simp only [List.length_cons]
        omega
      · have h := ih (fun i => indices i / 2)
        simp only [List.length_cons]
        omega

def compactPaths (tree : List (List DigestRegister)) (indices : Fin 38 → LeafIndex) :
    Fin 38 → List DigestRegister :=
  compactPathLevels (tree.take 23) (fun opening => (indices opening).val)

def authPathsWire (tree : List (List DigestRegister))
    (indices : Fin 38 → LeafIndex) : AuthPathsWire where
  rowCountBytes := encodeLE 2 38
  pathLengthBytes := List.ofFn fun opening =>
    ⟨(compactPaths tree indices opening).length, by
      have bounded : (compactPaths tree indices opening).length ≤ 23 := by
        unfold compactPaths
        exact (compact_path_levels_length_le (tree.take 23)
          (fun i => (indices i).val) opening).trans (List.length_take_le 23 tree)
      exact bounded.trans_lt (by decide)⟩
  nodeBytes := (List.ofFn fun opening =>
    (compactPaths tree indices opening).flatMap fun digest => (sourceDigest digest).val).flatten

def tapeBytes (tapes : Fin 38 → LeafTape) : List Byte :=
  (List.ofFn fun opening => List.ofFn (tapes opening)).flatten

def proofBytes (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 38 → LeafIndex)
    (publicFields : Fields) (tapes : Fin 38 → LeafTape) : List Byte :=
  [83, 77, 90, 65] ++ List.ofFn salt ++ encodeLE 4 nonce.val ++
  (sourceDigest digest).val ++
  (sourceMatrixWire publicFields.nonlinearHighs).encode ++
  (sourceMatrixWire publicFields.linearHighs).encode ++
  (sourceMatrixWire publicFields.combinationTails).encode ++
  (sourceMatrixWire publicFields.subsetEvaluations).encode ++
  (sourceMatrixWire publicFields.partialEvaluations).encode ++
  (authPathsWire tree indices).encode ++ tapeBytes tapes ++
  (sourceMatrixWire publicFields.decsMaskEvaluations).encode ++
  (sourceMatrixWire publicFields.decsHighs).encode ++ [1] ++
  (sourceMatrixWire publicFields.rowScalars).encode ++ encodeLE 4 0 ++ encodeLE 4 0

def finishBytes (pending : Bool) (bytes : List Byte) : Except String (List Byte) :=
  match sourceScopeFinish pending bytes with
  | .error message => .error message
  | .ok encoded => if encoded.length ≤ 164113 then .ok encoded
      else .error "smallwood SMZA inner proof exceeds the exact 164113-byte cap"

theorem finish_bytes_latched_failure (bytes : List Byte) :
    finishBytes true bytes =
      .error "smallwood SHA-512 field-XOF rejection budget exhausted" := by
  rfl

def selectedBytes (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes) (tree : List (List DigestRegister))
    (tapes : TapeTable) (view : PartialView Goldilocks)
    (result : SelectionResult opening.points) : Except String (List Byte) :=
  match result.targets, view.2.2.2 with
  | none, _ => .error "fixed DECS sampler exhausted its candidate pool"
  | some _, none => .error "q38 later opening coordinates missing after successful selection"
  | some targets, some later =>
      let complete : RemainingView Goldilocks :=
        (view.1, view.2.1, view.2.2.1, later)
      finishBytes result.pendingFailure
        (proofBytes salt opening.nonce digest tree targets.val
          (fields dsl statement parameters opening gamma reply transcript targets complete)
          (fun index => tapes (targets.val index)))

theorem selected_bytes_index_exhaustion
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes) (tree : List (List DigestRegister))
    (tapes : TapeTable) (view : PartialView Goldilocks)
    (result : SelectionResult opening.points) (exhausted : result.targets = none) :
    selectedBytes dsl statement parameters opening gamma reply transcript digest
      salt tree tapes view result =
        .error "fixed DECS sampler exhausted its candidate pool" := by
  simp [selectedBytes, exhausted]

theorem selected_bytes_success_is_exact_smza
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes) (tree : List (List DigestRegister))
    (tapes : TapeTable) (view : PartialView Goldilocks)
    (result : SelectionResult opening.points) (targets : IndexedTargets opening.points)
    (later : Later Goldilocks) (selected : result.targets = some targets)
    (available : view.2.2.2 = some later) :
    selectedBytes dsl statement parameters opening gamma reply transcript digest
      salt tree tapes view result =
        finishBytes result.pendingFailure
          (proofBytes salt opening.nonce digest tree targets.val
            (fields dsl statement parameters opening gamma reply transcript targets
              (view.1, view.2.1, view.2.2.1, later))
            (fun index => tapes (targets.val index))) := by
  simp [selectedBytes, selected, available]


end
end HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
