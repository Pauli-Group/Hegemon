import HegemonCrypto.SmallWoodV8Smz9PrivacyGameComposition
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset

/-!
# Public eager leaf encoding and chronological oracle-game transport

The public leaf constructor consumes the eager algebraic fields, sampled indices,
salt and revealed tapes. Its raw input contains canonical field representatives,
not fresh replacement mask values. The transport below instantiates the actual
source PIOP-mask recovery, PCS columns and committed-head callbacks.
-/

namespace HegemonCrypto.SmallWood.V8Smz9EagerOracleGame

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9JointAlgebraicLaw V8Smz9SingleProofPrivacy
open V8Smz9HonestHybrid V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9PrivacyGameComposition
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000

abbrev RawWord := Fin (256 ^ 8)
abbrev SaltBytes := Fin 32 → Byte

def rawWordBytes (word : RawWord) : Fin 8 → Byte := finFunctionFinEquiv.symm word

theorem raw_word_bytes_little_endian (word : RawWord) :
    (∑ byte : Fin 8, (rawWordBytes word byte).val * 256 ^ byte.val) = word.val := by
  rw [← finFunctionFinEquiv_apply]
  exact congrArg Fin.val (finFunctionFinEquiv.apply_symm_apply word)

def canonicalFieldWord (value : Goldilocks) : RawWord :=
  ⟨fromGoldilocks value, lt_trans (fromGoldilocks_lt value) (by norm_num [goldilocksModulus])⟩

def canonicalFieldBytes (value : Goldilocks) : Fin 8 → Byte :=
  rawWordBytes (canonicalFieldWord value)

theorem canonical_field_bytes_value (value : Goldilocks) :
    (∑ byte : Fin 8, (canonicalFieldBytes value byte).val * 256 ^ byte.val) =
      fromGoldilocks value := raw_word_bytes_little_endian _

theorem canonical_field_bytes_injective : Function.Injective canonicalFieldBytes := by
  intro left right equality
  have sameWords := congrArg finFunctionFinEquiv equality
  simp only [canonicalFieldBytes, rawWordBytes, Equiv.apply_symm_apply] at sameWords
  have values := congrArg Fin.val sameWords
  exact ZMod.val_injective _ values

def literalBytes (text : String) (count : ℕ) (length : text.toUTF8.size = count) :
    Fin count → Byte := fun index =>
  ⟨(text.toUTF8[index.val]'(by rw [length]; exact index.isLt)).toNat,
    UInt8.toNat_lt_size _⟩

/-- All 151 bytes preceding the leaf index: profile/role framing, word count and salt. -/
def canonicalLeafHeader (salt : SaltBytes) : LeafHeader :=
  Fin.append
    (Fin.append (rawWordBytes ⟨53, by norm_num⟩)
      (Fin.append (literalBytes smz9ProfileTag 53 (by decide))
        (Fin.append (rawWordBytes ⟨42, by norm_num⟩)
          (Fin.append (literalBytes (hashRoleTag .leaf) 42 (by decide))
            (rawWordBytes ⟨160, by norm_num⟩))))) salt

def fieldVectorBytes {count : ℕ} (values : Fin count → Goldilocks) : Fin (count * 8) → Byte :=
  fun index => canonicalFieldBytes (values (finProdFinEquiv.symm index).1)
    (finProdFinEquiv.symm index).2

theorem field_vector_bytes_at {count : ℕ} (values : Fin count → Goldilocks)
    (row : Fin count) (byte : Fin 8) :
    fieldVectorBytes values (finProdFinEquiv (row, byte)) = canonicalFieldBytes (values row) byte := by
  simp only [fieldVectorBytes, Equiv.symm_apply_apply]

/-- Row-count word, 140 canonical data words, mask-count word, five mask words and counter zero. -/
def canonicalLeafSuffix (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) : LeafSuffix :=
  Fin.append (rawWordBytes ⟨140, by norm_num⟩)
    (Fin.append (fieldVectorBytes rows)
      (Fin.append (rawWordBytes ⟨5, by norm_num⟩)
        (Fin.append (fieldVectorBytes masks) (rawWordBytes ⟨0, by norm_num⟩))))

def canonicalLeafInput (salt : SaltBytes) (index : LeafIndex) (tape : LeafTape)
    (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) : LeafInput :=
  sourceLeafInput (canonicalLeafHeader salt) (canonicalLeafSuffix rows masks) index tape

theorem canonical_leaf_index (salt : SaltBytes) (index : LeafIndex) (tape : LeafTape)
    (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) :
    rawInputIndex (canonicalLeafInput salt index tape rows masks) = index :=
  source_leaf_index_projection _ _ _ _

theorem canonical_leaf_tape (salt : SaltBytes) (index : LeafIndex) (tape : LeafTape)
    (rows : Fin 140 → Goldilocks) (masks : Fin 5 → Goldilocks) :
    leafTapeProjection (canonicalLeafInput salt index tape rows masks) = tape :=
  source_leaf_tape_projection _ _ _ _

def fieldWitness {F : Type*} (fields : EagerAlgebraicFields F) : WitnessOpeningView F :=
  fun opening row => fields.rowScalars opening (Fin.castAdd 10 row)

def fieldMasks {F : Type*} (fields : EagerAlgebraicFields F) : MaskOpeningValues F :=
  (fun opening polynomial => fields.rowScalars opening (Fin.natAdd 686 (Fin.castAdd 5 polynomial)),
    fun opening polynomial => fields.rowScalars opening (Fin.natAdd 686 (Fin.natAdd 5 polynomial)))

def fieldPartials {F : Type*} (fields : EagerAlgebraicFields F) : SourcePcsView F :=
  (fun polynomial opening column =>
    fields.partialEvaluations opening (Fin.castAdd 5 (finProdFinEquiv (polynomial, column))),
    fun polynomial opening => fields.partialEvaluations opening (Fin.natAdd 35 polynomial))

theorem eager_field_decoders {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma F) (response : DecsFullCoefficients F)
    (transcript : PiopCoefficients F) (targets : Fin 20 → F)
    (masks : MaskOpeningValues F) (view : SourceRemainingView F) :
    let fields := eagerAlgebraicFields points selected gamma response transcript targets masks view
    fieldWitness fields = view.1 ∧ fieldMasks fields = masks ∧ fieldPartials fields = view.2.1 := by
  refine ⟨?_, ?_, ?_⟩
  · funext opening row
    exact source_row_scalar_witness_index _ _ _ _
  · apply Prod.ext <;> funext opening polynomial
    · exact source_row_scalar_nonlinear_index _ _ _ _
    · exact source_row_scalar_linear_index _ _ _ _
  · apply Prod.ext
    · funext polynomial opening column
      exact source_partial_nonlinear_index _ _ _ _
    · funext polynomial opening
      exact source_partial_linear_index _ _ _

/-- All 140 source rows are reconstructed from fields already present in the public proof. -/
def rowsFromFields {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (targets : Fin 20 → F) (fields : EagerAlgebraicFields F) : OpenedRows F :=
  reconstructOpenedRows points selected
    (reconstructedCombinationHeads points (fieldWitness fields) (fieldMasks fields) (fieldPartials fields))
    fields.combinationTails targets fields.subsetEvaluations

theorem rows_from_eager_fields {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma F) (response : DecsFullCoefficients F)
    (transcript : PiopCoefficients F) (targets : Fin 20 → F)
    (masks : MaskOpeningValues F) (view : SourceRemainingView F) :
    rowsFromFields points selected targets
      (eagerAlgebraicFields points selected gamma response transcript targets masks view) =
    reconstructOpenedRows points selected (reconstructedCombinationHeads points view.1 masks view.2.1)
      view.2.2.1 targets view.2.2.2 := by
  obtain ⟨witness, mask, partials⟩ := eager_field_decoders points selected gamma response transcript targets masks view
  unfold rowsFromFields
  rw [witness, mask, partials]
  rfl

def indexedPoints (indices : Fin 20 → LeafIndex) : Fin 20 → Goldilocks :=
  fun opening => V8Smz9DisjointCoset.evaluationPoint (indices opening)

abbrev IndexedTargets (points : Fin 6 → Goldilocks) :=
  { indices : Fin 20 → LeafIndex //
    Function.Injective indices ∧ Smz9LvcsTailAdmissible points (indexedPoints indices) }

def targetValues {points : Fin 6 → Goldilocks} (targets : IndexedTargets points) :
    LvcsAdmissibleTargets points := ⟨indexedPoints targets.val, targets.property.2⟩

abbrev IndexChooser (points : Fin 6 → Goldilocks) :=
  WitnessOpeningView Goldilocks → SourcePcsView Goldilocks → LvcsEarlierTails Goldilocks →
    Option (IndexedTargets points)

def valueChooser {points : Fin 6 → Goldilocks} (choose : IndexChooser points) :=
  fun witness partials early => (choose witness partials early).map targetValues

abbrev EagerContext (points : Fin 6 → Goldilocks) :=
  Option (IndexedTargets points × EagerAlgebraicFields Goldilocks)

def eagerContext (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourceRemainingView Goldilocks) : EagerContext points :=
  (choose view.1 view.2.1 view.2.2.1).map fun targets =>
    (targets, eagerPublicAlgebraicFields parameters points selected gamma response transcript
      (indexedPoints targets.val) view)

def partialContext (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourcePartialRemainingView Goldilocks) : EagerContext points :=
  view.2.2.2.bind fun subset =>
    eagerContext parameters points selected gamma response transcript choose
      (view.1, view.2.1, view.2.2.1, subset)

theorem partial_context_abort_projection
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (choose : IndexChooser points)
    (view : SourceRemainingView Goldilocks) :
    partialContext parameters points selected gamma response transcript choose
        (sourceRemainingAbortProjection (valueChooser choose) view) =
      eagerContext parameters points selected gamma response transcript choose view := by
  cases chosen : choose view.1 view.2.1 view.2.2.1 <;>
    simp [partialContext, sourceRemainingAbortProjection, valueChooser, eagerContext, chosen]

def contextSelection {points : Fin 6 → Goldilocks} (context : EagerContext points) :
    Option (Finset LeafIndex) := context.map fun output => Finset.univ.image output.1.val

theorem abort_has_no_opened_programs {points : Fin 6 → Goldilocks} :
    openedOrEmpty (contextSelection (points := points) none) = ∅ := rfl

def publicOpenedInputs (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) : Finset LeafInput :=
  match context with
  | none => ∅
  | some (targets, fields) => Finset.univ.image fun opening : Fin 20 =>
      canonicalLeafInput salt (targets.val opening) (tapes (targets.val opening))
        (rowsFromFields points selected (indexedPoints targets.val) fields opening)
        (fields.decsMaskEvaluations opening)

theorem public_opened_inputs_only_revealed_tapes
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (left right : TapeTable)
    (same : ∀ index ∈ openedOrEmpty (contextSelection context), left index = right index) :
    publicOpenedInputs points selected salt context left =
      publicOpenedInputs points selected salt context right := by
  cases context with
  | none => rfl
  | some output =>
    apply Finset.image_congr
    intro opening _
    have equalTape := same (output.1.val opening) (by
      change output.1.val opening ∈ Finset.univ.image output.1.val
      exact Finset.mem_image.mpr ⟨opening, Finset.mem_univ _, rfl⟩)
    simp only [equalTape]

def publicOpenedOracle {Output : Type*} (old : LeafInput → Output) (labels : LeafIndex → Output)
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) : LeafInput → Output :=
  fun input => if input ∈ publicOpenedInputs points selected salt context tapes
    then labels (rawInputIndex input) else old input

theorem public_opened_oracle_restores_prior_entry {Output : Type*}
    (old : LeafInput → Output) (labels : LeafIndex → Output)
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) (input : LeafInput)
    (notOpened : input ∉ publicOpenedInputs points selected salt context tapes) :
    publicOpenedOracle old labels points selected salt context tapes input = old input := by
  simp only [publicOpenedOracle, if_neg notOpened]

def openingSlot (indices : Fin 20 → LeafIndex) (index : LeafIndex) : Fin 20 :=
  if existsSlot : ∃ opening, indices opening = index then existsSlot.choose else 0

theorem opening_slot_at (indices : Fin 20 → LeafIndex) (injective : Function.Injective indices)
    (opening : Fin 20) : openingSlot indices (indices opening) = opening := by
  unfold openingSlot
  split
  · next existsSlot => exact injective existsSlot.choose_spec
  · next absent => exact False.elim (absent ⟨opening, rfl⟩)

/-- A public total suffix table. Unopened entries are irrelevant to the opened-only reference. -/
def publicSuffix (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (context : EagerContext points) : LeafIndex → LeafSuffix :=
  match context with
  | none => fun _ => canonicalLeafSuffix 0 0
  | some (targets, fields) => fun index =>
      let opening := openingSlot targets.val index
      canonicalLeafSuffix
        (rowsFromFields points selected (indexedPoints targets.val) fields opening)
        (fields.decsMaskEvaluations opening)

theorem public_suffix_support_is_exact
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) :
    sourcePatchSupport (openedOrEmpty (contextSelection context))
        (fun _ => canonicalLeafHeader salt) (publicSuffix points selected context) tapes =
      publicOpenedInputs points selected salt context tapes := by
  cases context with
  | none => simp [sourcePatchSupport, contextSelection, openedOrEmpty, publicOpenedInputs]
  | some output =>
    change (Finset.univ.image output.1.val).image _ = Finset.univ.image _
    rw [Finset.image_image]
    apply Finset.image_congr
    intro opening _
    simp only [Function.comp_apply, publicSuffix, opening_slot_at _ output.1.property.1,
      canonicalLeafInput]

theorem public_suffix_overlay_is_exact {Output : Type*}
    (old : LeafInput → Output) (labels : LeafIndex → Output)
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (context : EagerContext points) (tapes : TapeTable) :
    sourceOverlay old labels (openedOrEmpty (contextSelection context))
        (fun _ => canonicalLeafHeader salt) (publicSuffix points selected context) tapes =
      publicOpenedOracle old labels points selected salt context tapes := by
  funext input
  simp only [sourceOverlay, publicOpenedOracle, public_suffix_support_is_exact]

section PhysicalPublicReference

variable {Other Output Workspace : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Output] [DecidableEq Output] [AddGroup Output]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- A public physical continuation and the complete prior oracle, including prior proof entries.
No privacy bound or experiment-equivalence field is accepted. -/
structure PublicContinuation where
  oldLeaf : LeafInput → Output
  other : Other → Output
  initial : PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  normalized : ‖initial‖ = 1
  steps : ℕ → PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
    PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  queries : ℕ
  post : TapeTable → PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
    PhysicalState (Other := Other) (Output := Output) (Workspace := Workspace)
  event : TapeTable → Finset (V8Smz9HiddenLeafQrom.QueryBasis (LeafInput ⊕ Other) Output Workspace)

def publicAtomicReference (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace)) :
    AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace) where
  oldLeaf := continuation.oldLeaf
  other := continuation.other
  targets := labels
  header := fun _ => canonicalLeafHeader salt
  suffix := publicSuffix points selected context
  initial := continuation.initial
  normalized := continuation.normalized
  steps := continuation.steps
  queries := continuation.queries
  post := continuation.post
  event := continuation.event

omit [DecidableEq Other] [DecidableEq Output] [AddGroup Output] [DecidableEq Workspace] in
/-- The reference table is literally the public serializer's opened-program table,
with every nonopened input answered by the previous oracle. -/
theorem public_atomic_kept_oracle_is_serializer
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) :
    (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
      (publicAtomicReference points selected salt labels context continuation)).oldLeaf =
    publicOpenedOracle continuation.oldLeaf labels points selected salt context
      (mergeTapes (openedOrEmpty (contextSelection context)) visible (fun _ => 0)) :=
  public_suffix_overlay_is_exact _ _ _ _ _ _ _

/-- Fill the unopened suffixes from the source coupling. Only the comparison game
contains this table; the opened-only reference above has no such input. -/
def completedAtomicReference (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (fullSuffix : LeafIndex → LeafSuffix) :
    AtomicReference (Other := Other) (Output := Output) (Workspace := Workspace) :=
  { publicAtomicReference points selected salt labels context continuation with suffix := fullSuffix }

omit [DecidableEq Other] [DecidableEq Output] [AddGroup Output] [DecidableEq Workspace] in
theorem completed_opened_oracle_eq_public
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (fullSuffix : LeafIndex → LeafSuffix)
    (suffixMatches : ∀ index ∈ openedOrEmpty (contextSelection context),
      fullSuffix index = publicSuffix points selected context index)
    (tapes : TapeTable) :
    sourceOverlay continuation.oldLeaf labels (openedOrEmpty (contextSelection context))
        (fun _ => canonicalLeafHeader salt) fullSuffix tapes =
      publicOpenedOracle continuation.oldLeaf labels points selected salt context tapes := by
  have supportEquality : sourcePatchSupport (openedOrEmpty (contextSelection context))
      (fun _ => canonicalLeafHeader salt) fullSuffix tapes =
    sourcePatchSupport (openedOrEmpty (contextSelection context))
      (fun _ => canonicalLeafHeader salt) (publicSuffix points selected context) tapes := by
    apply Finset.image_congr
    intro index member
    dsimp only
    rw [suffixMatches index member]
  funext input
  simp only [sourceOverlay, supportEquality, public_suffix_support_is_exact, publicOpenedOracle]

/-- A physical full-table-to-public-reference bound. Its only table-binding
premise is equality of the revealed raw suffixes, not a distance or game law.
The current-program polynomial/serialization adapter must discharge that equality.
-/
theorem completed_table_to_public_reference_bound
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (salt : SaltBytes) (labels : LeafIndex → Output) (context : EagerContext points)
    (continuation : PublicContinuation (Other := Other) (Output := Output) (Workspace := Workspace))
    (fullSuffix : LeafIndex → LeafSuffix)
    (suffixMatches : ∀ index ∈ openedOrEmpty (contextSelection context),
      fullSuffix index = publicSuffix points selected context index)
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) :
    |fullProgrammedAcceptance (openedOrEmpty (contextSelection context)) visible
        (completedAtomicReference points selected salt labels context continuation fullSuffix) -
      referenceAcceptance (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
        (publicAtomicReference points selected salt labels context continuation))| ≤
      hiddenPatchLoss continuation.queries := by
  have acceptanceEquality :
      referenceAcceptance (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
        (completedAtomicReference points selected salt labels context continuation fullSuffix)) =
      referenceAcceptance (keepOpenedPrograms (openedOrEmpty (contextSelection context)) visible
        (publicAtomicReference points selected salt labels context continuation)) := by
    simp only [referenceAcceptance, keepOpenedPrograms, completedAtomicReference, publicAtomicReference]
    rw [completed_opened_oracle_eq_public points selected salt labels context continuation fullSuffix suffixMatches,
      public_suffix_overlay_is_exact]
  rw [← acceptanceEquality, full_programmed_acceptance_eq_added_hidden_overlay]
  exact conditional_source_patch_bound _ _

end PhysicalPublicReference

/-- The source callbacks are fixed here; the observation can retain the full raw
opened oracle, prior entries, salt, labels, and any subsequent computation. -/
theorem source_eager_oracle_context_law {Result : Type*}
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (witnessValues : WitnessPackingValues Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (choose : IndexChooser points) (observe : EagerContext points → TapeTable → PMF Result) :
    ((uniformFintypePMF (SourceRemainingCoins Goldilocks)).bind fun coins =>
      (uniformFintypePMF TapeTable).bind fun tapes =>
        observe (partialContext parameters points selected gamma response transcript choose
          (sourceRemainingPartialChronologicalView witnessValues points
            (sourcePcsBaseForTranscript parameters witnessValues points transcript)
            (sourceCommittedHeadsForTranscript parameters witnessValues transcript)
            (valueChooser choose) coins)) tapes) =
    ((uniformFintypePMF (SourceRemainingView Goldilocks)).bind fun view =>
      (uniformFintypePMF TapeTable).bind fun tapes =>
        observe (eagerContext parameters points selected gamma response transcript choose view) tapes) := by
  have transported := source_partial_context_fresh_tape_transport
    (Index := LeafIndex) (Tape := LeafTape) witnessValues points witnessAdmissible pointsNonzero
    (sourcePcsBaseForTranscript parameters witnessValues points transcript)
    (sourceCommittedHeadsForTranscript parameters witnessValues transcript) fallback
    (valueChooser choose) (partialContext parameters points selected gamma response transcript choose) observe
  simpa only [partial_context_abort_projection] using transported

end

end HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
