import HegemonCrypto.SmallWoodV8Smz9DynamicPhysicalTransport
import HegemonCrypto.SmallWoodSmz9ProofWire

/-! Source post-final public byte constructor. All eight field matrices,
selected raw leaf tapes, compact paths, nonce, salt and raw SHA-512 digest are
serialized in the current SMZ9 order. The post-index XOF failure is computed
from public fields and retains the source's final scope failure.

This mathematical constructor does not itself assert Rust compiler refinement
or verifier acceptance. It makes the byte-valued public observation explicit.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PostFinalSerializer

open HegemonCrypto.CanonicalBytes HegemonCrypto.SmallWoodProofWire
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

def sourceMatrixWords {rows columns : Nat} (values : Fin rows → Fin columns → Goldilocks) : List Nat :=
  (List.ofFn fun row => List.ofFn fun column => fromGoldilocks (values row column)).flatten

def sourceMatrixWire {rows columns : Nat} (values : Fin rows → Fin columns → Goldilocks) : MatrixWire :=
  ⟨encodeLE 2 rows, encodeLE 2 columns, (sourceMatrixWords values).flatMap (encodeLE 8)⟩

theorem source_matrix_word_count {rows columns : Nat} (values : Fin rows → Fin columns → Goldilocks) :
    (sourceMatrixWords values).length = rows * columns := by
  simp only [sourceMatrixWords, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_ofFn, List.sum_ofFn, Finset.sum_const, Finset.card_univ, Fintype.card_fin,
    smul_eq_mul]

theorem source_matrix_byte_count {rows columns : Nat} (values : Fin rows → Fin columns → Goldilocks) :
    (sourceMatrixWire values).valueBytes.length = rows * columns * 8 := by
  simp only [sourceMatrixWire, List.length_flatMap, encodeLE_length, List.map_const',
    List.sum_replicate, source_matrix_word_count, smul_eq_mul]

theorem source_matrix_encoded_length {rows columns : Nat} (values : Fin rows → Fin columns → Goldilocks) :
    (sourceMatrixWire values).encode.length = 4 + rows * columns * 8 := by
  simp only [MatrixWire.encode, List.length_append]
  rw [source_matrix_byte_count]
  simp only [sourceMatrixWire, encodeLE_length]

def sourceSibling (index : Nat) : Nat := if index % 2 = 0 then index + 1 else index - 1

/-- This is the source loop over levels and then paths. Membership is tested
against ALL current opened positions, including their repeated ancestors. -/
def compactPathLevels : List (List DigestRegister) → (Fin 20 → Nat) → Fin 20 → List DigestRegister
  | [], _ => fun _ => []
  | level :: rest, indices =>
      let later := compactPathLevels rest (fun opening => indices opening / 2)
      fun opening =>
        let sibling := sourceSibling (indices opening)
        if sibling ∈ Finset.univ.image indices then later opening
        else level.getD sibling 0 :: later opening

theorem compact_path_length_le (levels : List (List DigestRegister)) (indices : Fin 20 → Nat)
    (opening : Fin 20) : (compactPathLevels levels indices opening).length ≤ levels.length := by
  induction levels generalizing indices with
  | nil => exact Nat.le_refl 0
  | cons level rest ih =>
      simp only [compactPathLevels]
      split
      · exact (ih _).trans (Nat.le_succ _)
      · simpa only [List.length_cons] using Nat.succ_le_succ (ih (fun i => indices i / 2))

def sourceCompactPaths (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex) :
    Fin 20 → List DigestRegister :=
  compactPathLevels (tree.take 23) (fun opening => (indices opening).val)

theorem source_compact_paths_match_source_levels (tree : List (List DigestRegister))
    (height : tree.length = 24) (indices : Fin 20 → LeafIndex) :
    sourceCompactPaths tree indices =
      compactPathLevels (tree.take (tree.length - 1)) (fun opening => (indices opening).val) := by
  simp only [sourceCompactPaths, height]

theorem source_compact_path_depth (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (opening : Fin 20) : (sourceCompactPaths tree indices opening).length ≤ 23 :=
  (compact_path_length_le (tree.take 23) _ opening).trans (List.length_take_le 23 tree)

def sourceAuthPathsWire (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex) : AuthPathsWire where
  rowCountBytes := encodeLE 2 20
  pathLengthBytes := List.ofFn fun opening =>
    ⟨(sourceCompactPaths tree indices opening).length,
      (source_compact_path_depth tree indices opening).trans_lt (by decide)⟩
  nodeBytes := (List.ofFn fun opening =>
    (sourceCompactPaths tree indices opening).flatMap fun digest => (sourceDigest digest).val).flatten

def selectedTapeBytes (tapes : Fin 20 → LeafTape) : List CanonicalBytes.Byte :=
  (List.ofFn fun opening => List.ofFn (tapes opening)).flatten

theorem selected_tape_byte_count (tapes : Fin 20 → LeafTape) :
    (selectedTapeBytes tapes).length = 1280 := by
  simp only [selectedTapeBytes, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_ofFn, List.sum_ofFn, Finset.sum_const, Finset.card_univ, Fintype.card_fin,
    smul_eq_mul]

/-- All dimensions use the source's TWO-byte u16 headers. Opened-witness
auxiliary counters are four-byte zeros; no auxiliary witness is serialized. -/
def sourceProofWire (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : Fin 20 → LeafTape) :
    SmallWoodSmz9ProofWire.ProofWire where
  saltBytes := List.ofFn salt
  nonceBytes := encodeLE 4 nonce.val
  piopHashBytes := (sourceDigest digest).val
  piop := ⟨sourceMatrixWire fields.nonlinearHighs, sourceMatrixWire fields.linearHighs⟩
  pcs := ⟨sourceMatrixWire fields.combinationTails, sourceMatrixWire fields.subsetEvaluations,
    sourceMatrixWire fields.partialEvaluations,
    ⟨sourceAuthPathsWire tree indices, selectedTapeBytes tapes,
      sourceMatrixWire fields.decsMaskEvaluations, sourceMatrixWire fields.decsHighs⟩⟩
  openedWitness := .rowScalars (sourceMatrixWire fields.rowScalars) (encodeLE 4 0) (encodeLE 4 0) []

def sourceProofBytes (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : Fin 20 → LeafTape) : List CanonicalBytes.Byte :=
  (sourceProofWire salt nonce digest tree indices fields tapes).encode

/-- Exact byte order of the current source serializer, including leaf tapes
between compact paths and the DECS field matrices. -/
theorem source_proof_bytes_order (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : Fin 20 → LeafTape) :
    sourceProofBytes salt nonce digest tree indices fields tapes =
      SmallWoodSmz9ProofWire.proofMagic ++ List.ofFn salt ++ encodeLE 4 nonce.val ++ (sourceDigest digest).val ++
      (sourceMatrixWire fields.nonlinearHighs).encode ++ (sourceMatrixWire fields.linearHighs).encode ++
      (sourceMatrixWire fields.combinationTails).encode ++ (sourceMatrixWire fields.subsetEvaluations).encode ++
      (sourceMatrixWire fields.partialEvaluations).encode ++ (sourceAuthPathsWire tree indices).encode ++
      selectedTapeBytes tapes ++ (sourceMatrixWire fields.decsMaskEvaluations).encode ++
      (sourceMatrixWire fields.decsHighs).encode ++ [1] ++ (sourceMatrixWire fields.rowScalars).encode ++
      encodeLE 4 0 ++ encodeLE 4 0 := by
  simp only [sourceProofBytes, sourceProofWire, SmallWoodSmz9ProofWire.ProofWire.encode,
    SmallWoodSmz9ProofWire.proofPayloadCodec, SmallWoodSmz9ProofWire.pcsCodec,
    SmallWoodSmz9ProofWire.decsCodec, SmallWoodSmz9ProofWire.openedWitnessSmz9Codec,
    SmallWoodSmz9ProofWire.authPathsCodec, piopCodec, matrixCodec, openedWitnessCodec,
    PrefixCodec.xmap, PrefixCodec.pair, PrefixCodec.fixed, PrefixCodec.refine,
    OpenedWitnessWire.encode, List.append_nil, List.append_assoc, id_eq]

theorem source_auth_node_bytes_length (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex) :
    (sourceAuthPathsWire tree indices).nodeBytes.length =
      ∑ opening : Fin 20, (sourceCompactPaths tree indices opening).length * 64 := by
  simp only [sourceAuthPathsWire, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_flatMap, sourceDigest, List.length_ofFn, List.map_const', List.sum_replicate,
    smul_eq_mul, List.sum_ofFn]

theorem source_auth_wire_length_bound (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex) :
    (sourceAuthPathsWire tree indices).encode.length ≤ 29462 := by
  have nodes : (∑ opening : Fin 20, (sourceCompactPaths tree indices opening).length * 64) ≤ 29440 := by
    calc
      _ ≤ ∑ _opening : Fin 20, 23 * 64 :=
        Finset.sum_le_sum fun opening _ => Nat.mul_le_mul_right 64 (source_compact_path_depth tree indices opening)
      _ = 29440 := by simp
  simp only [AuthPathsWire.encode, List.length_append]
  rw [source_auth_node_bytes_length]
  simp only [sourceAuthPathsWire, encodeLE_length, List.length_ofFn]
  omega

/-- Even the loose twenty-times-depth path bound fits the actual 128 KiB
encoder cap. The sharper 372-node verifier bound is a separate property. -/
theorem source_proof_bytes_length_bound (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : Fin 20 → LeafTape) :
    (sourceProofBytes salt nonce digest tree indices fields tapes).length ≤ 128495 := by
  have auth := source_auth_wire_length_bound tree indices
  rw [source_proof_bytes_order]
  simp only [List.length_append, SmallWoodSmz9ProofWire.proofMagic_length,
    List.length_ofFn, encodeLE_length, source_matrix_encoded_length, selected_tape_byte_count,
    List.length_singleton]
  have digestLength : (sourceDigest digest).val.length = 64 := (sourceDigest digest).property
  rw [digestLength]
  omega

theorem source_proof_bytes_fit_cap (salt : SaltBytes) (nonce : Fin 16) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (indices : Fin 20 → LeafIndex)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : Fin 20 → LeafTape) :
    (sourceProofBytes salt nonce digest tree indices fields tapes).length ≤ 131072 :=
  (source_proof_bytes_length_bound salt nonce digest tree indices fields tapes).trans (by decide)

/-- The serialized DECS hash/XOF stage can be re-evaluated from fields which
already occur in the public proof. It has no hidden coin or witness argument. -/
def sourceFieldsDecsSelection (bound : Nat) (largeEnough : 37434 ≤ bound)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (digest : DigestRegister) (fields : EagerAlgebraicFields Goldilocks) (pending : Bool) :
    NonleafProgram (OtherRawInput bound) (DecsSelectionResult points) :=
  sourceDecsSelection bound largeEnough points distinct digest
    (reconstructedCombinationHeads points (fieldWitness fields) (fieldMasks fields) (fieldPartials fields))
    fields.combinationTails pending

theorem current_fields_reproduce_source_decs_selection (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (view : SourceRemainingView Goldilocks) (digest : DigestRegister) (pending : Bool) :
    sourceFieldsDecsSelection bound largeEnough points distinct digest
      (currentEagerAlgebraicFields parameters points selected gamma response transcript targets view) pending =
    sourceCurrentDecsSelection bound largeEnough parameters points distinct transcript digest
      view.1 view.2.1 view.2.2.1 pending := by
  obtain ⟨witness, masks, partials⟩ := eager_field_decoders points selected gamma response transcript targets
    (currentPublicMaskOpenings parameters points transcript view.1) view
  unfold sourceFieldsDecsSelection currentEagerAlgebraicFields
  rw [witness, masks, partials]
  rfl

def tapesAtTargets {points : Fin 6 → Goldilocks} (targets : IndexedTargets points)
    (fields : EagerAlgebraicFields Goldilocks)
    (visible : OpenedTapes (Tape := LeafTape)
      (openedOrEmpty (contextSelection (some (targets, fields))))) : Fin 20 → LeafTape :=
  fun opening => visible ⟨targets.val opening, by exact Finset.mem_image.mpr ⟨opening, Finset.mem_univ _, rfl⟩⟩

theorem tapes_at_targets_are_source_tapes {points : Fin 6 → Goldilocks} (targets : IndexedTargets points)
    (fields : EagerAlgebraicFields Goldilocks) (tapes : TapeTable) :
    tapesAtTargets targets fields ((splitTapes (openedOrEmpty (contextSelection (some (targets, fields))))) tapes).1 =
      fun opening => tapes (targets.val opening) := rfl

/-- Public failure handling is explicit: genuine index exhaustion comes
before the final TLS error; completed proofs are serialized only after the
source field-XOF scope succeeds. The exact source wire size cap is retained. -/
def sourceContextBytes (bound : Nat) (largeEnough : 37434 ≤ bound)
    (salt : SaltBytes) (opening : ComputedOpening) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (oracle : OtherRawInput bound → DigestRegister)
    (context : EagerContext opening.points)
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection context))) : Except String (List CanonicalBytes.Byte) :=
  match context, visible with
  | none, _ => .error "fixed DECS sampler exhausted its candidate pool"
  | some (targets, fields), visible =>
      let pending := (NonleafProgram.interpret oracle
        (sourceFieldsDecsSelection bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest fields opening.pendingFailure)).pendingFailure
      match sourceScopeFinish pending
        (sourceProofBytes salt opening.nonce digest tree targets.val fields (tapesAtTargets targets fields visible)) with
      | .error message => .error message
      | .ok bytes => if bytes.length ≤ 131072 then .ok bytes
          else .error "smallwood SMZ8/SMZ9 inner proof exceeds the 131072-byte cap"

theorem source_context_index_exhaustion_precedes_tls (bound : Nat) (largeEnough : 37434 ≤ bound)
    (salt : SaltBytes) (opening : ComputedOpening) (digest : DigestRegister)
    (tree : List (List DigestRegister)) (oracle : OtherRawInput bound → DigestRegister)
    (visible : OpenedTapes (Tape := LeafTape) (openedOrEmpty (contextSelection (points := opening.points) none))) :
    sourceContextBytes bound largeEnough salt opening digest tree oracle none visible =
      .error "fixed DECS sampler exhausted its candidate pool" := rfl

end
end HegemonCrypto.SmallWood.V8Smz9PostFinalSerializer
