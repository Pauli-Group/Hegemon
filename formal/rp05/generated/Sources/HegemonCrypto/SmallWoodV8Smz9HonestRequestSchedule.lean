import HegemonCrypto.SmallWoodV8Smz9HonestFinalGame
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-! Executed non-leaf honest phases and source-order Merkle compilation.
This supplies the exact write-deferral step needed before drawing the final
PIOP input. The finite grammar contains ordinary reads and computed branches,
not free oracle-dependent advice. Its error results continue through the same
continuation as successful results; neither return form erases an overlay.

The literal parent-node constructor and level-by-level Merkle schedule are
included below. Full Rust refinement, field-XOF/source-evaluation compilation
and the final repeated-request endpoint are not claimed by this module. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9HonestFinalGame V8Smz9HonestWholeViewFinalInput
open V8Smz9RawCounterCompiler V8Smz9RuntimeDistribution V8Smz9HonestHybrid V8Smz9EagerOracleGame
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 10000

inductive NonleafProgram (Other Result : Type) : Type 1 where
  | done (result : Result)
  | read (input : Other) (next : DigestRegister → NonleafProgram Other Result)

namespace NonleafProgram

variable {Other Result Next : Type}

def bind : NonleafProgram Other Result → (Result → NonleafProgram Other Next) →
    NonleafProgram Other Next
  | .done result, next => next result
  | .read input rest, next => .read input (fun output => bind (rest output) next)

def interpret (oracle : Other → DigestRegister) : NonleafProgram Other Result → Result
  | .done result => result
  | .read input next => interpret oracle (next (oracle input))

def readCount : NonleafProgram Other Result → Nat
  | .done _ => 0
  | .read _ next => (Finset.univ.sup fun output => readCount (next output)) + 1

theorem interpret_bind (oracle : Other → DigestRegister) (program : NonleafProgram Other Result)
    (next : Result → NonleafProgram Other Next) :
    interpret oracle (bind program next) = interpret oracle (next (interpret oracle program)) := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

variable {Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

def compile : NonleafProgram Other Result →
    (Result → Program (LeafInput ⊕ Other) Work) → Program (LeafInput ⊕ Other) Work
  | .done result, next => next result
  | .read input rest, next => .honestRead (Sum.inr input) (fun output => compile (rest output) next)

theorem compiled_execution (randomized : Bool) (program : NonleafProgram Other Result)
    (next : Result → Program (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run randomized (compile program next) oracle state =
      run randomized (next (interpret (fun input => oracle (Sum.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

omit [DecidableEq Other] in
theorem compile_preserves_mass (cap : ℝ≥0∞) (program : NonleafProgram Other Result)
    (next : Result → Program (LeafInput ⊕ Other) Work)
    (remaining : ∀ result, InputMassAtMost cap (next result)) :
    InputMassAtMost cap (compile program next) := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact ih

/-- The current overlay may be moved after the entire non-leaf phase without
changing any branch or state. The persistent overlay remains in the actual
continuation on both success and error results. -/
theorem source_leaf_writes_can_be_deferred (randomized : Bool)
    (program : NonleafProgram Other Result) (next : Result → Program (LeafInput ⊕ Other) Work)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (labels : LeafIndex → DigestRegister) (programmed : Finset LeafIndex)
    (headers : LeafIndex → LeafHeader) (payloads : LeafIndex → LeafSuffix)
    (tapes : LeafIndex → LeafTape)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run randomized (compile program next)
      (fullSourceOverlay oldLeaf other labels programmed headers payloads tapes) state =
    run randomized (next (interpret other program))
      (fullSourceOverlay oldLeaf other labels programmed headers payloads tapes) state := by
  rw [compiled_execution]
  rfl

end NonleafProgram

def sourceNodeInput (left right : DigestRegister) : V8Smz9RawCounterCompiler.RawInput :=
  V8Smz9CoherentMerkleGeometry.framedInput SmallWoodTranscript.merkleNodeDomain 16
    (List.ofFn (V8Smz9CoherentMerkleInstrument.rawDigestBits.symm left) ++
      List.ofFn (V8Smz9CoherentMerkleInstrument.rawDigestBits.symm right))

theorem source_node_input_length (left right : DigestRegister) :
    (sourceNodeInput left right).length = 249 := by
  have profile : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  have role : SmallWoodTranscript.merkleNodeDomain.length = 36 := by decide
  simp only [sourceNodeInput, V8Smz9CoherentMerkleGeometry.framedInput,
    List.length_append, List.length_ofFn, encodeLE_length, profile, role]

def sourceNodeKey (bound : Nat) (largeEnough : 249 ≤ bound) (left right : DigestRegister) :
    OtherRawInput bound := otherRawKey bound (sourceNodeInput left right)
      (by rw [source_node_input_length]; exact largeEnough)
      (by rw [source_node_input_length]; decide)

theorem source_node_key_is_literal_input (bound : Nat) (largeEnough : 249 ≤ bound)
    (left right : DigestRegister) :
    rawBytes (Sum.inr (sourceNodeKey bound largeEnough left right)) = sourceNodeInput left right :=
  other_raw_key_is_literal_input _ _ _ _

/-- Source parent sequence: one raw read per pair, left/right order retained.
The source has a power-of-two leaf count, so its unary-node case is absent. -/
def sourceParentLevel (bound : Nat) (largeEnough : 249 ≤ bound) :
    (count : Nat) → (Fin (2 * count) → DigestRegister) →
      NonleafProgram (OtherRawInput bound) (Fin count → DigestRegister)
  | 0, _ => .done Fin.elim0
  | count + 1, labels =>
      .read (sourceNodeKey bound largeEnough (labels ⟨0, by omega⟩) (labels ⟨1, by omega⟩)) fun parent =>
        NonleafProgram.bind
          (sourceParentLevel bound largeEnough count (fun i => labels ⟨i.val + 2, by omega⟩))
          (fun parents => .done (Fin.cons parent parents))

def sourceMerkleLevels (bound : Nat) (largeEnough : 249 ≤ bound) :
    (depth : Nat) → (Fin (2 ^ depth) → DigestRegister) →
      NonleafProgram (OtherRawInput bound) (DigestRegister × List (List DigestRegister))
  | 0, labels => .done (labels ⟨0, by norm_num⟩, [List.ofFn labels])
  | depth + 1, labels =>
      NonleafProgram.bind
        (sourceParentLevel bound largeEnough (2 ^ depth)
          (fun i => labels ⟨i.val, by simpa only [pow_succ, Nat.mul_comm] using i.isLt⟩))
        (fun parents => NonleafProgram.bind (sourceMerkleLevels bound largeEnough depth parents)
          (fun result => .done (result.1, List.ofFn labels :: result.2)))

/-- All 23 actual Merkle levels are a finite sequence of ordinary non-leaf
reads. The returned list retains every source layer for opening paths. -/
def allSourceMerkleLevels (bound : Nat) (largeEnough : 249 ≤ bound)
    (labels : LeafIndex → DigestRegister) :
    NonleafProgram (OtherRawInput bound) (DigestRegister × List (List DigestRegister)) :=
  sourceMerkleLevels bound largeEnough 23 labels

def sourceDigest (digest : DigestRegister) : V8Smz9WholeViewObservation.Sha512Digest :=
  ⟨List.ofFn (V8Smz9CoherentMerkleInstrument.rawDigestBits.symm digest), by simp⟩

def sourceDigestWords (digest : DigestRegister) : List Nat := (sourceDigest digest).rawWords

theorem source_digest_word_count (digest : DigestRegister) : (sourceDigestWords digest).length = 8 := by
  simp only [sourceDigestWords, V8Smz9WholeViewObservation.Sha512Digest.rawWords,
    List.length_map, List.length_range]

theorem source_decode_le_range (bytes : List CanonicalBytes.Byte) :
    decodeLE bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => simp [decodeLE]
  | cons byte bytes ih =>
      have digit := byte.isLt
      simp only [decodeLE, List.length_cons, pow_succ]
      omega

theorem source_digest_word_is_u64 (digest : DigestRegister) (word : Nat)
    (member : word ∈ sourceDigestWords digest) : word < 2 ^ 64 := by
  obtain ⟨index, _, rfl⟩ := List.mem_map.mp member
  have bound := source_decode_le_range (((sourceDigest digest).val.drop (index * 8)).take 8)
  have lengthBound : (((sourceDigest digest).val.drop (index * 8)).take 8).length ≤ 8 :=
    List.length_take_le _ _
  have power := pow_le_pow_right' (by norm_num : (1 : Nat) ≤ 256) lengthBound
  exact bound.trans_le (by norm_num at power ⊢; exact power)

def sourceDigestPrefix (digest : DigestRegister) : Prefix := fun index =>
  ⟨(sourceDigestWords digest).get ⟨index.val, by rw [source_digest_word_count]; exact index.isLt⟩,
    source_digest_word_is_u64 digest _ (List.get_mem _ _)⟩

theorem source_digest_prefix_words (digest : DigestRegister) :
    (List.ofFn (sourceDigestPrefix digest)).map Fin.val = sourceDigestWords digest := by
  apply List.ext_getElem
  · simp only [List.length_map, List.length_ofFn, source_digest_word_count]
  · intro index leftBound rightBound
    simp only [List.getElem_map, List.getElem_ofFn, sourceDigestPrefix, List.get_eq_getElem]

theorem source_final_from_digest_is_actual_key (bound : Nat) (largeEnough : 25029 ≤ bound)
    (digest : DigestRegister) (transcript : V8Smz9EagerPrivacy.PiopCoefficients Goldilocks) :
    rawBytes (sourceFinalKey bound largeEnough (sourceDigestPrefix digest) transcript) =
      counterInput (sourcePrefix SmallWoodTranscript.piopTranscriptDomain
        (sourceDigestWords digest ++
          ((List.ofFn fun index : Fin 3105 =>
            fieldWord (alternatingCoefficientEquiv.symm transcript index)).map Fin.val))) ⟨0, by norm_num⟩ := by
  rw [source_final_key_is_literal_raw_input]
  simp only [sourceFinalRawInput, sourceFinalWords, List.map_append, source_digest_prefix_words]

theorem source_counter_raw_length (role : List CanonicalBytes.Byte) (words : List Nat)
    (counter : Fin (2 ^ 64)) :
    (counterInput (sourcePrefix role words) counter).length = 85 + role.length + 8 * words.length := by
  have payload : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    induction words with
    | nil => rfl
    | cons word words ih =>
        simp only [List.map_cons, List.flatten_cons, List.length_append, encodeLE_length,
          List.length_cons, ih]
        omega
  have profile : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  simp only [counterInput, sourcePrefix, List.length_append, encodeLE_length, profile, payload]
  omega

def sourceCounterKey (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ 1407) (counter : Fin (2 ^ 64)) :
    OtherRawInput bound := otherRawKey bound (counterInput (sourcePrefix role words) counter)
      (by rw [source_counter_raw_length]; exact bounded)
      (by rw [source_counter_raw_length]; exact notLeaf)

theorem source_counter_key_is_literal_input (bound : Nat)
    (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ 1407) (counter : Fin (2 ^ 64)) :
    rawBytes (Sum.inr (sourceCounterKey bound role words bounded notLeaf counter)) =
      counterInput (sourcePrefix role words) counter := other_raw_key_is_literal_input _ _ _ _

/-- Literal early-stopping source field parser. The counter key list is
consumed only while more canonical field words are required. A rejection-cap
failure returns none without erasing any earlier oracle interaction. -/
def sourceFieldReadLoop {Other : Type} (requested : Nat)
    (accepted : List V8Smz9WholeViewObservation.FieldWord) : List Other →
    NonleafProgram Other (Option (List V8Smz9WholeViewObservation.FieldWord))
  | [] => if requested ≤ accepted.length then .done (some (accepted.take requested)) else .done none
  | input :: rest => if requested ≤ accepted.length then .done (some (accepted.take requested)) else
      .read input fun digest =>
        sourceFieldReadLoop requested (accepted ++ acceptedFieldWords (sourceDigestWords digest)) rest

theorem source_field_read_loop_count {Other : Type} (requested : Nat)
    (accepted : List V8Smz9WholeViewObservation.FieldWord) (inputs : List Other) :
    NonleafProgram.readCount (sourceFieldReadLoop requested accepted inputs) ≤ inputs.length := by
  induction inputs generalizing accepted with
  | nil => simp only [sourceFieldReadLoop]; split <;> simp [NonleafProgram.readCount]
  | cons input rest ih =>
      simp only [sourceFieldReadLoop]
      split
      · simp [NonleafProgram.readCount]
      · change (Finset.univ.sup fun digest => NonleafProgram.readCount
          (sourceFieldReadLoop requested
            (accepted ++ acceptedFieldWords (sourceDigestWords digest)) rest)) + 1 ≤ rest.length + 1
        apply Nat.add_le_add_right
        exact Finset.sup_le fun digest _ => ih _

def sourceFieldXof (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ 1407)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram (OtherRawInput bound) (Option (List V8Smz9WholeViewObservation.FieldWord)) :=
  sourceFieldReadLoop requested [] (List.ofFn fun index : Fin (digestCallCap requested) =>
    sourceCounterKey bound role words bounded notLeaf ⟨index.val, by
      have cap : digestCallCap requested ≤ 2 ^ 21 + 4 := by
        unfold digestCallCap
        split <;> omega
      exact lt_of_lt_of_le index.isLt (le_trans cap (by norm_num))⟩)

theorem source_field_xof_query_bound (bound : Nat) (role : List CanonicalBytes.Byte) (words : List Nat)
    (bounded : 85 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 85 + role.length + 8 * words.length ≠ 1407)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram.readCount (sourceFieldXof bound role words bounded notLeaf requested countBound) ≤
      digestCallCap requested := by
  exact (source_field_read_loop_count requested [] _).trans (by simp)

def sourceSaltWords (salt : SaltBytes) : List Nat :=
  List.ofFn fun word : Fin 4 => decodeLE (List.ofFn fun byte : Fin 8 =>
    salt ⟨8 * word.val + byte.val, by omega⟩)

def sourceResponseWords (response : DecsFullCoefficients Goldilocks) : List Nat :=
  (List.ofFn fun repetition : Fin 5 => List.ofFn fun coefficient : Fin 388 =>
    fromGoldilocks (response repetition coefficient)).flatten

theorem source_response_word_count (response : DecsFullCoefficients Goldilocks) :
    (sourceResponseWords response).length = 1940 := by
  simp only [sourceResponseWords, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_ofFn, List.sum_ofFn, Finset.sum_const, Finset.card_univ, Fintype.card_fin,
    smul_eq_mul]

structure PrefinalResult where
  tree : List (List DigestRegister)
  hashMt : DigestRegister
  decsGamma : Option (List V8Smz9WholeViewObservation.FieldWord)
  hashFpp : DigestRegister
  piopGamma : Option (List V8Smz9WholeViewObservation.FieldWord)

/-- The real source's pre-final read order after the joint-coordinate
transport. D is the public uniform 5x388 response coordinate. This schedule
has no witness, old Q/M mask, transcript T or desired h_piop argument. Both
field-XOF failure flags are retained for the later source error check. -/
def sourcePrefinal (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605) :
    NonleafProgram (OtherRawInput bound) PrefinalResult :=
  let rootWords := fun root => sourceSaltWords salt ++ sourceDigestWords root ++ statementBinding
  let rootKey := fun root => sourceCounterKey bound SmallWoodTranscript.merkleRootDomain (rootWords root)
    (by simp only [rootWords, sourceSaltWords, List.length_append, List.length_ofFn,
      source_digest_word_count]; have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
        rw [role]; omega)
    (by simp only [rootWords, sourceSaltWords, List.length_append, List.length_ofFn,
      source_digest_word_count]; have role : SmallWoodTranscript.merkleRootDomain.length = 36 := by decide
        rw [role]; omega) ⟨0, by norm_num⟩
  NonleafProgram.bind (allSourceMerkleLevels bound (by omega) labels) fun built =>
    .read (rootKey built.1) fun firstHashMt =>
      NonleafProgram.bind
        (sourceFieldXof bound SmallWoodTranscript.decsCoefficientDomain (sourceDigestWords firstHashMt)
          (by rw [source_digest_word_count]; have role : SmallWoodTranscript.decsCoefficientDomain.length = 41 := by decide
              rw [role]; omega)
          (by rw [source_digest_word_count]; decide) 700 (by norm_num)) fun decsGamma =>
        .read (rootKey built.1) fun hashMt =>
          let piopInputWords := sourceDigestWords hashMt ++ sourceResponseWords response ++ statementBinding
          let inputKey := sourceCounterKey bound SmallWoodTranscript.piopInputDomain piopInputWords
            (by simp only [piopInputWords, List.length_append, source_digest_word_count,
              source_response_word_count]; have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]; omega)
            (by simp only [piopInputWords, List.length_append, source_digest_word_count,
              source_response_word_count]; have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
                rw [role]; omega) ⟨0, by norm_num⟩
          .read inputKey fun hashFpp =>
            NonleafProgram.bind
              (sourceFieldXof bound SmallWoodTranscript.piopCoefficientDomain (sourceDigestWords hashFpp)
                (by rw [source_digest_word_count]; have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
                    rw [role]; omega)
                (by rw [source_digest_word_count]; decide)
                (sourceGammaWordRequest retainedLinearRows)
                (by unfold sourceGammaWordRequest; omega)) fun piopGamma =>
              .done ⟨built.2, hashMt, decsGamma, hashFpp, piopGamma⟩

variable {Work : Type} [Fintype Work]

/-- Computed public non-leaf history followed by the actual input-first
final reprogramming event. The whole later request sequence is `next`. -/
def sourcePrefinalThenFinal (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605)
    (next : PrefinalResult → V8Smz9EagerPrivacy.PiopCoefficients Goldilocks → DigestRegister →
      Program (FullRawInput bound) Work) : Program (FullRawInput bound) Work :=
  NonleafProgram.compile
    (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response retainedLinearRows rowBound)
    (fun stageResult => sourceFinal bound largeEnough (sourceDigestPrefix stageResult.hashFpp) (next stageResult))

attribute [local irreducible] InputMassAtMost

theorem actual_prefinal_final_program_mass (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605)
    (next : PrefinalResult → V8Smz9EagerPrivacy.PiopCoefficients Goldilocks → DigestRegister →
      Program (FullRawInput bound) Work)
    (remaining : ∀ stageResult transcript output,
      InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ (next stageResult transcript output)) :
    InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹
      (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits salt labels response
        retainedLinearRows rowBound next) :=
  NonleafProgram.compile_preserves_mass ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹
    (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response
      retainedLinearRows rowBound)
    (fun stageResult => sourceFinal bound largeEnough (sourceDigestPrefix stageResult.hashFpp) (next stageResult))
    (fun stageResult => source_final_preserves_mass_bound bound largeEnough
      (sourceDigestPrefix stageResult.hashFpp) (next stageResult) (remaining stageResult))

theorem actual_prefinal_final_executes_computed_history (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605)
    (next : PrefinalResult → V8Smz9EagerPrivacy.PiopCoefficients Goldilocks → DigestRegister →
      Program (FullRawInput bound) Work)
    (randomized : Bool) (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run randomized (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits salt labels response
      retainedLinearRows rowBound next) oracle state =
      let stageResult := NonleafProgram.interpret (fun input => oracle (Sum.inr input))
        (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response
          retainedLinearRows rowBound)
      run randomized (sourceFinal bound largeEnough (sourceDigestPrefix stageResult.hashFpp)
        (next stageResult)) oracle state :=
  NonleafProgram.compiled_execution randomized
    (sourcePrefinal bound largeEnough statementBinding bindingFits salt labels response
      retainedLinearRows rowBound)
    (fun stageResult => sourceFinal bound largeEnough (sourceDigestPrefix stageResult.hashFpp) (next stageResult))
    oracle state

/-- A direct quantitative theorem for the computed source pre-final/final
program, with no per-SMZ9 distance supplied as a premise. Future requests are
covered by the continuation's syntactic mass/query/programming conditions. -/
theorem actual_prefinal_final_reprogramming_bound (bound : Nat) (largeEnough : 25029 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) (labels : LeafIndex → DigestRegister)
    (response : DecsFullCoefficients Goldilocks) (retainedLinearRows : Nat)
    (rowBound : retainedLinearRows ≤ 20605)
    (next : PrefinalResult → V8Smz9EagerPrivacy.PiopCoefficients Goldilocks → DigestRegister →
      Program (FullRawInput bound) Work)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (queries attempts : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : queryCount (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits
      salt labels response retainedLinearRows rowBound next) ≤ queries)
    (attemptBound : programmingCount (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits
      salt labels response retainedLinearRows rowBound next) ≤ attempts)
    (remaining : ∀ stageResult transcript output,
      InputMassAtMost ((goldilocksModulus : ℝ≥0∞) ^ 3105)⁻¹ (next stageResult transcript output)) :
    |acceptance true (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits
      salt labels response retainedLinearRows rowBound next) initial -
      acceptance false (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits
        salt labels response retainedLinearRows rowBound next) initial| ≤
      (attempts : ℝ) * (Real.sqrt ((queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹) +
        (queries : ℝ) * ((goldilocksModulus : ℝ) ^ 3105)⁻¹ / 2) :=
  measured_adaptive_final_game_bound bound ghhm
    (sourcePrefinalThenFinal bound largeEnough statementBinding bindingFits salt labels response
      retainedLinearRows rowBound next) initial queries attempts normalized queryBound attemptBound
    (actual_prefinal_final_program_mass bound largeEnough statementBinding bindingFits salt labels response
      retainedLinearRows rowBound next remaining)

end
end HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
