import SmzaRp05ExecutableReconstructionRestoreBridge

/-!
# The computed final PIOP input is the typed transcript input

This is a byte-order bridge, not an additional verifier predicate. Digest
words are unrestricted u64 values; polynomial coefficients use their canonical
field representatives. Both sides use the current SMZA frame, not the old
SMZ9 profile. No equality of hash outputs or reconstruction success is assumed.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureCodec

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableFinalVerifier
open SmzaRp04RecordedTranscript SmzaRp04RawRecordedTranscript
open V8Smz9HonestWholeViewFinalInput V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9RuntimeFieldLayout V8Smz9EagerPrivacy
open SmzaRp05ExecutableReconstruction
open V8SmzaOracleParser (RawDigest)

local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "RawDigest" => V8SmzaOracleParser.RawDigest

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

-- Kept local so the byte-order check does not wait on role-parser uniqueness.
private theorem decode_le_injective_same_length (left right : List Byte)
    (length : left.length = right.length) (decoded : decodeLE left = decodeLE right) :
    left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp_all
  | cons head tail ih =>
      cases right with
      | nil => simp at length
      | cons other rest =>
          have heads : head.val = other.val := by
            simp only [decodeLE] at decoded
            have headBound := head.isLt
            have otherBound := other.isLt
            omega
          have tails : decodeLE tail = decodeLE rest := by
            simp only [decodeLE, heads] at decoded
            omega
          exact congrArg₂ List.cons (Fin.ext heads) (ih rest (by simpa using length) tails)

private theorem decode_le_lt (bytes : List Byte) : decodeLE bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => simp [decodeLE]
  | cons head tail ih =>
      simp only [decodeLE, List.length_cons, pow_succ]
      have bounded := head.isLt
      nlinarith

private theorem encode_decode_le (bytes : List Byte) :
    encodeLE bytes.length (decodeLE bytes) = bytes := by
  apply decode_le_injective_same_length
  · exact encodeLE_length _ _
  · rw [decodeLE_encodeLE, Nat.mod_eq_of_lt (decode_le_lt bytes)]

private theorem flattened_matrix {Item : Type} {rows columns : Nat}
    (values : Fin rows → Fin columns → Item) :
    List.ofFn ((matrixEquiv rows columns Item).symm values) =
      (List.ofFn fun row => List.ofFn (values row)).flatten := by
  rw [List.ofFn_mul]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext row
  apply congrArg List.ofFn
  funext column
  have index :
      (⟨row.val * columns + column.val, by
        calc
          row.val * columns + column.val < (row.val + 1) * columns := by
            exact (Nat.add_lt_add_left column.isLt _).trans_eq
              (by rw [Nat.add_mul, Nat.one_mul])
          _ ≤ rows * columns := Nat.mul_le_mul_right columns row.isLt⟩ : Fin (rows * columns)) =
        finProdFinEquiv (row, column) := by
    apply Fin.ext
    change row.val * columns + column.val = column.val + columns * row.val
    rw [Nat.add_comm, Nat.mul_comm columns row.val]
  rw [index, matrix_equiv_symm_apply]

private theorem flatMap_eq_flatten_map {Item Other : Type}
    (values : List Item) (f : Item → List Other) :
    values.flatMap f = (values.map f).flatten := by
  induction values with
  | nil => rfl
  | cons value values ih => simp [ih]

private theorem flatMap_ofFn {Item Other : Type} {count : Nat}
    (values : Fin count → Item) (f : Item → List Other) :
    (List.ofFn values).flatMap f = (List.ofFn fun i => f (values i)).flatten := by
  rw [flatMap_eq_flatten_map, List.map_ofFn]
  rfl

private theorem flatMap_flatten {Item Other : Type}
    (values : List (List Item)) (f : Item → List Other) :
    values.flatten.flatMap f = (values.map fun row => row.flatMap f).flatten := by
  induction values with
  | nil => rfl
  | cons value values ih => simp [List.flatMap_append, ih]

private theorem payload_flatMap (words : List RawWord) :
    typedWordPayload words = words.flatMap (fun word => encodeLE 8 word.val) := by
  induction words with
  | nil => rfl
  | cons word words ih => simp only [typedWordPayload, List.flatMap_cons, ih]

theorem digest_prefix_payload (digest : RawDigest) :
    typedWordPayload (List.ofFn (digestPrefix digest)) = List.ofFn digest := by
  rw [payload_flatMap, flatMap_ofFn]
  have blocks : (fun word : Fin 8 => encodeLE 8 (digestPrefix digest word).val) =
      (fun word : Fin 8 => List.ofFn fun byte : Fin 8 =>
        digest (finProdFinEquiv (word, byte))) := by
    funext word
    rw [digestPrefix, byte_block_word_has_exact_le_coordinates]
    simpa only [List.length_ofFn] using
      (encode_decode_le (List.ofFn fun byte : Fin 8 =>
        digest (finProdFinEquiv (word, byte))))
  rw [blocks]
  rw [← flattened_matrix]
  apply congrArg List.ofFn
  exact (matrixEquiv 8 8 Byte).symm_apply_apply digest

/-- The allocation equivalence cancels its internal low/high splits, leaving
the literal per-repetition nonlinear-then-linear coefficient order. -/
theorem alternating_coefficients_are_rows (coefficients : PiopCoefficients Goldilocks) :
    alternatingCoefficientEquiv.symm coefficients =
      (matrixEquiv 5 (489 + 132) Goldilocks).symm
        (fun row => Fin.append (coefficients.1 row) (coefficients.2 row)) := by
  apply alternatingCoefficientEquiv.injective
  rw [Equiv.apply_symm_apply]
  simp [alternatingCoefficientEquiv, alternatingMasksEquiv,
    sourceMaskCoefficientEquiv, splitEquiv, Equiv.piCongrRight_apply,
    Pi.map, Prod.map_apply]
  have splitAppend (row : Fin 5) :
      (Fin.appendEquiv 489 132).symm
        (Fin.append (coefficients.1 row) (coefficients.2 row)) =
          (coefficients.1 row, coefficients.2 row) :=
    (Fin.appendEquiv 489 132).symm_apply_apply (coefficients.1 row, coefficients.2 row)
  apply Prod.ext
  · funext row index
    change coefficients.1 row index =
      ((Fin.appendEquiv 6 483) ((Fin.appendEquiv 6 483).symm
        (((Fin.appendEquiv 489 132).symm
          (Fin.append (coefficients.1 row) (coefficients.2 row))).1))) index
    rw [Equiv.apply_symm_apply, splitAppend]
  · funext row index
    change coefficients.2 row index =
      ((Fin.appendEquiv 6 126) ((Fin.appendEquiv 6 126).symm
        (((Fin.appendEquiv 489 132).symm
          (Fin.append (coefficients.1 row) (coefficients.2 row))).2))) index
    rw [Equiv.apply_symm_apply, splitAppend]

theorem source_coefficient_words_are_rows (coefficients : PiopCoefficients Goldilocks) :
    List.ofFn (fun index : Fin 3105 =>
      fieldWord (alternatingCoefficientEquiv.symm coefficients index)) =
      (List.ofFn fun row : Fin 5 =>
        (List.ofFn fun index : Fin 489 => fieldWord (coefficients.1 row index)) ++
          (List.ofFn fun index : Fin 132 => fieldWord (coefficients.2 row index))).flatten := by
  change List.ofFn (fieldWord ∘ alternatingCoefficientEquiv.symm coefficients) = _
  rw [← List.map_ofFn, alternating_coefficients_are_rows, flattened_matrix,
    List.map_flatten, List.map_ofFn]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext row
  change (List.ofFn (Fin.append (coefficients.1 row) (coefficients.2 row))).map fieldWord = _
  rw [List.ofFn_fin_append, List.map_append, List.map_ofFn, List.map_ofFn]
  rfl

def encodedTranscript (input : PiopInput) (pending : Bool) : ReconstructedTranscript where
  hashFpp := input.commitmentPrefix
  nonlinear row index := SmzaRp05ExecutableReconstruction.toWord (input.nonlinear row index)
  linearHigh row index := SmzaRp05ExecutableReconstruction.toWord (input.linearHigh row index)
  pendingXofFailure := pending

theorem encoded_final_input_eq_raw_input (input : PiopInput) (pending : Bool) :
    finalInput (encodedTranscript input pending) = rawInputOf input := by
  unfold finalInput rawInputOf rawPiopInput
  apply congrArg (V8SmzaOracleParser.framedInput SmallWoodTranscript.piopTranscriptDomain)
  unfold finalPayload sourceFinalWords canonicalCoefficients
  rw [payload_flatMap, List.flatMap_append]
  rw [← payload_flatMap, digest_prefix_payload]
  apply congrArg (List.ofFn input.commitmentPrefix ++ ·)
  rw [source_coefficient_words_are_rows, flatMap_flatten, List.map_ofFn]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext row
  simp only [coefficientBytes, encodedTranscript,
    flatMap_ofFn, fieldWord, SmzaRp05ExecutableReconstruction.toWord]
  rfl

/-- The source-connected reconstruction has precisely the mathematical
transcript already used by the scalar-check theorem, with the same prefix. -/
theorem reconstructed_final_input_eq_typed
    (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (matrix : V8Smz9PiopSoundness.Matrix (dsl.width statement))
    (opening : V8Smz9PiopSoundness.Opening) (proof : DecodedPiopFields)
    (hashFpp : RawDigest) (pending : Bool) :
    finalInput (reconstruct dsl statement matrix opening proof hashFpp pending) =
      rawInputOf (transcriptInput hashFpp
        (V8Smz9PiopReconstruction.reconstructedTranscript opening (proofHighs proof)
          (evaluation dsl statement matrix opening proof)
          (SmzaRp05RawScalarChecks.publicBatchedTarget dsl statement matrix))) := by
  have same : reconstruct dsl statement matrix opening proof hashFpp pending =
      encodedTranscript (transcriptInput hashFpp
        (V8Smz9PiopReconstruction.reconstructedTranscript opening (proofHighs proof)
          (evaluation dsl statement matrix opening proof)
          (SmzaRp05RawScalarChecks.publicBatchedTarget dsl statement matrix))) pending := by
    rfl
  rw [same, encoded_final_input_eq_raw_input]

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureCodec
