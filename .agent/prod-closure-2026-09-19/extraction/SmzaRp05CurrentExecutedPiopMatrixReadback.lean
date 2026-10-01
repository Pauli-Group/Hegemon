import SmzaRp05CurrentRawSampleReadback
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp04RawRoleSampling

/-! # Current executed PIOP matrix at the raw-role decoder boundary

This bridge identifies the PIOP matrix consumed by the same accepted PCS
execution with the raw-role output on the literal PIOP counter-input table
and that execution's oracle. It derives success from the final pending guard;
no matrix/readback or sampled-word certificate is supplied.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedPiopMatrixReadback

open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutableChallengeStage (FieldWord scan counterInput counterKeys zeroWord)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp04RawRoleSampling (actualPiopMatrixOutput rawPiopMatrixOutput
  rawFieldSample selectedRawBlocks totalEquivDecoder matrixFieldEquiv)
open V8Smz9CappedRawSampler (RawByteBlock FieldOutput sourceFieldSize)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9PiopSoundness (Matrix)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9RuntimeFieldLayout (matrixEquiv)
open V8Smz9RuntimeRandomness (idealFieldCoinEquivGoldilocks)

set_option autoImplicit false
noncomputable section

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

def currentPiopMatrixRawBlocks (oracle : Oracle) (digest : RawDigest) (width : Nat) :
    Fin (digestCallCap (5 * width)) → RawByteBlock :=
  fun counter => oracle (counterInput SmallWoodTranscript.piopCoefficientDomain
    digest counter.val)

def currentPiopMatrixVector (oracle : Oracle) (digest : RawDigest) (width : Nat) :
    VectorOutput (Fin (digestCallCap (5 * width))) :=
  fun counter => rawDigestBits
    (oracle (counterInput SmallWoodTranscript.piopCoefficientDomain digest counter.val))

private theorem current_piop_scan_eq_raw_sample (oracle : Oracle) (digest : RawDigest)
    (width : Nat) :
    scan oracle (5 * width) []
        (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest) =
      (rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width)).map List.ofFn := by
  let keys : Fin (digestCallCap (5 * width)) → RawInput :=
    fun counter => counterInput SmallWoodTranscript.piopCoefficientDomain digest counter.val
  have inputs :
      counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest =
        List.ofFn keys := by
    change (List.range (digestCallCap (5 * width))).map
      (counterInput SmallWoodTranscript.piopCoefficientDomain digest) = _
    exact (ofFn_fin_val_eq_range_map
      (n := digestCallCap (5 * width))
      (f := counterInput SmallWoodTranscript.piopCoefficientDomain digest)).symm
  rw [inputs]
  exact HegemonCrypto.SmallWood.SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample
    (5 * width) keys oracle

private def fieldWordsAsOutput (words : List FieldWord) (width : Nat) :
    FieldOutput sourceFieldSize (5 * width) :=
  fun index => words.getD index.val zeroWord

private theorem list_ofFn_getD {α : Type*} {n : Nat} (values : Fin n → α)
    (index : Fin n) (fallback : α) :
    (List.ofFn values).getD index.val fallback = values index := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    index.isLt, dif_pos, Option.getD_some]

private theorem raw_sample_is_scan_output (oracle : Oracle) (digest : RawDigest)
    (width : Nat) (sampled : Option (List FieldWord))
    (sampleEq : sampled = scan oracle (5 * width) []
      (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest)) :
    rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width) =
      sampled.map (fun words => fieldWordsAsOutput words width) := by
  have sampleMap : sampled =
      (rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width)).map List.ofFn :=
    sampleEq.trans (current_piop_scan_eq_raw_sample oracle digest width)
  have inverse : ∀ fields : FieldOutput sourceFieldSize (5 * width),
      fieldWordsAsOutput (List.ofFn fields) width = fields := by
    intro fields
    funext index
    exact list_ofFn_getD fields index zeroWord
  have recoverMap : Option.map (fun fields : FieldOutput sourceFieldSize (5 * width) =>
      fieldWordsAsOutput (List.ofFn fields) width)
      (rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width)) =
      rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width) := by
    cases rawSample : rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width) with
    | none => rfl
    | some fields => exact congrArg some (inverse fields)
  let asOutput : List FieldWord → FieldOutput sourceFieldSize (5 * width) :=
    fun words => fieldWordsAsOutput words width
  have lifted := congrArg (Option.map asOutput) sampleMap
  have mapComp :
      Option.map asOutput
          (Option.map (fun fields : FieldOutput sourceFieldSize (5 * width) => List.ofFn fields)
            (rawFieldSample (digestCallCap (5 * width)) (5 * width)
              (currentPiopMatrixRawBlocks oracle digest width))) =
        Option.map (fun fields : FieldOutput sourceFieldSize (5 * width) =>
          asOutput (List.ofFn fields))
          (rawFieldSample (digestCallCap (5 * width)) (5 * width)
            (currentPiopMatrixRawBlocks oracle digest width)) := by
    cases rawSample : rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width) <;> rfl
  have recoverMap' :
      Option.map (fun fields : FieldOutput sourceFieldSize (5 * width) =>
        asOutput (List.ofFn fields))
        (rawFieldSample (digestCallCap (5 * width)) (5 * width)
          (currentPiopMatrixRawBlocks oracle digest width)) =
      rawFieldSample (digestCallCap (5 * width)) (5 * width)
        (currentPiopMatrixRawBlocks oracle digest width) := by
    simpa [asOutput] using recoverMap
  have collapsed := lifted.trans (mapComp.trans recoverMap')
  simpa [asOutput] using collapsed.symm

private theorem fin_equiv_nat_cast (n : Nat) [NeZero n] (word : Fin n) :
    (ZMod.finEquiv n) word = (word.val : ZMod n) := by
  cases n with
  | zero => exact (NeZero.ne 0 rfl).elim
  | succ n =>
    apply ZMod.val_injective
    change word.val = ((word.val : ZMod (n + 1)).val)
    simp [ZMod.val_natCast, Nat.mod_eq_of_lt word.isLt]

private theorem ideal_field_coin_apply (word : FieldWord) :
    idealFieldCoinEquivGoldilocks word = word.val := by
  letI : NeZero V8Smz9RuntimeRandomness.fieldModulus := ⟨by decide⟩
  change (ZMod.finEquiv V8Smz9RuntimeRandomness.fieldModulus) word =
    (word.val : ZMod V8Smz9RuntimeRandomness.fieldModulus)
  exact fin_equiv_nat_cast V8Smz9RuntimeRandomness.fieldModulus word

private theorem field_words_decode_to_matrix (width : Nat) (words : List FieldWord) :
    matrixFieldEquiv width (fieldWordsAsOutput words width) =
      SmzaRp05PiopMatrixStage.matrixFromWords width words := by
  funext row column
  simp [matrixFieldEquiv, fieldWordsAsOutput, SmzaRp05PiopMatrixStage.matrixFromWords,
    matrixEquiv, idealFieldCoinEquivGoldilocks, V8Smz9RuntimeRandomness.fieldModulus]
  rw [Nat.mul_comm width row.val, Nat.add_comm]
  exact ideal_field_coin_apply (words.getD (row.val * width + column.val) zeroWord)

/-- The final accepted-transcript guard forces the same execution's PIOP
matrix to equal the actual raw-role output over its literal current key table
and oracle. -/
theorem execution_piop_matrix_is_actual_role_output
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List HegemonCrypto.CanonicalBytes.Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending binding statementBinding nonce
      wire oracle transcript)
    (clean : transcript.pendingXofFailure = false) :
    actualPiopMatrixOutput (Equiv.refl
      (Fin (digestCallCap (5 * dsl.width statement))))
        (currentPiopMatrixVector oracle stages.hashFpp (dsl.width statement)) =
      some stages.matrix := by
  obtain ⟨_, words, scanEq, matrixEq⟩ :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
      ns dsl statement pending binding statementBinding nonce wire oracle transcript stages clean
  have sampleEq := raw_sample_is_scan_output oracle stages.hashFpp
    (dsl.width statement) (some words) scanEq.symm
  have selectedEq : selectedRawBlocks
      (Equiv.refl (Fin (digestCallCap (5 * dsl.width statement))))
      (currentPiopMatrixVector oracle stages.hashFpp (dsl.width statement)) =
      currentPiopMatrixRawBlocks oracle stages.hashFpp (dsl.width statement) := by
    funext counter
    change rawDigestBits.symm
      (rawDigestBits (oracle (counterInput SmallWoodTranscript.piopCoefficientDomain
        stages.hashFpp counter.val))) = _
    exact rawDigestBits.symm_apply_apply _
  unfold actualPiopMatrixOutput rawPiopMatrixOutput
  rw [selectedEq, sampleEq]
  simp only [Option.map_some, Option.bind_some, totalEquivDecoder]
  rw [field_words_decode_to_matrix]
  exact congrArg some matrixEq.symm

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedPiopMatrixReadback
