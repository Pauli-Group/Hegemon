import SmzaRp05CurrentRawFieldScan
import SmzaRp05CurrentFieldCounterParser
import SmzaRp05CurrentRawSampleReadback
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentDecsMatrixSampling

/-! # Current DECS coefficient matrix: executed bytes to raw-role output

This bridge uses the same oracle and the literal current DECS coefficient
counter keys as the post-Merkle execution. It identifies the raw-role matrix
sample with the field words retained by that execution; it does not assume a
matrix output or a successful sampler. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedMatrixReadback

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutableChallengeStage (PostMerkle scan counterInput counterKeys)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentDecsMatrixSampling
  (currentRawDecsMatrixOutput currentActualDecsMatrixOutput currentDecsMatrixFieldEquiv)
open SmzaRp04RawRoleSampling (rawFieldSample selectedRawBlocks totalEquivDecoder)
open V8Smz9CappedRawSampler
  (RawByteBlock FieldOutput sourceFieldSize exact_literal_byte_counter_parser)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9RawCounterCompiler
  (acceptedFieldWords parseCounterVector counterVectorCandidates digestCallCap)
open V8Smz9HonestRequestSchedule (NonleafProgram sourceFieldReadLoop sourceDigestWords sourceDigest)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
noncomputable section

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

def currentDecsMatrixRawBlocks (oracle : Oracle) (root : RawDigest) :
    Fin (digestCallCap 700) → RawByteBlock :=
  fun counter => oracle (counterInput decsCoefficientDomain root counter.val)

def currentDecsMatrixVector (oracle : Oracle) (root : RawDigest) :
    VectorOutput (Fin (digestCallCap 700)) :=
  fun counter => rawDigestBits
    (oracle (counterInput decsCoefficientDomain root counter.val))

private theorem current_decs_scan_eq_raw_sample (oracle : Oracle) (root : RawDigest) :
    scan oracle 700 []
      (counterKeys decsCoefficientDomain 700 root) =
      (rawFieldSample (digestCallCap 700) 700
        (currentDecsMatrixRawBlocks oracle root)).map List.ofFn := by
  let keys : Fin (digestCallCap 700) → RawInput :=
    fun counter => counterInput decsCoefficientDomain root counter.val
  have inputs : counterKeys decsCoefficientDomain 700 root = List.ofFn keys := by
    change (List.range (digestCallCap 700)).map (counterInput decsCoefficientDomain root) = _
    exact (ofFn_fin_val_eq_range_map (n := digestCallCap 700)
      (f := counterInput decsCoefficientDomain root)).symm
  rw [inputs]
  exact HegemonCrypto.SmallWood.SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample
    700 keys oracle

private def fieldWordsAsOutput (words : List SmzaRp05ExecutableChallengeStage.FieldWord) :
    FieldOutput sourceFieldSize (140 * 5) :=
  fun index => words.getD index.val SmzaRp05ExecutableChallengeStage.zeroWord

private theorem list_ofFn_getD {α : Type*} {n : Nat} (values : Fin n → α)
    (index : Fin n) (fallback : α) :
    (List.ofFn values).getD index.val fallback = values index := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    index.isLt, dif_pos, Option.getD_some]

private theorem raw_sample_is_post_sample
    (oracle : Oracle) (root : RawDigest) (sampled : Option (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (sampleEq : sampled = scan oracle 700 []
      (counterKeys decsCoefficientDomain 700 root)) :
    rawFieldSample (digestCallCap 700) 700
      (currentDecsMatrixRawBlocks oracle root) = sampled.map fieldWordsAsOutput := by
  have sampleMap : sampled =
      (rawFieldSample (digestCallCap 700) 700
        (currentDecsMatrixRawBlocks oracle root)).map List.ofFn :=
    sampleEq.trans (current_decs_scan_eq_raw_sample oracle root)
  have inverse : ∀ fields : FieldOutput sourceFieldSize 700,
      fieldWordsAsOutput (List.ofFn fields) = fields := by
    intro fields
    funext index
    exact list_ofFn_getD fields index SmzaRp05ExecutableChallengeStage.zeroWord
  have recoverMap :
      Option.map (fun fields : FieldOutput sourceFieldSize 700 =>
        fieldWordsAsOutput (List.ofFn fields))
        (rawFieldSample (digestCallCap 700) 700
          (currentDecsMatrixRawBlocks oracle root)) =
      rawFieldSample (digestCallCap 700) 700
        (currentDecsMatrixRawBlocks oracle root) := by
    cases rawSample : rawFieldSample (digestCallCap 700) 700
        (currentDecsMatrixRawBlocks oracle root) with
    | none => rfl
    | some fields => exact congrArg some (inverse fields)
  have lifted := congrArg (Option.map fieldWordsAsOutput) sampleMap
  have mapComp :
      Option.map fieldWordsAsOutput
          (Option.map List.ofFn
            (rawFieldSample (digestCallCap 700) 700
              (currentDecsMatrixRawBlocks oracle root))) =
        Option.map (fun fields : FieldOutput sourceFieldSize 700 =>
          fieldWordsAsOutput (List.ofFn fields))
          (rawFieldSample (digestCallCap 700) 700
            (currentDecsMatrixRawBlocks oracle root)) := by
    cases rawSample : rawFieldSample (digestCallCap 700) 700
        (currentDecsMatrixRawBlocks oracle root) <;> rfl
  have collapsed := lifted.trans (mapComp.trans recoverMap)
  exact collapsed.symm

/-- The actual post-Merkle execution's successful DECS coefficient words
decode to exactly the raw-role DECS matrix output on the same literal
counter-input table and oracle. Sampler failure is retained on both sides. -/
theorem executed_post_merkle_decs_matrix_raw_output
    (ns : SmzaRp05LeafNamespace.Namespace) (oracle : Oracle)
    (input : SmzaRp05ExecutableMerkleVerifier.Input) (post : PostMerkle)
    (executed : (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).eval oracle = some post) :
    currentRawDecsMatrixOutput (currentDecsMatrixRawBlocks oracle post.root) =
      post.sampled.bind fun words =>
        totalEquivDecoder currentDecsMatrixFieldEquiv
          (fieldWordsAsOutput words) := by
  obtain ⟨_, sampledEq, _, _⟩ :=
    SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core ns oracle input post executed
  have sampleEq := raw_sample_is_post_sample oracle post.root post.sampled sampledEq
  unfold currentRawDecsMatrixOutput
  rw [sampleEq]
  cases post.sampled <;> rfl

/-- For identity coordinate selection, the role output above is also the
actual raw-role output of the vector computed from that same oracle. -/
theorem executed_post_merkle_actual_decs_matrix_raw_output
    (ns : SmzaRp05LeafNamespace.Namespace) (oracle : Oracle)
    (input : SmzaRp05ExecutableMerkleVerifier.Input) (post : PostMerkle)
    (executed : (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).eval oracle = some post) :
    currentActualDecsMatrixOutput (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (currentDecsMatrixVector oracle post.root) =
      post.sampled.bind fun words =>
        totalEquivDecoder currentDecsMatrixFieldEquiv
          (fieldWordsAsOutput words) := by
  calc
    currentActualDecsMatrixOutput (Equiv.refl (Fin (digestCallCap (140 * 5))))
        (currentDecsMatrixVector oracle post.root) =
        currentRawDecsMatrixOutput (currentDecsMatrixRawBlocks oracle post.root) := by
      change currentRawDecsMatrixOutput
        (selectedRawBlocks (Equiv.refl (Fin (digestCallCap (140 * 5))))
          (currentDecsMatrixVector oracle post.root)) =
        currentRawDecsMatrixOutput (currentDecsMatrixRawBlocks oracle post.root)
      apply congrArg currentRawDecsMatrixOutput
      funext counter
      change rawDigestBits.symm
          (rawDigestBits (oracle
            (counterInput decsCoefficientDomain post.root counter.val))) =
        oracle (counterInput decsCoefficientDomain post.root counter.val)
      exact rawDigestBits.symm_apply_apply _
    _ = _ := executed_post_merkle_decs_matrix_raw_output ns oracle input post executed

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedMatrixReadback
