import HegemonCrypto.SmallWoodV8Smz9StableHashCsr
import HegemonCrypto.SmallWoodV8Smz9StableConfigHash

namespace HegemonCrypto.SmallWood.V8Smz9StableStateHash

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9StableHashCsr
open HegemonCrypto.SmallWood.V8Smz9StableConfigHash (call_digest_word)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation

def assetBit (publicWords : List Nat) (level : Nat) : Nat :=
  (publicWords.getD 84 0 / 2^level) % 2

theorem asset_bit_bound (publicWords : List Nat) (level : Nat) :
    assetBit publicWords level < 2 := Nat.mod_lt _ (by decide)

theorem stable_bit_field_value {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (canonical : CanonicalPublicWords publicWords) (level : Fin 4) :
    (values.getD (316+level.val) 0 : F) = (assetBit publicWords level.val : F) := by
  have asset := equations 88 (.publicWord 84) (by decide)
  have bit := equations (316+level.val) (.bit 88 level.val) (by fin_cases level <;> decide)
  simp only [expressionField] at asset bit
  rw [asset] at bit
  have representative : (publicWords.getD 84 0 : F).val = publicWords.getD 84 0 :=
    ZMod.val_natCast_of_lt (canonical_public_coordinate canonical (index := 84) (by decide)).2
  rw [representative] at bit
  exact bit

theorem stable_orientation_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (canonical : CanonicalPublicWords publicWords) (level : Fin 4) :
    (values.getD (348+3*level.val) 0 : F) = -(1-(assetBit publicWords level.val : F)) ∧
      (values.getD (349+3*level.val) 0 : F) = -(assetBit publicWords level.val : F) := by
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  have bit := stable_bit_field_value equations canonical level
  have positive := equations (347+3*level.val) (.sub 1 (316+level.val))
    (by fin_cases level <;> decide)
  have inverse := equations (348+3*level.val) (.sub 0 (347+3*level.val))
    (by fin_cases level <;> decide)
  have negative := equations (349+3*level.val) (.sub 0 (316+level.val))
    (by fin_cases level <;> decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero positive inverse negative
  rw [one, bit] at positive
  rw [zero, positive, zero_sub] at inverse
  rw [zero, bit, zero_sub] at negative
  exact ⟨inverse, negative⟩

def pathAttempt (level which lane : Nat) : CsrExecutableAttempt :=
  let call := 115+2*level+which
  let previous := 113+2*level+which
  let sibling := 41463+7*level+lane%7
  let source := hashFinalIndex previous (lane%7)
  let terms := if lane < 7 then
      [(hashInitialIndex call lane, 1), (source, 348+3*level), (sibling, 349+3*level)]
    else if lane < 14 then
      [(hashInitialIndex call lane, 1), (sibling, 348+3*level), (source, 349+3*level)]
    else [(hashInitialIndex call lane, 1)]
  attempt (20004+32*level+16*which+lane) 55 (32*level+16*which+lane) 0 terms
    (if lane < 14 then 0 else if lane=14 then 559+level else 544)

theorem exact_path_attempts (level : Fin 4) (which : Fin 2) (lane : Fin 16) :
    pathAttempt level.val which.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 55) =
      (List.range 4).flatMap (fun level => (List.range 2).flatMap (fun which =>
        (List.range 16).map (pathAttempt level which))) := by decide
  apply (List.mem_filter.mp (show pathAttempt level.val which.val lane.val ∈
    exactCsrAttempts.filter (fun entry => entry.family == 55) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨level.val, List.mem_range.mpr level.isLt,
    List.mem_flatMap.mpr ⟨which.val, List.mem_range.mpr which.isLt,
      List.mem_map.mpr ⟨lane.val, List.mem_range.mpr lane.isLt, rfl⟩⟩⟩

def pathLaneSource (publicWords packed : List Nat) (level which lane : Nat) : Nat :=
  let previous := packedWord packed (hashFinalIndex (113+2*level+which) (lane%7))
  let sibling := packedWord packed (41463+7*level+lane%7)
  if assetBit publicWords level = 0 then if lane < 7 then previous else sibling
  else if lane < 7 then sibling else previous

theorem accepted_path_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (level : Fin 4) (which : Fin 2) (lane : Fin 14) :
    packedWord packed (hashInitialIndex (115+2*level.val+which.val) lane.val) =
      pathLaneSource publicWords packed level.val which.val lane.val := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero
  obtain ⟨inverse, negative⟩ := stable_orientation_coefficients equations accepted.1 level
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_path_attempts level which ⟨lane.val, by omega⟩))
  have bitBound := asset_bit_bound publicWords level.val
  by_cases bitZero : assetBit publicWords level.val = 0
  · simp only [bitZero, Nat.cast_zero, sub_zero, neg_zero] at inverse negative
    by_cases left : lane.val < 7
    · simp only [pathAttempt, left, lane.isLt, ↓reduceIte, attempt, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one, zero,
        inverse, negative, one_mul, neg_one_mul, zero_mul, add_zero] at eq
      simpa [pathLaneSource, bitZero, left] using
        canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
          (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)
    · simp only [pathAttempt, left, lane.isLt, ↓reduceIte, attempt, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one, zero,
        inverse, negative, one_mul, neg_one_mul, zero_mul, add_zero] at eq
      simpa [pathLaneSource, bitZero, left] using
        canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
          (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)
  · have bitOne : assetBit publicWords level.val = 1 := by omega
    simp only [bitOne, Nat.cast_one, sub_self, neg_zero] at inverse negative
    by_cases left : lane.val < 7
    · simp only [pathAttempt, left, lane.isLt, ↓reduceIte, attempt, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one, zero,
        inverse, negative, one_mul, neg_one_mul, zero_mul, zero_add, add_zero] at eq
      simpa [pathLaneSource, bitZero, left] using
        canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
          (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)
    · simp only [pathAttempt, left, lane.isLt, ↓reduceIte, attempt, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one, zero,
        inverse, negative, one_mul, neg_one_mul, zero_mul, zero_add, add_zero] at eq
      simpa [pathLaneSource, bitZero, left] using
        canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
          (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)

theorem accepted_path_constant {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (level : Fin 4) (which : Fin 2) (lane : Fin 16) (high : 14 ≤ lane.val) :
    packedWord packed (hashInitialIndex (115+2*level.val+which.val) lane.val) =
      if lane.val=14 then stablecoinV8DomainStateNode0+level.val else poseidon2V8SuiteMarker := by
  apply accepted_constant_coordinate accepted (20004+32*level.val+16*which.val+lane.val) 55
    (32*level.val+16*which.val+lane.val) 0 _
    (if lane.val=14 then 559+level.val else 544)
    (if lane.val=14 then stablecoinV8DomainStateNode0+level.val else poseidon2V8SuiteMarker)
  · simpa only [pathAttempt, if_neg (show ¬lane.val<7 by omega),
      if_neg (show ¬lane.val<14 by omega)] using exact_path_attempts level which lane
  · fin_cases level <;> fin_cases lane <;> decide
  · fin_cases level <;> fin_cases lane <;> decide

def sourceSibling (packed : List Nat) (level : Nat) : Digest :=
  (List.range 7).map (fun lane => packedWord packed (41463+7*level+lane))

theorem source_sibling_word (packed : List Nat) (level : Nat) {lane : Nat} (bound : lane<7) :
    (sourceSibling packed level).getD lane 0 = packedWord packed (41463+7*level+lane) := by
  simp [sourceSibling, List.getD_eq_getElem?_getD, bound]

theorem accepted_path_initial {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (level : Fin 4) (which : Fin 2) :
    packedInitialState packed (115+2*level.val+which.val) =
      if assetBit publicWords level.val=0 then
        compressFrame (stablecoinV8DomainStateNode0+level.val)
          (callDigest packed (113+2*level.val+which.val)) (sourceSibling packed level.val)
      else compressFrame (stablecoinV8DomainStateNode0+level.val)
        (sourceSibling packed level.val) (callDigest packed (113+2*level.val+which.val)) := by
  by_cases bitZero : assetBit publicWords level.val=0
  all_goals simp only [bitZero, ↓reduceIte]
  all_goals apply List.map_congr_left
  all_goals intro lane member
  all_goals have bound : lane<16 := List.mem_range.mp member
  all_goals by_cases left : lane<7
  all_goals try {
    have div : lane%7=lane := Nat.mod_eq_of_lt left
    have source := accepted_path_source accepted level which ⟨lane, by omega⟩
    simpa only [pathLaneSource, bitZero, ↓reduceIte, if_pos left, compressFrame, div,
      source_sibling_word packed _ left, call_digest_word packed _ left] using source }
  all_goals by_cases right : lane<14
  all_goals try {
    have subBound : lane-7<7 := by omega
    have mod : lane%7=lane-7 := by omega
    have source := accepted_path_source accepted level which ⟨lane, right⟩
    simpa only [pathLaneSource, bitZero, ↓reduceIte, if_neg left, if_pos right, compressFrame, mod,
      source_sibling_word packed _ subBound, call_digest_word packed _ subBound] using source }
  all_goals simpa [compressFrame, left, right] using
    accepted_path_constant accepted level which ⟨lane, bound⟩ (by change 14 ≤ lane; omega)

theorem accepted_path_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (level : Fin 4) (which : Fin 2) :
    callDigest packed (115+2*level.val+which.val) =
      if assetBit publicWords level.val=0 then
        poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level.val)
          (callDigest packed (113+2*level.val+which.val)) (sourceSibling packed level.val)
      else poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level.val)
        (sourceSibling packed level.val) (callDigest packed (113+2*level.val+which.val)) := by
  have frame := accepted_path_initial accepted level which
  by_cases bitZero : assetBit publicWords level.val=0
  all_goals simp only [bitZero, ↓reduceIte] at frame ⊢
  all_goals exact accepted_compress_digest accepted (by omega) _ _ _ frame

def leafAttempt (which lane : Nat) : CsrExecutableAttempt :=
  let coordinate := hashInitialIndex (113+which) lane
  let terms := if lane < 7 then [(coordinate, 1), (hashFinalIndex 112 lane, 158)]
    else if lane < 11 ∧ which=0 then [(coordinate, 1), (41498+(lane-7), 158)]
    else [(coordinate, 1)]
  let target := if lane < 7 then 0 else if lane < 11 then
      if which=0 then 0 else 113+(lane-7)
    else if lane=11 then 346 else if lane < 14 then 0 else if lane=14 then 558 else 544
  attempt (19972+16*which+lane) 54 (16*which+lane) 0 terms target

theorem exact_leaf_attempts (which : Fin 2) (lane : Fin 16) :
    leafAttempt which.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 54) =
      (List.range 2).flatMap (fun which => (List.range 16).map (leafAttempt which)) := by decide
  apply (List.mem_filter.mp (show leafAttempt which.val lane.val ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 54) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨which.val, List.mem_range.mpr which.isLt,
    List.mem_map.mpr ⟨lane.val, List.mem_range.mpr lane.isLt, rfl⟩⟩

theorem accepted_leaf_config {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (which : Fin 2) (lane : Fin 7) :
    packedWord packed (hashInitialIndex (113+which.val) lane.val) =
      packedWord packed (hashFinalIndex 112 lane.val) := by
  apply accepted_copied_coordinate accepted (19972+16*which.val+lane.val) 54
    (16*which.val+lane.val) 0 _ _
  simpa only [leafAttempt, if_pos lane.isLt] using
    exact_leaf_attempts which ⟨lane.val, by omega⟩

theorem accepted_leaf_before_counter {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (counter : Fin 4) :
    packedWord packed (hashInitialIndex 113 (7+counter.val)) =
      packedWord packed (41498+counter.val) := by
  apply accepted_copied_coordinate accepted (19979+counter.val) 54 (7+counter.val) 0 _ _
  have member := exact_leaf_attempts ⟨0, by decide⟩ ⟨7+counter.val, by omega⟩
  simpa [leafAttempt, show ¬7+counter.val<7 by omega,
    show 7+counter.val<11 by omega, Nat.add_assoc,
    show 19972+(7+counter.val)=19979+counter.val by omega] using member

theorem accepted_leaf_after_counter {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (counter : Fin 4) :
    packedWord packed (hashInitialIndex 114 (7+counter.val)) = publicWords.getD (109+counter.val) 0 := by
  apply accepted_public_coordinate accepted (19995+counter.val) 54 (23+counter.val) 0 _
    (113+counter.val) (109+counter.val)
  · have member := exact_leaf_attempts ⟨1, by decide⟩ ⟨7+counter.val, by omega⟩
    simpa [leafAttempt, show ¬7+counter.val<7 by omega,
      show 7+counter.val<11 by omega, Nat.add_assoc,
      show 19988+(7+counter.val)=19995+counter.val by omega,
      show 16+(7+counter.val)=23+counter.val by omega] using member
  · fin_cases counter <;> decide
  · change 109+counter.val<120
    omega

theorem stable_index_field_value {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (canonical : CanonicalPublicWords publicWords) :
    (values.getD 346 0 : F) = ((publicWords.getD 84 0 % 16 : Nat) : F) := by
  have b0 := stable_bit_field_value equations canonical ⟨0, by decide⟩
  have b1 := stable_bit_field_value equations canonical ⟨1, by decide⟩
  have b2 := stable_bit_field_value equations canonical ⟨2, by decide⟩
  have b3 := stable_bit_field_value equations canonical ⟨3, by decide⟩
  change (values.getD 316 0 : F) = (assetBit publicWords 0 : F) at b0
  change (values.getD 317 0 : F) = (assetBit publicWords 1 : F) at b1
  change (values.getD 318 0 : F) = (assetBit publicWords 2 : F) at b2
  change (values.getD 319 0 : F) = (assetBit publicWords 3 : F) at b3
  have c2 := equations 2 (.constant 2) (by decide)
  have c4 := equations 128 (.constant 4) (by decide)
  have c8 := equations 207 (.constant 8) (by decide)
  have m1 := equations 341 (.mul 2 317) (by decide)
  have a1 := equations 342 (.add 316 341) (by decide)
  have m2 := equations 343 (.mul 128 318) (by decide)
  have a2 := equations 344 (.add 342 343) (by decide)
  have m3 := equations 345 (.mul 207 319) (by decide)
  have a3 := equations 346 (.add 344 345) (by decide)
  simp only [expressionField, Nat.cast_ofNat] at c2 c4 c8 m1 a1 m2 a2 m3 a3
  have decomposition : assetBit publicWords 0 + 2*assetBit publicWords 1 +
      4*assetBit publicWords 2 + 8*assetBit publicWords 3 = publicWords.getD 84 0 % 16 := by
    simp only [assetBit, Nat.pow_zero, Nat.pow_one, Nat.reducePow, Nat.div_one]
    omega
  rw [a3, a2, a1, m1, m2, m3, c2, c4, c8, b0, b1, b2, b3]
  simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat] using
    congrArg (fun value : Nat => (value : F)) decomposition

theorem accepted_leaf_index {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedWord packed (hashInitialIndex (113+which.val) 11) = publicWords.getD 84 0 % 16 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  simp only [expressionField, Nat.cast_one] at one
  have index := stable_index_field_value equations accepted.1
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_leaf_attempts which ⟨11, by decide⟩))
  simp only [leafAttempt, show ¬(11:Nat)<7 by decide, Nat.lt_irrefl, false_and,
    ↓reduceIte, attempt, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one,
    one_mul, add_zero, index] at eq
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) _ eq
  have remainder := Nat.mod_lt (publicWords.getD 84 0) (by decide : 0<16)
  change _ < 18446744069414584321
  omega

theorem accepted_leaf_constant {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (which : Fin 2) (lane : Fin 16) (high : 12 ≤ lane.val) :
    packedWord packed (hashInitialIndex (113+which.val) lane.val) =
      if lane.val < 14 then 0 else if lane.val=14 then stablecoinV8DomainStateLeaf
      else poseidon2V8SuiteMarker := by
  apply accepted_constant_coordinate accepted (19972+16*which.val+lane.val) 54
    (16*which.val+lane.val) 0 _
    (if lane.val<14 then 0 else if lane.val=14 then 558 else 544)
    (if lane.val<14 then 0 else if lane.val=14 then stablecoinV8DomainStateLeaf else poseidon2V8SuiteMarker)
  · simpa only [leafAttempt, show ¬lane.val<7 by omega,
      show ¬lane.val<11 by omega, false_and,
      ↓reduceIte, show lane.val≠11 by omega] using exact_leaf_attempts which lane
  · fin_cases lane <;> decide
  · fin_cases lane <;> decide

def leafLaneSource (publicWords packed : List Nat) (which lane : Nat) : Nat :=
  if lane<7 then packedWord packed (hashFinalIndex 112 lane)
  else if lane<11 then if which=0 then packedWord packed (41498+(lane-7))
    else publicWords.getD (109+(lane-7)) 0
  else if lane=11 then publicWords.getD 84 0 % 16
  else if lane<14 then 0 else if lane=14 then stablecoinV8DomainStateLeaf else poseidon2V8SuiteMarker

theorem accepted_leaf_lane {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (which : Fin 2) (lane : Fin 16) :
    packedWord packed (hashInitialIndex (113+which.val) lane.val) =
      leafLaneSource publicWords packed which.val lane.val := by
  by_cases low : lane.val<7
  · simpa only [leafLaneSource, if_pos low] using accepted_leaf_config accepted which ⟨lane.val, low⟩
  · by_cases counter : lane.val<11
    · have counterBound : lane.val-7<4 := by omega
      have laneEq : 7+(lane.val-7)=lane.val := by omega
      fin_cases which
      · simpa only [leafLaneSource, if_neg low, if_pos counter, ↓reduceIte, laneEq] using
          accepted_leaf_before_counter accepted ⟨lane.val-7, counterBound⟩
      · simpa only [leafLaneSource, if_neg low, if_pos counter, Nat.one_ne_zero, ↓reduceIte, laneEq] using
          accepted_leaf_after_counter accepted ⟨lane.val-7, counterBound⟩
    · by_cases index : lane.val=11
      · simpa [leafLaneSource, index] using accepted_leaf_index accepted which
      · simpa only [leafLaneSource, if_neg low, if_neg counter, if_neg index] using
          accepted_leaf_constant accepted which lane (by omega)

def rawCounters (publicWords packed : List Nat) (which : Nat) : V8StablecoinCounters :=
  if which=0 then
    ⟨packedWord packed 41498, packedWord packed 41499, packedWord packed 41500, packedWord packed 41501⟩
  else ⟨publicWords.getD 109 0, publicWords.getD 110 0, publicWords.getD 111 0, publicWords.getD 112 0⟩

theorem leaf_source_frame (publicWords packed : List Nat) (which : Fin 2) :
    (List.range 16).map (leafLaneSource publicWords packed which.val) =
      compressFrame stablecoinV8DomainStateLeaf (callDigest packed 112)
        [(rawCounters publicWords packed which.val).epochId,
         (rawCounters publicWords packed which.val).mintedInEpoch,
         (rawCounters publicWords packed which.val).totalDebt,
         (rawCounters publicWords packed which.val).sequence, publicWords.getD 84 0 % 16, 0, 0] := by
  apply List.map_congr_left
  intro lane member
  have bound : lane<16 := List.mem_range.mp member
  fin_cases which <;> interval_cases lane <;> rfl

theorem accepted_leaf_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    callDigest packed (113+which.val) = exactV8StablecoinLeaf
      (publicWords.getD 84 0 % 16) (callDigest packed 112) (rawCounters publicWords packed which.val) := by
  apply accepted_compress_digest accepted (by omega) _ _ _
  apply Eq.trans _ (leaf_source_frame publicWords packed which)
  apply List.map_congr_left
  intro lane member
  exact accepted_leaf_lane accepted which ⟨lane, List.mem_range.mp member⟩


end HegemonCrypto.SmallWood.V8Smz9StableStateHash
