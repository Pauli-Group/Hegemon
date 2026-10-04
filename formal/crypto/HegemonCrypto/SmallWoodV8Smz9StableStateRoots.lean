import HegemonCrypto.SmallWoodV8Smz9StableStateHash
import HegemonCrypto.SmallWoodV8Smz9StableIssuerEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedCounterEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9StableStateRoots

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes (packedFinalState)
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9StableConfigHash
open HegemonCrypto.SmallWood.V8Smz9StableStateHash
open HegemonCrypto.SmallWood.V8Smz9StableIssuerEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation

def rawSiblings (packed : List Nat) : List Digest :=
  (List.range 4).map (sourceSibling packed)

def stateStep (publicWords packed : List Nat) (current : Digest) (level : Nat) : Digest :=
  if assetBit publicWords level=0 then
    poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) current (sourceSibling packed level)
  else poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) (sourceSibling packed level) current

theorem accepted_state_fold {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (which : Fin 2) (count : Nat) (bound : count ≤ 4) :
    callDigest packed (113+2*count+which.val) =
      (List.range count).foldl (stateStep publicWords packed)
        (exactV8StablecoinLeaf (publicWords.getD 84 0 % 16) (callDigest packed 112)
          (rawCounters publicWords packed which.val)) := by
  induction count with
  | zero => simpa only [Nat.mul_zero, Nat.add_zero, List.range_zero, List.foldl_nil] using
      accepted_leaf_digest accepted which
  | succ count ih =>
    have prior := ih (by omega)
    have step := accepted_path_digest accepted ⟨count, by omega⟩ which
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, ← prior]
    rw [show 113+2*(count+1)+which.val=115+2*count+which.val by omega]
    exact step

theorem asset_bit_mod16 (publicWords : List Nat) (level : Fin 4) :
    assetBit publicWords level.val = ((publicWords.getD 84 0 % 16) / 2^level.val) % 2 := by
  fin_cases level <;>
    simp only [assetBit, Nat.pow_zero, Nat.pow_one, Nat.reducePow, Nat.div_one] <;> omega

theorem raw_siblings_word (packed : List Nat) {level : Nat} (bound : level<4) :
    (rawSiblings packed).getD level [] = sourceSibling packed level := by
  simp [rawSiblings, List.getD_eq_getElem?_getD, bound]

private theorem foldl_eq_on (left right : Digest → Nat → Digest)
    (levels : List Nat) (initial : Digest)
    (agree : ∀ level, level ∈ levels → ∀ state, left state level=right state level) :
    levels.foldl left initial=levels.foldl right initial := by
  induction levels generalizing initial with
  | nil => rfl
  | cons head tail ih =>
    simp only [List.foldl_cons]
    rw [agree head List.mem_cons_self initial]
    exact ih _ (by intro level member state; exact agree level (List.mem_cons_of_mem _ member) state)

theorem state_fold_eq_exact (publicWords packed : List Nat) (config : Digest)
    (counters : V8StablecoinCounters) :
    (List.range 4).foldl (stateStep publicWords packed)
        (exactV8StablecoinLeaf (publicWords.getD 84 0 % 16) config counters) =
      exactV8StablecoinRoot (publicWords.getD 84 0) config counters (rawSiblings packed) := by
  unfold exactV8StablecoinRoot
  change _ = (List.range 4).foldl (fun current level =>
    if ((publicWords.getD 84 0 % 16)/2^level)%2=0 then
      poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level) current
        ((rawSiblings packed).getD level [])
    else poseidon2V8Compress14 (stablecoinV8DomainStateNode0+level)
      ((rawSiblings packed).getD level []) current)
      (exactV8StablecoinLeaf (publicWords.getD 84 0 % 16) config counters)
  apply foldl_eq_on
  intro level member current
  have bound := List.mem_range.mp member
  rw [raw_siblings_word packed bound]
  unfold stateStep
  rw [asset_bit_mod16 publicWords ⟨level, bound⟩]

theorem accepted_state_root_raw {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    callDigest packed (121+which.val) = exactV8StablecoinRoot (publicWords.getD 84 0)
      (callDigest packed 112) (rawCounters publicWords packed which.val) (rawSiblings packed) := by
  exact (accepted_state_fold accepted which 4 (by decide)).trans
    (state_fold_eq_exact publicWords packed _ _)

def rootOutputAttempt (which lane : Nat) : CsrExecutableAttempt :=
  attempt (20132+2*lane+which) 56 (2*lane+which) 1
    [(hashFinalIndex (121+which) lane, 306)] (362+5*lane+which)

theorem exact_root_output_attempts (which : Fin 2) (lane : Fin 7) :
    rootOutputAttempt which.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 56) =
      (List.range 7).flatMap (fun lane => (List.range 2).map (fun which => rootOutputAttempt which lane)) := by decide
  apply (List.mem_filter.mp (show rootOutputAttempt which.val lane.val ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 56) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨lane.val, List.mem_range.mpr lane.isLt,
    List.mem_map.mpr ⟨which.val, List.mem_range.mpr which.isLt, rfl⟩⟩

theorem stable_enabled_field_gate {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (enabled : publicWords.getD 83 0=1 ∨ publicWords.getD 83 0=2) :
    (values.getD 306 0 : F)=1 ∧ (values.getD 307 0 : F)=0 := by
  have z := equations 0 (.constant 0) (by decide)
  have o := equations 1 (.constant 1) (by decide)
  have t := equations 2 (.constant 2) (by decide)
  have d := equations 87 (.publicWord 83) (by decide)
  have m := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have b := equations 305 (.selectEqual 87 2 1 0) (by decide)
  have e := equations 306 (.add 304 305) (by decide)
  have n := equations 307 (.sub 1 306) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] at z o t d m b e n
  have neq : (2:F)≠1 := by decide
  have gate : (values.getD 306 0 : F)=1 := by
    rw [e, m, b, d, o, t, z]
    rcases enabled with mint | burn
    · simp only [mint, Nat.cast_one, Ne.symm neq, ↓reduceIte, add_zero]
    · simp only [burn, Nat.cast_ofNat, neq, ↓reduceIte, zero_add]
  rw [o, gate, sub_self] at n
  exact ⟨gate, n⟩

theorem root_output_field_value {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (enabled : publicWords.getD 83 0=1 ∨ publicWords.getD 83 0=2)
    (which : Fin 2) (lane : Fin 7) :
    (values.getD (362+5*lane.val+which.val) 0 : F) =
      (publicWords.getD ((if which.val=0 then 95 else 102)+lane.val) 0 : F) := by
  obtain ⟨gate, inactive⟩ := stable_enabled_field_gate equations enabled
  have before := equations (99+lane.val) (.publicWord (95+lane.val)) (by fin_cases lane <;> decide)
  have after := equations (106+lane.val) (.publicWord (102+lane.val)) (by fin_cases lane <;> decide)
  have gap := equations (359+5*lane.val) (.sub (99+lane.val) (106+lane.val))
    (by fin_cases lane <;> decide)
  have dormant := equations (360+5*lane.val) (.mul 307 (359+5*lane.val))
    (by fin_cases lane <;> decide)
  have beforeActive := equations (361+5*lane.val) (.mul (99+lane.val) 306)
    (by fin_cases lane <;> decide)
  have beforeTarget := equations (362+5*lane.val) (.add (360+5*lane.val) (361+5*lane.val))
    (by fin_cases lane <;> decide)
  have afterTarget := equations (363+5*lane.val) (.mul (106+lane.val) 306)
    (by fin_cases lane <;> decide)
  simp only [expressionField] at before after gap dormant beforeActive beforeTarget afterTarget
  rw [inactive, zero_mul] at dormant
  rw [before, gate, mul_one] at beforeActive
  rw [dormant, beforeActive, zero_add] at beforeTarget
  rw [after, gate, mul_one] at afterTarget
  fin_cases which
  · simpa only [Nat.add_zero, ↓reduceIte] using beforeTarget
  · simpa only [Nat.one_ne_zero, ↓reduceIte, show 362+5*lane.val+1=363+5*lane.val by omega] using afterTarget

theorem accepted_root_output_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (enabled : publicWords.getD 83 0=1 ∨ publicWords.getD 83 0=2)
    (which : Fin 2) (lane : Fin 7) :
    packedWord packed (hashFinalIndex (121+which.val) lane.val) =
      publicWords.getD ((if which.val=0 then 95 else 102)+lane.val) 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have gate := (stable_enabled_field_gate equations enabled).1
  have target := root_output_field_value equations enabled which lane
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_root_output_attempts which lane))
  simp only [rootOutputAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, gate, target, one_mul, add_zero] at eq
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (canonical_public_coordinate accepted.1 (index := (if which.val=0 then 95 else 102)+lane.val)
      (by change _<120; split <;> omega)).2 eq

def rawPublicRoot (publicWords : List Nat) (which : Nat) : Digest :=
  (List.range 7).map (fun lane => publicWords.getD ((if which=0 then 95 else 102)+lane) 0)

theorem accepted_root_output {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (enabled : publicWords.getD 83 0=1 ∨ publicWords.getD 83 0=2) (which : Fin 2) :
    callDigest packed (121+which.val)=rawPublicRoot publicWords which.val := by
  apply List.ext_getElem
  · simp [callDigest, packedFinalState, digestWords, rawPublicRoot]
  · intro lane leftBound rightBound
    have bound : lane<7 := by simpa [rawPublicRoot] using rightBound
    rw [← List.getD_eq_getElem _ 0 leftBound, ← List.getD_eq_getElem _ 0 rightBound]
    simp only [call_digest_word packed _ bound]
    simpa [rawPublicRoot, List.getD_eq_getElem?_getD, bound] using
      accepted_root_output_word accepted enabled which ⟨lane, bound⟩

theorem admitted_public_state_root {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (which : Fin 2) :
    rawPublicRoot publicWords which.val =
      if which.val=0 then statement.stablecoin.beforeRoot else statement.stablecoin.afterRoot := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, intent, before, after, _⟩ := domain.2.1
  have encoded (word : Nat) : publicWords.getD (83+word) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD word 0 := by
    rw [← domain.1]
    exact encoded_stable_public_word statement domain.2.1 word
  apply List.ext_getElem
  · fin_cases which <;> simp [rawPublicRoot, before.1, after.1, digestWords]
  · intro lane leftBound rightBound
    have bound : lane<7 := by simpa [rawPublicRoot] using leftBound
    rw [← List.getD_eq_getElem _ 0 leftBound, ← List.getD_eq_getElem _ 0 rightBound]
    have source := encoded ((if which.val=0 then 12 else 19)+lane)
    fin_cases which <;> interval_cases lane <;>
      simpa [rawPublicRoot, encodeStablecoinPublic, List.getD_eq_getElem?_getD,
        List.getElem?_append, List.length_append, intent.1, before.1, after.1, digestWords] using source

theorem admitted_raw_before {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    rawCounters publicWords packed 0 =
      decodeV8StablecoinBefore (projectTypedWitness statement packed).stablecoin := by
  have c0 := admitted_stable_before_word_source domain (counter := 0) (by decide)
  have c1 := admitted_stable_before_word_source domain (counter := 1) (by decide)
  have c2 := admitted_stable_before_word_source domain (counter := 2) (by decide)
  have c3 := admitted_stable_before_word_source domain (counter := 3) (by decide)
  simp only [rawCounters, ↓reduceIte, decodeV8StablecoinBefore]
  congr 1
  · exact c0.symm
  · exact c1.symm
  · exact c2.symm
  · exact c3.symm

theorem admitted_raw_after {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    rawCounters publicWords packed 1 = statement.stablecoin.after := by
  obtain ⟨_, _, _, epoch, minted, debt, sequence⟩ := admitted_stable_public_counters domain
  cases afterEq : statement.stablecoin.after with
  | mk ep mi de seq =>
    simp only [afterEq] at epoch minted debt sequence
    simp only [rawCounters, Nat.one_ne_zero, ↓reduceIte, epoch, minted, debt, sequence]

theorem projected_sibling_word (statement : V8PublicStatement) (packed : List Nat)
    (level : Fin 4) (lane : Fin 7) :
    stableWitnessWord (projectTypedWitness statement packed).stablecoin (59+level.val*7+lane.val) =
      packedWord packed (hashInitialIndex (115+2*level.val)
        ((if (statement.stablecoin.assetId/2^level.val)%2=0 then 7 else 0)+lane.val)) := by
  fin_cases level <;> fin_cases lane <;> rfl

theorem admitted_raw_siblings {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    rawSiblings packed = decodeV8StablecoinSiblings (projectTypedWitness statement packed).stablecoin := by
  have asset := (admitted_issuer_public_scalars domain).2.1
  apply List.map_congr_left
  intro level member
  have levelBound : level<4 := List.mem_range.mp member
  apply List.map_congr_left
  intro lane member
  have laneBound : lane<7 := List.mem_range.mp member
  have projection := projected_sibling_word statement packed ⟨level, levelBound⟩ ⟨lane, laneBound⟩
  rw [← asset] at projection
  change stableWitnessWord (projectTypedWitness statement packed).stablecoin (59+level*7+lane) =
    packedWord packed (hashInitialIndex (115+2*level)
      ((if assetBit publicWords level=0 then 7 else 0)+lane)) at projection
  by_cases bitZero : assetBit publicWords level=0
  · have source := accepted_path_source domain.2.2 ⟨level, levelBound⟩ ⟨0, by decide⟩
      ⟨7+lane, by omega⟩
    have mod : (7+lane)%7=lane := by omega
    have noLeft : ¬7+lane<7 := by omega
    simp only [pathLaneSource, bitZero, if_pos, if_neg noLeft, mod, Nat.add_zero] at source
    change packedWord packed (41463+7*level+lane) =
      stableWitnessWord (projectTypedWitness statement packed).stablecoin (59+level*7+lane)
    rw [projection]
    simpa only [if_pos bitZero] using source.symm
  · have source := accepted_path_source domain.2.2 ⟨level, levelBound⟩ ⟨0, by decide⟩
      ⟨lane, by omega⟩
    have mod : lane%7=lane := Nat.mod_eq_of_lt laneBound
    simp only [pathLaneSource, bitZero, ↓reduceIte, if_pos laneBound, mod, Nat.add_zero] at source
    change packedWord packed (41463+7*level+lane) =
      stableWitnessWord (projectTypedWitness statement packed).stablecoin (59+level*7+lane)
    rw [projection]
    simpa only [if_neg bitZero, Nat.zero_add] using source.symm

theorem admitted_stable_state_roots {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction ≠ .disabled) :
    let witness := (projectTypedWitness statement packed).stablecoin
    let config := decodeV8StablecoinConfig witness
    let before := decodeV8StablecoinBefore witness
    let siblings := decodeV8StablecoinSiblings witness
    exactV8StablecoinRoot statement.stablecoin.assetId (exactV8StablecoinConfigDigest config)
        before siblings = statement.stablecoin.beforeRoot ∧
      exactV8StablecoinRoot statement.stablecoin.assetId (exactV8StablecoinConfigDigest config)
        statement.stablecoin.after siblings = statement.stablecoin.afterRoot := by
  obtain ⟨direction, asset, _⟩ := admitted_issuer_public_scalars domain
  have rawEnabled : publicWords.getD 83 0=1 ∨ publicWords.getD 83 0=2 := by
    cases mode : statement.stablecoin.direction
    · exact False.elim (enabled mode)
    · exact Or.inl (by simpa [mode, StableDirection.word] using direction)
    · exact Or.inr (by simpa [mode, StableDirection.word] using direction)
  have before := accepted_state_root_raw domain.2.2 ⟨0, by decide⟩
  have after := accepted_state_root_raw domain.2.2 ⟨1, by decide⟩
  rw [asset, admitted_config_digest domain, admitted_raw_before domain, admitted_raw_siblings domain] at before
  rw [asset, admitted_config_digest domain, admitted_raw_after domain, admitted_raw_siblings domain] at after
  have beforeOutput := (accepted_root_output domain.2.2 rawEnabled ⟨0, by decide⟩).trans
    (admitted_public_state_root domain ⟨0, by decide⟩)
  have afterOutput := (accepted_root_output domain.2.2 rawEnabled ⟨1, by decide⟩).trans
    (admitted_public_state_root domain ⟨1, by decide⟩)
  exact ⟨before.symm.trans beforeOutput, after.symm.trans afterOutput⟩


end HegemonCrypto.SmallWood.V8Smz9StableStateRoots
