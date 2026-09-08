import HegemonCrypto.SmallWoodV8Smz9Compress14Endpoint
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabled

namespace HegemonCrypto.SmallWood.V8Smz9StableHashWiring

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
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false

attribute [local irreducible] Poseidon2Width16Kernel.permutation

def issuerAttempt (which lane : Nat) : CsrExecutableAttempt :=
  let target := if lane < 7 then 0 else if lane < 14 then
      if which = 0 then if lane = 7 then 88 else if lane = 8 then 89 else 0
      else 91 + (lane - 7)
    else if lane = 14 then 563 + which else 544
  let terms := if lane < 7 then
      [(hashInitialIndex (123 + which) lane, 1), (41491 + lane, 158)]
    else [(hashInitialIndex (123 + which) lane, 1)]
  attempt (20146 + 16 * which + lane) 57 (16 * which + lane) 0 terms target

theorem exact_issuer_attempts : ∀ which, which < 2 → ∀ lane, lane < 16 →
    issuerAttempt which lane ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 57) =
      (List.range 2).flatMap (fun which => (List.range 16).map (issuerAttempt which)) := by decide
  intro which whichBound lane laneBound
  apply (List.mem_filter.mp (show issuerAttempt which lane ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 57) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨which, List.mem_range.mpr whichBound,
    List.mem_map.mpr ⟨lane, List.mem_range.mpr laneBound, rfl⟩⟩

def issuerSecret (packed : List Nat) : Digest :=
  (List.range 7).map (fun lane => packedWord packed (41491 + lane))

def issuerRight (publicWords : List Nat) (which : Nat) : Digest :=
  if which = 0 then [publicWords.getD 84 0, publicWords.getD 85 0, 0, 0, 0, 0, 0]
  else (List.range 7).map (fun lane => publicWords.getD (87 + lane) 0)

def issuerDomain (which : Nat) : Nat :=
  if which = 0 then stablecoinV8DomainIssuerCommitment else stablecoinV8DomainIssuerAuthorization

theorem issuer_target_value {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (which : Fin 2) (lane : Fin 16) (high : 7 ≤ lane.val) :
    (values.getD (issuerAttempt which.val lane.val).targetRoot 0 : F) =
      ((compressFrame (issuerDomain which.val) [] (issuerRight publicWords which.val)).getD
        lane.val 0 : F) := by
  have zero := equations 0 (.constant 0) (by decide)
  have suite := equations 544 (.constant poseidon2V8SuiteMarker) (by decide)
  have commit := equations 563 (.constant stablecoinV8DomainIssuerCommitment) (by decide)
  have auth := equations 564 (.constant stablecoinV8DomainIssuerAuthorization) (by decide)
  have pub (i : Fin 120) : (values.getD (4+i.val) 0 : F) = (publicWords.getD i.val 0 : F) := by
    have found : exactCsrExpressions[4+i.val]? = some (.publicWord i.val) := by
      fin_cases i <;> decide
    exact equations _ _ found
  have p84 := pub ⟨84, by decide⟩
  have p85 := pub ⟨85, by decide⟩
  have p87 := pub ⟨87, by decide⟩
  have p88 := pub ⟨88, by decide⟩
  have p89 := pub ⟨89, by decide⟩
  have p90 := pub ⟨90, by decide⟩
  have p91 := pub ⟨91, by decide⟩
  have p92 := pub ⟨92, by decide⟩
  have p93 := pub ⟨93, by decide⟩
  simp only [expressionField, Nat.cast_zero] at zero suite commit auth
  fin_cases which <;> fin_cases lane <;> simp_all [issuerAttempt, attempt, issuerRight, issuerDomain,
    compressFrame, List.getD_eq_getElem?_getD]

theorem accepted_issuer_initial_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedInitialState packed (123 + which.val) =
      compressFrame (issuerDomain which.val) (issuerSecret packed) (issuerRight publicWords which.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  have neg := equations 158 (.sub 0 1) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero neg
  rw [zero, one, zero_sub] at neg
  apply List.map_congr_left
  intro lane member
  have bound : lane < 16 := List.mem_range.mp member
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_issuer_attempts which.val which.isLt lane bound))
  by_cases low : lane < 7
  · have natural : packedWord packed (hashInitialIndex (123+which.val) lane) =
        packedWord packed (41491+lane) := by
      apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
        (packed_word_canonical accepted.2.1 _)
      simp only [issuerAttempt, low, ↓reduceIte, attempt, csrFieldSum, List.map_cons,
        List.map_nil, List.sum_cons, List.sum_nil, one, zero, neg, one_mul,
        neg_one_mul, add_zero] at eq
      exact add_neg_eq_zero.mp eq
    simpa [compressFrame, low, issuerSecret, List.getD_eq_getElem?_getD] using natural
  · have target := issuer_target_value equations which ⟨lane, bound⟩ (by change 7 ≤ lane; omega)
    simp only [issuerAttempt, low, ↓reduceIte, attempt] at target
    simp only [issuerAttempt, low, ↓reduceIte, attempt, csrFieldSum, List.map_cons,
      List.map_nil, List.sum_cons, List.sum_nil, one, one_mul, add_zero] at eq
    have rhsBound : (compressFrame (issuerDomain which.val) []
        (issuerRight publicWords which.val)).getD lane 0 <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
      have cp (i : Nat) (ib : i < 120) : publicWords.getD i 0 <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus :=
        (canonical_public_coordinate accepted.1 (index := i) ib).2
      fin_cases which <;> interval_cases lane <;>
        simp_all [compressFrame, issuerDomain, issuerRight, List.getD_eq_getElem?_getD,
          poseidon2V8SuiteMarker, stablecoinV8DomainIssuerCommitment,
          stablecoinV8DomainIssuerAuthorization]
      all_goals first | exact cp _ (by decide) | decide
    have natural := canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _) rhsBound (eq.trans target)
    simpa [compressFrame, low, List.getD_eq_getElem?_getD, bound] using natural

theorem accepted_issuer_commitment {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    callDigest packed 123 = exactV8StablecoinIssuerCommitment
      (publicWords.getD 84 0) (publicWords.getD 85 0) (issuerSecret packed) := by
  exact accepted_compress_digest accepted (by decide) _ _ _
    (accepted_issuer_initial_frame accepted ⟨0, by decide⟩)

theorem accepted_issuer_authorization {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    callDigest packed 124 = exactV8StablecoinIssuerAuthorization
      ((List.range 7).map (fun lane => publicWords.getD (87+lane) 0)) (issuerSecret packed) := by
  exact accepted_compress_digest accepted (by decide) _ _ _
    (accepted_issuer_initial_frame accepted ⟨1, by decide⟩)

theorem admitted_issuer_secret_source {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    decodeV8StablecoinIssuerSecret (projectTypedWitness statement packed).stablecoin =
      issuerSecret packed := by
  apply List.map_congr_left
  intro lane member
  have bound : lane < 7 := List.mem_range.mp member
  have projection : stableWitnessWord (projectTypedWitness statement packed).stablecoin (87 + lane) =
      packedWord packed (hashInitialIndex 123 lane) := by
    change (projectStablecoinWords statement packed).getD (87 + lane) 0 = _
    simp only [projectStablecoinWords, List.getD_eq_getElem?_getD]
    rw [List.getElem?_append_right (by simp [List.length_flatMap])]
    simp [List.length_flatMap, bound]
  rw [projection]
  simpa [stableCopyDestination, stableCopySource, stableSourceIndex,
    show ¬59 + lane < 55 by omega, show ¬59 + lane < 59 by omega,
    Nat.add_assoc, show 41408+(83+lane)=41491+lane by omega] using
    accepted_stable_copy_equality domain.2.2 (word := 59 + lane) (by omega)


end HegemonCrypto.SmallWood.V8Smz9StableHashWiring
