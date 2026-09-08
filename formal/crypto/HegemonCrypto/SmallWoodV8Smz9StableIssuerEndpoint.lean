import HegemonCrypto.SmallWoodV8Smz9StableHashWiring

namespace HegemonCrypto.SmallWood.V8Smz9StableIssuerEndpoint

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes (packedFinalState)
open HegemonCrypto.SmallWood.V8Smz9Compress14Endpoint
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation

def issuerOutputAttempt (which lane : Nat) : CsrExecutableAttempt :=
  if which=0 then attempt (20178+lane) 58 lane 1
      [(hashFinalIndex 123 lane, 304), (41414+lane, 323)] 0
  else attempt (20185+lane) 59 lane 1 [(hashFinalIndex 124 lane, 304)] (394+lane)

theorem exact_issuer_output_attempts (which : Fin 2) (lane : Fin 7) :
    issuerOutputAttempt which.val lane.val ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 58 || entry.family == 59) =
      (List.range 2).flatMap (fun which => (List.range 7).map (issuerOutputAttempt which)) := by decide
  apply (List.mem_filter.mp (show issuerOutputAttempt which.val lane.val ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 58 || entry.family == 59) from ?_)).1
  rw [checked]
  exact List.mem_flatMap.mpr ⟨which.val, List.mem_range.mpr which.isLt,
    List.mem_map.mpr ⟨lane.val, List.mem_range.mpr lane.isLt, rfl⟩⟩

theorem mint_field_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (mint : publicWords.getD 83 0=1) :
    (values.getD 304 0 : F)=1 ∧ (values.getD 323 0 : F)= -1 ∧ (values.getD 0 0 : F)=0 := by
  have zero := equations 0 (.constant 0) (by decide)
  have one := equations 1 (.constant 1) (by decide)
  have direction := equations 87 (.publicWord 83) (by decide)
  have gate := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have negative := equations 323 (.sub 0 304) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at zero one direction gate negative
  rw [mint, Nat.cast_one] at direction
  rw [direction, one, if_pos rfl] at gate
  rw [zero, gate, zero_sub] at negative
  exact ⟨gate, negative, zero⟩

theorem accepted_mint_issuer_commitment_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0=1) (lane : Fin 7) :
    packedWord packed (hashFinalIndex 123 lane.val) = packedWord packed (41414+lane.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨gate, negative, zero⟩ := mint_field_coefficients equations mint
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_issuer_output_attempts ⟨0, by decide⟩ lane))
  simp only [issuerOutputAttempt, ↓reduceIte, attempt, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, gate, negative, zero,
    one_mul, neg_one_mul, add_zero] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp eq)

theorem accepted_mint_issuer_authorization_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0=1) (lane : Fin 7) :
    packedWord packed (hashFinalIndex 124 lane.val) = publicWords.getD (113+lane.val) 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨gate, _, _⟩ := mint_field_coefficients equations mint
  have publicEq := equations (117+lane.val) (.publicWord (113+lane.val))
    (by fin_cases lane <;> decide)
  have target := equations (394+lane.val) (.mul (117+lane.val) 304)
    (by fin_cases lane <;> decide)
  simp only [expressionField] at publicEq target
  rw [publicEq, gate, mul_one] at target
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_issuer_output_attempts ⟨1, by decide⟩ lane))
  simp only [issuerOutputAttempt, Nat.one_ne_zero, ↓reduceIte, attempt, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, gate, target,
    one_mul, add_zero] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (canonical_public_coordinate accepted.1 (index := 113+lane.val) (by change _<120; omega)).2 eq

def rawIssuerCommitment (packed : List Nat) : Digest :=
  (List.range 7).map (fun lane => packedWord packed (41414+lane))

def rawIssuerPublicDigest (publicWords : List Nat) (which : Nat) : Digest :=
  (List.range 7).map (fun lane => publicWords.getD ((if which=0 then 87 else 113)+lane) 0)

theorem issuer_call_digest_word (packed : List Nat) (call : Nat) {lane : Nat} (bound : lane<7) :
    (callDigest packed call).getD lane 0 = packedWord packed (hashFinalIndex call lane) := by
  simp [callDigest, packedFinalState, digestWords, List.getD_eq_getElem?_getD, bound]

theorem accepted_mint_issuer_digests {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0=1) :
    callDigest packed 123 = rawIssuerCommitment packed ∧
      callDigest packed 124 = rawIssuerPublicDigest publicWords 1 := by
  constructor
  · apply List.ext_getElem
    · simp [callDigest, packedFinalState, digestWords, rawIssuerCommitment]
    · intro lane leftBound rightBound
      have bound : lane<7 := by simpa [rawIssuerCommitment] using rightBound
      rw [← List.getD_eq_getElem _ 0 leftBound, ← List.getD_eq_getElem _ 0 rightBound]
      simp only [issuer_call_digest_word packed _ bound]
      simpa [rawIssuerCommitment, List.getD_eq_getElem?_getD, bound] using
        accepted_mint_issuer_commitment_word accepted mint ⟨lane, bound⟩
  · apply List.ext_getElem
    · simp [callDigest, packedFinalState, digestWords, rawIssuerPublicDigest]
    · intro lane leftBound rightBound
      have bound : lane<7 := by simpa [rawIssuerPublicDigest] using rightBound
      rw [← List.getD_eq_getElem _ 0 leftBound, ← List.getD_eq_getElem _ 0 rightBound]
      simp only [issuer_call_digest_word packed _ bound]
      simpa [rawIssuerPublicDigest, List.getD_eq_getElem?_getD, bound] using
        accepted_mint_issuer_authorization_word accepted mint ⟨lane, bound⟩

theorem admitted_issuer_public_scalars {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    publicWords.getD 83 0 = statement.stablecoin.direction.word ∧
      publicWords.getD 84 0 = statement.stablecoin.assetId ∧
      publicWords.getD 85 0 = statement.stablecoin.policyVersion := by
  have encoded (word : Nat) : publicWords.getD (83+word) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD word 0 := by
    rw [← domain.1]
    exact encoded_stable_public_word statement domain.2.1 word
  exact ⟨by simpa [encodeStablecoinPublic] using encoded 0,
    by simpa [encodeStablecoinPublic] using encoded 1,
    by simpa [encodeStablecoinPublic] using encoded 2⟩

theorem admitted_issuer_public_digest {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (which : Fin 2) :
    rawIssuerPublicDigest publicWords which.val =
      if which.val=0 then statement.stablecoin.actionIntent else statement.stablecoin.issuerAuthorization := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, intent, before, after, auth, _⟩ := domain.2.1
  have encoded (word : Nat) : publicWords.getD (83+word) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD word 0 := by
    rw [← domain.1]
    exact encoded_stable_public_word statement domain.2.1 word
  apply List.ext_getElem
  · fin_cases which <;> simp [rawIssuerPublicDigest, intent.1, auth.1, digestWords]
  · intro lane leftBound rightBound
    have bound : lane<7 := by simpa [rawIssuerPublicDigest] using leftBound
    rw [← List.getD_eq_getElem _ 0 leftBound, ← List.getD_eq_getElem _ 0 rightBound]
    have source := encoded ((if which.val=0 then 4 else 30)+lane)
    fin_cases which <;> interval_cases lane <;>
      simpa [rawIssuerPublicDigest, encodeStablecoinPublic, List.getD_eq_getElem?_getD,
        List.getElem?_append, List.length_append, intent.1, before.1, after.1, digestWords] using source

theorem admitted_config_issuer_commitment_source {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin).issuerCommitment =
      rawIssuerCommitment packed := by
  apply List.map_congr_left
  intro lane member
  have bound : lane<7 := List.mem_range.mp member
  have source := admitted_stable_config_word_source domain (word := 6+lane) (by omega)
  simpa [rawIssuerCommitment, Nat.add_assoc,
    show 41408+(6+lane)=41414+lane by omega] using source

theorem admitted_stable_mint_issuer_links {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mint : statement.stablecoin.direction = .mint) :
    let witness := (projectTypedWitness statement packed).stablecoin
    let secret := decodeV8StablecoinIssuerSecret witness
    exactV8StablecoinIssuerCommitment statement.stablecoin.assetId statement.stablecoin.policyVersion secret =
        (decodeV8StablecoinConfig witness).issuerCommitment ∧
      exactV8StablecoinIssuerAuthorization statement.stablecoin.actionIntent secret =
        statement.stablecoin.issuerAuthorization := by
  obtain ⟨direction, asset, policy⟩ := admitted_issuer_public_scalars domain
  have mintWord : publicWords.getD 83 0=1 := by simpa [mint, StableDirection.word] using direction
  obtain ⟨commitOutput, authOutput⟩ := accepted_mint_issuer_digests domain.2.2 mintWord
  have commitPrimitive := accepted_issuer_commitment domain.2.2
  have authPrimitive := accepted_issuer_authorization domain.2.2
  have secret := admitted_issuer_secret_source domain
  have commitSource := admitted_config_issuer_commitment_source domain
  have intent := admitted_issuer_public_digest domain ⟨0, by decide⟩
  have authorization := admitted_issuer_public_digest domain ⟨1, by decide⟩
  change rawIssuerPublicDigest publicWords 0 = statement.stablecoin.actionIntent at intent
  change rawIssuerPublicDigest publicWords 1 = statement.stablecoin.issuerAuthorization at authorization
  constructor
  · rw [secret, commitSource, ← asset, ← policy]
    exact commitPrimitive.symm.trans commitOutput
  · rw [secret, ← intent, ← authorization]
    exact authPrimitive.symm.trans authOutput


end HegemonCrypto.SmallWood.V8Smz9StableIssuerEndpoint
