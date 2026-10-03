import HegemonCrypto.SmallWoodV8Smz9StableRolesEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableDecimalEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedCounterEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCommonEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CsrExecutableAttempt FieldExpression)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRolesEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableDecimalEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def roleDigest (packed : List Nat) (role : Nat) : Digest :=
  (List.range 7).map fun limb =>
    packed.getD (41408 + commitmentOffset role + limb) 0

def configCommitments (config : V8StablecoinConfigOpening) : List Digest :=
  [config.issuerCommitment, config.policyAdminCommitment,
    config.oracleAuthorityCommitment, config.attestationAuthorityCommitment,
    config.lockedCollateralCommitment]

theorem admitted_config_commitments {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    configCommitments (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin) =
      [roleDigest packed 0, roleDigest packed 1, roleDigest packed 2,
        roleDigest packed 3, roleDigest packed 4] := by
  have slice (start : Nat) (bound : start ≤ 48) :
      stableWitnessSlice (projectTypedWitness statement packed).stablecoin start 7 =
        (List.range 7).map (fun limb => packed.getD (41408 + start + limb) 0) := by
    unfold stableWitnessSlice
    apply List.map_congr_left
    intro limb member
    have limbBound := List.mem_range.mp member
    rw [admitted_stable_config_word_source domain (by omega : start + limb < 55)]
    simp only [packedWord, Nat.add_assoc]
  simp only [configCommitments, decodeV8StablecoinConfig]
  rw [slice 6 (by decide), slice 24 (by decide), slice 31 (by decide),
    slice 38 (by decide), slice 48 (by decide)]
  rfl

theorem role_digest_getD (packed : List Nat) (role : Nat)
    {limb : Nat} (bound : limb < 7) :
    (roleDigest packed role).getD limb 0 =
      packed.getD (41408 + commitmentOffset role + limb) 0 := by
  simp only [roleDigest, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range bound, Option.map_some, Option.getD_some]

theorem accepted_role_digest_properties {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (enabled : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    ([roleDigest packed 0, roleDigest packed 1, roleDigest packed 2,
      roleDigest packed 3, roleDigest packed 4].all
        (fun digest => digest.any (fun word => decide (word ≠ 0)))) = true ∧
    DigestListPairwiseDistinct
      [roleDigest packed 0, roleDigest packed 1, roleDigest packed 2,
        roleDigest packed 3, roleDigest packed 4] := by
  obtain ⟨nonzero, distinct⟩ := accepted_stable_commitment_roles accepted enabled
  have roleNonzero (role : Nat) (bound : role < 5) :
      (roleDigest packed role).any (fun word => decide (word ≠ 0)) = true := by
    obtain ⟨limb, limbBound, ne⟩ := nonzero role bound
    apply List.any_eq_true.mpr
    refine ⟨packed.getD (41408 + commitmentOffset role + limb) 0, ?_, ?_⟩
    · exact List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩
    · exact decide_eq_true ne
  have pairDistinct (pair : Nat) (bound : pair < 10) :
      roleDigest packed (commitmentPair pair).1 ≠
        roleDigest packed (commitmentPair pair).2 := by
    obtain ⟨limb, limbBound, ne⟩ := distinct pair bound
    intro equal
    have words := congrArg (fun digest : Digest => digest.getD limb 0) equal
    rw [role_digest_getD packed _ limbBound, role_digest_getD packed _ limbBound] at words
    exact ne words
  constructor
  · simp only [List.all_cons, List.all_nil, roleNonzero 0 (by decide),
      roleNonzero 1 (by decide), roleNonzero 2 (by decide),
      roleNonzero 3 (by decide), roleNonzero 4 (by decide), Bool.and_self]
  ·
    have p0 := pairDistinct 0 (by decide)
    have p1 := pairDistinct 1 (by decide)
    have p2 := pairDistinct 2 (by decide)
    have p3 := pairDistinct 3 (by decide)
    have p4 := pairDistinct 4 (by decide)
    have p5 := pairDistinct 5 (by decide)
    have p6 := pairDistinct 6 (by decide)
    have p7 := pairDistinct 7 (by decide)
    have p8 := pairDistinct 8 (by decide)
    have p9 := pairDistinct 9 (by decide)
    norm_num [commitmentPair] at p0 p1 p2 p3 p4 p5 p6 p7 p8 p9
    simp [DigestListPairwiseDistinct, p0, p1, p2, p3, p4, p5, p6, p7, p8, p9]

def configIdentityAttempts : List CsrExecutableAttempt :=
  [attempt 19320 42 0 0 [(41408, 1)] 88,
   attempt 19321 42 1 0 [(41409, 1)] 89]

theorem exact_config_identity_attempts : ∀ entry, entry ∈ configIdentityAttempts →
    entry ∈ exactCsrAttempts := by
  have cert : exactCsrAttempts.filter (fun entry => entry.family == 42) =
      configIdentityAttempts := by decide
  intro entry member
  have filtered : entry ∈ exactCsrAttempts.filter (fun entry => entry.family == 42) := by
    rw [cert]
    exact member
  exact (List.mem_filter.mp filtered).1

theorem admitted_stable_asset_policy_binding {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin).assetId =
      statement.stablecoin.assetId ∧
    (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin).policyVersion =
      statement.stablecoin.policyVersion := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace domain.2.2
  have one := equations 1 (.constant 1) (by decide)
  have asset := equations 88 (.publicWord 84) (by decide)
  have policy := equations 89 (.publicWord 85) (by decide)
  simp only [expressionField, Nat.cast_one] at one asset policy
  have assetMember := exact_config_identity_attempts
    (attempt 19320 42 0 0 [(41408, 1)] 88) (by decide)
  have policyMember := exact_config_identity_attempts
    (attempt 19321 42 1 0 [(41409, 1)] 89) (by decide)
  have ae := accepted_csr_attempt_field_equality (attempts _ assetMember)
  have pe := accepted_csr_attempt_field_equality (attempts _ policyMember)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, one, asset, policy, one_mul, add_zero] at ae pe
  have an := canonical_nat_cast_injective (packed_word_canonical domain.2.2.2.1 _)
    (canonical_public_coordinate domain.2.2.1 (index := 84) (by decide)).2 ae
  have pn := canonical_nat_cast_injective (packed_word_canonical domain.2.2.2.1 _)
    (canonical_public_coordinate domain.2.2.1 (index := 85) (by decide)).2 pe
  have pubAsset : publicWords.getD 84 0 = statement.stablecoin.assetId := by
    rw [← domain.1]
    have encoded := encoded_stable_public_word statement domain.2.1 1
    simpa [encodeStablecoinPublic] using encoded
  have pubPolicy : publicWords.getD 85 0 = statement.stablecoin.policyVersion := by
    rw [← domain.1]
    have encoded := encoded_stable_public_word statement domain.2.1 2
    simpa [encodeStablecoinPublic] using encoded
  constructor
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 0 = _
    rw [admitted_stable_config_word_source domain (by decide : 0 < 55)]
    change packed.getD 41408 0 = statement.stablecoin.assetId
    exact an.trans pubAsset
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 1 = _
    rw [admitted_stable_config_word_source domain (by decide : 1 < 55)]
    change packed.getD 41409 0 = statement.stablecoin.policyVersion
    exact pn.trans pubPolicy

theorem admitted_enabled_asset_nonzero {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    statement.stablecoin.assetId ≠ 0 := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _⟩ := domain.2.1
  rcases enabled with mint | burn
  · simp only [CanonicalCompatibility, mint] at compatibility
    obtain ⟨_, _, _, _, _, _, asset, _, _, _, nonzero, _⟩ := compatibility
    rw [asset] at nonzero
    exact nonzero
  · simp only [CanonicalCompatibility, burn] at compatibility
    obtain ⟨_, _, _, _, _, _, asset, _, _, _, nonzero, _⟩ := compatibility
    rw [asset] at nonzero
    exact nonzero

/-- The exact typed common stablecoin predicate follows from accepted source constraints. -/
theorem admitted_stable_common_valid {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    exactV8StablecoinCommonValid
      (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin)
      (decodeV8StablecoinBefore (projectTypedWitness statement packed).stablecoin) := by
  have rawDirection : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2 := by
    rw [(admitted_stable_public_counters domain).1]
    rcases enabled with mint | burn
    · left; rw [mint]; rfl
    · right; rw [burn]; rfl
  have asset := (admitted_stable_asset_policy_binding domain).1
  have nonzero := admitted_enabled_asset_nonzero domain enabled
  have roles := accepted_role_digest_properties domain.2.2 rawDirection
  have commitments := admitted_config_commitments domain
  have decimal := accepted_stable_decimal_scale domain.2.2 rawDirection
  have amounts := accepted_stable_nine_value_bounds domain.2.2
  have sequences := accepted_stable_sequence_epoch_bounds domain.2.2
  have cap := (accepted_stable_epoch_and_cap_inequalities domain.2.2).2.1
  have enabledAt := (accepted_stable_odd_range domain.2.2
    (spec := ⟨7, false, 41411, 0, 112, 31, 33⟩) (by decide)).2
  change packedWord packed 41411 < 2 ^ 63 at enabledAt
  have retiredAt := (accepted_stable_odd_range domain.2.2
    (spec := ⟨8, false, 41413, 0, 143, 31, 34⟩) (by decide)).2
  change packedWord packed 41413 < 2 ^ 63 at retiredAt
  have oracleSubmittedAt := (accepted_stable_odd_range domain.2.2
    (spec := ⟨9, false, 41423, 0, 174, 31, 35⟩) (by decide)).2
  change packedWord packed 41423 < 2 ^ 63 at oracleSubmittedAt
  have oracleMaxAge := (accepted_stable_odd_range domain.2.2
    (spec := ⟨10, false, 41424, 0, 205, 31, 36⟩) (by decide)).2
  change packedWord packed 41424 < 2 ^ 63 at oracleMaxAge
  have attestationCreatedAt := (accepted_stable_odd_range domain.2.2
    (spec := ⟨11, false, 41428, 0, 236, 31, 37⟩) (by decide)).2
  change packedWord packed 41428 < 2 ^ 63 at attestationCreatedAt
  have attestationMaxAge := (accepted_stable_odd_range domain.2.2
    (spec := ⟨12, false, 41431, 0, 267, 31, 38⟩) (by decide)).2
  change packedWord packed 41431 < 2 ^ 63 at attestationMaxAge
  have collateralScale := (accepted_stable_odd_range domain.2.2
    (spec := ⟨13, false, 41455, 0, 298, 31, 39⟩) (by decide)).2
  change packedWord packed 41455 < 2 ^ 63 at collateralScale
  have configWord := fun word bound => admitted_stable_config_word_source domain (word := word) bound
  have beforeWord := fun counter bound => admitted_stable_before_word_source domain (counter := counter) bound
  unfold exactV8StablecoinCommonValid
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [asset]
    exact nonzero
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 14 < stablecoinValueBound
    rw [configWord 14 (by decide)]
    exact amounts.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 19 < stablecoinValueBound
    rw [configWord 19 (by decide)]
    exact amounts.2.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 56 < stablecoinValueBound
    rw [beforeWord 1 (by decide)]
    exact amounts.2.2.2.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 57 < stablecoinValueBound
    rw [beforeWord 2 (by decide)]
    exact amounts.2.2.2.2.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 3 < stablecoinScalarBound
    rw [configWord 3 (by decide)]
    exact enabledAt
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 5 < stablecoinScalarBound
    rw [configWord 5 (by decide)]
    exact retiredAt
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 15 < stablecoinScalarBound
    rw [configWord 15 (by decide)]
    exact oracleSubmittedAt
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 16 < stablecoinScalarBound
    rw [configWord 16 (by decide)]
    exact oracleMaxAge
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 20 < stablecoinScalarBound
    rw [configWord 20 (by decide)]
    exact attestationCreatedAt
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 23 < stablecoinScalarBound
    rw [configWord 23 (by decide)]
    exact attestationMaxAge
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 47 < stablecoinScalarBound
    rw [configWord 47 (by decide)]
    exact collateralScale
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 55 < stablecoinScalarBound
    rw [beforeWord 0 (by decide)]
    have bound := sequences.2.2.1
    norm_num [stablecoinScalarBound] at bound ⊢
    omega
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 58 < stablecoinScalarBound
    rw [beforeWord 3 (by decide)]
    exact sequences.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 56 ≤
      stableWitnessWord (projectTypedWitness statement packed).stablecoin 14
    rw [beforeWord 1 (by decide), configWord 14 (by decide)]
    exact cap
  · change (configCommitments (decodeV8StablecoinConfig
      (projectTypedWitness statement packed).stablecoin)).all
        (fun digest => digest.any (fun word => decide (word ≠ 0))) = true
    rw [commitments]
    exact roles.1
  · change DigestListPairwiseDistinct (configCommitments
      (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin))
    rw [commitments]
    exact roles.2
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 46 ≤ 18
    rw [configWord 46 (by decide)]
    exact decimal.1
  · change stableWitnessWord (projectTypedWitness statement packed).stablecoin 47 =
      10 ^ stableWitnessWord (projectTypedWitness statement packed).stablecoin 46
    rw [configWord 47 (by decide), configWord 46 (by decide)]
    exact decimal.2


end HegemonCrypto.SmallWood.V8Smz9SemanticStableCommonEndpoint
