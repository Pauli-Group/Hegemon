import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom
import HegemonCrypto.SmallWoodV8Smz9WholeViewObservation
import Mathlib.Logic.Equiv.Set

/-!
# Literal finite counter-block compiler

A vector oracle contains raw 512-bit blocks, not already sampled field elements.
The construction retains the entire complement of the framed counter domain.
Its compute/answer/uncompute circuit has exactly two vector-oracle calls and
acts correctly on arbitrary superpositions with arbitrary private workspace.
No extraction-success, SHA-512 security, or reprogramming bound is assumed here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler

open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9RuntimeDistribution
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 4096
set_option maxHeartbeats 800000

abbrev Byte := HegemonCrypto.CanonicalBytes.Byte
abbrev RawInput := List Byte

/-- This is the byte prefix, including every length frame, before the counter. -/
def sourcePrefix (role : List Byte) (words : List ℕ) : RawInput :=
  encodeLE 8 53 ++ V8Smz9WholeViewObservation.smz9ProfileDomain ++
    encodeLE 8 role.length ++ role ++ encodeLE 8 words.length ++
      (words.map (encodeLE 8)).flatten

def counterInput (leading : RawInput) (counter : Fin (2 ^ 64)) : RawInput :=
  leading ++ encodeLE 8 counter.val

theorem source_counter_input_is_exact_raw_key (role : List Byte) (words : List ℕ)
    (counter : Fin (2 ^ 64)) :
    counterInput (sourcePrefix role words) counter =
      (V8Smz9WholeViewObservation.RawSha512OracleKey.mk
        (some V8Smz9WholeViewObservation.smz9ProfileDomain) role words counter.val).preimage := by
  simp only [counterInput, sourcePrefix,
    V8Smz9WholeViewObservation.RawSha512OracleKey.preimage, List.append_assoc]
  rfl

/-- Different prefixes or different u64 counters are different literal inputs.
This is byte framing injectivity, not a collision-resistance premise. -/
theorem counter_input_injective : Function.Injective
    (fun key : RawInput × Fin (2 ^ 64) => counterInput key.1 key.2) := by
  intro left right equal
  have lengths := congrArg List.length equal
  simp only [counterInput, List.length_append, encodeLE_length] at lengths
  have prefixLengths : left.1.length = right.1.length := by omega
  have parts := List.append_inj equal prefixLengths
  have counters : left.2 = right.2 := by
    apply Fin.ext
    exact encodeLE_injective_of_lt
      left.2.isLt right.2.isLt parts.2
  exact Prod.ext parts.1 counters

/-- Executable suffix routing: no table search or preimage inversion is needed
to recognize a literal counter key. Prefix bytes need not be a valid SMZ9 frame. -/
def parseRawCounterSuffix (input : RawInput) : Option (RawInput × Fin (2 ^ 64)) :=
  if 8 ≤ input.length then
    let candidate := decodeLE (input.drop (input.length - 8))
    if bounded : candidate < 2 ^ 64 then
      some (input.take (input.length - 8), ⟨candidate, bounded⟩)
    else none
  else none

theorem raw_counter_suffix_roundtrip (leading : RawInput) (counter : Fin (2 ^ 64)) :
    parseRawCounterSuffix (counterInput leading counter) = some (leading, counter) := by
  have counterMod : counter.val % 18446744073709551616 = counter.val :=
    Nat.mod_eq_of_lt counter.isLt
  simp [parseRawCounterSuffix, counterInput, encodeLE_length, decodeLE_encodeLE,
    counterMod]

/-- A bounded counter prefix embeds into the complete raw-byte input domain. -/
def boundedCounterInput (blocks : ℕ) (bound : blocks ≤ 2 ^ 64)
    (key : RawInput × Fin blocks) : RawInput :=
  counterInput key.1 ⟨key.2.val, lt_of_lt_of_le key.2.isLt bound⟩

theorem bounded_counter_input_injective (blocks : ℕ) (bound : blocks ≤ 2 ^ 64) :
    Function.Injective (boundedCounterInput blocks bound) := by
  intro left right equal
  have same : (left.1, (⟨left.2.val, lt_of_lt_of_le left.2.isLt bound⟩ : Fin (2 ^ 64))) =
      (right.1, (⟨right.2.val, lt_of_lt_of_le right.2.isLt bound⟩ : Fin (2 ^ 64))) :=
    counter_input_injective equal
  apply Prod.ext
  · exact congrArg (fun key : RawInput × Fin (2 ^ 64) => key.1) same
  · apply Fin.ext
    exact congrArg (fun key => key.2.val) same

/-- Parse all common SMZ9 length frames and preserve the raw counter. -/
def parseSourceFrame (input : RawInput) : Option (List Byte × List Byte × ℕ) := do
  let (profileLength, afterProfileLength) ← readFixed 8 input
  let (profile, afterProfile) ← readFixed (decodeLE profileLength) afterProfileLength
  let (roleLength, afterRoleLength) ← readFixed 8 afterProfile
  let (role, afterRole) ← readFixed (decodeLE roleLength) afterRoleLength
  let (wordCount, afterWordCount) ← readFixed 8 afterRole
  let (payload, afterPayload) ← readFixed (8 * decodeLE wordCount) afterWordCount
  let (counter, suffix) ← readFixed 8 afterPayload
  if profile = V8Smz9WholeViewObservation.smz9ProfileDomain ∧ suffix = []
    then some (role, payload, decodeLE counter) else none

theorem parse_source_frame_roundtrip (role : List Byte) (words : List ℕ)
    (counter : Fin (2 ^ 64))
    (roleBound : role.length < 256 ^ 8) (wordBound : words.length < 256 ^ 8) :
    parseSourceFrame (counterInput (sourcePrefix role words) counter) =
      some (role, (words.map (encodeLE 8)).flatten, counter.val) := by
  have payloadLength : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    clear wordBound
    induction words with
    | nil => rfl
    | cons word words induction => simp [encodeLE_length, induction, Nat.mul_add, Nat.add_comm]
  have profileLength : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  have roleMod : role.length % 18446744073709551616 = role.length := Nat.mod_eq_of_lt roleBound
  have wordMod : words.length % 18446744073709551616 = words.length := Nat.mod_eq_of_lt wordBound
  have counterBound : counter.val < 256 ^ 8 := counter.isLt
  have counterMod : counter.val % 18446744073709551616 = counter.val := Nat.mod_eq_of_lt counterBound
  simp [parseSourceFrame, counterInput, sourcePrefix, List.append_assoc, readFixed,
    encodeLE_length, decodeLE_encodeLE, roleMod, wordMod, profileLength,
    payloadLength]
  have counterTake : (encodeLE 8 counter.val).take 8 = encodeLE 8 counter.val := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 counter.val))
  rw [counterTake, decodeLE_encodeLE]
  exact counterMod

def typedWordPayload : List (Fin (2 ^ 64)) → List Byte
  | [] => []
  | word :: words => encodeLE 8 word.val ++ typedWordPayload words

theorem typed_word_payload_length (words : List (Fin (2 ^ 64))) :
    (typedWordPayload words).length = 8 * words.length := by
  induction words with
  | nil => rfl
  | cons word words induction => simp [typedWordPayload, encodeLE_length, induction, Nat.mul_add, Nat.add_comm]

theorem typed_word_payload_is_source_payload (words : List (Fin (2 ^ 64))) :
    typedWordPayload words = ((words.map Fin.val).map (encodeLE 8)).flatten := by
  induction words with
  | nil => rfl
  | cons word words induction => simp [typedWordPayload, induction]

theorem typed_word_payload_injective : Function.Injective typedWordPayload := by
  intro left
  induction left with
  | nil =>
    intro right equal
    have lengths := congrArg List.length equal
    rw [typed_word_payload_length, typed_word_payload_length] at lengths
    have empty : right.length = 0 := by simpa using lengths
    exact (List.length_eq_zero_iff.mp empty).symm
  | cons word words induction =>
    intro right equal
    cases right with
    | nil =>
      have lengths := congrArg List.length equal
      rw [typed_word_payload_length, typed_word_payload_length] at lengths
      simp at lengths
    | cons other others =>
      have parts := List.append_inj equal
        ((encodeLE_length 8 word.val).trans (encodeLE_length 8 other.val).symm)
      have headEq : word = other := Fin.ext (encodeLE_injective_of_lt word.isLt other.isLt parts.1)
      exact congrArg₂ List.cons headEq (induction parts.2)

/-- Complete role/u64-word/counter injectivity is derived through the parser.
Noncanonical unbounded Nat words are deliberately not given this claim. -/
theorem typed_source_counter_frame_injective
    (leftRole rightRole : List Byte) (leftWords rightWords : List (Fin (2 ^ 64)))
    (leftCounter rightCounter : Fin (2 ^ 64))
    (leftRoleBound : leftRole.length < 256 ^ 8) (rightRoleBound : rightRole.length < 256 ^ 8)
    (leftWordBound : leftWords.length < 256 ^ 8) (rightWordBound : rightWords.length < 256 ^ 8)
    (equal : counterInput (sourcePrefix leftRole (leftWords.map Fin.val)) leftCounter =
      counterInput (sourcePrefix rightRole (rightWords.map Fin.val)) rightCounter) :
    leftRole = rightRole ∧ leftWords = rightWords ∧ leftCounter = rightCounter := by
  have parsed := congrArg parseSourceFrame equal
  rw [parse_source_frame_roundtrip leftRole _ leftCounter leftRoleBound (by simpa using leftWordBound),
    parse_source_frame_roundtrip rightRole _ rightCounter rightRoleBound (by simpa using rightWordBound)] at parsed
  have parts := Option.some.inj parsed
  refine ⟨congrArg Prod.fst parts, ?_, ?_⟩
  · apply typed_word_payload_injective
    simpa only [typed_word_payload_is_source_payload] using congrArg (fun value => value.2.1) parts
  · exact Fin.ext (congrArg (fun value => value.2.2) parts)

section Factorization

variable {Raw Prefix Counter Output : Type*}

abbrev Complement (encode : Prefix × Counter → Raw) :=
  { input : Raw // input ∉ Set.range encode }

/-- All unselected raw inputs, including malformed frames, remain present. -/
def fullRawDomainEquiv (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) :
    ((Prefix × Counter) ⊕ Complement encode) ≃ Raw :=
  (Equiv.sumCongr (Equiv.ofInjective encode injective) (Equiv.refl _)).trans
    (Equiv.Set.sumCompl (Set.range encode))

@[simp] theorem full_raw_domain_on_counter (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (key : Prefix × Counter) :
    fullRawDomainEquiv encode injective (.inl key) = encode key := rfl

@[simp] theorem full_raw_domain_on_complement (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (key : Complement encode) :
    fullRawDomainEquiv encode injective (.inr key) = key.val := rfl

@[simp] theorem full_raw_domain_inverse_counter (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (key : Prefix × Counter) :
    (fullRawDomainEquiv encode injective).symm (encode key) = .inl key :=
  (fullRawDomainEquiv encode injective).symm_apply_apply (.inl key)

@[simp] theorem full_raw_domain_inverse_complement (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (key : Complement encode) :
    (fullRawDomainEquiv encode injective).symm key.val = .inr key :=
  (fullRawDomainEquiv encode injective).symm_apply_apply (.inr key)

/-- Literal raw tables factor into counter vectors and an unchanged complement. -/
def rawTableFactorization (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) :
    (Raw → Output) ≃ (Prefix → Counter → Output) × (Complement encode → Output) :=
  ((Equiv.arrowCongr (fullRawDomainEquiv encode injective) (Equiv.refl Output)).symm.trans
    (Equiv.sumArrowEquivProdArrow (Prefix × Counter) (Complement encode) Output)).trans
      (Equiv.prodCongr (Equiv.curry Prefix Counter Output) (Equiv.refl _))

@[simp] theorem raw_table_factorization_block (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (oracle : Raw → Output)
    (leading : Prefix) (counter : Counter) :
    (rawTableFactorization encode injective oracle).1 leading counter =
      oracle (encode (leading, counter)) := rfl

@[simp] theorem raw_table_factorization_complement (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) (oracle : Raw → Output)
    (input : Complement encode) :
    (rawTableFactorization encode injective oracle).2 input = oracle input.val := rfl

/-- Uniformity is transported through a proved bijection, not assumed for a wrapper hash.
The finite-domain theorem applies to each finite raw-query universe. -/
theorem uniform_raw_table_factorization [Fintype Raw] [Fintype Prefix] [Fintype Counter]
    [Fintype Output] [Nonempty Output] (encode : Prefix × Counter → Raw)
    (injective : Function.Injective encode) :
    pmfMap (uniformFintypePMF (Raw → Output)) (rawTableFactorization encode injective) =
      uniformFintypePMF ((Prefix → Counter → Output) × (Complement encode → Output)) := by
  exact V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv (rawTableFactorization encode injective)

theorem factored_uniform_mass_is_product [Fintype Raw] [Fintype Prefix] [Fintype Counter]
    [Fintype Output] [Nonempty Output] (encode : Prefix × Counter → Raw)
    (vector : Prefix → Counter → Output) (other : Complement encode → Output) :
    uniformFintypePMF ((Prefix → Counter → Output) × (Complement encode → Output))
        (vector, other) = uniformFintypePMF (Prefix → Counter → Output) vector *
          uniformFintypePMF (Complement encode → Output) other := by
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul]
  exact ENNReal.mul_inv (Or.inr (by simp)) (Or.inl (by simp))

end Factorization

abbrev CounterQueryBasis (Prefix Counter Other Output Workspace : Type*) :=
  ((Prefix × Counter) ⊕ Other) × Output × (Counter → Output) × Workspace

def routedPrefix {Prefix Counter Other : Type*} (dummy : Prefix) :
    (Prefix × Counter) ⊕ Other → Prefix := Sum.elim Prod.fst (fun _ => dummy)

def vectorComputeEquiv {Prefix Counter Other Output Workspace : Type*} [AddGroup Output]
    (vector : Prefix → Counter → Output) (dummy : Prefix) :
    CounterQueryBasis Prefix Counter Other Output Workspace ≃
      CounterQueryBasis Prefix Counter Other Output Workspace where
  toFun b := (b.1, b.2.1, b.2.2.1 + vector (routedPrefix dummy b.1), b.2.2.2)
  invFun b := (b.1, b.2.1, b.2.2.1 - vector (routedPrefix dummy b.1), b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

theorem vector_uncompute_is_same_xor_query {Prefix Counter Other Workspace : Type*}
    (vector : Prefix → Counter → DigestRegister) (dummy : Prefix)
    (basis : CounterQueryBasis Prefix Counter Other DigestRegister Workspace) :
    (vectorComputeEquiv vector dummy).symm basis = vectorComputeEquiv vector dummy basis := by
  have negVector : -(vector (routedPrefix dummy basis.1)) =
      vector (routedPrefix dummy basis.1) := by
    funext counter
    exact digest_register_neg_eq_self _
  change (basis.1, basis.2.1, basis.2.2.1 - vector (routedPrefix dummy basis.1), basis.2.2.2) = _
  rw [sub_eq_add_neg, negVector]
  rfl

def selectCounterEquiv {Prefix Counter Other Output Workspace : Type*} [AddGroup Output]
    (other : Other → Output) :
    CounterQueryBasis Prefix Counter Other Output Workspace ≃
      CounterQueryBasis Prefix Counter Other Output Workspace where
  toFun b := (b.1, b.2.1 + Sum.elim (fun key => b.2.2.1 key.2) other b.1,
    b.2.2.1, b.2.2.2)
  invFun b := (b.1, b.2.1 - Sum.elim (fun key => b.2.2.1 key.2) other b.1,
    b.2.2.1, b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

def twoVectorQueryEquiv {Prefix Counter Other Output Workspace : Type*} [AddGroup Output]
    (vector : Prefix → Counter → Output) (other : Other → Output) (dummy : Prefix) :
    CounterQueryBasis Prefix Counter Other Output Workspace ≃
      CounterQueryBasis Prefix Counter Other Output Workspace :=
  ((vectorComputeEquiv vector dummy).trans (selectCounterEquiv other)).trans
    (vectorComputeEquiv vector dummy).symm

theorem two_vector_queries_clean_basis {Prefix Counter Other Output Workspace : Type*}
    [AddGroup Output] (vector : Prefix → Counter → Output) (other : Other → Output)
    (dummy : Prefix) (input : (Prefix × Counter) ⊕ Other) (answer : Output) (work : Workspace) :
    twoVectorQueryEquiv vector other dummy (input, answer, 0, work) =
      (input, answer + Sum.elim (fun key => vector key.1 key.2) other input, 0, work) := by
  cases input <;> simp [twoVectorQueryEquiv, vectorComputeEquiv, selectCounterEquiv, routedPrefix]

def twoVectorQueryLinearEquiv {Prefix Counter Other Output Workspace : Type*} [AddGroup Output]
    (vector : Prefix → Counter → Output) (other : Other → Output) (dummy : Prefix) :
    (CounterQueryBasis Prefix Counter Other Output Workspace → ℂ) ≃ₗ[ℂ]
      (CounterQueryBasis Prefix Counter Other Output Workspace → ℂ) where
  toFun state := state ∘ (twoVectorQueryEquiv vector other dummy).symm
  invFun state := state ∘ twoVectorQueryEquiv vector other dummy
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem two_vector_queries_preserve_squared_hilbert_norm
    {Prefix Counter Other Output Workspace : Type*}
    [Fintype Prefix] [Fintype Counter] [Fintype Other] [Fintype Output] [Fintype Workspace]
    [AddGroup Output] (vector : Prefix → Counter → Output) (other : Other → Output)
    (dummy : Prefix) (state : CounterQueryBasis Prefix Counter Other Output Workspace → ℂ) :
    (∑ basis, Complex.normSq (twoVectorQueryLinearEquiv vector other dummy state basis)) =
      ∑ basis, Complex.normSq (state basis) := by
  exact (twoVectorQueryEquiv vector other dummy).symm.sum_comp
    (fun basis => Complex.normSq (state basis))

def cleanVectorState {Prefix Counter Other Output Workspace : Type*} [Zero Output]
    (state : QueryBasis ((Prefix × Counter) ⊕ Other) Output Workspace → ℂ) :
    CounterQueryBasis Prefix Counter Other Output Workspace → ℂ :=
  fun basis => if basis.2.2.1 = 0 then state (basis.1, basis.2.1, basis.2.2.2) else 0

theorem two_vector_queries_coherent_simulation
    {Prefix Counter Other Output Workspace : Type*} [AddGroup Output]
    (vector : Prefix → Counter → Output) (other : Other → Output) (dummy : Prefix)
    (state : QueryBasis ((Prefix × Counter) ⊕ Other) Output Workspace → ℂ) :
    twoVectorQueryLinearEquiv vector other dummy (cleanVectorState state) =
      cleanVectorState
        (oracleQueryLinearEquiv (Sum.elim (fun key => vector key.1 key.2) other) state) := by
  funext basis
  rcases basis with ⟨input, answer, auxiliary, work⟩
  cases input <;> by_cases clean : auxiliary = 0
  all_goals simp [twoVectorQueryLinearEquiv, twoVectorQueryEquiv, vectorComputeEquiv,
    selectCounterEquiv, routedPrefix, cleanVectorState, oracleQueryLinearEquiv,
    oracleQueryBasisEquiv, clean]

def rawQueryBasisEquiv {Raw Prefix Counter Output Workspace : Type*}
    (encode : Prefix × Counter → Raw) (injective : Function.Injective encode) :
    CounterQueryBasis Prefix Counter (Complement encode) Output Workspace ≃
      Raw × Output × (Counter → Output) × Workspace :=
  Equiv.prodCongr (fullRawDomainEquiv encode injective) (Equiv.refl _)

/-- Conjugating by the oracle-free input partition yields an operator on the
original raw-input register, not just on an ideal typed query alphabet. -/
def compiledRawQueryEquiv {Raw Prefix Counter Output Workspace : Type*} [AddGroup Output]
    (encode : Prefix × Counter → Raw) (injective : Function.Injective encode)
    (oracle : Raw → Output) (dummy : Prefix) :
    (Raw × Output × (Counter → Output) × Workspace) ≃
      (Raw × Output × (Counter → Output) × Workspace) :=
  ((rawQueryBasisEquiv encode injective).symm.trans
    (twoVectorQueryEquiv (rawTableFactorization encode injective oracle).1
      (rawTableFactorization encode injective oracle).2 dummy)).trans
        (rawQueryBasisEquiv encode injective)

theorem compiled_raw_query_clean_basis {Raw Prefix Counter Output Workspace : Type*}
    [AddGroup Output] (encode : Prefix × Counter → Raw) (injective : Function.Injective encode)
    (oracle : Raw → Output) (dummy : Prefix) (input : Raw) (answer : Output) (work : Workspace) :
    compiledRawQueryEquiv encode injective oracle dummy (input, answer, 0, work) =
      (input, answer + oracle input, 0, work) := by
  obtain ⟨key, rfl⟩ := (fullRawDomainEquiv encode injective).surjective input
  cases key <;>
    simp [compiledRawQueryEquiv, rawQueryBasisEquiv, two_vector_queries_clean_basis]

/-- A complement input receives its own padded vector address. Hence the
efficient query simulation need not enumerate a supposedly free complement table. -/
def paddedCoordinate {Prefix Counter Other : Type*} (dummyCounter : Counter) :
    (Prefix × Counter) ⊕ Other → (Prefix ⊕ Other) × Counter
  | .inl (leading, counter) => (.inl leading, counter)
  | .inr other => (.inr other, dummyCounter)

theorem padded_coordinate_injective {Prefix Counter Other : Type*} (dummyCounter : Counter) :
    Function.Injective (paddedCoordinate (Prefix := Prefix) (Other := Other) dummyCounter) := by
  intro left right equal
  cases left with
  | inl left =>
    cases right with
    | inl right =>
      have parts : left.1 = right.1 ∧ left.2 = right.2 := by simpa [paddedCoordinate] using equal
      exact congrArg Sum.inl (Prod.ext parts.1 parts.2)
    | inr right => simp [paddedCoordinate] at equal
  | inr left =>
    cases right with
    | inl right => simp [paddedCoordinate] at equal
    | inr right => simpa [paddedCoordinate] using equal

def fullRawPaddedCoordinate {Raw Prefix Counter : Type*}
    (encode : Prefix × Counter → Raw) (injective : Function.Injective encode)
    (dummyCounter : Counter) : Raw → (Prefix ⊕ Complement encode) × Counter :=
  paddedCoordinate dummyCounter ∘ (fullRawDomainEquiv encode injective).symm

theorem full_raw_padded_coordinate_injective {Raw Prefix Counter : Type*}
    (encode : Prefix × Counter → Raw) (injective : Function.Injective encode)
    (dummyCounter : Counter) :
    Function.Injective (fullRawPaddedCoordinate encode injective dummyCounter) :=
  (padded_coordinate_injective dummyCounter).comp (fullRawDomainEquiv encode injective).symm.injective

private theorem uniformProductBind {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] :
    uniformFintypePMF (A × B) = (uniformFintypePMF A).bind fun a =>
      pmfMap (uniformFintypePMF B) (fun b => (a, b)) := by
  apply PMF.ext
  intro pair
  rcases pair with ⟨a, b⟩
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul,
    PMF.bind_apply, pmfMap, Function.comp_apply, PMF.pure_apply, Prod.mk.injEq]
  simp [ite_and]
  exact @ENNReal.mul_inv (Fintype.card A : ℝ≥0∞) (Fintype.card B : ℝ≥0∞)
    (Or.inr (by simp)) (Or.inl (by simp))

theorem uniform_product_first_marginal {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] :
    pmfMap (uniformFintypePMF (A × B)) Prod.fst = uniformFintypePMF A := by
  rw [uniformProductBind]
  simp [pmfMap, PMF.bind_bind, Function.comp_def]

theorem uniform_vector_block_marginal {Counter Output : Type*}
    [Fintype Counter] [Fintype Output] [Nonempty Output] (counter : Counter) :
    pmfMap (uniformFintypePMF (Counter → Output)) (fun vector => vector counter) =
      uniformFintypePMF Output := by
  let split := Equiv.piSplitAt counter (fun _ : Counter => Output)
  have splitLaw := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv split
  have pushed := congrArg (fun law => pmfMap law Prod.fst) splitLaw
  rw [pmfMap_comp, uniform_product_first_marginal] at pushed
  exact pushed

theorem digest_register_cardinality : Fintype.card DigestRegister = 2 ^ 512 := by
  simp only [DigestRegister, Fintype.card_fun, Fintype.card_fin, ZMod.card]

/-- A selected raw block retains 512-bit point probability even when the
complete oracle answer contains many counter blocks. -/
theorem uniform_vector_block_point_mass {Counter : Type*} [Fintype Counter]
    (counter : Counter) (digest : DigestRegister) :
    pmfMap (uniformFintypePMF (Counter → DigestRegister)) (fun vector => vector counter) digest =
      (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  rw [uniform_vector_block_marginal, uniformFintypePMF_apply, digest_register_cardinality]
  simp only [Nat.cast_pow, Nat.cast_ofNat]

/-- A uniform complete table remains uniform on any injectively selected
coordinates. Unused padded blocks are genuine independent coins. -/
theorem uniform_table_injective_restriction {Raw Full Output : Type*}
    [Fintype Raw] [Fintype Full] [Fintype Output] [Nonempty Output]
    (select : Raw → Full) (injective : Function.Injective select) :
    pmfMap (uniformFintypePMF (Full → Output)) (fun table input => table (select input)) =
      uniformFintypePMF (Raw → Output) := by
  let outside := { input : Full // input ∉ Set.range select }
  let partition : Raw ⊕ outside ≃ Full :=
    (Equiv.sumCongr (Equiv.ofInjective select injective) (Equiv.refl _)).trans
      (Equiv.Set.sumCompl (Set.range select))
  let split : (Full → Output) ≃ (Raw → Output) × (outside → Output) :=
    (Equiv.arrowCongr partition (Equiv.refl Output)).symm.trans
      (Equiv.sumArrowEquivProdArrow Raw outside Output)
  have splitLaw := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv split
  have pushed := congrArg (fun law => pmfMap law Prod.fst) splitLaw
  rw [pmfMap_comp, uniform_product_first_marginal] at pushed
  exact pushed

theorem padded_vector_oracle_has_exact_uniform_raw_law
    {Raw Key Counter Output : Type*} [Fintype Raw] [Fintype Key] [Fintype Counter]
    [Fintype Output] [Nonempty Output]
    (address : Raw → Key × Counter) (injective : Function.Injective address) :
    pmfMap (uniformFintypePMF (Key → Counter → Output))
      (fun vector input => vector (address input).1 (address input).2) =
        uniformFintypePMF (Raw → Output) := by
  letI : DecidableEq (Key × Counter) := Classical.decEq _
  have uncurried := V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv
    (Equiv.curry Key Counter Output).symm
  have pushed := congrArg
    (fun law => pmfMap law (fun table input => table (address input))) uncurried
  rw [pmfMap_comp] at pushed
  exact pushed.trans (uniform_table_injective_restriction (Output := Output) address injective)

abbrev RoutedQueryBasis (Raw Counter Output Workspace : Type*) :=
  Raw × Output × (Counter → Output) × Workspace

def routedVectorComputeEquiv {Raw Key Counter Output Workspace : Type*} [AddGroup Output]
    (vector : Key → Counter → Output) (address : Raw → Key × Counter) :
    RoutedQueryBasis Raw Counter Output Workspace ≃ RoutedQueryBasis Raw Counter Output Workspace where
  toFun b := (b.1, b.2.1, b.2.2.1 + vector (address b.1).1, b.2.2.2)
  invFun b := (b.1, b.2.1, b.2.2.1 - vector (address b.1).1, b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

def routedCounterSelectEquiv {Raw Key Counter Output Workspace : Type*} [AddGroup Output]
    (address : Raw → Key × Counter) :
    RoutedQueryBasis Raw Counter Output Workspace ≃ RoutedQueryBasis Raw Counter Output Workspace where
  toFun b := (b.1, b.2.1 + b.2.2.1 (address b.1).2, b.2.2.1, b.2.2.2)
  invFun b := (b.1, b.2.1 - b.2.2.1 (address b.1).2, b.2.2.1, b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

def twoRoutedVectorQueryEquiv {Raw Key Counter Output Workspace : Type*} [AddGroup Output]
    (vector : Key → Counter → Output) (address : Raw → Key × Counter) :
    RoutedQueryBasis Raw Counter Output Workspace ≃ RoutedQueryBasis Raw Counter Output Workspace :=
  ((routedVectorComputeEquiv vector address).trans (routedCounterSelectEquiv address)).trans
    (routedVectorComputeEquiv vector address).symm

theorem two_routed_vector_queries_clean_basis {Raw Key Counter Output Workspace : Type*}
    [AddGroup Output] (vector : Key → Counter → Output) (address : Raw → Key × Counter)
    (input : Raw) (answer : Output) (work : Workspace) :
    twoRoutedVectorQueryEquiv vector address (input, answer, 0, work) =
      (input, answer + vector (address input).1 (address input).2, 0, work) := by
  simp [twoRoutedVectorQueryEquiv, routedVectorComputeEquiv, routedCounterSelectEquiv]

def twoRoutedVectorQueryLinearEquiv {Raw Key Counter Output Workspace : Type*} [AddGroup Output]
    (vector : Key → Counter → Output) (address : Raw → Key × Counter) :
    (RoutedQueryBasis Raw Counter Output Workspace → ℂ) ≃ₗ[ℂ]
      (RoutedQueryBasis Raw Counter Output Workspace → ℂ) where
  toFun state := state ∘ (twoRoutedVectorQueryEquiv vector address).symm
  invFun state := state ∘ twoRoutedVectorQueryEquiv vector address
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem two_routed_queries_preserve_squared_hilbert_norm
    {Raw Key Counter Output Workspace : Type*}
    [Fintype Raw] [Fintype Counter] [Fintype Output] [Fintype Workspace]
    [AddGroup Output] (vector : Key → Counter → Output) (address : Raw → Key × Counter)
    (state : RoutedQueryBasis Raw Counter Output Workspace → ℂ) :
    (∑ basis, Complex.normSq (twoRoutedVectorQueryLinearEquiv vector address state basis)) =
      ∑ basis, Complex.normSq (state basis) := by
  exact (twoRoutedVectorQueryEquiv vector address).symm.sum_comp
    (fun basis => Complex.normSq (state basis))

def cleanRoutedVectorState {Raw Counter Output Workspace : Type*} [Zero Output]
    (state : QueryBasis Raw Output Workspace → ℂ) : RoutedQueryBasis Raw Counter Output Workspace → ℂ :=
  fun basis => if basis.2.2.1 = 0 then state (basis.1, basis.2.1, basis.2.2.2) else 0

theorem two_routed_vector_queries_coherent_simulation
    {Raw Key Counter Output Workspace : Type*} [AddGroup Output]
    (vector : Key → Counter → Output) (address : Raw → Key × Counter)
    (state : QueryBasis Raw Output Workspace → ℂ) :
    twoRoutedVectorQueryLinearEquiv vector address (cleanRoutedVectorState state) =
      cleanRoutedVectorState
        (oracleQueryLinearEquiv (fun input => vector (address input).1 (address input).2) state) := by
  funext basis
  rcases basis with ⟨input, answer, auxiliary, work⟩
  by_cases clean : auxiliary = 0
  all_goals simp [twoRoutedVectorQueryLinearEquiv, twoRoutedVectorQueryEquiv,
    routedVectorComputeEquiv, routedCounterSelectEquiv, cleanRoutedVectorState,
    oracleQueryLinearEquiv, oracleQueryBasisEquiv, clean]

theorem routed_vector_uncompute_is_same_xor_query {Raw Key Counter Workspace : Type*}
    (vector : Key → Counter → DigestRegister) (address : Raw → Key × Counter)
    (basis : RoutedQueryBasis Raw Counter DigestRegister Workspace) :
    (routedVectorComputeEquiv vector address).symm basis =
      routedVectorComputeEquiv vector address basis := by
  have negVector : -(vector (address basis.1).1) = vector (address basis.1).1 := by
    funext counter
    exact digest_register_neg_eq_self _
  change (basis.1, basis.2.1, basis.2.2.1 - vector (address basis.1).1, basis.2.2.2) = _
  rw [sub_eq_add_neg, negVector]
  rfl

/-- The exact eight little-endian words in each literal digest, in counter order. -/
def counterVectorCandidates {blocks : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest) : List ℕ :=
  (List.ofFn fun counter => (vector counter).rawWords).flatten

theorem counter_vector_candidate_count {blocks : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest) :
    (counterVectorCandidates vector).length = 8 * blocks := by
  simp [counterVectorCandidates, V8Smz9WholeViewObservation.Sha512Digest.rawWords,
    List.length_flatten, Nat.mul_comm, Function.comp_def]

def decodeFieldWord (candidate : ℕ) : Option V8Smz9WholeViewObservation.FieldWord :=
  if canonical : candidate < V8Smz9RuntimeRandomness.fieldModulus
    then some ⟨candidate, canonical⟩ else none

def acceptedFieldWords (candidates : List ℕ) : List V8Smz9WholeViewObservation.FieldWord :=
  candidates.filterMap decodeFieldWord

/-- The complete fixed vector is scanned, but only its first requested accepts
are returned. No fallback field value is supplied on exhaustion. -/
def parseCounterVector {blocks : ℕ} (requested : ℕ)
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest) :
    Option (List V8Smz9WholeViewObservation.FieldWord) :=
  let accepted := acceptedFieldWords (counterVectorCandidates vector)
  if requested ≤ accepted.length then some (accepted.take requested) else none

theorem counter_parser_success_iff {blocks requested : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest)
    (output : List V8Smz9WholeViewObservation.FieldWord) :
    parseCounterVector requested vector = some output ↔
      requested ≤ (acceptedFieldWords (counterVectorCandidates vector)).length ∧
        output = (acceptedFieldWords (counterVectorCandidates vector)).take requested := by
  by_cases enough : requested ≤ (acceptedFieldWords (counterVectorCandidates vector)).length
  all_goals simp [parseCounterVector, enough, eq_comm]

theorem counter_parser_output_length {blocks requested : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest)
    (output : List V8Smz9WholeViewObservation.FieldWord)
    (success : parseCounterVector requested vector = some output) :
    output.length = requested := by
  obtain ⟨enough, exactOutput⟩ := (counter_parser_success_iff vector output).mp success
  rw [exactOutput, List.length_take, min_eq_left enough]

theorem counter_parser_abort_iff {blocks requested : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest) :
    parseCounterVector requested vector = none ↔
      (acceptedFieldWords (counterVectorCandidates vector)).length < requested := by
  simp [parseCounterVector]

theorem zero_request_returns_empty {blocks : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest) :
    parseCounterVector 0 vector = some [] := by simp [parseCounterVector]

theorem exact_field_rejection_boundary :
    decodeFieldWord 18446744069414584320 = some ⟨18446744069414584320, by decide⟩ ∧
      decodeFieldWord 18446744069414584321 = none ∧
      decodeFieldWord 18446744073709551615 = none := by decide

def allRejectedDigest : V8Smz9WholeViewObservation.Sha512Digest :=
  ⟨List.replicate 64 255, by simp⟩

theorem literal_all_ff_block_aborts :
    parseCounterVector 1 (fun _ : Fin 1 => allRejectedDigest) = none := by decide

theorem literal_zero_block_supplies_eight_words :
    parseCounterVector 8 (fun _ : Fin 1 => V8Smz9WholeViewObservation.Sha512Digest.zero) =
      some (List.replicate 8 0) := by decide

def rejectedCandidateCount (candidates : List ℕ) : ℕ :=
  (candidates.filter fun candidate => V8Smz9RuntimeRandomness.fieldModulus ≤ candidate).length

theorem accepted_plus_rejected_is_total (candidates : List ℕ) :
    (acceptedFieldWords candidates).length + rejectedCandidateCount candidates = candidates.length := by
  induction candidates with
  | nil => rfl
  | cons candidate candidates induction =>
    by_cases canonical : candidate < V8Smz9RuntimeRandomness.fieldModulus
    · simp [acceptedFieldWords, decodeFieldWord, rejectedCandidateCount,
        canonical, Nat.not_le.mpr canonical] at *
      omega
    · simp [acceptedFieldWords, decodeFieldWord, rejectedCandidateCount,
        canonical, Nat.le_of_not_lt canonical] at *
      omega

theorem counter_parser_abort_iff_rejection_threshold {blocks requested : ℕ}
    (vector : Fin blocks → V8Smz9WholeViewObservation.Sha512Digest)
    (withinCapacity : requested ≤ 8 * blocks) :
    parseCounterVector requested vector = none ↔
      8 * blocks - requested + 1 ≤ rejectedCandidateCount (counterVectorCandidates vector) := by
  rw [counter_parser_abort_iff]
  have partition := accepted_plus_rejected_is_total (counterVectorCandidates vector)
  rw [counter_vector_candidate_count] at partition
  omega

/-- Compiler equality includes the abort outcome on the same literal block vector. -/
theorem factored_counter_parser_is_literal_raw_parser {Raw Prefix : Type*} {blocks : ℕ}
    (encode : Prefix × Fin blocks → Raw) (injective : Function.Injective encode)
    (oracle : Raw → V8Smz9WholeViewObservation.Sha512Digest) (leading : Prefix) (requested : ℕ) :
    parseCounterVector requested ((rawTableFactorization encode injective oracle).1 leading) =
      parseCounterVector requested (fun counter => oracle (encode (leading, counter))) := rfl

/-- Exactly the source's cap, including its zero-output special case. -/
def digestCallCap (requested : ℕ) : ℕ := if requested = 0 then 0 else (requested + 32 + 7) / 8

/-- Exact DECS count and a separate small-request regression example. The
4150-word request is not the full current PIOP gamma stream. -/
theorem exact_decs_and_example_counter_caps :
    digestCallCap 700 = 92 ∧ digestCallCap 4150 = 523 ∧
      8 * digestCallCap 700 = 736 ∧ 8 * digestCallCap 4150 = 4184 := by decide

theorem exact_decs_and_example_abort_thresholds :
    8 * digestCallCap 700 - 700 + 1 = 37 ∧
      8 * digestCallCap 4150 - 4150 + 1 = 35 := by decide

/-- Source gamma batches the larger of the 830 nonlinear roots and the
statement-specialized retained CSR count, using the same five rows. -/
def sourceGammaWordRequest (retainedLinearRows : ℕ) : ℕ :=
  5 * max 830 retainedLinearRows

theorem gamma_caps_of_retained_row_bounds (retainedLinearRows : ℕ)
    (lower : 15561 ≤ retainedLinearRows) (upper : retainedLinearRows ≤ 20605) :
    77805 ≤ sourceGammaWordRequest retainedLinearRows ∧
      sourceGammaWordRequest retainedLinearRows ≤ 103025 ∧
      9730 ≤ digestCallCap (sourceGammaWordRequest retainedLinearRows) ∧
      digestCallCap (sourceGammaWordRequest retainedLinearRows) ≤ 12883 := by
  unfold sourceGammaWordRequest digestCallCap
  rw [max_eq_right (by omega : 830 ≤ retainedLinearRows)]
  simp only [if_neg (by omega : 5 * retainedLinearRows ≠ 0)]
  omega

end

end HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
