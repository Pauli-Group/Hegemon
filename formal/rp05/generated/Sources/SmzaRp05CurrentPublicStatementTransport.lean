import SmzaRp05CurrentAcceptedRefinement
import SmzaRp05FinalIntentFold
import Hegemon.Transaction.Poseidon2V8PublicDecoder

/-!
# Typed V8 public frontend for RP05

The layout decoder in `Poseidon2V8PublicDecoder` is deliberately permissive:
it checks the 120-word shape and the direction tag only.  This file adds the
finite checks performed by `SmallwoodPoseidon2V8PublicStatement::try_from_public_words`
and `validate_public_structure` in `smallwood_poseidon2_v8_types.rs`, using
the existing RP05 104-word action-intent fold and its live domain.

The two accepted-relation interfaces are kept distinct: relation acceptance
on `currentPublicWords` is transported to the typed encoder only after the
layout round-trip theorem has identified those word lists.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8PublicDecoder
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes
open HegemonCrypto.SmallWood.SmzaRp05FinalIntentFold

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
noncomputable section

private def partitionWords {α : Type} (words : List α) : List Nat → List (List α)
  | [] => []
  | count :: counts => words.take count :: partitionWords (words.drop count) counts

private theorem flatten_partitionWords {α : Type} (words : List α)
    (counts : List Nat) (exactTotal : counts.sum = words.length) :
    (partitionWords words counts).flatten = words := by
  induction counts generalizing words with
  | nil =>
      have wordsLength : words.length = 0 := by simpa using exactTotal.symm
      cases words <;> simp_all [partitionWords]
  | cons count counts ih =>
      simp only [List.sum_cons] at exactTotal
      have countBound : count ≤ words.length := by omega
      have tailTotal : counts.sum = (words.drop count).length := by
        simp
        omega
      calc
        (partitionWords words (count :: counts)).flatten =
            words.take count ++ (partitionWords (words.drop count) counts).flatten := by
              simp [partitionWords]
        _ = words.take count ++ words.drop count := by
          rw [ih (words.drop count) tailTotal]
        _ = words := List.take_append_drop count words

private def v8PublicWordChunkSizes : List Nat :=
  [2, 2, 7, 7, 7, 7, 6, 6, 1, 1, 1, 7, 4, 1, 1, 1, 1, 1, 6, 6, 6,
   1, 1, 1, 1, 1, 1, 7, 1, 7, 7, 1, 1, 1, 1, 7]

private theorem v8_public_word_chunk_sizes_sum :
    v8PublicWordChunkSizes.sum = publicWordCount := by decide

private def publicSlice (words : List Nat) (offset count : Nat) : List Nat :=
  (words.drop offset).take count

private theorem singleton_getD_eq_publicSlice (words : List Nat) (offset : Nat)
    (inRange : offset < words.length) :
    [words.getD offset 0] = publicSlice words offset 1 := by
  induction words generalizing offset with
  | nil => simp at inRange
  | cons head tail ih =>
      cases offset with
      | zero => simp [publicSlice, List.getD]
      | succ offset =>
          have tailRange : offset < tail.length := by simp at inRange; omega
          simpa [publicSlice, List.getD] using ih offset tailRange

/-- Current source action-intent sponge from the exact RP05 final 104-word
projection, distinct from the historical 120-word semantic projection. -/
def rustV8ActionIntent (statement : V8PublicStatement) : Digest :=
  poseidon2V8Sponge currentIntentBindingDomain
    (finalIntentWords (encodePublicStatement statement))

def rustV8SemanticPrimitives : V8SemanticPrimitives :=
  { exactV8SemanticPrimitives with actionIntent := rustV8ActionIntent }

private def statementDecodedFromWords (words : List Nat) (direction : StableDirection) :
    V8PublicStatement :=
  { inputFlags := publicSlice words 0 2
    outputFlags := publicSlice words 2 2
    nullifiers := [publicSlice words 4 7, publicSlice words 11 7]
    commitments := [publicSlice words 18 7, publicSlice words 25 7]
    ciphertextCommitments := [publicSlice words 32 6, publicSlice words 38 6]
    fee := words.getD 44 0
    valueBalanceSign := words.getD 45 0
    valueBalanceMagnitude := words.getD 46 0
    merkleRoot := publicSlice words 47 7
    balanceAssets := publicSlice words 54 4
    compatibility :=
      { enabled := words.getD 58 0
        assetId := words.getD 59 0
        policyVersion := words.getD 60 0
        issuanceSign := words.getD 61 0
        issuanceMagnitude := words.getD 62 0
        reservedLegacyCommitments :=
          [publicSlice words 63 6, publicSlice words 69 6, publicSlice words 75 6] }
    version := words.getD 81 0
    cryptoSuite := words.getD 82 0
    stablecoin :=
      { direction
        assetId := words.getD 84 0
        policyVersion := words.getD 85 0
        magnitude := words.getD 86 0
        actionIntent := publicSlice words 87 7
        parentHeight := words.getD 94 0
        beforeRoot := publicSlice words 95 7
        afterRoot := publicSlice words 102 7
        after :=
          { epochId := words.getD 109 0
            mintedInEpoch := words.getD 110 0
            totalDebt := words.getD 111 0
            sequence := words.getD 112 0 }
        issuerAuthorization := publicSlice words 113 7 } }

private theorem encode_statementDecodedFromWords_eq_partition
    (words : List Nat) (direction : StableDirection)
    (wordsLength : words.length = publicWordCount)
    (directionWord : direction.word = words.getD 83 0) :
    encodePublicStatement (statementDecodedFromWords words direction) =
      (partitionWords words v8PublicWordChunkSizes).flatten := by
  have wordsLength120 : words.length = 120 := by
    simpa only [publicWordCount] using wordsLength
  have scalar44 := singleton_getD_eq_publicSlice words 44 (by omega)
  have scalar45 := singleton_getD_eq_publicSlice words 45 (by omega)
  have scalar46 := singleton_getD_eq_publicSlice words 46 (by omega)
  have scalar58 := singleton_getD_eq_publicSlice words 58 (by omega)
  have scalar59 := singleton_getD_eq_publicSlice words 59 (by omega)
  have scalar60 := singleton_getD_eq_publicSlice words 60 (by omega)
  have scalar61 := singleton_getD_eq_publicSlice words 61 (by omega)
  have scalar62 := singleton_getD_eq_publicSlice words 62 (by omega)
  have scalar81 := singleton_getD_eq_publicSlice words 81 (by omega)
  have scalar82 := singleton_getD_eq_publicSlice words 82 (by omega)
  have scalar84 := singleton_getD_eq_publicSlice words 84 (by omega)
  have scalar85 := singleton_getD_eq_publicSlice words 85 (by omega)
  have scalar86 := singleton_getD_eq_publicSlice words 86 (by omega)
  have scalar94 := singleton_getD_eq_publicSlice words 94 (by omega)
  have scalar109 := singleton_getD_eq_publicSlice words 109 (by omega)
  have scalar110 := singleton_getD_eq_publicSlice words 110 (by omega)
  have scalar111 := singleton_getD_eq_publicSlice words 111 (by omega)
  have scalar112 := singleton_getD_eq_publicSlice words 112 (by omega)
  have scalar83 := singleton_getD_eq_publicSlice words 83 (by omega)
  have scalar44to46 : [words.getD 44 0, words.getD 45 0, words.getD 46 0] =
      publicSlice words 44 1 ++ publicSlice words 45 1 ++ publicSlice words 46 1 := by
    change [words.getD 44 0] ++ [words.getD 45 0] ++ [words.getD 46 0] = _
    rw [scalar44, scalar45, scalar46]
  have scalar58to62 : [words.getD 58 0, words.getD 59 0, words.getD 60 0,
      words.getD 61 0, words.getD 62 0] =
      publicSlice words 58 1 ++ publicSlice words 59 1 ++ publicSlice words 60 1 ++
        publicSlice words 61 1 ++ publicSlice words 62 1 := by
    change [words.getD 58 0] ++ [words.getD 59 0] ++ [words.getD 60 0] ++
      [words.getD 61 0] ++ [words.getD 62 0] = _
    rw [scalar58, scalar59, scalar60, scalar61, scalar62]
  have scalar81to82 : [words.getD 81 0, words.getD 82 0] =
      publicSlice words 81 1 ++ publicSlice words 82 1 := by
    change [words.getD 81 0] ++ [words.getD 82 0] = _
    rw [scalar81, scalar82]
  have scalar83to86 : [words.getD 83 0, words.getD 84 0, words.getD 85 0,
      words.getD 86 0] =
      publicSlice words 83 1 ++ publicSlice words 84 1 ++
        publicSlice words 85 1 ++ publicSlice words 86 1 := by
    change [words.getD 83 0] ++ [words.getD 84 0] ++ [words.getD 85 0] ++
      [words.getD 86 0] = _
    rw [scalar83, scalar84, scalar85, scalar86]
  have scalar109to112 : [words.getD 109 0, words.getD 110 0, words.getD 111 0,
      words.getD 112 0] =
      publicSlice words 109 1 ++ publicSlice words 110 1 ++
        publicSlice words 111 1 ++ publicSlice words 112 1 := by
    change [words.getD 109 0] ++ [words.getD 110 0] ++ [words.getD 111 0] ++
      [words.getD 112 0] = _
    rw [scalar109, scalar110, scalar111, scalar112]
  simp only [statementDecodedFromWords, encodePublicStatement, encodeCompatibility,
    encodeStablecoinPublic, List.flatten_cons, List.flatten_nil]
  simp only [partitionWords, v8PublicWordChunkSizes, List.flatten_cons,
    List.flatten_nil]
  rw [directionWord, scalar44to46, scalar58to62, scalar81to82, scalar83to86,
    scalar94, scalar109to112]
  simp only [publicSlice, List.drop_zero]
  norm_num

private theorem getD_default_independent_of_inRange
    (words : List Nat) (index defaultA defaultB : Nat)
    (inRange : index < words.length) :
    words.getD index defaultA = words.getD index defaultB := by
  simp [List.getD, inRange]

private theorem decoded_stable_direction_word
    {word : Nat} {direction : StableDirection}
    (decoded : decodeStableDirection? word = some direction) :
    direction.word = word := by
  cases word with
  | zero => cases direction <;> simp [decodeStableDirection?, StableDirection.word] at decoded ⊢
  | succ word =>
      cases word with
      | zero => cases direction <;> simp [decodeStableDirection?, StableDirection.word] at decoded ⊢
      | succ word =>
          cases word with
          | zero => cases direction <;> simp [decodeStableDirection?, StableDirection.word] at decoded ⊢
          | succ word => simp [decodeStableDirection?] at decoded

theorem decoded_public_words_reencode
    {words : List Nat} {statement : V8PublicStatement}
    (decoded : decodePublicStatement? words = some statement) :
    encodePublicStatement statement = words := by
  have wordsLength : words.length = publicWordCount := by
    by_contra notLength
    have lengthNe : words.length ≠ publicWordCount := by omega
    simp [decodePublicStatement?, lengthNe] at decoded
  have wordsLength120 : words.length = 120 := by
    simpa only [publicWordCount] using wordsLength
  change (if words.length = publicWordCount then
    (decodeStableDirection? (words[83]?.getD 3)).bind
      (fun direction => some (statementDecodedFromWords words direction))
    else none) = some statement at decoded
  rw [if_pos wordsLength] at decoded
  have bindFacts := decoded
  simp only [Option.bind_eq_some_iff] at bindFacts
  rcases bindFacts with ⟨direction, directionDecoded, parsedSome⟩
  have parsedStructure : statementDecodedFromWords words direction = statement :=
    Option.some.inj parsedSome
  have directionWordAtParser : direction.word = words[83]?.getD 3 :=
    decoded_stable_direction_word directionDecoded
  have directionIndexInRange : 83 < words.length := by omega
  have directionWord : direction.word = words.getD 83 0 := by
    calc
      direction.word = words.getD 83 3 := by
        simpa only [List.getD_eq_getElem?_getD] using directionWordAtParser
      _ = words.getD 83 0 :=
        getD_default_independent_of_inRange words 83 3 0 directionIndexInRange
  rw [← parsedStructure, encode_statementDecodedFromWords_eq_partition
    words direction wordsLength directionWord]
  exact flatten_partitionWords words v8PublicWordChunkSizes
    (by rw [v8_public_word_chunk_sizes_sum, wordsLength])

/-- The structural and range checks represented by the native V8 public
parser. The list-shape checks correspond to its fixed-size arrays; canonical
asset/compatibility and active/inactive slot checks correspond to the two
validation helpers in the Rust source. `actionIntentMatches` is the formal
source-equivalent recomputation gate, using the 104-word projection above. -/
structure CurrentRustPublicChecks (statement : V8PublicStatement) : Prop where
  inputFlagsLength : statement.inputFlags.length = inputCount
  outputFlagsLength : statement.outputFlags.length = outputCount
  inputFlagsBoolean : ∀ flag, flag ∈ statement.inputFlags → BooleanWord flag
  outputFlagsBoolean : ∀ flag, flag ∈ statement.outputFlags → BooleanWord flag
  nullifiersLength : statement.nullifiers.length = inputCount
  nullifiersWords : ∀ digest, digest ∈ statement.nullifiers → ExactWords digestWords digest
  commitmentsLength : statement.commitments.length = outputCount
  commitmentsWords : ∀ digest, digest ∈ statement.commitments → ExactWords digestWords digest
  ciphertextLength : statement.ciphertextCommitments.length = outputCount
  ciphertextWords : ∀ digest, digest ∈ statement.ciphertextCommitments →
    ExactWords ciphertextCommitmentWords digest
  feeBound : statement.fee < valueBound
  zeroValueBalanceSign : statement.valueBalanceSign = 0
  zeroValueBalanceMagnitude : statement.valueBalanceMagnitude = 0
  merkleRootWords : ExactWords digestWords statement.merkleRoot
  balanceAssets : CanonicalBalanceAssets statement.balanceAssets
  compatibility : CanonicalCompatibility statement.balanceAssets
    statement.compatibility statement.stablecoin
  circuitVersion : statement.version = circuitVersion
  cryptoSuite : statement.cryptoSuite = cryptoSuiteEta
  parentHeightBound : statement.stablecoin.parentHeight < stablecoinScalarBound
  actionIntentWords : ExactWords digestWords statement.stablecoin.actionIntent
  beforeRootWords : ExactWords digestWords statement.stablecoin.beforeRoot
  afterRootWords : ExactWords digestWords statement.stablecoin.afterRoot
  issuerAuthorizationWords : ExactWords digestWords statement.stablecoin.issuerAuthorization
  slots : PublicSlotShapeValid statement
  distinctActiveNullifiers :
    (flagAt statement.inputFlags 0 = 1 → flagAt statement.inputFlags 1 = 1 →
      digestAt statement.nullifiers 0 ≠ digestAt statement.nullifiers 1)
  actionIntentMatches : statement.stablecoin.direction ≠ .disabled →
    statement.stablecoin.actionIntent = rustV8ActionIntent statement
  encodedWordsCanonical : ∀ word, word ∈ encodePublicStatement statement →
    word < fieldModulus

/-- Run the formal typed frontend on the actual 120 words projected from the
current byte preamble. This is the mathematical source model of the Rust
frontend checks; it is not an imported Rust acceptance receipt. -/
noncomputable def parseCurrentPublicStatement?
    (preamble : Statement) : Option V8PublicStatement := by
  classical
  exact do
    let statement ← decodePublicStatement? (currentPublicWords preamble)
    if h : CurrentRustPublicChecks statement then some statement else none

/-- Relational presentation of a successful parse, exposing the exact layout
decode and the finite native-surface checks without hiding either as an
assumption about the desired canonicality conclusion. -/
def CurrentPublicParserAccepted
    (preamble : Statement) (statement : V8PublicStatement) : Prop :=
  decodePublicStatement? (currentPublicWords preamble) = some statement ∧
    CurrentRustPublicChecks statement

theorem parse_current_public_statement_iff
    (preamble : Statement) (statement : V8PublicStatement) :
    parseCurrentPublicStatement? preamble = some statement ↔
      CurrentPublicParserAccepted preamble statement := by
  classical
  unfold parseCurrentPublicStatement? CurrentPublicParserAccepted
  cases decodePublicStatement? (currentPublicWords preamble) with
  | none => simp
  | some parsed =>
      by_cases checked : CurrentRustPublicChecks parsed
      · change (if h : CurrentRustPublicChecks parsed then some parsed else none) =
          some statement ↔
            (some parsed = some statement ∧ CurrentRustPublicChecks statement)
        rw [dif_pos checked]
        constructor
        · intro equality
          have same : parsed = statement := Option.some.inj equality
          subst statement
          exact ⟨rfl, checked⟩
        · intro accepted
          exact accepted.1
      · change (if h : CurrentRustPublicChecks parsed then some parsed else none) =
          some statement ↔
            (some parsed = some statement ∧ CurrentRustPublicChecks statement)
        rw [dif_neg checked]
        constructor
        · intro impossible
          cases impossible
        · intro accepted
          have same : parsed = statement := Option.some.inj accepted.1
          subst statement
          exact (checked accepted.2).elim

theorem current_parse_reencodes_public_words
    (preamble : Statement) (statement : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? preamble = some statement) :
    encodePublicStatement statement = currentPublicWords preamble := by
  have accepted := (parse_current_public_statement_iff preamble statement).mp parsed
  exact decoded_public_words_reencode accepted.1

/-- Every successful source-model parse entails the typed canonicality
predicate with the native V8 action-intent projection. The existing formal
`exactV8SemanticPrimitives` uses a different 120-word projection, so this
does not silently claim those two semantics coincide. -/
theorem successful_current_parse_is_source_canonical
    (preamble : Statement) (statement : V8PublicStatement)
    (parsed : CurrentPublicParserAccepted preamble statement) :
    CanonicalPublicStatement rustV8SemanticPrimitives statement := by
  rcases parsed with ⟨_decoded, valid⟩
  rcases valid with ⟨inputFlagsLength, outputFlagsLength,
        inputFlagsBoolean, outputFlagsBoolean, nullifiersLength, nullifiersWords,
        commitmentsLength, commitmentsWords, ciphertextLength, ciphertextWords,
        feeBound, zeroValueBalanceSign, zeroValueBalanceMagnitude,
        merkleRootWords, balanceAssets, compatibility, circuitVersion,
        cryptoSuite, parentHeightBound, actionIntentWords, beforeRootWords,
        afterRootWords, issuerAuthorizationWords, slots,
        distinctActiveNullifiers, actionIntentMatches, encodedWordsCanonical⟩
  refine ⟨inputFlagsLength, outputFlagsLength, inputFlagsBoolean,
        outputFlagsBoolean, nullifiersLength, nullifiersWords,
        commitmentsLength, commitmentsWords, ciphertextLength, ciphertextWords,
        feeBound, zeroValueBalanceSign, zeroValueBalanceMagnitude,
        merkleRootWords, balanceAssets, compatibility, circuitVersion,
        cryptoSuite, parentHeightBound, actionIntentWords, beforeRootWords,
        afterRootWords, issuerAuthorizationWords, slots,
        distinctActiveNullifiers, ?_, ?_⟩
  · simpa [rustV8SemanticPrimitives] using actionIntentMatches
  ·
    refine ⟨?_, encodedWordsCanonical⟩
    have wordsLength : (currentPublicWords preamble).length = publicWordCount := by
      by_contra notLength
      have lengthNe : (currentPublicWords preamble).length ≠ publicWordCount := by omega
      simp [decodePublicStatement?, lengthNe] at _decoded
    rw [decoded_public_words_reencode _decoded]
    exact wordsLength

theorem parse_output_is_canonical
    (preamble : Statement) (statement : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? preamble = some statement) :
    CanonicalPublicStatement rustV8SemanticPrimitives statement :=
  successful_current_parse_is_source_canonical preamble statement
    ((parse_current_public_statement_iff preamble statement).mp parsed)

/-- Current accepted relation witnesses transport to the generated program
on the typed statement. The public equality is derived from successful parse;
no private packed witness is exposed. -/
theorem current_acceptance_transports_to_typed_program
    (preamble : Statement) (statement : V8PublicStatement) (packed : List Nat)
    (parsed : parseCurrentPublicStatement? preamble = some statement)
    (accepted : currentRefinement.AcceptsPacked preamble packed) :
    program.AcceptsPacked (encodePublicStatement statement) packed := by
  have samePublicWords := current_parse_reencodes_public_words preamble statement parsed
  have acceptedCurrent : currentDsl.components.AcceptsPacked
      (currentPublicWords preamble) packed := by
    change currentDsl.components.AcceptsPacked
      (currentPublicWords preamble) packed at accepted
    exact accepted
  change program.AcceptsPacked (encodePublicStatement statement) packed
  rw [samePublicWords]
  change currentDsl.components.AcceptsPacked (currentPublicWords preamble) packed
  exact acceptedCurrent

/-- A successful current-source parse carries both the source-current
canonical public statement and the same private packed witness accepted by
the generated relation on its typed encoding. -/
theorem parsed_current_acceptance_yields_typed_witness
    (preamble : Statement) (statement : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? preamble = some statement)
    (acceptedWitness : ∃ packed, currentRefinement.AcceptsPacked preamble packed) :
    CanonicalPublicStatement rustV8SemanticPrimitives statement ∧
      ∃ packed, program.AcceptsPacked (encodePublicStatement statement) packed := by
  refine ⟨parse_output_is_canonical preamble statement parsed, ?_⟩
  rcases acceptedWitness with ⟨packed, accepted⟩
  exact ⟨packed, current_acceptance_transports_to_typed_program
    preamble statement packed parsed accepted⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
