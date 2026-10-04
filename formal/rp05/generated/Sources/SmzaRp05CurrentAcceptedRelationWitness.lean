import SmzaRp05CurrentAcceptedRelationOutcome
import SmzaRp05CurrentPublicStatementTransport

/-! # Typed witness transport at modeled public admission

The accepted physical theorem supplies full satisfaction of the current
generated relation for its actual recovered rows. A successful modeled V8
public parser supplies the canonical public-word guard needed by the
relation refinement; the two facts yield executable packed acceptance on
the typed statement. This is a Lean-model composition, not a Rust-to-Lean
frontend refinement theorem.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8PublicDecoder
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05TracePrefixes
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationOutcome
open SmzaQ38Recovery (RecoveredRows packedFromRows)

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

/-- A successful modeled current public parse derives, rather than assumes,
the canonical-word predicate required by the current relation refinement. -/
theorem current_parse_supplies_relation_word_canonicality
    (preamble : Statement) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? preamble = some typed) :
    CanonicalPublicWords (currentPublicWords preamble) := by
  have accepted := (parse_current_public_statement_iff preamble typed).mp parsed
  have wordsEq := current_parse_reencodes_public_words preamble typed parsed
  refine ⟨?_, ?_⟩
  · change (SmzaRp05TracePrefixes.publicWords preamble).length =
      publicStatementWordCount
    simpa [publicStatementWordCount] using
      SmzaRp05TracePrefixes.public_words_length preamble
  · intro word membership
    rw [← wordsEq] at membership
    exact accepted.2.encodedWordsCanonical word membership

/-- Full satisfaction for the actual recovered RP05 rows becomes an
executable packed witness once the existing modeled canonical-public-input
parser succeeds on the same byte preamble. The witness is exactly
`packedFromRows rows`; no extraction, soundness, or acceptance fact is an
additional premise. -/
theorem current_full_rows_yield_typed_accepted_witness
    (preamble : Statement) (typed : V8PublicStatement)
    (parsed : parseCurrentPublicStatement? preamble = some typed)
    (rows : RecoveredRows)
    (satisfied : HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
      ((relationModel currentDsl certificates).recoveredCandidate preamble rows).system) :
    CanonicalPublicStatement rustV8SemanticPrimitives typed ∧
      program.AcceptsPacked (encodePublicStatement typed) (packedFromRows rows) := by
  have publicCanonical := current_parse_supplies_relation_word_canonicality
    preamble typed parsed
  have currentAccepted := currentRefinement.fullySatisfiedAccepts
    preamble rows publicCanonical satisfied
  have typedAccepted := current_acceptance_transports_to_typed_program
    preamble typed (packedFromRows rows) parsed currentAccepted
  exact ⟨parse_output_is_canonical preamble typed parsed, typedAccepted⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness
