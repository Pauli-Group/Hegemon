import Hegemon.Transaction.Poseidon2V8ConstraintRefinement
import Hegemon.Transaction.Poseidon2V8SemanticSpecification

namespace Hegemon
namespace Transaction
namespace Poseidon2V8SemanticAdequacy

open Poseidon2V8RelationProgram
open Poseidon2V8SemanticSpecification

/-!
Universal semantic-adequacy boundary for the `HGV8RP03` V8 relation program.

The transaction specification is imported from a module that does not import the relation
program.  This file therefore cannot let a compiler receipt choose its own semantic target.
The receipt below also avoids one opaque `program accepts ↔ semantics` field: accepted packed
assignments must decode, and five named, universal refinement obligations establish each conjunct
of `V8RelationSemanticValid`.  The theorem then assembles those obligations.

The checked-in source does not yet inhabit this receipt.  Exhaustive activity-mask and
authorization-mode fixtures exercise honest lowering, but finite fixtures are not a proof about
all 43,904-word assignments.  Consensus stablecoin context and the exact 2,147-byte ciphertexts
remain explicit action-admission conjuncts outside the private packed relation.
-/

universe u

/--
Non-circular refinement obligations for one fixed primitive interpretation and one pinned
relation-program instance.  Every soundness field quantifies over arbitrary canonical public
words and arbitrary packed witnesses accepted by the executable program.
-/
structure Hgv8rp03SemanticAdequacyReceipt
    (components : RelationProgramComponents) where
  programCanonical : components.Canonical
  decodePublicWords : List Nat → Option V8PublicStatement
  decodePackedWitness : V8PublicStatement → List Nat → Option V8Witness
  lowerTypedWitness : V8PublicStatement → V8Witness → List Nat
  decodePublicWordsExact :
    ∀ publicWords statement,
      decodePublicWords publicWords = some statement →
        encodePublicStatement statement = publicWords
  lowerTypedWitnessExactLength :
    ∀ statement witness,
      (lowerTypedWitness statement witness).length =
        Poseidon2V8SemanticSpecification.packedWitnessWordCount
  lowerDecodeRoundtrip :
    ∀ statement witness,
      decodePackedWitness statement (lowerTypedWitness statement witness) = some witness
  acceptedPublicWordsDecode :
    ∀ publicWords packedWitness,
      components.AcceptsPacked publicWords packedWitness →
        ∃ statement, decodePublicWords publicWords = some statement
  acceptedPackedWitnessDecodes :
    ∀ publicWords packedWitness statement,
      decodePublicWords publicWords = some statement →
        components.AcceptsPacked publicWords packedWitness →
          ∃ witness, decodePackedWitness statement packedWitness = some witness
  canonicalPublicStatementRefinement :
    ∀ publicWords packedWitness statement witness,
      decodePublicWords publicWords = some statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            CanonicalPublicStatement exactV8SemanticPrimitives statement
  canonicalWitnessShapeRefinement :
    ∀ publicWords packedWitness statement witness,
      decodePublicWords publicWords = some statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            CanonicalWitnessShape statement witness
  cryptographicLinksRefinement :
    ∀ publicWords packedWitness statement witness,
      decodePublicWords publicWords = some statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            V8CryptographicLinksValid exactV8SemanticPrimitives statement witness
  perAssetBalanceRefinement :
    ∀ publicWords packedWitness statement witness,
      decodePublicWords publicWords = some statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            V8BalanceValid statement witness
  stablecoinTransitionRefinement :
    ∀ publicWords packedWitness statement witness,
      decodePublicWords publicWords = some statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            exactV8SemanticPrimitives.stableTransition (derivedRelationContext statement)
              statement.stablecoin witness.stablecoin
  /-- Completeness for the canonical typed lowerer, not for an arbitrary alternate encoding. -/
  honestTypedLoweringAccepted :
    ∀ statement witness,
      ExactV8RelationSemanticValid statement witness →
        components.AcceptsPacked (encodePublicStatement statement)
          (lowerTypedWitness statement witness)

/--
Every accepted packed assignment has one decoded witness satisfying the fixed V8 transaction
semantics.  This is universal in the statement and all 43,904 packed witness words.
-/
theorem accepted_packed_program_yields_exact_v8_semantics
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (accepted : components.AcceptsPacked publicWords packedWitness) :
    ∃ statement witness,
      receipt.decodePublicWords publicWords = some statement ∧
        receipt.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness := by
  obtain ⟨statement, statementDecoded⟩ :=
    receipt.acceptedPublicWordsDecode publicWords packedWitness accepted
  obtain ⟨witness, witnessDecoded⟩ :=
    receipt.acceptedPackedWitnessDecodes publicWords packedWitness statement
      statementDecoded accepted
  refine ⟨statement, witness, statementDecoded, witnessDecoded,
    receipt.decodePublicWordsExact publicWords statement statementDecoded, ?_⟩
  exact ⟨
    receipt.canonicalPublicStatementRefinement publicWords packedWitness statement witness
      statementDecoded witnessDecoded accepted,
    receipt.canonicalWitnessShapeRefinement publicWords packedWitness statement witness
      statementDecoded witnessDecoded accepted,
    receipt.cryptographicLinksRefinement publicWords packedWitness statement witness
      statementDecoded witnessDecoded accepted,
    receipt.perAssetBalanceRefinement publicWords packedWitness statement witness
      statementDecoded witnessDecoded accepted,
    receipt.stablecoinTransitionRefinement publicWords packedWitness statement witness
      statementDecoded witnessDecoded accepted⟩

/-- Any mutation leaving no valid decoded semantic opening is rejected by the pinned program. -/
theorem no_exact_v8_semantic_opening_implies_program_rejection
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (noOpening : ¬ ∃ statement witness,
      receipt.decodePublicWords publicWords = some statement ∧
        receipt.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness) :
    ¬ components.AcceptsPacked publicWords packedWitness := by
  intro accepted
  exact noOpening (accepted_packed_program_yields_exact_v8_semantics receipt accepted)

/-- Every valid typed transaction lowers to an accepted canonical packed assignment. -/
theorem exact_v8_semantics_lower_to_accepted_program
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {statement : V8PublicStatement} {witness : V8Witness}
    (valid : ExactV8RelationSemanticValid statement witness) :
    components.AcceptsPacked (encodePublicStatement statement)
      (receipt.lowerTypedWitness statement witness) :=
  receipt.honestTypedLoweringAccepted statement witness valid

/-- Exact Rust source-verifier predicate bound to the same pinned program interpreter. -/
structure Hgv8rp03RustLeanSemanticRefinementReceipt
    (components : RelationProgramComponents) where
  semanticAdequacy : Hgv8rp03SemanticAdequacyReceipt components
  rustVerifierAccepts : List Nat → List Nat → Prop
  rustVerifierAcceptsIffPinnedProgram :
    ∀ publicWords packedWitness,
      rustVerifierAccepts publicWords packedWitness ↔
        components.AcceptsPacked publicWords packedWitness

/-- Rust acceptance implies an exact decoded V8 transaction semantic opening. -/
theorem rust_verifier_acceptance_yields_exact_v8_semantics
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03RustLeanSemanticRefinementReceipt components)
    {publicWords packedWitness : List Nat}
    (accepted : receipt.rustVerifierAccepts publicWords packedWitness) :
    ∃ statement witness,
      receipt.semanticAdequacy.decodePublicWords publicWords = some statement ∧
        receipt.semanticAdequacy.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness := by
  apply accepted_packed_program_yields_exact_v8_semantics receipt.semanticAdequacy
  exact (receipt.rustVerifierAcceptsIffPinnedProgram publicWords packedWitness).mp accepted

/-- A Rust verifier must reject any packed assignment with no exact semantic opening. -/
theorem no_exact_v8_semantic_opening_implies_rust_rejection
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03RustLeanSemanticRefinementReceipt components)
    {publicWords packedWitness : List Nat}
    (noOpening : ¬ ∃ statement witness,
      receipt.semanticAdequacy.decodePublicWords publicWords = some statement ∧
        receipt.semanticAdequacy.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness) :
    ¬ receipt.rustVerifierAccepts publicWords packedWitness := by
  intro accepted
  exact noOpening (rust_verifier_acceptance_yields_exact_v8_semantics receipt accepted)

/--
The private relation plus independently checked consensus context and ciphertext bytes gives the
full action semantics.  Those two bindings are deliberately not hidden inside the relation
receipt.
-/
theorem accepted_relation_plus_external_bindings_yields_full_action_semantics
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (context : V8StablecoinContext) (ciphertexts : V8InlineCiphertexts)
    (contextBound : ∀ statement,
      receipt.decodePublicWords publicWords = some statement →
        ConsensusContextMatches context statement)
    (ciphertextsBound : ∀ statement,
      receipt.decodePublicWords publicWords = some statement →
        InlineCiphertextsMatch exactV8SemanticPrimitives statement ciphertexts)
    (accepted : components.AcceptsPacked publicWords packedWitness) :
    ∃ statement witness,
      receipt.decodePublicWords publicWords = some statement ∧
        receipt.decodePackedWitness statement packedWitness = some witness ∧
        ExactV8FullActionSemanticValid context ciphertexts statement witness := by
  obtain ⟨statement, witness, statementDecoded, witnessDecoded, _, semanticValid⟩ :=
    accepted_packed_program_yields_exact_v8_semantics receipt accepted
  exact ⟨statement, witness, statementDecoded, witnessDecoded,
    semanticValid, contextBound statement statementDecoded,
    ciphertextsBound statement statementDecoded⟩

/-!
The source verifier now has a second, fail-closed acceptance gate after the algebraic checks: it
decodes an arbitrary packed assignment, validates the typed surface, rebuilds the complete
assignment with the source primitives, and requires all 43,904 words to match.  The structure
below models the evidence returned by that gate without claiming a theorem that the compiled Rust
machine code implements this Lean predicate.  Each semantic family stays explicit.
-/

structure SourceVerifierCanonicalReloweringOpening
    (components : RelationProgramComponents) (publicWords packedWitness : List Nat) where
  statement : V8PublicStatement
  witness : V8Witness
  programAccepted : components.AcceptsPacked publicWords packedWitness
  publicEncodingExact : encodePublicStatement statement = publicWords
  packedWordCountExact :
    packedWitness.length = Poseidon2V8SemanticSpecification.packedWitnessWordCount
  canonicalPublic : CanonicalPublicStatement exactV8SemanticPrimitives statement
  canonicalWitness : CanonicalWitnessShape statement witness
  cryptographicLinks :
    V8CryptographicLinksValid exactV8SemanticPrimitives statement witness
  perAssetBalance : V8BalanceValid statement witness
  stablecoinTransition :
    exactV8SemanticPrimitives.stableTransition (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin

def SourceVerifierCanonicalReloweringAccepts
    (components : RelationProgramComponents) (publicWords packedWitness : List Nat) : Prop :=
  Nonempty (SourceVerifierCanonicalReloweringOpening components publicWords packedWitness)

theorem source_verifier_gate_discharges_canonical_public_statement
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ statement, encodePublicStatement statement = publicWords ∧
      CanonicalPublicStatement exactV8SemanticPrimitives statement := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.publicEncodingExact, opening.canonicalPublic⟩

theorem source_verifier_gate_discharges_canonical_witness_shape
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ statement witness, CanonicalWitnessShape statement witness := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.witness, opening.canonicalWitness⟩

theorem source_verifier_gate_discharges_cryptographic_links
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ statement witness,
      V8CryptographicLinksValid exactV8SemanticPrimitives statement witness := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.witness, opening.cryptographicLinks⟩

theorem source_verifier_gate_discharges_per_asset_balance
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ statement witness, V8BalanceValid statement witness := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.witness, opening.perAssetBalance⟩

theorem source_verifier_gate_discharges_stablecoin_transition
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ (statement : V8PublicStatement) (witness : V8Witness),
      exactV8SemanticPrimitives.stableTransition (derivedRelationContext statement)
        statement.stablecoin witness.stablecoin := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.witness, opening.stablecoinTransition⟩

theorem source_verifier_canonical_relowering_yields_exact_v8_semantics
    {components : RelationProgramComponents} {publicWords packedWitness : List Nat}
    (accepted : SourceVerifierCanonicalReloweringAccepts components publicWords packedWitness) :
    ∃ statement witness,
      encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness := by
  rcases accepted with ⟨opening⟩
  exact ⟨opening.statement, opening.witness, opening.publicEncodingExact,
    opening.canonicalPublic, opening.canonicalWitness, opening.cryptographicLinks,
    opening.perAssetBalance, opening.stablecoinTransition⟩

inductive CheckedInSemanticAdequacyCoverage where
  | typedLoweringReplay
  | sourceVerifierCanonicalRelowering
  | universalAcceptedWitnessSoundness
deriving DecidableEq, Repr

/-- Current status: the source verifier enforces canonical relowering; Rust/Lean refinement remains. -/
def checkedInSemanticAdequacyCoverage : CheckedInSemanticAdequacyCoverage :=
  .sourceVerifierCanonicalRelowering

theorem checked_in_universal_semantic_adequacy_is_not_complete :
    checkedInSemanticAdequacyCoverage ≠ .universalAcceptedWitnessSoundness := by
  decide

/-- A release receipt cannot exist until the checked-in status is explicitly promoted by proof. -/
structure CheckedInUniversalSemanticRefinement where
  coverageExact :
    checkedInSemanticAdequacyCoverage = .universalAcceptedWitnessSoundness

theorem checked_in_universal_semantic_refinement_receipt_is_unavailable :
    ¬ Nonempty CheckedInUniversalSemanticRefinement := by
  intro evidence
  rcases evidence with ⟨receipt⟩
  exact checked_in_universal_semantic_adequacy_is_not_complete receipt.coverageExact

end Poseidon2V8SemanticAdequacy
end Transaction
end Hegemon
