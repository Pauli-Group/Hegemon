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
Public frontend admission is part of the domain: a decoded statement must have its exact public
encoding and satisfy the fixed public semantic rules before the packed equations are considered.
Raw `AcceptsPacked` alone does not enforce inactive-nullifier padding.  Within the admitted domain,
the receipt requires arbitrary accepted packed assignments to decode and four named universal
private refinements to establish the remaining conjuncts of `V8RelationSemanticValid`.

The checked-in source does not yet inhabit this receipt.  Exhaustive activity-mask and
authorization-mode fixtures exercise honest lowering, but finite fixtures are not a proof about
all 43,904-word assignments.  Refinement from actual frontend execution to public admission is
also unproved.  Consensus stablecoin context and the exact 2,147-byte ciphertexts remain explicit
action-admission conjuncts outside the private packed relation.
-/

universe u

/--
Public-only admission for one exact decoded statement.  This contains no private witness or
private semantic conclusion.  The Rust frontend's public validation must be separately refined
to this fixed predicate; the private equation system cannot supply every public structural rule.
-/
def AdmittedPublicStatement
    (decodePublicWords : List Nat → Option V8PublicStatement)
    (publicWords : List Nat) (statement : V8PublicStatement) : Prop :=
  decodePublicWords publicWords = some statement ∧
    encodePublicStatement statement = publicWords ∧
    CanonicalPublicStatement exactV8SemanticPrimitives statement

/-- Exact public words admitted independently of any packed private assignment. -/
def AdmittedPublicWords
    (decodePublicWords : List Nat → Option V8PublicStatement)
    (publicWords : List Nat) : Prop :=
  ∃ statement, AdmittedPublicStatement decodePublicWords publicWords statement

/--
Non-circular refinement obligations for one fixed primitive interpretation and one pinned
relation-program instance.  Every private soundness field quantifies over arbitrary admitted
public statements and arbitrary packed witnesses accepted by the executable program.  Public
decoder completeness prevents a chosen decoder from making this admitted domain artificially
empty or omitting any canonically encoded public statement.
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
  canonicalPublicWordsDecode :
    ∀ statement,
      CanonicalPublicStatement exactV8SemanticPrimitives statement →
        decodePublicWords (encodePublicStatement statement) = some statement
  /-- The source lowerer is only required to succeed on valid typed transactions. -/
  lowerTypedWitnessExactLength :
    ∀ statement witness,
      ExactV8RelationSemanticValid statement witness →
        (lowerTypedWitness statement witness).length =
          Poseidon2V8SemanticSpecification.packedWitnessWordCount
  /-- Completeness roundtrip on valid inputs; no condition on arbitrary accepted assignments. -/
  lowerDecodeRoundtrip :
    ∀ statement witness,
      ExactV8RelationSemanticValid statement witness →
        decodePackedWitness statement (lowerTypedWitness statement witness) = some witness
  acceptedPackedWitnessDecodes :
    ∀ publicWords packedWitness statement,
      AdmittedPublicStatement decodePublicWords publicWords statement →
        components.AcceptsPacked publicWords packedWitness →
          ∃ witness, decodePackedWitness statement packedWitness = some witness
  canonicalWitnessShapeRefinement :
    ∀ publicWords packedWitness statement witness,
      AdmittedPublicStatement decodePublicWords publicWords statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            CanonicalWitnessShape statement witness
  cryptographicLinksRefinement :
    ∀ publicWords packedWitness statement witness,
      AdmittedPublicStatement decodePublicWords publicWords statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            V8CryptographicLinksValid exactV8SemanticPrimitives statement witness
  perAssetBalanceRefinement :
    ∀ publicWords packedWitness statement witness,
      AdmittedPublicStatement decodePublicWords publicWords statement →
        decodePackedWitness statement packedWitness = some witness →
          components.AcceptsPacked publicWords packedWitness →
            V8BalanceValid statement witness
  stablecoinTransitionRefinement :
    ∀ publicWords packedWitness statement witness,
      AdmittedPublicStatement decodePublicWords publicWords statement →
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

/-- The receipt admits every canonical public statement's exact encoding. -/
theorem canonical_public_statement_has_admitted_encoding
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {statement : V8PublicStatement}
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    AdmittedPublicWords receipt.decodePublicWords (encodePublicStatement statement) := by
  exact ⟨statement, receipt.canonicalPublicWordsDecode statement canonical, rfl, canonical⟩

/--
For every admitted public statement, every accepted packed assignment has a decoded witness
satisfying the fixed V8 transaction semantics.  Public admission is an explicit independent
premise; the private refinements are universal over all 43,904 packed witness words.
-/
theorem accepted_packed_program_yields_exact_v8_semantics
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (admitted : AdmittedPublicWords receipt.decodePublicWords publicWords)
    (accepted : components.AcceptsPacked publicWords packedWitness) :
    ∃ statement witness,
      receipt.decodePublicWords publicWords = some statement ∧
        receipt.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness := by
  obtain ⟨statement, statementAdmitted⟩ := admitted
  have statementDecoded := statementAdmitted.1
  have encodingExact := statementAdmitted.2.1
  have canonicalPublic := statementAdmitted.2.2
  obtain ⟨witness, witnessDecoded⟩ :=
    receipt.acceptedPackedWitnessDecodes publicWords packedWitness statement
      statementAdmitted accepted
  refine ⟨statement, witness, statementDecoded, witnessDecoded,
    encodingExact, ?_⟩
  exact ⟨canonicalPublic,
    receipt.canonicalWitnessShapeRefinement publicWords packedWitness statement witness
      statementAdmitted witnessDecoded accepted,
    receipt.cryptographicLinksRefinement publicWords packedWitness statement witness
      statementAdmitted witnessDecoded accepted,
    receipt.perAssetBalanceRefinement publicWords packedWitness statement witness
      statementAdmitted witnessDecoded accepted,
    receipt.stablecoinTransitionRefinement publicWords packedWitness statement witness
      statementAdmitted witnessDecoded accepted⟩

/-- On admitted public words, absence of a valid semantic opening implies program rejection. -/
theorem no_exact_v8_semantic_opening_implies_program_rejection
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (admitted : AdmittedPublicWords receipt.decodePublicWords publicWords)
    (noOpening : ¬ ∃ statement witness,
      receipt.decodePublicWords publicWords = some statement ∧
        receipt.decodePackedWitness statement packedWitness = some witness ∧
        encodePublicStatement statement = publicWords ∧
        ExactV8RelationSemanticValid statement witness) :
    ¬ components.AcceptsPacked publicWords packedWitness := by
  intro accepted
  exact noOpening (accepted_packed_program_yields_exact_v8_semantics receipt admitted accepted)

/-- Every valid typed transaction lowers to an accepted canonical packed assignment. -/
theorem exact_v8_semantics_lower_to_accepted_program
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {statement : V8PublicStatement} {witness : V8Witness}
    (valid : ExactV8RelationSemanticValid statement witness) :
    components.AcceptsPacked (encodePublicStatement statement)
      (receipt.lowerTypedWitness statement witness) :=
  receipt.honestTypedLoweringAccepted statement witness valid

/-- Valid typed lowering supplies both public admission and packed-program acceptance. -/
theorem exact_v8_semantics_lower_to_admitted_program
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {statement : V8PublicStatement} {witness : V8Witness}
    (valid : ExactV8RelationSemanticValid statement witness) :
    AdmittedPublicWords receipt.decodePublicWords (encodePublicStatement statement) ∧
      components.AcceptsPacked (encodePublicStatement statement)
        (receipt.lowerTypedWitness statement witness) := by
  exact ⟨canonical_public_statement_has_admitted_encoding receipt valid.1,
    receipt.honestTypedLoweringAccepted statement witness valid⟩

/--
Required Rust refinement for frontend admission followed by full packed-equation checking.
The equivalence includes public admission, not only raw algebraic acceptance.  This uninhabited
receipt does not model acceptance of proof bytes: an extraction theorem must first provide the
full packed assignment.  It also does not credit the honest compiler's extra relowering check.
-/
structure Hgv8rp03RustLeanSemanticRefinementReceipt
    (components : RelationProgramComponents) where
  semanticAdequacy : Hgv8rp03SemanticAdequacyReceipt components
  rustVerifierAccepts : List Nat → List Nat → Prop
  rustVerifierAcceptsIffAdmittedPinnedProgram :
    ∀ publicWords packedWitness,
      rustVerifierAccepts publicWords packedWitness ↔
        AdmittedPublicWords semanticAdequacy.decodePublicWords publicWords ∧
          components.AcceptsPacked publicWords packedWitness

/-- The required Rust refinement must establish the public admission premise explicitly. -/
theorem rust_verifier_acceptance_includes_public_admission
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03RustLeanSemanticRefinementReceipt components)
    {publicWords packedWitness : List Nat}
    (accepted : receipt.rustVerifierAccepts publicWords packedWitness) :
    AdmittedPublicWords receipt.semanticAdequacy.decodePublicWords publicWords :=
  ((receipt.rustVerifierAcceptsIffAdmittedPinnedProgram publicWords packedWitness).mp accepted).1

/-- Refined frontend/full-assignment acceptance yields a decoded semantic opening. -/
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
  obtain ⟨admitted, packedAccepted⟩ :=
    (receipt.rustVerifierAcceptsIffAdmittedPinnedProgram publicWords packedWitness).mp accepted
  exact accepted_packed_program_yields_exact_v8_semantics receipt.semanticAdequacy
    admitted packedAccepted

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
The admitted public statement and private relation, plus independently checked consensus context
and ciphertext bytes, give the full action semantics.  These public and external bindings are
not consequences of raw packed-program acceptance.
-/
theorem accepted_relation_plus_external_bindings_yields_full_action_semantics
    {components : RelationProgramComponents}
    (receipt : Hgv8rp03SemanticAdequacyReceipt components)
    {publicWords packedWitness : List Nat}
    (admitted : AdmittedPublicWords receipt.decodePublicWords publicWords)
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
    accepted_packed_program_yields_exact_v8_semantics receipt admitted accepted
  exact ⟨statement, witness, statementDecoded, witnessDecoded,
    semanticValid, contextBound statement statementDecoded,
    ciphertextsBound statement statementDecoded⟩

/-!
The full-witness source helper `verify_packed_witness` performs an additional gate after checking
the algebraic equations: it decodes an arbitrary packed assignment, validates the typed surface,
rebuilds the assignment, and compares all 43,904 words.  Its non-test caller is the honest compiler.
The actual proof verifier receives opening messages rather than this full assignment and does
not invoke that relowering gate.  It cannot use the gate as its witness-extraction theorem.

The historical `SourceVerifier` names below refer only to that full-witness helper.  The record
states semantic outcomes that a source-refinement proof would have to supply, and its theorems
only project or assemble those fields.  Neither the record nor its projections prove that Rust
execution produces this semantic evidence; no such refinement or proof-verifier implication is
claimed here.  Each semantic family stays explicit.
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

/--
Current status: the honest compilation path calls a full-witness canonical relowering helper.
The historical constructor name does not mean the proof verifier enforces that extra gate.
Universal packed semantic adequacy, frontend execution refinement, and proof extraction remain.
-/
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
