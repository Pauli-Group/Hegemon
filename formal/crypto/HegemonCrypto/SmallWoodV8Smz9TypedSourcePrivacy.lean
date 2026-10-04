import HegemonCrypto.SmallWoodV8Smz9SourcePackedConstruction
import HegemonCrypto.SmallWoodV8Smz9SourceTypedPrivacyBase
import HegemonCrypto.SmallWoodV8Smz9SourceLifetimePrivacy

/-! Constructive typed-witness instantiation of the existing source
lifetime privacy theorem. Admission and the retained source-row count are
derived. The external adaptive-reprogramming theorem, common public request
parameters, common continuation, and normalized initial state remain explicit.
This file is not a Rust/RNG/hash refinement or production security claim. -/

namespace HegemonCrypto.SmallWood.V8Smz9TypedSourcePrivacy

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SourceFullTypedCandidate V8Smz9SourcePackedConstruction
open V8Smz9CurrentPublicContext
open V8Smz9SourceLifetime V8Smz9SourcePublicErasure
open V8Smz9SourceLifetimePrivacy V8Smz9LifetimePrivacyBudget
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame
open V8Smz9EagerOracleGame (SaltBytes)
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

attribute [local irreducible] fullTypedSourceCandidate retainedAttempts
attribute [local irreducible] sourceLifetimeAcceptance privacyLoss

/-- Typed validity supplies the actual packed domain via the fixed full source
constructor. The binding bytes and salt remain the public request parameters. -/
def typedSourceRequest {bound : Nat}
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (salt : SaltBytes) : SourceRequestData bound where
  statement := statement
  publicValues := encodePublicStatement statement
  witness := fullTypedSourceCandidate statement witness
  domain := full_candidate_canonical_public_packed_domain statement witness valid
  statementBinding := statementBinding
  bindingFits := bindingFits
  salt := salt
  retainedRows := (retainedAttempts (encodePublicStatement statement)).length
  rowBound := typed_retained_rows_bound statement

theorem typed_request_witness_is_full_candidate {bound : Nat}
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes) :
    (typedSourceRequest statement witness valid statementBinding bindingFits salt).witness =
      fullTypedSourceCandidate statement witness := rfl

theorem typed_request_retained_rows_are_actual {bound : Nat}
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes) :
    (typedSourceRequest statement witness valid statementBinding bindingFits salt).retainedRows =
      (retainedAttempts (encodePublicStatement statement)).length := rfl

/-- Both witnesses may differ. No packed-domain or erasure-equality premise
is supplied: the constructor derives the former and reduction proves the latter. -/
theorem typed_requests_publicly_equal {bound : Nat}
    (statement : V8PublicStatement) (left right : V8Witness)
    (leftValid : ExactV8RelationSemanticValid statement left)
    (rightValid : ExactV8RelationSemanticValid statement right)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes) :
    publicRequest (typedSourceRequest statement left leftValid statementBinding bindingFits salt) =
      publicRequest (typedSourceRequest statement right rightValid statementBinding bindingFits salt) :=
  Eq.refl ({
    statement := statement
    publicValues := encodePublicStatement statement
    statementBinding := statementBinding
    bindingFits := bindingFits
    salt := salt
    retainedRows := (retainedAttempts (encodePublicStatement statement)).length
    rowBound := typed_retained_rows_bound statement
  } : PublicRequestData bound)

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- Exactly one source request, followed by a common zero-request continuation.
The continuation may still make its indexed number of oracle queries. -/
def typedSingleRequestLifetime {queries : Nat}
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes)
    (next : ByteResult → Lifetime bound Work queries 0) :
    Lifetime bound Work (16790291 + queries) 1 :=
  Lifetime.sourceRequest
    (typedSourceRequest statement witness valid statementBinding bindingFits salt) next

theorem typed_single_request_publicly_equivalent {queries : Nat}
    (statement : V8PublicStatement) (left right : V8Witness)
    (leftValid : ExactV8RelationSemanticValid statement left)
    (rightValid : ExactV8RelationSemanticValid statement right)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes)
    (next : ByteResult → Lifetime bound Work queries 0) :
    PubliclyEquivalent
      (typedSingleRequestLifetime statement left leftValid statementBinding bindingFits salt next)
      (typedSingleRequestLifetime statement right rightValid statementBinding bindingFits salt next) := by
  exact PubliclyEquivalent.sourceRequest (queries := queries) (requests := 0)
    (left := next) (right := next)
    (typedSourceRequest statement left leftValid statementBinding bindingFits salt)
    (typedSourceRequest statement right rightValid statementBinding bindingFits salt)
    (typed_requests_publicly_equal statement left right leftValid rightValid
      statementBinding bindingFits salt)
    (fun output => source_lifetime_publicly_equivalent_self (next output))

theorem typed_single_request_erasure_equal {queries : Nat}
    (statement : V8PublicStatement) (left right : V8Witness)
    (leftValid : ExactV8RelationSemanticValid statement left)
    (rightValid : ExactV8RelationSemanticValid statement right)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes)
    (next : ByteResult → Lifetime bound Work queries 0) :
    eraseSource (typedSingleRequestLifetime statement left leftValid statementBinding bindingFits salt next) =
      eraseSource (typedSingleRequestLifetime statement right rightValid statementBinding bindingFits salt next) :=
  public_erasure_eq_of_publicly_equivalent
    (typed_single_request_publicly_equivalent statement left right leftValid rightValid
      statementBinding bindingFits salt next)

/-- Direct instantiation of the existing ideal-source privacy theorem. The
external theorem and normalized common initial state are not discharged here. -/
theorem actual_two_typed_witness_single_request_bound {queries : Nat}
    (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    (statement : V8PublicStatement) (left right : V8Witness)
    (leftValid : ExactV8RelationSemanticValid statement left)
    (rightValid : ExactV8RelationSemanticValid statement right)
    (statementBinding : List Nat)
    (bindingFits : 15704 + 8 * statementBinding.length ≤ bound) (salt : SaltBytes)
    (next : ByteResult → Lifetime bound Work queries 0)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance false largeEnough
        (typedSingleRequestLifetime statement left leftValid statementBinding bindingFits salt next) initial -
      sourceLifetimeAcceptance false largeEnough
        (typedSingleRequestLifetime statement right rightValid statementBinding bindingFits salt next) initial| ≤
      2 * privacyLoss (16790291 + queries) 1 :=
  actual_two_witness_lifetime_bound largeEnough ghhm
    (left := typedSingleRequestLifetime statement left leftValid statementBinding bindingFits salt next)
    (right := typedSingleRequestLifetime statement right rightValid statementBinding bindingFits salt next)
    (typed_single_request_publicly_equivalent statement left right leftValid rightValid
      statementBinding bindingFits salt next) initial normalized


end
end HegemonCrypto.SmallWood.V8Smz9TypedSourcePrivacy
