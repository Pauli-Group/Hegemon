import SmzaRp05ActualAcceptedAuthorizationEndpoint
import SmzaRp05SupplyClosureInputNative

/-! A small adapter from source facts on one concrete designated pair to its
accepted-pair authorization failure.  The accepted relation witnesses supply
the owner and rho equalities; only exact note equality, projected-position
equality, and the actual active-nullifier mismatch are inputs. -/

namespace HegemonCrypto.SmallWood.SmzaRp05DesignatedComparisonFailureFromSourceFacts

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05AcceptedPairAuthorization
open HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
open HegemonCrypto.SmallWood.SmzaRp05CurrentAuthorizationCertificate
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open scoped Classical

set_option autoImplicit false

/-- Exact equality of the two selected note encodings and their projected
positions, together with an actual mismatch of the pair's active public
nullifiers, constructs the source certificate evidence and hence the exact
accepted-pair authorization-failure event. -/
theorem designated_comparison_source_facts_imply_accepted_pair_failure
    (comparison : DesignatedAuthorizationComparison)
    (sameNoteWords : exactV8NoteWords
        (projectNote comparison.pair.1.packed (noteCall comparison.pair.1.input)) =
      exactV8NoteWords
        (projectNote comparison.pair.2.packed (noteCall comparison.pair.2.input)))
    (samePosition : projectPosition comparison.pair.1.packed
        comparison.pair.1.input.val =
      projectPosition comparison.pair.2.packed comparison.pair.2.input.val)
    (activeNullifierMismatch :
      activePublicNullifier comparison.pair.1 ≠
        activePublicNullifier comparison.pair.2) :
    acceptedPairAuthorizationFailure comparison.pair := by
  let pair := comparison.pair
  have evidence : SameSourceNoteEvidence pair.1 pair.2 := by
    constructor
    · intro limb
      exact same_accepted_note_owner_words pair.1.accepted pair.2.accepted
        pair.1.input pair.2.input sameNoteWords limb
    · exact samePosition
    · intro limb
      exact equal_projected_note_words_coordinate
        (noteCall pair.1.input) (noteCall pair.2.input) sameNoteWords
        (6 + limb.val) (by omega)
  change acceptedPreimageAlias pair ∨
    (Nonempty (SameSourceNoteEvidence pair.1 pair.2) ∧
      activePublicNullifier pair.1 ≠ activePublicNullifier pair.2)
  exact Or.inr ⟨⟨evidence⟩, activeNullifierMismatch⟩

end HegemonCrypto.SmallWood.SmzaRp05DesignatedComparisonFailureFromSourceFacts
