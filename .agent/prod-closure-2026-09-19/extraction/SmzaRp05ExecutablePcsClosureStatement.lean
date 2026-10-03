import SmzaRp05ExecutablePcsClosure

/-!
# Current statement binding for the decoded verifier closure

SMZA `transcript_binding_words_for_domain` decodes all 1104 preamble bytes
into 138 little-endian u64 words. `strict_zk_leaf_statement_binding` returns
that same entire binding. Derive both representations from the same finite
Statement used by the relation evaluator; neither representation is an
independent verifier input. The existing nonce is still a decoded proof
field, not an added carrier field. Outer parser/profile qualification and
the mathematical-to-Rust refinement remain outside this theorem.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStatement

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (finalInput)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)

set_option autoImplicit false

def statementBindingWords (statement : SmzaRp05StatementNamespace.Statement) : List Nat :=
  (List.range 138).map fun index =>
    decodeLE ((statement.toBytes.drop (8 * index)).take 8)

theorem statement_binding_word_count (statement : SmzaRp05StatementNamespace.Statement) :
    (statementBindingWords statement).length = 138 := by
  simp only [statementBindingWords, List.length_map, List.length_range]

noncomputable def verifierProgram (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) : Program Unit :=
  SmzaRp05ExecutablePcsClosure.verifierProgram ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire

/-- The statement's leaf/root bytes, PCS binding words, and PIOP relation
interpretation now share one statement input by construction. -/
theorem accepted_current_statement_has_stages (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (accepted : (verifierProgram ns dsl statement pending nonce wire).eval oracle = some ()) :
    ∃ transcript,
      Nonempty (ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript) ∧
      transcript.pendingXofFailure = false ∧
      oracle (finalInput transcript) = wire.hPiop ∧
      (finalInput transcript, wire.hPiop) ∈
        ((verifierProgram ns dsl statement pending nonce wire).record oracle).2 :=
  SmzaRp05ExecutablePcsClosure.accepted_execution_has_stages ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire oracle accepted

end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureStatement
