import HegemonCrypto.SmallWoodV8Smz9OracleExtraction
import HegemonCrypto.SmallWoodV8Smz9RelationProgramComponentsGenerated
import Hegemon.Transaction.Poseidon2V8PublicDecoder

/-!
# Concrete HGV8RP03 specialization of SMZ9 candidate-oracle extraction

This module fixes the candidate inverse and executable acceptance equivalence to the materialized
HGV8RP03 program.  It also composes the exact canonical public decoder with that acceptance.
These are executable-program and layout statements only: they do not prove the five universal
typed semantic-refinement families, verifier-to-DECS proximity, Fiat--Shamir binding, commitment
binding, or production authority.
-/

namespace HegemonCrypto.SmallWood.V8Smz9ConcreteOracleExtraction

open HegemonCrypto.SmallWood.V8Smz9OracleExtraction
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8PublicDecoder
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

noncomputable section

/-- Candidate-oracle satisfaction is exactly packed interpreter acceptance for HGV8RP03. -/
theorem hgv8rp03_extracted_program_satisfied_iff_accepts_packed
    (publicWords : List Nat)
    (oracle : CommittedOracle) :
    ExtractedProgramSatisfied hgv8rp03ProgramComponents publicWords oracle ↔
      hgv8rp03ProgramComponents.AcceptsPacked publicWords
        (extractPackedWitness oracle) :=
  extracted_program_satisfied_iff_accepts_packed
    hgv8rp03ProgramComponents publicWords oracle

/--
For an already canonical typed statement, candidate extraction preserves both the exact public
decoder layout and HGV8RP03 packed interpreter acceptance.
-/
theorem hgv8rp03_extracted_program_satisfaction_decodes_canonical_public_statement
    (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (oracle : CommittedOracle)
    (satisfied : ExtractedProgramSatisfied hgv8rp03ProgramComponents
      (encodePublicStatement statement) oracle) :
    decodePublicStatement? (encodePublicStatement statement) = some statement ∧
      hgv8rp03ProgramComponents.AcceptsPacked (encodePublicStatement statement)
        (extractPackedWitness oracle) := by
  exact ⟨decode_encode_of_canonical exactV8SemanticPrimitives statement canonical,
    (hgv8rp03_extracted_program_satisfied_iff_accepts_packed
      (encodePublicStatement statement) oracle).mp satisfied⟩

/-- The concrete HGV8RP03 nonlinear interpreter has the pointwise root-zero consequence. -/
theorem hgv8rp03_extracted_program_satisfaction_makes_each_nonlinear_root_zero
    {publicWords : List Nat}
    {oracle : CommittedOracle}
    (satisfied : ExtractedProgramSatisfied hgv8rp03ProgramComponents publicWords oracle)
    (lane : Fin V8Smz9OracleExtraction.packingFactor)
    {root : Nat}
    (rootMembership : root ∈ hgv8rp03ProgramComponents.nonlinearExecutable.roots) :
    ∃ values,
      evalExpressionNodes publicWords (extractedWitnessLaneRows oracle lane)
          hgv8rp03ProgramComponents.nonlinearExecutable.expressions = some values ∧
        values[root]? = some 0 :=
  extracted_program_satisfaction_makes_each_nonlinear_root_zero
    satisfied lane rootMembership

end

end HegemonCrypto.SmallWood.V8Smz9ConcreteOracleExtraction
