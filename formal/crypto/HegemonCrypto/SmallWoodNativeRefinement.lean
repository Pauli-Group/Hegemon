import Hegemon.Transaction.ProofWrapperWire
import HegemonCrypto.SmallWoodProofWireExamples
import HegemonCrypto.TransactionProofWire

/-!
# Accepted SmallWood byte-path refinement

This module composes the three deterministic parsers reached before cryptographic verification:

1. the outer bincode `TransactionProof` wrapper;
2. the current SmallWood candidate wrapper; and
3. the active compact `SMW2` proof.

The production-semantics package supplies independently reviewed bincode fixture constructors for
the outer wrapper.  The research package supplies exact executable codecs for the candidate and
inner proof.  The composite examples therefore exercise the same bytes across both packages.

The universal theorems establish exact consumption, canonical re-encoding, and encoding
injectivity for the mathematical codec.  Generated cases bind that codec to the three Rust parsers.
They do not prove arbitrary Rust/compiler refinement or cryptographic verifier equivalence.
-/

namespace HegemonCrypto.SmallWood.NativeRefinement

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWoodCandidateWire
open HegemonCrypto.SmallWoodProofWire
open HegemonCrypto.SmallWoodProofWireExamples
open HegemonCrypto.TransactionProofWire

theorem decode_active_artifact_iff_canonical_encoding
    {input : List Byte}
    {artifact : ActiveAcceptedProofWire} :
    decodeActiveAcceptedProofWireExact input = some artifact ↔
      artifact.Canonical ∧ input = artifact.encode := by
  constructor
  · exact decodeActiveAcceptedProofWireExact_sound
  · rintro ⟨canonical, rfl⟩
    exact decodeActiveAcceptedProofWireExact_encode artifact canonical

/-- Canonical accepted-path bytes identify one and only one decoded artifact. -/
theorem canonical_active_artifact_encoding_injective
    {left right : ActiveAcceptedProofWire}
    (leftCanonical : left.Canonical)
    (rightCanonical : right.Canonical)
    (sameBytes : left.encode = right.encode) :
    left = right := by
  have leftDecoded :=
    decodeActiveAcceptedProofWireExact_encode left leftCanonical
  have rightDecoded :=
    decodeActiveAcceptedProofWireExact_encode right rightCanonical
  rw [sameBytes, rightDecoded] at leftDecoded
  exact (Option.some.inj leftDecoded).symm

def countedBytes (bytes : List Byte) : CountedWire :=
  { countBytes := encodeLE 8 bytes.length, payloadBytes := bytes }

def countedWords (words : List Nat) : CountedWire :=
  { countBytes := encodeLE 8 words.length,
    payloadBytes := words.flatMap (encodeLE 8) }

def importProductionBytes (bytes : List Hegemon.Byte) : List Byte :=
  bytes.map fun value =>
    ⟨value % 256, Nat.mod_lt value (by decide)⟩

def currentCandidateBytes
    (arithmetization : Nat)
    (proofBytes : List Byte)
    (auxiliaryWords : List Nat := []) : List Byte :=
  (encodeLE 4 arithmetization)
    ++ (countedBytes proofBytes).encode
    ++ (countedWords auxiliaryWords).encode

def outerArtifactBytes
    (backend : Nat)
    (candidateBytes : List Byte)
    (serializedStarkInputs : Option (List Byte)) : List Byte :=
  importProductionBytes
      Hegemon.Transaction.ProofWrapperWire.transactionProofWrapperPrefixBeforeBackend
    ++ encodeLE 4 backend
    ++ (countedBytes candidateBytes).encode
    ++ match serializedStarkInputs with
      | none => [0]
      | some bytes => [1] ++ bytes

def activeArtifactBytesFor
    (proofBytes : List Byte)
    (arithmetization : Nat := activeArithmetizationVariant)
    (auxiliaryWords : List Nat := [])
    (backend : Nat := Hegemon.Transaction.ProofWrapperWire.smallwoodBackendVariant)
    (serializedStarkInputs : Option (List Byte) :=
      some (importProductionBytes
        Hegemon.Transaction.ProofWrapperWire.serializedStarkInputsBytes)) :
    List Byte :=
  outerArtifactBytes backend
    (currentCandidateBytes arithmetization proofBytes auxiliaryWords)
    serializedStarkInputs

def canonicalActiveArtifactBytes : List Byte :=
  activeArtifactBytesFor canonicalMinimalProof.encode

def trailingOuterArtifactBytes : List Byte :=
  canonicalActiveArtifactBytes ++ [170]

def wrongBackendArtifactBytes : List Byte :=
  activeArtifactBytesFor canonicalMinimalProof.encode
    (backend := 0)

def missingStarkInputsArtifactBytes : List Byte :=
  activeArtifactBytesFor canonicalMinimalProof.encode
    (serializedStarkInputs := none)

def circuitVersionOffset : Nat :=
  (importProductionBytes
    Hegemon.Transaction.ProofWrapperWire.transactionPublicInputsBytes).length - 4

def cryptoSuiteOffset : Nat :=
  (importProductionBytes
    Hegemon.Transaction.ProofWrapperWire.transactionPublicInputsBytes).length - 2

def wrongCircuitVersionArtifactBytes : List Byte :=
  canonicalActiveArtifactBytes.set circuitVersionOffset 3

def wrongCryptoSuiteArtifactBytes : List Byte :=
  canonicalActiveArtifactBytes.set cryptoSuiteOffset 2

def wrongArithmetizationArtifactBytes : List Byte :=
  activeArtifactBytesFor canonicalMinimalProof.encode
    (arithmetization := activeArithmetizationVariant - 1)

def auxiliaryWordArtifactBytes : List Byte :=
  activeArtifactBytesFor canonicalMinimalProof.encode
    (auxiliaryWords := [7])

def trailingInnerProofArtifactBytes : List Byte :=
  activeArtifactBytesFor (canonicalMinimalProof.encode ++ [170])

def noncanonicalFieldArtifactBytes : List Byte :=
  activeArtifactBytesFor noncanonicalFieldProof.encode

def emptyInnerProofArtifactBytes : List Byte :=
  activeArtifactBytesFor []

def activeArtifactParserAccepts (bytes : List Byte) : Bool :=
  (decodeActiveAcceptedProofWireExact bytes).isSome

set_option maxRecDepth 200000 in
theorem canonical_active_artifact_bytes_accept :
    activeArtifactParserAccepts canonicalActiveArtifactBytes = true := by
  decide

set_option maxRecDepth 200000 in
theorem trailing_outer_artifact_bytes_reject :
    activeArtifactParserAccepts trailingOuterArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem wrong_backend_artifact_bytes_reject :
    activeArtifactParserAccepts wrongBackendArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem missing_stark_inputs_artifact_bytes_reject :
    activeArtifactParserAccepts missingStarkInputsArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem wrong_circuit_version_artifact_bytes_reject :
    activeArtifactParserAccepts wrongCircuitVersionArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem wrong_crypto_suite_artifact_bytes_reject :
    activeArtifactParserAccepts wrongCryptoSuiteArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem wrong_arithmetization_artifact_bytes_reject :
    activeArtifactParserAccepts wrongArithmetizationArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem auxiliary_word_artifact_bytes_reject :
    activeArtifactParserAccepts auxiliaryWordArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem trailing_inner_proof_artifact_bytes_reject :
    activeArtifactParserAccepts trailingInnerProofArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem noncanonical_field_artifact_bytes_reject :
    activeArtifactParserAccepts noncanonicalFieldArtifactBytes = false := by
  decide

set_option maxRecDepth 200000 in
theorem empty_inner_proof_artifact_bytes_reject :
    activeArtifactParserAccepts emptyInnerProofArtifactBytes = false := by
  decide

end HegemonCrypto.SmallWood.NativeRefinement
