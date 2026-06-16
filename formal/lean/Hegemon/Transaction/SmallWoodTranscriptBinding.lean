import Hegemon.Bytes

set_option maxRecDepth 10000

namespace Hegemon
namespace Transaction
namespace SmallWoodTranscriptBinding

def smallwoodBindingTranscriptDomain : List Byte :=
  asciiBytes "hegemon.tx.smallwood-binding-transcript.v1"

def smallwoodPublicStatementDomain : List Byte :=
  asciiBytes "hegemon.tx.smallwood-public-statement.v1"

def smallwoodFieldXofDomain : List Byte :=
  asciiBytes "hegemon.blake3-field-xof.v1"

def activeCircuitVersion : Nat := 2
def activeCryptoSuite : Nat := 2

def arithBridge64V1 : Nat := 0
def arithDirectPacked64V1 : Nat := 1
def arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 : Nat := 7

def effectiveConstraintDegree : Nat := 8
def poseidonWidth : Nat := 12
def poseidonRate : Nat := 6
def poseidonSteps : Nat := 31
def groupedRowsPerPermutation : Nat := 32
def skipInitialMdsRowsPerPermutation : Nat := 31

structure NoGrindingProfile where
  rho : Nat
  nbOpenedEvals : Nat
  beta : Nat
  openingPowBits : Nat
  decsNbEvals : Nat
  decsNbOpenedEvals : Nat
  decsEta : Nat
  decsPowBits : Nat
deriving DecidableEq, Repr

def activeProfile : NoGrindingProfile :=
  { rho := 2,
    nbOpenedEvals := 3,
    beta := 2,
    openingPowBits := 0,
    decsNbEvals := 32768,
    decsNbOpenedEvals := 23,
    decsEta := 3,
    decsPowBits := 0 }

def legacyProfile : NoGrindingProfile :=
  { activeProfile with decsNbOpenedEvals := 24 }

def profileForArithmetization (arithmetization : Nat) : NoGrindingProfile :=
  if arithmetization = arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 then
    activeProfile
  else
    legacyProfile

def arithmetizationLabel (arithmetization : Nat) : List Byte :=
  if arithmetization = arithBridge64V1 then
    asciiBytes "candidate-smallwood-bridge-pcs-ark"
  else if arithmetization = arithDirectPacked64V1 then
    asciiBytes "candidate-smallwood-direct-packed-payload"
  else if arithmetization = arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 then
    asciiBytes "candidate-smallwood-direct-packed-64-inline-merkle-compact-bindings-skip-initial-mds"
  else
    asciiBytes "candidate-smallwood-unknown"

def poseidonRowsPerPermutation (arithmetization : Nat) : Nat :=
  if arithmetization = arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 then
    skipInitialMdsRowsPerPermutation
  else
    groupedRowsPerPermutation

def profileBytes (profile : NoGrindingProfile) : List Byte :=
  u64le profile.rho
    ++ u64le profile.nbOpenedEvals
    ++ u64le profile.beta
    ++ u64le profile.openingPowBits
    ++ u64le profile.decsNbEvals
    ++ u64le profile.decsNbOpenedEvals
    ++ u64le profile.decsEta
    ++ u64le profile.decsPowBits

def smallwoodProfileMaterial
    (circuitVersion cryptoSuite arithmetization : Nat) : List Byte :=
  smallwoodPublicStatementDomain
    ++ arithmetizationLabel arithmetization
    ++ smallwoodFieldXofDomain
    ++ u16le circuitVersion
    ++ u16le cryptoSuite
    ++ u64le arithmetization
    ++ u64le effectiveConstraintDegree
    ++ profileBytes (profileForArithmetization arithmetization)
    ++ u64le poseidonWidth
    ++ u64le poseidonRate
    ++ u64le poseidonSteps
    ++ u64le (poseidonRowsPerPermutation arithmetization)

def paddingLength (bytes : List Byte) : Nat :=
  (8 - bytes.length % 8) % 8

def paddingBytes (bytes : List Byte) : List Byte :=
  List.replicate (paddingLength bytes) 0

def unpaddedTranscript
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  smallwoodBindingTranscriptDomain
    ++ smallwoodProfileMaterial circuitVersion cryptoSuite arithmetization
    ++ statementBytes

def transcriptPadding
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  paddingBytes
    (unpaddedTranscript circuitVersion cryptoSuite arithmetization statementBytes)

def transcriptAfterStatement
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  transcriptPadding circuitVersion cryptoSuite arithmetization statementBytes

def transcriptAfterProfile
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  statementBytes
    ++ transcriptAfterStatement circuitVersion cryptoSuite arithmetization statementBytes

def transcriptAfterDomain
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  smallwoodProfileMaterial circuitVersion cryptoSuite arithmetization
    ++ transcriptAfterProfile circuitVersion cryptoSuite arithmetization statementBytes

def smallwoodTranscriptBinding
    (circuitVersion cryptoSuite arithmetization : Nat)
    (statementBytes : List Byte) : List Byte :=
  smallwoodBindingTranscriptDomain
    ++ transcriptAfterDomain circuitVersion cryptoSuite arithmetization statementBytes

structure TranscriptSurface where
  circuitVersion : Nat
  cryptoSuite : Nat
  arithmetization : Nat
  statementBytes : List Byte
  transcriptBytes : List Byte
deriving DecidableEq, Repr

def acceptedSmallwoodTranscriptBinding (surface : TranscriptSurface) : Prop :=
  surface.transcriptBytes =
    smallwoodTranscriptBinding
      surface.circuitVersion
      surface.cryptoSuite
      surface.arithmetization
      surface.statementBytes

def SmallwoodTranscriptBindingFacts (surface : TranscriptSurface) : Prop :=
  acceptedSmallwoodTranscriptBinding surface

def activeProfileMaterial : List Byte :=
  smallwoodProfileMaterial
    activeCircuitVersion
    activeCryptoSuite
    arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1

def legacyDirectProfileMaterial : List Byte :=
  smallwoodProfileMaterial
    activeCircuitVersion
    activeCryptoSuite
    arithDirectPacked64V1

def sampleStatementBytes : List Byte :=
  patternedBytes 37 90

def sampleTranscriptBinding : List Byte :=
  smallwoodTranscriptBinding
    activeCircuitVersion
    activeCryptoSuite
    arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
    sampleStatementBytes

def sampleSurface : TranscriptSurface :=
  { circuitVersion := activeCircuitVersion,
    cryptoSuite := activeCryptoSuite,
    arithmetization :=
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    statementBytes := sampleStatementBytes,
    transcriptBytes := sampleTranscriptBinding }

-- This models transcript construction and vector conformance only; backend
-- cryptographic soundness and generic serialization correctness are external.
theorem smallwood_profile_material_binds_version :
    activeProfileMaterial =
      smallwoodPublicStatementDomain
        ++ arithmetizationLabel
          arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        ++ smallwoodFieldXofDomain
        ++ u16le activeCircuitVersion
        ++ u16le activeCryptoSuite
        ++ u64le arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        ++ u64le effectiveConstraintDegree
        ++ profileBytes activeProfile
        ++ u64le poseidonWidth
        ++ u64le poseidonRate
        ++ u64le poseidonSteps
        ++ u64le skipInitialMdsRowsPerPermutation := by
  decide

theorem smallwood_profile_material_binds_arithmetization :
    activeProfileMaterial != legacyDirectProfileMaterial := by
  decide

theorem smallwood_transcript_binding_starts_with_domain :
    ∃ tail,
      sampleTranscriptBinding = smallwoodBindingTranscriptDomain ++ tail := by
  unfold sampleTranscriptBinding smallwoodTranscriptBinding
  exact
    ⟨transcriptAfterDomain
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        sampleStatementBytes,
      rfl⟩

theorem smallwood_transcript_binding_includes_profile_material :
    ∃ pre suffix,
      sampleTranscriptBinding = pre ++ activeProfileMaterial ++ suffix := by
  unfold sampleTranscriptBinding smallwoodTranscriptBinding transcriptAfterDomain
  unfold activeProfileMaterial
  exact
    ⟨smallwoodBindingTranscriptDomain,
      transcriptAfterProfile
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        sampleStatementBytes,
      rfl⟩

theorem smallwood_transcript_binding_includes_statement_bytes :
    ∃ pre suffix,
      sampleTranscriptBinding = pre ++ sampleStatementBytes ++ suffix := by
  unfold sampleTranscriptBinding smallwoodTranscriptBinding transcriptAfterDomain
  unfold transcriptAfterProfile
  exact
    ⟨smallwoodBindingTranscriptDomain
        ++ smallwoodProfileMaterial
          activeCircuitVersion
          activeCryptoSuite
          arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
      transcriptAfterStatement
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        sampleStatementBytes,
      rfl⟩

theorem smallwood_transcript_binding_padding_aligned_to_eight :
    sampleTranscriptBinding =
      unpaddedTranscript
        activeCircuitVersion
        activeCryptoSuite
        arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        sampleStatementBytes
        ++ paddingBytes
          (unpaddedTranscript
            activeCircuitVersion
            activeCryptoSuite
            arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
            sampleStatementBytes) := by
  unfold sampleTranscriptBinding smallwoodTranscriptBinding transcriptAfterDomain
  unfold transcriptAfterProfile transcriptAfterStatement transcriptPadding
  unfold unpaddedTranscript
  rfl

theorem accepted_smallwood_transcript_binding_implies_statement_boundary_facts
    {surface : TranscriptSurface}
    (accepted : acceptedSmallwoodTranscriptBinding surface) :
    SmallwoodTranscriptBindingFacts surface := by
  exact accepted

end SmallWoodTranscriptBinding
end Transaction
end Hegemon
