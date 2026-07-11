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
def arithDirectPacked64CompactBindingsV1 : Nat := 2
def arithDirectPacked128CompactBindingsV1 : Nat := 3
def arithDirectPacked16CompactBindingsV1 : Nat := 4
def arithDirectPacked32CompactBindingsV1 : Nat := 5
def arithDirectPacked64CompactBindingsSkipInitialMdsV1 : Nat := 6
def arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 : Nat := 7
def arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 : Nat := 8

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
  { activeProfile with decsNbOpenedEvals := 25 }

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
  else if arithmetization = arithDirectPacked64CompactBindingsV1 then
    asciiBytes "candidate-smallwood-direct-packed-compact-bindings"
  else if arithmetization = arithDirectPacked128CompactBindingsV1 then
    asciiBytes "candidate-smallwood-direct-packed-128-compact-bindings"
  else if arithmetization = arithDirectPacked16CompactBindingsV1 then
    asciiBytes "candidate-smallwood-direct-packed-16-compact-bindings"
  else if arithmetization = arithDirectPacked32CompactBindingsV1 then
    asciiBytes "candidate-smallwood-direct-packed-32-compact-bindings"
  else if arithmetization = arithDirectPacked64CompactBindingsSkipInitialMdsV1 then
    asciiBytes "candidate-smallwood-direct-packed-64-compact-bindings-skip-initial-mds"
  else if arithmetization = arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 then
    asciiBytes "candidate-smallwood-direct-packed-64-inline-merkle-compact-bindings-skip-initial-mds"
  else if arithmetization = arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 then
    asciiBytes "candidate-smallwood-direct-packed-128-inline-merkle-compact-bindings-skip-initial-mds"
  else
    asciiBytes "candidate-smallwood-unknown"

def poseidonRowsPerPermutation (arithmetization : Nat) : Nat :=
  if arithmetization = arithDirectPacked64CompactBindingsSkipInitialMdsV1 then
    skipInitialMdsRowsPerPermutation
  else if arithmetization = arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 then
    skipInitialMdsRowsPerPermutation
  else if arithmetization = arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 then
    skipInitialMdsRowsPerPermutation
  else
    groupedRowsPerPermutation

def deployedSmallwoodArithmetizationTags : List Nat :=
  [ arithBridge64V1,
    arithDirectPacked64V1,
    arithDirectPacked64CompactBindingsV1,
    arithDirectPacked128CompactBindingsV1,
    arithDirectPacked16CompactBindingsV1,
    arithDirectPacked32CompactBindingsV1,
    arithDirectPacked64CompactBindingsSkipInitialMdsV1,
    arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 ]

def legacyProfileArithmetizationTags : List Nat :=
  [ arithBridge64V1,
    arithDirectPacked64V1,
    arithDirectPacked64CompactBindingsV1,
    arithDirectPacked128CompactBindingsV1,
    arithDirectPacked16CompactBindingsV1,
    arithDirectPacked32CompactBindingsV1,
    arithDirectPacked64CompactBindingsSkipInitialMdsV1,
    arithDirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 ]

def profileBytes (profile : NoGrindingProfile) : List Byte :=
  u64le profile.rho
    ++ u64le profile.nbOpenedEvals
    ++ u64le profile.beta
    ++ u64le profile.openingPowBits
    ++ u64le profile.decsNbEvals
    ++ u64le profile.decsNbOpenedEvals
    ++ u64le profile.decsEta
    ++ u64le profile.decsPowBits

structure ProfileBindingParameters where
  circuitVersion : Nat
  cryptoSuite : Nat
  arithmetization : Nat
  constraintDegree : Nat
  profile : NoGrindingProfile
  poseidonWidth : Nat
  poseidonRate : Nat
  poseidonSteps : Nat
  poseidonRowsPerPermutation : Nat
deriving DecidableEq, Repr

abbrev NoGrindingProfile.wellFormed (profile : NoGrindingProfile) : Prop :=
  profile.rho < 2 ^ 64
    ∧ profile.nbOpenedEvals < 2 ^ 64
    ∧ profile.beta < 2 ^ 64
    ∧ profile.openingPowBits < 2 ^ 64
    ∧ profile.decsNbEvals < 2 ^ 64
    ∧ profile.decsNbOpenedEvals < 2 ^ 64
    ∧ profile.decsEta < 2 ^ 64
    ∧ profile.decsPowBits < 2 ^ 64

abbrev ProfileBindingParameters.wellFormed
    (parameters : ProfileBindingParameters) : Prop :=
  parameters.circuitVersion < 2 ^ 16
    ∧ parameters.cryptoSuite < 2 ^ 16
    ∧ parameters.arithmetization < 2 ^ 64
    ∧ parameters.constraintDegree < 2 ^ 64
    ∧ parameters.profile.wellFormed
    ∧ parameters.poseidonWidth < 2 ^ 64
    ∧ parameters.poseidonRate < 2 ^ 64
    ∧ parameters.poseidonSteps < 2 ^ 64
    ∧ parameters.poseidonRowsPerPermutation < 2 ^ 64

def activeProfileBindingParameters : ProfileBindingParameters :=
  { circuitVersion := activeCircuitVersion,
    cryptoSuite := activeCryptoSuite,
    arithmetization :=
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    constraintDegree := effectiveConstraintDegree,
    profile := activeProfile,
    poseidonWidth := poseidonWidth,
    poseidonRate := poseidonRate,
    poseidonSteps := poseidonSteps,
    poseidonRowsPerPermutation := skipInitialMdsRowsPerPermutation }

def profileBindingParameterBytes
    (parameters : ProfileBindingParameters) : List Byte :=
  u16le parameters.circuitVersion
    ++ u16le parameters.cryptoSuite
    ++ u64le parameters.arithmetization
    ++ u64le parameters.constraintDegree
    ++ profileBytes parameters.profile
    ++ u64le parameters.poseidonWidth
    ++ u64le parameters.poseidonRate
    ++ u64le parameters.poseidonSteps
    ++ u64le parameters.poseidonRowsPerPermutation

def profileMaterialWithParameters
    (parameters : ProfileBindingParameters) : List Byte :=
  smallwoodPublicStatementDomain
    ++ arithmetizationLabel parameters.arithmetization
    ++ smallwoodFieldXofDomain
    ++ profileBindingParameterBytes parameters

inductive ProfileBindingField
  | circuitVersion
  | cryptoSuite
  | arithmetization
  | constraintDegree
  | rho
  | openedEvaluations
  | beta
  | openingGrindingBits
  | decsEvaluations
  | decsOpenedEvaluations
  | decsEta
  | decsGrindingBits
  | poseidonWidth
  | poseidonRate
  | poseidonSteps
  | poseidonRowsPerPermutation
deriving DecidableEq, Repr

def activeProfileMutationFields : List ProfileBindingField :=
  [ .circuitVersion,
    .cryptoSuite,
    .arithmetization,
    .constraintDegree,
    .rho,
    .openedEvaluations,
    .beta,
    .openingGrindingBits,
    .decsEvaluations,
    .decsOpenedEvaluations,
    .decsEta,
    .decsGrindingBits,
    .poseidonWidth,
    .poseidonRate,
    .poseidonSteps,
    .poseidonRowsPerPermutation ]

def ProfileBindingField.label : ProfileBindingField -> String
  | .circuitVersion => "circuit-version"
  | .cryptoSuite => "crypto-suite"
  | .arithmetization => "arithmetization"
  | .constraintDegree => "constraint-degree"
  | .rho => "rho"
  | .openedEvaluations => "opened-evaluations"
  | .beta => "beta"
  | .openingGrindingBits => "opening-grinding-bits"
  | .decsEvaluations => "decs-evaluations"
  | .decsOpenedEvaluations => "decs-opened-evaluations"
  | .decsEta => "decs-eta"
  | .decsGrindingBits => "decs-grinding-bits"
  | .poseidonWidth => "poseidon-width"
  | .poseidonRate => "poseidon-rate"
  | .poseidonSteps => "poseidon-steps"
  | .poseidonRowsPerPermutation => "poseidon-rows-per-permutation"

def ProfileBindingField.mutate
    (field : ProfileBindingField) : ProfileBindingParameters :=
  match field with
  | .circuitVersion =>
      { activeProfileBindingParameters with
          circuitVersion := activeCircuitVersion + 1 }
  | .cryptoSuite =>
      { activeProfileBindingParameters with
          cryptoSuite := activeCryptoSuite + 1 }
  | .arithmetization =>
      { activeProfileBindingParameters with
          arithmetization := arithDirectPacked64V1 }
  | .constraintDegree =>
      { activeProfileBindingParameters with
          constraintDegree := effectiveConstraintDegree + 1 }
  | .rho =>
      { activeProfileBindingParameters with
          profile := { activeProfile with rho := activeProfile.rho + 1 } }
  | .openedEvaluations =>
      { activeProfileBindingParameters with
          profile :=
            { activeProfile with
              nbOpenedEvals := activeProfile.nbOpenedEvals + 1 } }
  | .beta =>
      { activeProfileBindingParameters with
          profile := { activeProfile with beta := activeProfile.beta + 1 } }
  | .openingGrindingBits =>
      { activeProfileBindingParameters with
          profile := { activeProfile with openingPowBits := 1 } }
  | .decsEvaluations =>
      { activeProfileBindingParameters with
          profile :=
            { activeProfile with decsNbEvals := activeProfile.decsNbEvals + 1 } }
  | .decsOpenedEvaluations =>
      { activeProfileBindingParameters with
          profile :=
            { activeProfile with
              decsNbOpenedEvals := activeProfile.decsNbOpenedEvals + 1 } }
  | .decsEta =>
      { activeProfileBindingParameters with
          profile := { activeProfile with decsEta := activeProfile.decsEta + 1 } }
  | .decsGrindingBits =>
      { activeProfileBindingParameters with
          profile := { activeProfile with decsPowBits := 1 } }
  | .poseidonWidth =>
      { activeProfileBindingParameters with
          poseidonWidth := SmallWoodTranscriptBinding.poseidonWidth + 1 }
  | .poseidonRate =>
      { activeProfileBindingParameters with
          poseidonRate := SmallWoodTranscriptBinding.poseidonRate + 1 }
  | .poseidonSteps =>
      { activeProfileBindingParameters with
          poseidonSteps := SmallWoodTranscriptBinding.poseidonSteps + 1 }
  | .poseidonRowsPerPermutation =>
      { activeProfileBindingParameters with
          poseidonRowsPerPermutation := skipInitialMdsRowsPerPermutation + 1 }

def activeProfileSingleFieldMutationCases :
    List (String × ProfileBindingParameters) :=
  activeProfileMutationFields.map fun field => (field.label, field.mutate)

def activeProfileSingleFieldMutationNames : List String :=
  activeProfileMutationFields.map ProfileBindingField.label

def activeProfileSingleFieldMutations : List ProfileBindingParameters :=
  activeProfileMutationFields.map ProfileBindingField.mutate

def circuitVersionWraparoundMutation : ProfileBindingParameters :=
  { activeProfileBindingParameters with
      circuitVersion := activeCircuitVersion + 2 ^ 16 }

theorem active_profile_is_no_grinding :
    activeProfile.openingPowBits = 0
      ∧ activeProfile.decsPowBits = 0 := by
  decide

theorem active_profile_binding_parameters_well_formed :
    activeProfileBindingParameters.wellFormed := by
  decide

theorem active_profile_binding_rejects_all_named_in_range_single_field_mutations :
    ∀ mutation ∈ activeProfileSingleFieldMutations,
      mutation.wellFormed
        ∧ profileMaterialWithParameters mutation ≠
          profileMaterialWithParameters activeProfileBindingParameters := by
  decide

theorem circuit_version_wraparound_mutation_is_not_well_formed :
    ¬ circuitVersionWraparoundMutation.wellFormed := by
  decide

theorem circuit_version_wraparound_collision_is_outside_production_domain :
    profileMaterialWithParameters circuitVersionWraparoundMutation =
        profileMaterialWithParameters activeProfileBindingParameters
      ∧ ¬ circuitVersionWraparoundMutation.wellFormed := by
  decide

theorem active_profile_mutation_names_cover_every_mutation :
    activeProfileSingleFieldMutationNames.length =
      activeProfileSingleFieldMutations.length := by
  decide

theorem active_profile_mutation_fields_are_unique :
    activeProfileMutationFields.Nodup := by
  decide

def smallwoodProfileMaterial
    (circuitVersion cryptoSuite arithmetization : Nat) : List Byte :=
  profileMaterialWithParameters
    { circuitVersion := circuitVersion,
      cryptoSuite := cryptoSuite,
      arithmetization := arithmetization,
      constraintDegree := effectiveConstraintDegree,
      profile := profileForArithmetization arithmetization,
      poseidonWidth := poseidonWidth,
      poseidonRate := poseidonRate,
      poseidonSteps := poseidonSteps,
      poseidonRowsPerPermutation :=
        poseidonRowsPerPermutation arithmetization }

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

theorem active_inline_merkle_profile_uses_active_decs_opening_count :
    (profileForArithmetization
      arithDirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1).decsNbOpenedEvals = 23 := by
  rfl

theorem legacy_profile_arithmetizations_use_legacy_decs_opening_count :
    ∀ tag ∈ legacyProfileArithmetizationTags,
      (profileForArithmetization tag).decsNbOpenedEvals = 25 := by
  decide

theorem deployed_smallwood_profile_materials_distinguish_arithmetization_tags :
    (deployedSmallwoodArithmetizationTags.map fun tag =>
      smallwoodProfileMaterial activeCircuitVersion activeCryptoSuite tag).Nodup := by
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
