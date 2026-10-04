import Hegemon.Transaction.SmallWoodTranscriptBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodPublicStatementBinding

open Hegemon.Transaction.SmallWoodTranscriptBinding

def verifierPublicInputBaseLength : Nat := 76

def smallwoodPublicStatementValueCount : Nat :=
  verifierPublicInputBaseLength + 2

def smallwoodPublicStatementValues
    (verifierPublicValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : List Nat :=
  verifierPublicValues ++ [circuitVersion, cryptoSuite]

def activeRawWitnessLength : Nat := 241
def activeRelationRowCount : Nat := 699
def activePoseidonPermutationCount : Nat := 172
def activePoseidonStateRowCount : Nat :=
  activePoseidonPermutationCount *
    SmallWoodTranscriptBinding.compressedRowsPerPermutation
def activeExpandedWitnessLength : Nat :=
  activeRelationRowCount * 64
def activePackingFactor : Nat := 64
def activeEffectiveConstraintDegree : Nat := 8

def bincodeVecU64 (values : List Nat) : List Byte :=
  u64le values.length ++ (values.map u64le).flatten

/--
Exact bincode 1.x encoding of the active Rust `SmallwoodPublicStatement`.

The field order and widths match the production Rust structure:
`Vec<u64>`, six `u32` geometry fields, then two `u16` fields. The geometry is
consensus-fixed for the active 64-lane compressed relation.
-/
def smallwoodPublicStatementBytes (statementValues : List Nat) : List Byte :=
  bincodeVecU64 statementValues
    ++ u32le statementValues.length
    ++ u32le activeRawWitnessLength
    ++ u32le activeRelationRowCount
    ++ u32le activePoseidonPermutationCount
    ++ u32le activePoseidonStateRowCount
    ++ u32le activeExpandedWitnessLength
    ++ u16le activePackingFactor
    ++ u16le activeEffectiveConstraintDegree

def validSmallwoodPublicStatementValues
    (verifierPublicValues statementValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : Bool :=
  verifierPublicValues.length = verifierPublicInputBaseLength
    && statementValues =
      smallwoodPublicStatementValues
        verifierPublicValues
        circuitVersion
        cryptoSuite

structure PublicStatementSurface where
  verifierPublicValues : List Nat
  statementValues : List Nat
  circuitVersion : Nat
  cryptoSuite : Nat
  arithmetization : Nat
  statementBytes : List Byte
  transcriptBytes : List Byte

def transcriptSurface (surface : PublicStatementSurface) :
    TranscriptSurface :=
  { circuitVersion := surface.circuitVersion,
    cryptoSuite := surface.cryptoSuite,
    arithmetization := surface.arithmetization,
    statementBytes := surface.statementBytes,
    transcriptBytes := surface.transcriptBytes }

def acceptedSmallwoodPublicStatementBinding
    (surface : PublicStatementSurface) : Prop :=
  surface.verifierPublicValues.length = verifierPublicInputBaseLength
    ∧ surface.statementValues =
      smallwoodPublicStatementValues
        surface.verifierPublicValues
        surface.circuitVersion
        surface.cryptoSuite
    ∧ surface.statementBytes =
      smallwoodPublicStatementBytes surface.statementValues
    ∧ acceptedSmallwoodTranscriptBinding (transcriptSurface surface)

structure SmallWoodPublicStatementBindingFacts
    (surface : PublicStatementSurface) : Prop where
  verifierBaseLength :
    surface.verifierPublicValues.length = verifierPublicInputBaseLength
  statementValuesAppendVersion :
    surface.statementValues =
      surface.verifierPublicValues ++ [surface.circuitVersion, surface.cryptoSuite]
  statementValuesExactLength :
    surface.statementValues.length = smallwoodPublicStatementValueCount
  statementBytesBoundary :
    surface.statementBytes =
      smallwoodPublicStatementBytes surface.statementValues
  transcriptBinding :
    acceptedSmallwoodTranscriptBinding (transcriptSurface surface)

theorem base_verifier_public_vector_length :
    verifierPublicInputBaseLength = 76 := by
  rfl

theorem smallwood_public_statement_values_append_version_binding
    (verifierPublicValues : List Nat)
    (circuitVersion cryptoSuite : Nat) :
    smallwoodPublicStatementValues
        verifierPublicValues
        circuitVersion
        cryptoSuite =
      verifierPublicValues ++ [circuitVersion, cryptoSuite] := by
  rfl

theorem smallwood_public_statement_values_length
    {verifierPublicValues : List Nat}
    {circuitVersion cryptoSuite : Nat}
    (baseLen : verifierPublicValues.length = verifierPublicInputBaseLength) :
    (smallwoodPublicStatementValues
        verifierPublicValues
        circuitVersion
        cryptoSuite).length =
      smallwoodPublicStatementValueCount := by
  simp
    [smallwoodPublicStatementValues,
      smallwoodPublicStatementValueCount,
      verifierPublicInputBaseLength,
      baseLen]

theorem active_public_statement_geometry :
    activeRawWitnessLength = 241
      ∧ activeRelationRowCount = 699
      ∧ activePoseidonPermutationCount = 172
      ∧ activePoseidonStateRowCount = 24424
      ∧ activeExpandedWitnessLength = 44736
      ∧ activePackingFactor = 64
      ∧ activeEffectiveConstraintDegree = 8 := by
  decide

theorem smallwood_public_statement_bytes_length
    {statementValues : List Nat}
    (statementLength :
      statementValues.length = smallwoodPublicStatementValueCount) :
    (smallwoodPublicStatementBytes statementValues).length = 660 := by
  have encodedValuesLength :
      ((statementValues.map u64le).flatten).length =
        statementValues.length * 8 := by
    clear statementLength
    induction statementValues with
    | nil => rfl
    | cons value rest induction =>
        simp only [List.map_cons, List.flatten_cons, List.length_append,
          List.length_cons]
        rw [u64le_length, induction]
        omega
  simp [smallwoodPublicStatementBytes, bincodeVecU64,
    smallwoodPublicStatementValueCount, verifierPublicInputBaseLength,
    encodedValuesLength, statementLength, u64le_length, u32le_length,
    u16le_length]

theorem accepted_smallwood_public_statement_binding_exposes_verifier_prefix
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    surface.statementValues =
      surface.verifierPublicValues ++ [surface.circuitVersion, surface.cryptoSuite] := by
  rcases accepted with ⟨_baseLen, statementValues, _bytesBoundary, _transcript⟩
  simpa [smallwoodPublicStatementValues] using statementValues

theorem accepted_smallwood_public_statement_binding_exposes_version_suffix
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    ∃ verifierPrefix,
      surface.statementValues =
        verifierPrefix ++ [surface.circuitVersion, surface.cryptoSuite]
        ∧ verifierPrefix = surface.verifierPublicValues := by
  exact
    ⟨surface.verifierPublicValues,
      accepted_smallwood_public_statement_binding_exposes_verifier_prefix accepted,
      rfl⟩

theorem accepted_smallwood_public_statement_binding_forbids_public_value_extension
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    surface.statementValues.length = smallwoodPublicStatementValueCount := by
  rcases accepted with ⟨baseLen, statementValues, _bytesBoundary, _transcript⟩
  rw [statementValues]
  exact
    smallwood_public_statement_values_length
      (verifierPublicValues := surface.verifierPublicValues)
      (circuitVersion := surface.circuitVersion)
      (cryptoSuite := surface.cryptoSuite)
      baseLen

theorem accepted_smallwood_public_statement_binding_feeds_transcript_surface
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    acceptedSmallwoodTranscriptBinding (transcriptSurface surface) := by
  exact accepted.right.right.right

theorem accepted_smallwood_public_statement_binding_facts
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    SmallWoodPublicStatementBindingFacts surface := by
  exact
    { verifierBaseLength := accepted.left,
      statementValuesAppendVersion :=
        accepted_smallwood_public_statement_binding_exposes_verifier_prefix accepted,
      statementValuesExactLength :=
        accepted_smallwood_public_statement_binding_forbids_public_value_extension accepted,
      statementBytesBoundary := accepted.right.right.left,
      transcriptBinding :=
        accepted_smallwood_public_statement_binding_feeds_transcript_surface accepted }

end SmallWoodPublicStatementBinding
end Transaction
end Hegemon
