import Hegemon.Transaction.SmallWoodTranscriptBinding

namespace Hegemon
namespace Transaction
namespace SmallWoodPublicStatementBinding

open Hegemon.Transaction.SmallWoodTranscriptBinding

def p3PublicInputBaseLength : Nat := 76

def smallwoodPublicStatementValueCount : Nat :=
  p3PublicInputBaseLength + 2

def smallwoodPublicStatementValues
    (p3PublicValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : List Nat :=
  p3PublicValues ++ [circuitVersion, cryptoSuite]

def validSmallwoodPublicStatementValues
    (p3PublicValues statementValues : List Nat)
    (circuitVersion cryptoSuite : Nat) : Bool :=
  p3PublicValues.length = p3PublicInputBaseLength
    && statementValues =
      smallwoodPublicStatementValues
        p3PublicValues
        circuitVersion
        cryptoSuite

structure PublicStatementSurface where
  p3PublicValues : List Nat
  statementValues : List Nat
  circuitVersion : Nat
  cryptoSuite : Nat
  arithmetization : Nat
  statementBytes : List Byte
  transcriptBytes : List Byte
  statementBytesBindStatementValues : Prop

def transcriptSurface (surface : PublicStatementSurface) :
    TranscriptSurface :=
  { circuitVersion := surface.circuitVersion,
    cryptoSuite := surface.cryptoSuite,
    arithmetization := surface.arithmetization,
    statementBytes := surface.statementBytes,
    transcriptBytes := surface.transcriptBytes }

def acceptedSmallwoodPublicStatementBinding
    (surface : PublicStatementSurface) : Prop :=
  surface.p3PublicValues.length = p3PublicInputBaseLength
    ∧ surface.statementValues =
      smallwoodPublicStatementValues
        surface.p3PublicValues
        surface.circuitVersion
        surface.cryptoSuite
    ∧ surface.statementBytesBindStatementValues
    ∧ acceptedSmallwoodTranscriptBinding (transcriptSurface surface)

structure SmallWoodPublicStatementBindingFacts
    (surface : PublicStatementSurface) : Prop where
  p3BaseLength :
    surface.p3PublicValues.length = p3PublicInputBaseLength
  statementValuesAppendVersion :
    surface.statementValues =
      surface.p3PublicValues ++ [surface.circuitVersion, surface.cryptoSuite]
  statementValuesExactLength :
    surface.statementValues.length = smallwoodPublicStatementValueCount
  statementBytesBoundary :
    surface.statementBytesBindStatementValues
  transcriptBinding :
    acceptedSmallwoodTranscriptBinding (transcriptSurface surface)

theorem base_p3_public_vector_length :
    p3PublicInputBaseLength = 76 := by
  rfl

theorem smallwood_public_statement_values_append_version_binding
    (p3PublicValues : List Nat)
    (circuitVersion cryptoSuite : Nat) :
    smallwoodPublicStatementValues
        p3PublicValues
        circuitVersion
        cryptoSuite =
      p3PublicValues ++ [circuitVersion, cryptoSuite] := by
  rfl

theorem smallwood_public_statement_values_length
    {p3PublicValues : List Nat}
    {circuitVersion cryptoSuite : Nat}
    (baseLen : p3PublicValues.length = p3PublicInputBaseLength) :
    (smallwoodPublicStatementValues
        p3PublicValues
        circuitVersion
        cryptoSuite).length =
      smallwoodPublicStatementValueCount := by
  simp
    [smallwoodPublicStatementValues,
      smallwoodPublicStatementValueCount,
      p3PublicInputBaseLength,
      baseLen]

theorem accepted_smallwood_public_statement_binding_exposes_p3_prefix
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    surface.statementValues =
      surface.p3PublicValues ++ [surface.circuitVersion, surface.cryptoSuite] := by
  rcases accepted with ⟨_baseLen, statementValues, _bytesBoundary, _transcript⟩
  simpa [smallwoodPublicStatementValues] using statementValues

theorem accepted_smallwood_public_statement_binding_exposes_version_suffix
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    ∃ p3Prefix,
      surface.statementValues =
        p3Prefix ++ [surface.circuitVersion, surface.cryptoSuite]
        ∧ p3Prefix = surface.p3PublicValues := by
  exact
    ⟨surface.p3PublicValues,
      accepted_smallwood_public_statement_binding_exposes_p3_prefix accepted,
      rfl⟩

theorem accepted_smallwood_public_statement_binding_forbids_public_value_extension
    {surface : PublicStatementSurface}
    (accepted : acceptedSmallwoodPublicStatementBinding surface) :
    surface.statementValues.length = smallwoodPublicStatementValueCount := by
  rcases accepted with ⟨baseLen, statementValues, _bytesBoundary, _transcript⟩
  rw [statementValues]
  exact
    smallwood_public_statement_values_length
      (p3PublicValues := surface.p3PublicValues)
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
    { p3BaseLength := accepted.left,
      statementValuesAppendVersion :=
        accepted_smallwood_public_statement_binding_exposes_p3_prefix accepted,
      statementValuesExactLength :=
        accepted_smallwood_public_statement_binding_forbids_public_value_extension accepted,
      statementBytesBoundary := accepted.right.right.left,
      transcriptBinding :=
        accepted_smallwood_public_statement_binding_feeds_transcript_surface accepted }

end SmallWoodPublicStatementBinding
end Transaction
end Hegemon
