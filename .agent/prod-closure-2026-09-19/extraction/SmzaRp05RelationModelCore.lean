import SmzaRp05PublicWords
import SmzaQ38Recovery
import HegemonCrypto.SmallWoodV8Smz9PiopSoundness

/-! Relation-dependent PIOP candidate data, independent of trace labels. -/
namespace HegemonCrypto.SmallWood.SmzaRp05TracePrefixes

open SmzaRp05StatementNamespace SmzaQ38Recovery V8Smz9PiopSoundness

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false

/-- Relation-dependent data needed by chronological prefix construction.
`width statement` is the current relation's affine-batching dimension for
that statement (including its current CSR/retained-attempt policy), not
RP04's `max 773 ...`. The q38 source rows, Merkle geometry, and challenge
types remain fixed; candidate construction and its width are supplied by the
generated current relation. -/
structure RelationModel where
  width : Statement → Nat
  recoveredCandidate : (statement : Statement) → RecoveredRows →
    Candidate (width statement)

end HegemonCrypto.SmallWood.SmzaRp05TracePrefixes
