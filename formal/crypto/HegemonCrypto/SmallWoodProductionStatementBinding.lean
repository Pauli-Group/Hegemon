import Hegemon.Transaction.SmallWoodPublicStatementBinding
import HegemonCrypto.SmallWoodRoundByRound

/-!
# Exact active public-statement transcript binding

This module closes the byte boundary between the production constraint map and
the SHA-512 transcript. It uses the exact bincode layout checked against Rust,
then interprets the padded transcript bytes as the same little-endian `u64`
words consumed by the native verifier.
-/

namespace HegemonCrypto.SmallWood.ProductionStatementBinding

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodPublicStatementBinding
open Hegemon.Transaction.SmallWoodTranscriptBinding

def canonicalProtocolBytes
    (bytes : List Hegemon.Byte) : List HegemonCrypto.CanonicalBytes.Byte :=
  bytes.map fun value =>
    ⟨value % 256, Nat.mod_lt value (by decide)⟩

/-- Little-endian `u64` interpretation used after Rust pads the binding to eight bytes. -/
def bindingBytesToWords
    (bytes : List HegemonCrypto.CanonicalBytes.Byte) : List Word :=
  (List.range (bytes.length / 8)).map fun index =>
    ⟨decodeLE ((bytes.drop (index * 8)).take 8) % (2 ^ 64),
      Nat.mod_lt _ (by positivity)⟩

def productionPublicStatementBytes
    (statement : Statement) : List HegemonCrypto.CanonicalBytes.Byte :=
  canonicalProtocolBytes
    (smallwoodPublicStatementBytes statement.publicValues)

def productionTranscriptBindingBytes
    (statement : Statement) : List HegemonCrypto.CanonicalBytes.Byte :=
  canonicalProtocolBytes
    (smallwoodTranscriptBinding
      activeCircuitVersion
      activeCryptoSuite
      arithDirectPacked64CompressedLevel5
      (smallwoodPublicStatementBytes statement.publicValues))

/--
The unique words used by every active verifier challenge. No transcript word is
provided independently of the exact production statement.
-/
def productionStatementBindingWords
    (statement : Statement) : List Word :=
  bindingBytesToWords (productionTranscriptBindingBytes statement)

def StatementBindingExact
    (statement : Statement)
    (transcript : HegemonCrypto.SmallWoodTranscript.Transcript) : Prop :=
  transcript.statementBindingWords =
    productionStatementBindingWords statement

theorem production_public_statement_encoding_has_fixed_length
    {statement : Statement}
    (active : ActiveStatement statement) :
    (productionPublicStatementBytes statement).length = 660 := by
  have mapBound := active.2.2.2.2.2
  change
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.productionConstraintMapBoundB
      statement = true at mapBound
  unfold
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.productionConstraintMapBoundB
      at mapBound
  simp only [Bool.and_eq_true] at mapBound
  have canonical :
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.canonicalProductionPublicValuesB
        statement.publicValues = true :=
    mapBound.1.1.1.1.1.1
  unfold
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.canonicalProductionPublicValuesB
      at canonical
  simp only [Bool.and_eq_true] at canonical
  have publicLength : statement.publicValues.length = 78 := by
    exact of_decide_eq_true canonical.1.1.1.1.1.1.1.1
  simp [productionPublicStatementBytes, canonicalProtocolBytes,
    smallwood_public_statement_bytes_length publicLength]

end HegemonCrypto.SmallWood.ProductionStatementBinding
