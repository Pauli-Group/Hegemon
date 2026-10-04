import Hegemon.FullShakeRelation.Core

namespace Hegemon
namespace FullShakeRelation

structure StatementWidthLedger where
  magic : Nat
  grammarVersion : Nat
  activityFlags : Nat
  anchor : Nat
  nullifiers : Nat
  commitments : Nat
  ciphertextHashes : Nat
  balanceAssetSlots : Nat
  fee : Nat
  valueBalance : Nat
  stablecoinBinding : Nat
  balanceTag : Nat
  activationBinding : Nat
deriving DecidableEq, Repr

def StatementWidthLedger.total (widths : StatementWidthLedger) : Nat :=
  widths.magic
    + widths.grammarVersion
    + widths.activityFlags
    + widths.anchor
    + widths.nullifiers
    + widths.commitments
    + widths.ciphertextHashes
    + widths.balanceAssetSlots
    + widths.fee
    + widths.valueBalance
    + widths.stablecoinBinding
    + widths.balanceTag
    + widths.activationBinding

/-
Stablecoin binding is 1 + 8 + 4 + 9 + 3*56 = 190 bytes.
Activation is 4*2 + 8 + 8 + 32 + 48 + 48 = 152 bytes.
-/
def canonicalWidths : StatementWidthLedger :=
  { magic := 8,
    grammarVersion := 2,
    activityFlags := 4,
    anchor := digestBytes,
    nullifiers := 2 * digestBytes,
    commitments := 2 * digestBytes,
    ciphertextHashes := 2 * digestBytes,
    balanceAssetSlots := 4 * 8,
    fee := 8,
    valueBalance := 1 + 8,
    stablecoinBinding := 1 + 8 + 4 + (1 + 8) + 3 * digestBytes,
    balanceTag := digestBytes,
    activationBinding := 4 * 2 + 8 + 8 + 32 + 48 + 48 }

theorem canonical_width_ledger_is_exactly_853 :
    canonicalWidths.total = canonicalStatementBytes := by
  decide

theorem public_digest_width_is_exactly_56 : digestBytes = 56 := by
  rfl

structure StatementParserSurface where
  widths : StatementWidthLedger
  totalBytes : Nat
  magicMatches : Bool
  grammarVersionMatches : Bool
  flagsBinary : Bool
  signedAmountsCanonical : Bool
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def statementParserAccepts (surface : StatementParserSurface) : Bool :=
  surface.widths == canonicalWidths
    && surface.totalBytes == canonicalStatementBytes
    && surface.totalBytes == surface.widths.total
    && surface.magicMatches
    && surface.grammarVersionMatches
    && surface.flagsBinary
    && surface.signedAmountsCanonical
    && surface.consumedAllBytes
    && surface.canonicalReencodeMatches

structure AcceptedStatementParserFacts (surface : StatementParserSurface) : Prop where
  widthsExact : surface.widths = canonicalWidths
  totalBytesExact : surface.totalBytes = canonicalStatementBytes
  ledgerMatchesTotal : surface.totalBytes = surface.widths.total
  magicMatches : surface.magicMatches = true
  grammarVersionMatches : surface.grammarVersionMatches = true
  flagsBinary : surface.flagsBinary = true
  signedAmountsCanonical : surface.signedAmountsCanonical = true
  consumedAllBytes : surface.consumedAllBytes = true
  canonicalReencodeMatches : surface.canonicalReencodeMatches = true

theorem accepted_statement_parser_exposes_exact_grammar
    {surface : StatementParserSurface}
    (accepted : statementParserAccepts surface = true) :
    AcceptedStatementParserFacts surface := by
  unfold statementParserAccepts at accepted
  simp only [Bool.and_eq_true] at accepted
  have widthsExact : surface.widths = canonicalWidths := by
    simpa using accepted.1.1.1.1.1.1.1.1
  have totalBytesExact : surface.totalBytes = canonicalStatementBytes := by
    simpa using accepted.1.1.1.1.1.1.1.2
  have ledgerMatchesTotal : surface.totalBytes = surface.widths.total := by
    simpa using accepted.1.1.1.1.1.1.2
  exact
    { widthsExact := widthsExact,
      totalBytesExact := totalBytesExact,
      ledgerMatchesTotal := ledgerMatchesTotal,
      magicMatches := accepted.1.1.1.1.1.2,
      grammarVersionMatches := accepted.1.1.1.1.2,
      flagsBinary := accepted.1.1.1.2,
      signedAmountsCanonical := accepted.1.1.2,
      consumedAllBytes := accepted.1.2,
      canonicalReencodeMatches := accepted.2 }

def canonicalParserFixture : StatementParserSurface :=
  { widths := canonicalWidths,
    totalBytes := canonicalStatementBytes,
    magicMatches := true,
    grammarVersionMatches := true,
    flagsBinary := true,
    signedAmountsCanonical := true,
    consumedAllBytes := true,
    canonicalReencodeMatches := true }

theorem canonical_parser_fixture_accepts :
    statementParserAccepts canonicalParserFixture = true := by
  decide

theorem trailing_byte_rejects :
    statementParserAccepts
      { canonicalParserFixture with totalBytes := canonicalStatementBytes + 1 } = false := by
  decide

theorem truncation_rejects :
    statementParserAccepts
      { canonicalParserFixture with totalBytes := canonicalStatementBytes - 1 } = false := by
  decide

theorem nonbinary_flag_rejects :
    statementParserAccepts
      { canonicalParserFixture with flagsBinary := false } = false := by
  decide

theorem negative_zero_encoding_rejects :
    statementParserAccepts
      { canonicalParserFixture with signedAmountsCanonical := false } = false := by
  decide

theorem wrong_digest_width_grammar_rejects :
    statementParserAccepts
      { canonicalParserFixture with
        widths := { canonicalWidths with anchor := 48 } } = false := by
  decide

end FullShakeRelation
end Hegemon
