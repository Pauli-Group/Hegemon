import SmzaRp05CurrentAcceptedRelationWitness
import SmzaRp05CurrentPublicStatementTransport
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05TracePrefixes
import SmzaRp05GeneratedCertificates
import SmzaRp05SupplyClosureOutputHistory
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05FinalSupplySoundness
import FiniteLedgerSupplyR8

/-! # Shared current-history data and admission definitions

These are the unchanged data/projection and coinbase-check definitions shared
by the older replay argument and the current selector-fed finite-ledger proof.
Keeping them separate avoids requiring the older replay proof as an import of
the current conservation argument. No acceptance rule or theorem premise changes.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRefinement
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRelationWitness
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs (publicNullifier)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open SmzaRp05TracePrefixes (Payload)
open V8Smz9McaDecoder (DecodedSource)
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness (SupplyState)
open SmzaFiniteLedgerSupply (nativeValue)
open Hegemon.Consensus (nativeCoinbaseAmount)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 100000

attribute [local irreducible]
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied

noncomputable section

/-- A successful current designated extraction. The packed projection is not
an input field: it is computed from this exact decoder output. -/
structure DesignatedRun where
  preamble : Statement
  typedStatement : V8PublicStatement
  root : CurrentCommittedOracle
  fpp : Payload
  coefficients : CurrentCoefficients
  source : DecodedSource Goldilocks (Fin 5) 140
  decoded : currentSourceDecoder406 root fpp coefficients = some source
  parsed : parseCurrentPublicStatement? preamble = some typedStatement
  fullySatisfied : HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
    ((relationModel currentDsl certificates).recoveredCandidate
      preamble source.data).system

def designatedPacked (run : DesignatedRun) : List Nat :=
  packedFromRows run.source.data

def outputRecord (run : DesignatedRun) : AcceptedOutputRecord :=
  (encodePublicStatement run.typedStatement, designatedPacked run)

def blockNullifiers (runs : List DesignatedRun) : List Digest :=
  runs.flatMap fun run =>
    (List.finRange 2).filterMap fun input =>
      if (encodePublicStatement run.typedStatement).getD input.val 0 = 1 then
        some (publicNullifier (encodePublicStatement run.typedStatement) input)
      else none

def blockFees (runs : List DesignatedRun) : Nat :=
  (runs.map fun run => run.typedStatement.fee).sum

/-- Executable canonical-shape check for a source coinbase note. -/
def coinbaseOpeningCanonical (opening : V8NoteOpening) : Bool :=
  decide (Hegemon.Transaction.Poseidon2V8SemanticSpecification.CanonicalNoteOpening
    opening)

def blockCoinbaseCanonical : Option (Nat × V8NoteOpening) → Bool
  | none => true
  | some (_, opening) => coinbaseOpeningCanonical opening

def coinbasePaid? (supply : SupplyState) (runs : List DesignatedRun)
    (coinbase : Option (Nat × V8NoteOpening)) : Option Nat :=
  match coinbase with
  | none => some 0
  | some (height, opening) =>
      if height ∉ supply.issuedHeights then
        if 0 < height then
          match nativeCoinbaseAmount height (supply.feeEscrow + blockFees runs) with
          | none => none
          | some paid =>
              if nativeValue opening = paid && opening.assetId = nativeAssetId
              then if coinbaseOpeningCanonical opening then some paid else none
              else none
        else none
      else none

end

end HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint
