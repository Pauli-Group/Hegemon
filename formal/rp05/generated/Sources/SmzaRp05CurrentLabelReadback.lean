import SmzaRp05CurrentAcceptedQueryExtraction
import SmzaRp05CurrentTracePrefixes406

/-! # Readback into the current 406-point source labels

These equalities identify the finite measured tables and selected fixed-input
response in the accepted-stage statement with the literal source objects used
by the current 406-point prefix constructor.  They do not establish any
probability bound or production qualification.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentLabelReadback

open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQueryExtraction
open HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedQuerySupport
open HegemonCrypto.SmallWood.SmzaRp05CurrentTracePrefixes406
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentMaxAgreementRecovery (Position)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp05TracePrefixes (Payload)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

/-- The accepted-stage measured data table is the data projection of the
exact root oracle extracted from the same frozen raw-record set.  This is a
total-table equality, including the zero default outside the 140 data
columns, and needs no collision-free or decoder premise. -/
theorem measured_data_table_eq_extracted_root_oracle
    (ns : Namespace) (records : RawRecords) (fuel : Nat) (root : RawDigest)
    (column : Nat) (index : Position) :
    measuredDataTable ns records fuel root column index =
      SmzaQ38McaSourceBinding.oracleData
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) records fuel .root root)) column index := by
  by_cases bounded : column < 140
  · simp [measuredDataTable, SmzaQ38McaSourceBinding.oracleData,
      SmzaQ38OracleExtraction.committedColumnValue,
      V8Smz9OracleExtraction.wordToGoldilocks,
      SmzaQ38OracleExtraction.wordToGoldilocks, bounded]
  · simp [measuredDataTable, SmzaQ38McaSourceBinding.oracleData, bounded]

/-- The accepted-stage measured five-row mask table is the mask projection
of that same extracted root oracle, with no collision-free or decoder
premise. -/
theorem measured_mask_table_eq_extracted_root_oracle
    (ns : Namespace) (records : RawRecords) (fuel : Nat) (root : RawDigest)
    (row : Fin 5) (index : Position) :
    measuredMaskTable ns records fuel root row index =
      SmzaQ38McaSourceBinding.oracleMasks
        (SmzaRp05TracePrefixes.rootOracle ns
          (extract (globalOnlineNext ns) records fuel .root root)) row index := by
  simp [measuredMaskTable, SmzaQ38McaSourceBinding.oracleMasks,
    V8Smz9OracleExtraction.wordToGoldilocks,
    SmzaQ38OracleExtraction.wordToGoldilocks]

/-- A constant selected input parsed as the current FPP role induces exactly
the current 406-point source response rule.  Both sides reduce to the five
406-word slices beginning after the eight-word response header; there is no
assumption equating opaque response functions. -/
theorem constant_input_rule_eq_current406
    (input : V8SmzaOracleParser.RawInput) (fpp : Payload)
    (domain : List Byte)
    (parsed : V8SmzaOracleParser.parseFramed input = some (domain, fpp.bytes)) :
    SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
        (fun _ : SmzaRp05CurrentMaxAgreementRecovery.Coefficients => input) =
      currentResponseRule406 fpp := by
  funext coefficients row
  simp only [SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection,
    SmzaRp05CurrentResponseInputDecoder.responseOfPayload,
    currentResponseRule406, SmzaRp05TracePrefixes.sourceResponse,
    parsed]
  rw [SmzaRp04TracePrefixes.sourceResponse]
  rfl

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentLabelReadback
