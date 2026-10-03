import SmzaRp05CurrentResponseRuleReadback

/-! # Current raw-input to bounded response bridge

Read the five-by-406 response directly from the current parsed payload using
the parser's word accessor. Equality with same-run restored rows is proved
from the exact current framed serialization via the checked coefficient-cell
decoder. The challenge-indexed raw-input selector remains explicit; this does
not assert that it is fixed before the matrix challenge.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentResponseInputDecoder

abbrev Goldilocks := HegemonCrypto.SmallWood.Goldilocks
abbrev FieldRow := SmzaRp05DecsResponseProjection.FieldRow
abbrev Coefficients := SmzaRp05CurrentResponseRuleReadback.Coefficients
abbrev ResponseRule := SmzaRp05CurrentResponseRuleReadback.ResponseRule
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Byte := HegemonCrypto.CanonicalBytes.Byte
abbrev BoundedResponse :=
  HegemonCrypto.SmallWood.V8Smz9McaRecovery.BoundedResponse

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

/-- Decode exactly the current eight-word digest prefix followed by the
five-by-406 coefficient table. Invalid parser inputs are not used in the
readback theorem below. -/
def responseOfPayload (payload : List Byte) :
    BoundedResponse Goldilocks (Fin 5) 405 :=
  fun row => (Polynomial.degreeLTEquiv Goldilocks 406).symm
    (fun coefficient =>
      ((V8SmzaOracleParser.wordAt payload
        (8 + row.val * 406 + coefficient.val) : Nat) : Goldilocks))

/-- Equality to the actual restored coefficient row, obtained from exact
current-profile framing and the parser's byte-word theorem. -/
theorem response_payload_eq_restored_rows
    (input payload : List Byte) (words leading suffix : List Nat)
    (rows : List FieldRow) (wordCountBound : words.length < 256 ^ 8)
    (frameEq : input = V8SmzaOracleParser.framedInput
      SmallWoodTranscript.piopInputDomain ((words.map (HegemonCrypto.CanonicalBytes.encodeLE 8)).flatten))
    (parsed : V8SmzaOracleParser.parseFramed input =
      some (SmallWoodTranscript.piopInputDomain, payload))
    (wordsEq : words = leading ++
      ((rows.map fun values => values.map fun value => value.val).flatten ++ suffix))
    (leadingLength : leading.length = 8)
    (rowCount : rows.length = 5)
    (rowShape : ∀ values, values ∈ rows → values.length = 406) :
    responseOfPayload payload =
      SmzaRp05CurrentResponseRuleReadback.boundedResponseOfRows rows := by
  funext row
  change (Polynomial.degreeLTEquiv Goldilocks 406).symm
      (fun coefficient : Fin 406 =>
        ((V8SmzaOracleParser.wordAt payload
          (8 + row.val * 406 + coefficient.val) : Nat) : Goldilocks)) =
    (Polynomial.degreeLTEquiv Goldilocks 406).symm
      (fun coefficient : Fin 406 =>
        (rows.getD row.val []).getD coefficient.val 0)
  apply congrArg ((Polynomial.degreeLTEquiv Goldilocks 406).symm)
  funext coefficient
  have rowBound : row.val < rows.length := by rw [rowCount]; exact row.isLt
  have decoded := SmzaRp05CurrentResponsePrequeryDecode.prior_input_decodes_response_coefficient
    input payload words leading suffix rows row.val coefficient.val wordCountBound
    frameEq parsed wordsEq leadingLength rowShape rowBound coefficient.isLt
  change ((V8SmzaOracleParser.wordAt payload
      (8 + row.val * 406 + coefficient.val) : Nat) : Goldilocks) =
    (rows.getD row.val []).getD coefficient.val 0
  rw [decoded]
  exact ZMod.natCast_zmod_val _

/-- The selected response rule is derived from an explicit challenge-to-raw-
input function, not from a host-selected table. Parser failure yields a total
default response, but the source-readback theorem requires a successful parse. -/
def responseRuleOfRawInputSelection
    (selectInput : Coefficients → RawInput) : ResponseRule :=
  fun coefficients => responseOfPayload
    (((V8SmzaOracleParser.parseFramed (selectInput coefficients)).map Prod.snd).getD [])

/-- On the exact selected input and same-run restored serialization, the
raw-input-derived rule reads back the native 406-coefficient polynomials. -/
theorem selected_input_response_polynomial_readback
    (selectInput : Coefficients → RawInput) (coefficients : Coefficients)
    (input payload : List Byte) (words leading suffix : List Nat)
    (rows : List FieldRow) (row : Fin 5)
    (wordCountBound : words.length < 256 ^ 8)
    (selected : selectInput coefficients = input)
    (frameEq : input = V8SmzaOracleParser.framedInput
      SmallWoodTranscript.piopInputDomain ((words.map (HegemonCrypto.CanonicalBytes.encodeLE 8)).flatten))
    (parsed : V8SmzaOracleParser.parseFramed input =
      some (SmallWoodTranscript.piopInputDomain, payload))
    (wordsEq : words = leading ++
      ((rows.map fun values => values.map fun value => value.val).flatten ++ suffix))
    (leadingLength : leading.length = 8)
    (rowCount : rows.length = 5)
    (rowShape : ∀ values, values ∈ rows → values.length = 406) :
    HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
      (responseRuleOfRawInputSelection selectInput coefficients) row =
      SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
        (rows.getD row.val []) := by
  have selectedParse : V8SmzaOracleParser.parseFramed (selectInput coefficients) =
      some (SmallWoodTranscript.piopInputDomain, payload) := by
    rw [selected, parsed]
  change HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
    (responseOfPayload (((V8SmzaOracleParser.parseFramed (selectInput coefficients)).map Prod.snd).getD [])) row = _
  rw [selectedParse]
  change HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
    (responseOfPayload payload) row = _
  rw [response_payload_eq_restored_rows input payload words leading suffix rows
    wordCountBound frameEq parsed wordsEq leadingLength rowCount rowShape]
  exact SmzaRp05CurrentResponseRuleReadback.bounded_response_of_rows_readback
    rows row (by
      have rowBound : row.val < rows.length := by rw [rowCount]; exact row.isLt
      have rowValue : rows.getD row.val [] = rows[row.val] :=
        List.getD_eq_getElem rows [] rowBound
      have member : rows.getD row.val [] ∈ rows := by
        rw [rowValue]
        exact List.getElem_mem rowBound
      exact rowShape _ member)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentResponseInputDecoder
