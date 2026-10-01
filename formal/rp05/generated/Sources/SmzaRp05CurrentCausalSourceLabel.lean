import SmzaRp05AcceptedRoleLabels
import SmzaRp05CurrentSourceRoleEvent

/-! Current 406-point source-label readback on the single causal trace.
Payloads and earlier-role values remain explicit input readbacks here; the
accepted-execution constructors must supply them. No selected q38 answer is
an input to the label constructor. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentCausalSourceLabel

open SmzaRp05TracePrefixes
open SmzaRp05AcceptedRoleLabels
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentSourceRoleEvent
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05StatementNamespace
open SmzaChallengeStageTargets (Role)
open SmzaQ38McaSourceBinding (oracleData oracleMasks)
open V8Smz9PiopSoundness (Matrix Opening)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible] currentSourceDecoder406 currentSourcePrefix406
  V8Smz9McaDecoder.decodeSource V8Smz9McaDecoder.responseSupport
  currentMatrixLabelOfResult406 currentOpeningLabelOfResult406

theorem current_causal_prefix_readback
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (trace : Trace)
    (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (matrixGood : ¬ currentMatrixBad
      (oracleData (causalOracle ns trace)) (oracleMasks (causalOracle ns trace)) coefficients) :
    currentSourcePrefixFromTrace406 model ns statement (advice .decsSample) trace =
      some (currentSourcePrefix406 (causalOracle ns trace) messages.fpp coefficients
        (baseOpeningPoints opening.1)
        (SmzaRp05TracePrefixes.queryCoefficients messages.decs) matrixGood) := by
  classical
  unfold currentSourcePrefixFromTrace406
  rw [messages.decsRead, messages.piopRead, messages.fppRead]
  dsimp only [Bind.bind, Option.bind]
  rw [earlier.sampleCoefficients, earlier.sampleOpening]
  dsimp only [Bind.bind, Option.bind]
  change (if bad : currentMatrixBad (oracleData (causalOracle ns trace))
      (oracleMasks (causalOracle ns trace)) coefficients then none else _) = _
  rw [dif_neg matrixGood]
  rfl

theorem current_source_labels_of_statement_bytes
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (advice : AllEarlierTables model .decsSample)
    (trace : Trace) (label : CurrentSourcePrefix406)
    (readback : currentSourcePrefixFromTrace406 model ns statement
      (advice statement) trace = some label) :
    currentSourceRoleLabelsFromBytes406 model ns advice statement.toBytes trace =
      .decoded statement label := by
  have length : statement.toBytes.length = SmzaRp05LeafNamespace.preambleBytes :=
    SmzaRp05StatementNamespace.Statement.toBytes_length statement
  have roundtrip : statementOfBytes statement.toBytes length = statement := by
    exact SmzaRp05StatementNamespace.Statement.toBytes_injective
      (statement_of_bytes_roundtrip statement.toBytes length)
  simp only [currentSourceRoleLabelsFromBytes406, statementOfBytes?,
    dif_pos length, roundtrip, readback]

private theorem generic_causal_matrix_label_readback
    (decoder : CurrentCommittedOracle → Payload → CurrentCoefficients →
      Option (V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140))
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : decoder (causalOracle ns trace) messages.fpp
      coefficients = some source) :
    currentMatrixLabelUsingDecoder406 decoder model ns statement (advice .piopMatrix)
      (causalTrace trace .piopMatrix) =
        some ⟨model.recoveredCandidate statement source.data⟩ := by
  simp only [currentMatrixLabelUsingDecoder406, causalTrace, messages.fppRead,
    earlier.matrixCoefficients, RoleOutput, Option.bind_eq_bind, Option.bind_some]
  rw [show rootOracle ns (child (child (child trace 0) 0) 0) =
    causalOracle ns trace from rfl]
  exact current_matrix_label_of_result_success406 model statement _ source recovered

private theorem generic_causal_opening_label_readback
    (decoder : CurrentCommittedOracle → Payload → CurrentCoefficients →
      Option (V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140))
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : decoder (causalOracle ns trace) messages.fpp
      coefficients = some source) :
    currentOpeningLabelUsingDecoder406 decoder model ns statement (advice .piopOpening)
      (causalTrace trace .piopOpening) =
        some ⟨model.recoveredCandidate statement source.data, matrix,
          SmzaRp05TracePrefixes.piopResponse messages.piop⟩ := by
  simp only [currentOpeningLabelUsingDecoder406, causalTrace, messages.piopRead,
    messages.fppRead, earlier.openingCoefficients, earlier.openingMatrix,
    RoleOutput, Option.bind_eq_bind, Option.bind_some]
  rw [show rootOracle ns (child (child (child trace 0) 0) 0) =
    causalOracle ns trace from rfl]
  exact current_opening_label_of_result_success406 model statement _ matrix
    (SmzaRp05TracePrefixes.piopResponse messages.piop) source recovered

theorem current_causal_matrix_label_readback
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : currentSourceDecoder406 (causalOracle ns trace) messages.fpp
      coefficients = some source) :
    currentMatrixLabel406 model ns statement (advice .piopMatrix)
      (causalTrace trace .piopMatrix) =
        some ⟨model.recoveredCandidate statement source.data⟩ := by
  exact generic_causal_matrix_label_readback currentSourceDecoder406 model ns
    statement trace messages advice coefficients matrix opening earlier source recovered

theorem current_causal_opening_label_readback
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : Statement) (trace : Trace) (messages : CausalPayloads ns trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : CurrentCoefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages coefficients matrix opening)
    (source : V8Smz9McaDecoder.DecodedSource Goldilocks (Fin 5) 140)
    (recovered : currentSourceDecoder406 (causalOracle ns trace) messages.fpp
      coefficients = some source) :
    currentOpeningLabel406 model ns statement (advice .piopOpening)
      (causalTrace trace .piopOpening) =
        some ⟨model.recoveredCandidate statement source.data, matrix,
          SmzaRp05TracePrefixes.piopResponse messages.piop⟩ := by
  exact generic_causal_opening_label_readback currentSourceDecoder406 model ns
    statement trace messages advice coefficients matrix opening earlier source recovered

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentCausalSourceLabel
