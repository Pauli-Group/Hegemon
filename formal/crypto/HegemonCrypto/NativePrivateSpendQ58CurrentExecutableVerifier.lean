import HegemonCrypto.NativePrivateSpendQ58CurrentCompactMerkle
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedDecs
import HegemonCrypto.NativePrivateSpendQ58CurrentRetainedResponseReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier
import HegemonCrypto.NativePrivateSpendQ58CurrentPublicFactorizationBase
import HegemonCrypto.SmallWoodV8Smz9PiopReconstruction
import HegemonCrypto.NativePrivateSpendQ58CurrentChronologicalRequest
import SmzaRp05FinalProgramMiddleExecution
import SmzaRp05LvcsWireProjection
import SmzaRp05CurrentProofWireProgram
import SmzaRp05PiopMatrixStage
import SmzaRp05PcsMerklePayload

/-!
Current adversarial post-parser verifier source projection. Every PCS head,
query, LVCS row, Merkle root, DECS polynomial, batching coefficient and PIOP
coefficient is computed from the existing wire data under the same oracle.
There is no scalar-check, recovered-table, Satisfies or accepted-transcript
input, and no additional MCA/LVCS equation guard. Native restoration and
field/parser interpretation are the retained finite F1 boundary. This source
proposal is not typed yet and does not establish adaptive accepted-invalid
mass: chronological fixed-table extraction and event coverage remain separate.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentExecutableVerifier

open Polynomial
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log ask)
open SmzaRp05ExecutableChallengeStage
  (FieldWord fieldLoop callCap returnedWords pendingFailure zeroWord digestWords)
open SmzaRp05PcsWireProjection
  (DecodedPcsFields decodePcsFields decodeFieldMatrix fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields decodeDecsResponseFields)
open NativePrivateSpendQ58CurrentPublicOpening (Relation Row Check Batch packing csrWeights)
open V8Smz9PiopSoundness (Matrix ClaimedTranscript)
open V8Smz9PiopOpeningRecovery
open scoped BigOperators Classical

namespace CM
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace Input merkleProgram)
end CM
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (frame roleName)
end F
namespace RC
export NativePrivateSpendQ58CurrentRoleClassifier (canonicalCurrentQueryBytes)
end RC
namespace CR
export NativePrivateSpendQ58CurrentChronologicalRequest
  (sortedCurrentIndices currentOpeningAdmissible currentOpeningValid)
end CR
namespace AD
export NativePrivateSpendQ58CurrentAcceptedDecs (currentRestore)
end AD
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback (sourceHashProgram)
end RR

set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false
noncomputable section

abbrev Wire := SmzaRp05CurrentProofWireProgram.ExistingProofFieldView

/-- Literal current SMZD opening domain. Historical PCS denominator exclusions
are absent from the current native verifier and are not introduced here. -/
abbrev Opening := { raw : Fin 6 → Goldilocks // CR.currentOpeningAdmissible raw }

def points (opening : Opening) : Fin 6 → Goldilocks := opening.1

/-- The same six-word shape and predicate as currentOpeningValid. -/
def decodeOpeningWords (words : List FieldWord) : Option Opening :=
  if valid : words.length = 6 ∧ CR.currentOpeningAdmissible
      (V8Smz9HonestOpeningSchedule.sourcePointVector words) then
    some ⟨V8Smz9HonestOpeningSchedule.sourcePointVector words, valid.2⟩
  else none

theorem decode_current_opening_characterization (words : List FieldWord) :
    (decodeOpeningWords words).isSome = CR.currentOpeningValid words := by
  change (decodeOpeningWords words).isSome =
    decide (words.length = 6 ∧ CR.currentOpeningAdmissible
      (V8Smz9HonestOpeningSchedule.sourcePointVector words))
  unfold decodeOpeningWords
  by_cases valid : words.length = 6 ∧ CR.currentOpeningAdmissible
      (V8Smz9HonestOpeningSchedule.sourcePointVector words)
  · rw [dif_pos valid]
    simp [valid]
  · rw [dif_neg valid]
    simp [valid]

/-- The current public source configuration, not the retained686-row DSL. -/
def widths : List Nat := List.replicate 26210 1 ++ List.replicate 10 2
def deltas : List Nat := List.replicate 26210 0 ++ List.replicate 5 59 ++ List.replicate 5 1

structure PiopFields where
  nonlinearHighs : Fin 5 → Fin 69 → FieldWord
  linearHighs : Fin 5 → Fin 126 → FieldWord
  rowScalars : Fin 6 → Fin 26220 → FieldWord

structure DecodedFields where
  pcs : DecodedPcsFields
  decs : DecodedDecsResponseFields
  piop : PiopFields
  rowScalars : List (List FieldWord)

private def matrixHasShape {α : Type} (matrix : List (List α))
    (rows columns : Nat) : Bool :=
  decide (matrix.length = rows) && !(matrix.any fun row => decide (row.length ≠ columns))

private def indexed (matrix : List (List FieldWord)) (i j : Nat) : FieldWord :=
  (matrix.getD i []).getD j zeroWord

/-- Canonical words and exact current shape precede every indexed projection.
The one existing opened-row matrix feeds BOTH PCS and PIOP. -/
def decodeWire (wire : Wire) : Option DecodedFields := do
  if !matrixHasShape wire.piopNonlinearHighs 5 69 ||
      !matrixHasShape wire.piopLinearHighs 5 126 ||
      !matrixHasShape wire.openedRowScalars 6 26220 then none else pure ()
  let nonlinear ← decodeFieldMatrix wire.piopNonlinearHighs
  let linear ← decodeFieldMatrix wire.piopLinearHighs
  let rows ← decodeFieldMatrix wire.openedRowScalars
  let pcs ← decodePcsFields wire.partialEvals wire.rcombiTails wire.subsetEvals
  let decs ← decodeDecsResponseFields wire.decsHighCoeffs wire.decsMaskingEvals
  pure {
    pcs := pcs
    decs := decs
    piop := {
      nonlinearHighs := fun i j => indexed nonlinear i.val j.val
      linearHighs := fun i j => indexed linear i.val j.val
      rowScalars := fun i j => indexed rows i.val j.val }
    rowScalars := rows }

/-- Literal COMPFF01 field-XOF frames, including the opening nonce. -/
def fieldKeys (role : SmzaChallengeStageTargets.Role) (requested : Nat)
    (digest : V8SmzaOracleParser.RawDigest) (nonce : Nat := 0) :
    List V8SmzaOracleParser.RawInput :=
  (List.range (callCap requested)).map fun counter =>
    RC.canonicalCurrentQueryBytes ⟨role, digest, nonce, counter⟩

def fieldXof (role : SmzaChallengeStageTargets.Role) (requested : Nat)
    (digest : V8SmzaOracleParser.RawDigest) (nonce : Nat := 0) :
    Program (Option (List FieldWord)) := fieldLoop requested [] (fieldKeys role requested digest nonce)

theorem literal_request_counts :
    callCap 80 = 14 ∧ callCap 700 = 92 ∧
    5 * 1344594 = 6722970 ∧ callCap 6722970 = 840376 := by decide

/-- Capped exhaustion remains pending source failure, including across trials. -/
def openingAttempt (pending : Bool) (digest : V8SmzaOracleParser.RawDigest) (nonce : Nat) :
    Program (Option Opening × Bool) :=
  (fieldXof .piopOpening 6 digest nonce).bind fun sampled => .done (some
    (decodeOpeningWords (returnedWords 6 sampled),
      pendingFailure pending sampled))

def openingScan (digest : V8SmzaOracleParser.RawDigest) :
    List Nat → Bool → Program (Nat × Opening × Bool)
  | [], _ => .done none
  | nonce :: rest, pending =>
      (openingAttempt pending digest nonce).bind fun (opening, failed) =>
        match opening with
        | none => openingScan digest rest failed
        | some points => .done (some (nonce, points, failed))

/-- First valid nonce, compare existing proof nonce, then repeat the sample. -/
def canonicalOpening (pending : Bool) (nonce : Fin (2 ^ 32))
    (digest : V8SmzaOracleParser.RawDigest) : Program (Opening × Bool) :=
  (openingScan digest (List.range 16) pending).bind fun (expected, _, failed) =>
    if nonce.val = expected then
      (openingAttempt failed digest nonce.val).bind fun (opening, nextPending) =>
        .done (opening.map fun points => (points, nextPending))
    else .done none

/-- Source fixed80-word scan, first58 distinct eligible residues, then sort. -/
def queryResult (pending : Bool) (sampled : Option (List FieldWord)) :
    Option (List Nat × Bool) :=
  let selected := (CR.sortedCurrentIndices (returnedWords 80 sampled)).map Fin.val
  if selected.length = 58 then some (selected, pendingFailure pending sampled) else none

def queryProgram (pending : Bool) (digest : V8SmzaOracleParser.RawDigest) :
    Program (List Nat × Bool) :=
  (fieldXof .decsSample 80 digest).bind fun sampled => .done (queryResult pending sampled)

def decsInput (digest : V8SmzaOracleParser.RawDigest)
    (heads tails : List (List Goldilocks)) : V8SmzaOracleParser.RawInput :=
  let words := digestWords digest ++
    (heads.zip tails).flatMap fun pair => (pair.1 ++ pair.2).map fun value => value.val
  F.frame (F.roleName .decs) words.length (words.flatMap (encodeLE 8))

/-- Native leaf construction, with all existing tape/mask/path fields retained. -/
def makeMerkleInput (salt binding : List Byte) (pending : Bool)
    (indexes : List Nat) (rows : List (List Goldilocks))
    (masks : List (List FieldWord)) (tapes : List (List Byte))
    (paths : List (List V8SmzaOracleParser.RawDigest)) : Option CM.Input := do
  if salt.length ≠ 32 ∨ binding.length ≠ 616 ∨
      indexes.length ≠ 58 ∨ rows.length ≠ 58 ∨ masks.length ≠ 58 ∨
      tapes.length ≠ 58 ∨ paths.length ≠ 58 ∨
      rows.any (fun row => decide (row.length ≠ 140)) ∨
      masks.any (fun row => decide (row.length ≠ 5)) ∨
      tapes.any (fun tape => decide (tape.length ≠ 64)) then none else pure ()
  pure {
    salt := salt
    binding := binding
    indices := fun j => indexes.getD j.val 0
    payloads := fun j => SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
      (tapes.getD j.val []) (indexes.getD j.val 0)
      (rows.getD j.val []) (masks.getD j.val [])
    paths := fun j => paths.getD j.val []
    pendingXofFailure := pending }

structure PcsOutput where
  heads : List (List Goldilocks)
  indexes : List Nat
  decsPoints : List Goldilocks
  rows : List (List Goldilocks)
  input : CM.Input
  root : V8SmzaOracleParser.RawDigest
  gamma : List (List FieldWord)
  polynomials : List (List Goldilocks)
  hashFpp : V8SmzaOracleParser.RawDigest
  pending : Bool

def gammaRows (words : List FieldWord) : List (List FieldWord) :=
  List.ofFn fun row : Fin 5 => List.ofFn fun column : Fin 140 =>
    words.getD (140 * row.val + column.val) zeroWord

/-- Mathematical source PCS interpreter. The LVCS routine retains its actual
local residual guard. DECS restore supplies its equations; neither equation
family is inserted as an additional acceptance gate. -/
def pcsProgram (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) : Program PcsOutput :=
  let evalPoints := List.ofFn (points opening)
  match SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs evalPoints
      decoded.rowScalars 64 widths deltas 2 13115 with
  | none => .done none
  | some heads =>
      if heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
          heads.any (fun row => decide (row.length ≠ 13115)) ∨
          decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58)) then .done none else
      (ask (decsInput wire.hPiop heads
        (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))).bind fun openingDigest =>
      (queryProgram pending openingDigest).bind fun (indexes, sampledPending) =>
      match SmzaRp05DecsPointProjection.fieldPoints 13173 indexes with
      | none => .done none
      | some decsPoints =>
        match SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields decoded.pcs
            evalPoints decsPoints decoded.rowScalars 64 widths deltas 2 13115 140 58 with
        | none => .done none
        | some rows =>
          match makeMerkleInput wire.salt ns.binding sampledPending indexes rows
              decoded.decs.maskingEvals wire.tapes wire.paths with
          | none => .done none
          | some input =>
            (CM.merkleProgram ns input).bind fun root =>
            (fieldXof .decsMatrix 700 root).bind fun sampled =>
            let gamma := gammaRows (returnedWords 700 sampled)
            let pointWords := decsPoints.map SmzaRp05ExecutableRestore.toWord
            let rowWords := rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord
            match AD.currentRestore decoded.decs rowWords gamma pointWords with
            | none => .done none
            | some polynomials =>
              (RR.sourceHashProgram (digestWords root) decoded.decs rowWords gamma
                pointWords (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)).bind fun hashFpp =>
                .done (some ⟨heads, indexes, decsPoints, rows, input, root,
                  gamma, polynomials, hashFpp, pendingFailure sampledPending sampled⟩)

/-- Extract the ordinary restoration result from the accepted PCS program.
It is not a verifier premise and the returned rows/gamma/points are not chosen
independently of the execution. -/
theorem pcs_execution_has_restoration (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    AD.currentRestore decoded.decs
      (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord) =
        some output.polynomials := by
  cases headEq : SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
      (List.ofFn (points opening)) decoded.rowScalars 64 widths deltas 2 13115 with
  | none => simp only [pcsProgram, headEq, Program.eval] at executed; cases executed
  | some heads =>
      by_cases bad : heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
          heads.any (fun row => decide (row.length ≠ 13115)) ∨
          decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58))
      · simp only [pcsProgram, headEq, if_pos bad, Program.eval] at executed
        cases executed
      · simp only [pcsProgram, headEq, if_neg bad] at executed
        obtain ⟨openingDigest, _hashExecuted, afterHash⟩ :=
          SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (ask (decsInput wire.hPiop heads
              (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))) _ output executed
        obtain ⟨query, _queryExecuted, afterQuery⟩ :=
          SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
            (queryProgram pending openingDigest) _ output afterHash
        rcases query with ⟨indexes, sampledPending⟩
        cases pointEq : SmzaRp05DecsPointProjection.fieldPoints 13173 indexes with
        | none => simp only [pointEq, Program.eval] at afterQuery; cases afterQuery
        | some decsPoints =>
          simp only [pointEq] at afterQuery
          cases rowEq : SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields decoded.pcs
              (List.ofFn (points opening)) decsPoints decoded.rowScalars 64 widths deltas
              2 13115 140 58 with
          | none => simp only [rowEq, Program.eval] at afterQuery; cases afterQuery
          | some rows =>
            simp only [rowEq] at afterQuery
            cases inputEq : makeMerkleInput wire.salt ns.binding sampledPending indexes rows
                decoded.decs.maskingEvals wire.tapes wire.paths with
            | none => simp only [inputEq, Program.eval] at afterQuery; cases afterQuery
            | some input =>
              simp only [inputEq] at afterQuery
              obtain ⟨root, _rootExecuted, afterRoot⟩ :=
                SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                  (CM.merkleProgram ns input) _ output afterQuery
              obtain ⟨sampled, _gammaExecuted, afterGamma⟩ :=
                SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                  (fieldXof .decsMatrix 700 root) _ output afterRoot
              let gamma := gammaRows (returnedWords 700 sampled)
              let pointWords := decsPoints.map SmzaRp05ExecutableRestore.toWord
              let rowWords := rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord
              change
                (match AD.currentRestore decoded.decs rowWords gamma pointWords with
                 | none => (.done none : Program PcsOutput)
                 | some polynomials =>
                     (RR.sourceHashProgram (digestWords root) decoded.decs
                       rowWords gamma pointWords
                       (List.ofFn fun i : Fin 77 =>
                         V8SmzaOracleParser.wordAt ns.binding i.val)).bind fun hashFpp =>
                       .done (some ⟨heads, indexes, decsPoints, rows, input, root,
                         gamma, polynomials, hashFpp,
                         pendingFailure sampledPending sampled⟩)).eval oracle =
                  some output at afterGamma
              generalize restoreEq :
                AD.currentRestore decoded.decs rowWords gamma pointWords =
                  restored at afterGamma
              cases restored with
              | none =>
                change (none : Option PcsOutput) = some output at afterGamma
                cases afterGamma
              | some polynomials =>
                obtain ⟨hashFpp, _fppExecuted, returned⟩ :=
                  SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
                    (RR.sourceHashProgram (digestWords root) decoded.decs rowWords gamma pointWords
                      (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val))
                    _ output afterGamma
                have same :
                    (⟨heads, indexes, decsPoints, rows, input, root, gamma, polynomials,
                      hashFpp, pendingFailure sampledPending sampled⟩ : PcsOutput) = output :=
                  Option.some.inj returned
                rw [← same]
                exact restoreEq

/-- The five-by58 equations are consequences of the real restoration call.
No FiveMcaChecks proof or successful recovery is an acceptance input. -/
theorem pcs_execution_has_five_opened_checks (ns : CM.Namespace) (pending : Bool) (wire : Wire)
    (decoded : DecodedFields) (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    output.polynomials.length = 5 ∧
      ∀ k, k < 5 → ∀ j, j < 58 →
        SmzaRp05ExecutablePcsClosureDecsChecks.sourceEvaluation decoded.decs
          (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          output.gamma k j = some
            ((SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
              (output.polynomials.getD k [])).eval
                ((SmzaRp05DecsResponseProjection.decodeFieldRow
                  (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)).getD j 0)) := by
  exact NativePrivateSpendQ58CurrentAcceptedDecs.restore_success_has_five_source_checks
    58 decoded.decs
    (output.rows.map fun (row : List Goldilocks) => row.map SmzaRp05ExecutableRestore.toWord)
    output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 13115 output.polynomials
    (by
      simpa only [NativePrivateSpendQ58CurrentAcceptedDecs.currentRestore] using
        (pcs_execution_has_restoration ns pending wire decoded opening oracle output executed))

/-- Scalar families are the actual current sparse CSR and multiplication
occurrences. They do not use an honest or satisfying witness structure. -/
def openedWitness (proof : PiopFields) (coordinate : Fin 6) (row : Row) : Goldilocks :=
  (proof.rowScalars coordinate ⟨row.val, row.isLt.trans_le (by decide)⟩).val

def openedNonlinearMask (proof : PiopFields) (coordinate : Fin 6) (row : Fin 5) : Goldilocks :=
  (proof.rowScalars coordinate ⟨26210 + row.val, by omega⟩).val

def openedLinearMask (proof : PiopFields) (coordinate : Fin 6) (row : Fin 5) : Goldilocks :=
  (proof.rowScalars coordinate ⟨26215 + row.val, by omega⟩).val

def nonlinearScalar (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (witness : Row → Goldilocks) (check : Check) : Goldilocks :=
  if bound : check.val < 5210 then
    let batch : Batch := ⟨check.val, bound⟩
    witness (relation.batch batch 0) - witness (relation.batch batch 1) * witness (relation.batch batch 2)
  else 0

def linearScalar (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (witness : Row → Goldilocks)
    (point : Goldilocks) (check : Check) : Goldilocks :=
  publicLinearOpening (csrWeights (relation.csr check))
    (sourcePackingLagrange packing) witness point

def evaluation (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594) (opening : Opening)
    (proof : PiopFields) : V8Smz9PiopReconstruction.EvaluationTrace where
  nonlinear row coordinate :=
    (∑ check, matrix row check * nonlinearScalar relation (openedWitness proof coordinate) check) /
      (V8Smz9PiopOpeningRecovery.packingVanishing packing).eval (points opening coordinate) +
      openedNonlinearMask proof coordinate row
  linear row coordinate :=
    (∑ check, matrix row check * linearScalar relation (openedWitness proof coordinate)
      (points opening coordinate) check) + openedLinearMask proof coordinate row

def target (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594) (row : Fin 5) : Goldilocks :=
  ∑ check, matrix row check * relation.target check

def nonlinearHigh (proof : PiopFields) (row : Fin 5) : Goldilocks[X] :=
  ∑ index : Fin 69, C ((proof.nonlinearHighs row index).val : Goldilocks) * X ^ (6 + index.val)

def nonlinearPolynomial (opening : Opening) (proof : PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) : Goldilocks[X] :=
  DecsRestore.restorePolynomial Finset.univ (points opening) (nonlinearHigh proof row)
    (trace.nonlinear row)

theorem nonlinear_high_degree (proof : PiopFields) (row : Fin 5) :
    (nonlinearHigh proof row).natDegree ≤ 74 := by
  unfold nonlinearHigh
  apply natDegree_sum_le_of_forall_le
  intro index _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

theorem nonlinear_polynomial_degree (opening : Opening) (proof : PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) :
    (nonlinearPolynomial opening proof trace row).natDegree ≤ 74 := by
  apply DecsRestore.restore_polynomial_natDegree_le
    opening.2.1.injOn
  · decide
  · exact nonlinear_high_degree proof row

theorem nonlinear_polynomial_evaluation (opening : Opening) (proof : PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) (coordinate : Fin 6) :
    (nonlinearPolynomial opening proof trace row).eval (points opening coordinate) =
      trace.nonlinear row coordinate :=
  DecsRestore.restore_polynomial_eval
    opening.2.1.injOn
    (Finset.mem_univ coordinate)

def linearPolynomial (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594) (opening : Opening)
    (proof : PiopFields) (trace : V8Smz9PiopReconstruction.EvaluationTrace)
    (row : Fin 5) : Goldilocks[X] :=
  let high := V8Smz9PiopReconstruction.linearHighPart
    (fun index => (proof.linearHighs row index).val)
  let base := DecsRestore.restorePolynomial Finset.univ
    (LinearPiopExact.augmentedPoint (points opening)) high
    (V8Smz9PiopReconstruction.augmentedValues (trace.linear row))
  base + C ((target relation matrix row - packingSum packing base) /
    V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening)) *
      LinearPiopExact.normalizedRootPolynomial (points opening)

structure Transcript where
  hashFpp : V8SmzaOracleParser.RawDigest
  nonlinear : Fin 5 → Fin 75 → FieldWord
  linearHigh : Fin 5 → Fin 132 → FieldWord
  pending : Bool

def reconstruct (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594) (opening : Opening)
    (proof : PiopFields) (hashFpp : V8SmzaOracleParser.RawDigest) (pending : Bool) : Transcript :=
  let trace := evaluation relation matrix opening proof
  { hashFpp := hashFpp
    nonlinear := fun row index => SmzaRp05ExecutableReconstruction.toWord
      ((nonlinearPolynomial opening proof trace row).coeff index.val)
    linearHigh := fun row index => SmzaRp05ExecutableReconstruction.toWord
      ((linearPolynomial relation matrix opening proof trace row).coeff (index.val + 1))
    pending := pending }

def transcriptWords (transcript : Transcript) : List Nat :=
  digestWords transcript.hashFpp ++
    (List.ofFn fun row : Fin 5 =>
      (List.ofFn (transcript.nonlinear row)).map Fin.val ++
        (List.ofFn (transcript.linearHigh row)).map Fin.val).flatten

def finalInput (transcript : Transcript) : V8SmzaOracleParser.RawInput :=
  F.frame (F.roleName .piop) 1043 ((transcriptWords transcript).flatMap (encodeLE 8))

theorem current_final_word_count : 8 + 5 * (75 + 132) = 1043 := by decide

def finalize (expected : V8SmzaOracleParser.RawDigest) (transcript : Transcript) : Program Unit :=
  (ask (finalInput transcript)).bind fun actual =>
    .done (SmzaRp05ExecutableFinalVerifier.verdict transcript.pending expected actual)

def matrixProgram (pending : Bool) (digest : V8SmzaOracleParser.RawDigest) :
    Program (Matrix 1344594 × Bool) :=
  (fieldXof .piopMatrix 6722970 digest).bind fun sampled => .done (some
    (SmzaRp05PiopMatrixStage.matrixFromWords 1344594 (returnedWords 6722970 sampled),
      pendingFailure pending sampled))

def transcriptProgram (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : Wire) :
    Program Transcript :=
  match decodeWire wire with
  | none => .done none
  | some decoded =>
      (canonicalOpening pending nonce wire.hPiop).bind fun (opening, openingPending) =>
      (pcsProgram ns openingPending wire decoded opening).bind fun pcs =>
      (matrixProgram pcs.pending pcs.hashFpp).bind fun (matrix, finalPending) =>
        .done (some (reconstruct relation matrix opening decoded.piop pcs.hashFpp finalPending))

def verifierProgram (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : Wire) : Program Unit :=
  (transcriptProgram ns relation pending nonce wire).bind (finalize wire.hPiop)

/-- Outputs below are extracted AFTER ordinary execution, never supplied as
per-step proofs or desired accepting witnesses. -/
structure ExecutionStages (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : Wire)
    (oracle : Oracle) (transcript : Transcript) where
  decoded : DecodedFields
  opening : Opening
  openingPending : Bool
  pcs : PcsOutput
  matrix : Matrix 1344594
  finalPending : Bool
  decodedEq : decodeWire wire = some decoded
  openingExecuted : (canonicalOpening pending nonce wire.hPiop).eval oracle =
    some (opening, openingPending)
  pcsExecuted : (pcsProgram ns openingPending wire decoded opening).eval oracle = some pcs
  matrixExecuted : (matrixProgram pcs.pending pcs.hashFpp).eval oracle = some (matrix, finalPending)
  reconstructed : reconstruct relation matrix opening decoded.piop pcs.hashFpp finalPending = transcript

attribute [local irreducible] canonicalOpening pcsProgram matrixProgram reconstruct

theorem transcript_execution_has_stages (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : Wire)
    (oracle : Oracle) (transcript : Transcript)
    (executed : (transcriptProgram ns relation pending nonce wire).eval oracle =
      some transcript) :
    Nonempty (ExecutionStages ns relation pending nonce wire oracle transcript) := by
  cases decodedEq : decodeWire wire with
  | none =>
      simp only [transcriptProgram, decodedEq, Program.eval] at executed
      cases executed
  | some decoded =>
      simp only [transcriptProgram, decodedEq] at executed
      obtain ⟨openingPair, openingExecuted, afterOpening⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (canonicalOpening pending nonce wire.hPiop) _ transcript executed
      rcases openingPair with ⟨opening, openingPending⟩
      obtain ⟨pcs, pcsExecuted, afterPcs⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (pcsProgram ns openingPending wire decoded opening) _ transcript afterOpening
      obtain ⟨matrixPair, matrixExecuted, reconstructed⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (matrixProgram pcs.pending pcs.hashFpp) _ transcript afterPcs
      rcases matrixPair with ⟨matrix, finalPending⟩
      exact ⟨⟨decoded, opening, openingPending, pcs, matrix, finalPending,
        decodedEq, openingExecuted, pcsExecuted, matrixExecuted, Option.some.inj reconstructed⟩⟩

/-- Accepted execution derives the exact current AFTER transcript, clean
pending state, final digest equality and record in THAT execution's log. -/
theorem accepted_execution_has_stages (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : Wire)
    (oracle : Oracle)
    (accepted : (verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    ∃ transcript, Nonempty (ExecutionStages ns relation pending nonce wire oracle transcript) ∧
      transcript.pending = false ∧ oracle (finalInput transcript) = wire.hPiop ∧
      (finalInput transcript, wire.hPiop) ∈
        ((verifierProgram ns relation pending nonce wire).record oracle).2 := by
  obtain ⟨transcript, constructed, finished⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (transcriptProgram ns relation pending nonce wire) (finalize wire.hPiop) () accepted
  have verdict := SmzaRp05ExecutableFinalVerifier.verdict_success transcript.pending wire.hPiop
    (oracle (finalInput transcript))
  have finishedVerdict : SmzaRp05ExecutableFinalVerifier.verdict transcript.pending wire.hPiop
      (oracle (finalInput transcript)) = some () := by
    simpa only [finalize, ask, Program.bind, Program.eval] using finished
  obtain ⟨clean, equal⟩ := verdict.mp finishedVerdict
  have finalRecorded : (finalInput transcript, wire.hPiop) ∈
      ((finalize wire.hPiop transcript).record oracle).2 := by
    simp [finalize, ask, Program.bind, Program.record, equal]
  exact ⟨transcript, transcript_execution_has_stages ns relation pending nonce wire
    oracle transcript constructed, clean, equal,
    Program.bind_log_right oracle (transcriptProgram ns relation pending nonce wire)
      (finalize wire.hPiop) transcript constructed finalRecorded⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentExecutableVerifier
