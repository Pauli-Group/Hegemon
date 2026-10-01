import SmzaRp05PcsWireProjection
import SmzaRp05ExecutableRestore
import HegemonCrypto.SmallWoodTranscript

/-!
# Source-shaped RP05 DECS response projection

COMPILED DEVELOPMENT PROJECTION. This stage derives the PCS transcript words from
existing DECS `high_coeffs`/`masking_evals`, reconstructed LVCS evaluation rows,
and verifier-derived DECS `gamma` and evaluation points. It does not accept
restored polynomials or `hashFpp` as inputs. The Rust source is
`decs_commitment_transcript_with_challenge` and `poly_restore` in
`smallwood_engine.rs`.

The dimensions are checked dynamically against the selected verifier shape:
five DECS polynomials, 38 opened evaluations in current SMZA, one gamma row
per polynomial, and one point per opened evaluation. The transcript prefix is
the eight digest words of `hash_mt`, followed by the five restored coefficient
vectors in order.

The upstream derivation of `gamma`, evaluation points, and LVCS rows is not
implemented by this file; they are explicit outputs of preceding verifier
stages. Rust/Lean arithmetic and source parity, accepted-proof composition,
the final PIOP transcript hash, and soundness are not established here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05DecsResponseProjection

open HegemonCrypto.SmallWood.SmzaRp05ExecutableRestore
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8SmzaOracleParser (RawDigest)
open SmzaRp05ExecutableMerkleVerifier (Program)
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection (FieldMatrix)

set_option autoImplicit false

abbrev FieldRow := List Goldilocks

/-- Existing two DECS proof matrices, decoded in their original wire order. -/
structure DecodedDecsResponseFields where
  highCoeffs : FieldMatrix
  maskingEvals : FieldMatrix
deriving DecidableEq

def decodeDecsResponseFields (highCoeffs maskingEvals : List (List Nat)) :
    Option DecodedDecsResponseFields := do
  let highCoeffs ← HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection.decodeFieldMatrix highCoeffs
  let maskingEvals ← HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection.decodeFieldMatrix maskingEvals
  pure ⟨highCoeffs, maskingEvals⟩

def decodeFieldRow (words : List FieldWord) : FieldRow := words.map fun word => word.val

def exprSum : List Expr → Expr
  | [] => .term 0 0
  | value :: rest => .add value (exprSum rest)

def exprProduct : List Expr → Expr
  | [] => .term 0 1
  | value :: rest => .mul value (exprProduct rest)

/-- Lagrange basis for the `index`th entry of the source-ordered DECS point
list. Distinctness is an upstream protocol condition, just as in Rust's
generic interpolation path. -/
def responseBasis (points : FieldRow) (index : Nat) : Expr :=
  exprProduct ((List.range points.length).filterMap fun j =>
    if j = index then none else
      let x := points.getD index 0
      let y := points.getD j 0
      some (divisor x y))

/-- Interpolate the low coefficients of the residual evaluation vector using
the same Lagrange polynomial represented by `ExecutableRestore.Expr`. -/
def responseLowPolynomial (points values : FieldRow) : Expr :=
  exprSum ((List.range points.length).map fun i =>
    .mul (.term 0 (values.getD i 0)) (responseBasis points i))

def evalExpr (expression : Expr) (point : Goldilocks) : Goldilocks :=
  SmzaRp05ExecutableRestore.eval expression point

def responseHighPolynomial (opened : Nat) (high : FieldRow) : Expr :=
  exprSum ((List.range high.length).map fun i =>
    .term (opened + i) (high.getD i 0))

/-- Rust `poly_restore`: subtract `x^opened * high(x)` from every requested
evaluation, interpolate those residuals at the verifier-derived points, then
append the unchanged high polynomial beginning at degree `opened`. -/
def polyRestoreResponse (points values high : FieldRow) : Option FieldRow := do
  if points.length ≠ values.length then none else pure ()
  let opened := points.length
  let highExpr := responseHighPolynomial opened high
  let residual := values.zip points |>.map fun (value, point) =>
    value - evalExpr highExpr point
  let lowExpr := responseLowPolynomial points residual
  let restored := Expr.add lowExpr highExpr
  pure ((List.range (opened + high.length)).map fun degree =>
    SmzaRp05ExecutableRestore.coefficient restored degree)

/-- Compute one DEC evaluation row: LVCS row dot verifier gamma, plus the
proof-carried masking evaluation. -/
def decEvaluation (lvcsRow gamma : FieldRow) (masking : Goldilocks) : Option Goldilocks := do
  if lvcsRow.length ≠ gamma.length then none else pure ()
  pure ((List.range gamma.length).foldl (fun acc index =>
    acc + lvcsRow.getD index 0 * gamma.getD index 0) 0 + masking)

/-- Restore all DECS response polynomials in source `k` order. Every matrix
shape must agree; malformed proof data cannot be default-filled. -/
def restoredResponsePolynomials (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) :
    Option (List FieldRow) := do
  if fields.highCoeffs.length ≠ 5 ∨ fields.maskingEvals.length ≠ 38 ∨
      evalPoints.length ≠ 38 ∨ gamma.length ≠ 5 ∨ lvcsRows.length ≠ 38 ∨
      fields.maskingEvals.any (fun row => decide (row.length ≠ 5)) ∨
      gamma.any (fun row => decide (row.length ≠ rowCount)) ∨
      lvcsRows.any (fun row => decide (row.length ≠ rowCount)) ∨
      fields.highCoeffs.any (fun row => decide (row.length ≠ highCount))
    then none else pure ()
  let points := decodeFieldRow evalPoints
  if points.length ≠ 38 then none else pure ()
  if !decide points.Nodup then none else pure ()
  (List.range 5).mapM fun polynomialIndex => do
    let gammaRow := decodeFieldRow (gamma.getD polynomialIndex [])
    let highRow := decodeFieldRow (fields.highCoeffs.getD polynomialIndex [])
    let maskingRow := fields.maskingEvals.map fun row =>
      (row.getD polynomialIndex ⟨0, by decide⟩).val
    let values ← (List.range 38).mapM fun evaluationIndex => do
      let row := decodeFieldRow (lvcsRows.getD evaluationIndex [])
      decEvaluation row gammaRow (maskingRow.getD evaluationIndex 0)
    polyRestoreResponse points values highRow

/-- Rust DECS/PCS transcript words: digest words of `hash_mt`, then each
restored DECS polynomial's coefficients in polynomial-index order. -/
def responseTranscriptWords (hashMt : RawDigest) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) :
    Option (List Nat) := do
  let polynomials ← restoredResponsePolynomials fields lvcsRows gamma evalPoints
    rowCount highCount
  pure (SmzaRp05ExecutableChallengeStage.digestWords hashMt ++
    (polynomials.flatten.map fun coefficient => coefficient.val))

/-- `piop_recompute_transcript` hashes the PCS transcript followed by the
verifier-derived statement-binding words. The digest is queried from the
ordinary oracle program, never supplied as an independent proof parameter. -/
def hashFppProgram (hashMt : RawDigest) (fields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat) :
    Option (Program RawDigest) := do
  let pcsWords ← responseTranscriptWords hashMt fields lvcsRows gamma evalPoints
    rowCount highCount
  let words := pcsWords ++ statementBinding
  let input := V8SmzaOracleParser.framedInput SmallWoodTranscript.piopInputDomain
    (words.flatMap (encodeLE 8))
  pure (SmzaRp05ExecutableMerkleVerifier.ask input)

theorem transcript_prefix_is_hash_mt (hashMt : RawDigest)
    (fields : DecodedDecsResponseFields) (lvcsRows gamma : List (List FieldWord))
    (evalPoints : List FieldWord) (rowCount highCount : Nat)
    (words : List Nat)
    (formed : responseTranscriptWords hashMt fields lvcsRows gamma evalPoints
      rowCount highCount = some words) :
    ∃ body, words = SmzaRp05ExecutableChallengeStage.digestWords hashMt ++ body := by
  unfold responseTranscriptWords at formed
  cases restored : restoredResponsePolynomials fields lvcsRows gamma evalPoints
      rowCount highCount with
  | none => simp [restored] at formed
  | some polynomials =>
      simp [restored] at formed
      exact ⟨(polynomials.map fun row => row.map fun coefficient => coefficient.val).flatten,
        formed.symm⟩

end HegemonCrypto.SmallWood.SmzaRp05DecsResponseProjection
