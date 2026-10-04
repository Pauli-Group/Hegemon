import SmzaRp05ExecutableFinalVerifier
import SmzaRp05RawScalarChecks

/-!
# Proof-connected mathematical PIOP reconstruction suffix

SOURCE-ONLY, NOT COMPILED. This file closes the *data-construction* gap for
the PIOP suffix: neither reconstructed coefficients nor an EvaluationTrace
nor ClaimedTranscript is supplied by the caller. All are calculated from
the existing proof's high coefficients and opened_witness.row_scalars.
No acceptance, extraction, or generated-certificate premise is used.

IMPORTANT EXECUTABILITY BOUNDARY: the reused Polynomial restoration and
relation interpretation are noncomputable definitions. Thus `reconstruct`
is a pure mathematical function, NOT yet an executable verifier stage.
An executable implementation and equality to this function remain needed;
this file does not hide that gap behind a supplied callback or certificate.

Rust source: smallwood_engine.rs `piop_recompute_transcript` (10428 ff.)
splits each 696-word row into witness[0..686], nonlinear masks[686..691],
linear masks[691..696]; restores nonlinear degree 488 from six values and
483 proof highs; restores linear degree 132 from those six values plus a
zero value at zero and 126 proof highs; corrects its packing sum, and hashes
only its 132 nonconstant coefficients. These are the operations below.

INPUT PROVENANCE STILL REQUIRED, not premises of a theorem here:
* `opening` and `matrix` are the derived admissible six-point opening and
  gamma-prime values; `hashFpp` is hash_piop(PCS transcript ++ binding), NOT
  proof.h_piop. Their actual oracle derivation must be composed upstream.
* The concrete current data is `SmzaRp05GeneratedCertificates.currentDsl`
  in relation/SmzaRp05GeneratedCertificates.lean:20. Its source-only import
  chain remains blocked upstream, so this file keeps RawScalarChecks' DSL
  parameter rather than claim a checked current-DAG/CSR composition. No
  RP04 relation is substituted and no GeneratedCertificates premise is
  smuggled in. The function can be specialized to that existing data once
  its dependency chain checks; its certificate is not an argument here.
* `pcs_recompute_transcript` (10698 ff.) still needs proof-connected
  pcs_reconstruct_combi_heads / lvcs_recompute_rows and DECS poly_restore.
  The Merkle/challenge core does not yet calculate hashFpp or its matrix.

Consequently this does not prove Rust acceptance, FiveMcaChecks,
TwelveLvcsChecks, or a BEFORE hash record. The evaluation and packing-sum
theorems below are genuine consequences of reconstruction, but alone say
nothing about the pre-opening committed transcript.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableReconstruction

open Polynomial
open V8Smz9PiopSoundness V8Smz9PiopReconstruction
open V8Smz9AdaptiveFiniteAccounting V8Smz9EagerSimulator
open SmzaRp05RelationRefinement SmzaRp05StatementNamespace
open SmzaRp05RawScalarChecks
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open V8SmzaOracleParser (RawDigest)
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
noncomputable section

/-- Exactly the existing PIOP high fields and existing row-scalar openings.
Fixed dimensions stand for successful existing shape/canonical decoding;
no extra serialized fields or corrected coefficients are introduced. -/
structure DecodedPiopFields where
  nonlinearHighs : Fin 5 → Fin 483 → FieldWord
  linearHighs : Fin 5 → Fin 126 → FieldWord
  rowScalars : Fin 6 → Fin 696 → FieldWord

def toField (word : FieldWord) : Goldilocks := word.val

def toWord (value : Goldilocks) : FieldWord :=
  ⟨value.val, value.val_lt⟩

def proofHighs (proof : DecodedPiopFields) : ProofHighs where
  nonlinear row index := toField (proof.nonlinearHighs row index)
  linear row index := toField (proof.linearHighs row index)

def witness (proof : DecodedPiopFields) : Fin 6 → Fin 686 → Goldilocks :=
  fun coordinate row =>
    toField (proof.rowScalars coordinate ⟨row.val, by omega⟩)

def masks (proof : DecodedPiopFields) : MaskOpeningValues Goldilocks :=
  (fun coordinate row =>
    toField (proof.rowScalars coordinate ⟨686 + row.val, by omega⟩),
   fun coordinate row =>
    toField (proof.rowScalars coordinate ⟨691 + row.val, by omega⟩))

/-- Relation evaluation is computed, not supplied as scalar-check evidence. -/
def evaluation (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) : EvaluationTrace :=
  verifierEvaluationTrace dsl statement matrix opening (witness proof) (masks proof)

def nonlinearPolynomial (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (row : Fin 5) : Goldilocks[X] :=
  restoredNonlinear opening ((proofHighs proof).nonlinear row)
    ((evaluation dsl statement matrix opening proof).nonlinear row)

def linearPolynomial (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (row : Fin 5) : Goldilocks[X] :=
  reconstructedLinear opening ((proofHighs proof).linear row)
    ((evaluation dsl statement matrix opening proof).linear row)
    (publicBatchedTarget dsl statement matrix row)

/-- Pure mathematical suffix. All final coefficient arrays are calculated;
`pending` is the propagated source XOF state, never reset or certified clean.
There is no final digest or accepting transcript among the inputs. -/
def reconstruct (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : RawDigest) (pending : Bool) :
    ReconstructedTranscript where
  hashFpp := hashFpp
  nonlinear row index :=
    toWord ((nonlinearPolynomial dsl statement matrix opening proof row).coeff index.val)
  linearHigh row index :=
    toWord ((linearPolynomial dsl statement matrix opening proof row).coeff (index.val + 1))
  pendingXofFailure := pending

theorem reconstructed_nonlinear_evaluation (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (row : Fin 5) (coordinate : Fin 6) :
    (nonlinearPolynomial dsl statement matrix opening proof row).eval
        (points opening coordinate) =
      (evaluation dsl statement matrix opening proof).nonlinear row coordinate :=
  restored_nonlinear_evaluation opening _ _ coordinate

theorem reconstructed_linear_evaluation (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (row : Fin 5) (coordinate : Fin 6) :
    (linearPolynomial dsl statement matrix opening proof row).eval
        (points opening coordinate) =
      (evaluation dsl statement matrix opening proof).linear row coordinate := by
  unfold linearPolynomial reconstructedLinear
  rw [corrected_linear_evaluation, restored_linear_base_evaluation]

theorem reconstructed_linear_target (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (row : Fin 5) :
    V8Smz9PiopOpeningRecovery.packingSum V8Smz9AdaptiveFiniteAccounting.packingPoint
        (linearPolynomial dsl statement matrix opening proof row) =
      publicBatchedTarget dsl statement matrix row := by
  exact corrected_linear_target opening _ _

theorem pending_preserved (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : DecodedPiopFields) (hashFpp : RawDigest) (pending : Bool) :
    (reconstruct dsl statement matrix opening proof hashFpp pending).pendingXofFailure =
      pending := rfl

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableReconstruction
