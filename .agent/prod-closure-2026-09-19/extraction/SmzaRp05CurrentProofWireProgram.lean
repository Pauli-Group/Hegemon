import SmzaRp05CurrentOpeningProgram
import SmzaRp05PcsWireProjection
import SmzaRp05DecsResponseProjection
import SmzaRp05ExecutableReconstruction

/-!
# Current-profile same-proof field projection

This module removes separate caller arguments for PCS matrices, DECS matrices,
PIOP matrices, DECS tapes, and Merkle paths by taking the extant serialized
field payloads together and canonically decoding them before running the
current-opening program. The matrix payloads and paths/tapes are the existing
`PcsProof`, `DecsProof`, and `opened_witness` fields; no extra proof fields are
introduced.

Boundary: this is the projection *after* the Rust outer proof parser. Lean does
not yet define the `SmallwoodProof` byte parser, so `ExistingProofFieldView` is
not a byte string and this definition does not claim RawInput/RawDigest
acceptance from serialized proof bytes. The exact unclosed interface is the
Rust proof-byte decode/bind stage that produces this field view. Contextual
verifier inputs (statement/relation, shape, salt binding, and statement-binding
words) remain explicit below.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentProofWireProgram

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (FieldWord canonicalWord)
open V8SmzaOracleParser (RawDigest)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05StatementNamespace (Statement)

set_option autoImplicit false

/-- Existing fields exposed by successful Rust proof parsing. Matrices retain
their source row order and words; malformed/noncanonical values are rejected
by `decodeExistingProofFieldView`. -/
structure ExistingProofFieldView where
  hPiop : RawDigest
  salt : List Byte
  partialEvals : List (List Nat)
  rcombiTails : List (List Nat)
  subsetEvals : List (List Nat)
  -- The source proof has one opened-witness RowScalars matrix; PCS and PIOP
  -- decode this same field, not independently chosen matrices.
  openedRowScalars : List (List Nat)
  decsHighCoeffs : List (List Nat)
  decsMaskingEvals : List (List Nat)
  piopNonlinearHighs : List (List Nat)
  piopLinearHighs : List (List Nat)
  tapes : List (List Byte)
  paths : List (List RawDigest)

private def matrixHasShape {α : Type} (matrix : List (List α))
    (rows columns : Nat) : Bool :=
  decide (matrix.length = rows) &&
    !(matrix.any fun row => decide (row.length ≠ columns))

private def asIndexedMatrix (matrix : List (List FieldWord)) (i j : Nat) : FieldWord :=
  ((matrix.getD i []).getD j ⟨0, by decide⟩)

/-- Decode a fixed-shape existing PIOP matrix into the functions consumed by
the reconstruction suffix. The guards precede all indexed projections, so
defaults in `asIndexedMatrix` are unreachable for returned values. -/
private def decodePiopFields (nonlinearHighs linearHighs rowScalars : List (List Nat)) :
    Option SmzaRp05ExecutableReconstruction.DecodedPiopFields := do
  if !matrixHasShape nonlinearHighs 5 483 ||
      !matrixHasShape linearHighs 5 126 ||
      !matrixHasShape rowScalars 6 696 then none else pure ()
  let nonlinear ← SmzaRp05PcsWireProjection.decodeFieldMatrix nonlinearHighs
  let linear ← SmzaRp05PcsWireProjection.decodeFieldMatrix linearHighs
  let scalars ← SmzaRp05PcsWireProjection.decodeFieldMatrix rowScalars
  pure {
    nonlinearHighs := fun i j => asIndexedMatrix nonlinear i.val j.val
    linearHighs := fun i j => asIndexedMatrix linear i.val j.val
    rowScalars := fun i j => asIndexedMatrix scalars i.val j.val
  }

/-- Canonical decoding of the unchanged PCS/DECS/PIOP fields, preserving the
source proof's tapes and authentication paths. -/
def decodeExistingProofFieldView (wire : ExistingProofFieldView) :
    Option (SmzaRp05PcsWireProjection.DecodedMiddleWire ×
      SmzaRp05DecsResponseProjection.DecodedDecsResponseFields ×
      SmzaRp05ExecutableReconstruction.DecodedPiopFields) := do
  let middle ← SmzaRp05PcsWireProjection.decodeMiddleWire wire.partialEvals
    wire.rcombiTails wire.subsetEvals wire.openedRowScalars
  let decs ← SmzaRp05DecsResponseProjection.decodeDecsResponseFields
    wire.decsHighCoeffs wire.decsMaskingEvals
  let piop ← decodePiopFields wire.piopNonlinearHighs wire.piopLinearHighs
    wire.openedRowScalars
  pure (middle, decs, piop)

/-- Same-oracle current-profile composition from the extant source-shaped
proof-field view. A malformed field view rejects before any oracle calls. -/
noncomputable def currentProofFieldProgram
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (binding : List Byte)
    (statementBinding : List Nat) (wire : ExistingProofFieldView) : Program Unit :=
  match decodeExistingProofFieldView wire with
  | none => .done none
  | some (middle, decs, piop) =>
      SmzaRp05CurrentOpeningProgram.currentOpeningFinalProgram ns dsl statement
        pending wire.hPiop middle.pcs decs piop packingFactor widths deltas beta
        lvcsCols tailCount totalRows wire.salt binding statementBinding
        wire.tapes wire.paths

end HegemonCrypto.SmallWood.SmzaRp05CurrentProofWireProgram
