import SmzaRp05DecsPointProjection
import SmzaRp05LvcsWireProjection

/-!
# Same-run PCS-opening to LVCS-row program

COMPILED DEVELOPMENT PROJECTION. This composition consumes the existing decoded
partial evaluations, combination tails, subset evaluations, opened row
scalars, and `h_piop`. It computes heads, hashes the opening request, samples
the exact DECS indexes, constructs disjoint-coset field points, then
reconstructs LVCS rows. Neither heads, sampled points, nor rows are caller
arguments or added to the proof wire.

This does not yet create the authenticated DECS leaf payloads/root, derive the
five DECS gamma rows from that root, restore the DECS polynomials, or compute
`hash_fpp` and the final PIOP transcript. It is not a full verifier theorem.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PcsLvcsMiddle

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PcsWireProjection (DecodedMiddleWire decodeMiddleWire)

set_option autoImplicit false

def rowsProgram (pending : Bool) (hPiop : V8SmzaOracleParser.RawDigest)
    (wire : DecodedMiddleWire) (evalPoints : List Goldilocks)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) :
    Option (Program (List (List Goldilocks))) := do
  let pointsProgram ← SmzaRp05DecsPointProjection.openingPointProgram pending
    hPiop wire.pcs evalPoints wire.rowScalars packingFactor widths deltas
    beta lvcsCols tailCount
  pure (pointsProgram.bind fun decsPoints =>
    .done (SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
      wire.pcs evalPoints decsPoints wire.rowScalars packingFactor
      widths deltas beta lvcsCols totalRows tailCount))

/-- Keep the exact sampled indexes for subsequent authenticated-leaf queries. -/
def indexedRowsProgram (pending : Bool) (hPiop : V8SmzaOracleParser.RawDigest)
    (wire : DecodedMiddleWire) (evalPoints : List Goldilocks)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) :
    Option (Program (List Nat × List (List Goldilocks))) := do
  let indexPointProgram ← SmzaRp05DecsPointProjection.openingIndexPointProgram
    pending hPiop wire.pcs evalPoints wire.rowScalars packingFactor
    widths deltas beta lvcsCols tailCount
  pure (indexPointProgram.bind fun (indexes, points) =>
    .done ((SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
      wire.pcs evalPoints points wire.rowScalars packingFactor
      widths deltas beta lvcsCols totalRows tailCount).map
        (fun rows => (indexes, rows))))

/-- Raw existing proof-field arrays are decoded before any transcript request.
Malformed field words and inconsistent PCS matrices reject via the pure stage. -/
def rowsFromWireProgram (pending : Bool) (hPiop : V8SmzaOracleParser.RawDigest)
    (partialEvals rcombiTails subsetEvals openedRowScalars : List (List Nat))
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat) :
    Option (Program (List (List Goldilocks))) := do
  let wire ← decodeMiddleWire partialEvals rcombiTails subsetEvals openedRowScalars
  rowsProgram pending hPiop wire evalPoints packingFactor widths deltas
    beta lvcsCols tailCount totalRows

end HegemonCrypto.SmallWood.SmzaRp05PcsLvcsMiddle
