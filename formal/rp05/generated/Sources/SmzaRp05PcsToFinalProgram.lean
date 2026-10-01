import SmzaRp05PiopMatrixStage

/-!
# PCS middle joined to the existing mathematical PIOP suffix

COMPILED DEVELOPMENT COMPOSITION. The same decoded PIOP row-scalar fields feed PCS
head reconstruction and final relation evaluation. The PCS program computes
`hash_fpp`, then the PIOP coefficient sampler computes gamma-prime, then the
existing reconstruction calculates nonlinear/linear coefficients and the
existing final program compares the final transcript digest to proof.h_piop.
No head, LVCS row, Merkle root, DECS polynomial, hash, batching matrix or
reconstructed final transcript is a caller input or serialized field.

Still open: the typed six-point opening must be joined to the canonical
nonce/`h_piop` source stage; public relation/statement binding must be fixed
to the current generated identity; all new modules require Lean checking and
the accepted-run extraction theorem. The existing reconstruction's relation
interpretation is noncomputable, so this is a mathematical program, not a
compiled Rust-verifier equivalence proof.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PcsToFinalProgram

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05PcsWireProjection (DecodedPcsFields DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open V8Smz9PiopSoundness (Opening)
open HegemonCrypto.CanonicalBytes
open SmzaRp05RelationRefinement (RelationDsl)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

def sameProofRows (pcs : DecodedPcsFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    DecodedMiddleWire :=
  ⟨pcs, List.ofFn fun i : Fin 6 =>
    List.ofFn fun j : Fin 696 => piop.rowScalars i j⟩

noncomputable def finalFromMiddleProgram (ns : Namespace)
    (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    (opening : Opening) (pending : Bool) (hPiop : RawDigest)
    (pcs : DecodedPcsFields) (decs : DecodedDecsResponseFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat)
    (salt binding : List Byte) (statementBinding : List Nat)
    (tapes : List (List Byte)) (paths : List (List RawDigest)) :
    Option (Program Unit) := do
  let evalPoints : List Goldilocks :=
    List.ofFn (fun j : Fin 6 =>
      HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
  let middle ← SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
    (sameProofRows pcs piop) decs evalPoints packingFactor widths deltas
    beta lvcsCols tailCount totalRows salt binding statementBinding tapes paths
  pure (middle.bind fun (hashFpp, middlePending) =>
    (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
      middlePending hashFpp).bind fun (matrix, finalPending) =>
        SmzaRp05ExecutableFinalVerifier.finalize hPiop
          (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
            opening piop hashFpp finalPending))

end HegemonCrypto.SmallWood.SmzaRp05PcsToFinalProgram
