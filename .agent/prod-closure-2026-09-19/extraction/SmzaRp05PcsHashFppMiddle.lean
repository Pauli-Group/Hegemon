import SmzaRp05PcsMerklePayload
import SmzaRp05DecsResponseProjection

/-!
# Proof-connected PCS/LVCS/DECS middle through hash_fpp

COMPILED DEVELOPMENT PROJECTION. This ordinary oracle program composes the source
order: existing PCS/opened-row fields -> computed heads -> DECS opening hash
and q38 indexes -> disjoint-coset field points -> LVCS rows -> strict leaf
payloads/compact Merkle root -> 700 DECS coefficients -> response polynomial
restoration from existing high/masking proof fields -> PCS transcript plus
statement binding -> `hash_fpp` query. No reconstructed row, gamma, root, or
`hash_fpp` is an independent input or a new serialized proof field.

The canonical six PIOP opening points, public config and statement binding
are verifier inputs here and must still be connected to their existing
derivation. This source-only composition is not yet a Lean-checked theorem or
full accepted-proof/soundness endpoint.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PcsHashFppMiddle

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (FieldWord PostMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open HegemonCrypto.CanonicalBytes

set_option autoImplicit false

def gammaRows (post : PostMerkle) : List (List FieldWord) :=
  let sampled := SmzaRp05ExecutableChallengeStage.returnedWords 700 post.sampled
  (List.range 5).map fun repetition =>
    (sampled.drop (repetition * 140)).take 140

def hashFppMiddleProgram (ns : Namespace) (pending : Bool)
    (hPiop : RawDigest) (wire : DecodedMiddleWire)
    (decsFields : DecodedDecsResponseFields)
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat)
    (salt binding : List Byte) (statementBinding : List Nat)
    (tapes : List (List Byte)) (paths : List (List RawDigest)) :
    Option (Program (RawDigest × Bool)) := do
  let earlier ← SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending
    hPiop wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
    totalRows salt binding decsFields.maskingEvals tapes paths
  pure (earlier.bind fun (indexes, rows, post) =>
    match SmzaRp05DecsPointProjection.fieldPoints (lvcsCols + tailCount) indexes with
    | none => .done none
    | some points =>
        let rowsAsWords := rows.map fun row =>
          row.map SmzaRp05ExecutableRestore.toWord
        let pointWords := points.map SmzaRp05ExecutableRestore.toWord
        match SmzaRp05DecsResponseProjection.hashFppProgram post.root
            decsFields rowsAsWords (gammaRows post) pointWords totalRows
            lvcsCols statementBinding with
        | none => .done none
        | some hashProgram => hashProgram.bind fun digest =>
            .done (some (digest, post.pending)))

end HegemonCrypto.SmallWood.SmzaRp05PcsHashFppMiddle
