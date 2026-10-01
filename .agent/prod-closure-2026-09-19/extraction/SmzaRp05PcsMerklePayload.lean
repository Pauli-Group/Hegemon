import SmzaRp05PcsLvcsMiddle

/-!
# Reconstructed LVCS rows to the existing authenticated DECS leaf program

COMPILED DEVELOPMENT PROJECTION. Each legacy-normalized leaf payload is formed from
the current proof's salt, sampled table index, 64-byte leaf tape, reconstructed
140-word LVCS row, and five existing masking evaluations. The current RP05
statement preamble is supplied by the verifier's statement-binding step.
The compact authentication paths are existing proof bytes. No leaf payload or
root is admitted as an independent witness and no proof wire grows.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PcsMerklePayload

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Input)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05PcsWireProjection (DecodedMiddleWire FieldMatrix)
open SmzaRp05ExecutableChallengeStage (FieldWord PostMerkle)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

def normalizedLeafPayload (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord) : List Byte :=
  salt ++ encodeLE 8 index ++ tape ++ encodeLE 8 row.length ++
    row.flatMap (fun word => encodeLE 8 word.val) ++
    encodeLE 8 masks.length ++ masks.flatMap (fun word => encodeLE 8 word.val)

theorem normalized_payload_length (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (rowLength : row.length = 140) (maskLength : masks.length = 5) :
    (normalizedLeafPayload salt tape index row masks).length = 1280 := by
  have rowBytes (values : List Goldilocks) :
      (values.flatMap fun word => encodeLE 8 word.val).length = values.length * 8 := by
    induction values with
    | nil => rfl
    | cons word rest ih =>
        simp only [List.flatMap_cons, List.length_append, encodeLE_length,
          List.length_cons, ih]
        omega
  have maskBytes (values : List FieldWord) :
      (values.flatMap fun word => encodeLE 8 word.val).length = values.length * 8 := by
    induction values with
    | nil => rfl
    | cons word rest ih =>
        simp only [List.flatMap_cons, List.length_append, encodeLE_length,
          List.length_cons, ih]
        omega
  simp [normalizedLeafPayload, rowBytes, maskBytes, encodeLE_length,
    saltLength, tapeLength, rowLength, maskLength]

/-- Build the Merkle verifier's actual input, rejecting every wrong outer
dimension before indexed projections. Its payload bytes are calculated from
the LVCS output, never separately supplied. -/
def makeMerkleInput (salt binding : List Byte) (pending : Bool)
    (indexes : List Nat) (rows : List (List Goldilocks))
    (masks : FieldMatrix) (tapes : List (List Byte))
    (paths : List (List RawDigest)) : Option Input := do
  if salt.length ≠ 32 ∨ binding.length ≠ 1104 ∨
      indexes.length ≠ 38 ∨ rows.length ≠ 38 ∨ masks.length ≠ 38 ∨
      tapes.length ≠ 38 ∨ paths.length ≠ 38 ∨
      rows.any (fun row => decide (row.length ≠ 140)) ∨
      masks.any (fun row => decide (row.length ≠ 5)) ∨
      tapes.any (fun tape => decide (tape.length ≠ 64)) then none else pure ()
  pure {
    salt := salt
    binding := binding
    indices := fun j => indexes.getD j.val 0
    payloads := fun j => normalizedLeafPayload salt (tapes.getD j.val [])
      (indexes.getD j.val 0) (rows.getD j.val []) (masks.getD j.val [])
    paths := fun j => paths.getD j.val []
    pendingXofFailure := pending
  }

/-- In a single oracle program, opening-derived indexes and LVCS rows feed
the Merkle verifier, then its root feeds the existing 700-word gamma sampler.
The returned root/gamma values are not caller arguments. -/
def postMerkleFromPcsProgram (ns : Namespace) (pending : Bool)
    (hPiop : RawDigest) (wire : DecodedMiddleWire)
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat)
    (salt binding : List Byte) (masks : FieldMatrix)
    (tapes : List (List Byte)) (paths : List (List RawDigest)) :
    Option (Program PostMerkle) := do
  let earlier ← SmzaRp05PcsLvcsMiddle.indexedRowsProgram pending hPiop wire
    evalPoints packingFactor widths deltas beta lvcsCols tailCount totalRows
  pure (earlier.bind fun (indexes, rows) =>
    match makeMerkleInput salt binding pending indexes rows masks tapes paths with
    | none => .done none
    | some input => SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input)

/-- Retain the same reconstructed rows for the later DECS response. -/
def postMerkleWithRowsProgram (ns : Namespace) (pending : Bool)
    (hPiop : RawDigest) (wire : DecodedMiddleWire)
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat)
    (salt binding : List Byte) (masks : FieldMatrix)
    (tapes : List (List Byte)) (paths : List (List RawDigest)) :
    Option (Program (List Nat × List (List Goldilocks) × PostMerkle)) := do
  let earlier ← SmzaRp05PcsLvcsMiddle.indexedRowsProgram pending hPiop wire
    evalPoints packingFactor widths deltas beta lvcsCols tailCount totalRows
  pure (earlier.bind fun (indexes, rows) =>
    match makeMerkleInput salt binding pending indexes rows masks tapes paths with
    | none => .done none
    | some input =>
        (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).bind
          (fun post => .done (some (indexes, rows, post))))

end HegemonCrypto.SmallWood.SmzaRp05PcsMerklePayload
