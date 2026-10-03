import SmzaRp05PcsToFinalProgram
import SmzaRp04RawRoleSampling

/-!
# Current-profile canonical opening joined to the decoded-proof program

This module makes the six-point PIOP opening an ordinary raw-oracle result.
For each nonce in source order 0 through 15 it samples six canonical
Goldilocks words from the active SMZA `piopOpening` frame and applies the
existing typed opening decoder. The first decoder success is passed directly
to the PCS-to-final program using the same `hPiop` and the same oracle. No
opening or opening certificate is a caller input.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningProgram

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9PiopSoundness (Opening)
open SmzaRp04RawRoleSampling (openingDecoder)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05StatementNamespace (Statement)
open SmzaRp05PcsWireProjection (DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)

set_option autoImplicit false

def openingCounterInput (hPiop : RawDigest) (nonce counter : Nat) : RawInput :=
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
    V8SmzaOracleParser.profileDomain ++
    encodeLE 8 SmallWoodTranscript.piopOpeningDomain.length ++
    SmallWoodTranscript.piopOpeningDomain ++
    encodeLE 8 9 ++ encodeLE 8 nonce ++ List.ofFn hPiop ++ encodeLE 8 counter

def openingFieldCap : Nat := SmzaRp05ExecutableChallengeStage.callCap 6

def openingFieldInputs (hPiop : RawDigest) (nonce : Nat) : List RawInput :=
  (List.range openingFieldCap).map (openingCounterInput hPiop nonce)

noncomputable def decodeOpeningWords (words : List FieldWord) : Option Opening :=
  if words.length = 6 then
    openingDecoder (fun index => words.getD index.val ⟨0, by decide⟩)
  else none

noncomputable def openingAttempt (hPiop : RawDigest) (nonce : Nat) :
    Program (Option Opening) :=
  (SmzaRp05ExecutableChallengeStage.fieldLoop 6 []
    (openingFieldInputs hPiop nonce)).bind fun sampled =>
      match sampled with
      | none => .done none
      | some words => .done (some (decodeOpeningWords words))

noncomputable def chooseOpeningProgram (hPiop : RawDigest) : Program Opening :=
  let rec scan : List Nat → Program (Option Opening)
    | [] => .done none
    | nonce :: rest =>
        (openingAttempt hPiop nonce).bind fun result =>
          match result with
          | some opening => .done (some opening)
          | none => scan rest
  (scan (List.range 16)).bind fun selected => .done selected

theorem current_nonce_and_cap :
    openingFieldCap = 5 ∧ (List.range 16).length = 16 := by
  decide

/-- Exact middle signature with its opening removed from caller inputs. The
nonce scan and final PIOP verifier execute under the same oracle and use the
decoded proof's `hPiop` throughout. -/
noncomputable def currentOpeningFinalProgram (ns : SmzaRp05LeafNamespace.Namespace)
    (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (hPiop : RawDigest)
    (pcs : DecodedPcsFields) (decs : DecodedDecsResponseFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) : Program Unit :=
  (chooseOpeningProgram hPiop).bind fun opening =>
    match SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
      pending hPiop pcs decs piop packingFactor widths deltas beta lvcsCols
      tailCount totalRows salt binding statementBinding tapes paths with
    | none => .done none
    | some final => final

end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningProgram
