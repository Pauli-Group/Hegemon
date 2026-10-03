import SmallWoodV8SmzaOracleParserR2
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch
import Mathlib.Data.List.OfFn

namespace HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.CanonicalBytes
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

def framePrefix : List V8Smz9HiddenLeafQrom.Byte :=
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++ V8SmzaOracleParser.profileDomain ++
  encodeLE 8 (V8SmzaOracleParser.roleName .leaf).length ++
    V8SmzaOracleParser.roleName .leaf ++ encodeLE 8 160

theorem frame_prefix_length : framePrefix.length = 119 := by decide

def bytesOfList {n : Nat} (xs : List V8Smz9HiddenLeafQrom.Byte) (h : xs.length = n) : Fin n → V8Smz9HiddenLeafQrom.Byte :=
  fun i => xs[i.val]'(by rw [h]; exact i.isLt)

theorem bytes_of_list_roundtrip {n : Nat} (xs : List V8Smz9HiddenLeafQrom.Byte) (h : xs.length = n) :
    List.ofFn (bytesOfList xs h) = xs := by
  subst n
  exact List.ofFn_getElem

def header (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte) : LeafHeader :=
  Fin.append (bytesOfList framePrefix frame_prefix_length) salt

def suffix (data : Fin 1176 → V8Smz9HiddenLeafQrom.Byte) : LeafSuffix :=
  Fin.append data (bytesOfList (n := 8) (encodeLE 8 0) (by decide))

def payload (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte) (index : LeafIndex) (tape : LeafTape)
    (data : Fin 1176 → V8Smz9HiddenLeafQrom.Byte) : List V8Smz9HiddenLeafQrom.Byte :=
  List.ofFn salt ++ List.ofFn (indexBytes index) ++ List.ofFn tape ++ List.ofFn data

/-- Exact SMZA profile framing, not a q20 profile-domain alias. Data contains
    both leaf field blocks and their length words; field canonicality is not
    needed for the hidden-tape support bound. -/
theorem source_split_is_smza_frame (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte) (index : LeafIndex)
    (tape : LeafTape) (data : Fin 1176 → V8Smz9HiddenLeafQrom.Byte) :
    List.ofFn (sourceLeafInput (header salt) (suffix data) index tape) =
      V8SmzaOracleParser.framedInput (V8SmzaOracleParser.roleName .leaf)
        (payload salt index tape data) := by
  have payloadLength : (payload salt index tape data).length = 1280 := by
    simp only [payload, List.length_append, List.length_ofFn]
  rw [V8SmzaOracleParser.framedInput, payloadLength]
  simp only [sourceLeafInput, tapedLeafInput, header, suffix, List.ofFn_fin_append,
    bytes_of_list_roundtrip, payload, framePrefix, List.append_assoc]

theorem smza_frame_tape_projection (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte) (index : LeafIndex)
    (tape : LeafTape) (data : Fin 1176 → V8Smz9HiddenLeafQrom.Byte) :
    leafTapeProjection (sourceLeafInput (header salt) (suffix data) index tape) = tape :=
  source_leaf_tape_projection _ _ _ _

theorem smza_frame_index_projection (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte) (index : LeafIndex)
    (tape : LeafTape) (data : Fin 1176 → V8Smz9HiddenLeafQrom.Byte) :
    rawInputIndex (sourceLeafInput (header salt) (suffix data) index tape) = index :=
  source_leaf_index_projection _ _ _ _

/-- A genuine coherent changed-input hybrid on exact SMZA-shaped leaves.
    The reference oracle, query circuit, salt, suffixes and target values
    are fixed independently of fresh hidden tapes. This is NOT yet a proof
    that an entire honest q38 protocol execution satisfies those conditions. -/
theorem smza_leaf_overlay_distance
    {Output Workspace : Type*} [Fintype Output] [AddGroup Output]
    [Fintype Workspace]
    (oldOracle : LeafInput → Output) (targets : LeafIndex → Output)
    (unopened : Finset LeafIndex) (salt : Fin 32 → V8Smz9HiddenLeafQrom.Byte)
    (data : LeafIndex → Fin 1176 → V8Smz9HiddenLeafQrom.Byte)
    (steps : ℕ → State (Input := LeafInput) (Output := Output) (Workspace := Workspace) ≃ₗᵢ[ℂ]
      State (Input := LeafInput) (Output := Output) (Workspace := Workspace))
    (initial : State (Input := LeafInput) (Output := Output) (Workspace := Workspace))
    (normalized : ‖initial‖ = 1) (queries : ℕ) :
    (∑ hidden : LeafIndex → LeafTape,
      ‖run (sourceOverlay oldOracle targets unopened (fun _ => header salt)
          (fun i => suffix (data i)) hidden) steps initial queries -
        run oldOracle steps initial queries‖) /
      (Fintype.card (LeafIndex → LeafTape) : ℝ) ≤
        Real.sqrt (4 * (queries : ℝ) ^ 2 * (2 ^ 512 : ℝ)⁻¹) :=
  source_overlay_mean_distance_le oldOracle targets unopened (fun _ => header salt)
    (fun i => suffix (data i)) steps initial normalized queries

end
end HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
