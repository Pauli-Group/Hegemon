namespace Hegemon
namespace Native
namespace PendingActionCanonicality

/-!
Executable active-native-V3 wire-era model for `PendingAction` canonicality.

Active V3 has no consensus arrival-time field. Exact historical V1 bytes
(32-byte action id plus `received_ms`) and unreleased interim V2 bytes
(48-byte action id plus `received_ms`) are identify-and-reject only; no value
of the retired field is upgraded into V3. Wall-clock arrival time and block
header time are outside this model. Exact SCALE decoding, hash collision
resistance, persistence durability, and downstream action semantics remain
separate assumptions bound by the generated production vectors.
-/

def u64Max : Nat := 18446744073709551615

inductive WireEra where
  | activeV3
  | legacyV2ReceivedMs
  | legacyV1ActionId32ReceivedMs
  | malformed
deriving DecidableEq, Repr

structure Input where
  wireEra : WireEra
  receivedMs : Option Nat
deriving DecidableEq, Repr

inductive Reject where
  | retiredV2ReceivedMs
  | retiredV1ActionId32
  | malformed
deriving DecidableEq, Repr

def evaluate (input : Input) : Except Reject Unit :=
  match input.wireEra, input.receivedMs with
  | .activeV3, none => Except.ok ()
  | .legacyV2ReceivedMs, some _ => Except.error .retiredV2ReceivedMs
  | .legacyV1ActionId32ReceivedMs, some _ => Except.error .retiredV1ActionId32
  | _, _ => Except.error .malformed

theorem accepts_iff_exact_active_v3 (input : Input) :
    evaluate input = Except.ok () ↔
      input.wireEra = .activeV3 ∧ input.receivedMs = none := by
  cases input with
  | mk wireEra receivedMs =>
      cases wireEra <;> cases receivedMs <;> simp [evaluate]

theorem legacy_v2_rejection_is_independent_of_timestamp (receivedMs : Nat) :
    evaluate { wireEra := .legacyV2ReceivedMs, receivedMs := some receivedMs } =
      Except.error .retiredV2ReceivedMs := by
  rfl

theorem legacy_v1_rejection_is_independent_of_timestamp (receivedMs : Nat) :
    evaluate { wireEra := .legacyV1ActionId32ReceivedMs, receivedMs := some receivedMs } =
      Except.error .retiredV1ActionId32 := by
  rfl

theorem boundary_cases_fail_closed :
    (evaluate { wireEra := .activeV3, receivedMs := none }).isOk = true ∧
    (evaluate { wireEra := .legacyV2ReceivedMs, receivedMs := some 0 }).isOk = false ∧
    (evaluate { wireEra := .legacyV2ReceivedMs, receivedMs := some u64Max }).isOk = false ∧
    (evaluate { wireEra := .legacyV1ActionId32ReceivedMs, receivedMs := some 0 }).isOk = false ∧
    (evaluate { wireEra := .legacyV1ActionId32ReceivedMs, receivedMs := some u64Max }).isOk = false ∧
    (evaluate { wireEra := .malformed, receivedMs := none }).isOk = false := by
  native_decide

end PendingActionCanonicality
end Native
end Hegemon
