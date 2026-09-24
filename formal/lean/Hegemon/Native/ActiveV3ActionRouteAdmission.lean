namespace Hegemon
namespace Native
namespace ActiveV3ActionRouteAdmission

inductive Route where
  | inlineTransfer
  | sidecarTransfer
  | candidateArtifact
  | coinbase
  | bridge
  | unsupported
deriving DecidableEq, Repr

inductive Reject where
  | inactiveSidecar
  | retiredCandidate
  | inactiveBridge
  | externalCoinbase
  | unsupportedRoute
deriving DecidableEq, Repr

structure Input where
  route : Route
  allowInternalCoinbase : Bool
deriving DecidableEq, Repr

/-!
The production fixed-ID gate runs before payload decode or queue reservation.
Its rejection order is sidecar, candidate, any bridge-family route, then an
externally supplied coinbase.  `Route` is already the result of the fixed-ID
projection, so `evaluate` preserves exactly that classified decision table.
-/
def evaluate (input : Input) : Except Reject Unit :=
  match input.route with
  | Route.sidecarTransfer => Except.error Reject.inactiveSidecar
  | Route.candidateArtifact => Except.error Reject.retiredCandidate
  | Route.bridge => Except.error Reject.inactiveBridge
  | Route.coinbase =>
      if input.allowInternalCoinbase then Except.ok ()
      else Except.error Reject.externalCoinbase
  | Route.inlineTransfer => Except.ok ()
  | Route.unsupported => Except.error Reject.unsupportedRoute

theorem accepts_iff_active_route (input : Input) :
    evaluate input = Except.ok () ↔
      input.route = Route.inlineTransfer ∨
      (input.route = Route.coinbase ∧ input.allowInternalCoinbase = true) := by
  cases input with
  | mk route allowInternalCoinbase =>
      cases route <;> cases allowInternalCoinbase <;> simp [evaluate]

theorem inline_transfer_accepts :
    evaluate { route := Route.inlineTransfer, allowInternalCoinbase := false } =
      Except.ok () := by
  rfl

theorem sidecar_always_rejects (allowInternalCoinbase : Bool) :
    evaluate { route := Route.sidecarTransfer, allowInternalCoinbase } =
      Except.error Reject.inactiveSidecar := by
  rfl

theorem candidate_always_rejects (allowInternalCoinbase : Bool) :
    evaluate { route := Route.candidateArtifact, allowInternalCoinbase } =
      Except.error Reject.retiredCandidate := by
  rfl

theorem bridge_always_rejects (allowInternalCoinbase : Bool) :
    evaluate { route := Route.bridge, allowInternalCoinbase } =
      Except.error Reject.inactiveBridge := by
  rfl

theorem unsupported_always_rejects (allowInternalCoinbase : Bool) :
    evaluate { route := Route.unsupported, allowInternalCoinbase } =
      Except.error Reject.unsupportedRoute := by
  rfl

theorem coinbase_is_internal_only :
    evaluate { route := Route.coinbase, allowInternalCoinbase := false } =
        Except.error Reject.externalCoinbase ∧
      evaluate { route := Route.coinbase, allowInternalCoinbase := true } =
        Except.ok () := by
  constructor <;> rfl

end ActiveV3ActionRouteAdmission
end Native
end Hegemon
