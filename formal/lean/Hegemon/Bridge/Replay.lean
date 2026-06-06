namespace Hegemon
namespace Bridge

abbrev ReplayKey := List UInt8

structure ReplayState where
  consumed : List ReplayKey
deriving DecidableEq, Repr

def ReplayState.empty : ReplayState :=
  { consumed := [] }

def ReplayState.accept (state : ReplayState) (key : ReplayKey) : Option ReplayState :=
  if key ∈ state.consumed then
    none
  else
    some { consumed := key :: state.consumed }

theorem accept_inserts_key
    {state next : ReplayState} {key : ReplayKey} :
    state.accept key = some next ->
    key ∈ next.consumed := by
  intro accepted
  unfold ReplayState.accept at accepted
  split at accepted
  · cases accepted
  · cases accepted
    simp

theorem accept_prevents_duplicate
    {state next : ReplayState} {key : ReplayKey} :
    state.accept key = some next ->
    next.accept key = none := by
  intro accepted
  unfold ReplayState.accept at accepted
  split at accepted
  · cases accepted
  · cases accepted
    unfold ReplayState.accept
    simp

end Bridge
end Hegemon
