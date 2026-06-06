import Hegemon.Bridge.Encoding

namespace Hegemon
namespace Bridge

abbrev ReplayKey := List Byte

structure ReplayState where
  consumed : List ReplayKey
  pending : List ReplayKey
deriving DecidableEq, Repr

def ReplayState.empty : ReplayState :=
  { consumed := [], pending := [] }

def ReplayState.accept (state : ReplayState) (key : ReplayKey) : Option ReplayState :=
  if key ∈ state.consumed then
    none
  else
    some { state with consumed := key :: state.consumed }

def ReplayState.stage (state : ReplayState) (key : ReplayKey) : Option ReplayState :=
  if key ∈ state.consumed then
    none
  else if key ∈ state.pending then
    none
  else
    some { state with pending := key :: state.pending }

def ReplayState.importOne (state : ReplayState) (key : ReplayKey) : Option ReplayState :=
  if key ∈ state.consumed then
    none
  else
    some { consumed := key :: state.consumed, pending := state.pending.erase key }

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

theorem stage_inserts_pending
    {state next : ReplayState} {key : ReplayKey} :
    state.stage key = some next ->
    key ∈ next.pending := by
  intro staged
  unfold ReplayState.stage at staged
  split at staged
  · cases staged
  · split at staged
    · cases staged
    · cases staged
      simp

theorem stage_prevents_duplicate_pending
    {state next : ReplayState} {key : ReplayKey} :
    state.stage key = some next ->
    next.stage key = none := by
  intro staged
  unfold ReplayState.stage at staged
  split at staged
  · cases staged
  · split at staged
    · cases staged
    · cases staged
      unfold ReplayState.stage
      simp

theorem import_inserts_consumed
    {state next : ReplayState} {key : ReplayKey} :
    state.importOne key = some next ->
    key ∈ next.consumed := by
  intro imported
  unfold ReplayState.importOne at imported
  split at imported
  · cases imported
  · cases imported
    simp

theorem import_prevents_reimport
    {state next : ReplayState} {key : ReplayKey} :
    state.importOne key = some next ->
    next.importOne key = none := by
  intro imported
  unfold ReplayState.importOne at imported
  split at imported
  · cases imported
  · cases imported
    unfold ReplayState.importOne
    simp

theorem import_prevents_restaging
    {state next : ReplayState} {key : ReplayKey} :
    state.importOne key = some next ->
    next.stage key = none := by
  intro imported
  unfold ReplayState.importOne at imported
  split at imported
  · cases imported
  · cases imported
    unfold ReplayState.stage
    simp

end Bridge
end Hegemon
