import Hegemon.Bytes

namespace Hegemon
namespace Shielded

abbrev Nullifier := List Byte

def zeroNullifier : Nullifier :=
  List.replicate 48 0

def isZeroNullifier (key : Nullifier) : Bool :=
  key == zeroNullifier

structure NullifierState where
  spent : List Nullifier
  pending : List Nullifier
deriving DecidableEq, Repr

def NullifierState.empty : NullifierState :=
  { spent := [], pending := [] }

def NullifierState.stage (state : NullifierState) (key : Nullifier) : Option NullifierState :=
  if isZeroNullifier key then
    none
  else if key ∈ state.spent then
    none
  else if key ∈ state.pending then
    none
  else
    some { state with pending := key :: state.pending }

def NullifierState.importOne (state : NullifierState) (key : Nullifier) : Option NullifierState :=
  if isZeroNullifier key then
    none
  else if key ∈ state.spent then
    none
  else
    some { spent := key :: state.spent, pending := state.pending.erase key }

theorem stage_rejects_zero (state : NullifierState) :
    state.stage zeroNullifier = none := by
  unfold NullifierState.stage isZeroNullifier
  simp

theorem import_rejects_zero (state : NullifierState) :
    state.importOne zeroNullifier = none := by
  unfold NullifierState.importOne isZeroNullifier
  simp

theorem stage_inserts_pending
    {state next : NullifierState} {key : Nullifier} :
    state.stage key = some next ->
    key ∈ next.pending := by
  intro staged
  unfold NullifierState.stage at staged
  split at staged
  · cases staged
  · split at staged
    · cases staged
    · split at staged
      · cases staged
      · cases staged
        simp

theorem stage_prevents_duplicate_pending
    {state next : NullifierState} {key : Nullifier} :
    state.stage key = some next ->
    next.stage key = none := by
  intro staged
  unfold NullifierState.stage at staged
  split at staged
  · cases staged
  · split at staged
    · cases staged
    · split at staged
      · cases staged
      · cases staged
        unfold NullifierState.stage
        simp

theorem import_inserts_spent
    {state next : NullifierState} {key : Nullifier} :
    state.importOne key = some next ->
    key ∈ next.spent := by
  intro imported
  unfold NullifierState.importOne at imported
  split at imported
  · cases imported
  · split at imported
    · cases imported
    · cases imported
      simp

theorem import_prevents_reimport
    {state next : NullifierState} {key : Nullifier} :
    state.importOne key = some next ->
    next.importOne key = none := by
  intro imported
  unfold NullifierState.importOne at imported
  split at imported
  · cases imported
  · split at imported
    · cases imported
    · cases imported
      unfold NullifierState.importOne
      simp

theorem import_prevents_restaging
    {state next : NullifierState} {key : Nullifier} :
    state.importOne key = some next ->
    next.stage key = none := by
  intro imported
  unfold NullifierState.importOne at imported
  split at imported
  · cases imported
  · split at imported
    · cases imported
    · cases imported
      unfold NullifierState.stage
      simp

end Shielded
end Hegemon
