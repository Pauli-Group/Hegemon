import Q38Rp05CurrentFinalKey

/-!
# Generic two-read request composition

This isolates the execution identity for a nonleaf prefix, one final
nonleaf-key read, and a nonleaf continuation. The theorem is parametric in
both programs so applying it does not unfold the large concrete RP05 schedules.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

def compileCurrentTwoRead
    {bound : Nat} {Prefix Final Work : Type} [Fintype Work]
    (initialProgram : NonleafProgram (Rp05OtherRawInput bound) Prefix)
    (finalKey : Prefix → Rp05OtherRawInput bound)
    (continuation :
      Prefix → DigestRegister → NonleafProgram (Rp05OtherRawInput bound) Final)
    (next : Final → Program (Rp05FullRawInput bound) Work) :
    Program (Rp05FullRawInput bound) Work :=
  compileCurrentNonleaf initialProgram fun value =>
    .honestRead (Sum.inr (finalKey value)) fun digest =>
      compileCurrentNonleaf (continuation value digest) next

def currentTwoReadResult
    {bound : Nat} {Prefix Final : Type}
    (initialProgram : NonleafProgram (Rp05OtherRawInput bound) Prefix)
    (finalKey : Prefix → Rp05OtherRawInput bound)
    (continuation :
      Prefix → DigestRegister → NonleafProgram (Rp05OtherRawInput bound) Final)
    (oracle : Rp05FullRawInput bound → DigestRegister) : Final :=
  let other := fun input => oracle (Sum.inr input)
  let value := NonleafProgram.interpret other initialProgram
  let digest := other (finalKey value)
  NonleafProgram.interpret other (continuation value digest)

theorem compile_current_two_read_fixed_oracle
    {bound : Nat} {Prefix Final Work : Type} [Fintype Work]
    (randomized : Bool)
    (initialProgram : NonleafProgram (Rp05OtherRawInput bound) Prefix)
    (finalKey : Prefix → Rp05OtherRawInput bound)
    (continuation :
      Prefix → DigestRegister → NonleafProgram (Rp05OtherRawInput bound) Final)
    (next : Final → Program (Rp05FullRawInput bound) Work)
    (oracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    run randomized (compileCurrentTwoRead initialProgram finalKey continuation next)
        oracle state =
      run randomized (next (currentTwoReadResult initialProgram finalKey continuation oracle))
        oracle state := by
  unfold compileCurrentTwoRead currentTwoReadResult
  rw [compile_current_nonleaf_execution]
  simp only [run]
  rw [compile_current_nonleaf_execution]

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
