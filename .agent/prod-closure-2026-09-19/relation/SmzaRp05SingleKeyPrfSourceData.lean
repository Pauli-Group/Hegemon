import SmzaRp05Components

/-! Exact current-RP05 attempt coordinates for the call-0 SingleKey PRF. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components

set_option autoImplicit false

def initialTarget (lane : Fin 16) : Nat :=
  if lane.val = 8 then 538
  else if lane.val = 9 then 539
  else if lane.val = 10 then 540
  else if lane.val = 11 then 1
  else if lane.val = 15 then 541
  else 0

def initialExpected (lane : Fin 16) : Nat :=
  if lane.val = 8 then 0x4853_4b41_5632_0001
  else if lane.val = 9 then 7
  else if lane.val = 10 then 0x5350_4f4e_4745_5631
  else if lane.val = 11 then 1
  else if lane.val = 15 then 0x4845_475f_5032_3136
  else 0

def initialAttempt (lane : Fin 16) : CsrExecutableAttempt :=
  { globalIndex := 15736 + lane.val
    family := 12
    localIndex := lane.val
    emission := 0
    terms :=
      if lane.val < 5 then
        [(18112 + 64 * lane.val, 1), (14528 + lane.val, 160)]
      else
        [(18112 + 64 * lane.val, 1)]
    targetRoot := initialTarget lane }

def legacyAttempt (limb : Fin 7) : CsrExecutableAttempt :=
  { globalIndex := 15752 + limb.val
    family := 13
    localIndex := limb.val
    emission := 0
    terms := [(6784 + limb.val, 1), (28736 + 64 * limb.val, 3)]
    targetRoot := 0 }

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
