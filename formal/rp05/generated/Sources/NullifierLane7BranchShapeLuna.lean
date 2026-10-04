import NullifierLane7GenericEquationLuna

/-! Symbolic-input branch shape for the initial block-zero lane-seven row. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

/-- Under block zero and lane seven, the source row is one hash head followed
by the opaque 32-term position tail. The input Fin remains arbitrary. -/
theorem initial_terms_block0_lane7_shape
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (input block : Fin 2) (lane : Fin 16)
    (blockZero : block.val = 0) (laneSeven : lane.val = 7) :
    initialTerms oneNode negativeNode positiveNode powerNode
        (input, block, lane) =
      [(hashInitialIndex (callOf (input, block, lane)) lane.val, oneNode)] ++
        positionTerms input powerNode := by
  have blockEq : block = (0 : Fin 2) := Fin.ext blockZero
  have laneEq : lane = (7 : Fin 16) := Fin.ext laneSeven
  subst block
  subst lane
  change [(hashInitialIndex (callOf (input, (0 : Fin 2), (7 : Fin 16))) 7,
      oneNode)] ++ positionTerms input powerNode =
    [(hashInitialIndex (callOf (input, (0 : Fin 2), (7 : Fin 16))) 7,
      oneNode)] ++ positionTerms input powerNode
  rfl

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
