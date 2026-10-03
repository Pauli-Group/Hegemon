namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

/-- Any list action given by these empty/cons equations commutes with a
pointwise commuting transform. -/
theorem listAction_commute {Index State : Type}
    (step : Index → State → State) (run : List Index → State → State)
    (runNil : ∀ state, run [] state = state)
    (runCons : ∀ index remaining state,
      run (index :: remaining) state = run remaining (step index state))
    (transform : State → State)
    (stepCommutes : ∀ index state,
      step index (transform state) = transform (step index state))
    (indices : List Index) (state : State) :
    run indices (transform state) = transform (run indices state) := by
  induction indices generalizing state with
  | nil =>
      rw [runNil, runNil]
  | cons index remaining inductionHypothesis =>
      calc
        run (index :: remaining) (transform state) =
            run remaining (step index (transform state)) := runCons _ _ _
        _ = run remaining (transform (step index state)) := by rw [stepCommutes]
        _ = transform (run remaining (step index state)) := inductionHypothesis _
        _ = transform (run (index :: remaining) state) := by rw [runCons]

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
