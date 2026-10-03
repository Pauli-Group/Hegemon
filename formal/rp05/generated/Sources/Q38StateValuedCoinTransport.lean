import Q38CompleteAlgebraR2

/-! State-valued finite coin transports. Values may be density matrices or
unnormalized instrument outputs; these identities do not fix a random-oracle
table, discard a register, or equate only scalar output marginals.

Source-only until the user's compilation condition is satisfied. -/
namespace HegemonCrypto.SmallWood.V8SmzaStateValuedCoinTransport
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

variable {Coins View Rest Early Later Tag Value : Type*}
variable [Fintype Coins] [Fintype View] [Fintype Rest]
variable [Fintype Early] [Fintype Later] [Fintype Tag]
variable [AddCommMonoid Value]

/-- A bijective fresh-coin change of variables preserves any state-valued
continuation. Equal finite cardinalities also preserve uniform normalization. -/
theorem bijective_state_kernel_sum (e : Coins ≃ View) (kernel : View → Value) :
    (∑ coin, kernel (e coin)) = ∑ view, kernel view := by
  exact e.sum_comp kernel

/-- Keep the unexposed coins as an explicit coordinate. An offset may depend
on them; the resulting public block is still jointly uniform with them. -/
theorem public_block_retains_remaining_coins
    (e : Rest → Coins ≃ View) (kernel : Rest → View → Value) :
    (∑ rest, ∑ coin, kernel rest (e rest coin)) =
      ∑ view, ∑ rest, kernel rest view := by
  calc
    _ = ∑ rest, ∑ view, kernel rest view := by
      apply Finset.sum_congr rfl
      intro rest _
      exact (e rest).sum_comp (kernel rest)
    _ = _ := Finset.sum_comm

/-- The next public challenge can be the outcome of an arbitrary quantum
instrument on the earlier public block. The kernel retains that outcome's
unnormalized state. Each successful challenge uses its own coin equivalence,
but every equivalence preserves the SAME earlier block.

Instrument probabilities and all later operations live inside `kernel`;
there is no assumption that the challenge is independent of the earlier block. -/
theorem adaptive_challenge_state_kernel_sum
    (e : Tag → Coins ≃ (Early × Later)) (earlier : Coins → Early)
    (preserve : ∀ tag coin, (e tag coin).1 = earlier coin)
    (kernel : Early → Tag → Later → Value) :
    (∑ coin, ∑ tag, kernel (earlier coin) tag (e tag coin).2) =
      ∑ early, ∑ tag, ∑ later, kernel early tag later := by
  calc
    _ = ∑ tag, ∑ coin, kernel (earlier coin) tag (e tag coin).2 :=
      Finset.sum_comm
    _ = ∑ tag, ∑ view : Early × Later, kernel view.1 tag view.2 := by
      apply Finset.sum_congr rfl
      intro tag _
      simp_rw [← preserve tag]
      exact (e tag).sum_comp (fun view => kernel view.1 tag view.2)
    _ = ∑ tag, ∑ early, ∑ later, kernel early tag later := by
      simp only [Fintype.sum_prod_type]
    _ = _ := Finset.sum_comm

end
end HegemonCrypto.SmallWood.V8SmzaStateValuedCoinTransport
