import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout

/-!
# Retained-prefix challenge feedback through triangular bijections

Fixed-challenge bijectivity alone does not survive choosing a challenge from the same coins.
There is, however, a useful stronger condition: every fixed-challenge bijection retains exactly
the same first output. A challenge computed only from that retained output can be fed back into
the second part without changing the joint uniform law. The inverse below derives this fact;
no honest/simulated equality or complete-view distance is a hypothesis.

This module proves the general algebraic step. Its source-specific use additionally requires
showing that the actual earlier SMZ9 output is independent of the later challenge in the exact
maps, and that no earlier observation outside that output depends on unrevealed coins. It does
not by itself provide commitment hiding, quantum reprogramming, or whole-proof privacy.
-/

namespace HegemonCrypto.SmallWood.V8Smz9TriangularAlgebraicLaw

open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout

noncomputable section

variable {Coins Prefix Tail Challenge : Type*}

/-- A later challenge can depend on the earlier output, provided that output is retained by
every member of the fixed-challenge family. -/
def triangularChallengeEquiv
    (maps : Challenge → Coins ≃ (Prefix × Tail))
    (earlyOutput : Coins → Prefix)
    (firstIndependent : ∀ challenge coins, (maps challenge coins).1 = earlyOutput coins)
    (choose : Prefix → Challenge) : Coins ≃ (Prefix × Tail) where
  toFun coins := maps (choose (earlyOutput coins)) coins
  invFun output := (maps (choose output.1)).symm output
  left_inv coins := by
    dsimp
    rw [firstIndependent]
    exact (maps (choose (earlyOutput coins))).symm_apply_apply coins
  right_inv output := by
    have retained : earlyOutput ((maps (choose output.1)).symm output) = output.1 := by
      rw [← firstIndependent (choose output.1)]
      rw [Equiv.apply_symm_apply]
    dsimp
    rw [retained, Equiv.apply_symm_apply]

theorem triangular_challenge_retains_prefix
    (maps : Challenge → Coins ≃ (Prefix × Tail))
    (earlyOutput : Coins → Prefix)
    (firstIndependent : ∀ challenge coins, (maps challenge coins).1 = earlyOutput coins)
    (choose : Prefix → Challenge) (coins : Coins) :
    (triangularChallengeEquiv maps earlyOutput firstIndependent choose coins).1 = earlyOutput coins :=
  firstIndependent (choose (earlyOutput coins)) coins

/-- Complete joint uniformity survives this precise form of same-coin challenge feedback. -/
theorem triangular_challenge_joint_uniform_law
    [Fintype Coins] [Nonempty Coins]
    [Fintype Prefix] [Nonempty Prefix] [Fintype Tail] [Nonempty Tail]
    (maps : Challenge → Coins ≃ (Prefix × Tail))
    (earlyOutput : Coins → Prefix)
    (firstIndependent : ∀ challenge coins, (maps challenge coins).1 = earlyOutput coins)
    (choose : Prefix → Challenge) :
    pmfMap (uniformFintypePMF Coins)
        (fun coins => maps (choose (earlyOutput coins)) coins) =
      uniformFintypePMF (Prefix × Tail) :=
  uniform_pmf_map_equiv (triangularChallengeEquiv maps earlyOutput firstIndependent choose)

/-- An arbitrary earlier history is retained jointly. It can select all maps and the later
challenge rule; the current ideal coins are sampled freshly after that earlier history. -/
theorem history_selected_triangular_joint_law
    {History : Type*}
    [Fintype Coins] [Nonempty Coins]
    [Fintype Prefix] [Nonempty Prefix] [Fintype Tail] [Nonempty Tail]
    (historyLaw : PMF History)
    (maps : History → Challenge → Coins ≃ (Prefix × Tail))
    (earlyOutput : History → Coins → Prefix)
    (firstIndependent : ∀ history challenge coins,
      (maps history challenge coins).1 = earlyOutput history coins)
    (choose : History → Prefix → Challenge) :
    (historyLaw.bind fun history => pmfMap (uniformFintypePMF Coins)
      (fun coins => (history, maps history (choose history (earlyOutput history coins)) coins))) =
    (historyLaw.bind fun history => pmfMap (uniformFintypePMF (Prefix × Tail))
      (fun output => (history, output))) := by
  apply congrArg (PMF.bind historyLaw)
  funext history
  change pmfMap (uniformFintypePMF Coins)
    ((fun output => (history, output)) ∘
      (fun coins => maps history (choose history (earlyOutput history coins)) coins)) = _
  rw [← pmfMap_comp,
    triangular_challenge_joint_uniform_law (maps history) (earlyOutput history)
      (firstIndependent history) (choose history)]

end

end HegemonCrypto.SmallWood.V8Smz9TriangularAlgebraicLaw
