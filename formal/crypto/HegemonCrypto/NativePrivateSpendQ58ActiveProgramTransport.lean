import HegemonCrypto.NativePrivateSpendQ58ActiveEventProjection

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58ActiveProgramTransport

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open NativePrivateSpendQ58ActiveEventProjection

noncomputable section
set_option autoImplicit false
variable {Key Counter Work Result : Type}

private theorem restrict_zero (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live) :
    restrictFiber (Work := Work) live dummy fixed (0 : FullState (Key := Key) (Counter := Counter) (Work := Work)) = 0 := by
  funext basis
  unfold restrictFiber
  split <;> rfl

/-- The fixed read is the same physical read and same fiber; its original
answer is checked, rather than supplied as a response equality premise. -/
theorem conditioned_fixed_read_to_sparse_check
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (key : Key) (inactive : ¬live key) (answer : VectorOutput Counter)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed
        (NativePrivateSpendQ58PartitionTransport.conditioned live fixed
          (physicalReadBranch key answer state)) =
      if fixed ⟨key, inactive⟩ = answer then
        restrictFiber live dummy fixed
          (NativePrivateSpendQ58PartitionTransport.conditioned live fixed state)
      else 0 := by
  rw [NativePrivateSpendQ58PartitionTransport.physical_read_to_same_fiber,
    dif_neg inactive]
  by_cases same : fixed ⟨key, inactive⟩ = answer
  · simp only [if_pos same]
  · simp only [if_neg same, restrict_zero]

/-- One sparse branch step. Original raw calls, answers and continuation are
unchanged; only live calls touch the active database. Fixed mismatches abort
with zero amplitude while still using the same answer-dependent Program. -/
def sparseRun [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter] [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter →
      V8SmzaOracleParser.RawDigest) :
    (program : Program Result) → Branches decode program →
      SparseState (Counter := Counter) (Work := Work) live →
      SparseState (Counter := Counter) (Work := Work) live
  | .done _, _, state => state
  | .read raw next, ⟨answer, branch⟩, state =>
      sparseRun live fixed encode decode (next (decode raw answer)) branch
        (if active : live (encode raw) then
          physicalReadBranch (⟨encode raw, active⟩ : ActiveKey live) answer state
        else if fixed ⟨encode raw, active⟩ = answer then state else 0)

theorem restrict_mixed_run
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter →
      V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed
        (NativePrivateSpendQ58PartitionTransport.mixedRun live fixed
          encode decode program branch state) =
      sparseRun live fixed encode decode program branch
        (restrictFiber live dummy fixed state) := by
  induction program generalizing state with
  | done result => rfl
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      simp only [NativePrivateSpendQ58PartitionTransport.mixedRun, sparseRun]
      rw [ih]
      by_cases active : live (encode raw)
      · rw [dif_pos active, dif_pos active]
        rw [restrict_physical_read_active live dummy fixed ⟨encode raw, active⟩]
      · rw [dif_neg active, dif_neg active]
        by_cases same : fixed ⟨encode raw, active⟩ = answer
        · rw [if_pos same, if_pos same]
        · rw [if_neg same, if_neg same, restrict_zero]

/-- Literal full-run transport of the original physical answer branch. No
acceptance, table-response agreement or causal-prior membership is assumed. -/
theorem physical_run_to_sparse_same_fiber
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter →
      V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed
        (NativePrivateSpendQ58PartitionTransport.conditioned live fixed
          (physicalRun encode decode program branch state)) =
      sparseRun live fixed encode decode program branch
        (restrictFiber live dummy fixed
          (NativePrivateSpendQ58PartitionTransport.conditioned live fixed state)) := by
  rw [NativePrivateSpendQ58PartitionTransport.physical_run_to_mixed_same_fiber]
  exact restrict_mixed_run live dummy fixed encode decode program branch _

/-- Fixed-fiber event mass follows the same full Program and original branch,
including failed prefixes. The event itself is not declared an accepted-invalid
failure certificate by this transport lemma. -/
theorem physical_run_same_fiber_event_mass
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter →
      V8SmzaOracleParser.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (event : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work) →
      Database (ActiveKey live) (VectorOutput Counter) → Prop)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (sparseEventProject live event
      (sparseRun live fixed encode decode program branch
        (restrictFiber live dummy fixed
          (NativePrivateSpendQ58PartitionTransport.conditioned live fixed state)))) =
      normSquared (NativePrivateSpendQ58PartitionTransport.projectFiber live fixed
        (fullEventProject live event
          (NativePrivateSpendQ58PartitionTransport.conditioned live fixed
            (physicalRun encode decode program branch state)))) := by
  rw [← physical_run_to_sparse_same_fiber live dummy fixed encode decode program branch state]
  exact same_fiber_event_mass live dummy fixed event _

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58ActiveProgramTransport
