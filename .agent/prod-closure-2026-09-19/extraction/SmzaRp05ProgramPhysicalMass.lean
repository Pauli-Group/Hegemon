import SmzaRp05AdaptivePhysicalReadBound

/-!
# Exhaustive Born mass of an adaptive executable read program

`physicalBranchesFintype` already recursively enumerates the dependent branch
tree of a source `Program`. This theorem uses that enumeration and the
standard-totality invariant to show that the unnormalised branch weights of
the complete adaptive physical interpreter sum to the incoming norm. The
program may choose each next raw query as a function of the prior decoded
answer; no branch is normalized or discarded.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ProgramPhysicalMass

open scoped BigOperators Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05PhysicalTerminalRead
open SmzaRp05VectorReadCharge (Answer VectorCmsState)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

variable {Key Counter Work Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

/-- Every answer-dependent physical branch is included, with its original
unnormalised Born weight. Under standard totality, the exhaustive sum is
exactly the incoming norm. -/
theorem adaptive_program_branch_mass_eq_initial
    (encode : RawInput → Key)
    (decode : RawInput → Answer (Counter := Counter) → RawDigest)
    (program : Program Result)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (total : StandardTotal state) :
    letI := physicalBranchesFintype decode program
    (∑ branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program,
      normSquared (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
        encode decode program branch state)) = normSquared state := by
  induction program generalizing state with
  | done result =>
      letI := physicalBranchesFintype decode (Program.done result)
      simp [SmzaRp05PhysicalAcceptedReplayLite.Branches,
        SmzaRp05PhysicalAcceptedReplayLite.physicalRun]
  | read raw next ih =>
      letI (answer : Answer (Counter := Counter)) :
          Fintype (SmzaRp05PhysicalAcceptedReplayLite.Branches decode
            (next (decode raw answer))) :=
        physicalBranchesFintype decode (next (decode raw answer))
      letI := physicalBranchesFintype decode (Program.read raw next)
      change
        (∑ branch : (answer : Answer (Counter := Counter)) ×
            SmzaRp05PhysicalAcceptedReplayLite.Branches decode
              (next (decode raw answer)),
          normSquared (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
            encode decode (Program.read raw next) branch state)) =
          normSquared state
      rw [Fintype.sum_sigma]
      calc
        (∑ answer : Answer (Counter := Counter),
            ∑ branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode
                (next (decode raw answer)),
              normSquared (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
                encode decode (next (decode raw answer)) branch
                  (SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep
                    (encode raw) answer state))) =
            ∑ answer : Answer (Counter := Counter),
              normSquared (physicalReadBranch (encode raw) answer state) := by
          apply Finset.sum_congr rfl
          intro answer _
          have branchTotal : StandardTotal
              (SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep
                (encode raw) answer state) := by
            simpa only [SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep,
              physicalReadBranch] using
              (physical_read_branch_standard_total (encode raw) answer state total)
          simpa only [SmzaRp05PhysicalAcceptedReplayLite.physicalRun,
            SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep,
            physicalReadBranch] using
            ih (decode raw answer)
              (SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep
                (encode raw) answer state) branchTotal
        _ = normSquared state :=
          sum_physical_read_branch_norm_squared (encode raw) state total

end
end HegemonCrypto.SmallWood.SmzaRp05ProgramPhysicalMass
