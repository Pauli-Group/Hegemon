import HegemonCrypto.NativePrivateSpendQ58CurrentConstructorGrouping
import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate

/-! Current92-counter gamma is derived from one actual whole-vector read
in the same standard physical branch. Fixed-fiber identification is supplied
by the separately checked current RoleClassifier/GammaFiber theorem using
the derived base parser receipt below; no per-counter agreement is assumed.
This is a source proposal, not a new quantum mass or acceptance claim. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGroupedGamma

open HegemonCrypto.CmsCompressedOracle (Basis State)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog physicalRun basisOracle)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Counter RawDigest Key frame zero encode decode keyBytes recorded_current_base_parser
    current_decs_basis_agreement)
end G
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (gammaAt gamma_at_congr_on_current_decs_keys)
end S
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (parseCurrentStageQuery)
end C
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- The actual recorded current DECS vector's finite key parses as the
current root-target counter-zero representative. No parsed-key premise. -/
theorem current_recorded_decs_base_query {Result : Type}
    (program : Program Result) (branch : Branches G.decode program)
    (root : G.RawDigest) (vector : VectorOutput G.Counter)
    (recorded : (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) ∈
      answerLog G.decode program branch) :
    C.parseCurrentStageQuery (G.keyBytes program
      (G.encode program (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero))) =
      some ⟨.decsMatrix, root, 0, 0⟩ :=
  G.recorded_current_base_parser program branch .decsMatrix root
    ⟨0, by decide⟩ G.zero vector recorded

/-- The complete capped scan, including rejection and exhaustion, depends
on the same actual recorded vector's literal92 current coordinates. -/
theorem current_gamma_from_same_branch_vector {Result Work : Type}
    [Fintype Work] [DecidableEq Work]
    (program : Program Result) (branch : Branches G.decode program)
    (state : State (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (basis : Basis (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (nonzero : globalDecompress
      (physicalRun (G.encode program) G.decode program branch state) basis ≠ 0)
    (root : G.RawDigest) (vector : VectorOutput G.Counter)
    (recorded : (G.frame .decsMatrix root ⟨0, by decide⟩ G.zero, vector) ∈
      answerLog G.decode program branch) (fallback : G.RawDigest) :
    S.gammaAt (basisOracle (G.encode program) G.decode basis fallback) root =
      S.gammaAt (fun raw => G.decode raw vector) root := by
  exact S.gamma_at_congr_on_current_decs_keys _ _ root
    (G.current_decs_basis_agreement program branch state basis nonzero root vector recorded fallback)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGroupedGamma
