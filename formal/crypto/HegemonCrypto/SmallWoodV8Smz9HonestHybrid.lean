import HegemonCrypto.SmallWoodV8Smz9SingleProofPrivacy
import Mathlib.Analysis.Complex.Basic

/-!
# An honest-side randomized-leaf / DECS-mask change of variables

This file defines an ideal experiment, not a security receipt for real SHA-512. Its input coins
are the proved ideal rejection-sampler outputs. LVCS tails and full DECS masks are sampled before
independent leaf digests, matching the randomized-leaf hybrid's chronological allocation.

An explicit translation of all 5*388 DECS mask coefficients gives an equal experiment in which
the full DECS response is sampled before the 140*20 LVCS tails. The equality preserves arbitrary
observations, including the old mask and the final witness-dependent leaf overlay. Projecting
away those correlated values then derives a fresh-tail law jointly with root material, DECS
responses, and any public computation from that material. No fixed-context independence is a
premise. The separate oracle lemma preserves every adaptive non-leaf query and the final overlay
when leaf-only programming is delayed across an atomic honest invocation.

Missing: the QROM transition from honest hashes to independently randomized leaf digests, exact
Rust/byte refinement, external-query interleaving, and removal of the correlated leaf overlay.
No whole-proof privacy, repeated security, concrete primitive security or authority follows.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HonestHybrid

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9JointAlgebraicLaw V8Smz9SingleProofPrivacy
open scoped BigOperators ENNReal

noncomputable section

abbrev DecsFullCoefficients (F : Type*) :=
  Fin decsEta → Fin decsPolynomialCoefficientCount → F

abbrev DecsGamma (F : Type*) := Fin decsEta → Fin lvcsRowCount → F

/-- Runtime mat_mul followed by interpolation of the complete 388 consecutive values. -/
def exactDecsUnmaskedCoefficients {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) : DecsFullCoefficients F :=
  fun combination coefficient =>
    (∑ source : Fin decsPolynomialCoefficientCount,
      Polynomial.C (∑ row : Fin lvcsRowCount,
        gamma combination row * lvcsRotatedRow heads tails row source) *
      Lagrange.basis (Finset.univ : Finset (Fin decsPolynomialCoefficientCount))
        (fun node => (node.val : F)) source).coeff coefficient.val

def exactDecsResponse {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) (mask : DecsFullCoefficients F) :
    DecsFullCoefficients F := exactDecsUnmaskedCoefficients gamma heads tails + mask

def exactDecsMaskTranslation {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) : DecsFullCoefficients F ≃ DecsFullCoefficients F :=
  affineOutputEquiv (AddEquiv.refl _) (exactDecsUnmaskedCoefficients gamma heads tails)

theorem exact_decs_mask_translation_apply {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) (mask : DecsFullCoefficients F) :
    exactDecsMaskTranslation gamma heads tails mask =
      exactDecsResponse gamma heads tails mask := rfl

theorem exact_decs_mask_translation_inverse {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) (response : DecsFullCoefficients F) :
    (exactDecsMaskTranslation gamma heads tails).symm response =
      response - exactDecsUnmaskedCoefficients gamma heads tails := rfl

/-- An explicit new mask preserves all response coefficients when the LVCS tails change. -/
theorem changed_lvcs_tails_preserve_full_decs_response {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F)
    (oldTails newTails : LvcsRandomTailCoins F) (oldMask : DecsFullCoefficients F) :
    exactDecsResponse gamma heads newTails
        (oldMask + exactDecsUnmaskedCoefficients gamma heads oldTails -
          exactDecsUnmaskedCoefficients gamma heads newTails) =
      exactDecsResponse gamma heads oldTails oldMask := by
  unfold exactDecsResponse
  abel

def acceptedDecsMaskAllocation : RuntimeFieldCoins 1940 ≃ DecsFullCoefficients Goldilocks :=
  (Equiv.piCongrRight fun _ : Fin 1940 => idealFieldCoinEquivGoldilocks).trans
    (matrixEquiv decsEta decsPolynomialCoefficientCount Goldilocks)

def idealTailLaw : PMF (LvcsRandomTailCoins Goldilocks) :=
  pmfMap (iidUniformRejectionSamplerOutputPMF 2800) acceptedLvcsTailAllocation

def idealDecsMaskLaw : PMF (DecsFullCoefficients Goldilocks) :=
  pmfMap (iidUniformRejectionSamplerOutputPMF 1940) acceptedDecsMaskAllocation

theorem ideal_tail_law_is_uniform :
    idealTailLaw = uniformFintypePMF (LvcsRandomTailCoins Goldilocks) :=
  ideal_accepted_lvcs_tails_are_jointly_uniform

theorem ideal_decs_mask_law_is_uniform :
    idealDecsMaskLaw = uniformFintypePMF (DecsFullCoefficients Goldilocks) := by
  unfold idealDecsMaskLaw
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv acceptedDecsMaskAllocation

/-- Uniform-mask transport retains both the old mask and its translated response. -/
theorem uniform_translation_preserves_arbitrary_observation
    {Coins Result : Type*} [Fintype Coins] [Nonempty Coins]
    (translation : Coins ≃ Coins) (observe : Coins → Coins → PMF Result) :
    ((uniformFintypePMF Coins).bind fun coins => observe coins (translation coins)) =
      (uniformFintypePMF Coins).bind (fun output => observe (translation.symm output) output) := by
  calc
    _ = (pmfMap (uniformFintypePMF Coins) translation).bind
        (fun output => observe (translation.symm output) output) := by
      simp [pmfMap, PMF.bind_bind, Function.comp_def]
    _ = _ := by rw [uniform_pmf_map_equiv translation]

/-- One independent 512-bit digest for each of the actual 2^23 leaf positions. -/
abbrev Smz9LeafDigests := Fin (2 ^ 23) → Fin (2 ^ 512)

def idealRandomizedLeafLaw : PMF Smz9LeafDigests := uniformFintypePMF Smz9LeafDigests

/--
Chronological H1: earlier state; fresh LVCS tails; fresh DECS masks; independent leaf outputs;
root-derived gamma; full masked response. `observe` may retain the complete final oracle table.
`Base` includes earlier witness/PIOP/PCS-head coins and the pre-invocation oracle, NOT new tails.
-/
def randomizedLeafHonestExperiment {Base Leaves Result : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → LvcsCommittedHeads Goldilocks)
    (gamma : Base → Leaves → DecsGamma Goldilocks)
    (observe : Base → Leaves → LvcsRandomTailCoins Goldilocks →
      DecsFullCoefficients Goldilocks → DecsFullCoefficients Goldilocks → Result) : PMF Result :=
  baseLaw.bind fun base =>
    idealTailLaw.bind fun tails =>
      idealDecsMaskLaw.bind fun mask =>
        leafLaw.bind fun leaves => PMF.pure
          (observe base leaves tails mask (exactDecsResponse (gamma base leaves) (heads base) tails mask))

/--
The same complete law, but root material and a fresh response are sampled before the tail phase.
The old mask is reconstructed, not omitted. This is a change of variables, not commitment hiding.
-/
theorem randomized_leaf_honest_joint_reparameterization
    {Base Leaves Result : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → LvcsCommittedHeads Goldilocks)
    (gamma : Base → Leaves → DecsGamma Goldilocks)
    (observe : Base → Leaves → LvcsRandomTailCoins Goldilocks →
      DecsFullCoefficients Goldilocks → DecsFullCoefficients Goldilocks → Result) :
    randomizedLeafHonestExperiment baseLaw leafLaw heads gamma observe =
      baseLaw.bind (fun base => leafLaw.bind fun leaves =>
        (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun response =>
          (uniformFintypePMF (LvcsRandomTailCoins Goldilocks)).bind fun tails =>
            PMF.pure (observe base leaves tails
              (response - exactDecsUnmaskedCoefficients (gamma base leaves) (heads base) tails)
              response)) := by
  unfold randomizedLeafHonestExperiment
  rw [ideal_tail_law_is_uniform, ideal_decs_mask_law_is_uniform]
  apply congrArg (PMF.bind baseLaw)
  funext base
  have reorder :
      ((uniformFintypePMF (LvcsRandomTailCoins Goldilocks)).bind fun tails =>
        (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun mask =>
          leafLaw.bind fun leaves => PMF.pure
            (observe base leaves tails mask
              (exactDecsResponse (gamma base leaves) (heads base) tails mask))) =
      leafLaw.bind (fun leaves =>
        (uniformFintypePMF (LvcsRandomTailCoins Goldilocks)).bind fun tails =>
          (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun mask => PMF.pure
            (observe base leaves tails mask
              (exactDecsResponse (gamma base leaves) (heads base) tails mask))) := by
    simp_rw [PMF.bind_comm (uniformFintypePMF (DecsFullCoefficients Goldilocks)) leafLaw]
    exact PMF.bind_comm _ _ _
  rw [reorder]
  apply congrArg (PMF.bind leafLaw)
  funext leaves
  calc
    _ = (uniformFintypePMF (LvcsRandomTailCoins Goldilocks)).bind (fun tails =>
        (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun response =>
          PMF.pure (observe base leaves tails
            (response - exactDecsUnmaskedCoefficients (gamma base leaves) (heads base) tails)
            response)) := by
      apply congrArg (PMF.bind (uniformFintypePMF (LvcsRandomTailCoins Goldilocks)))
      funext tails
      exact uniform_translation_preserves_arbitrary_observation
        (exactDecsMaskTranslation (gamma base leaves) (heads base) tails)
        (fun mask response => PMF.pure (observe base leaves tails mask response))
    _ = _ := PMF.bind_comm _ _ _

/--
The public prefix is GENERATED in the experiment. Root traces, the PCS transcript, hash_fpp,
and h_piop may all be computed by `publicView` from retained base, random leaves, and full response.
The result proves their joint fresh-tail factorization rather than taking it as a premise.
-/
theorem randomized_leaf_public_prefix_has_fresh_lvcs_tails
    {Base Leaves Public : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → LvcsCommittedHeads Goldilocks)
    (gamma : Base → Leaves → DecsGamma Goldilocks)
    (publicView : Base → Leaves → DecsFullCoefficients Goldilocks → Public) :
    randomizedLeafHonestExperiment baseLaw leafLaw heads gamma
        (fun base leaves tails _ response => (base, leaves, response, publicView base leaves response, tails)) =
      baseLaw.bind (fun base => leafLaw.bind fun leaves =>
        (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun response =>
          pmfMap (uniformFintypePMF (LvcsRandomTailCoins Goldilocks))
            (fun tails => (base, leaves, response, publicView base leaves response, tails))) := by
  exact randomized_leaf_honest_joint_reparameterization baseLaw leafLaw heads gamma _

/-- The first challenge stage may fail; successful stages supply the exact local LVCS interface. -/
structure GeneratedLvcsStage where
  points : Fin piopOpeningCount → Goldilocks
  fallback : LvcsAdmissibleTargets points
  chooseTargets : LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)

def honestLvcsStageOutput
    (heads : LvcsCommittedHeads Goldilocks) (stage : Option GeneratedLvcsStage)
    (tails : LvcsRandomTailCoins Goldilocks) :
    Option (LvcsEarlierTails Goldilocks × Option (LvcsLaterSubset Goldilocks)) :=
  stage.map fun selected =>
    exactLvcsPartialFeedbackOutput selected.points heads selected.chooseTargets tails

def uniformLvcsStageOutput (stage : Option GeneratedLvcsStage)
    (view : LvcsEarlierTails Goldilocks × LvcsLaterSubset Goldilocks) :
    Option (LvcsEarlierTails Goldilocks × Option (LvcsLaterSubset Goldilocks)) :=
  stage.map fun selected =>
    (view.1, (selected.chooseTargets view.1).map fun _ => view.2)

theorem generated_lvcs_stage_preserves_both_abort_levels
    (heads : LvcsCommittedHeads Goldilocks) (stage : Option GeneratedLvcsStage) :
    pmfMap (uniformFintypePMF (LvcsRandomTailCoins Goldilocks))
        (honestLvcsStageOutput heads stage) =
      pmfMap (uniformFintypePMF (LvcsEarlierTails Goldilocks × LvcsLaterSubset Goldilocks))
        (uniformLvcsStageOutput stage) := by
  cases stage with
  | none => simp [honestLvcsStageOutput, uniformLvcsStageOutput, pmfMap, Function.comp_def]
  | some selected =>
    have localLaw := exact_lvcs_partial_feedback_joint_law selected.points heads
      selected.fallback selected.chooseTargets
    have pushed := congrArg (fun law => pmfMap law some) localLaw
    simp only [pmfMap_comp] at pushed
    exact pushed

/--
Compose the derived honest-side fresh-prefix law with the actual local LVCS triangular law.
The stage is computed AFTER the random leaves and DECS response; its points are not externally
fixed in the experiment. Earlier-stage failure and DECS-selector failure both remain observable.
The final leaf oracle overlay is intentionally not projected into this independence conclusion.
-/
theorem randomized_leaf_then_lvcs_joint_law
    {Base Leaves : Type*}
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (heads : Base → LvcsCommittedHeads Goldilocks)
    (gamma : Base → Leaves → DecsGamma Goldilocks)
    (makeStage : Base → Leaves → DecsFullCoefficients Goldilocks → Option GeneratedLvcsStage) :
    randomizedLeafHonestExperiment baseLaw leafLaw heads gamma
      (fun base leaves tails _ response =>
        (base, leaves, response,
          honestLvcsStageOutput (heads base) (makeStage base leaves response) tails)) =
      baseLaw.bind (fun base => leafLaw.bind fun leaves =>
        (uniformFintypePMF (DecsFullCoefficients Goldilocks)).bind fun response =>
          pmfMap (uniformFintypePMF (LvcsEarlierTails Goldilocks × LvcsLaterSubset Goldilocks))
            (fun view => (base, leaves, response,
              uniformLvcsStageOutput (makeStage base leaves response) view))) := by
  rw [randomized_leaf_honest_joint_reparameterization]
  apply congrArg (PMF.bind baseLaw)
  funext base
  apply congrArg (PMF.bind leafLaw)
  funext leaves
  apply congrArg (PMF.bind (uniformFintypePMF (DecsFullCoefficients Goldilocks)))
  funext response
  have localLaw := generated_lvcs_stage_preserves_both_abort_levels
    (heads base) (makeStage base leaves response)
  have pushed := congrArg
    (fun law => pmfMap law (fun output => (base, leaves, response, output))) localLaw
  simp only [pmfMap_comp] at pushed
  exact pushed

/-! ## Exact delayed-leaf-overlay execution equality -/

inductive HashRole where
  | leaf | internalNode | rootBinding | decsGamma | piopInput | piopGamma
  | piopFinal | piopOpenings | decsOpeningInput | decsIndexSampler
  deriving DecidableEq, Fintype

/-- Literal active SMZ9 tags, without the unrelated receipt-key presence marker. -/
def hashRoleTag : HashRole → String
  | .leaf => "hegemon.smallwood.strict-zk.merkle-leaf.v1"
  | .internalNode => "hegemon.smallwood.level5.merkle-node"
  | .rootBinding => "hegemon.smallwood.level5.merkle-root"
  | .decsGamma => "hegemon.smallwood.level5.decs-coefficient"
  | .piopInput => "hegemon.smallwood.level5.piop-input"
  | .piopGamma => "hegemon.smallwood.level5.piop-coefficient"
  | .piopFinal => "hegemon.smallwood.level5.piop-transcript"
  | .piopOpenings => "hegemon.smallwood.level5.piop-opening"
  | .decsOpeningInput => "hegemon.smallwood.level5.decs-opening"
  | .decsIndexSampler => "hegemon.smallwood.level5.decs-fixed-sampling"

def smz9ProfileTag : String := "hegemon.smallwood.poseidon2-v8.smz9.sha512.profile.v1"

def littleEndian64Bytes (value : Nat) : List UInt8 :=
  List.ofFn fun index : Fin 8 => UInt8.ofNat (value / 256 ^ index.val)

/-- The exact common profile/role prefix; word framing and counter may be any trailing bytes. -/
def smz9FramedRoleInput (role : HashRole) (remaining : List UInt8) : List UInt8 :=
  littleEndian64Bytes smz9ProfileTag.toUTF8.size ++ smz9ProfileTag.toUTF8.data.toList ++
    littleEndian64Bytes (hashRoleTag role).toUTF8.size ++
      (hashRoleTag role).toUTF8.data.toList ++ remaining

theorem smz9_role_length_byte (role : HashRole) (remaining : List UInt8) :
    (smz9FramedRoleInput role remaining)[61]? =
      some (UInt8.ofNat (hashRoleTag role).toUTF8.size) := by
  cases role <;> rfl

/-- Actual framed SMZ9 leaf inputs cannot alias any listed later honest-query role. -/
theorem smz9_nonleaf_bytes_cannot_alias_leaf
    (role : HashRole) (notLeaf : role ≠ .leaf)
    (nonLeafRemaining leafRemaining : List UInt8) :
    smz9FramedRoleInput role nonLeafRemaining ≠ smz9FramedRoleInput .leaf leafRemaining := by
  intro sameBytes
  have sameRoleLength := congrArg (fun bytes : List UInt8 => bytes[61]?) sameBytes
  rw [smz9_role_length_byte, smz9_role_length_byte] at sameRoleLength
  cases role <;> simp_all [hashRoleTag]
  all_goals exact absurd sameRoleLength (by decide)

def applyLeafOverlay {Payload Output : Type*}
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output) :
    HashRole × Payload → Output :=
  fun input => if input.1 = .leaf then (overlay input.2).getD (oracle input) else oracle input

theorem leaf_overlay_preserves_other_roles {Payload Output : Type*}
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output)
    (input : HashRole × Payload) (notLeaf : input.1 ≠ .leaf) :
    applyLeafOverlay oracle overlay input = oracle input := by
  simp [applyLeafOverlay, notLeaf]

/-- Finite adaptive honest continuation. Every internal request carries its actual role. -/
inductive NonLeafProgram (Payload Output Result : Type*) where
  | done (result : Result)
  | query (input : HashRole × Payload) (notLeaf : input.1 ≠ .leaf)
      (next : Output → NonLeafProgram Payload Output Result)

def runNonLeafProgram {Payload Output Result : Type*}
    (oracle : HashRole × Payload → Output) :
    NonLeafProgram Payload Output Result → Result × List ((HashRole × Payload) × Output)
  | .done result => (result, [])
  | .query input _ next =>
      let answer := oracle input
      let remaining := runNonLeafProgram oracle (next answer)
      (remaining.1, (input, answer) :: remaining.2)

theorem delayed_leaf_overlay_preserves_all_internal_queries
    {Payload Output Result : Type*}
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output)
    (program : NonLeafProgram Payload Output Result) :
    runNonLeafProgram (applyLeafOverlay oracle overlay) program = runNonLeafProgram oracle program := by
  induction program with
  | done result => rfl
  | query input notLeaf next inductionHypothesis =>
    simp only [runNonLeafProgram, leaf_overlay_preserves_other_roles oracle overlay input notLeaf,
      inductionHypothesis]

/-- Both schedules expose the same final oracle, not merely the same classical return value. -/
theorem delayed_leaf_overlay_preserves_final_table_and_trace
    {Payload Output Result : Type*}
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output)
    (program : NonLeafProgram Payload Output Result) :
    (runNonLeafProgram (applyLeafOverlay oracle overlay) program, applyLeafOverlay oracle overlay) =
      (runNonLeafProgram oracle program, applyLeafOverlay oracle overlay) := by
  rw [delayed_leaf_overlay_preserves_all_internal_queries]

/-! ## Coherent oracle action on the non-leaf query subspace

For a fixed classical oracle table, addition into the response register is a basis permutation.
Over a 512-bit vector of ZMod 2 values this is exactly the usual XOR query. Its complex-linear
extension below is invertible and preserves squared Hilbert norm. Equality under leaf overlays
holds on the non-leaf input subspace, not on arbitrary external queries including leaf inputs.
-/

abbrev NonLeafInput (Payload : Type*) :=
  { input : HashRole × Payload // input.1 ≠ .leaf }

abbrev QueryBasis (Payload Output Workspace : Type*) :=
  NonLeafInput Payload × Output × Workspace

def nonLeafQueryBasisEquiv {Payload Output Workspace : Type*} [AddGroup Output]
    (oracle : HashRole × Payload → Output) :
    QueryBasis Payload Output Workspace ≃ QueryBasis Payload Output Workspace where
  toFun basis := (basis.1, basis.2.1 + oracle basis.1.val, basis.2.2)
  invFun basis := (basis.1, basis.2.1 - oracle basis.1.val, basis.2.2)
  left_inv basis := by rcases basis with ⟨input, answer, workspace⟩; simp
  right_inv basis := by rcases basis with ⟨input, answer, workspace⟩; simp

def nonLeafQueryLinearEquiv {Payload Output Workspace : Type*} [AddGroup Output]
    (oracle : HashRole × Payload → Output) :
    (QueryBasis Payload Output Workspace → ℂ) ≃ₗ[ℂ]
      (QueryBasis Payload Output Workspace → ℂ) where
  toFun state := state ∘ (nonLeafQueryBasisEquiv oracle).symm
  invFun state := state ∘ nonLeafQueryBasisEquiv oracle
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem nonleaf_query_preserves_squared_hilbert_norm
    {Payload Output Workspace : Type*} [Fintype Payload] [Fintype Output] [Fintype Workspace]
    [AddGroup Output] (oracle : HashRole × Payload → Output)
    (state : QueryBasis Payload Output Workspace → ℂ) :
    (∑ basis, Complex.normSq (nonLeafQueryLinearEquiv oracle state basis)) =
      ∑ basis, Complex.normSq (state basis) := by
  exact (nonLeafQueryBasisEquiv oracle).symm.sum_comp (fun basis => Complex.normSq (state basis))

theorem leaf_overlay_preserves_coherent_nonleaf_query
    {Payload Output Workspace : Type*} [AddGroup Output]
    (oracle : HashRole × Payload → Output) (overlay : Payload → Option Output)
    (state : QueryBasis Payload Output Workspace → ℂ) :
    nonLeafQueryLinearEquiv (applyLeafOverlay oracle overlay) state =
      nonLeafQueryLinearEquiv oracle state := by
  funext basis
  change state (basis.1, basis.2.1 - applyLeafOverlay oracle overlay basis.1.val, basis.2.2) = _
  rw [leaf_overlay_preserves_other_roles oracle overlay basis.1.val basis.1.property]
  rfl

end

end HegemonCrypto.SmallWood.V8Smz9HonestHybrid
