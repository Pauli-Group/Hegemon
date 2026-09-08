import HegemonCrypto.SmallWoodV8Smz9PostFinalPhysical
import HegemonCrypto.SmallWoodV8Smz9MeasuredPrefix
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity

/-! The source-bound byte pivot inside one actual measured prior history.
Public reference execution is defined for unnormalized states directly;
normalization is only a mathematical scaling lemma, never postselection. -/

namespace HegemonCrypto.SmallWood.V8Smz9BytePrefix

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9CurrentPublicContext
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9SingleProofPrivacy
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentProgramPiop
open V8Smz9CurrentProgramOpeningBinding V8Smz9ZeroKnowledge V8Smz9HonestHybrid
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9HonestOpeningSchedule V8Smz9SourceIndexSampler V8Smz9AdjacentComposition
open V8Smz9PrivacyGameComposition V8Smz9RuntimeDistribution V8Smz9WholeViewObservation
open V8Smz9PostFinalSerializer V8Smz9PostFinalProgram V8Smz9PostFinalPhysical
open V8Smz9MeasuredSameOracleAdjacent V8Smz9MeasuredTablePublic
open V8Smz9MeasuredCurrentPrivacy V8Smz9MeasuredAdjacentComposition
open V8Smz9RunHomogeneity V8Smz9MeasuredPrefix
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work]

/-- Public data and complete future code only. In particular this object
contains neither an oracle nor an initial state nor a private witness. -/
structure PublicBytePivot (bound : Nat) where
  largeEnough : 37434 ≤ bound
  statement : V8PublicStatement
  publicValues : List Nat
  batching : Fin 5 → Nat → Goldilocks
  gamma : DecsGamma Goldilocks
  response : DecsFullCoefficients Goldilocks
  transcript : PiopCoefficients Goldilocks
  digest : DigestRegister
  pending : Bool
  salt : SaltBytes
  labels : LeafIndex → DigestRegister
  tree : List (List DigestRegister)
  next : ByteFuture (Work := Work) bound

/-- The source statement may be chosen by the actual earlier history. Its
packing certificate supplies validity, not a requested privacy conclusion. -/
structure BytePivotJob (bound queryBound : Nat) extends PublicBytePivot (Work := Work) bound where
  witness : List Nat
  domain : CanonicalPublicPackedDomain statement publicValues witness
  bounded : ∀ bytes, queryCount (next bytes) ≤ queryBound

def rawBytePublicKernel (randomized : Bool) (bound : Nat)
    (job : PublicBytePivot (Work := Work) bound) (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) : ℝ :=
  match sourceComputedOpening bound (by have := job.largeEnough; omega) job.digest job.pending
      (fun input => oracle (Sum.inr input)) with
  | none => run randomized (job.next (.error "smallwood opening nonce trial limit exhausted")) oracle state
  | some opening =>
      uniformAverage fun view : SourceRemainingView Goldilocks =>
        let context := currentIndexedContext (statementParameters job.statement job.batching)
          opening.points (computed_opening_selected_rank opening) job.gamma job.response job.transcript
          (computedIndexChooser bound job.largeEnough (statementParameters job.statement job.batching)
            opening job.transcript job.digest (fun input => oracle (Sum.inr input))) view
        uniformAverage fun tapes : TapeTable =>
          let opened := openedOrEmpty (contextSelection context)
          let visible := (splitTapes opened tapes).1
          let bytes := sourceContextBytes bound job.largeEnough job.salt opening job.digest job.tree
            (fun input => oracle (Sum.inr input)) context visible
          run randomized (job.next bytes)
            (Sum.elim (publicOpenedOracle (fun input => oracle (Sum.inl input)) job.labels
              opening.points (computed_opening_selected_rank opening) job.salt context
              (mergeTapes opened visible (fun _ => 0))) (fun input => oracle (Sum.inr input))) state

attribute [local irreducible] sourceComputedOpening sourceContextBytes currentIndexedContext
  V8Smz9HonestWholeViewGames.run

theorem raw_byte_public_kernel_is_reference (randomized : Bool) (bound : Nat)
    (job : PublicBytePivot (Work := Work) bound) (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖state‖ = 1) :
    rawBytePublicKernel randomized bound job oracle state =
      bytePostFinalReference randomized bound job.largeEnough job.statement job.batching job.gamma job.response
        job.transcript job.digest job.pending job.salt job.labels job.tree oracle job.next state normalized := by
  unfold rawBytePublicKernel bytePostFinalReference sameOraclePostFinalPublic measuredActualPostFinalPublic
  cases chosen : sourceComputedOpening bound (by have := job.largeEnough; omega) job.digest job.pending
      (fun input => oracle (Sum.inr input)) with
  | none =>
      simp only [measuredContinuedAbortPublic, byteAbortFuture, withPersistentOracle]
      congr 1
      funext input
      cases input <;> rfl
  | some opening => rfl

def rawByteSourceKernel (randomized : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) : ℝ :=
  physicalPostFinalAcceptance randomized bound job.largeEnough (statementParameters job.statement job.batching)
    job.gamma job.response job.transcript job.digest job.pending (packingValues job.witness)
    job.salt job.labels job.tree oracle job.next state

theorem raw_byte_source_kernel_homogeneous (randomized : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) (oracle : FullOracle bound) :
    QuadraticallyHomogeneous (rawByteSourceKernel randomized bound queryBound job oracle) := by
  unfold rawByteSourceKernel physicalPostFinalAcceptance
  apply uniform_average_quadratically_homogeneous
  intro coins
  apply uniform_average_quadratically_homogeneous
  intro tapes
  exact run_quadratically_homogeneous _ _ _

theorem raw_byte_public_kernel_homogeneous (randomized : Bool) (bound : Nat)
    (job : PublicBytePivot (Work := Work) bound) (oracle : FullOracle bound) :
    QuadraticallyHomogeneous (rawBytePublicKernel randomized bound job oracle) := by
  unfold rawBytePublicKernel
  cases sourceComputedOpening bound (by have := job.largeEnough; omega) job.digest job.pending
      (fun input => oracle (Sum.inr input)) with
  | none => exact run_quadratically_homogeneous _ _ _
  | some opening =>
      apply uniform_average_quadratically_homogeneous
      intro view
      apply uniform_average_quadratically_homogeneous
      intro tapes
      exact run_quadratically_homogeneous _ _ _

/-- No conditional-uniformity premise is supplied: the current fresh coins
are sampled inside rawByteSourceKernel, and its preceding mask transport is
the separately proved source-stage equality. Every prior branch state is
handled with its original Born weight. -/
theorem actual_byte_pivot_subnormalized_bound (randomized : Bool) (bound queryBound : Nat)
    (job : BytePivotJob (Work := Work) bound queryBound) (oracle : FullOracle bound)
    (state : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    |rawByteSourceKernel randomized bound queryBound job oracle state -
      rawBytePublicKernel randomized bound job.toPublicBytePivot oracle state| ≤
      hiddenPatchLoss queryBound * ‖state‖ ^ 2 := by
  apply normalized_comparison_lifts_to_all_states
    (rawByteSourceKernel randomized bound queryBound job oracle)
    (rawBytePublicKernel randomized bound job.toPublicBytePivot oracle)
    (raw_byte_source_kernel_homogeneous randomized bound queryBound job oracle)
    (raw_byte_public_kernel_homogeneous randomized bound job.toPublicBytePivot oracle)
    (hiddenPatchLoss queryBound)
  intro normalizedState unitNorm
  rw [raw_byte_public_kernel_is_reference randomized bound job.toPublicBytePivot oracle normalizedState unitNorm]
  exact actual_byte_program_to_public_reference_bound randomized bound job.largeEnough job.statement
    job.publicValues job.witness job.domain job.batching job.gamma job.response job.transcript job.digest job.pending
    job.salt job.labels job.tree oracle job.next normalizedState unitNorm queryBound job.bounded

/-- The actual prior oracle history is inside one finite physical program,
not supplied as supposedly fresh correlated initial advice. The public pivot
uses only the public projection of the history-chosen source job. -/
theorem actual_history_byte_pivot_bound (randomized : Bool) (bound queryBound : Nat)
    (history : Prefix (LeafInput ⊕ OtherRawInput bound) Work (BytePivotJob (Work := Work) bound queryBound))
    (initial : GameState (Input := LeafInput ⊕ OtherRawInput bound) (Work := Work))
    (normalized : ‖initial‖ = 1) :
    |prefixAcceptance randomized history (rawByteSourceKernel randomized bound queryBound) initial -
      prefixAcceptance randomized history
        (fun job => rawBytePublicKernel randomized bound job.toPublicBytePivot) initial| ≤
      hiddenPatchLoss queryBound := by
  apply actual_history_prefix_pivot_bound randomized history _ _ (hiddenPatchLoss queryBound)
  · rw [current_hidden_patch_loss_closed_form]
    positivity
  · exact actual_byte_pivot_subnormalized_bound randomized bound queryBound
  · exact normalized

end
end HegemonCrypto.SmallWood.V8Smz9BytePrefix
