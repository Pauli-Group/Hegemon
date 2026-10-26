import HegemonCrypto.NativeLaunchCommitmentResponseBinding
import HegemonCrypto.NativeLaunchFppHistoryBinding

/-! Conditional finite classical-history join, not accepted Rust execution.
The separately supplied raw-key selector determines the prior response; it is
not constructed from the final sampled wire. Recorded membership and finite
collision exclusion imply literal key equality, then complete decoding supplies
the calculated response internally. Chronology, real-game selection, densities,
source geometry/refinement, QROM, simulation and release authority remain open.
The leading digest is hash_mt, not an unwrapped Merkle root. -/
set_option autoImplicit false
namespace HegemonCrypto.NativeLaunchFppResponseHistory
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec (Word RawInput)
open NativeLaunchRelationModelStatement
open NativeLaunchCommitmentReadback (family frame)
open NativeLaunchCommitmentResponseBinding
open NativeLaunchFppHistoryBinding
open SmallWood
open SmallWood.NativeLaunchRelationModelResponse
open SmallWood.V8Smz9McaRecovery (BoundedResponse)
open SmallWood.V8Smz9McaDecoder (responseSupport)
open SmallWood.V8Smz9RawCounterCompiler (typedWordPayload)
noncomputable section

def zeroResponse (branch : Branch) : BoundedResponse Goldilocks (Fin 5) (degree branch) :=
  fun _ => 0

/-- The selector is supplied separately and has no wire/point argument here.
This does not prove a caller's selector was chosen chronologically in a game. -/
def priorResponse (branch : Branch) (priorKey : Matrix → RawInput) :
    Matrix → BoundedResponse Goldilocks (Fin 5) (degree branch) := fun matrix =>
  match decodeFppResponse branch (priorKey matrix) with
  | some decoded => decoded.response
  | none => zeroResponse branch

theorem parse_failure_uses_zero (branch : Branch) (priorKey : Matrix → RawInput)
    (matrix : Matrix) (failed : decodeFppResponse branch (priorKey matrix) = none) :
    priorResponse branch priorKey matrix = zeroResponse branch := by
  simp [priorResponse, failed]

/-- A concrete complete FPP key built from actual restored rows, the full
statement, and the supplied leading hash_mt digest. -/
def rebuiltKey {branch : Branch} {Position : Type*}
    (leadingDigest : Digest) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix) : RawInput :=
  frame (restoredCommitment leadingDigest statement point wire matrix)

/-- Full selected record recovery is derived from history, not supplied as a
response-equality or positive-correctness premise. -/
theorem selected_decode_of_history {branch : Branch} {Position : Type*}
    (H : Oracle) (history : History) (priorKey : Matrix → RawInput)
    (leadingDigest : Digest) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (priorTail rebuiltTail : List Word) (claimed : Digest)
    (recorded : RecordedChain H history (family branch) (priorKey matrix) priorTail claimed)
    (accepted : reconstructedDigest H (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail = claimed)
    (clean : ¬ RelevantCollision H (relevantInputs H history (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail)) :
    decodeFppResponse branch (priorKey matrix) =
      some ⟨typedWordPayload (List.ofFn leadingDigest), statementBytes statement,
        calculatedResponse point wire matrix⟩ := by
  have sameKey := accepted_digest_binds_raw_fpp H history (family branch)
    (priorKey matrix) (rebuiltKey leadingDigest statement point wire matrix)
    priorTail rebuiltTail claimed recorded accepted clean
  rw [sameKey]
  exact decode_restored_commitment leadingDigest statement point wire matrix

theorem selected_response_of_history {branch : Branch} {Position : Type*}
    (H : Oracle) (history : History) (priorKey : Matrix → RawInput)
    (leadingDigest : Digest) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (priorTail rebuiltTail : List Word) (claimed : Digest)
    (recorded : RecordedChain H history (family branch) (priorKey matrix) priorTail claimed)
    (accepted : reconstructedDigest H (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail = claimed)
    (clean : ¬ RelevantCollision H (relevantInputs H history (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail)) :
    priorResponse branch priorKey matrix = calculatedResponse point wire matrix := by
  have decoded := selected_decode_of_history H history priorKey leadingDigest statement
    point wire matrix priorTail rebuiltTail claimed recorded accepted clean
  simp [priorResponse, decoded]

/-- Selected-matrix DECS support now uses the internally derived binding.
Authenticated source readback and distinct query points remain explicit. -/
theorem query_support_of_history {branch : Branch} {Position : Type*} [Fintype Position]
    (H : Oracle) (history : History) (priorKey : Matrix → RawInput)
    (leadingDigest : Digest) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (priorTail rebuiltTail : List Word) (claimed : Digest)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (readback : SourceReadback wire data masks)
    (recorded : RecordedChain H history (family branch) (priorKey matrix) priorTail claimed)
    (accepted : reconstructedDigest H (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail = claimed)
    (clean : ¬ RelevantCollision H (relevantInputs H history (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail))
    (index : Fin (queryCount branch)) :
    wire.positions index ∈ responseSupport point (degree branch) data masks
      (priorResponse branch priorKey) matrix := by
  exact query_agrees_with_prior_response point wire matrix data masks
    (priorResponse branch priorKey) distinct readback
    (selected_response_of_history H history priorKey leadingDigest statement
      point wire matrix priorTail rebuiltTail claimed recorded accepted clean) index

/-- An overlapping deterministic exceptional-event cover, with no density or
probability claim and no inferred chronological prequery history. -/
theorem query_failure_cover {branch : Branch} {Position : Type*} [Fintype Position]
    (H : Oracle) (history : History) (priorKey : Matrix → RawInput)
    (leadingDigest : Digest) (statement : Statement (family branch))
    (point : Position → Goldilocks) (wire : WireFields branch Position) (matrix : Matrix)
    (priorTail rebuiltTail : List Word) (claimed : Digest)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (readback : SourceReadback wire data masks)
    (accepted : reconstructedDigest H (family branch)
      (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail = claimed)
    (index : Fin (queryCount branch))
    (failed : wire.positions index ∉ responseSupport point (degree branch) data masks
      (priorResponse branch priorKey) matrix) :
    ¬ RecordedChain H history (family branch) (priorKey matrix) priorTail claimed ∨
      RelevantCollision H (relevantInputs H history (family branch)
        (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail) := by
  by_cases recorded : RecordedChain H history (family branch) (priorKey matrix) priorTail claimed
  · by_cases collision : RelevantCollision H (relevantInputs H history (family branch)
        (rebuiltKey leadingDigest statement point wire matrix) rebuiltTail)
    · exact Or.inr collision
    · exact False.elim (failed (query_support_of_history H history priorKey leadingDigest statement
        point wire matrix priorTail rebuiltTail claimed data masks distinct readback
        recorded accepted collision index))
  · exact Or.inl recorded
end
end HegemonCrypto.NativeLaunchFppResponseHistory
