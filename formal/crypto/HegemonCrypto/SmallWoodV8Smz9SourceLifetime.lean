import HegemonCrypto.SmallWoodV8Smz9PostFinalQueryBudget

/-! A finite adaptive lifetime of actual source byte requests.

The lifetime is fixed before the uniform raw oracle is sampled. Its only
oracle access is through charged queries. Source request continuations retain
the full byte/error result and the same quantum state and persistent table.

The two indices are worst-branch resource budgets, not exact request counts.
They avoid taking an unjustified finite maximum over the infinite type
`Except String (List Byte)`. All branches must satisfy the same budgets.
Only the actual source leaf events are randomized by the game bit. This is
the first reprogramming stage, not the final transcript or public-reference
endpoint and not a Rust implementation-refinement theorem. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceLifetime

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9EagerPrivacy V8Smz9EagerOracleGame V8Smz9RuntimeRandomness
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentPublicContext
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9DynamicRequest V8Smz9PostFinalProgram V8Smz9PostFinalQueryBudget
open V8Smz9RuntimeDistribution
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000
set_option Elab.async false

attribute [local irreducible] V8Smz9HonestWholeViewGames.run sourceCompleteByteRequest uniformAverage InputMassAtMost

/-- An admitted source request. Public input and witness admission are
explicit; the compiler obtains packing values from this same witness. -/
structure SourceRequestData (bound : Nat) where
  statement : V8PublicStatement
  publicValues : List Nat
  witness : List Nat
  domain : CanonicalPublicPackedDomain statement publicValues witness
  statementBinding : List Nat
  bindingFits : 15704 + 8 * statementBinding.length ≤ bound
  salt : SaltBytes
  retainedRows : Nat
  rowBound : retainedRows ≤ 20605

abbrev ByteResult := Except String (List CanonicalBytes.Byte)

/-- Complete instruments and genuine uniform local randomness permit
adaptive classical histories without admitting an oracle-dependent AST or
initial state. The finish node may leave its budgets unused. -/
inductive Lifetime (bound : Nat) (Work : Type) [Fintype Work] : Nat → Nat → Type 1 where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      Lifetime bound Work queries requests
  | gate {queries requests : Nat}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | quantumQuery {queries requests : Nat}
      (next : Lifetime bound Work queries requests) : Lifetime bound Work (queries + 1) requests
  | honestRead {queries requests : Nat} (input : FullRawInput bound)
      (next : DigestRegister → Lifetime bound Work queries requests) :
      Lifetime bound Work (queries + 1) requests
  | instrument {queries requests count : Nat}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : Fin count → Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | random {queries requests : Nat} (source : RandomSource)
      (next : source.Coins → Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | sourceRequest {queries requests : Nat} (request : SourceRequestData bound)
      (next : ByteResult → Lifetime bound Work queries requests) :
      Lifetime bound Work (16790291 + queries) (requests + 1)

def remainingCoinsSource : RandomSource :=
  ⟨SourceRemainingCoins Goldilocks, inferInstance, inferInstance⟩

def jointMasksSource : RandomSource :=
  ⟨JointMaskCoins Goldilocks, inferInstance, inferInstance⟩

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- A request compiler is an ordinary program constructor, not an assumed
endpoint law. Its continuation contains the entire later lifetime. -/
abbrev RequestCompiler (bound : Nat) (Work : Type) [Fintype Work] :=
  SourceRequestData bound → (ByteResult → Program (FullRawInput bound) Work) →
    Program (FullRawInput bound) Work

/-- Literal source request expansion. Both coin groups are sampled locally;
the source builder then computes actual leaves, DECS/PIOP, final digest,
opening/index and bytes before entering the supplied continuation. -/
def actualRequestCompiler (largeEnough : 37434 ≤ bound) : RequestCompiler bound Work :=
  fun request next =>
    .random remainingCoinsSource fun coins =>
      .random jointMasksSource fun masks =>
        sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
          request.statement (packingValues request.witness) coins masks request.salt
          request.retainedRows request.rowBound next

/-- The structural compiler is proved against a symbolic request operation
so the kernel never needs to unfold a concrete 2^23-leaf batch during an
induction over the adversary's lifetime. -/
def compileWith (step : RequestCompiler bound Work) :
    {queries requests : Nat} → Lifetime bound Work queries requests → Program (FullRawInput bound) Work
  | _, _, .finish event => .finish event
  | _, _, .gate operation next => .gate operation (compileWith step next)
  | _, _, .quantumQuery next => .quantumQuery (compileWith step next)
  | _, _, .honestRead input next => .honestRead input (fun digest => compileWith step (next digest))
  | _, _, .instrument operation next => .instrument operation (fun outcome => compileWith step (next outcome))
  | _, _, .random source next => .random source (fun coins => compileWith step (next coins))
  | _, _, .sourceRequest request next => step request (fun output => compileWith step (next output))

/-- The actual compiler specializes the structural compiler to the literal
source operation above; no arbitrary request implementation is left open. -/
def compileSource (largeEnough : 37434 ≤ bound) {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) : Program (FullRawInput bound) Work :=
  compileWith (actualRequestCompiler largeEnough) lifetime

/-- The entire post-final byte request contains no fresh-input event of its
own. The only new input-mass obligations are the actual source leaf tapes. -/
theorem source_complete_byte_request_mass (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound) (coins : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (next : ByteResult → Program (FullRawInput bound) Work)
    (remaining : ∀ output, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next output)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
        request.statement (packingValues request.witness) coins masks request.salt
        request.retainedRows request.rowBound next) := by
  unfold sourceCompleteByteRequest
  apply source_all_leaves_computed_prefix_mass
  intro tapes labels stageResult response transcript digest pending
  unfold sourcePostFinalProgram
  apply NonleafProgram.compile_preserves_mass
  exact remaining

theorem actual_request_compiler_mass (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound) (next : ByteResult → Program (FullRawInput bound) Work)
    (remaining : ∀ output, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next output)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (actualRequestCompiler largeEnough request next) := by
  simp only [actualRequestCompiler, InputMassAtMost]
  intro coins masks
  exact source_complete_byte_request_mass largeEnough request coins masks next remaining

theorem actual_request_compiler_query_bound (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound) (next : ByteResult → Program (FullRawInput bound) Work)
    (queries : Nat) (remaining : ∀ output, queryCount (next output) ≤ queries) :
    queryCount (actualRequestCompiler largeEnough request next) ≤ 16790291 + queries := by
  unfold actualRequestCompiler
  apply Finset.sup_le
  intro coins _
  apply Finset.sup_le
  intro masks _
  exact source_complete_byte_request_query_bound bound largeEnough request.statementBinding request.bindingFits
    request.statement (packingValues request.witness) coins masks request.salt request.retainedRows
    request.rowBound next queries remaining

theorem actual_request_compiler_programming_bound (largeEnough : 37434 ≤ bound)
    (request : SourceRequestData bound) (next : ByteResult → Program (FullRawInput bound) Work)
    (programs : Nat) (remaining : ∀ output, programmingCount (next output) ≤ programs) :
    programmingCount (actualRequestCompiler largeEnough request next) ≤ 8388608 + programs := by
  unfold actualRequestCompiler
  apply Finset.sup_le
  intro coins _
  apply Finset.sup_le
  intro masks _
  exact source_complete_byte_request_programming_bound bound largeEnough request.statementBinding request.bindingFits
    request.statement (packingValues request.witness) coins masks request.salt request.retainedRows
    request.rowBound next programs remaining

theorem compiled_with_input_mass (step : RequestCompiler bound Work) (cap : ℝ≥0∞)
    (bounded : ∀ request next, (∀ output, InputMassAtMost cap (next output)) →
      InputMassAtMost cap (step request next))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    InputMassAtMost cap (compileWith step lifetime) := by
  induction lifetime with
  | finish event => simp only [compileWith, InputMassAtMost]
  | gate operation next ih => simpa only [compileWith, InputMassAtMost] using ih
  | quantumQuery next ih => simpa only [compileWith, InputMassAtMost] using ih
  | honestRead input next ih => simpa only [compileWith, InputMassAtMost] using ih
  | instrument operation next ih => simpa only [compileWith, InputMassAtMost] using ih
  | random source next ih => simpa only [compileWith, InputMassAtMost] using ih
  | sourceRequest request next ih => exact bounded request _ ih

theorem compiled_with_query_bound (step : RequestCompiler bound Work)
    (bounded : ∀ request next queries, (∀ output, queryCount (next output) ≤ queries) →
      queryCount (step request next) ≤ 16790291 + queries)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    queryCount (compileWith step lifetime) ≤ queries := by
  induction lifetime with
  | finish event => exact Nat.zero_le _
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact Nat.add_le_add_right ih 1
  | honestRead input next ih => exact Nat.add_le_add_right (Finset.sup_le fun output _ => ih output) 1
  | instrument operation next ih => exact Finset.sup_le fun outcome _ => ih outcome
  | random source next ih => exact Finset.sup_le fun coins _ => ih coins
  | sourceRequest request next ih => exact bounded request _ _ ih

theorem compiled_with_programming_bound (step : RequestCompiler bound Work)
    (bounded : ∀ request next programs, (∀ output, programmingCount (next output) ≤ programs) →
      programmingCount (step request next) ≤ 8388608 + programs)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    programmingCount (compileWith step lifetime) ≤ 8388608 * requests := by
  induction lifetime with
  | finish event => exact Nat.zero_le _
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact Finset.sup_le fun output _ => ih output
  | instrument operation next ih => exact Finset.sup_le fun outcome _ => ih outcome
  | random source next ih => exact Finset.sup_le fun coins _ => ih coins
  | sourceRequest request next ih =>
      exact (bounded request _ _ ih).trans (by omega)

theorem compiled_source_input_mass (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (compileSource largeEnough lifetime) :=
  compiled_with_input_mass (actualRequestCompiler largeEnough) _ (actual_request_compiler_mass largeEnough) lifetime

theorem compiled_source_query_bound (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    queryCount (compileSource largeEnough lifetime) ≤ queries :=
  compiled_with_query_bound (actualRequestCompiler largeEnough) (actual_request_compiler_query_bound largeEnough) lifetime

theorem compiled_source_programming_bound (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests) :
    programmingCount (compileSource largeEnough lifetime) ≤ 8388608 * requests :=
  compiled_with_programming_bound (actualRequestCompiler largeEnough)
    (actual_request_compiler_programming_bound largeEnough) lifetime

/-- One uniform oracle is sampled after the entire adaptive code and its
initial state have been fixed. Both games share that initial distribution. -/
def sourceLifetimeAcceptance (randomized : Bool) (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  acceptance randomized (compileSource largeEnough lifetime) initial

/-- Whole-history first-stage leaf reprogramming. Query accounting includes
every later byte/error branch, all ordinary/quantum reads, all source reads,
and every subsequent source request. The only external mathematical premise
is the already-declared universal adaptive-reprogramming theorem. -/
theorem whole_source_lifetime_leaf_reprogramming_bound (largeEnough : 37434 ≤ bound)
    (ghhm : ExternalAdaptiveReprogramming (Input := FullRawInput bound) (Work := Work))
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |sourceLifetimeAcceptance true largeEnough lifetime initial -
      sourceLifetimeAcceptance false largeEnough lifetime initial| ≤
      ((8388608 * requests : Nat) : ℝ) *
        (Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
          (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
  measured_adaptive_leaf_game_bound ghhm (compileSource largeEnough lifetime) initial queries
    (8388608 * requests) normalized (compiled_source_query_bound largeEnough lifetime)
    (compiled_source_programming_bound largeEnough lifetime) (compiled_source_input_mass largeEnough lifetime)

theorem source_lifetime_acceptance_is_probability (randomized : Bool) (largeEnough : 37434 ≤ bound)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    0 ≤ sourceLifetimeAcceptance randomized largeEnough lifetime initial ∧
      sourceLifetimeAcceptance randomized largeEnough lifetime initial ≤ 1 :=
  game_acceptance_is_probability randomized (compileSource largeEnough lifetime) initial normalized

end
end HegemonCrypto.SmallWood.V8Smz9SourceLifetime
