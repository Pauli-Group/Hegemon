import HegemonCrypto.SmallWoodV8Smz9CurrentRepeatedPrivacy

/-! A failed proof request can be followed by more oracle interaction. This
module retains that continuation and derives the hidden-leaf comparison even
when every current leaf remains unopened. A public-abort phase is an actual
oracle-independent isometry on the retained state, followed by the entire
request suffix; it is not a scalar terminal failure probability.

No current prover refinement or complete privacy theorem is asserted here. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestWholeViewAbort

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentRepeatedPrivacy
open V8Smz9PrivacyGameComposition
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-! The finite counterexample uses one pre-request and one post-request basis
query. Both oracle bits, the hidden address and the new answer are independent
uniform bits. A terminal public failure does not erase their later correlation. -/

abbrev AbortToyCoins := (Bool × Bool) × (Bool × Bool)

def abortToyOracle (coins : AbortToyCoins) (input : Bool) : Bool :=
  if input then coins.1.2 else coins.1.1

def abortToyUpdatedOracle (coins : AbortToyCoins) : Bool → Bool :=
  Function.update (abortToyOracle coins) coins.2.1 coins.2.2

def abortToyChanged (coins : AbortToyCoins) : Prop :=
  abortToyUpdatedOracle coins false ≠ abortToyOracle coins false

instance abortToyChangedDecidable : DecidablePred abortToyChanged := fun coins =>
  inferInstanceAs (Decidable (abortToyUpdatedOracle coins false ≠ abortToyOracle coins false))

theorem public_abort_does_not_erase_oracle_distinguishing_event :
    (Finset.univ.filter abortToyChanged).card = 4 ∧
      Fintype.card AbortToyCoins = 16 := by decide

theorem omitted_programs_have_no_change_event :
    (Finset.univ.filter (fun coins : AbortToyCoins =>
      abortToyOracle coins false ≠ abortToyOracle coins false)).card = 0 := by
  simp

variable {Other Updates Work : Type*} [Fintype Other] [DecidableEq Other]
variable [Fintype Updates] [DecidableEq Updates] [Fintype Work] [DecidableEq Work]

/-- The public-abort marker can be controlled by the retained history. The
suffix includes subsequent requests, honest reads, updates and coherent reads. -/
def abortedRequestContinuation
    (request : Nat)
    (markFailure : RetainedGate (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (suffix : RequestGrammar (LeafInput ⊕ Other) Updates Work) :
    RequestGrammar (LeafInput ⊕ Other) Updates Work :=
  .requestPhase request .publicAbort markFailure suffix

omit [DecidableEq Other] [DecidableEq Updates] [DecidableEq Work] in
theorem public_abort_continues_retained_execution
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (request : Nat)
    (markFailure : RetainedGate (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (suffix : RequestGrammar (LeafInput ⊕ Other) Updates Work)
    (initial : RetainedState (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work)) :
    runRequestGrammar lookup oracle (abortedRequestContinuation request markFailure suffix) initial =
      runRequestGrammar lookup oracle suffix (markFailure initial) := rfl

omit [DecidableEq Other] [DecidableEq Updates] [DecidableEq Work] in
theorem public_abort_charges_complete_suffix
    (request : Nat)
    (markFailure : RetainedGate (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (suffix : RequestGrammar (LeafInput ⊕ Other) Updates Work) :
    logicalReadCount (abortedRequestContinuation request markFailure suffix) =
      logicalReadCount suffix := rfl

/-- Every current leaf has been programmed before this public failure. The
fresh tapes remain internal while the complete future program executes. -/
def abortedSourceAcceptance
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister)
    (header : LeafIndex → LeafHeader) (payload : LeafIndex → LeafSuffix)
    (grammar : RequestGrammar (LeafInput ⊕ Other) Updates Work)
    (initial : RetainedState (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (event : Finset (RetainedBasis (LeafInput ⊕ Other) Updates Work)) : ℝ :=
  (∑ tapes : LeafIndex → LeafTape,
    born event (runRequestGrammar lookup
      (fullSourceOverlay oldLeaf other targets Finset.univ header payload tapes) grammar initial)) /
    (Fintype.card (LeafIndex → LeafTape) : ℝ)

/-- The reference restores each hidden current write to the preceding oracle;
it preserves all prior history and all future retained-register writes. -/
def abortedPublicAcceptance
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (grammar : RequestGrammar (LeafInput ⊕ Other) Updates Work)
    (initial : RetainedState (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (event : Finset (RetainedBasis (LeafInput ⊕ Other) Updates Work)) : ℝ :=
  (∑ _tapes : LeafIndex → LeafTape,
    born event (runRequestGrammar lookup (Sum.elim oldLeaf other) grammar initial)) /
    (Fintype.card (LeafIndex → LeafTape) : ℝ)

/-- A concrete physical continuation bound for a failed request. The initial
state, baseline, grammar and event have no current-hidden-tape argument. This
is the same freshness boundary as the successful-request hidden-patch theorem. -/
theorem aborted_request_hidden_leaf_suffix_bound
    (lookup : Updates → (LeafInput ⊕ Other) → Option DigestRegister)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister)
    (header : LeafIndex → LeafHeader) (payload : LeafIndex → LeafSuffix)
    (request : Nat)
    (markFailure : RetainedGate (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (suffix : RequestGrammar (LeafInput ⊕ Other) Updates Work)
    (initial : RetainedState (Input := LeafInput ⊕ Other) (Updates := Updates) (Work := Work))
    (normalized : ‖initial‖ = 1)
    (event : Finset (RetainedBasis (LeafInput ⊕ Other) Updates Work)) :
    let grammar := abortedRequestContinuation request markFailure suffix
    |abortedSourceAcceptance lookup oldLeaf other targets header payload grammar initial event -
      abortedPublicAcceptance lookup oldLeaf other grammar initial event| ≤
        hiddenPatchLoss (2 * logicalReadCount suffix) := by
  let grammar := abortedRequestContinuation request markFailure suffix
  let circuit := compileRequestGrammar lookup grammar
  have bound := full_source_overlay_cq_born_distance_le oldLeaf other targets Finset.univ
    header payload (compiledSteps circuit) (circuit.prepare initial)
    ((circuit.prepare.norm_map initial).trans normalized) circuit.afterQueries.length
    (fun _ => LinearIsometryEquiv.refl ℂ _) (fun _ => event)
  have execution : ∀ oracle,
      run oracle (compiledSteps circuit) (circuit.prepare initial) circuit.afterQueries.length =
        runRequestGrammar lookup oracle grammar initial := fun oracle =>
    compiled_grammar_is_current_game_circuit lookup oracle grammar initial
  simp_rw [execution] at bound
  change |abortedSourceAcceptance lookup oldLeaf other targets header payload grammar initial event -
    abortedPublicAcceptance lookup oldLeaf other grammar initial event| ≤
      hiddenPatchLoss circuit.afterQueries.length at bound
  simpa only [abortedSourceAcceptance, abortedPublicAcceptance,
    hiddenPatchLoss, circuit,
    compiled_raw_query_count, grammar, public_abort_charges_complete_suffix] using bound

theorem aborted_request_loss_closed_form (queries : Nat) :
    hiddenPatchLoss (2 * queries) = 8 * (queries : ℝ) / (2 ^ 256 : ℝ) :=
  compiled_request_suffix_loss_closed_form queries

end
end HegemonCrypto.SmallWood.V8Smz9HonestWholeViewAbort
