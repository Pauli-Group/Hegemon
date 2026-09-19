import SmzaStageGlobalSplit
import HegemonCrypto.CmsCompressedOracleUnitary

/-!
Initialized finite selected-stage routing for the RP04 full-vector oracle.

The selected raw-input branch is an actual Record operator supplied together
with its exact Split intertwining law.  Every other raw input uses the checked
full-vector CMS query.  Consequently the one-call routing error is literally
an input-sector projection of `selected_stage_global_split_bound`; it is not a
new operator estimate.  The finite theorem then telescopes those checked local
errors from a Split-fixed initial state.

The endpoint deliberately keeps three implementation facts visible:

* exact Record/Split intertwining for the selected branch;
* contraction of the indexed routed call and private inter-query steps; and
* reachable active-target support for each pre-query original state.

Those are strictly local operator/support obligations.  None assumes the
finite coupling conclusion, transcript acceptance, or extraction success.
-/
namespace HegemonCrypto.SmallWood.SmzaInitializedStageRouting

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsCompressedOracleUnitary
open V8Smz9CoherentMerklePartition V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets SmzaFixedAdvicePrefix
open SmzaStageControlledSplit SmzaStageGlobalSplit

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

variable {Key Counter Target Label Cell Private Advice : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Target] [Fintype Label] [Fintype Cell] [Fintype Private]

abbrev SB := StageBasis Key Counter Target Label Cell Private
abbrev StageState := SB (Key := Key) (Counter := Counter) (Target := Target)
  (Label := Label) (Cell := Cell) (Private := Private) → ℂ

def inputProject (selected : Key → Bool) (value : Bool)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) :=
  fun basis => if selected basis.input = value then state basis else 0

theorem input_project_normSquared_le (selected : Key → Bool) (value : Bool)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    normSquared (inputProject selected value state) ≤ normSquared state := by
  unfold normSquared inputProject
  apply Finset.sum_le_sum
  intro basis _
  by_cases same : selected basis.input = value
  · simp [same]
  · simp [same, Complex.normSq_nonneg]

def roleSelected (role : Role)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (key : Key) : Bool :=
  decide (InRoleDomain role (keyBytes key))

def routedOriginal (selected : Key → Bool)
    (record : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (cap : Nat)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) :=
  fun basis => if selected basis.input then record state basis
    else boundedQuery vectorPhaseSystem cap state basis

def routedIndexed (selected : Key → Bool)
    (record : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (cap : Nat)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) :=
  fun basis => if selected basis.input then record state basis
    else boundedQuery vectorPhaseSystem cap state basis

/-- Exact route identity: the selected Record sector cancels by its supplied
intertwining law, leaving only the unselected projection of the checked CMS
commutator. -/
theorem routed_error_eq_unselected_commutator
    (selected : Key → Bool)
    (split : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) ≃
      SB (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (recordOriginal recordIndexed :
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (splitInput : ∀ basis, (split basis).input = basis.input)
    (recordIntertwines : ∀ state,
      permute split (recordOriginal state) = recordIndexed (permute split state))
    (cap : Nat)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    permute split (routedOriginal selected recordOriginal cap state) -
        routedIndexed selected recordIndexed cap (permute split state) =
      inputProject selected false
        (permute split (boundedQuery vectorPhaseSystem cap state) -
          boundedQuery vectorPhaseSystem cap (permute split state)) := by
  funext basis
  have inverseInput : (split.symm basis).input = basis.input := by
    simpa using (splitInput (split.symm basis)).symm
  cases chosen : selected basis.input
  · simp [routedOriginal, routedIndexed, inputProject, permute, inverseInput, chosen]
  · have exactRecord := congrFun (recordIntertwines state) basis
    have zero :
        recordOriginal state (split.symm basis) -
          recordIndexed (permute split state) basis = 0 :=
      sub_eq_zero.mpr exactRecord
    simpa [routedOriginal, routedIndexed, inputProject, permute, inverseInput,
      chosen] using zero

/-- One actual role-selected routed call.  The coefficient is inherited from
`selected_stage_global_split_bound`; selecting an input sector cannot increase
squared norm. -/
theorem selected_role_routed_call_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (empty : Cell) (cap : Nat)
    (recordOriginal recordIndexed :
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (recordIntertwines : ∀ state,
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (recordOriginal state) =
        recordIndexed
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state))
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private))
    (recordCap : ∀ basis, state basis ≠ 0 → (activeSector empty basis).card ≤ cap) :
    normSquared
      (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (routedOriginal (roleSelected role keyBytes) recordOriginal cap state) -
        routedIndexed (roleSelected role keyBytes) recordIndexed cap
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state)) ≤
      (576 * cap / (2^512 : ℝ)) * normSquared state := by
  rw [routed_error_eq_unselected_commutator
    (selected := roleSelected role keyBytes)
    (split := fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
    (recordOriginal := recordOriginal) (recordIndexed := recordIndexed)
    (splitInput := by intro basis; rfl) recordIntertwines cap state]
  exact (input_project_normSquared_le (roleSelected role keyBytes) false _).trans
    (selected_stage_global_split_bound next children role fuel keyBytes targetBytes counter
      code advice empty cap state recordCap)

def run (indexed : Bool) (selected : Key → Bool)
    (recordOriginal recordIndexed :
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (privateStep : Nat →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (cap : Nat)
    (initial : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) : Nat →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private)
  | 0 => initial
  | n + 1 => privateStep (n + 1)
      (if indexed then routedIndexed selected recordIndexed cap
          (run indexed selected recordOriginal recordIndexed privateStep cap initial n)
       else routedOriginal selected recordOriginal cap
          (run indexed selected recordOriginal recordIndexed privateStep cap initial n))

theorem state_norm_sub_triangle
    (left middle right : StageState (Key := Key) (Counter := Counter)
      (Target := Target) (Label := Label) (Cell := Cell) (Private := Private)) :
    stateNorm (left - right) ≤
      stateNorm (left - middle) + stateNorm (middle - right) := by
  have decomposition : left - right = (left - middle) + (middle - right) := by
    funext basis
    simp only [Pi.sub_apply, Pi.add_apply]
    ring
  rw [decomposition]
  exact state_norm_add_le _ _

/-! Event transport is stated on the same full-vector physical basis.  It is
used after `initialized_selected_stage_coupling_norm`; no measurement or
classical distribution is postulated here. -/

def eventState (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) :=
  fun basis => if event basis then state basis else 0

def eventProbability
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) : ℝ :=
  normSquared (eventState event state)

theorem event_probability_nonnegative
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    0 ≤ eventProbability event state := by
  unfold eventProbability normSquared
  exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _

theorem event_norm_le
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    stateNorm (eventState event state) ≤ stateNorm state := by
  apply state_norm_le_of_norm_squared_le
  unfold normSquared eventState
  apply Finset.sum_le_sum
  intro basis _
  by_cases inside : event basis <;> simp [inside, Complex.normSq_nonneg]

theorem event_norm_transport
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (left right : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    stateNorm (eventState event left) ≤
      stateNorm (eventState event right) + stateNorm (left - right) := by
  have decomposition : eventState event left =
      eventState event right + eventState event (left - right) := by
    funext basis
    by_cases inside : event basis <;> simp [eventState, inside]
  rw [decomposition]
  exact (state_norm_add_le _ _).trans
    (add_le_add le_rfl (event_norm_le event (left - right)))

theorem event_sqrt_probability
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (state : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private)) :
    Real.sqrt (eventProbability event state) = stateNorm (eventState event state) := by
  unfold eventProbability
  rw [← state_norm_sq_eq_norm_squared, Real.sqrt_sq_eq_abs,
    abs_of_nonneg (state_norm_nonnegative _)]

/-- A measured event transfers across any initialized-routing norm bound with
the exact cross term.  In particular, instantiate `distance` with
`initialized_selected_stage_coupling_norm`; using only its squared-mass
corollary would incorrectly discard this term. -/
theorem event_probability_transport
    (event : SB (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private) → Prop)
    (left right : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private))
    (delta : ℝ) (distance : stateNorm (left - right) ≤ delta) :
    eventProbability event left ≤ eventProbability event right +
      2 * Real.sqrt (eventProbability event right) * delta + delta ^ 2 := by
  have amplitude : Real.sqrt (eventProbability event left) ≤
      Real.sqrt (eventProbability event right) + delta := by
    rw [event_sqrt_probability, event_sqrt_probability]
    exact (event_norm_transport event left right).trans (add_le_add le_rfl distance)
  have deltaNonnegative := (state_norm_nonnegative (left - right)).trans distance
  have leftSquare := Real.sq_sqrt (event_probability_nonnegative event left)
  have rightSquare := Real.sq_sqrt (event_probability_nonnegative event right)
  have leftNonnegative := Real.sqrt_nonneg (eventProbability event left)
  have rightNonnegative := Real.sqrt_nonneg (eventProbability event right)
  nlinarith

/-- Initialized finite execution.  This is the stage-aware analogue of the
retained final-only `SmzaExecutionCouplingR5` telescope.  Its premises name
the exact local implementation obligations instead of assuming the resulting
finite error bound. -/
theorem initialized_selected_stage_coupling_norm
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (empty : Cell) (cap count : Nat)
    (recordOriginal recordIndexed :
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (privateStep : Nat →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (initial : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private))
    (recordIntertwines : ∀ state,
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (recordOriginal state) =
        recordIndexed
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state))
    (initialFixed :
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) initial = initial)
    (privateCommutes : ∀ n state,
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (privateStep n state) =
        privateStep n
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state))
    (privateDistance : ∀ n left right,
      stateNorm (privateStep n left - privateStep n right) ≤ stateNorm (left - right))
    (indexedDistance : ∀ left right,
      stateNorm
        (routedIndexed (roleSelected role keyBytes) recordIndexed cap left -
          routedIndexed (roleSelected role keyBytes) recordIndexed cap right) ≤
        stateNorm (left - right))
    (originalSubnormalized : ∀ n, n ≤ count →
      Subnormalized (run false (roleSelected role keyBytes) recordOriginal recordIndexed
        privateStep cap initial n))
    (reachableActive : ∀ n, n < count → ∀ basis,
      run false (roleSelected role keyBytes) recordOriginal recordIndexed
          privateStep cap initial n basis ≠ 0 →
        (activeSector empty basis).card ≤ cap) :
    stateNorm
      (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (run false (roleSelected role keyBytes) recordOriginal recordIndexed
            privateStep cap initial count) -
        run true (roleSelected role keyBytes) recordOriginal recordIndexed
          privateStep cap initial count) ≤
      (count : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ)) := by
  let selected := roleSelected role keyBytes
  let split := fullSplit (Cell := Cell) (Private := Private)
    (labels next role fuel keyBytes targetBytes counter code advice)
  have all : ∀ n, n ≤ count →
      stateNorm
        (permute split
            (run false selected recordOriginal recordIndexed privateStep cap initial n) -
          run true selected recordOriginal recordIndexed privateStep cap initial n) ≤
        (n : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ)) := by
    intro n within
    induction n with
    | zero =>
      simp only [run, Nat.cast_zero, zero_mul, split]
      have h := congrArg stateNorm
        (congrArg (fun value => value - initial) initialFixed)
      rw [h]
      simp [sub_self, state_norm_zero]
    | succ n ih =>
      let old := run false selected recordOriginal recordIndexed privateStep cap initial n
      let current := run true selected recordOriginal recordIndexed privateStep cap initial n
      let afterOld := permute split (routedOriginal selected recordOriginal cap old)
      let middle := routedIndexed selected recordIndexed cap (permute split old)
      let afterCurrent := routedIndexed selected recordIndexed cap current
      have localMass := selected_role_routed_call_bound next children role fuel keyBytes
        targetBytes counter code advice empty cap recordOriginal recordIndexed
        recordIntertwines old (reachableActive n (lt_of_lt_of_le (Nat.lt_succ_self n) within))
      have localMassOne : normSquared (afterOld - middle) ≤
          576 * cap / (2^512 : ℝ) := by
        exact localMass.trans (by
          have normalized := originalSubnormalized n ((Nat.le_succ n).trans within)
          have nonnegative : 0 ≤ 576 * (cap : ℝ) / (2^512 : ℝ) := by positivity
          simpa only [afterOld, middle, split, old, selected, mul_one] using
            (mul_le_mul_of_nonneg_left normalized nonnegative))
      have localNorm : stateNorm (afterOld - middle) ≤
          Real.sqrt (576 * cap / (2^512 : ℝ)) :=
        state_norm_le_sqrt _ (by positivity) localMassOne
      have propagated : stateNorm (middle - afterCurrent) ≤
          stateNorm (permute split old - current) := by
        exact indexedDistance (permute split old) current
      change stateNorm
        (permute split (privateStep (n + 1)
            (routedOriginal selected recordOriginal cap old)) -
          privateStep (n + 1)
            (routedIndexed selected recordIndexed cap current)) ≤ _
      rw [privateCommutes]
      calc
        _ ≤ stateNorm (afterOld - afterCurrent) :=
          privateDistance (n + 1) afterOld afterCurrent
        _ ≤ stateNorm (afterOld - middle) + stateNorm (middle - afterCurrent) :=
          state_norm_sub_triangle afterOld middle afterCurrent
        _ ≤ Real.sqrt (576 * cap / (2^512 : ℝ)) +
            stateNorm (permute split old - current) := add_le_add localNorm propagated
        _ ≤ Real.sqrt (576 * cap / (2^512 : ℝ)) +
            (n : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ)) :=
          add_le_add le_rfl (ih ((Nat.le_succ n).trans within))
        _ = ((n + 1 : Nat) : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ)) := by
          push_cast
          ring
  simpa only [selected, split] using all count le_rfl

theorem initialized_selected_stage_coupling_mass
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (targetBytes : Target → V8SmzaOracleParser.RawInput) (counter : Counter)
    (code : Advice → V8SmzaOracleParser.RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace V8SmzaOracleParser.RawInput → Label)
    (advice : Advice) (empty : Cell) (cap count : Nat)
    (recordOriginal recordIndexed :
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (privateStep : Nat →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private) →
      StageState (Key := Key) (Counter := Counter) (Target := Target)
        (Label := Label) (Cell := Cell) (Private := Private))
    (initial : StageState (Key := Key) (Counter := Counter) (Target := Target)
      (Label := Label) (Cell := Cell) (Private := Private))
    (recordIntertwines : ∀ state,
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (recordOriginal state) =
        recordIndexed
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state))
    (initialFixed :
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) initial = initial)
    (privateCommutes : ∀ n state,
      permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (privateStep n state) =
        privateStep n
          (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice)) state))
    (privateDistance : ∀ n left right,
      stateNorm (privateStep n left - privateStep n right) ≤ stateNorm (left - right))
    (indexedDistance : ∀ left right,
      stateNorm
        (routedIndexed (roleSelected role keyBytes) recordIndexed cap left -
          routedIndexed (roleSelected role keyBytes) recordIndexed cap right) ≤
        stateNorm (left - right))
    (originalSubnormalized : ∀ n, n ≤ count →
      Subnormalized (run false (roleSelected role keyBytes) recordOriginal recordIndexed
        privateStep cap initial n))
    (reachableActive : ∀ n, n < count → ∀ basis,
      run false (roleSelected role keyBytes) recordOriginal recordIndexed
          privateStep cap initial n basis ≠ 0 →
        (activeSector empty basis).card ≤ cap) :
    normSquared
      (permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
          (run false (roleSelected role keyBytes) recordOriginal recordIndexed
            privateStep cap initial count) -
        run true (roleSelected role keyBytes) recordOriginal recordIndexed
          privateStep cap initial count) ≤
      (count : ℝ)^2 * (576 * cap / (2^512 : ℝ)) := by
  let error :=
    permute (fullSplit (labels next role fuel keyBytes targetBytes counter code advice))
        (run false (roleSelected role keyBytes) recordOriginal recordIndexed
          privateStep cap initial count) -
      run true (roleSelected role keyBytes) recordOriginal recordIndexed
        privateStep cap initial count
  have bound := initialized_selected_stage_coupling_norm next children role fuel keyBytes
    targetBytes counter code advice empty cap count recordOriginal recordIndexed privateStep
    initial recordIntertwines initialFixed privateCommutes privateDistance indexedDistance
    originalSubnormalized reachableActive
  have nonnegative := state_norm_nonnegative error
  have squareBound : stateNorm error ^ 2 ≤
      ((count : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ))) ^ 2 := by
    nlinarith [show 0 ≤ (count : ℝ) *
      Real.sqrt (576 * cap / (2^512 : ℝ)) by positivity]
  rw [state_norm_sq_eq_norm_squared] at squareBound
  calc
    normSquared error ≤
        ((count : ℝ) * Real.sqrt (576 * cap / (2^512 : ℝ))) ^ 2 := squareBound
    _ = (count : ℝ)^2 * (576 * cap / (2^512 : ℝ)) := by
      rw [mul_pow, Real.sq_sqrt (by positivity :
        0 ≤ 576 * (cap : ℝ) / (2^512 : ℝ))]

end
end HegemonCrypto.SmallWood.SmzaInitializedStageRouting
