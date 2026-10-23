import HegemonCrypto.NativePrivateSpendQ58Wpcs

/-!
Joint ideal-coordinate transport with two public-dependent failure selectors,
source-shaped delayed poison handling, and inverse-retained state kernels.
This is not Rust refinement or a claim that those kernels are public-only.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58AbortComposition
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev W := NativePrivateSpendQ58Wpcs.W
abbrev P := NativePrivateSpendQ58Wpcs.P
abbrev Q := NativePrivateSpendQ58ChronologicalMasks.Q
abbrev D := NativePrivateSpendQ58ChronologicalMasks.D
abbrev Coins := NativePrivateSpendQ58ChronologicalMasks.Coins
abbrev Base := NativePrivateSpendQ58ChronologicalMasks.Base
abbrev Model := NativePrivateSpendQ58ChronologicalMasks.Model
abbrev Values := NativePrivateSpendQ58Wpcs.Values
abbrev Tails := NativePrivateSpendQ58LvcsJoint.Tails
abbrev Earlier := NativePrivateSpendQ58LvcsJoint.Earlier
abbrev Later := NativePrivateSpendQ58LvcsJoint.Later
abbrev Targets := NativePrivateSpendQ58LvcsJoint.Targets
abbrev Response := D × Q
/-- W/P types in output denote Z witness openings and S partial openings. -/
abbrev View := Response × ((W × P) × (Earlier × Later))
abbrev Error := String
abbrev Status := Option Error

structure Step (A : Type*) where
  poison : Status
  result : Except Error A

/-- Exactly the sticky first-error policy of the source field-XOF scope. -/
def recordPoison (old : Status) (error : Error) : Status :=
  match old with | none => some error | some first => some first

/-- For source request lengths smaller than p these are p-1-index. -/
def poisonWords (n : Nat) : Fin n → Goldilocks := fun index => -1 - (index.val : Goldilocks)

def consumeField {n : Nat} (old : Status)
    (reply : Except Error (Fin n → Goldilocks)) : Status × (Fin n → Goldilocks) :=
  match reply with
  | .ok words => (old, words)
  | .error error => (recordPoison old error, poisonWords n)

/-- A direct downstream error returns before finish; only successful control
flow consults the sticky poison slot. This models error precedence, not reset. -/
def finish {A : Type*} (step : Step A) : Except Error A :=
  match step.result with
  | .error error => .error error
  | .ok value => match step.poison with
    | none => .ok value
    | some error => .error error

theorem first_poison_sticks (first later : Error) :
    recordPoison (some first) later = some first := rfl

theorem downstream_error_precedes_poison {A : Type*} (status : Status) (error : Error) :
    finish (⟨status, .error error⟩ : Step A) = .error error := rfl

theorem poisoned_success_is_failure {A : Type*} (error : Error) (value : A) :
    finish (⟨some error, .ok value⟩ : Step A) = .error error := rfl

def correction (points : Fin 6 → Goldilocks) : Goldilocks :=
  (∑ lane : Fin 64, ∏ opening : Fin 6, ((lane.val : Goldilocks) - points opening)) /
    ∏ opening : Fin 6, -points opening

/-- Includes actual inherited conservative checks, not merely sufficient rank. -/
def ValidPoints (points : Fin 6 → Goldilocks) : Prop :=
  Smz9WitnessInterpolationAdmissible points ∧
  (∀ opening, points opening ≠ 0) ∧ correction points ≠ 0 ∧
  (∀ opening, points opening ^ 64 ≠ 1) ∧
  (∀ opening, points opening ^ 35 ≠ 1) ∧
  (∀ opening, points opening ^ 63 ≠ 1)

structure PiopPlan where
  nonce : Nat
  points : Fin 6 → Goldilocks
  valid : ValidPoints points

/-- Source has16 trials, then replays the chosen request. The functional reply
argument models the SAME oracle input/counter history on replay, not fresh coins.
Field-XOF exhaustion supplies poison words and does not immediately return. -/
def piopLoop (answers : Nat → Except Error (Fin 6 → Goldilocks)) :
    Nat → Nat → Status → Step PiopPlan
  | 0, _, status => ⟨status, .error "smallwood opening nonce trial limit exhausted"⟩
  | fuel + 1, nonce, status =>
    let consumed := consumeField status (answers nonce)
    if valid : ValidPoints consumed.2 then
      let replay := consumeField consumed.1 (answers nonce)
      ⟨replay.1, .ok ⟨nonce, consumed.2, valid⟩⟩
    else piopLoop answers fuel (nonce + 1) consumed.1

def canonicalPiop (answers : Nat → Except Error (Fin 6 → Goldilocks))
    (status : Status) : Step PiopPlan := piopLoop answers 16 0 status

/-- Source first-distinct truncation, before sorting. All80 field words have
already been consumed, including those after the58th selected index. -/
def keepDecsCandidate (kept : List Nat) (word : Goldilocks) : List Nat :=
  if kept.length = 58 then kept
  else if word.val < (goldilocksModulus / 8388608) * 8388608 then
    let index := word.val % 8388608
    if index ∈ kept then kept else kept ++ [index]
  else kept

def insertIndex (index : Nat) : List Nat → List Nat
  | [] => [index]
  | first :: rest => if index ≤ first then index :: first :: rest
      else first :: insertIndex index rest

/-- Explicit80-draw source selector including delayed field-XOF poisoning.
The source coset map/Targets proof is a separate binding obligation. -/
def rawDecsSelector (status : Status)
    (reply : Except Error (Fin 80 → Goldilocks)) : Step (List Nat) :=
  let consumed := consumeField status reply
  let kept := (List.ofFn consumed.2).foldl keepDecsCandidate []
  if kept.length = 58 then
    ⟨consumed.1, .ok (kept.foldr insertIndex [])⟩
  else ⟨consumed.1, .error "fixed DECS sampler exhausted its candidate pool"⟩

/-- Each function has the source's public dependency signature. It is NOT an
assumed simulator equality. Connecting it to Rust hash framing/selector execution
and proving the head-factorization contract remain separate obligations.
The enclosing fixed root/oracle branch and public statement are captured here. -/
structure PublicControl where
  piop : D → Q → Step PiopPlan
  decs : D → Q → PiopPlan → W → P → Earlier → Status → Step Targets
  fallbackPiop : PiopPlan
  fallbackTargets : Targets

def plan (control : PublicControl) (d : D) (t : Q) : PiopPlan :=
  match (control.piop d t).result with
  | .ok selected => selected
  | .error _ => control.fallbackPiop

/-- PIOP failure never executes the later source selector. The total bijection
uses discarded fallback coordinates; successful-but-poisoned plans still proceed. -/
def selectLater (control : PublicControl) (d : D) (t : Q)
    (z : W) (s : P) (earlier : Earlier) : Step Targets :=
  let first := control.piop d t
  match first.result with
  | .error error => ⟨first.poison, .error error⟩
  | .ok selected => control.decs d t selected z s earlier first.poison

def targets (control : PublicControl) (d : D) (t : Q)
    (z : W) (s : P) (earlier : Earlier) : Targets :=
  match (selectLater control d t z s earlier).result with
  | .ok selected => selected
  | .error _ => control.fallbackTargets

def responseFirst : (Base × Response) ≃ (Response × ((W × P) × Tails)) where
  toFun value := (value.2, ((value.1.1, value.1.2.1), value.1.2.2))
  invFun value := ((value.2.1.1, value.2.1.2, value.2.2), value.1)
  left_inv _ := rfl
  right_inv _ := rfl

/-- Apply only the earlier joint mask equivalence, retaining the same tails. -/
def maskStage (model : Model) : Coins ≃ (Response × ((W × P) × Tails)) :=
  NativePrivateSpendQ58ChronologicalMasks.roleOrder.trans
    ((NativePrivateSpendQ58ChronologicalMasks.fiberEquiv
      (NativePrivateSpendQ58ChronologicalMasks.maskEquiv model)).trans responseFirst)

def remainder (values : Values) (model : Model) (control : PublicControl)
    (response : Response) : ((W × P) × Tails) ≃ ((W × P) × (Earlier × Later)) :=
  let selected := plan control response.1 response.2
  NativePrivateSpendQ58Wpcs.remainingEquiv values selected.points
    selected.valid.1 selected.valid.2.1 model response.1 response.2
      (targets control response.1 response.2)

/-- All232283 original coordinates become D,T,Z,S,E,L jointly. -/
def completeEquiv (values : Values) (model : Model) (control : PublicControl) : Coins ≃ View :=
  (maskStage model).trans
    (NativePrivateSpendQ58ChronologicalMasks.fiberEquiv (remainder values model control))

/-- Concrete mask chronology before W/PCS/same-tail feedback, including Q in
physical heads and the full D dependency of the unmasked PIOP response. -/
def completeOutput (values : Values) (model : Model) (control : PublicControl)
    (coins : Coins) : View :=
  let w := coins.1
  let q := coins.2.1
  let p := coins.2.2.1
  let tails := coins.2.2.2.1
  let d := NativePrivateSpendQ58ChronologicalMasks.decsOffset model.gamma
    (model.heads w p q) tails + coins.2.2.2.2
  let t := model.piopUnmasked w d + q
  ((d, t), remainder values model control (d, t) ((w, p), tails))

theorem complete_matches (values : Values) (model : Model) (control : PublicControl)
    (coins : Coins) : completeEquiv values model control coins =
      completeOutput values model control coins := rfl

theorem complete_joint_uniform (values : Values) (model : Model) (control : PublicControl) :
    pmfMap (uniformFintypePMF Coins) (completeOutput values model control) =
      uniformFintypePMF View :=
  uniform_pmf_map_equiv (completeEquiv values model control)

/-- D/T are retained algebraic coordinates. On failure there is no proof body;
an arbitrary external projection may additionally hide D/T, as the source does. -/
abbrev Body := Nat × W × P × Earlier × Targets × Later
abbrev Observation := Response × Except Error Body

def observation (control : PublicControl) (view : View) : Observation :=
  let d := view.1.1
  let t := view.1.2
  let first := control.piop d t
  (view.1, match first.result with
    | .error error => .error error
    | .ok selected =>
      let last := control.decs d t selected view.2.1.1 view.2.1.2 view.2.2.1 first.poison
      finish ⟨last.poison, last.result.map fun selectedTargets =>
        (selected.nonce, view.2.1.1, view.2.1.2, view.2.2.1, selectedTargets, view.2.2.2)⟩)

/-- Direct abort projection: neither conditioning nor renormalization. -/
theorem complete_abort_law (values : Values) (model : Model) (control : PublicControl) :
    pmfMap (uniformFintypePMF Coins)
      (observation control ∘ completeOutput values model control) =
      pmfMap (uniformFintypePMF View) (observation control) := by
  have law := congrArg (fun law => pmfMap law (observation control))
    (complete_joint_uniform values model control)
  rw [pmfMap_comp] at law
  exact law

def optionObservation (control : PublicControl) (view : View) : Response × Option Body :=
  (view.1, (observation control view).2.toOption)

theorem complete_option_law (values : Values) (model : Model) (control : PublicControl) :
    pmfMap (uniformFintypePMF Coins)
      (optionObservation control ∘ completeOutput values model control) =
      pmfMap (uniformFintypePMF View) (optionObservation control) := by
  have law := congrArg (fun law => pmfMap law (optionObservation control))
    (complete_joint_uniform values model control)
  rw [pmfMap_comp] at law
  exact law

/-- Initialized oracle/leaf state, branch weights, all old coins, exact errors
and future continuation remain INSIDE the kernel. This theorem supplies no
public-only-kernel premise and makes no independence inference from uniformity. -/
theorem initialized_kernel_transport {Branch Value : Type*}
    [Fintype Branch] [AddCommMonoid Value]
    (values : Values) (models : Branch → Model) (controls : Branch → PublicControl)
    (kernel : Branch → Coins → View → Observation → Value) :
    (∑ coins, ∑ branch, kernel branch coins
      (completeEquiv values (models branch) (controls branch) coins)
      (observation (controls branch)
        (completeEquiv values (models branch) (controls branch) coins))) =
    ∑ view, ∑ branch, kernel branch
      ((completeEquiv values (models branch) (controls branch)).symm view) view
      (observation (controls branch) view) := by
  rw [Finset.sum_comm]
  calc
    _ = ∑ branch, ∑ view, kernel branch
        ((completeEquiv values (models branch) (controls branch)).symm view) view
        (observation (controls branch) view) := by
      apply Finset.sum_congr rfl
      intro branch _
      let e := completeEquiv values (models branch) (controls branch)
      have reindex := e.sum_comp (fun view => kernel branch (e.symm view) view
        (observation (controls branch) view))
      simpa only [Equiv.symm_apply_apply] using reindex
    _ = _ := Finset.sum_comm

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58AbortComposition
