import Q38AdaptiveOpeningRetainedReveal

/-! Literal physical games, isolated from their composition proof for
bounded serial validation. All declarations are preserved verbatim. -/
namespace HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid V8Smz9MeasuredSourceHiddenPatch
open V8Smz9HonestLeafBatch V8SmzaLeafFrameHybrid V8SmzaRetainedOpenedOverlay V8SmzaSelectionFeedback
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Other Work Job : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

def fullOracle (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) : Input Other → DigestRegister :=
  fullSourceOverlay old other targets Finset.univ (fun _ => header salt) (fun i => suffix (data i)) tapes

def realReveal (randomized : Bool) (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) → Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) :
    PhysicalKernel (Input := Input Other) (Work := Work) Job :=
  programKernel randomized (fun job => revealProgram (unopened job) (program job) tapes)
    (fun _ => fullOracle old other targets salt data tapes)

def publicReveal (randomized : Bool) (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) → Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : Tapes) :
    PhysicalKernel (Input := Input Other) (Work := Work) Job :=
  programKernel randomized (fun job => revealProgram (unopened job) (program job) tapes)
    (fun job => fullSourceOverlay old other targets (unopened job)ᶜ
      (fun _ => header salt) (fun i => suffix (data i)) tapes)

def adaptiveFullGame (randomized : Bool) (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) → Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) : ℝ :=
  uniformAverage fun tapes : Tapes => execute selecPrefix
    (realReveal randomized unopened program old other targets salt data tapes).observe
    (fullOracle old other targets salt data tapes) state

def adaptivePublicGame (randomized : Bool) (selecPrefix : Selection (Input Other) Work Job)
    (unopened : Job → Finset LeafIndex)
    (program : (job : Job) → (Opened (unopened job) → LeafTape) → Program (Input Other) Work)
    (old : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState (Input := Input Other) (Work := Work)) : ℝ :=
  uniformAverage fun tapes : Tapes => execute selecPrefix
    (publicReveal randomized unopened program old other targets salt data tapes).observe
    (Sum.elim old other) state

end
end HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
