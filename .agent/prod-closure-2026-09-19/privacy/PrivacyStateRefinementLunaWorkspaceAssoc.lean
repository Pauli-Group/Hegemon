import Q38Rp05MeasuredInstrument
import Q38Rp05ChronologicalAlgebra
import Q38MeasuredCmsNonleafCore

/-!
# Fresh-label workspace refinement for the RP05 PIOP instrument

`initializedFreshState` stores workspace as `Labels × (D × Work)`, while the
measured PIOP interface uses `D × BaseWork`.  Set
`BaseWork := Labels × Work`: the following explicit coordinate bijection
reassociates the state without tracing out or measuring the fresh label table.
The branch mass ledger is then exactly the existing complete-instrument
identity on the transported state.  This file does not identify a
post-final continuation: that continuation must run on the reply slice while
retaining the labels and oracle database.
-/
namespace HegemonCrypto.SmallWood.PrivacyStateRefinementLunaWorkspaceAssoc

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

/-- The concrete product-coordinate isomorphism needed to specialize the
PIOP instrument with `BaseWork = Labels × Work`. -/
def freshReplyWorkspaceEquiv (Labels D Work : Type) :
    Labels × (D × Work) ≃ D × (Labels × Work) where
  toFun x := (x.2.1, (x.1, x.2.2))
  invFun x := (x.2.1, (x.1, x.2.2))
  left_inv x := by cases x with | mk labels rest => cases rest; rfl
  right_inv x := by cases x with | mk reply rest => cases rest; rfl

/-- Transport a complete CMS state along the workspace coordinate isomorphism.
All input, phase, and compressed-database coordinates are copied verbatim. -/
def transportFreshReplyWorkspace
    {Input Output Phase Labels D Work : Type}
    (state : State Input Output Phase (Labels × (D × Work))) :
    State Input Output Phase (D × (Labels × Work)) :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.2.1,
        (basis.workspace.1, basis.workspace.2.2))
      database := basis.database }

/-- The state transport is a permutation of the full CMS basis, hence preserves
the squared norm exactly.  The proof is pointwise reindexing by the workspace
equivalence; no normalization or branch conditioning occurs. -/
theorem transportFreshReplyWorkspace_normSquared
    {Input Output Phase Labels D Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D]
    [Fintype Work] [DecidableEq Work]
    (state : State Input Output Phase (Labels × (D × Work))) :
    normSquared (transportFreshReplyWorkspace state) = normSquared state := by
  classical
  unfold normSquared transportFreshReplyWorkspace
  let basisEquiv :
      Basis Input Output Phase (D × (Labels × Work)) ≃
        Basis Input Output Phase (Labels × (D × Work)) :=
    { toFun := fun b =>
        { input := b.input
          phase := b.phase
          workspace := (b.workspace.2.1, (b.workspace.1, b.workspace.2.2))
          database := b.database }
      invFun := fun b =>
        { input := b.input
          phase := b.phase
          workspace := (b.workspace.2.1, (b.workspace.1, b.workspace.2.2))
          database := b.database }
      left_inv := by intro b; cases b; rfl
      right_inv := by intro b; cases b; rfl }
  exact basisEquiv.sum_comp (fun b => Complex.normSq (state b))

/-- The workspace coordinate permutation is invisible to response Fourier
transformation: every summand stays in the same input, workspace, and database
fiber. -/
theorem transportFreshReplyWorkspace_responseFourier
    {Input Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D]
    [Fintype Work] [DecidableEq Work]
    (state : ResponseCmsState Input (Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D)
        (responseFourierState state) =
      responseFourierState
        (transportFreshReplyWorkspace (D := D) state) := by
  funext basis
  rfl

/-- A compressed coordinate query commutes with the same workspace
reassociation because it changes only the input, phase, and database axes. -/
theorem transportFreshReplyWorkspace_decompressAt
    {Input Output Phase Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D] [Fintype Work] [DecidableEq Work]
    (input : Input)
    (state : State Input Output Phase (Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D) (decompressAt input state) =
      decompressAt input (transportFreshReplyWorkspace (D := D) state) := by
  rfl

theorem transportFreshReplyWorkspace_globalDecompress
    {Input Output Phase Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D] [Fintype Work] [DecidableEq Work]
    (state : State Input Output Phase (Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D) (globalDecompress state) =
      globalDecompress (transportFreshReplyWorkspace (D := D) state) := by
  unfold globalDecompress
  induction (Finset.univ : Finset Input).toList with
  | nil => rfl
  | cons input rest ih =>
      simp only [decompress_list_cons]
      rw [transportFreshReplyWorkspace_decompressAt, ih]

/-- Consequently the workspace map commutes pointwise with the actual
`phaseEncode = globalDecompress ∘ responseFourierState` used by the measured
instrument. -/
theorem transportFreshReplyWorkspace_phaseEncode
    {Input Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D]
    [Fintype Work] [DecidableEq Work]
    (state : ResponseCmsState Input (Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D) (phaseEncode state) =
      phaseEncode (transportFreshReplyWorkspace (D := D) state) := by
  unfold phaseEncode
  rw [transportFreshReplyWorkspace_globalDecompress,
    transportFreshReplyWorkspace_responseFourier]

/-- Reassociate the public reply into the inner workspace of a purified
oracle-register family. -/
def reassociateFreshReplyFamily
    {Input Output Phase Labels Work : Type}
    (family : OracleRegisterFamily (Input := Input) (Output := Output)
      (Phase := Phase) (Workspace := Labels × (D × Work))) :
    OracleRegisterFamily (Input := Input) (Output := Output)
      (Phase := Phase) (Workspace := D × (Labels × Work)) :=
  fun oracle registers =>
    family oracle
      (registers.1, registers.2.1,
        (freshReplyWorkspaceEquiv Labels D Work).invFun registers.2.2)

/-- Purifying an oracle family commutes with the concrete workspace
reassociation, including the complete total-database label. -/
theorem transportFreshReplyWorkspace_totalOracleFamilyState
    {Input Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D] [Fintype Work] [DecidableEq Work]
    (family : OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D) (totalOracleFamilyState family) =
      totalOracleFamilyState (reassociateFreshReplyFamily family) := by
  funext basis
  rfl

/-- Pointwise bridge requested by the actual measured instrument: the
workspace reassociation commutes with `phaseEncode (totalOracleFamilyState …)`
and preserves each purified-oracle amplitude exactly. -/
theorem transportFreshReplyWorkspace_phaseEncodedFamily
    {Input Labels Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Labels] [DecidableEq Labels]
    [Fintype D] [DecidableEq D] [Fintype Work] [DecidableEq Work]
    (family : OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Labels × (D × Work))) :
    transportFreshReplyWorkspace (D := D)
        (phaseEncode (totalOracleFamilyState family)) =
      phaseEncode
        (totalOracleFamilyState
          (reassociateFreshReplyFamily family)) := by
  rw [transportFreshReplyWorkspace_phaseEncode,
    transportFreshReplyWorkspace_totalOracleFamilyState]

/-- Apply the response Fourier transform independently in every oracle
branch. -/
def responseFourierOracleFamily
    {Input Work : Type}
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Work)) :
    OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work) :=
  fun oracle => responseFourierRegisters (family oracle)

/-- The response Fourier transform preserves the purified total-oracle form;
this is the support fact needed to invoke instrument completeness without
assuming `GloballyTotal` as a free premise. -/
theorem responseFourier_totalOracleFamilyState
    {Input Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Work] [DecidableEq Work]
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Work)) :
    responseFourierState (totalOracleFamilyState family) =
      totalOracleFamilyState (responseFourierOracleFamily family) := by
  have inverseEq :
      responseFourierInverseState (responseFourierState
        (totalOracleFamilyState family)) =
      responseFourierInverseState
        (totalOracleFamilyState (responseFourierOracleFamily family)) := by
    rw [response_fourier_inverse_left,
      response_fourier_inverse_total_oracle_family_state]
    simp only [responseFourierOracleFamily,
      response_fourier_registers_inverse_left]
  have forwardEq := congrArg responseFourierState inverseEq
  simpa only [response_fourier_inverse_right] using forwardEq

/-- An encoded purified family is globally total because decompressing it
returns a response-Fourier-transformed purified family over the same complete
oracle tables. -/
theorem phaseEncodedFamily_globallyTotal
    {Input Work : Type}
    [Fintype Input] [DecidableEq Input]
    [Fintype Work] [DecidableEq Work]
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Work)) :
    GloballyTotal (phaseEncode (totalOracleFamilyState family)) := by
  apply globally_total_of_total_oracle_simulation
    (phaseEncode (totalOracleFamilyState family))
    (responseFourierOracleFamily family)
  unfold phaseEncode
  rw [global_decompress_involutive,
    responseFourier_totalOracleFamilyState]

/-- Exact measured Born mass for the reassociated, phase-encoded purified
RP05 family. Totality is derived from the complete-oracle family itself; no
arbitrary branch weights or normalized-branch assumptions are supplied. -/
theorem rp05_reassociated_family_born_mass
    {Other Work : Type}
    [Fintype Other] [DecidableEq Other]
    [Fintype Work] [DecidableEq Work]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (enough : ∀ reply : D,
      NonleafProgram.readCount (piopSuffix shape stage reply) ≤ fuel)
    (family : OracleRegisterFamily
      (Input := Rp05LeafInput ⊕ Other) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (LeafIndex → DigestRegister) × (D × Work))) :
    (∑ outcome : D × PublicTrace DigestRegister fuel,
      normSquared
        ((rp05PiopMeasuredInstrument fuel shape stage enough).branch
          outcome (transportFreshReplyWorkspace (D := D)
            (phaseEncode (totalOracleFamilyState family))))) =
      normSquared (phaseEncode (totalOracleFamilyState family)) := by
  let targetFamily := reassociateFreshReplyFamily family
  have stateAlignment :=
    transportFreshReplyWorkspace_phaseEncodedFamily family
  have bornComplete :=
    (rp05PiopMeasuredInstrument fuel shape stage enough).complete
      (phaseEncode (totalOracleFamilyState targetFamily))
      (phaseEncodedFamily_globallyTotal targetFamily)
  calc
    _ = ∑ outcome : D × PublicTrace DigestRegister fuel,
        normSquared
          ((rp05PiopMeasuredInstrument fuel shape stage enough).branch
            outcome (phaseEncode (totalOracleFamilyState targetFamily))) := by
          rw [stateAlignment]
    _ = normSquared (phaseEncode (totalOracleFamilyState targetFamily)) :=
          bornComplete
    _ = normSquared
        (transportFreshReplyWorkspace (D := D)
          (phaseEncode (totalOracleFamilyState family))) := by
          rw [← stateAlignment]
    _ = normSquared (phaseEncode (totalOracleFamilyState family)) :=
          transportFreshReplyWorkspace_normSquared _

end
end HegemonCrypto.SmallWood.PrivacyStateRefinementLunaWorkspaceAssoc
