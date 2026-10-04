import Q38Rp05PostFinalCompiler
import Q38Rp05MeasuredBranchCore
import Q38Rp05MeasuredInstrument
import PrivacyStateRefinementLunaWorkspaceAssoc

/-!
# RP05 measured-trace oracle-family instrument

The public answer trace is a measurement of the persistent oracle database,
not an instrument on the adversary's query/work register alone.  This file
records the missing exact representation bridge: a trace restricts the outer
total-oracle family at precisely the answers in that trace, and phase-basis
execution of the corresponding successive read projectors is the encoding of
that restricted family.  Noncanonical and fuel-exhausted traces are retained
as zero branches.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Work Other Result : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

abbrev Family (Input Work : Type) := OracleRegisterFamily
  (Input := Input) (Output := DigestRegister)
  (Phase := DigestRegister) (Workspace := Work)

abbrev PhaseState (Input Work : Type) := ResponseCmsState Input Work

/-- The actual phase-basis branch obtained by successively measuring every
answer in a padded public trace. -/
def phaseTraceState (embed : Other → Input) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel → PhaseState Input Work → PhaseState Input Work :=
  Q38Rp05MeasuredInstrument.phaseTraceState embed

/-- Pointwise restriction of the purified total-oracle family selected by
the same answer trace.  The family is not reconstructed after the branch and
therefore remains indexed by the common old oracle. -/
def traceFamily (embed : Other → Input) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel → Family Input Work → Family Input Work :=
  Q38Rp05MeasuredInstrument.traceOracleFamily embed

/-- Exact intertwining of the successive physical read projectors with
restriction of the outer total-oracle family.  In particular the branch state
and all decoded parameters are conditioned on the same oracle answers. -/
theorem phase_trace_state_total_oracle_family
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (trace : PublicTrace DigestRegister fuel) (family : Family Input Work) :
    phaseTraceState embed fuel program trace
        (phaseEncode (totalOracleFamilyState family)) =
      phaseEncode (totalOracleFamilyState
        (traceFamily embed fuel program trace family)) := by
  exact Q38Rp05MeasuredInstrument.phase_trace_total_oracle_family
    embed fuel program trace family

/-- The phase trace is definitionally the existing measured-CMS trace.  This
lets its already-proved orthogonal completeness theorem be used without a
second normalization or a detached trace distribution. -/
theorem phase_trace_state_eq_measured_trace
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (trace : PublicTrace DigestRegister fuel) (state : PhaseState Input Work) :
    phaseTraceState embed fuel program trace state =
      traceState embed fuel program trace state := by
  exact Q38Rp05MeasuredInstrument.phase_trace_eq_trace_state
    embed fuel program trace state

/-- Completeness of the concrete public-trace instrument on every reachable
total-database phase state.  All abort/padding branches occur in the finite
sum; none is conditioned away or renormalized. -/
theorem phase_trace_state_complete
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (state : PhaseState Input Work) (total : GloballyTotal state) :
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (phaseTraceState embed fuel program trace state)) =
      normSquared state := by
  simp_rw [phase_trace_state_eq_measured_trace embed fuel program]
  exact trace_state_complete embed fuel program enough state total

/-- Total-oracle-family specialization of trace completeness.  Together with
`phase_trace_state_total_oracle_family`, this is the mass ledger required to
apply a normalized P8/P9 comparison separately to every *same-prior* branch
and sum the resulting quadratic branch weights exactly. -/
theorem phase_trace_total_oracle_family_complete
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (family : Family Input Work) :
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (phaseTraceState embed fuel program trace
        (phaseEncode (totalOracleFamilyState family)))) =
      normSquared (phaseEncode (totalOracleFamilyState family)) := by
  exact phase_trace_state_complete embed fuel program enough
    (phaseEncode (totalOracleFamilyState family))
    (HegemonCrypto.SmallWood.PrivacyStateRefinementLunaWorkspaceAssoc.phaseEncodedFamily_globallyTotal
      family)

section InitializedAlignment

variable {Index Branch BaseWork : Type}
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

omit [Fintype Input] [DecidableEq Input]
  [Fintype Branch] [DecidableEq Branch]
  [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The response Fourier transform does not touch the appended saved-label
table.  This is the exact register-coordinate commutation needed before any
controlled swap is applied. -/
theorem response_fourier_append_uniform_labels
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    responseFourierState
        (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index)
        (responseFourierState state) := by
  exact Q38Rp05MeasuredInstrument.response_fourier_append_uniform_labels state

/-- Phase encoding commutes with adding the independent uniform saved-label
table. -/
theorem phase_encode_append_uniform_labels
    (state : ResponseCmsState Input (Branch × BaseWork)) :
    phaseEncode (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index) (phaseEncode state) := by
  exact Q38Rp05MeasuredInstrument.phase_encode_append_uniform_labels state

/-- Exact base-prior alignment used by P7.  The canonical family is formed
from the unchanged pre-resampling state.  Appending its independent uniform
saved-label table and returning to phase coordinates reconstructs
`initializedFreshState (coreOfCmsState state)` pointwise.  No canonical family
of the tape-dependent changed state appears. -/
theorem initialized_phase_family_canonical_eq_initialized_fresh
    (state : ResponseCmsState Input (Branch × BaseWork))
    (supported : TotalDatabaseSupport (phaseDecode state)) :
    initializedPhaseFamily (Environment := Index)
        (canonicalTotalFamily (phaseDecode state)) =
      initializedFreshState (Index := Index) (coreOfCmsState state) := by
  exact Q38Rp05MeasuredInstrument.initialized_phase_family_of_same_reached
    state supported

end InitializedAlignment

end
end HegemonCrypto.SmallWood.Q38Rp05FinalPrivacyInstrument
