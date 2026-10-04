import Q38MeasuredCmsNonleafCore
import Q38MeasuredCmsNonleafShapeCore
import Q38WholeViewCmsSemantics
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch

/-!
# Minimal measured RP05 branch API

This file owns only the public-slice and trace-branch semantics needed to
identify a concrete measured branch with its unchanged total-oracle family.
It is independent of the post-final compiler and adaptive-opening modules.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

variable {Input Public BaseWork Other Result : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Public] [DecidableEq Public]
variable [Fintype BaseWork] [DecidableEq BaseWork]

abbrev Rp05LeafInput := Fin 2511 → HegemonCrypto.CanonicalBytes.Byte

abbrev PhaseState (Input Work : Type) := ResponseCmsState Input Work

structure CMSCompleteInstrument
    (Input DomainWork CodomainWork Outcome : Type)
    [Fintype Input] [DecidableEq Input]
    [Fintype DomainWork] [DecidableEq DomainWork]
    [Fintype CodomainWork] [DecidableEq CodomainWork]
    [Fintype Outcome] where
  branch : Outcome → PhaseState Input DomainWork → PhaseState Input CodomainWork
  complete : ∀ state, GloballyTotal state →
    (∑ outcome, normSquared (branch outcome state)) = normSquared state

def publicSlice (publicValue : Public)
    (state : PhaseState Input (Public × BaseWork)) : PhaseState Input BaseWork :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (publicValue, basis.workspace)
      database := basis.database }

def publicSliceBasisEquiv :
    Public × HegemonCrypto.CmsCompressedOracle.Basis
      Input DigestRegister DigestRegister BaseWork ≃
      HegemonCrypto.CmsCompressedOracle.Basis
        Input DigestRegister DigestRegister (Public × BaseWork) where
  toFun pair :=
    { input := pair.2.input
      phase := pair.2.phase
      workspace := (pair.1, pair.2.workspace)
      database := pair.2.database }
  invFun basis :=
    (basis.workspace.1,
      { input := basis.input
        phase := basis.phase
        workspace := basis.workspace.2
        database := basis.database })
  left_inv pair := by cases pair; rfl
  right_inv basis := by cases basis; rfl

omit [DecidableEq Public] [DecidableEq BaseWork] in
theorem public_slice_complete (state : PhaseState Input (Public × BaseWork)) :
    (∑ publicValue : Public, normSquared (publicSlice publicValue state)) =
      normSquared state := by
  unfold normSquared publicSlice
  change (∑ publicValue : Public,
      ∑ basis : HegemonCrypto.CmsCompressedOracle.Basis
        Input DigestRegister DigestRegister BaseWork,
        Complex.normSq (state (publicSliceBasisEquiv (publicValue, basis)))) =
    ∑ basis : HegemonCrypto.CmsCompressedOracle.Basis
      Input DigestRegister DigestRegister (Public × BaseWork),
      Complex.normSq (state basis)
  calc
    _ = ∑ pair : Public × HegemonCrypto.CmsCompressedOracle.Basis
          Input DigestRegister DigestRegister BaseWork,
          Complex.normSq (state (publicSliceBasisEquiv pair)) := by
            rw [Fintype.sum_prod_type]
    _ = ∑ basis : HegemonCrypto.CmsCompressedOracle.Basis
          Input DigestRegister DigestRegister (Public × BaseWork),
          Complex.normSq (state basis) := by
            exact publicSliceBasisEquiv.sum_comp
              (fun basis => Complex.normSq (state basis))

omit [Fintype Input] [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
theorem public_slice_decompress_at (publicValue : Public) (input : Input)
    (state : PhaseState Input (Public × BaseWork)) :
    publicSlice publicValue (decompressAt input state) =
      decompressAt input (publicSlice publicValue state) := rfl

theorem public_slice_decompress_list (publicValue : Public) (inputs : List Input)
    (state : PhaseState Input (Public × BaseWork)) :
    publicSlice publicValue (decompressList inputs state) =
      decompressList inputs (publicSlice publicValue state) := by
  induction inputs with
  | nil => rfl
  | cons input tail ih =>
      rw [decompress_list_cons, decompress_list_cons,
        public_slice_decompress_at, ih]

theorem public_slice_global_decompress (publicValue : Public)
    (state : PhaseState Input (Public × BaseWork)) :
    publicSlice publicValue (globalDecompress state) =
      globalDecompress (publicSlice publicValue state) := by
  unfold globalDecompress
  exact public_slice_decompress_list publicValue _ state

theorem public_slice_globally_total (publicValue : Public)
    (state : PhaseState Input (Public × BaseWork))
    (total : GloballyTotal state) : GloballyTotal (publicSlice publicValue state) := by
  intro input
  rw [← public_slice_global_decompress]
  intro basis absent
  exact total input
    { input := basis.input
      phase := basis.phase
      workspace := (publicValue, basis.workspace)
      database := basis.database } absent

def publicSliceFamily (publicValue : Public)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Public × BaseWork)) :
    OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := BaseWork) :=
  fun oracle register =>
    family oracle (register.1, register.2.1, publicValue, register.2.2)

omit [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
theorem public_slice_total_oracle_family_state (publicValue : Public)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Public × BaseWork)) :
    publicSlice publicValue (totalOracleFamilyState family) =
      totalOracleFamilyState (publicSliceFamily publicValue family) := by
  funext basis
  rfl

omit [Fintype BaseWork] [DecidableEq BaseWork] in
@[simp] theorem total_oracle_family_state_zero :
    totalOracleFamilyState
        (0 : OracleRegisterFamily (Input := Input)
          (Output := DigestRegister) (Phase := DigestRegister)
          (Workspace := BaseWork)) = 0 := by
  funext basis
  simp [totalOracleFamilyState]

omit [Fintype Input] [DecidableEq Input] [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
theorem public_slice_response_fourier (publicValue : Public)
    (state : PhaseState Input (Public × BaseWork)) :
    publicSlice publicValue (responseFourierState state) =
      responseFourierState (publicSlice publicValue state) := by
  funext basis
  rfl

theorem public_slice_phase_encode (publicValue : Public)
    (state : PhaseState Input (Public × BaseWork)) :
    publicSlice publicValue (phaseEncode state) =
      phaseEncode (publicSlice publicValue state) := by
  unfold phaseEncode
  rw [public_slice_global_decompress, public_slice_response_fourier]

omit [Fintype Input] [DecidableEq Input] [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
def traceStateWithRead {StateType : Type} [Zero StateType]
    (readStep : Other → DigestRegister → StateType → StateType) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel → StateType → StateType
  | 0, .done _, _, state => state
  | 0, .read _ _, _, _ => 0
  | _ + 1, .done _, trace, state =>
      match trace with
      | none => state
      | some _ => 0
  | fuel + 1, .read input next, trace, state =>
      match trace with
      | none => 0
      | some (answer, tail) =>
          traceStateWithRead readStep fuel (next answer) tail
            (readStep input answer state)

omit [Fintype Input] [DecidableEq Input] [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
def traceFamilyWithRead {FamilyType : Type} [Zero FamilyType]
    (readStep : Other → DigestRegister → FamilyType → FamilyType) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel → FamilyType → FamilyType
  | 0, .done _, _, family => family
  | 0, .read _ _, _, _ => 0
  | _ + 1, .done _, trace, family =>
      match trace with
      | none => family
      | some _ => 0
  | fuel + 1, .read input next, trace, family =>
      match trace with
      | none => 0
      | some (answer, tail) =>
          traceFamilyWithRead readStep fuel (next answer) tail
            (readStep input answer family)

omit [Fintype Input] [DecidableEq Input] [Fintype Public] [DecidableEq Public]
  [Fintype BaseWork] [DecidableEq BaseWork] in
theorem trace_recursion_with_read_filter
    {StateType FamilyType : Type} [Zero StateType] [Zero FamilyType]
    (readState : Other → DigestRegister → StateType → StateType)
    (readFamily : Other → DigestRegister → FamilyType → FamilyType)
    (encode : FamilyType → StateType)
    (zeroLaw : encode 0 = 0)
    (readLaw : ∀ input answer family,
      readState input answer (encode family) =
        encode (readFamily input answer family)) :
    ∀ fuel (program : NonleafProgram Other Result)
      (trace : PublicTrace DigestRegister fuel) (family : FamilyType),
      traceStateWithRead readState fuel program trace (encode family) =
        encode (traceFamilyWithRead readFamily fuel program trace family) := by
  intro fuel
  induction fuel with
  | zero =>
      intro program trace family
      cases program <;>
        simp [traceStateWithRead, traceFamilyWithRead, zeroLaw]
  | succ fuel ih =>
      intro program trace family
      cases program with
      | done result =>
          cases trace <;>
            simp [traceStateWithRead, traceFamilyWithRead, zeroLaw]
      | read input next =>
          cases trace with
          | none =>
              simp [traceStateWithRead, traceFamilyWithRead, zeroLaw]
          | some branch =>
              rcases branch with ⟨answer, tail⟩
              simp only [traceStateWithRead, traceFamilyWithRead]
              rw [readLaw]
              exact ih (next answer) tail (readFamily input answer family)

def encodedOracleFamilyState
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := BaseWork)) : PhaseState Input BaseWork :=
  phaseEncode (totalOracleFamilyState family)

def phaseOracleReadStep (embed : Other → Input) :
    Other → DigestRegister → PhaseState Input BaseWork → PhaseState Input BaseWork :=
  fun input answer state => phaseReadBranch (embed input) answer state

def oracleFamilyReadStep (embed : Other → Input) :
    Other → DigestRegister → OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := BaseWork) → OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := BaseWork) :=
  fun input answer family oracle =>
    if oracle (embed input) = answer then family oracle else 0

def phaseTraceState (embed : Other → Input) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel → PhaseState Input BaseWork →
        PhaseState Input BaseWork :=
  traceStateWithRead (phaseOracleReadStep embed)

def traceOracleFamily (embed : Other → Input) :
    (fuel : Nat) → NonleafProgram Other Result →
      PublicTrace DigestRegister fuel →
      OracleRegisterFamily (Input := Input) (Output := DigestRegister)
        (Phase := DigestRegister) (Workspace := BaseWork) →
      OracleRegisterFamily (Input := Input) (Output := DigestRegister)
        (Phase := DigestRegister) (Workspace := BaseWork) :=
  traceFamilyWithRead (oracleFamilyReadStep embed)

omit [Fintype Input] [Fintype BaseWork] [DecidableEq BaseWork] in
theorem decompress_at_zero (input : Input) :
    decompressAt input (0 : PhaseState Input BaseWork) = 0 := by
  funext basis
  change (decompressFiber
      (databaseFiberState (0 : PhaseState Input BaseWork)
        basis.input basis.phase basis.workspace input
        (databaseEquiv input basis.database).1)).ofLp
      (databaseEquiv input basis.database).2 = 0
  have fiberZero :
      databaseFiberState (0 : PhaseState Input BaseWork)
        basis.input basis.phase basis.workspace input
        (databaseEquiv input basis.database).1 = 0 := by
    ext coordinate
    simp [databaseFiberState]
  rw [fiberZero, map_zero]
  simp

omit [Fintype Input] [DecidableEq Input]
  [Fintype BaseWork] [DecidableEq BaseWork] in
theorem response_fourier_zero :
    responseFourierState (0 : PhaseState Input BaseWork) = 0 := by
  funext basis
  simp [responseFourierState, digestResponseFourier]

theorem decompress_list_zero (inputs : List Input) :
    decompressList inputs (0 : PhaseState Input BaseWork) = 0 := by
  induction inputs with
  | nil => rfl
  | cons input tail ih =>
      rw [decompress_list_cons, ih, decompress_at_zero]

@[simp] theorem phase_encode_zero :
    phaseEncode (0 : PhaseState Input BaseWork) = 0 := by
  unfold phaseEncode globalDecompress
  rw [response_fourier_zero]
  exact decompress_list_zero _

theorem phase_read_total_oracle_family
    (embed : Other → Input) (input : Other) (answer : DigestRegister)
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := BaseWork)) :
    phaseReadBranch (embed input) answer
        (phaseEncode (totalOracleFamilyState family)) =
      phaseEncode (totalOracleFamilyState
        (fun oracle => if oracle (embed input) = answer then family oracle else 0)) := by
  unfold phaseReadBranch
  rw [phase_decode_encode, databaseReadBranch_totalOracleFamilyState]

theorem encoded_oracle_family_state_zero :
    encodedOracleFamilyState
        (0 : OracleRegisterFamily (Input := Input)
          (Output := DigestRegister) (Phase := DigestRegister)
          (Workspace := BaseWork)) = 0 := by
  simp only [encodedOracleFamilyState, total_oracle_family_state_zero,
    phase_encode_zero]

theorem phase_trace_total_oracle_family
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (trace : PublicTrace DigestRegister fuel)
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := BaseWork)) :
    phaseTraceState embed fuel program trace
        (phaseEncode (totalOracleFamilyState family)) =
      phaseEncode (totalOracleFamilyState
        (traceOracleFamily embed fuel program trace family)) := by
  change traceStateWithRead (phaseOracleReadStep embed)
      fuel program trace (encodedOracleFamilyState family) =
    encodedOracleFamilyState
      (traceFamilyWithRead (oracleFamilyReadStep embed) fuel program trace family)
  exact trace_recursion_with_read_filter
    (readState := phaseOracleReadStep embed)
    (readFamily := oracleFamilyReadStep embed)
    (encode := encodedOracleFamilyState)
    (zeroLaw := encoded_oracle_family_state_zero)
    (readLaw := phase_read_total_oracle_family embed)
    fuel program trace family

theorem phase_trace_eq_trace_state
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (trace : PublicTrace DigestRegister fuel)
    (state : PhaseState Input BaseWork) :
    phaseTraceState embed fuel program trace state =
      traceState embed fuel program trace state := by
  induction fuel generalizing program state with
  | zero => cases program <;> rfl
  | succ fuel ih =>
      cases program with
      | done result => cases trace <;> rfl
      | read input next =>
          cases trace with
          | none => rfl
          | some branch =>
              rcases branch with ⟨answer, tail⟩
              simp only [phaseTraceState, traceStateWithRead, phaseOracleReadStep,
                traceState]
              rw [phase_read_branch_eq_measured]
              exact ih (next answer) tail
                (measuredReadBranch (embed input) answer state)

theorem phase_trace_complete
    (embed : Other → Input) (fuel : Nat)
    (program : NonleafProgram Other Result)
    (enough : NonleafProgram.readCount program ≤ fuel)
    (state : PhaseState Input BaseWork) (total : GloballyTotal state) :
    (∑ trace : PublicTrace DigestRegister fuel,
      normSquared (phaseTraceState embed fuel program trace state)) =
      normSquared state := by
  simp_rw [phase_trace_eq_trace_state embed fuel program]
  exact trace_state_complete embed fuel program enough state total

def measuredBranchFamily
    (embed : Other → Input) (fuel : Nat)
    (program : Public → NonleafProgram Other Result)
    (outcome : Public × PublicTrace DigestRegister fuel)
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Public × BaseWork)) :
    OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := BaseWork) :=
  traceOracleFamily embed fuel (program outcome.1) outcome.2
    (publicSliceFamily outcome.1 family)

theorem measured_instrument_branch_total_oracle_family
    (embed : Other → Input) (fuel : Nat)
    (program : Public → NonleafProgram Other Result)
    (_enough : ∀ publicValue, NonleafProgram.readCount (program publicValue) ≤ fuel)
    (outcome : Public × PublicTrace DigestRegister fuel)
    (family : OracleRegisterFamily (Input := Input)
      (Output := DigestRegister) (Phase := DigestRegister)
      (Workspace := Public × BaseWork)) :
    phaseTraceState embed fuel (program outcome.1) outcome.2
        (publicSlice outcome.1 (phaseEncode (totalOracleFamilyState family))) =
      phaseEncode (totalOracleFamilyState
        (measuredBranchFamily embed fuel program outcome family)) := by
  rw [public_slice_phase_encode, public_slice_total_oracle_family_state]
  exact phase_trace_total_oracle_family embed fuel (program outcome.1)
    outcome.2 (publicSliceFamily outcome.1 family)

def measuredInstrument
    (embed : Other → Input) (fuel : Nat)
    (program : Public → NonleafProgram Other Result)
    (enough : ∀ publicValue, NonleafProgram.readCount (program publicValue) ≤ fuel) :
    CMSCompleteInstrument Input (Public × BaseWork) BaseWork
      (Public × PublicTrace DigestRegister fuel) where
  branch outcome state :=
    phaseTraceState embed fuel (program outcome.1) outcome.2
      (publicSlice outcome.1 state)
  complete state total := by
    rw [Fintype.sum_prod_type]
    calc
      _ = ∑ publicValue : Public, normSquared (publicSlice publicValue state) := by
        apply Finset.sum_congr rfl
        intro publicValue _
        exact phase_trace_complete embed fuel (program publicValue) (enough publicValue)
          (publicSlice publicValue state)
          (public_slice_globally_total publicValue state total)
      _ = normSquared state := public_slice_complete state

def rp05PiopMeasuredInstrument
    {Other : Type} [Fintype Other] [DecidableEq Other]
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (enough : ∀ reply : Q38DecsResponse,
      NonleafProgram.readCount (piopSuffix shape stage reply) ≤ fuel) :
    CMSCompleteInstrument (Rp05LeafInput ⊕ Other)
      (Q38DecsResponse × BaseWork) BaseWork
      (Q38DecsResponse × PublicTrace DigestRegister fuel) :=
  measuredInstrument (Input := Rp05LeafInput ⊕ Other)
    (Public := Q38DecsResponse) (BaseWork := BaseWork)
    Sum.inr fuel (fun reply => piopSuffix shape stage reply) enough

theorem rp05_piop_branch_total_oracle_family
    {Other : Type} [Fintype Other] [DecidableEq Other]
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (fuel : Nat) (shape : Q38PrefinalShape Other) (stage : DecsStage)
    (enough : ∀ reply : Q38DecsResponse,
      NonleafProgram.readCount (piopSuffix shape stage reply) ≤ fuel)
    (outcome : Q38DecsResponse × PublicTrace DigestRegister fuel)
    (family : OracleRegisterFamily
      (Input := Rp05LeafInput ⊕ Other) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Q38DecsResponse × BaseWork)) :
    (rp05PiopMeasuredInstrument fuel shape stage enough).branch outcome
        (phaseEncode (totalOracleFamilyState family)) =
      phaseEncode (totalOracleFamilyState
        (measuredBranchFamily (Input := Rp05LeafInput ⊕ Other)
          (Public := Q38DecsResponse) (BaseWork := BaseWork) Sum.inr fuel
          (fun reply => piopSuffix shape stage reply) outcome family)) := by
  simpa [rp05PiopMeasuredInstrument, measuredInstrument] using
    measured_instrument_branch_total_oracle_family Sum.inr fuel
      (fun reply => piopSuffix shape stage reply) enough outcome family

end
end HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
