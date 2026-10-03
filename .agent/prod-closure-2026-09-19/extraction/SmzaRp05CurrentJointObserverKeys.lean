import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05ExecutableBindSupport

/-! The terminal whole-prefix observer repeats an already included unit
program. Its all-answer reachable grouped-key universe is therefore exactly
the original joint universe. This module transports only the dependent CMS
carrier over that genuine universe equality; branch correspondence and mass
factorization remain separate statements. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverKeys

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05CurrentJointAcceptedExecution
  (firstAcceptedVerifierProgram secondAcceptedVerifierProgram
    sequential_first_groups_subset twoAcceptedProgram_eq_sequentialUnitProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open V8SmzaOracleParser (RawInput)
open HegemonCrypto.CmsCompressedOracle
open scoped Classical

noncomputable section
set_option autoImplicit false

/-- Replay the first accepted whole prefix after the actual unit joint
chronology. The replay carries its own real program branch. -/
def terminalWholePrefixObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program Unit :=
  (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂).bind fun _ =>
      firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁

/-- The original first whole prefix is contained in the all-digest support of
the actual two-transaction unit program. -/
theorem first_prefix_groups_subset_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    groups (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁) ⊆
      groups (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  rw [twoAcceptedProgram_eq_sequentialUnitProgram]
  exact sequential_first_groups_subset

/-- Replaying that prefix adds no ex-ante grouped key, including on digest
continuations that are not selected by the accepted branch. -/
theorem terminal_observer_groups_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    groups (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) =
    groups (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  exact SmzaRp05ExecutableBindSupport.groups_constant_bind_eq_of_suffix_subset
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
      pending₁ pending₂ nonce₁ nonce₂)
    (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (first_prefix_groups_subset_joint producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)

/-- Abstract dependent-subtype equality induced by equality of finite sets. -/
theorem subtype_type_eq_of_finset_eq {α : Type}
    (left right : Finset α) (same : left = right) :
    {value : α // value ∈ left} = {value : α // value ∈ right} := by
  exact congrArg (fun cells : Finset α => {value : α // value ∈ cells}) same

/-- Casting a subtype across a finite-set equality leaves its underlying
coordinate unchanged. The equality endpoints are variables so dependent
elimination does not unfold the executable reachable-set quotient. -/
theorem subtype_cast_val_of_finset_eq {α : Type}
    (left right : Finset α) (same : left = right)
    (key : {value : α // value ∈ left}) :
    (cast (subtype_type_eq_of_finset_eq left right same) key).val = key.val := by
  cases same
  rfl

/-- The finite squared norm of a function is invariant under dependent type
transport. CMS basis norms reduce to this sum after transporting the basis
type induced by the key equality. -/
theorem finite_sum_normSq_cast_of_type_eq
    {Basis₁ Basis₂ : Type}
    [fintypeBasis₁ : Fintype Basis₁] [fintypeBasis₂ : Fintype Basis₂]
    (sameBasis : Basis₁ = Basis₂) (state : Basis₁ → ℂ) :
    (∑ basis : Basis₂,
      Complex.normSq ((cast (congrArg (fun basis => basis → ℂ) sameBasis) state) basis)) =
      ∑ basis : Basis₁, Complex.normSq (state basis) := by
  cases sameBasis
  have sameFintype : fintypeBasis₁ = fintypeBasis₂ := Subsingleton.elim _ _
  cases sameFintype
  rfl

/-- Exact key type equality between the unit joint chronology and its
terminal whole-prefix observer. -/
theorem terminal_observer_key_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) =
      Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  change
    {key : GroupKey // key ∈ insert (groupKeyOf [])
      (groups (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂))} =
    {key : GroupKey // key ∈ insert (groupKeyOf [])
      (groups (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂))}
  exact subtype_type_eq_of_finset_eq _ _
    (congrArg (insert (groupKeyOf []))
      (terminal_observer_groups_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).symm)

/-- Transported membership of a concrete CMS key has the same grouped
address. -/
theorem included_cast_terminal_key
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (key : Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) :
    included (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
        (cast (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂) key) =
    included (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) key := by
  let sameUniverse := congrArg (insert (groupKeyOf []))
    (terminal_observer_groups_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).symm
  change
    (cast (subtype_type_eq_of_finset_eq _ _ sameUniverse) key).val = key.val
  exact subtype_cast_val_of_finset_eq _ _ sameUniverse key

/-- The canonical raw-input encoder commutes with the joint-to-observer key
cast. This makes the same encoded query address available to physical replay. -/
theorem encode_cast_terminal_key
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) (raw : RawInput) :
    cast (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
        (encode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂) raw) =
      encode (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) raw := by
  apply Subtype.ext
  let sameUniverse := congrArg (insert (groupKeyOf []))
    (terminal_observer_groups_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).symm
  change
    (cast (subtype_type_eq_of_finset_eq _ _ sameUniverse)
      (encode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) raw)).val =
      (encode (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂) raw).val
  calc
    _ = (encode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂) raw).val :=
        subtype_cast_val_of_finset_eq _ _ sameUniverse _
    _ = (encode (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂) raw).val := by
        unfold encode
        have sameMember :
            groupKeyOf raw ∈ insert (groupKeyOf [])
                (groups (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
                  statement₂ pending₁ pending₂ nonce₁ nonce₂)) ↔
              groupKeyOf raw ∈ insert (groupKeyOf [])
                (groups (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
                  statement₂ pending₁ pending₂ nonce₁ nonce₂)) := by
          rw [terminal_observer_groups_eq_joint]
        by_cases member : groupKeyOf raw ∈ insert (groupKeyOf [])
            (groups (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
              statement₂ pending₁ pending₂ nonce₁ nonce₂))
        · simp [member, sameMember.mp member]
        · have absent : ¬ groupKeyOf raw ∈ insert (groupKeyOf [])
              (groups (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
                statement₂ pending₁ pending₂ nonce₁ nonce₂)) := by
            intro present
            exact member (sameMember.mpr present)
          simp [member, absent]

/-- The CMS state carrier casts along the exact finite key-type equality. -/
theorem cmsStateTypeEq
    {Output Phase Workspace : Type}
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    State (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) Output Phase Workspace =
      State (Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)) Output Phase Workspace :=
  congrArg (fun key => State key Output Phase Workspace)
    (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
      pending₁ pending₂ nonce₁ nonce₂)

/-- Move a state on the original joint universe to the equal observer key
universe. This is ordinary equality transport, not a zero-extension. -/
def castJointCmsState
    {Output Phase Workspace : Type}
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (state : State (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) Output Phase Workspace) :
    State (Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)) Output Phase Workspace :=
  cast (cmsStateTypeEq producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂) state

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverKeys
