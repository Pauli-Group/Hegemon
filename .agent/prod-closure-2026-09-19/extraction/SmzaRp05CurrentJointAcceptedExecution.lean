import SmzaRp05ExecutableMerklePaths
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05ExecutableAddressCompiler
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05CurrentProofWireProgram
import SmzaRp05GeneratedCertificates
import SmzaRp05ExecutableBindSupport

/-! # One sequential accepted execution for two current transactions

The joint carrier below is a single nested `Program` and a single
`physicalRun` under one oracle and one incoming state. The structural lemmas
derive its accepted branch split, ordered read/key logs, and component
reachable-group embeddings. They do not identify the component CMS Born
spaces: those have different finite-key types, and transporting a selector
projector between them still requires an explicit register/database
extension-naturalness theorem. No independent executions, caller-supplied
coupling, or event-bound premise is introduced here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys answerLog rawLog branchResult physicalRun)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05ExecutableBindSupport (groups_subset_constant_bind)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Output Result Phase Work : Type}
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]
variable (decode : RawInput → Output → RawDigest)

/-- Compose two *unit-returning* programs without resetting the CMS state or
oracle. -/
def sequentialUnitProgram (first second : Program Unit) : Program Unit :=
  first.bind fun _ => second

theorem program_bind_assoc {α β γ : Type} (program : Program α)
    (next : α → Program β) (last : β → Program γ) :
    (program.bind next).bind last =
      program.bind (fun value => (next value).bind last) := by
  induction program with
  | done result => cases result <;> rfl
  | read raw cont ih =>
      simp only [Program.bind]
      congr 1
      funext digest
      exact ih digest

private theorem eval_bind_some_iff {α β : Type}
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (program : Program α) (next : α → Program β) (value : β) :
    (program.bind next).eval oracle = some value ↔
      ∃ result, program.eval oracle = some result ∧
        (next result).eval oracle = some value := by
  rw [Program.eval_bind]
  simp only [Option.bind_eq_some_iff]

private theorem eval_producer_verifier_some_iff
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32)) :
    (producer.bind (fun wire => verifierProgram ns currentDsl statement pending nonce wire)).eval oracle =
      some () ↔
      ∃ wire, producer.eval oracle = some wire ∧
        (verifierProgram ns currentDsl statement pending nonce wire).eval oracle = some () := by
  exact eval_bind_some_iff oracle producer
    (fun wire => verifierProgram ns currentDsl statement pending nonce wire) ()

/-- The branch constructor corresponding to the sequential unit bind. -/
def sequentialUnitBranch : (first : Program Unit) →
    Branches decode first → (second : Program Unit) → Branches decode second →
      Branches decode (sequentialUnitProgram first second)
  | .done none, _, _, _ => PUnit.unit
  | .done (some ()), _, _, secondBranch => secondBranch
  | .read raw next, ⟨answer, firstTail⟩, second, secondBranch =>
      ⟨answer, sequentialUnitBranch (next (decode raw answer))
        firstTail second secondBranch⟩

theorem sequentialUnitBranch_result
    (first second : Program Unit)
    (firstBranch : Branches decode first)
    (secondBranch : Branches decode second) :
    branchResult decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) =
      (branchResult decode first firstBranch).bind
        (fun _ => branchResult decode second secondBranch) := by
  induction first with
  | done result =>
      cases result with
      | none => rfl
      | some value => cases value; rfl
  | read raw next ih =>
      rcases firstBranch with ⟨answer, firstTail⟩
      simpa only [sequentialUnitProgram, Program.bind, sequentialUnitBranch,
        branchResult] using ih (decode raw answer) firstTail

theorem sequentialUnitBranch_keys
    {Key : Type} (encode : RawInput → Key)
    (first second : Program Unit)
    (firstBranch : Branches decode first)
    (secondBranch : Branches decode second)
    (firstAccepted : branchResult decode first firstBranch = some ()) :
      branchKeys encode decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) =
      branchKeys encode decode first firstBranch ++
        branchKeys encode decode second secondBranch := by
  induction first with
  | done result =>
      cases result with
      | none => simp [branchResult] at firstAccepted
      | some value =>
          cases value
          rfl
  | read raw next ih =>
      rcases firstBranch with ⟨answer, firstTail⟩
      have tailEq := ih (decode raw answer) firstTail
        (by simpa only [branchResult] using firstAccepted)
      simpa only [sequentialUnitProgram, Program.bind, sequentialUnitBranch,
        branchKeys, List.cons_append] using congrArg (List.cons (encode raw)) tailEq

theorem sequentialUnitBranch_answerLog
    (first second : Program Unit)
    (firstBranch : Branches decode first)
    (secondBranch : Branches decode second)
    (firstAccepted : branchResult decode first firstBranch = some ()) :
    answerLog decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) =
      answerLog decode first firstBranch ++ answerLog decode second secondBranch := by
  induction first with
  | done result =>
      cases result with
      | none => simp [branchResult] at firstAccepted
      | some value =>
          cases value
          simp [sequentialUnitProgram, Program.bind, sequentialUnitBranch, answerLog]
  | read raw next ih =>
      rcases firstBranch with ⟨answer, firstTail⟩
      have tailEq := ih (decode raw answer) firstTail
        (by simpa only [branchResult] using firstAccepted)
      simpa only [sequentialUnitProgram, Program.bind, sequentialUnitBranch,
        answerLog, List.cons_append] using congrArg (List.cons (raw, answer)) tailEq

theorem sequentialUnitBranch_rawLog
    (first second : Program Unit)
    (firstBranch : Branches decode first)
    (secondBranch : Branches decode second)
    (firstAccepted : branchResult decode first firstBranch = some ()) :
    rawLog decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) =
      rawLog decode first firstBranch ++ rawLog decode second secondBranch := by
  rw [show rawLog decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) =
      (answerLog decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch)).map
          (fun call => (call.1, decode call.1 call.2)) from rfl]
  rw [sequentialUnitBranch_answerLog decode first second firstBranch secondBranch firstAccepted]
  simp only [rawLog, List.map_append]

theorem sequentialUnitBranch_physicalRun
    {Key Phase Work : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key)
    (first second : Program Unit)
    (firstBranch : Branches decode first)
    (secondBranch : Branches decode second)
    (firstAccepted : branchResult decode first firstBranch = some ())
    (state : HegemonCrypto.CmsCompressedOracle.State Key Output Phase Work) :
    physicalRun encode decode (sequentialUnitProgram first second)
        (sequentialUnitBranch decode first firstBranch second secondBranch) state =
      physicalRun encode decode second secondBranch
        (physicalRun encode decode first firstBranch state) := by
  induction first generalizing state with
  | done result =>
      cases result with
      | none => simp [branchResult] at firstAccepted
      | some value =>
          cases value
          rfl
  | read raw next ih =>
      rcases firstBranch with ⟨answer, firstTail⟩
      simpa only [sequentialUnitProgram, Program.bind, sequentialUnitBranch,
        branchResult, physicalRun] using ih (decode raw answer) firstTail
          (by simpa only [branchResult] using firstAccepted)
          (HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite.physicalReadStep
            (encode raw) answer state)

theorem sequentialUnitBranch_split
    (first second : Program Unit)
    (jointBranch : Branches decode (sequentialUnitProgram first second))
    (accepted : branchResult decode (sequentialUnitProgram first second)
      jointBranch = some ()) :
    ∃ firstBranch secondBranch,
      branchResult decode first firstBranch = some () ∧
      branchResult decode second secondBranch = some () ∧
      jointBranch = sequentialUnitBranch decode first firstBranch second secondBranch := by
  induction first with
  | done result =>
      cases result with
      | none => simp [sequentialUnitProgram, Program.bind, branchResult] at accepted
      | some value =>
          cases value
          refine ⟨PUnit.unit, jointBranch, rfl, ?_, rfl⟩
          simpa only [sequentialUnitProgram, Program.bind, sequentialUnitBranch,
            branchResult] using accepted
  | read raw next ih =>
      rcases jointBranch with ⟨answer, jointTail⟩
      have tailAccepted : branchResult decode
          (sequentialUnitProgram (next (decode raw answer)) second) jointTail =
          some () := by
        simpa only [sequentialUnitProgram, Program.bind, branchResult] using accepted
      obtain ⟨firstTail, secondBranch, firstTailAccepted,
        secondAccepted, tailEq⟩ := ih (decode raw answer) jointTail tailAccepted
      refine ⟨⟨answer, firstTail⟩, secondBranch, ?_, secondAccepted, ?_⟩
      · simpa only [branchResult] using firstTailAccepted
      · exact congrArg (fun branch => Sigma.mk answer branch) tailEq

/-! The sequential branch proof above is intentionally single-universe; it
does not transport the workspace or selector across different key types. -/

/-- A real two-transaction carrier: the second producer is only run after
the first verifier returned successfully; both verifiers query the same
oracle and share the single `physicalRun` state. -/
def firstAcceptedVerifierProgram
    (producer₁ : Program ExistingProofFieldView)
    (ns₁ : Namespace)
    (statement₁ : SmzaRp05StatementNamespace.Statement)
    (pending₁ : Bool) (nonce₁ : Fin (2 ^ 32)) : Program Unit :=
  producer₁.bind fun wire₁ => verifierProgram ns₁ currentDsl statement₁
    pending₁ nonce₁ wire₁

/-- This is the second prover run in the actual chronology. Its producer is
the first accepted verifier program followed by the second producer. -/
def secondProducerAfterFirst
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ : Namespace)
    (statement₁ : SmzaRp05StatementNamespace.Statement)
    (pending₁ : Bool) (nonce₁ : Fin (2 ^ 32)) : Program ExistingProofFieldView :=
  (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).bind
    fun _ => producer₂

def secondAcceptedVerifierProgram
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program Unit :=
  (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁).bind
    fun wire₂ => verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂

/-- The literal prefix/tail presentation used for branch splitting is the
same `Program` as the second run's actual composed producer/verifier. -/
theorem twoAcceptedProgram_eq_sequentialUnitProgram
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂ =
    sequentialUnitProgram
      (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
      (producer₂.bind fun wire₂ => verifierProgram ns₂ currentDsl statement₂
        pending₂ nonce₂ wire₂) := by
  exact (program_bind_assoc
    (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (fun _ => producer₂)
    (fun wire₂ => verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂))

theorem twoAcceptedVerifierProgram_success_iff
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some () ↔
      ∃ wire₁ wire₂,
        producer₁.eval oracle = some wire₁ ∧
        (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval oracle = some () ∧
        producer₂.eval oracle = some wire₂ ∧
        (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).eval oracle = some () := by
  rw [twoAcceptedProgram_eq_sequentialUnitProgram]
  unfold sequentialUnitProgram
  rw [eval_bind_some_iff oracle
    (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (fun _ => producer₂.bind fun wire₂ =>
      verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂) ()]
  constructor
  · rintro ⟨result, firstAccepted, secondStageAccepted⟩
    cases result
    have firstSplit := (eval_producer_verifier_some_iff oracle producer₁ ns₁
      statement₁ pending₁ nonce₁).mp firstAccepted
    rcases firstSplit with
      ⟨wire₁, producer₁Ok, verifier₁Ok⟩
    have secondSplit := (eval_producer_verifier_some_iff oracle producer₂ ns₂
      statement₂ pending₂ nonce₂).mp secondStageAccepted
    rcases secondSplit with
      ⟨wire₂, producer₂Ok, verifier₂Ok⟩
    exact ⟨wire₁, wire₂, producer₁Ok, verifier₁Ok, producer₂Ok, verifier₂Ok⟩
  · rintro ⟨wire₁, wire₂, producer₁Ok, verifier₁Ok, producer₂Ok, verifier₂Ok⟩
    refine ⟨(), ?_, ?_⟩
    · exact (eval_producer_verifier_some_iff oracle producer₁ ns₁ statement₁
        pending₁ nonce₁).mpr ⟨wire₁, producer₁Ok, verifier₁Ok⟩
    · exact (eval_producer_verifier_some_iff oracle producer₂ ns₂ statement₂
        pending₂ nonce₂).mpr ⟨wire₂, producer₂Ok, verifier₂Ok⟩

theorem twoAcceptedVerifierProgram_record_append
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducer : producer₁.eval oracle = some wire₁)
    (firstAccepted : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducer : producer₂.eval oracle = some wire₂)
    (_secondAccepted : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record oracle).2 := by
  have firstProgramAccepted :
      (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).eval oracle = some () := by
    exact (eval_producer_verifier_some_iff oracle producer₁ ns₁ statement₁
      pending₁ nonce₁).mpr ⟨wire₁, firstProducer, firstAccepted⟩
  have composedProducerAccepted :
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁).eval oracle =
        some wire₂ := by
    simp [secondProducerAfterFirst, Program.eval_bind, firstProgramAccepted,
      secondProducer]
  have firstProgramLog := congrArg Prod.snd
    (Program.record_bind_success oracle producer₁
      (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
      wire₁ firstProducer)
  have secondProducerLog := congrArg Prod.snd
    (Program.record_bind_success oracle
      (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
      (fun _ => producer₂) () firstProgramAccepted)
  rw [secondAcceptedVerifierProgram, Program.record_bind_success oracle
    (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
    (fun wire => verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire)
    wire₂ composedProducerAccepted]
  rw [secondProducerAfterFirst, secondProducerLog, firstAcceptedVerifierProgram,
    firstProgramLog]

/-- Preserve the exact group key while moving a finite key into the larger
joint program's ex-ante universe. -/
def embedFiniteKey {α β : Type} (program : Program α) (joint : Program β)
    (groupsSubset : groups program ⊆ groups joint) (key : Key program) : Key joint := by
  classical
  refine ⟨included program key, ?_⟩
  change key.val ∈ insert (groupKeyOf []) (groups joint)
  rcases Finset.mem_insert.mp key.property with fallback | member
  · exact Finset.mem_insert.mpr (Or.inl fallback)
  · exact Finset.mem_insert_of_mem (groupsSubset member)

theorem embedFiniteKey_included {α β : Type} (program : Program α)
    (joint : Program β) (groupsSubset : groups program ⊆ groups joint)
    (key : Key program) :
    included joint (embedFiniteKey program joint groupsSubset key) = included program key := rfl

theorem embedFiniteKey_injective {α β : Type} (program : Program α)
    (joint : Program β) (groupsSubset : groups program ⊆ groups joint) :
    Function.Injective (embedFiniteKey program joint groupsSubset) := by
  intro left right equal
  apply Subtype.ext
  change included program left = included program right
  calc
    included program left =
        included joint (embedFiniteKey program joint groupsSubset left) :=
      (embedFiniteKey_included program joint groupsSubset left).symm
    _ = included joint (embedFiniteKey program joint groupsSubset right) :=
      congrArg (included joint) equal
    _ = included program right :=
      embedFiniteKey_included program joint groupsSubset right

/-- Enumerate the first program's finite grouped-key universe inside the
larger joint universe. -/
def firstKeyCoordinates {first joint : Program Unit}
    (groupsSubset : groups first ⊆ groups joint) :
  Fin (Fintype.card (Key first)) → Key joint :=
  fun coordinate => embedFiniteKey first joint groupsSubset
    ((Fintype.equivFin (Key first)).symm coordinate)

theorem firstKeyCoordinates_injective {first joint : Program Unit}
    (groupsSubset : groups first ⊆ groups joint) :
    Function.Injective (firstKeyCoordinates groupsSubset) := by
  intro left right equal
  have embeddedEqual :
      embedFiniteKey first joint groupsSubset
          ((Fintype.equivFin (Key first)).symm left) =
        embedFiniteKey first joint groupsSubset
          ((Fintype.equivFin (Key first)).symm right) := by
    exact equal
  exact (Fintype.equivFin (Key first)).symm.injective
    (embedFiniteKey_injective first joint groupsSubset embeddedEqual)

/-- Exact classical-database split into first-prefix key cells and their
complement in the joint program's key space. This equivalence is only a
database-coordinate reindexing; it is not a compressed-state or selector
projector naturality theorem. -/
def firstKeyDatabaseSplit {first joint : Program Unit}
    (groupsSubset : groups first ⊆ groups joint) :
    HegemonCrypto.FiniteOracleDatabase.Database (Key joint) Output ≃
      ((Fin (Fintype.card (Key first)) → Option Output) ×
        (HegemonCrypto.CmsOracleDatabaseBridge.OutsideInput
          (firstKeyCoordinates groupsSubset) → Option Output)) :=
  HegemonCrypto.CmsOracleDatabaseBridge.databaseSplitEquiv
    (firstKeyCoordinates groupsSubset)
    (firstKeyCoordinates_injective groupsSubset)

theorem sequential_first_groups_subset {first second : Program Unit} :
    groups first ⊆ groups (sequentialUnitProgram first second) := by
  simpa only [sequentialUnitProgram] using
    groups_subset_constant_bind first second

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution
