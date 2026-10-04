import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05ExecutableBindSupport
import SmzaRp05ExecutableAddressCompiler
import SmzaRp05ExecutableMerkleVerifier
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05CurrentProofWireProgram
import SmzaRp05GeneratedCertificates
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05GroupedSuffix

/-! # Ordered current verifier histories

An explicit finite list of proof-producing verifier stages, composed in
chronological order over the same executable oracle. Prefix and read-support
facts below are derived from list decomposition and accepted execution.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryVerifierProgram

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05ExecutableBindSupport
  (groups_subset_constant_bind groups_constant_bind_eq_of_suffix_subset)
open SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram program_bind_assoc firstAcceptedVerifierProgram
    secondAcceptedVerifierProgram twoAcceptedProgram_eq_sequentialUnitProgram)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05GroupedSuffix (GroupKey groupKeyOf)
open SmzaRp05LeafNamespace (Namespace)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

structure HistoryStage where
  proofProducer : Program ExistingProofFieldView
  ns : Namespace
  statement : SmzaRp05StatementNamespace.Statement
  pending : Bool
  nonce : Fin (2 ^ 32)

def stageProgram (stage : HistoryStage) : Program Unit :=
  stage.proofProducer.bind fun wire =>
    verifierProgram stage.ns currentDsl stage.statement stage.pending stage.nonce wire

def historyProgram : List HistoryStage → Program Unit
  | [] => .done (some ())
  | stage :: rest => sequentialUnitProgram (stageProgram stage) (historyProgram rest)

private theorem bind_unit_done (program : Program Unit) :
    program.bind (fun _ => (Program.done (some ()) : Program Unit)) = program := by
  induction program with
  | done result => cases result <;> rfl
  | read raw next ih =>
      simp only [Program.bind]
      congr 1
      funext answer
      exact ih answer

private theorem historyProgram_singleton (stage : HistoryStage) :
    historyProgram [stage] = stageProgram stage := by
  change sequentialUnitProgram (stageProgram stage) (Program.done (some ())) = _
  unfold sequentialUnitProgram
  exact bind_unit_done (stageProgram stage)

private theorem eval_bind_some_iff {α β : Type}
    (oracle : Oracle) (program : Program α) (next : α → Program β)
    (value : β) :
    (program.bind next).eval oracle = some value ↔
      ∃ result, program.eval oracle = some result ∧ (next result).eval oracle = some value := by
  rw [Program.eval_bind]
  simp only [Option.bind_eq_some_iff]

theorem historyProgram_append (earlierStages suffix : List HistoryStage) :
    historyProgram (earlierStages ++ suffix) =
      sequentialUnitProgram (historyProgram earlierStages) (historyProgram suffix) := by
  induction earlierStages with
  | nil => rfl
  | cons stage rest ih =>
      change sequentialUnitProgram (stageProgram stage) (historyProgram (rest ++ suffix)) =
        sequentialUnitProgram
          (sequentialUnitProgram (stageProgram stage) (historyProgram rest))
          (historyProgram suffix)
      rw [ih]
      exact (program_bind_assoc (stageProgram stage)
        (fun _ => historyProgram rest) (fun _ => historyProgram suffix)).symm

theorem accepted_history_retains_prefix
    (oracle : Oracle) (earlierStages suffix : List HistoryStage)
    (accepted : (historyProgram (earlierStages ++ suffix)).eval oracle = some ()) :
    (historyProgram earlierStages).eval oracle = some () := by
  rw [historyProgram_append] at accepted
  rcases (eval_bind_some_iff oracle (historyProgram earlierStages)
    (fun _ => historyProgram suffix) ()).mp accepted with
    ⟨result, prefixAccepted, _⟩
  cases result
  exact prefixAccepted

theorem history_prefix_groups_subset (earlierStages suffix : List HistoryStage) :
    groups (historyProgram earlierStages) ⊆
      groups (historyProgram (earlierStages ++ suffix)) := by
  rw [historyProgram_append]
  exact groups_subset_constant_bind (historyProgram earlierStages) (historyProgram suffix)

/-- A successful actual prefix reaches the constant suffix, so the suffix's
all-answer support is also represented in the whole sequential program. -/
def historyPrefixAt (stages : List HistoryStage) (i : Fin stages.length) : Program Unit :=
  historyProgram (stages.take (i.val + 1))

private theorem take_step_eq_nat (stages : List HistoryStage) (n : Nat)
    (bound : n < stages.length) :
    stages.take (n + 1) = stages.take n ++ [stages[n]] := by
  induction stages generalizing n with
  | nil => simp only [List.length_nil] at bound; omega
  | cons head tail ih =>
      cases n with
      | zero => rfl
      | succ n =>
          have tailBound : n < tail.length := by simp only [List.length_cons] at bound; omega
          simpa only [List.take_succ_cons, List.getElem_cons_succ, List.cons_append] using
            congrArg (List.cons head) (ih n tailBound)

private theorem take_step_eq (stages : List HistoryStage) (i : Fin stages.length) :
    stages.take (i.val + 1) = stages.take i.val ++ [stages[i.val]] :=
  take_step_eq_nat stages i.val i.isLt

theorem historyPrefixAt_groups_subset
    (stages : List HistoryStage) (i : Fin stages.length) :
    groups (historyPrefixAt stages i) ⊆ groups (historyProgram stages) := by
  calc
    groups (historyProgram (stages.take (i.val + 1))) ⊆
        groups (historyProgram (stages.take (i.val + 1) ++ stages.drop (i.val + 1))) :=
      history_prefix_groups_subset _ _
    _ = groups (historyProgram stages) := by
      rw [List.take_append_drop]

def retainedPrefixAt (stages : List HistoryStage)
    (i : Fin stages.length) : Program ExistingProofFieldView :=
  (historyProgram (stages.take i.val)).bind fun _ => stages[i.val].proofProducer

def stageVerifierAt (stages : List HistoryStage) (i : Fin stages.length)
    (wire : ExistingProofFieldView) : Program Unit :=
  verifierProgram (stages[i.val]).ns currentDsl (stages[i.val]).statement
    (stages[i.val]).pending (stages[i.val]).nonce wire

/-- The indexed stage's actual verifier program starts from the retained
prefix and returns the producer's original wire only to that verifier. -/
def indexedStageVerifierProgram (stages : List HistoryStage)
    (i : Fin stages.length) : Program Unit :=
  (retainedPrefixAt stages i).bind fun wire => stageVerifierAt stages i wire

theorem indexedStageVerifierProgram_eq_prefixAt
    (stages : List HistoryStage) (i : Fin stages.length) :
    indexedStageVerifierProgram stages i = historyPrefixAt stages i := by
  unfold indexedStageVerifierProgram retainedPrefixAt historyPrefixAt
  rw [take_step_eq stages i, historyProgram_append]
  change ((historyProgram (stages.take i.val)).bind
      (fun _ => stages[i.val].proofProducer)).bind
      (fun wire => stageVerifierAt stages i wire) =
    sequentialUnitProgram (historyProgram (stages.take i.val))
      (historyProgram [stages[i.val]])
  rw [historyProgram_singleton]
  change ((historyProgram (stages.take i.val)).bind
      (fun _ => stages[i.val].proofProducer)).bind
      (fun wire => stageVerifierAt stages i wire) =
    (historyProgram (stages.take i.val)).bind
      (fun _ => stageProgram (stages[i.val]))
  exact program_bind_assoc (historyProgram (stages.take i.val))
    (fun _ => stages[i.val].proofProducer) (fun wire => stageVerifierAt stages i wire)

/-- Acceptance of the complete history exposes the actual producer wire and
successful verifier result for every indexed stage on the same oracle. -/
theorem accepted_history_retains_indexed_stage
    (oracle : Oracle) (stages : List HistoryStage) (i : Fin stages.length)
    (accepted : (historyProgram stages).eval oracle = some ()) :
    ∃ wire, (retainedPrefixAt stages i).eval oracle = some wire ∧
      (stageVerifierAt stages i wire).eval oracle = some () := by
  have split : stages = stages.take (i.val + 1) ++ stages.drop (i.val + 1) :=
    (List.take_append_drop (i.val + 1) stages).symm
  have prefixAccepted :
      (historyProgram (stages.take (i.val + 1))).eval oracle = some () := by
    have acceptedSplit :
        (historyProgram (stages.take (i.val + 1) ++ stages.drop (i.val + 1))).eval oracle =
          some () := by
      rw [← split]
      exact accepted
    exact accepted_history_retains_prefix oracle
      (stages.take (i.val + 1)) (stages.drop (i.val + 1)) acceptedSplit
  have indexedAccepted :
      (indexedStageVerifierProgram stages i).eval oracle = some () := by
    rw [indexedStageVerifierProgram_eq_prefixAt]
    exact prefixAccepted
  exact (eval_bind_some_iff oracle (retainedPrefixAt stages i)
    (fun wire => stageVerifierAt stages i wire) ()).mp indexedAccepted

/-- Every finite-indexed stage verifier-prefix has all-answer read support
contained in the completed ordered history. -/
theorem indexedStage_groups_subset
    (stages : List HistoryStage) (i : Fin stages.length) :
    groups (indexedStageVerifierProgram stages i) ⊆ groups (historyProgram stages) := by
  rw [indexedStageVerifierProgram_eq_prefixAt]
  exact historyPrefixAt_groups_subset stages i

/-- Replay the chosen stage's original producer wire and verifier after the
complete history. -/
def terminalHistoryStageObserver (stages : List HistoryStage)
    (i : Fin stages.length) : Program Unit :=
  (historyProgram stages).bind fun _ =>
    (retainedPrefixAt stages i).bind fun wire => stageVerifierAt stages i wire

/-- The terminal observer has exactly the full history's all-answer grouped
key support, by suffix inclusion and union idempotence. -/
theorem terminalHistoryStageObserver_groups_eq
    (stages : List HistoryStage) (i : Fin stages.length) :
    groups (terminalHistoryStageObserver stages i) = groups (historyProgram stages) := by
  change groups ((historyProgram stages).bind fun _ =>
    indexedStageVerifierProgram stages i) = groups (historyProgram stages)
  exact groups_constant_bind_eq_of_suffix_subset (historyProgram stages)
    (indexedStageVerifierProgram stages i) (indexedStage_groups_subset stages i)

theorem terminalHistoryStageObserver_key_eq
    (stages : List HistoryStage) (i : Fin stages.length) :
    Key (terminalHistoryStageObserver stages i) = Key (historyProgram stages) := by
  change
    { key : SmzaRp05GroupedSuffix.GroupKey // key ∈ insert
      (SmzaRp05GroupedSuffix.groupKeyOf [])
        (groups (terminalHistoryStageObserver stages i)) } =
    { key : SmzaRp05GroupedSuffix.GroupKey // key ∈ insert
      (SmzaRp05GroupedSuffix.groupKeyOf []) (groups (historyProgram stages)) }
  apply congrArg (fun keySet : Finset SmzaRp05GroupedSuffix.GroupKey =>
    { key : SmzaRp05GroupedSuffix.GroupKey // key ∈ keySet })
  exact congrArg (insert (SmzaRp05GroupedSuffix.groupKeyOf []))
    (terminalHistoryStageObserver_groups_eq stages i)

/-- The concrete two-transaction history in protocol order. -/
def currentTwoStageHistory
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    List HistoryStage :=
  [ ⟨producer₁, ns₁, statement₁, pending₁, nonce₁⟩
  , ⟨producer₂, ns₂, statement₂, pending₂, nonce₂⟩ ]

/-- This explicit finite stage list is the existing actual joint chronology,
not an independently executed model. -/
theorem currentTwoStageHistory_program_eq
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    historyProgram (currentTwoStageHistory producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) =
    secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
  change sequentialUnitProgram
      (stageProgram ⟨producer₁, ns₁, statement₁, pending₁, nonce₁⟩)
      (historyProgram [⟨producer₂, ns₂, statement₂, pending₂, nonce₂⟩]) = _
  rw [historyProgram_singleton]
  change sequentialUnitProgram
      (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
      (producer₂.bind fun wire₂ =>
        verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂) = _
  exact (twoAcceptedProgram_eq_sequentialUnitProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).symm

/-- Acceptance of the concrete ordered history exposes the exact generated
proof views and matching successful verifier stages. -/
theorem currentTwoStageHistory_acceptance
    (oracle : Oracle)
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (historyProgram (currentTwoStageHistory producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)).eval oracle = some () ↔
      ∃ wire₁ wire₂,
        producer₁.eval oracle = some wire₁ ∧
        (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval oracle = some () ∧
        producer₂.eval oracle = some wire₂ ∧
        (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).eval oracle = some () := by
  rw [currentTwoStageHistory_program_eq]
  exact SmzaRp05CurrentJointAcceptedExecution.twoAcceptedVerifierProgram_success_iff
    oracle producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂

/-- On one accepted history oracle, the record is exactly the ordered
concatenation of its producer/verifier stage reads. -/
theorem currentTwoStageHistory_record_append
    (oracle : Oracle)
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducer : producer₁.eval oracle = some wire₁)
    (firstAccepted :
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval oracle = some ())
    (secondProducer : producer₂.eval oracle = some wire₂)
    (secondAccepted :
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).eval oracle = some ()) :
    ((historyProgram (currentTwoStageHistory producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)).record oracle).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record oracle).2 := by
  rw [currentTwoStageHistory_program_eq]
  exact SmzaRp05CurrentJointAcceptedExecution.twoAcceptedVerifierProgram_record_append
    oracle producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
    nonce₁ nonce₂ wire₁ wire₂ firstProducer firstAccepted secondProducer secondAccepted

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryVerifierProgram
