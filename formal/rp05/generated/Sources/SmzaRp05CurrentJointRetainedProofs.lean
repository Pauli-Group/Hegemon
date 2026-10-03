import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05ExecutableMerklePaths
import SmzaRp05CurrentProofWireProgram
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05GeneratedCertificates

/-! # Retain both source proof views in the one joint execution

The accepted chronology is exactly producer₁, verifier₁, producer₂,
verifier₂.  The observer returns the two ExistingProofFieldViews produced on
that chronology; it does not run producer₁ twice inside the accepted pair.
The first-proof projection below adds only the terminal verifier₁ replay.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentJointRetainedProofs

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentJointAcceptedExecution
  (firstAcceptedVerifierProgram secondAcceptedVerifierProgram
    twoAcceptedVerifierProgram_success_iff
    twoAcceptedVerifierProgram_record_append)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05LeafNamespace (Namespace)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

private theorem eval_bind_some_iff {α β : Type}
    (oracle : Oracle) (program : Program α) (next : α → Program β)
    (value : β) :
    (program.bind next).eval oracle = some value ↔
      ∃ result, program.eval oracle = some result ∧
        (next result).eval oracle = some value := by
  rw [Program.eval_bind]
  simp only [Option.bind_eq_some_iff]

/-- The first verifier prefix returns the exact view emitted by its producer.
The view is emitted only after that exact view has passed verifier₁. -/
def retainedFirstVerifierProgram
    (producer₁ : Program ExistingProofFieldView)
    (ns₁ : Namespace)
    (statement₁ : SmzaRp05StatementNamespace.Statement)
    (pending₁ : Bool) (nonce₁ : Fin (2 ^ 32)) : Program ExistingProofFieldView :=
  producer₁.bind fun wire₁ =>
    (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).bind
      fun _ => .done (some wire₁)

/-- One actual accepted chronology, with both source-shaped proof views
retained as the observer result.  In particular producer₁ occurs once in this
program; producer₂ is run only after verifier₁ returns successfully. -/
def jointRetainedProofObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Program (ExistingProofFieldView × ExistingProofFieldView) :=
  (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).bind
    fun wire₁ =>
      producer₂.bind fun wire₂ =>
        (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).bind
          fun _ => .done (some (wire₁, wire₂))

/-- Project the first retained source proof without issuing any oracle reads. -/
def retainedFirstProofProducer
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program ExistingProofFieldView :=
  (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂).bind fun proofs =>
      .done (some proofs.1)

/-- The requested terminal first-target reverification: the first proof is
projected from the already-retained pair after all four actual chronology
stages, then the first verifier is run once more. -/
def terminalFirstTargetReverificationProgram
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program Unit :=
  (retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂).bind fun wire₁ =>
      verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁

/-- The retained first-prefix observer is an optional proof-only replay of
producer₁ and verifier₁ after the joint chronology.  This is distinct from
the actual pair chronology above; it is useful when replaying the whole first
prefix through KnownAt rather than changing the original execution. -/
def terminalFirstPrefixObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program ExistingProofFieldView :=
  (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁ statement₂
    pending₁ pending₂ nonce₁ nonce₂).bind fun _ =>
      retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁

/-- Unit-valued terminal observer in the exact existing accepted-joint route:
the original unit carrier is followed by the same first accepted unit prefix.
This is the program shape consumed by the prefix/suffix/prefix KnownAt lemma. -/
def terminalUnitPrefixReplayObserver
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool)
    (nonce₁ nonce₂ : Fin (2 ^ 32)) : Program Unit :=
  (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
    statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ =>
      firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁

/-- Exact evaluation of the retained first prefix: its output is not a caller
supplied proof but the first producer's output, and success entails verifier₁
acceptance for that same output. -/
theorem retainedFirstVerifier_eval_iff
    (oracle : Oracle) (producer₁ : Program ExistingProofFieldView)
    (ns₁ : Namespace) (statement₁ : SmzaRp05StatementNamespace.Statement)
    (pending₁ : Bool) (nonce₁ : Fin (2 ^ 32))
    (wire₁ : ExistingProofFieldView) :
    (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).eval
        oracle = some wire₁ ↔
      producer₁.eval oracle = some wire₁ ∧
        (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval
          oracle = some () := by
  unfold retainedFirstVerifierProgram
  rw [eval_bind_some_iff oracle producer₁
    (fun wire =>
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire).bind
        fun _ => .done (some wire)) wire₁]
  constructor
  · rintro ⟨wire, producerOk, verifierTailOk⟩
    rcases (eval_bind_some_iff oracle
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
      (fun _ => .done (some wire)) wire₁).mp verifierTailOk with
      ⟨result, verifierOk, doneOk⟩
    cases result
    have wireEq : wire = wire₁ := by
      simpa [Program.eval] using doneOk
    subst wire
    exact ⟨producerOk, verifierOk⟩
  · rintro ⟨producerOk, verifierOk⟩
    refine ⟨wire₁, producerOk, ?_⟩
    exact (eval_bind_some_iff oracle
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)
      (fun _ => .done (some wire₁)) wire₁).mpr
      ⟨(), verifierOk, rfl⟩

/-- The observer returns exactly the two proof views whose producers and
matching verifiers succeeded under the same oracle. -/
theorem jointRetainedProofObserver_eval_iff
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView) :
    (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
        some (wire₁, wire₂) ↔
      producer₁.eval oracle = some wire₁ ∧
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval
        oracle = some () ∧
      producer₂.eval oracle = some wire₂ ∧
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).eval
        oracle = some () := by
  unfold jointRetainedProofObserver
  rw [eval_bind_some_iff oracle
    (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (fun wire => producer₂.bind fun wire₂ =>
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).bind
        fun _ => .done (some (wire, wire₂))) (wire₁, wire₂)]
  constructor
  · rintro ⟨firstWire, firstOk, secondTailOk⟩
    rcases (eval_bind_some_iff oracle producer₂
      (fun secondWire =>
        (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ secondWire).bind
          fun _ => .done (some (firstWire, secondWire))) (wire₁, wire₂)).mp
      secondTailOk with ⟨secondWire, secondProducerOk, secondVerifierTailOk⟩
    rcases (eval_bind_some_iff oracle
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ secondWire)
      (fun _ => .done (some (firstWire, secondWire))) (wire₁, wire₂)).mp
      secondVerifierTailOk with ⟨result, secondVerifierOk, pairOk⟩
    cases result
    have pairEq : (firstWire, secondWire) = (wire₁, wire₂) := by
      simpa [Program.eval] using pairOk
    rcases Prod.mk.inj pairEq with ⟨firstWireEq, secondWireEq⟩
    have firstFacts := (retainedFirstVerifier_eval_iff oracle producer₁ ns₁
      statement₁ pending₁ nonce₁ firstWire).mp firstOk
    rw [firstWireEq] at firstFacts
    have secondProducerOk' := secondProducerOk
    rw [secondWireEq] at secondProducerOk'
    have secondVerifierOk' := secondVerifierOk
    rw [secondWireEq] at secondVerifierOk'
    exact ⟨firstFacts.1, firstFacts.2, secondProducerOk', secondVerifierOk'⟩
  · rintro ⟨firstProducerOk, firstVerifierOk, secondProducerOk, secondVerifierOk⟩
    have firstOk := (retainedFirstVerifier_eval_iff oracle producer₁ ns₁ statement₁
      pending₁ nonce₁ wire₁).mpr ⟨firstProducerOk, firstVerifierOk⟩
    refine ⟨wire₁, firstOk, ?_⟩
    apply (eval_bind_some_iff oracle producer₂
      (fun secondWire =>
        (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ secondWire).bind
          fun _ => .done (some (wire₁, secondWire))) (wire₁, wire₂)).mpr
    refine ⟨wire₂, secondProducerOk, ?_⟩
    exact (eval_bind_some_iff oracle
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂)
      (fun _ => .done (some (wire₁, wire₂))) (wire₁, wire₂)).mpr
      ⟨(), secondVerifierOk, rfl⟩

/-- The proof-only prefix replay returns the same first proof view already
retained in the accepted pair.  This is the source-identity fact used by the
terminal readback argument; it relies on the same deterministic oracle, not a
caller-supplied witness or selector-stability premise. -/
theorem terminalFirstPrefixObserver_eval_iff
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ : ExistingProofFieldView) :
    (terminalFirstPrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some wire₁ ↔
    ∃ wire₂,
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
          some (wire₁, wire₂) := by
  unfold terminalFirstPrefixObserver
  rw [eval_bind_some_iff oracle
    (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
    (fun _ => retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    wire₁]
  constructor
  · rintro ⟨proofs, observerOk, replayOk⟩
    rcases proofs with ⟨firstWire, secondWire⟩
    obtain ⟨firstProducerOk, _, _, _⟩ :=
      (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
        firstWire secondWire).mp observerOk
    obtain ⟨replayProducerOk, _⟩ :=
      (retainedFirstVerifier_eval_iff oracle producer₁ ns₁ statement₁
        pending₁ nonce₁ wire₁).mp replayOk
    have sameWire : firstWire = wire₁ :=
      Option.some.inj (firstProducerOk.symm.trans replayProducerOk)
    subst firstWire
    exact ⟨secondWire, observerOk⟩
  · rintro ⟨wire₂, observerOk⟩
    have firstFacts :=
      (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂).mp observerOk
    have replayOk := (retainedFirstVerifier_eval_iff oracle producer₁ ns₁
      statement₁ pending₁ nonce₁ wire₁).mpr ⟨firstFacts.1, firstFacts.2.1⟩
    exact ⟨(wire₁, wire₂), observerOk, replayOk⟩

/-- Original two-verifier acceptance is equivalent to success of the
retained-pair observer. The witnesses are precisely the two emitted views. -/
theorem twoAccepted_success_iff_jointRetainedObserver_success
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some () ↔
    ∃ wire₁ wire₂,
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
          some (wire₁, wire₂) := by
  rw [twoAcceptedVerifierProgram_success_iff]
  constructor
  · rintro ⟨wire₁, wire₂, firstProducerOk, firstVerifierOk,
      secondProducerOk, secondVerifierOk⟩
    exact ⟨wire₁, wire₂,
      (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂).mpr
        ⟨firstProducerOk, firstVerifierOk, secondProducerOk, secondVerifierOk⟩⟩
  · rintro ⟨wire₁, wire₂, observerOk⟩
    have pairFacts := (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂).mp
      observerOk
    exact ⟨wire₁, wire₂, pairFacts⟩

/-- The exact unit-valued suffix observer succeeds iff the original accepted
joint succeeds. Its replay prefix success is derived from the original
joint's actual first producer/verifier facts. -/
theorem terminalUnitPrefixReplayObserver_success_iff
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some () ↔
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some () := by
  unfold terminalUnitPrefixReplayObserver
  rw [eval_bind_some_iff oracle
    (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
    (fun _ => firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁) ()]
  constructor
  · rintro ⟨_, jointOk, _⟩
    exact jointOk
  · intro jointOk
    obtain ⟨wire₁, _, firstProducerOk, firstVerifierOk,
      _, _⟩ := (twoAcceptedVerifierProgram_success_iff oracle producer₁ producer₂
        ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).mp jointOk
    have firstPrefixOk :
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).eval
          oracle = some () := by
      unfold firstAcceptedVerifierProgram
      exact (eval_bind_some_iff oracle producer₁
        (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
        ()).mpr ⟨wire₁, firstProducerOk, firstVerifierOk⟩
    exact ⟨(), jointOk, firstPrefixOk⟩

/-- The unit-valued terminal replay and the pair-retaining observer describe
the same success executions; this is a same-oracle program identity, not an
independent-run coupling premise. -/
theorem terminalUnitPrefixReplayObserver_success_iff_retainedPair_success
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some () ↔
    ∃ wire₁ wire₂,
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
          some (wire₁, wire₂) := by
  rw [terminalUnitPrefixReplayObserver_success_iff,
    twoAccepted_success_iff_jointRetainedObserver_success]

/-- The observer's retained trace is exactly chronological. Its first producer
appears once in this log; the first verifier replay is separately appended by
the terminal program below. -/
theorem jointRetainedProofObserver_record_log
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducerOk : producer₁.eval oracle = some wire₁)
    (firstVerifierOk : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducerOk : producer₂.eval oracle = some wire₂)
    (secondVerifierOk : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    ((jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
        oracle).2 := by
  have firstPrefixOk := (retainedFirstVerifier_eval_iff oracle producer₁ ns₁
    statement₁ pending₁ nonce₁ wire₁).mpr ⟨firstProducerOk, firstVerifierOk⟩
  unfold jointRetainedProofObserver
  rw [Program.record_bind_success oracle
    (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
    (fun firstWire => producer₂.bind fun secondWire =>
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ secondWire).bind
        fun _ => .done (some (firstWire, secondWire))) wire₁ firstPrefixOk]
  rw [Program.record_bind_success oracle producer₂
    (fun secondWire =>
      (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ secondWire).bind
        fun _ => .done (some (wire₁, secondWire))) wire₂ secondProducerOk]
  rw [Program.record_bind_success oracle
    (verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂)
    (fun _ => .done (some (wire₁, wire₂))) () secondVerifierOk]
  have firstPrefixLog :
      (Program.record oracle
        (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)).2 =
        (producer₁.record oracle).2 ++
          (Program.record oracle
            (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)).2 := by
    unfold retainedFirstVerifierProgram
    rw [Program.record_bind_success oracle producer₁
      (fun firstWire =>
        (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ firstWire).bind
          fun _ => .done (some firstWire)) wire₁ firstProducerOk]
    rw [Program.record_bind_success oracle
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)
      (fun _ => .done (some wire₁)) () firstVerifierOk]
    simp [Program.record]
  simp only [Program.record, List.append_nil] at firstPrefixLog ⊢
  rw [firstPrefixLog]
  simp only [List.append_assoc]

/-- The original unit-returning accepted carrier and the observer expose the
same chronological raw-oracle log for the same two produced views. -/
theorem jointRetainedProofObserver_record_eq_original
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducerOk : producer₁.eval oracle = some wire₁)
    (firstVerifierOk : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducerOk : producer₂.eval oracle = some wire₂)
    (secondVerifierOk : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    ((jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
    ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 := by
  rw [jointRetainedProofObserver_record_log oracle producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂
    firstProducerOk firstVerifierOk secondProducerOk secondVerifierOk]
  rw [twoAcceptedVerifierProgram_record_append oracle producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂
    firstProducerOk firstVerifierOk secondProducerOk secondVerifierOk]

/-- Raw-log contract for the exact unit route consumed by the terminal
KnownAt replay: original chronology once, then the same accepted first prefix.
The appended prefix is a proof-only observer suffix, not another transaction
in the actual joint execution. -/
theorem terminalUnitPrefixReplayObserver_record_log
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducerOk : producer₁.eval oracle = some wire₁)
    (firstVerifierOk : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducerOk : producer₂.eval oracle = some wire₂)
    (secondVerifierOk : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    (Program.record oracle
      (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
        oracle).2 ++
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 := by
  have jointOk := (twoAcceptedVerifierProgram_success_iff oracle producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).mpr
      ⟨wire₁, wire₂, firstProducerOk, firstVerifierOk, secondProducerOk,
        secondVerifierOk⟩
  have firstPrefixOk :
      (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁).eval
        oracle = some () := by
    unfold firstAcceptedVerifierProgram
    exact (eval_bind_some_iff oracle producer₁
      (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
      ()).mpr ⟨wire₁, firstProducerOk, firstVerifierOk⟩
  have firstPrefixLog :
      (Program.record oracle
        (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)).2 =
      (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by
    unfold firstAcceptedVerifierProgram
    exact congrArg Prod.snd
      (Program.record_bind_success oracle producer₁
        (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
        wire₁ firstProducerOk)
  have terminalLog := congrArg Prod.snd
    (Program.record_bind_success oracle
      (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)
      (fun _ => firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
      () jointOk)
  calc
    (Program.record oracle
      (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)).2 =
        (Program.record oracle
          (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂)).2 ++
        (Program.record oracle
          (firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)).2 := by
            simpa [terminalUnitPrefixReplayObserver] using terminalLog
    _ = (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 ++
        (producer₂.record oracle).2 ++
        ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
          oracle).2 ++
        (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by
            rw [twoAcceptedVerifierProgram_record_append oracle producer₁ producer₂ ns₁ ns₂
              statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂
              firstProducerOk firstVerifierOk secondProducerOk secondVerifierOk,
              firstPrefixLog]
            simp only [List.append_assoc]

/-- Projection to the first proof changes no oracle trace and emits exactly
the first component of the pair retained by the observer. -/
theorem retainedFirstProofProducer_eval_iff
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ : ExistingProofFieldView) :
    (retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle = some wire₁ ↔
    ∃ wire₂, (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
        some (wire₁, wire₂) := by
  unfold retainedFirstProofProducer
  rw [eval_bind_some_iff oracle
    (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
    (fun proofs => .done (some proofs.1)) wire₁]
  constructor
  · rintro ⟨proofs, observerOk, projectedOk⟩
    rcases proofs with ⟨first, second⟩
    change some first = some wire₁ at projectedOk
    have firstEq : first = wire₁ := Option.some.inj projectedOk
    subst first
    exact ⟨second, observerOk⟩
  · rintro ⟨wire₂, observerOk⟩
    exact ⟨(wire₁, wire₂), observerOk, rfl⟩

/-- The terminal verifier is the first target applied to the exact first proof
view emitted by the projection. -/
theorem terminalFirstTarget_eval_iff
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    (terminalFirstTargetReverificationProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
        some () ↔
    ∃ wire₁ wire₂,
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).eval oracle =
          some (wire₁, wire₂) ∧
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).eval
        oracle = some () := by
  unfold terminalFirstTargetReverificationProgram
  rw [eval_bind_some_iff oracle
    (retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂)
    (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire) ()]
  constructor
  · rintro ⟨wire₁, producerOk, verifierOk⟩
    rcases (retainedFirstProofProducer_eval_iff oracle producer₁ producer₂
      ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁).mp
      producerOk with ⟨wire₂, observerOk⟩
    exact ⟨wire₁, wire₂, observerOk, verifierOk⟩
  · rintro ⟨wire₁, wire₂, observerOk, verifierOk⟩
    refine ⟨wire₁, ?_, verifierOk⟩
    exact (retainedFirstProofProducer_eval_iff oracle producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁).mpr ⟨wire₂, observerOk⟩

/-- Exact raw-log chronology for the terminal target check.  The four actual
stages remain producer₁, verifier₁, producer₂, verifier₂; only verifier₁ is
appended for terminal reverification.  In particular this terminal program
does not execute producer₁ a second time. -/
theorem terminalFirstTarget_record_log
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducerOk : producer₁.eval oracle = some wire₁)
    (firstVerifierOk : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducerOk : producer₂.eval oracle = some wire₂)
    (secondVerifierOk : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    (Program.record oracle
      (terminalFirstTargetReverificationProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
        oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 := by
  have observerOk := (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂).mpr
      ⟨firstProducerOk, firstVerifierOk, secondProducerOk, secondVerifierOk⟩
  have projectionOk := (retainedFirstProofProducer_eval_iff oracle producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁).mpr
      ⟨wire₂, observerOk⟩
  have projectionLog := congrArg Prod.snd
    (Program.record_bind_success oracle
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)
      (fun proofs => .done (some proofs.1)) (wire₁, wire₂) observerOk)
  have projectedTrace :
      ((retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
      ((jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 := by
    simpa [retainedFirstProofProducer, Program.record] using projectionLog
  calc
    (Program.record oracle
      (terminalFirstTargetReverificationProgram producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)).2 =
        ((retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by
          unfold terminalFirstTargetReverificationProgram
          rw [Program.record_bind_success oracle
            (retainedFirstProofProducer producer₁ producer₂ ns₁ ns₂ statement₁
              statement₂ pending₁ pending₂ nonce₁ nonce₂)
            (fun wire => verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire)
            wire₁ projectionOk]
    _ = ((jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by rw [projectedTrace]
    _ = (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 ++
        (producer₂.record oracle).2 ++
        ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
          oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by
          rw [jointRetainedProofObserver_record_log oracle producer₁ producer₂ ns₁ ns₂
            statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂
            firstProducerOk firstVerifierOk secondProducerOk secondVerifierOk]

/-- Raw-log chronology for the proof-only whole-prefix replay used by
KnownAt-based terminal reasoning.  The actual chronology occurs once; the
separate proof-only suffix then replays producer₁ and verifier₁. -/
theorem terminalFirstPrefixObserver_record_log
    (oracle : Oracle) (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (wire₁ wire₂ : ExistingProofFieldView)
    (firstProducerOk : producer₁.eval oracle = some wire₁)
    (firstVerifierOk : (verifierProgram ns₁ currentDsl statement₁ pending₁
      nonce₁ wire₁).eval oracle = some ())
    (secondProducerOk : producer₂.eval oracle = some wire₂)
    (secondVerifierOk : (verifierProgram ns₂ currentDsl statement₂ pending₂
      nonce₂ wire₂).eval oracle = some ()) :
    ((terminalFirstPrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 ++
      (producer₂.record oracle).2 ++
      ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
        oracle).2 ++
      (producer₁.record oracle).2 ++
      ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
        oracle).2 := by
  have observerOk := (jointRetainedProofObserver_eval_iff oracle producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂).mpr
      ⟨firstProducerOk, firstVerifierOk, secondProducerOk, secondVerifierOk⟩
  have replayOk := (retainedFirstVerifier_eval_iff oracle producer₁ ns₁
    statement₁ pending₁ nonce₁ wire₁).mpr ⟨firstProducerOk, firstVerifierOk⟩
  have replayTrace :
      (Program.record oracle
        (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)).2 =
        (producer₁.record oracle).2 ++
          (Program.record oracle
            (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)).2 := by
    unfold retainedFirstVerifierProgram
    rw [Program.record_bind_success oracle producer₁
      (fun firstWire =>
        (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ firstWire).bind
          fun _ => .done (some firstWire)) wire₁ firstProducerOk]
    rw [Program.record_bind_success oracle
      (verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁)
      (fun _ => .done (some wire₁)) () firstVerifierOk]
    simp [Program.record]
  have terminalTrace := congrArg Prod.snd
    (Program.record_bind_success oracle
      (jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂)
      (fun _ => retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)
      (wire₁, wire₂) observerOk)
  calc
    ((terminalFirstPrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 =
        ((jointRetainedProofObserver producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).record oracle).2 ++
        (Program.record oracle
          (retainedFirstVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁)).2 := by
          simpa [terminalFirstPrefixObserver] using terminalTrace
    _ = (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 ++
        (producer₂.record oracle).2 ++
        ((verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂).record
          oracle).2 ++
        (producer₁.record oracle).2 ++
        ((verifierProgram ns₁ currentDsl statement₁ pending₁ nonce₁ wire₁).record
          oracle).2 := by
          rw [jointRetainedProofObserver_record_log oracle producer₁ producer₂ ns₁ ns₂
            statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ wire₁ wire₂
            firstProducerOk firstVerifierOk secondProducerOk secondVerifierOk,
            replayTrace]
          simp only [List.append_assoc]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentJointRetainedProofs
