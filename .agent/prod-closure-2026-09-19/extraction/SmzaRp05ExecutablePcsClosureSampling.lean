import SmzaRp05ExecutablePcsClosureStages

/-!
# Successful same-run challenge sampling forced by the final pending guard

These lemmas expose actual scan success only after the accumulated pending
flag is known false. Poison output is not treated as a successful sample.
They use the same raw oracle, keys, seeds, and source call caps as the assembled
verifier; no challenge-decoder success is supplied as a separate certificate.
The finite full-vector role-decoder and physical measurement identification
remain to be composed with these deterministic raw-scan equations.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureSampling

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage
  (FieldWord scan counterKeys fieldXof fieldLoop returnedWords pendingFailure)
open SmzaRp05ExecutablePcsClosure (queryProgram queryResult)
open V8SmzaOracleParser (RawDigest)
open V8Smz9PiopSoundness (Matrix)

set_option autoImplicit false

theorem matrix_program_exact (width : Nat) (pending : Bool) (digest : RawDigest)
    (oracle : Oracle) :
    (SmzaRp05PiopMatrixStage.matrixProgram width pending digest).eval oracle =
      let sampled := scan oracle (5 * width) []
        (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest)
      some (SmzaRp05PiopMatrixStage.matrixFromWords width
        (returnedWords (5 * width) sampled), pendingFailure pending sampled) := by
  simp only [SmzaRp05PiopMatrixStage.matrixProgram, Program.eval_bind,
    fieldXof, SmzaRp05ExecutableChallengeStage.field_loop_executes_scan,
    Option.bind_some, Program.eval]

theorem matrix_execution_clean (width : Nat) (pending : Bool) (digest : RawDigest)
    (oracle : Oracle) (matrix : Matrix width) (nextPending : Bool)
    (executed : (SmzaRp05PiopMatrixStage.matrixProgram width pending digest).eval
      oracle = some (matrix, nextPending)) (clean : nextPending = false) :
    pending = false ∧ ∃ words,
      scan oracle (5 * width) []
        (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest) =
          some words ∧
      matrix = SmzaRp05PiopMatrixStage.matrixFromWords width words := by
  rw [matrix_program_exact] at executed
  have pairEqual := Option.some.inj executed
  have matrixEqual := congrArg Prod.fst pairEqual
  have pendingEqual := congrArg Prod.snd pairEqual
  have finished : pendingFailure pending
      (scan oracle (5 * width) []
        (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * width) digest)) = false :=
    pendingEqual.trans clean
  obtain ⟨earlierClean, words, sampled⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _ finished
  refine ⟨earlierClean, words, sampled, ?_⟩
  simpa only [sampled, returnedWords, Option.getD_some] using matrixEqual.symm

theorem query_program_exact (pending : Bool) (digest : RawDigest) (oracle : Oracle) :
    (queryProgram pending digest).eval oracle =
      queryResult pending (scan oracle 50 []
        (counterKeys SmallWoodTranscript.decsFixedSamplingDomain 50 digest)) := by
  simp only [queryProgram, Program.eval_bind, fieldXof,
    SmzaRp05ExecutableChallengeStage.field_loop_executes_scan,
    Option.bind_some, Program.eval]

theorem query_execution_clean (pending : Bool) (digest : RawDigest) (oracle : Oracle)
    (indices : List Nat) (nextPending : Bool)
    (executed : (queryProgram pending digest).eval oracle = some (indices, nextPending))
    (clean : nextPending = false) :
    pending = false ∧ ∃ words,
      scan oracle 50 []
        (counterKeys SmallWoodTranscript.decsFixedSamplingDomain 50 digest) = some words := by
  rw [query_program_exact] at executed
  have pendingEqual := SmzaRp05ExecutablePcsClosure.query_pending_is_source_state
    pending _ indices nextPending executed
  exact SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _
    (pendingEqual.symm.trans clean)

/-- The final accepted transcript forces successful (non-poison) PIOP
matrix sampling and a clean PCS state in the very execution that produced it. -/
theorem execution_stages_clean_matrix
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : SmzaRp05RelationRefinement.RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List HegemonCrypto.CanonicalBytes.Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : SmzaRp05CurrentProofWireProgram.ExistingProofFieldView)
    (oracle : Oracle) (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (stages : SmzaRp05ExecutablePcsClosure.ExecutionStages ns dsl statement pending
      binding statementBinding nonce wire oracle transcript)
    (clean : transcript.pendingXofFailure = false) :
    stages.pcsPending = false ∧ ∃ words,
      scan oracle (5 * dsl.width statement) []
        (counterKeys SmallWoodTranscript.piopCoefficientDomain (5 * dsl.width statement)
          stages.hashFpp) = some words ∧
      stages.matrix = SmzaRp05PiopMatrixStage.matrixFromWords (dsl.width statement) words := by
  have pendingEqual := congrArg
    SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.pendingXofFailure
    stages.reconstructed
  exact matrix_execution_clean (dsl.width statement) stages.pcsPending stages.hashFpp
    oracle stages.matrix stages.finalPending stages.matrixExecuted
    (pendingEqual.trans clean)

end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureSampling
