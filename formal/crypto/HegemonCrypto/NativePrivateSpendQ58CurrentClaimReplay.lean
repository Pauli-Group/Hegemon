import HegemonCrypto.NativePrivateSpendQ58CurrentConstructorGrouping
import HegemonCrypto.NativePrivateSpendQ58CurrentFullLogReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentChallengeSourceDisjoint

/-! Current grouped claim storage to literal ordinary current acceptance.
The entire answer log comes from this Program branch. Claim storage supplies
every actual vector answer; the retained generic record replay then derives
the ordinary execution. No source candidate, relation success, extracted
certificate or oracle-agreement callback is supplied. These are deterministic
claim-conformance lemmas, not a premise that accepted invalid output has zero
mass. The physical adaptive-claims bound must derive the storage event.
SOURCE ONLY; no kernel or full G3 mass result. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentClaimReplay
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult answerLog rawLog branchClaims branchKeys branchAnswers
   branch_claims_eq_answer_log record_eq_of_branch_answers)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open scoped Classical
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (RawInput RawDigest Counter Key encode decode keyBytes zero)
end G
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire verifierProgram)
end E
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation Satisfies)
end C
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues)
end D
namespace F
export NativePrivateSpendQ58CurrentFullLogReadback
  (FullCurrentBad accepted_current_wire_has_witness_or_literal_full_event)
end F
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def fullClaims {Result : Type} (program : Program Result) (branch : Branches G.decode program) :=
  branchClaims (branchKeys (G.encode program) G.decode program branch)
    (branchAnswers (G.encode program) G.decode program branch)

def claimOracle {Result : Type} (program : Program Result)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (fallback : G.RawDigest) : Oracle := fun raw =>
  match database (G.encode program raw) with
  | none => fallback
  | some vector => G.decode raw vector

theorem current_claims_store_every_branch_vector {Result : Type}
    (program : Program Result) (branch : Branches G.decode program)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (fullClaims program branch) database)
    (call : G.RawInput × VectorOutput G.Counter)
    (recorded : call ∈ answerLog G.decode program branch) :
    database (G.encode program call.1) = some call.2 := by
  apply claims (G.encode program call.1, call.2)
  rw [fullClaims, branch_claims_eq_answer_log]
  exact List.mem_map.mpr ⟨call, recorded, rfl⟩

theorem current_grouped_claims_replay_actual_program {Result : Type}
    (program : Program Result) (branch : Branches G.decode program)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (fullClaims program branch) database)
    (fallback : G.RawDigest) :
    program.record (claimOracle program database fallback) =
      (branchResult G.decode program branch, rawLog G.decode program branch) := by
  apply record_eq_of_branch_answers (G.encode program) G.decode program branch
  intro call member
  have stored := current_claims_store_every_branch_vector program branch database claims call member
  simp only [claimOracle, stored]

/-- The verifier runs on the literal current wire produced on this same
branch. The bad alternatives refer to its actual ordinary full record. -/
theorem current_accepted_claimed_branch_has_witness_or_literal_event
    (producer : Program E.Wire) (ns : M.Namespace) (relation : C.Relation)
    (pending : Bool) (nonce : Fin (2^32))
    (branch : Branches G.decode (producer.bind (E.verifierProgram ns relation pending nonce)))
    (database : Database (G.Key (producer.bind (E.verifierProgram ns relation pending nonce)))
      (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent
      (fullClaims (producer.bind (E.verifierProgram ns relation pending nonce)) branch) database)
    (accepted : branchResult G.decode
      (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ())
    (fallback : G.RawDigest) :
    let program := producer.bind (E.verifierProgram ns relation pending nonce)
    let oracle := claimOracle program database fallback
    ∃ wire, producer.eval oracle = some wire ∧
      rawLog G.decode program branch = (producer.record oracle).2 ++
        ((E.verifierProgram ns relation pending nonce wire).record oracle).2 ∧
      ((∃ source : D.Decoded, C.Satisfies relation (D.decodedValues source)) ∨
        F.FullCurrentBad ns relation pending nonce wire oracle) := by
  let program := producer.bind (E.verifierProgram ns relation pending nonce)
  let oracle := claimOracle program database fallback
  have replay := current_grouped_claims_replay_actual_program program branch database claims fallback
  have ordinary : program.eval oracle = some () := by
    exact (Program.record_result oracle program).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨wire, produced, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (E.verifierProgram ns relation pending nonce) () ordinary
  have «prefix» := Program.record_bind_success oracle producer
    (E.verifierProgram ns relation pending nonce) wire produced
  refine ⟨wire, produced, ?_, F.accepted_current_wire_has_witness_or_literal_full_event
    ns relation pending nonce wire oracle verifierAccepted⟩
  exact (congrArg Prod.snd replay).symm.trans (congrArg Prod.snd «prefix»)

/-- Invalidity is the definition of the failure being classified, rather
than a premise that an extraction procedure returns a desired witness. -/
theorem current_accepted_invalid_claimed_branch_has_literal_event
    (producer : Program E.Wire) (ns : M.Namespace) (relation : C.Relation)
    (pending : Bool) (nonce : Fin (2^32))
    (branch : Branches G.decode (producer.bind (E.verifierProgram ns relation pending nonce)))
    (database : Database (G.Key (producer.bind (E.verifierProgram ns relation pending nonce)))
      (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent
      (fullClaims (producer.bind (E.verifierProgram ns relation pending nonce)) branch) database)
    (accepted : branchResult G.decode
      (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ())
    (invalid : ¬∃ source : D.Decoded, C.Satisfies relation (D.decodedValues source))
    (fallback : G.RawDigest) :
    let program := producer.bind (E.verifierProgram ns relation pending nonce)
    let oracle := claimOracle program database fallback
    ∃ wire, producer.eval oracle = some wire ∧
      F.FullCurrentBad ns relation pending nonce wire oracle := by
  obtain ⟨wire, produced, _recorded, result⟩ :=
    current_accepted_claimed_branch_has_witness_or_literal_event producer ns relation
      pending nonce branch database claims accepted fallback
  rcases result with witness | bad
  · exact (invalid witness).elim
  · exact ⟨wire, produced, bad⟩

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentClaimReplay
