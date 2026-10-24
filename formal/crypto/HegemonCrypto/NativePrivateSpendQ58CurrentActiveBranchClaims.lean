import HegemonCrypto.NativePrivateSpendQ58CurrentComplementReadback
import HegemonCrypto.NativePrivateSpendQ58ActiveEventProjection

/-! Actual current branch claims on the same selected-role fiber.
The active claims are a literal filter of this branch's answer log. Fixed
compatibility is derived from one nonzero conditioned physical branch, and
active claim storage then derives full claim storage in the completed sparse
database. No standard-view nonzero or desired execution callback is supplied.
SOURCE ONLY; the physical mass/projector join is separate. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActiveBranchClaims
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog rawLog branchResult physicalRun
  branch_claims_eq_answer_log)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaChallengeStageTargets (Role)
open scoped Classical
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (RawInput RawDigest Counter Key encode decode keyBytes zero)
end G
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive parseCurrentStageQuery)
end C
namespace T
export NativePrivateSpendQ58PartitionTransport
  (FixedTable CmsState conditioned nonzero_physical_fiber_fixed_answers)
end T
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge merge_active merge_fixed)
end A
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
  (fullClaims claimOracle current_grouped_claims_replay_actual_program
   current_accepted_invalid_claimed_branch_has_literal_event)
end Q
namespace R
export NativePrivateSpendQ58CurrentComplementReadback
  (current_recorded_source_key_and_decoder)
end R
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire verifierProgram)
end E
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace P
export NativePrivateSpendQ58CurrentPublicOpening (Relation Satisfies)
end P
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues)
end D
namespace B
export NativePrivateSpendQ58CurrentFullLogReadback (FullCurrentBad)
end B
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Result : Type}

/-- This is the literal current role predicate on actual current bytes. -/
def live (program : Program Result) (selected : Role) (caps : Role → Nat) :
    G.Key program → Prop := C.RoleActive selected caps (G.keyBytes program)

def activeClaims (program : Program Result) (selected : Role) (caps : Role → Nat)
    (branch : Branches G.decode program) :
    List (A.ActiveKey (live program selected caps) × VectorOutput G.Counter) :=
  (Q.fullClaims program branch).filterMap fun claim =>
    if active : live program selected caps claim.1 then some (⟨claim.1, active⟩, claim.2)
    else none

def fixedCompatible (program : Program Result) (selected : Role) (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (live program selected caps))
    (branch : Branches G.decode program) : Prop :=
  ∀ call ∈ answerLog G.decode program branch,
    ∀ inactive : ¬live program selected caps (G.encode program call.1),
      fixed ⟨G.encode program call.1, inactive⟩ = call.2

theorem current_recorded_active_claim_is_selected
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (branch : Branches G.decode program)
    (claim : G.Key program × VectorOutput G.Counter)
    (recorded : claim ∈ Q.fullClaims program branch)
    (active : live program selected caps claim.1) :
    (⟨claim.1, active⟩, claim.2) ∈ activeClaims program selected caps branch := by
  unfold activeClaims
  exact List.mem_filterMap.mpr ⟨claim, recorded, dif_pos active⟩

/-- One actual conditioned branch determines every consumed inactive vector.
This uses the retained exact mixed-run readback, not a standard-basis premise. -/
theorem current_nonzero_conditioned_branch_is_fixed_compatible
    {Work : Type} [Fintype Work] [DecidableEq Work]
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (live program selected caps))
    (branch : Branches G.decode program)
    (state : T.CmsState (Key := G.Key program) (Counter := G.Counter) (Work := Work))
    (basis : Basis (G.Key program) (VectorOutput G.Counter) (VectorOutput G.Counter) Work)
    (nonzero : T.conditioned (live program selected caps) fixed
      (physicalRun (G.encode program) G.decode program branch state) basis ≠ 0) :
    fixedCompatible program selected caps fixed branch := by
  intro call recorded inactive
  exact T.nonzero_physical_fiber_fixed_answers (live program selected caps) fixed
    (G.encode program) G.decode program branch state basis nonzero call recorded inactive

/-- Active storage plus that same branch's actual fixed compatibility gives
all of its claims in the completed database, including inactive challenges. -/
theorem current_active_claims_complete_full_branch
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (live program selected caps))
    (branch : Branches G.decode program)
    (database : Database (A.ActiveKey (live program selected caps)) (VectorOutput G.Counter))
    (compatible : fixedCompatible program selected caps fixed branch)
    (claims : ClaimsDatabaseEvent (activeClaims program selected caps branch) database) :
    ClaimsDatabaseEvent (Q.fullClaims program branch)
      (A.merge (live program selected caps) fixed database) := by
  intro claim member
  have mapped : claim ∈ (answerLog G.decode program branch).map
      (fun call => (G.encode program call.1, call.2)) := by
    simpa only [Q.fullClaims, branch_claims_eq_answer_log] using member
  obtain ⟨call, recorded, same⟩ := List.mem_map.mp mapped
  subst claim
  by_cases active : live program selected caps (G.encode program call.1)
  · have chosen := current_recorded_active_claim_is_selected program selected caps branch
      (G.encode program call.1, call.2) member active
    have stored := claims (⟨G.encode program call.1, active⟩, call.2) chosen
    exact (A.merge_active (live program selected caps) fixed database
      ⟨G.encode program call.1, active⟩).trans stored
  · exact (A.merge_fixed (live program selected caps) fixed database
      ⟨G.encode program call.1, active⟩).trans (congrArg some (compatible call recorded active))

/-- Completion derives ordinary replay for this SAME producer/verifier
branch. It does not assert that an arbitrary completion replays without its
actual active claims and inactive-answer compatibility. -/
theorem current_active_claims_replay_same_program
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter) (live program selected caps))
    (branch : Branches G.decode program)
    (database : Database (A.ActiveKey (live program selected caps)) (VectorOutput G.Counter))
    (compatible : fixedCompatible program selected caps fixed branch)
    (claims : ClaimsDatabaseEvent (activeClaims program selected caps branch) database)
    (fallback : G.RawDigest) :
    program.record (Q.claimOracle program (A.merge (live program selected caps) fixed database) fallback) =
      (branchResult G.decode program branch, rawLog G.decode program branch) := by
  exact Q.current_grouped_claims_replay_actual_program program branch
    (A.merge (live program selected caps) fixed database)
    (current_active_claims_complete_full_branch program selected caps fixed branch database compatible claims)
    fallback

/-- Native source frames remain LIVE under every selected role. Their
actual recorded digest is therefore already in the sparse active database. -/
theorem current_claimed_source_record_is_in_active_database
    (program : Program Result) (selected : Role) (caps : Role → Nat)
    (branch : Branches G.decode program)
    (database : Database (A.ActiveKey (live program selected caps)) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (activeClaims program selected caps branch) database)
    (call : G.RawInput × VectorOutput G.Counter)
    (recorded : call ∈ answerLog G.decode program branch)
    (unparsed : C.parseCurrentStageQuery call.1 = none) :
    (call.1, G.decode call.1 call.2) ∈
      rawRecords (fun key : A.ActiveKey (live program selected caps) => G.keyBytes program key.val)
        (vectorOutputBytes G.zero) database := by
  obtain ⟨keyBytes, decoder⟩ := R.current_recorded_source_key_and_decoder
    program branch call recorded unparsed
  have active : live program selected caps (G.encode program call.1) := by
    simp only [live, C.RoleActive, keyBytes, unparsed]
  have fullMember : (G.encode program call.1, call.2) ∈ Q.fullClaims program branch := by
    rw [Q.fullClaims, branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨call, recorded, rfl⟩
  have chosen := current_recorded_active_claim_is_selected program selected caps branch
    (G.encode program call.1, call.2) fullMember active
  have stored := claims (⟨G.encode program call.1, active⟩, call.2) chosen
  rw [decoder]
  have retained : (G.keyBytes program (G.encode program call.1), vectorOutputBytes G.zero call.2) ∈
      rawRecords (fun key : A.ActiveKey (live program selected caps) => G.keyBytes program key.val)
        (vectorOutputBytes G.zero) database := by
    letI : DecidableEq G.RawInput := V8Smz9CoherentMerkleInstrument.instDecidableEqRawInput
    apply Finset.mem_image.mpr
    exact ⟨(⟨G.encode program call.1, active⟩, call.2), Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, stored⟩, rfl⟩
  simpa only [keyBytes] using retained

theorem current_active_invalid_claimed_branch_has_literal_full_event
    (producer : Program E.Wire) (ns : M.Namespace) (relation : P.Relation)
    (pending : Bool) (nonce : Fin (2^32)) (selected : Role) (caps : Role → Nat)
    (fixed : T.FixedTable (Counter := G.Counter)
      (live (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps))
    (branch : Branches G.decode (producer.bind (E.verifierProgram ns relation pending nonce)))
    (database : Database (A.ActiveKey
      (live (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps))
      (VectorOutput G.Counter))
    (compatible : fixedCompatible (producer.bind (E.verifierProgram ns relation pending nonce))
      selected caps fixed branch)
    (claims : ClaimsDatabaseEvent (activeClaims
      (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps branch) database)
    (accepted : branchResult G.decode
      (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ())
    (invalid : ¬∃ source : D.Decoded, P.Satisfies relation (D.decodedValues source))
    (fallback : G.RawDigest) :
    ∃ wire, producer.eval (Q.claimOracle (producer.bind (E.verifierProgram ns relation pending nonce))
      (A.merge (live (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps)
        fixed database) fallback) = some wire ∧
      B.FullCurrentBad ns relation pending nonce wire
        (Q.claimOracle (producer.bind (E.verifierProgram ns relation pending nonce))
          (A.merge (live (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps)
            fixed database) fallback) := by
  exact Q.current_accepted_invalid_claimed_branch_has_literal_event producer ns relation pending nonce
    branch (A.merge (live (producer.bind (E.verifierProgram ns relation pending nonce)) selected caps)
      fixed database)
    (current_active_claims_complete_full_branch _ selected caps fixed branch database compatible claims)
    accepted invalid fallback

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActiveBranchClaims
