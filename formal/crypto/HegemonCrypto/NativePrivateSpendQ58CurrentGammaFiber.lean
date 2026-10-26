import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate

/-! Actual current DECS base-vector identity in one fixed CMS fiber.
The full recorded vector is derived equal to the same fiber's fixed vector.
Its literal current92-key scan therefore has the same gamma decode, including
field rejection and capped exhaustion. The current raw-counter producer map
which joins the actual PCS scan to this one vector is owned separately; no
historical53-byte group, per-key oracle equality or decode-law premise is used.
SOURCE ONLY: kernel and whole current producer-map integration pending. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGammaFiber

open scoped Classical
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog physicalRun)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaChallengeStageTargets (Role)
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (RoleActive FixedTable parseCurrentStageQuery fixedVectorAtNonce
   current_fixed_vector_matches_actual_record)
end C
namespace P
export NativePrivateSpendQ58PartitionTransport (CmsState conditioned)
end P
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (gammaAt)
end S
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (RawInput RawDigest)
end F
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Literal caps of the current field-XOF source constructors. The opening
has16 separate nonce trials, each with5 blocks; this cap is per nonce. -/
def currentRoleCaps : Role → Nat
  | .decsMatrix => 92
  | .piopMatrix => 840376
  | .piopOpening => 5
  | .decsSample => 14

theorem current_role_caps_are_actual_source_caps :
    currentRoleCaps .decsMatrix = SmzaRp05ExecutableChallengeStage.callCap 700 ∧
    currentRoleCaps .piopMatrix = SmzaRp05ExecutableChallengeStage.callCap 6722970 ∧
    currentRoleCaps .piopOpening = SmzaRp05ExecutableChallengeStage.callCap 6 ∧
    currentRoleCaps .decsSample = SmzaRp05ExecutableChallengeStage.callCap 80 := by decide

/-- Interpret one actual vector using the very raw-block decoder passed to
that physical branch. Only the literal current92 DECS constructor keys are
scanned. This definition introduces no alternate oracle-execution premise. -/
def gammaFromVector {Counter : Type}
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (root : F.RawDigest) (vector : VectorOutput Counter) :=
  S.gammaAt (fun raw => decode raw vector) root

variable {Key Counter Work Result : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

/-- This label consults only the selected physical fiber's fixed table.
Missing base-role keys remain none. It supplies no arbitrary source candidate
and does not assume that a final DECS/Piop sampler returned successfully. -/
def fixedGamma (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) selected currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest) (root : F.RawDigest) :=
  (C.fixedVectorAtNonce selected currentRoleCaps keyBytes fixed .decsMatrix root 0).map
    (gammaFromVector decode root)

/-- One actual recorded DECS base-vector read in the same nonzero physical
fiber determines the complete fixed vector. Every decoded raw coordinate is
then equal by congruence, rather than an assumed per-key equality law. -/
theorem current_decs_base_vector_is_same_fiber_fixed_vector
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (keyBytes : Key → F.RawInput) (injection : Function.Injective keyBytes)
    (fixed : C.FixedTable (Counter := Counter) selected currentRoleCaps keyBytes)
    (encode : F.RawInput → Key)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : P.CmsState (Key := Key) (Counter := Counter) (Work := Work))
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : P.conditioned (C.RoleActive selected currentRoleCaps keyBytes) fixed
      (physicalRun encode decode program branch state) basis ≠ 0)
    (call : F.RawInput × VectorOutput Counter) (recorded : call ∈ answerLog decode program branch)
    (root : F.RawDigest)
    (baseParsed : C.parseCurrentStageQuery (keyBytes (encode call.1)) =
      some ⟨.decsMatrix, root, 0, 0⟩) :
    C.fixedVectorAtNonce selected currentRoleCaps keyBytes fixed .decsMatrix root 0 =
      some call.2 ∧
    (∀ raw, (C.fixedVectorAtNonce selected currentRoleCaps keyBytes fixed
        .decsMatrix root 0).map (decode raw) = some (decode raw call.2)) := by
  have different : Role.decsMatrix ≠ selected := by
    rcases piopSelected with matrix | opening
    · rw [matrix]; decide
    · rw [opening]; decide
  have same := C.current_fixed_vector_matches_actual_record selected currentRoleCaps
    keyBytes injection fixed encode decode program branch state basis nonzero call recorded
    ⟨.decsMatrix, root, 0, 0⟩ baseParsed different
      (by change 0 < currentRoleCaps .decsMatrix; decide) rfl
  refine ⟨same, ?_⟩
  intro raw
  rw [same]
  rfl

/-- The exact same physical branch's DECS vector, not an independently
supplied vector or oracle agreement callback, produces the current gamma
label of the fixed fiber. A current producer-map theorem must additionally
identify the PCS92-counter reads with these coordinates; that obligation is
not replaced by a decode law or by historical grouped replay. -/
theorem current_decs_base_vector_has_same_fiber_current_gamma
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (keyBytes : Key → F.RawInput) (injection : Function.Injective keyBytes)
    (fixed : C.FixedTable (Counter := Counter) selected currentRoleCaps keyBytes)
    (encode : F.RawInput → Key)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : P.CmsState (Key := Key) (Counter := Counter) (Work := Work))
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : P.conditioned (C.RoleActive selected currentRoleCaps keyBytes) fixed
      (physicalRun encode decode program branch state) basis ≠ 0)
    (call : F.RawInput × VectorOutput Counter) (recorded : call ∈ answerLog decode program branch)
    (root : F.RawDigest)
    (baseParsed : C.parseCurrentStageQuery (keyBytes (encode call.1)) =
      some ⟨.decsMatrix, root, 0, 0⟩) :
    fixedGamma selected keyBytes fixed decode root = some (gammaFromVector decode root call.2) := by
  have same := current_decs_base_vector_is_same_fiber_fixed_vector selected piopSelected
    keyBytes injection fixed encode decode program branch state basis nonzero call recorded root baseParsed
  unfold fixedGamma
  rw [same.1]
  rfl

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGammaFiber
