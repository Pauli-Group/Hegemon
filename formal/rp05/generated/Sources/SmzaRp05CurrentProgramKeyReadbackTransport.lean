import SmzaRp05ExecutableProgramEquality
import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleInstrument

/-! Generic transport of executable read claims and byte-record readback
along equal programs and equal key carriers.  Program/key equalities are
abstract arguments: the lemmas eliminate only those equality variables and
never inspect a computed history program or key universe. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentProgramKeyReadbackTransport

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branch_claims_eq_answer_log
    answerLog)
open SmzaRp05ExecutableProgramEquality (castProgramBranch answerLog_cast_program)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.SmallWood.V8Smz9CoherentMerkleInstrument (rawRecords)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false

variable {Result Output : Type}

/-- The claim list of a program branch is transported by the exact key cast
induced by `sameKey`; no arbitrary claim list is supplied. -/
theorem branchClaims_cast_program
    {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (sameProgram : left = right)
    (sameKey : KeyLeft = KeyRight)
    (encodeLeft : RawInput → KeyLeft) (encodeRight : RawInput → KeyRight)
    (encodeEq : ∀ raw, encodeRight raw = cast sameKey (encodeLeft raw))
    (branch : Branches decode left) :
    branchClaims (branchKeys encodeRight decode right
        (castProgramBranch decode left right sameProgram branch))
      (branchAnswers encodeRight decode right
        (castProgramBranch decode left right sameProgram branch)) =
      (branchClaims (branchKeys encodeLeft decode left branch)
        (branchAnswers encodeLeft decode left branch)).map
          (fun claim => (cast sameKey claim.1, claim.2)) := by
  cases sameProgram
  cases sameKey
  simp only [castProgramBranch]
  rw [branch_claims_eq_answer_log, branch_claims_eq_answer_log]
  simp only [List.map_map, Function.comp_def]
  congr 1
  funext call
  cases call with
  | mk raw output => simp [encodeEq]

/-- A recorded-claim event is invariant under an explicit key reindexing. -/
theorem claimsDatabaseEvent_cast
    {KeyLeft KeyRight : Type} (sameKey : KeyLeft = KeyRight)
    (leftClaims : List (KeyLeft × Output))
    (rightClaims : List (KeyRight × Output))
    (claimsEq : rightClaims = leftClaims.map
      (fun claim => (cast sameKey claim.1, claim.2)))
    (leftDatabase : Database KeyLeft Output)
    (rightDatabase : Database KeyRight Output)
    (databaseEq : ∀ key, rightDatabase (cast sameKey key) = leftDatabase key)
    (leftRecorded : ClaimsDatabaseEvent leftClaims leftDatabase) :
    ClaimsDatabaseEvent rightClaims rightDatabase := by
  intro claim member
  rw [claimsEq] at member
  rcases List.mem_map.mp member with ⟨source, sourceMember, sourceEq⟩
  cases sourceEq
  simpa only [databaseEq] using leftRecorded source sourceMember

/-- Program equality plus its exact branch/key encodings transports the
actual accepted read-claim event to the reindexed database. -/
theorem acceptedBranchClaims_cast_program
    {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    (decode : RawInput → Output → RawDigest)
    (left right : Program Result) (sameProgram : left = right)
    (sameKey : KeyLeft = KeyRight)
    (encodeLeft : RawInput → KeyLeft) (encodeRight : RawInput → KeyRight)
    (encodeEq : ∀ raw, encodeRight raw = cast sameKey (encodeLeft raw))
    (branch : Branches decode left)
    (leftDatabase : Database KeyLeft Output)
    (rightDatabase : Database KeyRight Output)
    (databaseEq : ∀ key, rightDatabase (cast sameKey key) = leftDatabase key)
    (leftRecorded : ClaimsDatabaseEvent
      (branchClaims (branchKeys encodeLeft decode left branch)
        (branchAnswers encodeLeft decode left branch)) leftDatabase) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys encodeRight decode right
        (castProgramBranch decode left right sameProgram branch))
        (branchAnswers encodeRight decode right
          (castProgramBranch decode left right sameProgram branch)))
      rightDatabase := by
  apply claimsDatabaseEvent_cast sameKey _ _ ?_ leftDatabase rightDatabase
    databaseEq leftRecorded
  exact branchClaims_cast_program decode left right sameProgram sameKey
    encodeLeft encodeRight encodeEq branch

/-- Raw byte records are unchanged by a key reindexing when both the database
and key-byte encoder are transported along the same equality. -/
theorem rawRecords_cast_key_database
    {KeyLeft KeyRight : Type}
    [leftFinite : Fintype KeyLeft] [leftDecEq : DecidableEq KeyLeft]
    [rightFinite : Fintype KeyRight] [rightDecEq : DecidableEq KeyRight]
    [Fintype Output] [DecidableEq Output]
    (sameKey : KeyLeft = KeyRight)
    (keyBytesLeft : KeyLeft → RawInput) (keyBytesRight : KeyRight → RawInput)
    (outputBytes : Output → RawDigest)
    (keyBytesEq : ∀ key, keyBytesRight (cast sameKey key) = keyBytesLeft key)
    (leftDatabase : Database KeyLeft Output)
    (rightDatabase : Database KeyRight Output)
    (databaseEq : ∀ key, rightDatabase (cast sameKey key) = leftDatabase key) :
    rawRecords keyBytesRight outputBytes rightDatabase =
      rawRecords keyBytesLeft outputBytes leftDatabase := by
  cases sameKey
  have finiteInstances : rightFinite = leftFinite := Subsingleton.elim _ _
  cases finiteInstances
  have decEqInstances : rightDecEq = leftDecEq := Subsingleton.elim _ _
  cases decEqInstances
  have keyBytesSame : keyBytesRight = keyBytesLeft := funext keyBytesEq
  have databaseSame : rightDatabase = leftDatabase := funext databaseEq
  rw [keyBytesSame, databaseSame]

/-- The same key-byte transport preserves membership in any fixed raw-key
record set, which is the form used by finite-key inclusion arguments. -/
theorem keyBytes_mem_transport
    {KeyLeft KeyRight : Type} (sameKey : KeyLeft = KeyRight)
    (keyBytesLeft : KeyLeft → RawInput) (keyBytesRight : KeyRight → RawInput)
    (keyBytesEq : ∀ key, keyBytesRight (cast sameKey key) = keyBytesLeft key)
    (records : Finset RawInput) (key : KeyLeft)
    (member : keyBytesLeft key ∈ records) :
    keyBytesRight (cast sameKey key) ∈ records := by
  rw [keyBytesEq]
  exact member

end HegemonCrypto.SmallWood.SmzaRp05CurrentProgramKeyReadbackTransport
