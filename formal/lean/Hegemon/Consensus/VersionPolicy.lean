namespace Hegemon
namespace Consensus

structure VersionBinding where
  circuit : Nat
  crypto : Nat
deriving DecidableEq, Repr

structure VersionEvent where
  height : Nat
  versions : List VersionBinding
deriving DecidableEq, Repr

structure VersionSchedule where
  initial : List VersionBinding
  activations : List VersionEvent
  retirements : List VersionEvent
deriving DecidableEq, Repr

def containsVersion : List VersionBinding -> VersionBinding -> Bool
  | [], _ => false
  | head :: tail, version =>
      if head = version then true else containsVersion tail version

def insertVersion (versions : List VersionBinding) (version : VersionBinding) :
    List VersionBinding :=
  if containsVersion versions version then versions else version :: versions

def removeVersion : List VersionBinding -> VersionBinding -> List VersionBinding
  | [], _ => []
  | head :: tail, version =>
      if head = version then
        removeVersion tail version
      else
        head :: removeVersion tail version

def insertMany (versions additions : List VersionBinding) : List VersionBinding :=
  additions.foldl insertVersion versions

def removeMany (versions removals : List VersionBinding) : List VersionBinding :=
  removals.foldl removeVersion versions

def eventVersionsAt (height : Nat) (events : List VersionEvent) :
    List VersionBinding :=
  events.foldl
    (fun acc event =>
      if event.height <= height then acc ++ event.versions else acc)
    []

def allowedVersionsAt (schedule : VersionSchedule) (height : Nat) :
    List VersionBinding :=
  let initial := insertMany [] schedule.initial
  let activated := insertMany initial (eventVersionsAt height schedule.activations)
  removeMany activated (eventVersionsAt height schedule.retirements)

def firstUnsupportedVersion
    (schedule : VersionSchedule)
    (height : Nat)
    (txVersions : List VersionBinding) : Option VersionBinding :=
  txVersions.find? (fun version =>
    !containsVersion (allowedVersionsAt schedule height) version)

def versionPolicyAccepts
    (schedule : VersionSchedule)
    (height : Nat)
    (txVersions : List VersionBinding) : Bool :=
  firstUnsupportedVersion schedule height txVersions = none

def baseVersion : VersionBinding := {
  circuit := 2,
  crypto := 1
}

def nextCircuitVersion : VersionBinding := {
  circuit := 3,
  crypto := 1
}

def nextCryptoVersion : VersionBinding := {
  circuit := 2,
  crypto := 2
}

def activationSchedule : VersionSchedule := {
  initial := [baseVersion],
  activations := [{ height := 10, versions := [nextCircuitVersion] }],
  retirements := []
}

def retirementSchedule : VersionSchedule := {
  initial := [baseVersion, nextCircuitVersion],
  activations := [],
  retirements := [{ height := 20, versions := [baseVersion] }]
}

def sameHeightSchedule : VersionSchedule := {
  initial := [baseVersion],
  activations := [{ height := 10, versions := [nextCircuitVersion] }],
  retirements := [{ height := 10, versions := [nextCircuitVersion] }]
}

theorem versionPolicy_initial_accepts :
    versionPolicyAccepts activationSchedule 0 [baseVersion] = true := by
  decide

theorem versionPolicy_rejects_unknown_initial :
    firstUnsupportedVersion activationSchedule 0 [nextCryptoVersion] =
      some nextCryptoVersion := by
  decide

theorem versionPolicy_rejects_before_activation :
    firstUnsupportedVersion activationSchedule 9 [nextCircuitVersion] =
      some nextCircuitVersion := by
  decide

theorem versionPolicy_accepts_at_activation :
    versionPolicyAccepts activationSchedule 10 [baseVersion, nextCircuitVersion] = true := by
  decide

theorem versionPolicy_accepts_before_retirement :
    versionPolicyAccepts retirementSchedule 19 [baseVersion, nextCircuitVersion] = true := by
  decide

theorem versionPolicy_rejects_at_retirement :
    firstUnsupportedVersion retirementSchedule 20 [baseVersion] =
      some baseVersion := by
  decide

theorem versionPolicy_retirement_wins_same_height :
    firstUnsupportedVersion sameHeightSchedule 10 [nextCircuitVersion] =
      some nextCircuitVersion := by
  decide

theorem versionPolicy_reports_first_unsupported_in_tx_order :
    firstUnsupportedVersion activationSchedule 0 [baseVersion, nextCryptoVersion, nextCircuitVersion] =
      some nextCryptoVersion := by
  decide

end Consensus
end Hegemon
