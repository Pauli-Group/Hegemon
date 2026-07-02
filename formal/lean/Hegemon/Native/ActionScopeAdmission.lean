namespace Hegemon
namespace Native
namespace ActionScopeAdmission

inductive ActionRoute where
  | bridge
  | candidateArtifact
  | coinbase
  | transfer
deriving DecidableEq, Repr

inductive ScopeReject where
  | candidateArtifactPayloadWrongRoute
  | bridgeScopeInvalid
  | candidateScopeInvalid
  | candidatePayloadMissing
  | coinbaseScopeInvalid
  | unsupportedActionRoute
  | transferScopeInvalid
deriving DecidableEq, Repr

structure ScopeInput where
  candidateArtifactPayloadScoped : Bool
  bridgeRoute : Bool
  bridgeScopeValid : Bool
  candidateArtifactRoute : Bool
  candidateScopeValid : Bool
  candidatePayloadPresent : Bool
  coinbaseRoute : Bool
  coinbaseScopeValid : Bool
  transferRoute : Bool
  transferScopeValid : Bool
deriving DecidableEq, Repr

def evaluateScopeAdmission (input : ScopeInput) : Except ScopeReject ActionRoute :=
  if input.candidateArtifactPayloadScoped = false then
    Except.error ScopeReject.candidateArtifactPayloadWrongRoute
  else if input.bridgeRoute = true then
    if input.bridgeScopeValid = false then
      Except.error ScopeReject.bridgeScopeInvalid
    else
      Except.ok ActionRoute.bridge
  else if input.candidateArtifactRoute = true then
    if input.candidateScopeValid = false then
      Except.error ScopeReject.candidateScopeInvalid
    else if input.candidatePayloadPresent = false then
      Except.error ScopeReject.candidatePayloadMissing
    else
      Except.ok ActionRoute.candidateArtifact
  else if input.coinbaseRoute = true then
    if input.coinbaseScopeValid = false then
      Except.error ScopeReject.coinbaseScopeInvalid
    else
      Except.ok ActionRoute.coinbase
  else if input.transferRoute = false then
    Except.error ScopeReject.unsupportedActionRoute
  else if input.transferScopeValid = false then
    Except.error ScopeReject.transferScopeInvalid
  else
    Except.ok ActionRoute.transfer

def scopeAdmissionAccepts (input : ScopeInput) : Bool :=
  match evaluateScopeAdmission input with
  | Except.ok _ => true
  | Except.error _ => false

def scopeAdmissionRoute (input : ScopeInput) : Option ActionRoute :=
  match evaluateScopeAdmission input with
  | Except.ok route => some route
  | Except.error _ => none

def scopeAdmissionRejection (input : ScopeInput) : Option ScopeReject :=
  match evaluateScopeAdmission input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def scopePreconditions (input : ScopeInput) : Bool :=
  input.candidateArtifactPayloadScoped
    && if input.bridgeRoute then
      input.bridgeScopeValid
    else if input.candidateArtifactRoute then
      input.candidateScopeValid && input.candidatePayloadPresent
    else if input.coinbaseRoute then
      input.coinbaseScopeValid
    else
      input.transferRoute && input.transferScopeValid

theorem accepts_iff_scope_preconditions
    {input : ScopeInput} :
    scopeAdmissionAccepts input = true ↔ scopePreconditions input = true := by
  cases input with
  | mk candidateArtifactPayloadScoped bridgeRoute bridgeScopeValid candidateArtifactRoute
      candidateScopeValid candidatePayloadPresent coinbaseRoute coinbaseScopeValid transferRoute
      transferScopeValid =>
      cases candidateArtifactPayloadScoped <;>
        cases bridgeRoute <;>
        cases bridgeScopeValid <;>
        cases candidateArtifactRoute <;>
        cases candidateScopeValid <;>
        cases candidatePayloadPresent <;>
        cases coinbaseRoute <;>
        cases coinbaseScopeValid <;>
        cases transferRoute <;>
        cases transferScopeValid <;>
        simp [
          scopeAdmissionAccepts,
          scopePreconditions,
          evaluateScopeAdmission
        ]

def validBridge : ScopeInput :=
  {
    candidateArtifactPayloadScoped := true,
    bridgeRoute := true,
    bridgeScopeValid := true,
    candidateArtifactRoute := false,
    candidateScopeValid := false,
    candidatePayloadPresent := false,
    coinbaseRoute := false,
    coinbaseScopeValid := false,
    transferRoute := false,
    transferScopeValid := false
  }

def validCandidateArtifact : ScopeInput :=
  {
    validBridge with
    bridgeRoute := false,
    bridgeScopeValid := false,
    candidateArtifactRoute := true,
    candidateScopeValid := true,
    candidatePayloadPresent := true
  }

def validCoinbase : ScopeInput :=
  {
    validBridge with
    bridgeRoute := false,
    bridgeScopeValid := false,
    coinbaseRoute := true,
    coinbaseScopeValid := true
  }

def validTransfer : ScopeInput :=
  {
    validBridge with
    bridgeRoute := false,
    bridgeScopeValid := false,
    transferRoute := true,
    transferScopeValid := true
  }

theorem valid_bridge_accepts :
    evaluateScopeAdmission validBridge = Except.ok ActionRoute.bridge := by
  rfl

theorem valid_candidate_artifact_accepts :
    evaluateScopeAdmission validCandidateArtifact =
      Except.ok ActionRoute.candidateArtifact := by
  rfl

theorem valid_coinbase_accepts :
    evaluateScopeAdmission validCoinbase = Except.ok ActionRoute.coinbase := by
  rfl

theorem valid_transfer_accepts :
    evaluateScopeAdmission validTransfer = Except.ok ActionRoute.transfer := by
  rfl

theorem candidate_artifact_payload_wrong_route_rejects
    {input : ScopeInput}
    (wrongRoute : input.candidateArtifactPayloadScoped = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.candidateArtifactPayloadWrongRoute := by
  unfold evaluateScopeAdmission
  simp [wrongRoute]

theorem bridge_scope_invalid_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (bridgeRoute : input.bridgeRoute = true)
    (bridgeScopeInvalid : input.bridgeScopeValid = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.bridgeScopeInvalid := by
  unfold evaluateScopeAdmission
  simp [candidateScoped, bridgeRoute, bridgeScopeInvalid]

theorem candidate_scope_invalid_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (notBridge : input.bridgeRoute = false)
    (candidateRoute : input.candidateArtifactRoute = true)
    (candidateScopeInvalid : input.candidateScopeValid = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.candidateScopeInvalid := by
  unfold evaluateScopeAdmission
  simp [candidateScoped, notBridge, candidateRoute, candidateScopeInvalid]

theorem candidate_payload_missing_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (notBridge : input.bridgeRoute = false)
    (candidateRoute : input.candidateArtifactRoute = true)
    (candidateScopeValid : input.candidateScopeValid = true)
    (payloadMissing : input.candidatePayloadPresent = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.candidatePayloadMissing := by
  unfold evaluateScopeAdmission
  simp [candidateScoped, notBridge, candidateRoute, candidateScopeValid, payloadMissing]

theorem coinbase_scope_invalid_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (notBridge : input.bridgeRoute = false)
    (notCandidate : input.candidateArtifactRoute = false)
    (coinbaseRoute : input.coinbaseRoute = true)
    (coinbaseScopeInvalid : input.coinbaseScopeValid = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.coinbaseScopeInvalid := by
  unfold evaluateScopeAdmission
  simp [candidateScoped, notBridge, notCandidate, coinbaseRoute, coinbaseScopeInvalid]

theorem unsupported_action_route_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (notBridge : input.bridgeRoute = false)
    (notCandidate : input.candidateArtifactRoute = false)
    (notCoinbase : input.coinbaseRoute = false)
    (notTransfer : input.transferRoute = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.unsupportedActionRoute := by
  unfold evaluateScopeAdmission
  simp [candidateScoped, notBridge, notCandidate, notCoinbase, notTransfer]

theorem transfer_scope_invalid_rejects
    {input : ScopeInput}
    (candidateScoped : input.candidateArtifactPayloadScoped = true)
    (notBridge : input.bridgeRoute = false)
    (notCandidate : input.candidateArtifactRoute = false)
    (notCoinbase : input.coinbaseRoute = false)
    (transferRoute : input.transferRoute = true)
    (transferScopeInvalid : input.transferScopeValid = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.transferScopeInvalid := by
  unfold evaluateScopeAdmission
  simp [
    candidateScoped,
    notBridge,
    notCandidate,
    notCoinbase,
    transferRoute,
    transferScopeInvalid
  ]

theorem candidate_artifact_wrong_route_precedes_bridge_scope
    {input : ScopeInput}
    (wrongRoute : input.candidateArtifactPayloadScoped = false) :
    evaluateScopeAdmission input =
      Except.error ScopeReject.candidateArtifactPayloadWrongRoute := by
  unfold evaluateScopeAdmission
  simp [wrongRoute]

end ActionScopeAdmission
end Native
end Hegemon
