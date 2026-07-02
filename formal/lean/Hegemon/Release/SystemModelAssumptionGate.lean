namespace Hegemon
namespace Release
namespace SystemModelAssumptionGate

inductive SystemModelGateReject where
  | daRetentionMissing
  | storageDurabilityMissing
  | globalPrivacyMonitoringMissing
  | releaseInfrastructureMissing
  | dependencyScannerFreshnessMissing
  | performanceBudgetMissing
  | failClosedPolicyMissing
  | releaseBlockingPolicyMissing
deriving DecidableEq, Repr

structure SystemModelGateInput where
  daRetentionMonitor : Bool
  storageDurabilityMonitor : Bool
  globalPrivacyBoundaryMonitor : Bool
  releaseInfrastructureMonitor : Bool
  dependencyScannerFreshnessMonitor : Bool
  performanceBudgetMonitor : Bool
  allGatesFailClosed : Bool
  allGatesReleaseBlocking : Bool
deriving DecidableEq, Repr

def evaluateSystemModelGate
    (input : SystemModelGateInput) : Except SystemModelGateReject Unit :=
  if input.daRetentionMonitor = false then
    Except.error SystemModelGateReject.daRetentionMissing
  else if input.storageDurabilityMonitor = false then
    Except.error SystemModelGateReject.storageDurabilityMissing
  else if input.globalPrivacyBoundaryMonitor = false then
    Except.error SystemModelGateReject.globalPrivacyMonitoringMissing
  else if input.releaseInfrastructureMonitor = false then
    Except.error SystemModelGateReject.releaseInfrastructureMissing
  else if input.dependencyScannerFreshnessMonitor = false then
    Except.error SystemModelGateReject.dependencyScannerFreshnessMissing
  else if input.performanceBudgetMonitor = false then
    Except.error SystemModelGateReject.performanceBudgetMissing
  else if input.allGatesFailClosed = false then
    Except.error SystemModelGateReject.failClosedPolicyMissing
  else if input.allGatesReleaseBlocking = false then
    Except.error SystemModelGateReject.releaseBlockingPolicyMissing
  else
    Except.ok ()

def systemModelGateAccepts (input : SystemModelGateInput) : Bool :=
  match evaluateSystemModelGate input with
  | Except.ok _ => true
  | Except.error _ => false

def systemModelGatePreconditions (input : SystemModelGateInput) : Bool :=
  input.daRetentionMonitor
    && input.storageDurabilityMonitor
    && input.globalPrivacyBoundaryMonitor
    && input.releaseInfrastructureMonitor
    && input.dependencyScannerFreshnessMonitor
    && input.performanceBudgetMonitor
    && input.allGatesFailClosed
    && input.allGatesReleaseBlocking

theorem accepts_iff_system_model_gate_preconditions
    (input : SystemModelGateInput) :
    systemModelGateAccepts input =
      systemModelGatePreconditions input := by
  cases input with
  | mk daRetentionMonitor storageDurabilityMonitor
      globalPrivacyBoundaryMonitor releaseInfrastructureMonitor
      dependencyScannerFreshnessMonitor performanceBudgetMonitor
      allGatesFailClosed allGatesReleaseBlocking =>
      unfold systemModelGateAccepts systemModelGatePreconditions
        evaluateSystemModelGate
      cases daRetentionMonitor <;>
        cases storageDurabilityMonitor <;>
        cases globalPrivacyBoundaryMonitor <;>
        cases releaseInfrastructureMonitor <;>
        cases dependencyScannerFreshnessMonitor <;>
        cases performanceBudgetMonitor <;>
        cases allGatesFailClosed <;>
        cases allGatesReleaseBlocking <;>
        rfl

theorem accepted_system_model_gate_exposes_fail_closed_monitoring
    {input : SystemModelGateInput}
    (accepted : evaluateSystemModelGate input = Except.ok ()) :
    input.daRetentionMonitor = true
      ∧ input.storageDurabilityMonitor = true
      ∧ input.globalPrivacyBoundaryMonitor = true
      ∧ input.releaseInfrastructureMonitor = true
      ∧ input.dependencyScannerFreshnessMonitor = true
      ∧ input.performanceBudgetMonitor = true
      ∧ input.allGatesFailClosed = true
      ∧ input.allGatesReleaseBlocking = true := by
  have acceptedBool : systemModelGateAccepts input = true := by
    simp [systemModelGateAccepts, accepted]
  have preconditions : systemModelGatePreconditions input = true := by
    rw [← accepts_iff_system_model_gate_preconditions input]
    exact acceptedBool
  simpa [systemModelGatePreconditions, and_assoc] using preconditions

theorem da_retention_monitor_missing_rejects :
    evaluateSystemModelGate
      { daRetentionMonitor := false,
        storageDurabilityMonitor := true,
        globalPrivacyBoundaryMonitor := true,
        releaseInfrastructureMonitor := true,
        dependencyScannerFreshnessMonitor := true,
        performanceBudgetMonitor := true,
        allGatesFailClosed := true,
        allGatesReleaseBlocking := true } =
      Except.error SystemModelGateReject.daRetentionMissing := by
  rfl

theorem fail_closed_policy_missing_rejects_after_monitors :
    evaluateSystemModelGate
      { daRetentionMonitor := true,
        storageDurabilityMonitor := true,
        globalPrivacyBoundaryMonitor := true,
        releaseInfrastructureMonitor := true,
        dependencyScannerFreshnessMonitor := true,
        performanceBudgetMonitor := true,
        allGatesFailClosed := false,
        allGatesReleaseBlocking := true } =
      Except.error SystemModelGateReject.failClosedPolicyMissing := by
  rfl

def completeSystemModelGate : SystemModelGateInput :=
  { daRetentionMonitor := true,
    storageDurabilityMonitor := true,
    globalPrivacyBoundaryMonitor := true,
    releaseInfrastructureMonitor := true,
    dependencyScannerFreshnessMonitor := true,
    performanceBudgetMonitor := true,
    allGatesFailClosed := true,
    allGatesReleaseBlocking := true }

theorem complete_system_model_gate_accepts :
    evaluateSystemModelGate completeSystemModelGate = Except.ok () := by
  rfl

structure AcceptedSystemModelGateFacts
    (input : SystemModelGateInput) : Prop where
  accepted :
    evaluateSystemModelGate input = Except.ok ()
  daRetentionMonitor :
    input.daRetentionMonitor = true
  storageDurabilityMonitor :
    input.storageDurabilityMonitor = true
  globalPrivacyBoundaryMonitor :
    input.globalPrivacyBoundaryMonitor = true
  releaseInfrastructureMonitor :
    input.releaseInfrastructureMonitor = true
  dependencyScannerFreshnessMonitor :
    input.dependencyScannerFreshnessMonitor = true
  performanceBudgetMonitor :
    input.performanceBudgetMonitor = true
  allGatesFailClosed :
    input.allGatesFailClosed = true
  allGatesReleaseBlocking :
    input.allGatesReleaseBlocking = true

theorem accepted_system_model_gate_yields_facts
    {input : SystemModelGateInput}
    (accepted : evaluateSystemModelGate input = Except.ok ()) :
    AcceptedSystemModelGateFacts input := by
  have facts :=
    accepted_system_model_gate_exposes_fail_closed_monitoring accepted
  exact {
    accepted := accepted,
    daRetentionMonitor := facts.left,
    storageDurabilityMonitor := facts.right.left,
    globalPrivacyBoundaryMonitor := facts.right.right.left,
    releaseInfrastructureMonitor := facts.right.right.right.left,
    dependencyScannerFreshnessMonitor :=
      facts.right.right.right.right.left,
    performanceBudgetMonitor :=
      facts.right.right.right.right.right.left,
    allGatesFailClosed :=
      facts.right.right.right.right.right.right.left,
    allGatesReleaseBlocking :=
      facts.right.right.right.right.right.right.right
  }

end SystemModelAssumptionGate
end Release
end Hegemon
