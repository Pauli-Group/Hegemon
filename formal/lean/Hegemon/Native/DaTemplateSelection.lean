namespace Hegemon
namespace Native
namespace DaTemplateSelection

/-!
Executable model of the native miner's transfer-ciphertext DA-byte capacity
selector.

This model covers only checked byte accounting and deterministic ordered
authoring selection. The model alone does not establish that a chosen tier is
committed by the native block wire/PoW rules, and it does not claim Reed-Solomon
soundness, blob retrievability, proof/action-body availability, or data
availability. Its transfer inputs are
route-agnostic already-materialized canonical byte sizes; the model neither
authorizes sidecar transport nor proves sidecar ciphertext availability.
-/

def usizeMax : Nat := 18446744073709551615

def compactLengthPrefixBytes : Nat := 4

def checkedAddUsize (lhs rhs : Nat) : Option Nat :=
  if lhs > usizeMax then none
  else if rhs > usizeMax then none
  else if lhs + rhs > usizeMax then none
  else some (lhs + rhs)

def transferBlobContributionAux : Nat -> List Nat -> Option Nat
  | total, [] => some total
  | total, size :: rest =>
      match checkedAddUsize total compactLengthPrefixBytes with
      | none => none
      | some withLength =>
          match checkedAddUsize withLength size with
          | none => none
          | some next => transferBlobContributionAux next rest

/-- Bytes added to an existing blob by one transfer: the transaction's
compact ciphertext-count prefix plus one compact byte-length prefix and the
declared bytes for each ciphertext. -/
def transferBlobContribution (ciphertextSizes : List Nat) : Option Nat :=
  transferBlobContributionAux compactLengthPrefixBytes ciphertextSizes

inductive SingleTransferDecision where
  | contributionOverflow
  | individuallyTooLarge (contribution : Nat)
  | admissible (contribution : Nat)
deriving DecidableEq, Repr

/-- Classify individual encodability before considering cumulative capacity.
This ordering matches the production quarantine-before-prefix-stop behavior. -/
def classifySingleTransfer
    (maxBlobBytes : Nat)
    (ciphertextSizes : List Nat) : SingleTransferDecision :=
  match transferBlobContribution ciphertextSizes with
  | none => SingleTransferDecision.contributionOverflow
  | some contribution =>
      let singleBlobBytes :=
        (checkedAddUsize compactLengthPrefixBytes contribution).getD usizeMax
      if singleBlobBytes > maxBlobBytes then
        SingleTransferDecision.individuallyTooLarge contribution
      else
        SingleTransferDecision.admissible contribution

structure Action where
  actionId : Nat
  transferRoute : Bool
  ciphertextSizes : List Nat
  encodedBytes : Nat := 0
deriving DecidableEq, Repr

structure Limits where
  maxBlobBytes : Nat
  maxActionCount : Nat
  maxActionBytes : Nat
  reservedActionCount : Nat
  reservedActionBytes : Nat
deriving DecidableEq, Repr

inductive SelectionReject where
  | reservedActionCount
  | reservedActionBytes
deriving DecidableEq, Repr

structure Selection where
  selectedActionIds : List Nat
  individuallyUnencodableActionIds : List Nat
  deferredActionIds : List Nat
  blobBytes : Nat
  stoppedAtActionId : Option Nat
  countStoppedAtActionId : Option Nat
  selectedActionCount : Nat
  selectedActionBytes : Nat
deriving DecidableEq, Repr

inductive DaStep where
  | quarantine
  | deferTransfer (firstOverflow : Bool)
  | candidate (nextBlobBytes : Nat)
deriving DecidableEq, Repr

def evaluateDaStep
    (maxBlobBytes blobBytes : Nat)
    (transferCapacityExhausted : Bool)
    (action : Action) : DaStep :=
  if action.transferRoute = false then
    DaStep.candidate blobBytes
  else
    match classifySingleTransfer maxBlobBytes action.ciphertextSizes with
    | SingleTransferDecision.contributionOverflow => DaStep.quarantine
    | SingleTransferDecision.individuallyTooLarge _ => DaStep.quarantine
    | SingleTransferDecision.admissible contribution =>
        if transferCapacityExhausted then
          DaStep.deferTransfer false
        else
          match checkedAddUsize blobBytes contribution with
          | none => DaStep.deferTransfer true
          | some nextBlobBytes =>
              if nextBlobBytes > maxBlobBytes then
                DaStep.deferTransfer true
              else
                DaStep.candidate nextBlobBytes

def finishSelection
    (blobBytes actionCount actionBytes : Nat)
    (stoppedAtActionId countStoppedAtActionId : Option Nat)
    (selectedRev individuallyUnencodableRev deferredRev : List Nat) : Selection :=
  {
    selectedActionIds := selectedRev.reverse
    individuallyUnencodableActionIds := individuallyUnencodableRev.reverse
    deferredActionIds := deferredRev.reverse
    blobBytes := blobBytes
    stoppedAtActionId := stoppedAtActionId
    countStoppedAtActionId := countStoppedAtActionId
    selectedActionCount := actionCount
    selectedActionBytes := actionBytes
  }

def selectAux
    (limits : Limits)
    (blobBytes actionCount actionBytes : Nat)
    (transferCapacityExhausted : Bool)
    (stoppedAtActionId : Option Nat)
    (selectedRev individuallyUnencodableRev deferredRev : List Nat) :
    List Action -> Selection
  | [] =>
      finishSelection blobBytes actionCount actionBytes stoppedAtActionId none
        selectedRev individuallyUnencodableRev deferredRev
  | action :: rest =>
      match evaluateDaStep limits.maxBlobBytes blobBytes
          transferCapacityExhausted action with
      | DaStep.quarantine =>
          selectAux limits blobBytes actionCount actionBytes
            transferCapacityExhausted stoppedAtActionId selectedRev
            (action.actionId :: individuallyUnencodableRev) deferredRev rest
      | DaStep.deferTransfer firstOverflow =>
          let nextStoppedAt :=
            if firstOverflow && stoppedAtActionId.isNone then some action.actionId
            else stoppedAtActionId
          selectAux limits blobBytes actionCount actionBytes true nextStoppedAt
            selectedRev individuallyUnencodableRev
            (action.actionId :: deferredRev) rest
      | DaStep.candidate nextBlobBytes =>
          if actionCount ≥ limits.maxActionCount then
            {
              selectedActionIds := selectedRev.reverse
              individuallyUnencodableActionIds := individuallyUnencodableRev.reverse
              deferredActionIds := deferredRev.reverse
                ++ (action :: rest).map (fun item => item.actionId)
              blobBytes := blobBytes
              stoppedAtActionId := stoppedAtActionId
              countStoppedAtActionId := some action.actionId
              selectedActionCount := actionCount
              selectedActionBytes := actionBytes
            }
          else
            match checkedAddUsize actionBytes action.encodedBytes with
            | none =>
                selectAux limits blobBytes actionCount actionBytes
                  transferCapacityExhausted stoppedAtActionId selectedRev
                  individuallyUnencodableRev (action.actionId :: deferredRev) rest
            | some nextActionBytes =>
                if nextActionBytes > limits.maxActionBytes then
                  selectAux limits blobBytes actionCount actionBytes
                    transferCapacityExhausted stoppedAtActionId selectedRev
                    individuallyUnencodableRev (action.actionId :: deferredRev) rest
                else
                  match checkedAddUsize actionCount 1 with
                  | none =>
                      {
                        selectedActionIds := selectedRev.reverse
                        individuallyUnencodableActionIds :=
                          individuallyUnencodableRev.reverse
                        deferredActionIds := deferredRev.reverse
                          ++ (action :: rest).map (fun item => item.actionId)
                        blobBytes := blobBytes
                        stoppedAtActionId := stoppedAtActionId
                        countStoppedAtActionId := some action.actionId
                        selectedActionCount := actionCount
                        selectedActionBytes := actionBytes
                      }
                  | some nextActionCount =>
                      selectAux limits nextBlobBytes nextActionCount nextActionBytes
                        transferCapacityExhausted stoppedAtActionId
                        (action.actionId :: selectedRev)
                        individuallyUnencodableRev deferredRev rest

/-- Ordered greedy selection. Non-transfers consume no DA bytes. Individually
unencodable transfers are quarantined and skipped; the first cumulative
overflow defers that and all later encodable transfers while the scan keeps
later zero-DA actions eligible in their original relative order. -/
def selectWithLimits
    (limits : Limits)
    (actions : List Action) : Except SelectionReject Selection :=
  if limits.reservedActionCount > limits.maxActionCount
      || limits.reservedActionCount > usizeMax then
    Except.error SelectionReject.reservedActionCount
  else if limits.reservedActionBytes > limits.maxActionBytes
      || limits.reservedActionBytes > usizeMax then
    Except.error SelectionReject.reservedActionBytes
  else
    Except.ok
      (selectAux limits compactLengthPrefixBytes limits.reservedActionCount
        limits.reservedActionBytes false none [] [] [] actions)

/-- DA-only convenience projection used by tier arithmetic examples. -/
def select (maxBlobBytes : Nat) (actions : List Action) : Selection :=
  match selectWithLimits
      {
        maxBlobBytes := maxBlobBytes
        maxActionCount := usizeMax
        maxActionBytes := usizeMax
        reservedActionCount := 0
        reservedActionBytes := 0
      }
      actions with
  | Except.ok selection => selection
  | Except.error _ => finishSelection compactLengthPrefixBytes 0 0 none none [] [] []

structure Tier where
  chunkBytes : Nat
  maxBlobBytes : Nat
deriving DecidableEq, Repr

def oneKiBTier : Tier := { chunkBytes := 1024, maxBlobBytes := 174080 }
def fourKiBTier : Tier := { chunkBytes := 4096, maxBlobBytes := 696320 }
def sixteenKiBTier : Tier := { chunkBytes := 16384, maxBlobBytes := 2785280 }

/-- The locally derived authoring tiers. The arithmetic takes only canonical
blob length, never peer-selected tier input. Consensus binding is outside this
model. -/
def adaptiveTiers : List Tier := [oneKiBTier, fourKiBTier, sixteenKiBTier]

def smallestFittingTier : List Tier -> Nat -> Option Tier
  | [], _ => none
  | tier :: rest, blobBytes =>
      if blobBytes ≤ tier.maxBlobBytes then some tier
      else smallestFittingTier rest blobBytes

def adaptiveTierForBlobBytes (blobBytes : Nat) : Option Tier :=
  smallestFittingTier adaptiveTiers blobBytes

def oneKiBMaxBlobBytes : Nat := oneKiBTier.maxBlobBytes
def fourKiBMaxBlobBytes : Nat := fourKiBTier.maxBlobBytes
def maximumAdaptiveBlobBytes : Nat := sixteenKiBTier.maxBlobBytes

theorem raw_tier_exact_boundaries :
    adaptiveTierForBlobBytes 0 = some oneKiBTier ∧
    adaptiveTierForBlobBytes 174080 = some oneKiBTier ∧
    adaptiveTierForBlobBytes 174081 = some fourKiBTier ∧
    adaptiveTierForBlobBytes 696320 = some fourKiBTier ∧
    adaptiveTierForBlobBytes 696321 = some sixteenKiBTier ∧
    adaptiveTierForBlobBytes 2785280 = some sixteenKiBTier ∧
    adaptiveTierForBlobBytes 2785281 = none := by
  native_decide

/- Synthetic compact arithmetic fixture. Production encrypted-note sizes are
covered by separate full-wire boundary vectors; this is not a TPS claim. -/
def compactFixtureCiphertextSizes : List Nat := [611, 611]

def compactFixtureTransfer (actionId : Nat) : Action :=
  {
    actionId := actionId
    transferRoute := true
    ciphertextSizes := compactFixtureCiphertextSizes
  }

def plainAction (actionId : Nat) : Action :=
  {
    actionId := actionId
    transferRoute := false
    ciphertextSizes := []
  }

/-- The selector's relevant bridge projection: an ordered action with no
transfer-ciphertext DA contribution. The Rust conformance fixture materializes
this projection as an outbound bridge action. -/
def bridgeAction (actionId : Nat) : Action := plainAction actionId

def compactFixtureTransfers (count : Nat) : List Action :=
  (List.range count).map compactFixtureTransfer

def productionCiphertextSizes : List Nat := [2147, 2147]

def productionTransfer (actionId : Nat) : Action :=
  {
    actionId := actionId
    transferRoute := true
    ciphertextSizes := productionCiphertextSizes
  }

def productionTransfers (count : Nat) : List Action :=
  (List.range count).map productionTransfer

def productionInlineEncodedBytes : Nat := 128992
def autoCoinbaseEncodedBytes : Nat := 2525
def maxNativeBlockActionCount : Nat := 10000
def maxNativeBlockActionBytes : Nat := 67108864

def productionInlineTransfer (actionId : Nat) : Action :=
  { productionTransfer actionId with encodedBytes := productionInlineEncodedBytes }

def productionInlineTransfers (count : Nat) : List Action :=
  (List.range count).map productionInlineTransfer

def activeJointLimits : Limits :=
  {
    maxBlobBytes := maximumAdaptiveBlobBytes
    maxActionCount := maxNativeBlockActionCount
    maxActionBytes := maxNativeBlockActionBytes
    reservedActionCount := 1
    reservedActionBytes := autoCoinbaseEncodedBytes
  }

theorem compact_fixture_transfer_contributes_1234_bytes :
    transferBlobContribution compactFixtureCiphertextSizes = some 1234 := by
  rfl

theorem full_ml_kem_production_transfer_contributes_4306_bytes :
    transferBlobContribution productionCiphertextSizes = some 4306 := by
  rfl

theorem exact_single_transfer_capacity_accepts :
    classifySingleTransfer fourKiBMaxBlobBytes [696308] =
      SingleTransferDecision.admissible 696316 := by
  rfl

theorem one_byte_over_single_transfer_capacity_rejects :
    classifySingleTransfer fourKiBMaxBlobBytes [696309] =
      SingleTransferDecision.individuallyTooLarge 696317 := by
  rfl

theorem contribution_overflow_precedes_cumulative_capacity :
    classifySingleTransfer fourKiBMaxBlobBytes [usizeMax] =
      SingleTransferDecision.contributionOverflow := by
  rfl

theorem four_kib_capacity_accepts_exactly_564_compact_fixture_transfers :
    (select fourKiBMaxBlobBytes (compactFixtureTransfers 565)).selectedActionIds.length = 564 := by
  native_decide

theorem four_kib_da_only_capacity_accepts_exactly_161_full_ml_kem_transfers :
    (select fourKiBMaxBlobBytes (productionTransfers 162)).selectedActionIds.length = 161 := by
  native_decide

def activeJointCapacityCheck : Bool :=
  match selectWithLimits activeJointLimits (productionInlineTransfers 521) with
  | Except.error _ => false
  | Except.ok selection =>
      decide
        (selection.selectedActionIds.length = 520 ∧
          selection.deferredActionIds = [520] ∧
          selection.selectedActionCount = 521 ∧
          selection.selectedActionBytes = 67078365 ∧
          selection.blobBytes = 2239124)

theorem active_joint_capacity_selects_520_full_ml_kem_inline_transfers_plus_coinbase :
    activeJointCapacityCheck = true := by
  native_decide

theorem full_ml_kem_production_boundary_uses_693270_bytes :
    (select fourKiBMaxBlobBytes (productionTransfers 161)).blobBytes = 693270 := by
  native_decide

theorem first_cumulative_overflow_defers_transfers_but_not_later_bridge_actions :
    let actions := compactFixtureTransfers 565 ++ [bridgeAction 999]
    let selection := select fourKiBMaxBlobBytes actions
    selection.deferredActionIds = [564] ∧
      selection.selectedActionIds.getLast? = some 999 := by
  native_decide

theorem individual_oversize_does_not_head_of_line_block :
    let oversized : Action :=
      { actionId := 1, transferRoute := true, ciphertextSizes := [696309] }
    select fourKiBMaxBlobBytes
      [compactFixtureTransfer 0, oversized, plainAction 2, compactFixtureTransfer 3] =
      {
        selectedActionIds := [0, 2, 3]
        individuallyUnencodableActionIds := [1]
        deferredActionIds := []
        blobBytes := 2472
        stoppedAtActionId := none
        countStoppedAtActionId := none
        selectedActionCount := 3
        selectedActionBytes := 0
      } := by
  native_decide

theorem adaptive_compact_fixture_141_uses_one_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (compactFixtureTransfers 141)).blobBytes =
      some oneKiBTier := by
  native_decide

theorem adaptive_compact_fixture_142_uses_four_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (compactFixtureTransfers 142)).blobBytes =
      some fourKiBTier := by
  native_decide

theorem adaptive_full_ml_kem_40_uses_one_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (productionTransfers 40)).blobBytes =
      some oneKiBTier := by
  native_decide

theorem adaptive_full_ml_kem_41_uses_four_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (productionTransfers 41)).blobBytes =
      some fourKiBTier := by
  native_decide

theorem adaptive_full_ml_kem_161_uses_four_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (productionTransfers 161)).blobBytes =
      some fourKiBTier := by
  native_decide

theorem adaptive_full_ml_kem_162_uses_sixteen_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (productionTransfers 162)).blobBytes =
      some sixteenKiBTier := by
  native_decide

theorem adaptive_full_ml_kem_516_uses_sixteen_kib :
    adaptiveTierForBlobBytes
      (select maximumAdaptiveBlobBytes (productionTransfers 516)).blobBytes =
      some sixteenKiBTier := by
  native_decide

theorem adaptive_maximum_accepts_646_and_defers_647th :
    let selection := select maximumAdaptiveBlobBytes (productionTransfers 647)
    selection.selectedActionIds.length = 646 ∧
      selection.deferredActionIds = [646] ∧
      selection.blobBytes = 2781680 := by
  native_decide

end DaTemplateSelection
end Native
end Hegemon
