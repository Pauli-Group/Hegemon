import Hegemon.FullShakeRelation

open Hegemon.FullShakeRelation

namespace Hegemon
namespace FullShakeRelation
namespace GenerateFullShakeRelationVectors

/-!
Deterministic, dependency-free conformance vectors for the executable portion
of the prospective full SHAKE256 relation.  Digest values remain opaque natural
numbers here.  These vectors connect the finite Lean decision surfaces to an
independent Rust test; they do not manufacture any certificate from
`SecurityBoundary.lean`.
-/

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def boolListJson (values : List Bool) : String :=
  "[" ++ String.intercalate "," (values.map boolJson) ++ "]"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def stringListJson (values : List String) : String :=
  "[" ++ String.intercalate "," (values.map fun value => "\"" ++ value ++ "\"") ++ "]"

def noteKindName : NoteKind -> String
  | .ordinary => "ordinary"
  | .accumulator => "accumulator"
  | .valueLock => "value_lock"

def authModeName : AuthMode -> String
  | .singleKey => "single_key"
  | .accumulatorInit => "accumulator_init"
  | .approvalStep => "approval_step"
  | .valueLockCreation => "value_lock_creation"
  | .finalThresholdSpend => "final_threshold_spend"

def signedAmountJson (amount : SignedAmount) : String :=
  "{\"negative\":" ++ boolJson amount.negative
    ++ ",\"magnitude\":" ++ toString amount.magnitude ++ "}"

def noteSlotJson (note : NoteSlot) : String :=
  "{\"active\":" ++ boolJson note.active
    ++ ",\"kind\":\"" ++ noteKindName note.kind ++ "\""
    ++ ",\"value\":" ++ toString note.value
    ++ ",\"asset_id\":" ++ toString note.assetId ++ "}"

def noteSlotsJson (notes : Slot2 NoteSlot) : String :=
  "[" ++ noteSlotJson notes.first ++ "," ++ noteSlotJson notes.second ++ "]"

def accumulatorJson (state : AccumulatorState) : String :=
  "{\"policy_root\":" ++ toString state.policyRoot
    ++ ",\"intent_digest\":" ++ toString state.intentDigest
    ++ ",\"threshold\":" ++ toString state.threshold
    ++ ",\"signer_count\":" ++ toString state.signerCount
    ++ ",\"approval_count\":" ++ toString state.approvalCount
    ++ ",\"approved_slots\":" ++ boolListJson state.approvedSlots ++ "}"

def balanceRowJson (row : BalanceRow) : String :=
  "{\"input0\":" ++ toString row.input0
    ++ ",\"input1\":" ++ toString row.input1
    ++ ",\"output0\":" ++ toString row.output0
    ++ ",\"output1\":" ++ toString row.output1
    ++ ",\"expected_delta\":" ++ signedAmountJson row.expectedDelta ++ "}"

def activeAccumulatorNote : NoteSlot :=
  { active := true, kind := .accumulator, value := 0, assetId := nativeAssetId }

def activeValueLockNote : NoteSlot :=
  { active := true, kind := .valueLock, value := 7, assetId := nativeAssetId }

def policySignerTags : List Digest := [21, 22, 23, 0, 0, 0]

def policyDescriptor : AccumulatorState :=
  { policyRoot := 11,
    intentDigest := 12,
    threshold := 2,
    signerCount := 3,
    approvalCount := 0,
    approvedSlots := [false, false, false, false, false, false] }

def approvalCurrent : AccumulatorState :=
  { policyDescriptor with
    approvalCount := 1,
    approvedSlots := [true, false, false, false, false, false] }

def approvalNext : AccumulatorState :=
  { policyDescriptor with
    approvalCount := 2,
    approvedSlots := [true, true, false, false, false, false] }

def finalCurrent : AccumulatorState := approvalNext

def singleKeyValid : AuthSurface :=
  { mode := .singleKey,
    inputs := { first := ordinaryInput, second := inactiveNote },
    outputs := { first := ordinaryOutput, second := inactiveNote },
    current := zeroAccumulator,
    next := zeroAccumulator,
    signerTags := [0, 0, 0, 0, 0, 0],
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := false,
    statementIntent := 0 }

def accumulatorInitValid : AuthSurface :=
  { mode := .accumulatorInit,
    inputs := { first := ordinaryInput, second := inactiveNote },
    outputs := { first := activeAccumulatorNote, second := inactiveNote },
    current := zeroAccumulator,
    next := policyDescriptor,
    signerTags := policySignerTags,
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := true,
    statementIntent := 0 }

def approvalStepValid : AuthSurface :=
  { mode := .approvalStep,
    inputs := { first := activeAccumulatorNote, second := ordinaryInput },
    outputs := { first := activeAccumulatorNote, second := inactiveNote },
    current := approvalCurrent,
    next := approvalNext,
    signerTags := policySignerTags,
    derivedSignerTag := 22,
    chosenSignerSlot := 1,
    policyRootHashMatches := true,
    statementIntent := 12 }

def valueLockCreationValid : AuthSurface :=
  { mode := .valueLockCreation,
    inputs := { first := ordinaryInput, second := inactiveNote },
    outputs := { first := activeValueLockNote, second := inactiveNote },
    current := policyDescriptor,
    next := zeroAccumulator,
    signerTags := policySignerTags,
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := true,
    statementIntent := 12 }

def finalThresholdSpendValid : AuthSurface :=
  { mode := .finalThresholdSpend,
    inputs := { first := activeValueLockNote, second := activeAccumulatorNote },
    outputs := { first := ordinaryOutput, second := inactiveNote },
    current := finalCurrent,
    next := zeroAccumulator,
    signerTags := policySignerTags,
    derivedSignerTag := 0,
    chosenSignerSlot := 0,
    policyRootHashMatches := true,
    statementIntent := 12 }

def accumulatorInitPreapproved : AuthSurface :=
  { accumulatorInitValid with
    next :=
      { policyDescriptor with
        approvalCount := 1,
        approvedSlots := [true, false, false, false, false, false] } }

def duplicateApproval : AuthSurface :=
  { approvalStepValid with
    current := approvalNext,
    next :=
      { policyDescriptor with
        approvalCount := 3,
        approvedSlots := [true, true, true, false, false, false] } }

def approvalIntentLineageChange : AuthSurface :=
  { approvalStepValid with next := { approvalNext with intentDigest := 13 } }

def finalBelowThreshold : AuthSurface :=
  { finalThresholdSpendValid with
    current := { finalCurrent with threshold := 3 } }

def finalWrongIntent : AuthSurface :=
  { finalThresholdSpendValid with statementIntent := 13 }

def authCases : List (String × AuthSurface) :=
  [ ("single_key_valid", singleKeyValid),
    ("accumulator_init_valid", accumulatorInitValid),
    ("approval_step_valid", approvalStepValid),
    ("value_lock_creation_valid", valueLockCreationValid),
    ("final_threshold_spend_valid", finalThresholdSpendValid),
    ("single_key_typed_state_forgery", singleKeyTypedStateForgery),
    ("accumulator_init_preapproved", accumulatorInitPreapproved),
    ("duplicate_approval", duplicateApproval),
    ("approval_intent_lineage_change", approvalIntentLineageChange),
    ("final_without_accumulator_input", finalWithoutAccumulatorInput),
    ("final_below_threshold", finalBelowThreshold),
    ("final_wrong_intent", finalWrongIntent) ]

def zeroDeltaBalanced : BalanceRow :=
  { input0 := 7, input1 := 3, output0 := 5, output1 := 5,
    expectedDelta := zeroSignedAmount }

def balanceCases : List (String × BalanceRow) :=
  [ ("zero_delta_balanced", zeroDeltaBalanced),
    ("zero_delta_hidden_mint", { zeroDeltaBalanced with output1 := 6 }),
    ("positive_delta_fee",
      { input0 := 10, input1 := 0, output0 := 9, output1 := 0,
        expectedDelta := { negative := false, magnitude := 1 } }),
    ("negative_delta_burn",
      { input0 := 9, input1 := 0, output0 := 10, output1 := 0,
        expectedDelta := { negative := true, magnitude := 1 } }),
    ("negative_zero",
      { zeroDeltaBalanced with expectedDelta := negativeZero }),
    ("input_out_of_range",
      { zeroDeltaBalanced with input0 := maxNoteValue + 1 }) ]

def stableBase : PublicBalanceSurface :=
  { valueBalance := zeroSignedAmount,
    nativeRow := zeroDeltaBalanced,
    stableEnabled := false,
    stableIssuance := zeroSignedAmount }

def stableCases : List (String × PublicBalanceSurface) :=
  [ ("disabled_zero", stableBase),
    ("disabled_nonzero_issuance",
      { stableBase with stableIssuance := { negative := false, magnitude := 1 } }),
    ("enabled_mint_nonzero",
      { stableBase with
        stableEnabled := true,
        stableIssuance := { negative := false, magnitude := 10 } }),
    ("enabled_burn_nonzero",
      { stableBase with
        stableEnabled := true,
        stableIssuance := { negative := true, magnitude := 10 } }),
    ("enabled_zero", { stableBase with stableEnabled := true }),
    ("value_balance_nonzero",
      { stableBase with valueBalance := { negative := false, magnitude := 1 } }),
    ("native_negative_delta",
      { stableBase with
        nativeRow :=
          { input0 := 9, input1 := 0, output0 := 10, output1 := 0,
            expectedDelta := { negative := true, magnitude := 1 } } }) ]

def activityCaseJson (mask : Nat) : String :=
  let flags := flagsFromMask mask
  "{\"mask\":" ++ toString mask
    ++ ",\"input_flags\":" ++ boolListJson [flags.inputs.first, flags.inputs.second]
    ++ ",\"output_flags\":" ++ boolListJson [flags.outputs.first, flags.outputs.second]
    ++ ",\"expected_valid\":" ++ boolJson (activityAccepted flags) ++ "}"

def authCaseJson (entry : String × AuthSurface) : String :=
  let name := entry.1
  let surface := entry.2
  "{\"name\":\"" ++ name ++ "\""
    ++ ",\"mode\":\"" ++ authModeName surface.mode ++ "\""
    ++ ",\"inputs\":" ++ noteSlotsJson surface.inputs
    ++ ",\"outputs\":" ++ noteSlotsJson surface.outputs
    ++ ",\"current\":" ++ accumulatorJson surface.current
    ++ ",\"next\":" ++ accumulatorJson surface.next
    ++ ",\"signer_tags\":" ++ natListJson surface.signerTags
    ++ ",\"derived_signer_tag\":" ++ toString surface.derivedSignerTag
    ++ ",\"chosen_signer_slot\":" ++ toString surface.chosenSignerSlot
    ++ ",\"policy_root_hash_matches\":" ++ boolJson surface.policyRootHashMatches
    ++ ",\"statement_intent\":" ++ toString surface.statementIntent
    ++ ",\"expected_valid\":" ++ boolJson (authModeAccepted surface) ++ "}"

def balanceCaseJson (entry : String × BalanceRow) : String :=
  "{\"name\":\"" ++ entry.1 ++ "\",\"row\":" ++ balanceRowJson entry.2
    ++ ",\"expected_valid\":" ++ boolJson (balanceRowAccepted entry.2) ++ "}"

def stableCaseJson (entry : String × PublicBalanceSurface) : String :=
  let name := entry.1
  let surface := entry.2
  "{\"name\":\"" ++ name ++ "\""
    ++ ",\"value_balance\":" ++ signedAmountJson surface.valueBalance
    ++ ",\"native_row\":" ++ balanceRowJson surface.nativeRow
    ++ ",\"stable_enabled\":" ++ boolJson surface.stableEnabled
    ++ ",\"stable_issuance\":" ++ signedAmountJson surface.stableIssuance
    ++ ",\"expected_valid\":" ++ boolJson (publicBalanceAccepted surface) ++ "}"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\":1,\n"
    ++ "  \"authority\":\"finite Lean executable semantics; not a release certificate\",\n"
    ++ "  \"statement_widths\":{"
    ++ "\"magic\":" ++ toString canonicalWidths.magic
    ++ ",\"grammar_version\":" ++ toString canonicalWidths.grammarVersion
    ++ ",\"activity_flags\":" ++ toString canonicalWidths.activityFlags
    ++ ",\"anchor\":" ++ toString canonicalWidths.anchor
    ++ ",\"nullifiers\":" ++ toString canonicalWidths.nullifiers
    ++ ",\"commitments\":" ++ toString canonicalWidths.commitments
    ++ ",\"ciphertext_hashes\":" ++ toString canonicalWidths.ciphertextHashes
    ++ ",\"balance_asset_slots\":" ++ toString canonicalWidths.balanceAssetSlots
    ++ ",\"fee\":" ++ toString canonicalWidths.fee
    ++ ",\"value_balance\":" ++ toString canonicalWidths.valueBalance
    ++ ",\"stablecoin_binding\":" ++ toString canonicalWidths.stablecoinBinding
    ++ ",\"balance_tag\":" ++ toString canonicalWidths.balanceTag
    ++ ",\"activation_binding\":" ++ toString canonicalWidths.activationBinding
    ++ ",\"total\":" ++ toString canonicalWidths.total
    ++ ",\"digest\":" ++ toString digestBytes ++ "},\n"
    ++ "  \"activity_cases\":["
    ++ String.intercalate "," ((List.range 16).map activityCaseJson) ++ "],\n"
    ++ "  \"auth_cases\":[" ++ String.intercalate "," (authCases.map authCaseJson) ++ "],\n"
    ++ "  \"balance_cases\":["
    ++ String.intercalate "," (balanceCases.map balanceCaseJson) ++ "],\n"
    ++ "  \"stable_cases\":["
    ++ String.intercalate "," (stableCases.map stableCaseJson) ++ "],\n"
    ++ "  \"refinement_limits\":"
    ++ stringListJson
      [ "finite_cases_only",
        "opaque_digest_values_not_shake256",
        "no_arbitrary_byte_parser_equivalence",
        "no_rust_or_m4_acceptance_iff_proof",
        "no_zero_knowledge_or_pq128_qrom_certificate" ]
    ++ "\n}\n"

end GenerateFullShakeRelationVectors
end FullShakeRelation
end Hegemon

def main : IO Unit :=
  IO.print Hegemon.FullShakeRelation.GenerateFullShakeRelationVectors.vectorJson
