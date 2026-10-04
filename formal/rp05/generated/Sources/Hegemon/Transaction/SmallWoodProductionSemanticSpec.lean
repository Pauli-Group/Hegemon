import Hegemon.Transaction.SmallWoodProductionConstraintTableGenerated
import Hegemon.Transaction.Poseidon2NoteCommitment

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

namespace Hegemon
namespace Transaction
namespace SmallWoodProductionConstraintRefinement

/-
The generated constraint table is an extraction of the Rust builder.  This file
is deliberately independent of that extraction: it restates the deployed V4
compressed relation, including all three Poseidon2 permutations, as named Lean
code and reconstructs its symbolic program.
The production-map gate compares the generated roots and expression prefix to
this program, so regenerating a coherently weakened Rust table cannot bless the
weakening without also changing this reviewed specification.
-/

private def maxInputs : Nat := 2
private def maxOutputs : Nat := 2
private def balanceSlots : Nat := 4
private def merkleDepth : Nat := 32
private def hashLimbs : Nat := 6
private def multisigMaxSigners : Nat := 6
private def signerTagWords : Nat := 5
private def denseRangeRowCount : Nat := 5
private def publicValueCount : Nat := 78
private def rowCount : Nat := 699

private def publicInputFlag0 : Nat := 0
private def publicOutputFlag0 : Nat := 2
private def publicCiphertextHashes : Nat := 28
private def publicFee : Nat := 40
private def publicValueBalanceSign : Nat := 41
private def publicValueBalanceMagnitude : Nat := 42
private def publicSlotAssets : Nat := 49
private def publicStableEnabled : Nat := 53
private def publicStableAsset : Nat := 54
private def publicStablePolicyVersion : Nat := 55
private def publicStableIssuanceSign : Nat := 56
private def publicStableIssuanceMagnitude : Nat := 57
private def publicStablePolicyHash : Nat := 58
private def publicStableOracle : Nat := 64
private def publicStableAttestation : Nat := 70

private def inputRows : Nat := 34
private def outputRows : Nat := 12
private def valueRangeBase : Nat := 92
private def authBase : Nat := valueRangeBase
private def denseRangeBase : Nat := authBase + 149
private def inlineBindingBase : Nat := denseRangeBase + denseRangeRowCount
private def inlineMerkleGroups : Nat := 6
private def poseidonRowsBase : Nat := 273
private def poseidonRowsPerPermutation : Nat := 142
private def poseidonWidth : Nat := 12
private def compressedPoseidonSboxRows : Nat := 118
private def compressedPoseidonConstraintCount : Nat := 130
private def compressedPoseidonGroupCount : Nat := 3

private def authModeRows : Nat := 3
private def authInputPrfRows : Nat := 2
private def authInputKeyRows : Nat := 8
private def authLegacyDigestRows : Nat := 5
private def authAccumulatorDigestRows : Nat := 6
private def authNextAccumulatorDigestRows : Nat := 6
private def authValueLockDigestRows : Nat := 6
private def authStatementDigestRows : Nat := 6
private def authPolicyRows : Nat := 6
private def authIntentRows : Nat := 6
private def authScalarRows : Nat := 18
private def authThresholdFlagRows : Nat := 6
private def authSignerCountFlagRows : Nat := 6
private def authCountFlagRows : Nat := 7
private def authNextCountFlagRows : Nat := 7
private def authPolicySignerRows : Nat := 30
private def authMembershipFlagRows : Nat := 6
private def authDistinctInverseRows : Nat := 15
private def authConstraintCount : Nat := 374

private def rowInputBase (input : Nat) : Nat := input * inputRows
private def rowInputValue (input : Nat) : Nat := rowInputBase input
private def rowInputAsset (input : Nat) : Nat := rowInputBase input + 1
private def rowInputDirection (input bit : Nat) : Nat := rowInputBase input + 2 + bit
private def rowOutputBase (output : Nat) : Nat := maxInputs * inputRows + output * outputRows
private def rowOutputValue (output : Nat) : Nat := rowOutputBase output
private def rowOutputAsset (output : Nat) : Nat := rowOutputBase output + 1
private def rowOutputAuthKey (output limb : Nat) : Nat :=
  rowOutputBase output + outputRows - 4 + limb
private def rowDenseRange (row : Nat) : Nat :=
  denseRangeBase + row
private def rowAuthMode (mode : Nat) : Nat := authBase + mode
private def rowAuthInputPrf (input : Nat) : Nat := authBase + authModeRows + input
private def rowAuthInputKey (input limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + input * 4 + limb
private def rowAuthLegacyDigest (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows + limb
private def rowAuthCurrentDigest (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + limb
private def rowAuthNextDigest (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows + limb
private def rowAuthValueLockDigest (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows +
    authNextAccumulatorDigestRows + limb
private def rowAuthStatementDigest (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows +
    authNextAccumulatorDigestRows + authValueLockDigestRows + limb
private def rowAuthPolicy (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows +
    authNextAccumulatorDigestRows + authValueLockDigestRows +
    authStatementDigestRows + limb
private def rowAuthIntent (limb : Nat) : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows +
    authNextAccumulatorDigestRows + authValueLockDigestRows +
    authStatementDigestRows + authPolicyRows + limb
private def rowAuthThreshold : Nat :=
  authBase + authModeRows + authInputPrfRows + authInputKeyRows +
    authLegacyDigestRows + authAccumulatorDigestRows +
    authNextAccumulatorDigestRows + authValueLockDigestRows +
    authStatementDigestRows + authPolicyRows + authIntentRows
private def rowAuthSignerCount : Nat := rowAuthThreshold + 1
private def rowAuthCount : Nat := rowAuthThreshold + 2
private def rowAuthSlot (slot : Nat) : Nat := rowAuthThreshold + 3 + slot
private def rowAuthNextCount : Nat := rowAuthThreshold + 3 + multisigMaxSigners
private def rowAuthNextSlot (slot : Nat) : Nat :=
  rowAuthThreshold + 4 + multisigMaxSigners + slot
private def rowAuthSigner : Nat := rowAuthThreshold + 4 + multisigMaxSigners * 2
private def rowAuthDuplicateInverse : Nat := rowAuthSigner + 1
private def rowAuthThresholdFlag (flag : Nat) : Nat := rowAuthThreshold + authScalarRows + flag
private def rowAuthSignerCountFlag (flag : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows + flag
private def rowAuthCountFlag (flag : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows +
    authSignerCountFlagRows + flag
private def rowAuthNextCountFlag (flag : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows +
    authSignerCountFlagRows + authCountFlagRows + flag
private def rowAuthPolicySigner (index : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows +
    authSignerCountFlagRows + authCountFlagRows + authNextCountFlagRows + index
private def rowAuthMembershipFlag (flag : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows +
    authSignerCountFlagRows + authCountFlagRows + authNextCountFlagRows +
    authPolicySignerRows + flag
private def rowAuthDistinctInverse (pair : Nat) : Nat :=
  rowAuthThreshold + authScalarRows + authThresholdFlagRows +
    authSignerCountFlagRows + authCountFlagRows + authNextCountFlagRows +
    authPolicySignerRows + authMembershipFlagRows + pair
private def rowInlineMerkleBinding (group component : Nat) : Nat :=
  inlineBindingBase + group * 4 + component
private def rowInlinePolicyBinding (component : Nat) : Nat :=
  inlineBindingBase + inlineMerkleGroups * 4 + component
private def rowPoseidon (group step limb : Nat) : Nat :=
  poseidonRowsBase + (group * poseidonRowsPerPermutation + step) * poseidonWidth + limb

structure ProductionSemanticProgramBuilder where
  expressions : List ProductionConstraintExpression
  roots : List Nat
deriving DecidableEq, Repr

private abbrev BuildM := StateM ProductionSemanticProgramBuilder

private def initialSemanticExpressions : List ProductionConstraintExpression :=
  [ .constExpr 0, .constExpr 1, .constExpr 2,
    .constExpr (goldilocksModulus - 1) ]
    ++ (List.range publicValueCount).map .publicExpr
    ++ (List.range rowCount).map .witnessExpr
    ++ (List.range balanceSlots).map .slotInverseExpr
    ++ (List.range 2).map .stableSelectorExpr

private def initialBuilder : ProductionSemanticProgramBuilder :=
  { expressions := initialSemanticExpressions, roots := [] }

private def expressionIndex? (expression : ProductionConstraintExpression) :
    List ProductionConstraintExpression -> Nat -> Option Nat
  | [], _ => none
  | candidate :: candidates, index =>
      if candidate = expression then some index
      else expressionIndex? expression candidates (index + 1)

private def intern (expression : ProductionConstraintExpression) : BuildM Nat := fun state =>
  match expressionIndex? expression state.expressions 0 with
  | some index => (index, state)
  | none =>
      let index := state.expressions.length
      (index, { state with expressions := state.expressions ++ [expression] })

private def constant (value : Nat) : BuildM Nat :=
  intern (.constExpr (fieldValue value))

private def publicValue (index : Nat) : Nat := 4 + index
private def witnessRow (index : Nat) : Nat := 4 + publicValueCount + index
private def slotInverse (slot : Nat) : Nat := 4 + publicValueCount + rowCount + slot
private def stableSelector (bit : Nat) : Nat :=
  4 + publicValueCount + rowCount + balanceSlots + bit

private def add (left right : Nat) : BuildM Nat :=
  if left = 0 then pure right
  else if right = 0 then pure left
  else
    let ordered := if left <= right then (left, right) else (right, left)
    intern (.addExpr ordered.1 ordered.2)

private def sub (left right : Nat) : BuildM Nat :=
  if right = 0 then pure left
  else if left = right then pure 0
  else intern (.subExpr left right)

private def mul (left right : Nat) : BuildM Nat :=
  if left = 0 || right = 0 then pure 0
  else if left = 1 then pure right
  else if right = 1 then pure left
  else
    let ordered := if left <= right then (left, right) else (right, left)
    intern (.mulExpr ordered.1 ordered.2)

private def neg (value : Nat) : BuildM Nat :=
  if value = 0 then pure 0 else intern (.negExpr value)

private def emit (root : Nat) : BuildM Unit :=
  modify fun state => { state with roots := state.roots ++ [root] }

private def addAll (values : List Nat) : BuildM Nat := do
  let mut accumulator := 0
  for value in values do
    accumulator <- add accumulator value
  pure accumulator

private def mulAll (values : List Nat) : BuildM Nat := do
  let mut accumulator := 1
  for value in values do
    accumulator <- mul accumulator value
  pure accumulator

private def mul3 (left middle right : Nat) : BuildM Nat := do
  mul (← mul left middle) right

private def poseidonSbox (value : Nat) : BuildM Nat := do
  let value2 ← mul value value
  let value4 ← mul value2 value2
  let value6 ← mul value4 value2
  mul value6 value

private def poseidonApplyMds4 (input : List Nat) : BuildM (List Nat) := do
  let x0 := input.getD 0 0
  let x1 := input.getD 1 0
  let x2 := input.getD 2 0
  let x3 := input.getD 3 0
  let t01 ← add x0 x1
  let t23 ← add x2 x3
  let t0123 ← add t01 t23
  let t01123 ← add t0123 x1
  let t01233 ← add t0123 x3
  let output3 ← add t01233 (← add x0 x0)
  let output1 ← add t01123 (← add x2 x2)
  let output0 ← add t01123 t01
  let output2 ← add t01233 t23
  pure [output0, output1, output2, output3]

private def poseidonMdsLight (state : List Nat) : BuildM (List Nat) := do
  let mut mixed := []
  for block in List.range 3 do
    mixed := mixed ++ (← poseidonApplyMds4 ((state.drop (block * 4)).take 4))
  let mut columnSums := []
  for column in List.range 4 do
    let mut sum := 0
    for block in List.range 3 do
      sum ← add sum (mixed.getD (block * 4 + column) 0)
    columnSums := columnSums ++ [sum]
  let mut output := []
  for index in List.range poseidonWidth do
    output := output ++ [← add (mixed.getD index 0) (columnSums.getD (index % 4) 0)]
  pure output

private def poseidonExternalRound
    (state roundConstants : List Nat) : BuildM (List Nat) := do
  let mut sboxed := []
  for index in List.range poseidonWidth do
    let roundConstant ← constant (roundConstants.getD index 0)
    let withConstant ← add (state.getD index 0) roundConstant
    sboxed := sboxed ++ [← poseidonSbox withConstant]
  poseidonMdsLight sboxed

private def poseidonInternalRound
    (state : List Nat)
    (roundConstantValue : Nat) : BuildM (List Nat) := do
  let roundConstant ← constant roundConstantValue
  let first ← poseidonSbox (← add (state.getD 0 0) roundConstant)
  let sboxed := state.set 0 first
  let mut sum := 0
  for value in sboxed do
    sum ← add sum value
  let mut output := []
  for index in List.range poseidonWidth do
    let diagonal ← constant
      (Poseidon2NoteCommitment.internalMatrixDiagonal.getD index 0)
    let scaled ← mul (sboxed.getD index 0) diagonal
    output := output ++ [← add scaled sum]
  pure output

private def compressedPoseidonRow (group offset : Nat) : Nat :=
  poseidonRowsBase + group * poseidonRowsPerPermutation + offset

private def buildCompressedPoseidonGroup (group : Nat) : BuildM Unit := do
  let groupBase := compressedPoseidonRow group 0
  let mut state := (List.range poseidonWidth).map fun limb =>
    witnessRow (groupBase + limb)
  state ← poseidonMdsLight state
  let mut wireOffset := poseidonWidth

  for roundConstants in Poseidon2NoteCommitment.externalRoundConstantsInitial do
    for limb in List.range poseidonWidth do
      let wire := witnessRow (groupBase + wireOffset)
      let roundConstant ← constant (roundConstants.getD limb 0)
      emit (← sub wire (← add (state.getD limb 0) roundConstant))
      state := state.set limb (← sub wire roundConstant)
      wireOffset := wireOffset + 1
    state ← poseidonExternalRound state roundConstants

  for roundConstantValue in Poseidon2NoteCommitment.internalRoundConstants do
    let wire := witnessRow (groupBase + wireOffset)
    let roundConstant ← constant roundConstantValue
    emit (← sub wire (← add (state.getD 0 0) roundConstant))
    state := state.set 0 (← sub wire roundConstant)
    wireOffset := wireOffset + 1
    state ← poseidonInternalRound state roundConstantValue

  for roundConstants in Poseidon2NoteCommitment.externalRoundConstantsTerminal do
    for limb in List.range poseidonWidth do
      let wire := witnessRow (groupBase + wireOffset)
      let roundConstant ← constant (roundConstants.getD limb 0)
      emit (← sub wire (← add (state.getD limb 0) roundConstant))
      state := state.set limb (← sub wire roundConstant)
      wireOffset := wireOffset + 1
    state ← poseidonExternalRound state roundConstants

  for limb in List.range poseidonWidth do
    let finalValue := witnessRow
      (groupBase + poseidonWidth + compressedPoseidonSboxRows + limb)
    emit (← sub finalValue (state.getD limb 0))

private def buildCompressedPoseidonSemantics : BuildM Unit := do
  for group in List.range compressedPoseidonGroupCount do
    buildCompressedPoseidonGroup group

private def boolPolynomial (bit : Nat) : BuildM Nat := do
  mul bit (← sub bit 1)

private def selectedSlotWeight (bit0 bit1 slot : Nat) : BuildM Nat := do
  let inverse0 <- sub 1 bit0
  let inverse1 <- sub 1 bit1
  match slot with
  | 0 => mul inverse0 inverse1
  | 1 => mul bit0 inverse1
  | 2 => mul inverse0 bit1
  | _ => mul bit0 bit1

private def selectedSlotAsset (bit0 bit1 : Nat) : BuildM Nat := do
  let mut result := 0
  for slot in List.range balanceSlots do
    let weight <- selectedSlotWeight bit0 bit1 slot
    let term <- mul weight (publicValue (publicSlotAssets + slot))
    result <- add result term
  pure result

private def slotMembershipZero (asset : Nat) : BuildM Nat := do
  let mut result := 1
  for slot in List.range balanceSlots do
    result <- mul result (← sub asset (publicValue (publicSlotAssets + slot)))
  pure result

private def slotMembershipWeights (asset : Nat) : BuildM (List Nat) := do
  let mut weights := []
  for slot in List.range balanceSlots do
    let mut numerator := 1
    for other in List.range balanceSlots do
      if other != slot then
        numerator <- mul numerator (← sub asset (publicValue (publicSlotAssets + other)))
    weights := weights ++ [← mul numerator (slotInverse slot)]
  pure weights

private def signedFromParts (sign magnitude : Nat) : BuildM Nat := do
  let twiceSign <- add sign sign
  sub magnitude (← mul twiceSign magnitude)

private def radixFourDigitPolynomial (digit : Nat) : BuildM Nat := do
  let accumulator <- mul digit (← sub digit 1)
  let accumulator <- mul accumulator (← sub digit (← constant 2))
  mul accumulator (← sub digit (← constant 3))

private def slotActive (signerCountFlags : List Nat) (slot : Nat) : BuildM Nat :=
  addAll (signerCountFlags.drop slot)

private def buildPublicAndInputSemantics : BuildM Unit := do
  for input in List.range maxInputs do
    emit (← boolPolynomial (publicValue (publicInputFlag0 + input)))
  for output in List.range maxOutputs do
    emit (← boolPolynomial (publicValue (publicOutputFlag0 + output)))
  emit (← boolPolynomial (publicValue publicValueBalanceSign))
  emit (← boolPolynomial (publicValue publicStableEnabled))
  emit (← boolPolynomial (publicValue publicStableIssuanceSign))

  for input in List.range maxInputs do
    let asset := witnessRow (rowInputAsset input)
    let flag := publicValue (publicInputFlag0 + input)
    for bit in List.range merkleDepth do
      emit (← boolPolynomial (witnessRow (rowInputDirection input bit)))
    -- The Rust builder materializes this position expression even though the
    -- deployed inline-Merkle relation does not emit it as a separate root.
    let mut position := 0
    for bit in List.range merkleDepth do
      position <- add position (← mul (witnessRow (rowInputDirection input bit))
        (← constant (2 ^ bit)))
    emit (← mul flag (← slotMembershipZero asset))

  for group in List.range inlineMerkleGroups do
    let current := witnessRow (rowInlineMerkleBinding group 0)
    let left := witnessRow (rowInlineMerkleBinding group 1)
    let right := witnessRow (rowInlineMerkleBinding group 2)
    let direction := witnessRow (rowInlineMerkleBinding group 3)
    emit (← sub current (← add left (← mul direction (← sub right left))))

private def buildOutputAndStablecoinSemantics : BuildM Unit := do
  for output in List.range maxOutputs do
    let asset := witnessRow (rowOutputAsset output)
    let flag := publicValue (publicOutputFlag0 + output)
    let inactive <- sub 1 flag
    emit (← mul flag (← slotMembershipZero asset))
    for limb in List.range hashLimbs do
      emit (← mul inactive (publicValue (publicCiphertextHashes + output * hashLimbs + limb)))

  let bit0 := stableSelector 0
  let bit1 := stableSelector 1
  let stableEnabled := publicValue publicStableEnabled
  let stableDisabled <- sub 1 stableEnabled
  emit (← sub (← selectedSlotAsset bit0 bit1) (publicValue publicStableAsset))
  emit (← mul stableEnabled (← selectedSlotWeight bit0 bit1 0))
  emit (← mul stableDisabled (publicValue publicStableAsset))
  emit (← mul stableDisabled (publicValue publicStablePolicyVersion))
  emit (← mul stableDisabled (publicValue publicStableIssuanceSign))
  emit (← mul stableDisabled (publicValue publicStableIssuanceMagnitude))
  for limb in List.range hashLimbs do
    emit (← mul stableDisabled (publicValue (publicStablePolicyHash + limb)))
  for limb in List.range hashLimbs do
    emit (← mul stableDisabled (publicValue (publicStableOracle + limb)))
  for limb in List.range hashLimbs do
    emit (← mul stableDisabled (publicValue (publicStableAttestation + limb)))

private def buildBalanceAndRangeSemantics : BuildM Unit := do
  let bit0 := stableSelector 0
  let bit1 := stableSelector 1
  let stableEnabled := publicValue publicStableEnabled
  let signedValueBalance <- signedFromParts
    (publicValue publicValueBalanceSign) (publicValue publicValueBalanceMagnitude)
  let signedStableIssuance <- signedFromParts
    (publicValue publicStableIssuanceSign) (publicValue publicStableIssuanceMagnitude)
  let nativeExpected <- sub (publicValue publicFee) signedValueBalance

  for slot in List.range balanceSlots do
    let mut delta := 0
    for input in List.range maxInputs do
      let flag := publicValue (publicInputFlag0 + input)
      let value := witnessRow (rowInputValue input)
      let asset := witnessRow (rowInputAsset input)
      let weights <- slotMembershipWeights asset
      let weighted <- mul (← mul flag value) (weights.getD slot 0)
      delta <- add delta weighted
    for output in List.range maxOutputs do
      let flag := publicValue (publicOutputFlag0 + output)
      let value := witnessRow (rowOutputValue output)
      let asset := witnessRow (rowOutputAsset output)
      let weights <- slotMembershipWeights asset
      let weighted <- mul (← mul flag value) (weights.getD slot 0)
      delta <- sub delta weighted
    if slot = 0 then
      emit (← sub delta nativeExpected)
    else
      let stableWeight <- selectedSlotWeight bit0 bit1 slot
      let expected <- mul (← mul stableEnabled stableWeight) signedStableIssuance
      emit (← sub delta expected)

  for row in List.range (denseRangeRowCount - 1) do
    emit (← radixFourDigitPolynomial (witnessRow (rowDenseRange row)))
  emit (← boolPolynomial (witnessRow (rowDenseRange (denseRangeRowCount - 1))))

private def buildAuthorizationSemantics : BuildM Unit := do
  let authStart := (← get).roots.length
  let modeSingle := witnessRow (rowAuthMode 0)
  let modeApproval := witnessRow (rowAuthMode 1)
  let modeFinal := witnessRow (rowAuthMode 2)
  let input0Flag := publicValue publicInputFlag0
  let input1Flag := publicValue (publicInputFlag0 + 1)
  let output0Flag := publicValue publicOutputFlag0
  let nonSingle <- add modeApproval modeFinal
  for mode in [modeSingle, modeApproval, modeFinal] do
    emit (← boolPolynomial mode)
  emit (← sub (← add (← add modeSingle modeApproval) modeFinal) 1)

  let threshold := witnessRow rowAuthThreshold
  let signerCount := witnessRow rowAuthSignerCount
  let count := witnessRow rowAuthCount
  let approvedSlots := (List.range multisigMaxSigners).map fun slot =>
    witnessRow (rowAuthSlot slot)
  let nextCount := witnessRow rowAuthNextCount
  let nextApprovedSlots := (List.range multisigMaxSigners).map fun slot =>
    witnessRow (rowAuthNextSlot slot)
  let reservedSigner := witnessRow rowAuthSigner
  let reservedDuplicateInverse := witnessRow rowAuthDuplicateInverse
  let thresholdFlags := (List.range authThresholdFlagRows).map fun flag =>
    witnessRow (rowAuthThresholdFlag flag)
  let signerCountFlags := (List.range authSignerCountFlagRows).map fun flag =>
    witnessRow (rowAuthSignerCountFlag flag)
  let countFlags := (List.range authCountFlagRows).map fun flag =>
    witnessRow (rowAuthCountFlag flag)
  let nextCountFlags := (List.range authNextCountFlagRows).map fun flag =>
    witnessRow (rowAuthNextCountFlag flag)
  let policySignerTags := (List.range authPolicySignerRows).map fun index =>
    witnessRow (rowAuthPolicySigner index)
  let membershipFlags := (List.range authMembershipFlagRows).map fun flag =>
    witnessRow (rowAuthMembershipFlag flag)
  let policyDistinctInverses := (List.range authDistinctInverseRows).map fun pair =>
    witnessRow (rowAuthDistinctInverse pair)

  for limb in List.range hashLimbs do
    emit (← mul modeSingle (witnessRow (rowAuthPolicy limb)))
    emit (← mul modeSingle (witnessRow (rowAuthIntent limb)))
  for value in [threshold, signerCount, count, nextCount, reservedSigner,
      reservedDuplicateInverse] do
    emit (← mul modeSingle value)
  for value in approvedSlots do emit (← mul modeSingle value)
  for value in nextApprovedSlots do emit (← mul modeSingle value)
  for value in thresholdFlags do emit (← mul modeSingle value)
  for value in signerCountFlags do emit (← mul modeSingle value)
  for value in countFlags do emit (← mul modeSingle value)
  for value in nextCountFlags do emit (← mul modeSingle value)
  for value in membershipFlags do emit (← mul modeSingle value)
  for value in policySignerTags do emit (← mul modeSingle value)
  for value in policyDistinctInverses do emit (← mul modeSingle value)

  for _ in List.range (5 + hashLimbs * 4) do emit 0
  emit (← mul (witnessRow (rowInlinePolicyBinding 2))
    (← sub (witnessRow (rowInlinePolicyBinding 0))
      (witnessRow (rowInlinePolicyBinding 1))))

  let legacyPrf := witnessRow (rowAuthLegacyDigest 0)
  let currentPrf := witnessRow (rowAuthCurrentDigest 4)
  let valueLockPrf := witnessRow (rowAuthValueLockDigest 4)
  for input in List.range maxInputs do
    let flag := publicValue (publicInputFlag0 + input)
    let approvalPrf := if input = 0 then currentPrf else legacyPrf
    let finalPrf := if input = 0 then valueLockPrf else currentPrf
    let expectedPrf <- mul flag (← add (← add (← mul modeSingle legacyPrf)
      (← mul modeApproval approvalPrf)) (← mul modeFinal finalPrf))
    emit (← sub (witnessRow (rowAuthInputPrf input)) expectedPrf)
    for limb in List.range 4 do
      let legacyKey := witnessRow (rowAuthLegacyDigest (1 + limb))
      let currentKey := witnessRow (rowAuthCurrentDigest limb)
      let valueLockKey := witnessRow (rowAuthValueLockDigest limb)
      let approvalKey := if input = 0 then currentKey else legacyKey
      let finalKey := if input = 0 then valueLockKey else currentKey
      let expectedKey <- mul flag (← add (← add (← mul modeSingle legacyKey)
        (← mul modeApproval approvalKey)) (← mul modeFinal finalKey))
      emit (← sub (witnessRow (rowAuthInputKey input limb)) expectedKey)
  emit (← mul modeApproval (← sub input0Flag 1))
  emit (← mul modeApproval (← sub input1Flag 1))
  emit (← mul modeApproval (← sub output0Flag 1))
  emit (← mul modeFinal (← sub input0Flag 1))
  emit (← mul modeFinal (← sub input1Flag 1))
  for limb in List.range 4 do
    emit (← mul modeApproval (← sub (witnessRow (rowOutputAuthKey 0 limb))
      (witnessRow (rowAuthNextDigest limb))))

  for bit in thresholdFlags do emit (← mul nonSingle (← boolPolynomial bit))
  emit (← mul nonSingle (← sub (← addAll thresholdFlags) 1))
  let mut thresholdValue := 0
  for entry in thresholdFlags.zipIdx do
    thresholdValue <- add thresholdValue (← mul entry.1 (← constant (entry.2 + 1)))
  emit (← mul nonSingle (← sub threshold thresholdValue))
  for bit in signerCountFlags do emit (← mul nonSingle (← boolPolynomial bit))
  emit (← mul nonSingle (← sub (← addAll signerCountFlags) 1))
  let mut signerCountValue := 0
  for entry in signerCountFlags.zipIdx do
    signerCountValue <- add signerCountValue (← mul entry.1 (← constant (entry.2 + 1)))
  emit (← mul nonSingle (← sub signerCount signerCountValue))
  let mut thresholdExceedsSignerCount := 0
  for entry in thresholdFlags.zipIdx do
    let invalidSignerCounts <- addAll (signerCountFlags.take entry.2)
    thresholdExceedsSignerCount <- add thresholdExceedsSignerCount
      (← mul entry.1 invalidSignerCounts)
  emit (← mul nonSingle thresholdExceedsSignerCount)

  for bit in countFlags do emit (← mul nonSingle (← boolPolynomial bit))
  emit (← mul nonSingle (← sub (← addAll countFlags) 1))
  let mut countValue := 0
  for entry in countFlags.zipIdx do
    countValue <- add countValue (← mul entry.1 (← constant entry.2))
  emit (← mul nonSingle (← sub count countValue))
  for bit in nextCountFlags do emit (← mul modeApproval (← boolPolynomial bit))
  emit (← mul modeApproval (← sub (← addAll nextCountFlags) 1))
  let mut nextCountValue := 0
  for entry in nextCountFlags.zipIdx do
    nextCountValue <- add nextCountValue (← mul entry.1 (← constant entry.2))
  emit (← mul modeApproval (← sub nextCount nextCountValue))
  emit (← mul modeApproval (← sub (← sub nextCount count) 1))
  emit (← mul modeApproval (countFlags.getD multisigMaxSigners 0))

  for entry in approvedSlots.zipIdx do
    emit (← mul nonSingle (← boolPolynomial entry.1))
    let gated <- mul nonSingle entry.1
    let inactive <- sub 1 (← slotActive signerCountFlags entry.2)
    emit (← mul gated inactive)
  emit (← mul nonSingle (← sub count (← addAll approvedSlots)))
  for entry in nextApprovedSlots.zipIdx do
    emit (← mul modeApproval (← boolPolynomial entry.1))
    let gated <- mul modeApproval entry.1
    let inactive <- sub 1 (← slotActive signerCountFlags entry.2)
    emit (← mul gated inactive)
  emit (← mul modeApproval (← sub nextCount (← addAll nextApprovedSlots)))
  for slot in List.range multisigMaxSigners do
    let membership := membershipFlags.getD slot 0
    let approved := approvedSlots.getD slot 0
    let nextApproved := nextApprovedSlots.getD slot 0
    emit (← mul3 modeApproval membership approved)
    emit (← mul modeApproval (← sub (← sub nextApproved approved) membership))
  emit (← mul modeApproval reservedSigner)
  emit (← mul modeApproval reservedDuplicateInverse)
  for bit in membershipFlags do emit (← mul modeApproval (← boolPolynomial bit))
  emit (← mul modeApproval (← sub (← addAll membershipFlags) 1))
  for slot in List.range multisigMaxSigners do
    let membership := membershipFlags.getD slot 0
    let gated <- mul modeApproval membership
    let inactive <- sub 1 (← slotActive signerCountFlags slot)
    emit (← mul gated inactive)
    for limb in List.range signerTagWords do
      let gated <- mul modeApproval membership
      let difference <- sub (witnessRow (rowAuthLegacyDigest limb))
        (policySignerTags.getD (slot * signerTagWords + limb) 0)
      emit (← mul gated difference)
  for slot in List.range multisigMaxSigners do
    let active <- slotActive signerCountFlags slot
    for limb in List.range signerTagWords do
      emit (← mul3 nonSingle (← sub 1 active)
        (policySignerTags.getD (slot * signerTagWords + limb) 0))
  let mut pair := 0
  for left in List.range multisigMaxSigners do
    for right in (List.range multisigMaxSigners).drop (left + 1) do
      let activePair <- mul (← slotActive signerCountFlags left)
        (← slotActive signerCountFlags right)
      let difference <- sub (policySignerTags.getD (left * signerTagWords) 0)
        (policySignerTags.getD (right * signerTagWords) 0)
      let inverse := policyDistinctInverses.getD pair 0
      let gated <- mul nonSingle activePair
      let distinct <- sub (← mul difference inverse) 1
      emit (← mul gated distinct)
      emit (← mul3 nonSingle (← sub 1 activePair) inverse)
      pair := pair + 1

  let mut finalBelowThreshold := 0
  for entry in thresholdFlags.zipIdx do
    let below <- addAll (countFlags.take (entry.2 + 1))
    finalBelowThreshold <- add finalBelowThreshold (← mul entry.1 below)
  emit (← mul modeFinal finalBelowThreshold)
  for limb in List.range hashLimbs do
    emit (← mul modeFinal (← sub (witnessRow (rowAuthIntent limb))
      (witnessRow (rowAuthStatementDigest limb))))
  emit (← mul modeFinal nextCount)
  for approved in nextApprovedSlots do emit (← mul modeFinal approved)
  emit (← mul modeFinal reservedSigner)
  emit (← mul modeFinal reservedDuplicateInverse)
  emit (← mul modeFinal (← sub (nextCountFlags.getD 0 0) 1))
  for flag in nextCountFlags.drop 1 do emit (← mul modeFinal flag)
  for flag in membershipFlags do emit (← mul modeFinal flag)
  let currentCount := (← get).roots.length
  for _ in List.range (authStart + authConstraintCount - currentCount) do emit 0

def productionSemanticProgram : ProductionSemanticProgramBuilder :=
  let build : BuildM Unit := do
    buildPublicAndInputSemantics
    buildOutputAndStablecoinSemantics
    buildBalanceAndRangeSemantics
    buildAuthorizationSemantics
    buildCompressedPoseidonSemantics
  (build.run initialBuilder).2

def productionPoseidonSemanticConstraintStart : Nat := 500

def productionPoseidonSemanticConstraintCount : Nat :=
  compressedPoseidonGroupCount * compressedPoseidonConstraintCount

def productionSemanticConstraintCount : Nat :=
  productionPoseidonSemanticConstraintStart + productionPoseidonSemanticConstraintCount

/--
The independently rebuilt suffix corresponding exactly to nonlinear roots 500 through 889.
Its construction runs the deployed initial MDS, four external rounds, twenty-two internal
rounds, and four terminal external rounds for each of the three packed Poseidon row groups.
-/
def productionPoseidonSemanticRoots : List Nat :=
  (productionSemanticProgram.roots.drop productionPoseidonSemanticConstraintStart).take
    productionPoseidonSemanticConstraintCount

def productionSemanticProgramBoundB (map : ProductionConstraintMap) : Bool :=
  decide (productionSemanticProgram.roots.length = productionSemanticConstraintCount)
    && decide (map.nonlinearConstraintRoots.take productionSemanticConstraintCount =
      productionSemanticProgram.roots)
    && decide (map.nonlinearExpressions.take productionSemanticProgram.expressions.length =
      productionSemanticProgram.expressions)

def semanticBalanceOmissionMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearConstraintRoots := activeConstraintMap.nonlinearConstraintRoots.set 117 0 }

def semanticAuthorizationSubstitutionMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearConstraintRoots := activeConstraintMap.nonlinearConstraintRoots.set 268 0 }

def semanticPoseidonTransitionSubstitutionMap : ProductionConstraintMap :=
  { activeConstraintMap with
    nonlinearConstraintRoots := activeConstraintMap.nonlinearConstraintRoots.set
      productionPoseidonSemanticConstraintStart 0 }

/--
Executable conformance evidence. This closed-table size check deliberately uses `native_decide`;
it is not the axiom-free equation-to-permutation refinement theorem.
-/
theorem production_semantic_program_has_exact_deployed_poseidon_suffix :
    productionSemanticProgram.roots.length = 890
      ∧ productionPoseidonSemanticConstraintStart = 500
      ∧ productionPoseidonSemanticConstraintCount = 390
      ∧ productionPoseidonSemanticRoots.length = 390 := by
  native_decide

theorem active_production_semantic_program_is_bound :
    productionSemanticProgramBoundB activeConstraintMap = true := by
  native_decide

theorem stablecoin_production_semantic_program_is_bound :
    productionSemanticProgramBoundB stablecoinConstraintMap = true := by
  native_decide

theorem production_semantic_program_binding_covers_poseidon_roots_500_through_889
    {map : ProductionConstraintMap}
    (bound : productionSemanticProgramBoundB map = true) :
    map.nonlinearConstraintRoots.take productionSemanticConstraintCount =
        productionSemanticProgram.roots
      ∧ map.nonlinearExpressions.take productionSemanticProgram.expressions.length =
        productionSemanticProgram.expressions := by
  simp only [productionSemanticProgramBoundB, Bool.and_eq_true] at bound
  exact ⟨of_decide_eq_true bound.1.2, of_decide_eq_true bound.2⟩

theorem coherent_balance_omission_rejects_independent_semantic_spec :
    productionSemanticProgramBoundB semanticBalanceOmissionMap = false := by
  native_decide

theorem authorization_substitution_rejects_independent_semantic_spec :
    productionSemanticProgramBoundB semanticAuthorizationSubstitutionMap = false := by
  native_decide

/--
Executable mutation evidence. Like the other closed generated-table checks in this file, this
uses `native_decide` and is not used to discharge the production digest-refinement premise.
-/
theorem poseidon_transition_substitution_rejects_independent_semantic_spec :
    productionSemanticProgramBoundB semanticPoseidonTransitionSubstitutionMap = false := by
  native_decide

end SmallWoodProductionConstraintRefinement
end Transaction
end Hegemon
