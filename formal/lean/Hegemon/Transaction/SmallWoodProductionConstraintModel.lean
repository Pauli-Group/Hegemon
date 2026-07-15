namespace Hegemon
namespace Transaction
namespace SmallWoodProductionConstraintRefinement

def goldilocksModulus : Nat := 18446744069414584321

def fieldValue (value : Nat) : Nat := value % goldilocksModulus

def fieldAdd (left right : Nat) : Nat :=
  (left + right) % goldilocksModulus

def fieldSub (left right : Nat) : Nat :=
  (left + goldilocksModulus - (right % goldilocksModulus)) % goldilocksModulus

def fieldMul (left right : Nat) : Nat :=
  (left * right) % goldilocksModulus

def fieldNeg (value : Nat) : Nat :=
  fieldSub 0 value

def fieldPow (base exponent : Nat) : Nat :=
  if exponent = 0 then
    1
  else
    let half := fieldPow base (exponent / 2)
    let squared := fieldMul half half
    if exponent % 2 = 0 then squared else fieldMul squared base
termination_by exponent
decreasing_by
  omega

def fieldInverse (value : Nat) : Nat :=
  if fieldValue value = 0 then 0 else fieldPow value (goldilocksModulus - 2)

structure PublicFieldRange where
  name : String
  start : Nat
  stop : Nat
deriving DecidableEq, Repr

inductive ProductionConstraintExpression where
  | constExpr (value : Nat)
  | publicExpr (index : Nat)
  | witnessExpr (index : Nat)
  | slotInverseExpr (slot : Nat)
  | stableSelectorExpr (bit : Nat)
  | addExpr (left right : Nat)
  | subExpr (left right : Nat)
  | mulExpr (left right : Nat)
  | negExpr (value : Nat)
deriving DecidableEq, Repr

def ProductionConstraintExpression.references : ProductionConstraintExpression -> List Nat
  | .addExpr left right | .subExpr left right | .mulExpr left right => [left, right]
  | .negExpr value => [value]
  | _ => []

def ProductionConstraintExpression.wellFormedAt
    (publicValueCount witnessRowCount expressionIndex : Nat) :
    ProductionConstraintExpression -> Bool
  | .publicExpr index => decide (index < publicValueCount)
  | .witnessExpr index => decide (index < witnessRowCount)
  | .slotInverseExpr slot => decide (slot < 4)
  | .stableSelectorExpr bit => decide (bit < 2)
  | expression => expression.references.all (fun reference => decide (reference < expressionIndex))

structure ProductionConstraintMap where
  publicFieldRanges : List PublicFieldRange
  publicValues : List Nat
  publicValueCount : Nat
  rawWitnessLength : Nat
  lppcRowCount : Nat
  lppcPackingFactor : Nat
  effectiveConstraintDegree : Nat
  linearConstraintCount : Nat
  linearTermCount : Nat
  auxiliaryWitnessLimbCount : Nat
  linearTermOffsets : List Nat
  linearTermIndices : List Nat
  linearTermCoefficients : List Nat
  linearTargets : List Nat
  nonlinearConstraintCount : Nat
  nonlinearExpressionCount : Nat
  nonlinearExpressions : List ProductionConstraintExpression
  nonlinearConstraintRoots : List Nat
  nonlinearProgramDigest : List Nat
deriving DecidableEq, Repr

structure ProductionLinearTargetBinding where
  targetIndex : Nat
  publicValueIndex : Nat
  additiveConstant : Nat
deriving DecidableEq, Repr

structure ProductionLinearConstraintPatch where
  constraintStart : Nat
  removedConstraintCount : Nat
  removedTermCount : Nat
  replacementTermOffsets : List Nat
  replacementTermIndices : List Nat
  replacementTermCoefficients : List Nat
  replacementTargets : List Nat
deriving DecidableEq, Repr

structure ProductionLinearTargetOverride where
  targetIndex : Nat
  value : Nat
deriving DecidableEq, Repr

structure ProductionConstraintMapTemplate where
  inputFlags : List Nat
  outputFlags : List Nat
  baseMap : ProductionConstraintMap
  linearConstraintPatches : List ProductionLinearConstraintPatch
  linearTargetOverrides : List ProductionLinearTargetOverride
  linearTargetBindings : List ProductionLinearTargetBinding
deriving DecidableEq, Repr

def ProductionLinearTargetBinding.evaluate
    (binding : ProductionLinearTargetBinding)
    (publicValues : List Nat) : Nat :=
  fieldAdd (publicValues.getD binding.publicValueIndex 0) binding.additiveConstant

def instantiateProductionLinearTargets
    (baseTargets : List Nat)
    (bindings : List ProductionLinearTargetBinding)
    (publicValues : List Nat) : List Nat :=
  bindings.foldl
    (fun targets binding =>
      targets.set binding.targetIndex (binding.evaluate publicValues))
    baseTargets

def replaceListSlice
    (values : List Nat)
    (start removed : Nat)
    (replacement : List Nat) : List Nat :=
  values.take start ++ replacement ++ values.drop (start + removed)

def ProductionLinearConstraintPatch.apply
    (patch : ProductionLinearConstraintPatch)
    (map : ProductionConstraintMap) : ProductionConstraintMap :=
  let constraintStop := patch.constraintStart + patch.removedConstraintCount
  let oldTermStart := map.linearTermOffsets.getD patch.constraintStart 0
  let oldTermStop := map.linearTermOffsets.getD constraintStop oldTermStart
  let replacementTermCount := patch.replacementTermIndices.length
  let replacementConstraintCount := patch.replacementTargets.length
  let prefixOffsets := map.linearTermOffsets.take (patch.constraintStart + 1)
  let replacementOffsets := patch.replacementTermOffsets.tail.map (oldTermStart + ·)
  let suffixOffsets := map.linearTermOffsets.drop (constraintStop + 1) |>.map fun offset =>
    oldTermStart + replacementTermCount + (offset - oldTermStop)
  { map with
    linearConstraintCount :=
      map.linearConstraintCount - patch.removedConstraintCount + replacementConstraintCount
    linearTermCount := map.linearTermCount - patch.removedTermCount + replacementTermCount
    linearTermOffsets := prefixOffsets ++ replacementOffsets ++ suffixOffsets
    linearTermIndices := replaceListSlice map.linearTermIndices oldTermStart
      patch.removedTermCount patch.replacementTermIndices
    linearTermCoefficients := replaceListSlice map.linearTermCoefficients oldTermStart
      patch.removedTermCount patch.replacementTermCoefficients
    linearTargets := replaceListSlice map.linearTargets patch.constraintStart
      patch.removedConstraintCount patch.replacementTargets }

def applyProductionLinearConstraintPatches
    (baseMap : ProductionConstraintMap)
    (patches : List ProductionLinearConstraintPatch) : ProductionConstraintMap :=
  patches.foldl (fun map patch => patch.apply map) baseMap

def applyProductionLinearTargetOverrides
    (targets : List Nat)
    (overrides : List ProductionLinearTargetOverride) : List Nat :=
  overrides.foldl
    (fun values override => values.set override.targetIndex override.value)
    targets

def ProductionConstraintMapTemplate.instantiate
    (template : ProductionConstraintMapTemplate)
    (publicValues : List Nat) : ProductionConstraintMap :=
  let patched := applyProductionLinearConstraintPatches
    template.baseMap template.linearConstraintPatches
  let overriddenTargets := applyProductionLinearTargetOverrides
    patched.linearTargets template.linearTargetOverrides
  { patched with
    publicValues := publicValues
    linearTargets := instantiateProductionLinearTargets
      overriddenTargets template.linearTargetBindings publicValues }

def productionBalanceSlotPadding : Nat := 4294967294

def canonicalProductionNonNativeBalanceSlotsB : List Nat -> Nat -> Bool
  | [], _ => true
  | asset :: rest, previous =>
      if asset == productionBalanceSlotPadding then
        rest.all (· == productionBalanceSlotPadding)
      else
        decide (previous < asset)
          && canonicalProductionNonNativeBalanceSlotsB rest asset

def canonicalProductionBalanceSlotAssetsB (publicValues : List Nat) : Bool :=
  let slots := (publicValues.drop 49).take 4
  decide (slots.length = 4)
    && decide (slots.head? = some 0)
    && canonicalProductionNonNativeBalanceSlotsB slots.tail 0

def canonicalProductionPublicValuesB (publicValues : List Nat) : Bool :=
  decide (publicValues.length = 78)
    && publicValues.all (fun value => decide (value < goldilocksModulus))
    && decide (publicValues.getD 0 2 < 2)
    && decide (publicValues.getD 1 2 < 2)
    && decide (publicValues.getD 2 2 < 2)
    && decide (publicValues.getD 3 2 < 2)
    && canonicalProductionBalanceSlotAssetsB publicValues
    && decide (publicValues.getD 76 0 = 3)
    && decide (publicValues.getD 77 0 = 2)

def ProductionConstraintMapTemplate.matchesPublicValues
    (template : ProductionConstraintMapTemplate)
    (publicValues : List Nat) : Bool :=
  decide (template.inputFlags = [publicValues.getD 0 2, publicValues.getD 1 2])
    && decide (template.outputFlags = [publicValues.getD 2 2, publicValues.getD 3 2])

def productionConstraintMapTemplateFor?
    (templates : List ProductionConstraintMapTemplate)
    (publicValues : List Nat) : Option ProductionConstraintMapTemplate :=
  templates.find? (fun template => template.matchesPublicValues publicValues)

def productionConstraintMapForCanonicalValues?
    (templates : List ProductionConstraintMapTemplate)
    (publicValues : List Nat) : Option ProductionConstraintMap :=
  if canonicalProductionPublicValuesB publicValues then
    (productionConstraintMapTemplateFor? templates publicValues).map
      (fun template => template.instantiate publicValues)
  else
    none

def expressionProgramWellFormedB (map : ProductionConstraintMap) : Bool :=
  map.nonlinearExpressions.zipIdx.all fun expressionAndIndex =>
    expressionAndIndex.1.wellFormedAt
      map.publicValueCount map.lppcRowCount expressionAndIndex.2

def ProductionConstraintMap.sparseTableWellFormedB
    (map : ProductionConstraintMap) : Bool :=
  decide (map.publicValues.length = map.publicValueCount)
    && decide (map.linearTermOffsets.length = map.linearConstraintCount + 1)
    && decide (map.linearTermIndices.length = map.linearTermCount)
    && decide (map.linearTermCoefficients.length = map.linearTermCount)
    && decide (map.linearTargets.length = map.linearConstraintCount)
    && decide (map.linearTermOffsets.head? = some 0)
    && decide (map.linearTermOffsets.getLast? = some map.linearTermCount)
    && (map.linearTermOffsets.zip map.linearTermOffsets.tail).all
      (fun offsets => decide (offsets.1 <= offsets.2 ∧ offsets.2 <= map.linearTermCount))
    && map.linearTermIndices.all
      (fun index => decide (index < map.lppcRowCount * map.lppcPackingFactor))
    && decide (map.nonlinearExpressions.length = map.nonlinearExpressionCount)
    && decide (map.nonlinearConstraintRoots.length = map.nonlinearConstraintCount)
    && map.nonlinearConstraintRoots.all
      (fun root => decide (root < map.nonlinearExpressionCount))
    && expressionProgramWellFormedB map
    && decide (map.nonlinearProgramDigest.length = 32)
    && decide (map.auxiliaryWitnessLimbCount = 0)

def ProductionConstraintMap.sparseTableWellFormed
    (map : ProductionConstraintMap) : Prop :=
  map.sparseTableWellFormedB = true

def publicValueAt (publicValues : List Nat) (index : Nat) : Nat :=
  fieldValue (publicValues.getD index 0)

def slotAsset (publicValues : List Nat) (slot : Nat) : Nat :=
  publicValueAt publicValues (49 + slot)

def slotDenominator (publicValues : List Nat) (slot : Nat) : Nat :=
  (List.range 4).foldl
    (fun denominator other =>
      if other = slot then denominator
      else fieldMul denominator (fieldSub (slotAsset publicValues slot) (slotAsset publicValues other)))
    1

def stableSelectorSlot (publicValues : List Nat) : Nat :=
  if publicValueAt publicValues 53 = 0 then 0
  else if slotAsset publicValues 0 = publicValueAt publicValues 54 then 0
  else if slotAsset publicValues 1 = publicValueAt publicValues 54 then 1
  else if slotAsset publicValues 2 = publicValueAt publicValues 54 then 2
  else if slotAsset publicValues 3 = publicValueAt publicValues 54 then 3
  else 0

def ProductionConstraintExpression.eval
    (publicValues witnessRows : List Nat)
    (values : Array Nat) : ProductionConstraintExpression -> Nat
  | .constExpr value => fieldValue value
  | .publicExpr index => publicValueAt publicValues index
  | .witnessExpr index => fieldValue (witnessRows.getD index 0)
  | .slotInverseExpr slot => fieldInverse (slotDenominator publicValues slot)
  | .stableSelectorExpr bit => fieldValue ((stableSelectorSlot publicValues / (2 ^ bit)) % 2)
  | .addExpr left right => fieldAdd (values.getD left 0) (values.getD right 0)
  | .subExpr left right => fieldSub (values.getD left 0) (values.getD right 0)
  | .mulExpr left right => fieldMul (values.getD left 0) (values.getD right 0)
  | .negExpr value => fieldNeg (values.getD value 0)

def evalExpressionProgram
    (publicValues witnessRows : List Nat)
    (expressions : List ProductionConstraintExpression) : Array Nat :=
  expressions.foldl
    (fun values expression => values.push (expression.eval publicValues witnessRows values))
    #[]

def witnessLaneRows
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane : Nat) : List Nat :=
  (List.range map.lppcRowCount).map fun row =>
    witnessValues.getD (row * map.lppcPackingFactor + lane) 0

def nonlinearConstraintValue
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane constraint : Nat) : Nat :=
  let values := evalExpressionProgram
    map.publicValues (witnessLaneRows map witnessValues lane) map.nonlinearExpressions
  values.getD (map.nonlinearConstraintRoots.getD constraint 0) 1

def nonlinearConstraintEquation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane constraint : Nat) : Prop :=
  nonlinearConstraintValue map witnessValues lane constraint = 0

def nonlinearConstraintEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane constraint : Nat) : Bool :=
  decide (nonlinearConstraintValue map witnessValues lane constraint = 0)

def nonlinearLaneEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (lane : Nat) : Bool :=
  (List.range map.nonlinearConstraintCount).all fun constraint =>
    nonlinearConstraintEvaluatesB map witnessValues lane constraint

structure NonlinearConstraintFamilySpan where
  name : String
  start : Nat
  count : Nat
deriving DecidableEq, Repr

def publicShapeConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "public_shape", start := 0, count := 7 }

def inputConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "input_spend", start := 7, count := 72 }

def outputConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "output_validity", start := 79, count := 14 }

def stablecoinConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "stablecoin", start := 93, count := 24 }

def balanceConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "balance_conservation", start := 117, count := 4 }

def valueRangeConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "value_ranges", start := 121, count := 147 }

def authorizationConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "spend_authorization", start := 268, count := 374 }

def poseidonConstraintSpan : NonlinearConstraintFamilySpan :=
  { name := "poseidon_transitions", start := 642, count := 1080 }

def productionNonlinearConstraintFamilySpans : List NonlinearConstraintFamilySpan :=
  [ publicShapeConstraintSpan, inputConstraintSpan, outputConstraintSpan,
    stablecoinConstraintSpan, balanceConstraintSpan, valueRangeConstraintSpan,
    authorizationConstraintSpan, poseidonConstraintSpan ]

def nonlinearFamilyLaneEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (span : NonlinearConstraintFamilySpan)
    (lane : Nat) : Bool :=
  (List.range span.count).all fun relativeConstraint =>
    nonlinearConstraintEvaluatesB map witnessValues lane
      (span.start + relativeConstraint)

def nonlinearFamilyEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (span : NonlinearConstraintFamilySpan) : Bool :=
  (List.range map.lppcPackingFactor).all fun lane =>
    nonlinearFamilyLaneEvaluatesB map witnessValues span lane

def nonlinearProgramEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Bool :=
  decide (map.nonlinearConstraintCount = 1722)
    && (List.range map.lppcPackingFactor).all fun lane =>
      nonlinearLaneEvaluatesB map witnessValues lane

def linearConstraintValue
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (constraint : Nat) : Nat :=
  let start := map.linearTermOffsets.getD constraint 0
  let stop := map.linearTermOffsets.getD (constraint + 1) start
  (List.range (stop - start)).foldl
    (fun accumulator relativeTerm =>
      let term := start + relativeTerm
      let index := map.linearTermIndices.getD term 0
      let coefficient := map.linearTermCoefficients.getD term 0
      fieldAdd accumulator (fieldMul coefficient (witnessValues.getD index 0)))
    0

def linearConstraintEquation
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (constraint : Nat) : Prop :=
  linearConstraintValue map witnessValues constraint =
    fieldValue (map.linearTargets.getD constraint 0)

def linearConstraintEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat)
    (constraint : Nat) : Bool :=
  decide (linearConstraintValue map witnessValues constraint =
    fieldValue (map.linearTargets.getD constraint 0))

def linearProgramEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Bool :=
  (List.range map.linearConstraintCount).all fun constraint =>
    linearConstraintEvaluatesB map witnessValues constraint

def exactProductionConstraintMapEvaluatesB
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Bool :=
  map.sparseTableWellFormedB
    && decide (witnessValues.length = map.lppcRowCount * map.lppcPackingFactor)
    && linearProgramEvaluatesB map witnessValues
    && nonlinearProgramEvaluatesB map witnessValues

def ExactProductionConstraintMapEvaluates
    (map : ProductionConstraintMap)
    (witnessValues : List Nat) : Prop :=
  exactProductionConstraintMapEvaluatesB map witnessValues = true

end SmallWoodProductionConstraintRefinement
end Transaction
end Hegemon
