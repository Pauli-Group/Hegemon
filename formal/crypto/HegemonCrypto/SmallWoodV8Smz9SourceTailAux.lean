import HegemonCrypto.SmallWoodV8Smz9SourceTailInputs

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTail

open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

def limbBase : Nat := 2 ^ 32

def sourceBit (value index : Nat) : Nat := (value / 2 ^ index) % 2

def sourceDecimalAccumulator (decimals : Nat) : Nat → Nat
  | 0 => 1
  | count + 1 =>
      let previous := sourceDecimalAccumulator decimals count
      if sourceBit decimals count = 1 then previous * 10 ^ (2 ^ count) else previous

structure SourceMul3 where
  x0 : Nat := 0
  x1 : Nat := 0
  p0 : Nat := 0
  p1 : Nat := 0
  p2 : Nat := 0
  c0 : Nat := 0
  out : Nat → Nat := fun _ => 0
  c1 : Nat := 0
  c2 : Nat := 0

def sourceMul3 (x y z : Nat) : SourceMul3 :=
  let first := x * y
  let second := first * z
  let x0 := x % limbBase
  let p0 := first % limbBase
  let p1 := (first / limbBase) % limbBase
  let c1 := (p0 * z) / limbBase
  { x0 := x0
    x1 := x / limbBase
    p0 := p0
    p1 := p1
    p2 := (first / limbBase ^ 2) % limbBase
    c0 := (x0 * y) / limbBase
    out := fun index => (second / limbBase ^ index) % limbBase
    c1 := c1
    c2 := (p1 * z + c1) / limbBase }

def SourceMul3.rangeValues (limbs : SourceMul3) : List Nat :=
  [limbs.x0,limbs.x1,limbs.p0,limbs.p1,limbs.p2,limbs.c0,
   limbs.out 0,limbs.out 1,limbs.out 2,limbs.out 3,limbs.c1,limbs.c2]

/-- Borrow entering a limb; borrow zero is the initial zero borrow. -/
def sourceBorrow (left right : Nat → Nat) : Nat → Nat
  | 0 => 0
  | index + 1 => if left index < right index + sourceBorrow left right index then 1 else 0

def sourceDifference (left right : Nat → Nat) (index : Nat) : Nat :=
  let subtrahend := right index + sourceBorrow left right index
  if subtrahend ≤ left index then left index - subtrahend
  else limbBase + left index - subtrahend

structure SourceCollateral where
  left : SourceMul3 := {}
  right : SourceMul3 := {}
  difference : Nat → Nat := fun _ => 0
  borrows : Nat → Nat := fun _ => 0

def sourceCollateral (amount numerator debt denominator ratio : Nat) : SourceCollateral :=
  let left := sourceMul3 amount numerator 1000000
  let right := sourceMul3 debt denominator ratio
  { left := left
    right := right
    difference := sourceDifference left.out right.out
    borrows := fun index => sourceBorrow left.out right.out (index + 1) }

structure SourceAux where
  pathBits : Nat → Nat := fun _ => 0
  pathQuotient : Nat := 0
  sameEpoch : Nat := 0
  decimalBits : Nat → Nat := fun _ => 0
  decimalSlackBits : Nat → Nat := fun _ => 0
  decimalAccumulators : Nat → Nat := fun _ => 0
  enabledAge : Nat := 0
  retirementOrderGap : Nat := 0
  retirementHeightGap : Nat := 0
  oracleAge : Nat := 0
  oracleSlack : Nat := 0
  attestationAge : Nat := 0
  attestationSlack : Nat := 0
  ratioSlack : Nat := 0
  beforeCapSlack : Nat := 0
  afterCapSlack : Nat := 0
  epochGap : Nat := 0
  epochRemainder : Nat := 0
  timeCarries : Nat → Nat := fun _ => 0
  collateral : SourceCollateral := {}

def disabledSourceAux : SourceAux :=
  { sameEpoch := 1, decimalAccumulators := fun _ => 1 }

def sourceTimeCarry (left right extra : Nat) : Nat :=
  ((left % limbBase + right % limbBase + extra) / limbBase) % 2

/--
Actual source computations from typed data. Nat subtraction totalizes Rust's checked
subtraction outside admitted inputs; source checked-success/refinement is a separate
obligation, not an implicit premise or a claimed result of this constructor.
-/
def sourceAux (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness) : SourceAux :=
  if stablePublic.direction = .disabled then disabledSourceAux else
  let config := decodeV8StablecoinConfig witness
  let before := decodeV8StablecoinBefore witness
  let mint := stablePublic.direction = .mint
  let retired := config.retiredPresent = 1
  let currentEpoch := stablePublic.parentHeight / 4096
  let enabledAge := if mint then stablePublic.parentHeight - config.enabledAt else 0
  let retirementOrderGap := if mint ∧ retired then config.retiredAt - config.enabledAt - 1 else 0
  let retirementHeightGap := if mint ∧ retired then config.retiredAt - stablePublic.parentHeight - 1 else 0
  let oracleAge := if mint then stablePublic.parentHeight - config.oracleSubmittedAt else 0
  let oracleSlack := if mint then config.oracleMaxAge - oracleAge else 0
  let attestationAge := if mint then stablePublic.parentHeight - config.attestationCreatedAt else 0
  let attestationSlack := if mint then config.attestationMaxAge - attestationAge else 0
  let collateral := if mint then sourceCollateral config.collateralAmount
    config.oraclePriceNumerator stablePublic.after.totalDebt config.oraclePriceDenominator
    config.minCollateralRatioPpm else {}
  { pathBits := sourceBit stablePublic.assetId
    pathQuotient := stablePublic.assetId / 16
    sameEpoch := if before.epochId = currentEpoch then 1 else 0
    decimalBits := sourceBit config.collateralDecimals
    decimalSlackBits := sourceBit (18 - config.collateralDecimals)
    decimalAccumulators := fun bit => sourceDecimalAccumulator config.collateralDecimals (bit + 1)
    enabledAge := enabledAge
    retirementOrderGap := retirementOrderGap
    retirementHeightGap := retirementHeightGap
    oracleAge := oracleAge
    oracleSlack := oracleSlack
    attestationAge := attestationAge
    attestationSlack := attestationSlack
    ratioSlack := if mint then config.minCollateralRatioPpm - 1000000 else 0
    beforeCapSlack := config.maxMintPerEpoch - before.mintedInEpoch
    afterCapSlack := config.maxMintPerEpoch - stablePublic.after.mintedInEpoch
    epochGap := currentEpoch - before.epochId
    epochRemainder := stablePublic.parentHeight - currentEpoch * 4096
    timeCarries := fun index => if mint then
      [ sourceTimeCarry config.enabledAt enabledAge 0
      , if retired then sourceTimeCarry config.enabledAt retirementOrderGap 1 else 0
      , if retired then sourceTimeCarry stablePublic.parentHeight retirementHeightGap 1 else 0
      , sourceTimeCarry config.oracleSubmittedAt oracleAge 0
      , sourceTimeCarry oracleAge oracleSlack 0
      , sourceTimeCarry config.attestationCreatedAt attestationAge 0
      , sourceTimeCarry attestationAge attestationSlack 0 ].getD index 0
      else 0
    collateral := collateral }

def sourceNumericValues (aux : SourceAux) : List Nat :=
  [aux.pathQuotient,aux.enabledAge,aux.retirementOrderGap,aux.retirementHeightGap,
   aux.oracleAge,aux.oracleSlack,aux.attestationAge,aux.attestationSlack,aux.ratioSlack,
   aux.beforeCapSlack,aux.afterCapSlack,aux.epochGap,aux.epochRemainder] ++
  List.ofFn (fun bit : Fin 5 => aux.decimalAccumulators bit.val) ++
  aux.collateral.left.rangeValues ++ aux.collateral.right.rangeValues ++
  List.ofFn (fun index : Fin 4 => aux.collateral.difference index.val)

/-- Every list entry matches range_values source order, including the real parent height. -/
def sourceRangeValues (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (aux : SourceAux) : List (Nat × Nat) :=
  let config := decodeV8StablecoinConfig witness
  let before := decodeV8StablecoinBefore witness
  ([config.assetId,config.policyVersion,config.minCollateralRatioPpm,
    config.oraclePriceNumerator,config.oraclePriceDenominator,config.collateralAssetId,
    aux.ratioSlack].map fun value => (value,32)) ++
  ([config.enabledAt,config.retiredAt,config.oracleSubmittedAt,config.oracleMaxAge,
    config.attestationCreatedAt,config.attestationMaxAge,config.collateralScale,
    stablePublic.parentHeight,before.sequence,stablePublic.after.sequence,aux.enabledAge,
    aux.retirementOrderGap,aux.retirementHeightGap,aux.oracleAge,aux.oracleSlack,
    aux.attestationAge,aux.attestationSlack].map fun value => (value,63)) ++
  ([before.epochId,stablePublic.after.epochId,aux.epochGap].map fun value => (value,51)) ++
  ([config.maxMintPerEpoch,config.collateralAmount,stablePublic.magnitude,before.mintedInEpoch,
    before.totalDebt,stablePublic.after.mintedInEpoch,stablePublic.after.totalDebt,
    aux.beforeCapSlack,aux.afterCapSlack].map fun value => (value,56)) ++
  [(aux.epochRemainder,12),(aux.pathQuotient,28)] ++
  ((aux.collateral.left.rangeValues ++ aux.collateral.right.rangeValues ++
    List.ofFn (fun index : Fin 4 => aux.collateral.difference index.val)).map fun value => (value,32))

def sourceBooleanValues (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (aux : SourceAux) : List Nat :=
  let config := decodeV8StablecoinConfig witness
  let mint := if stablePublic.direction = .mint then 1 else 0
  let burn := if stablePublic.direction = .burn then 1 else 0
  [mint + burn,mint,burn,config.active,config.retiredPresent,
   config.attestationDisputed,config.attestationPresent] ++
  List.ofFn (fun bit : Fin 4 => aux.pathBits bit.val) ++ [aux.sameEpoch] ++
  List.ofFn (fun bit : Fin 5 => aux.decimalBits bit.val) ++
  List.ofFn (fun bit : Fin 5 => aux.decimalSlackBits bit.val) ++
  List.ofFn (fun limb : Fin 4 => aux.collateral.borrows limb.val) ++
  List.ofFn (fun index : Fin 7 => aux.timeCarries index.val) ++
  ((sourceRangeValues stablePublic witness aux).filter fun entry => entry.2 % 2 = 1).map
    fun entry => sourceBit entry.1 (entry.2 - 1)

theorem source_mul3_range_shape (limbs : SourceMul3) : limbs.rangeValues.length = 12 := by rfl

theorem source_numeric_shape (aux : SourceAux) : (sourceNumericValues aux).length = 46 := by
  simp only [sourceNumericValues, List.length_append, List.length_cons, List.length_nil,
    List.length_ofFn, source_mul3_range_shape]

theorem source_ranges_shape (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (aux : SourceAux) : (sourceRangeValues stablePublic witness aux).length = 66 := by
  simp only [sourceRangeValues, List.length_append, List.length_map, List.length_cons,
    List.length_nil, List.length_ofFn, source_mul3_range_shape]

theorem source_bit_boolean (value index : Nat) : sourceBit value index = 0 ∨ sourceBit value index = 1 := by
  have bound : sourceBit value index < 2 := Nat.mod_lt _ (by decide)
  omega

theorem source_borrow_boolean (left right : Nat → Nat) (index : Nat) :
    sourceBorrow left right index = 0 ∨ sourceBorrow left right index = 1 := by
  cases index with
  | zero => exact Or.inl rfl
  | succ index => unfold sourceBorrow; split_ifs <;> simp

theorem source_mul3_output_bound (x y z index : Nat) :
    (sourceMul3 x y z).out index < limbBase := Nat.mod_lt _ (by decide)

theorem source_collateral_difference_bound (amount numerator debt denominator ratio index : Nat) :
    (sourceCollateral amount numerator debt denominator ratio).difference index < limbBase := by
  have left := source_mul3_output_bound amount numerator 1000000 index
  have right := source_mul3_output_bound debt denominator ratio index
  have borrow := source_borrow_boolean (sourceMul3 amount numerator 1000000).out
    (sourceMul3 debt denominator ratio).out index
  change sourceDifference _ _ index < limbBase
  unfold sourceDifference
  dsimp only
  split_ifs <;> omega

theorem source_aux_disabled (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (disabled : stablePublic.direction = .disabled) :
    sourceAux stablePublic witness = disabledSourceAux := by
  simp only [sourceAux, if_pos disabled]

theorem disabled_aux_unconditional_units :
    disabledSourceAux.sameEpoch = 1 ∧
    (∀ bit, disabledSourceAux.decimalAccumulators bit = 1) ∧
    disabledSourceAux.epochGap = 0 ∧ disabledSourceAux.epochRemainder = 0 := by
  exact ⟨rfl, fun _ => rfl, rfl, rfl⟩

theorem disabled_numeric_exact :
    sourceNumericValues disabledSourceAux =
      List.replicate 13 0 ++ List.replicate 5 1 ++ List.replicate 28 0 := by decide


end HegemonCrypto.SmallWood.V8Smz9SourceStableTail

