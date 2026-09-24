import HegemonCrypto.SmallWoodV8Smz9SourceTailRoles

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTail

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (fieldAdd fieldSub fieldMul fieldInverse packedWitnessLaneRows packingFactor relationRowCount)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
  (AuthHashFinals auth_exact_words_getD)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

structure SourceMulTuple where
  a : Nat := 0
  b : Nat := 0
  c : Nat := 0

def sourceMul3Lane (limbs : SourceMul3) (y z : Nat) : Nat → SourceMulTuple
  | 0 => ⟨limbs.x0,y,limbs.p0 + limbBase * limbs.c0⟩
  | 1 => ⟨limbs.x1,y,limbs.p1 + limbBase * limbs.p2 - limbs.c0⟩
  | 2 => ⟨limbs.p0,z,limbs.out 0 + limbBase * limbs.c1⟩
  | 3 => ⟨limbs.p1,z,limbs.out 1 + limbBase * limbs.c2 - limbs.c1⟩
  | 4 => ⟨limbs.p2,z,limbs.out 2 + limbBase * limbs.out 3 - limbs.c2⟩
  | _ => {}

def sourceBaseMultiplication (_stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) (lane : Nat) : SourceMulTuple :=
  let config := decodeV8StablecoinConfig witness
  let before := decodeV8StablecoinBefore witness
  if lane < 5 then
    ⟨if lane = 0 then 1 else aux.decimalAccumulators (lane - 1),
      1 + aux.decimalBits lane * (10 ^ (2 ^ lane) - 1),
      aux.decimalAccumulators lane⟩
  else if lane < 10 then sourceMul3Lane aux.collateral.left config.oraclePriceNumerator 1000000 (lane - 5)
  else if lane < 15 then sourceMul3Lane aux.collateral.right config.oraclePriceDenominator
    config.minCollateralRatioPpm (lane - 10)
  else if lane = 15 then ⟨aux.epochGap,fieldInverse aux.epochGap,1 - aux.sameEpoch⟩
  else if lane = 16 then ⟨aux.sameEpoch,before.mintedInEpoch,aux.sameEpoch * before.mintedInEpoch⟩
  else if lane = 17 then ⟨aux.sameEpoch,aux.epochGap,0⟩
  else {}

def sourceLowResidual (x y z carry : Nat) : Nat :=
  fieldSub (fieldAdd (fieldAdd (x % limbBase) (y % limbBase)) 1)
    (fieldAdd (z % limbBase) (fieldMul limbBase carry))

def sourceHighResidual (x y z carry : Nat) : Nat :=
  fieldSub (fieldAdd (fieldAdd (x / limbBase) (y / limbBase)) carry) (z / limbBase)

/-- Parent helper overwrites beyond the base materializer's first 18 lanes. -/
def sourceMultiplication (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Nat) : SourceMulTuple :=
  let numeric := sourceNumericValues aux
  let booleans := sourceBooleanValues statement.stablecoin witness.stablecoin aux
  let mint := if statement.stablecoin.direction = .mint then 1 else 0
  let source3 := stableSourceWord statement witness 3
  let source4 := stableSourceWord statement witness 4
  let source5 := stableSourceWord statement witness 5
  let gate := mint * source4
  if lane < 18 then sourceBaseMultiplication statement.stablecoin witness.stablecoin aux lane
  else if lane < 24 then
    let carryLane := [23,28,29,35,40,41].getD (lane - 18) 0
    let left := limbBase - 1 - numeric.getD carryLane 0
    ⟨left,if mint = 1 then fieldInverse left else 0,mint⟩
  else if lane = 24 then ⟨1 - source4,source5,0⟩
  else if lane < 29 then
    let retirement :=
      [sourceLowResidual source3 (numeric.getD 2 0) source5 (booleans.getD 27 0),
       sourceHighResidual source3 (numeric.getD 2 0) source5 (booleans.getD 27 0),
       sourceLowResidual (wordAt (encodePublicStatement statement) 94)
         (numeric.getD 3 0) source5 (booleans.getD 28 0),
       sourceHighResidual (wordAt (encodePublicStatement statement) 94)
         (numeric.getD 3 0) source5 (booleans.getD 28 0)]
    ⟨gate,retirement.getD (lane - 25) 0,0⟩
  else if lane < 33 then
    ⟨1 - gate,[numeric.getD 2 0,numeric.getD 3 0,
      booleans.getD 27 0,booleans.getD 28 0].getD (lane - 29) 0,0⟩
  else {}

def sourceRadixDigit (value digit : Nat) : Nat := (value / 2 ^ (2 * digit)) % 4

def sourceRangeDigits (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (aux : SourceAux) : List Nat :=
  (sourceRangeValues stablePublic witness aux).flatMap fun entry =>
    (List.range (entry.2 / 2)).map fun digit => sourceRadixDigit entry.1 digit

def sourceRangeWidths : List Nat :=
  List.replicate 7 32 ++ List.replicate 17 63 ++ List.replicate 3 51 ++
  List.replicate 9 56 ++ [12,28] ++ List.replicate 28 32

theorem source_range_widths_exact (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) :
    (sourceRangeValues stablePublic witness aux).map Prod.snd = sourceRangeWidths := by rfl

theorem source_boolean_shape (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) :
    (sourceBooleanValues stablePublic witness aux).length = 53 := by
  simp [sourceBooleanValues, sourceRangeValues, SourceMul3.rangeValues, List.ofFn_succ]

theorem source_range_digit_shape (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) :
    (sourceRangeDigits stablePublic witness aux).length = 1434 := by
  simp only [sourceRangeDigits, List.length_flatMap, List.length_map, List.length_range]
  have widths := congrArg (fun widths : List Nat => (widths.map fun width => width / 2).sum)
    (source_range_widths_exact stablePublic witness aux)
  simp only [List.map_map, Function.comp_def] at widths
  rw [widths]
  decide

theorem source_radix_digit_bound (value digit : Nat) : sourceRadixDigit value digit < 4 :=
  Nat.mod_lt _ (by decide)

theorem source_range_digits_canonical (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) :
    ExactWords 1434 (sourceRangeDigits stablePublic witness aux) := by
  refine ⟨source_range_digit_shape stablePublic witness aux, ?_⟩
  intro word member
  obtain ⟨entry, _, member⟩ := List.mem_flatMap.mp member
  obtain ⟨digit, _, rfl⟩ := List.mem_map.mp member
  have bound := source_radix_digit_bound entry.1 digit
  have modulus : 4 < fieldModulus := by decide
  omega

/-- Full source 39-row tail. Auxiliaries are computed internally, never provided by a premise. -/
def sourceTailWord (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row lane : Nat) : Nat :=
  let aux := sourceAux statement.stablecoin witness.stablecoin
  if row < 2 then stableSourceWord statement witness (row * 64 + lane)
  else if row < 9 then sourceRoleWord statement witness hashes lane (row - 2)
  else if row = 9 then sourceRoleSelector statement witness hashes lane
  else if row = 10 then sourceRoleInverse statement witness hashes lane
  else if row = 11 then (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD lane 0
  else if row = 12 then (sourceNumericValues aux).getD lane 0
  else if row = 13 then (sourceMultiplication statement witness aux lane).a
  else if row = 14 then (sourceMultiplication statement witness aux lane).b
  else if row = 15 then (sourceMultiplication statement witness aux lane).c
  else if row < 39 then
    (sourceRangeDigits statement.stablecoin witness.stablecoin aux).getD ((row - 16) * 64 + lane) 0
  else 0

def sourceTailPacked (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) : List Nat :=
  List.ofFn fun slot : Fin 2496 => sourceTailWord statement witness hashes (slot.val / 64) (slot.val % 64)

def embedSourceTail (before : List Nat) (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) : List Nat := before ++ sourceTailPacked statement witness hashes

theorem source_tail_shape (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) : (sourceTailPacked statement witness hashes).length = 39 * 64 := by
  simp only [sourceTailPacked, List.length_ofFn]

theorem source_tail_packed_readback (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row : Fin 39) (lane : Fin 64) (fallback : Nat) :
    (sourceTailPacked statement witness hashes).getD (row.val * 64 + lane.val) fallback =
      sourceTailWord statement witness hashes row.val lane.val := by
  have bound : row.val * 64 + lane.val < 2496 := by omega
  have quotient : (row.val * 64 + lane.val) / 64 = row.val := by omega
  have remainder : (row.val * 64 + lane.val) % 64 = lane.val := by omega
  simp only [sourceTailPacked, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    bound, dif_pos, Option.getD_some, quotient, remainder]

theorem source_tail_global_lane_readback (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (row : Fin 39) (lane : Fin 64) :
    (packedWitnessLaneRows (embedSourceTail before statement witness hashes) lane.val).getD
        (647 + row.val) 0 = sourceTailWord statement witness hashes row.val lane.val := by
  have rowBound : 647 + row.val < 686 := by omega
  have address : (647 + row.val) * 64 + lane.val - before.length = row.val * 64 + lane.val := by omega
  simp only [packedWitnessLaneRows, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range, relationRowCount, rowBound,
    Option.map_some, Option.getD_some, packingFactor, embedSourceTail]
  rw [List.getElem?_append_right (by omega), address]
  exact source_tail_packed_readback statement witness hashes row lane 0

theorem source_tail_full_rectangle_length (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) :
    (embedSourceTail before statement witness hashes).length = 43904 := by
  simp only [embedSourceTail, List.length_append, prefixLength,
    source_tail_shape]

theorem source_tail_prefix_unchanged (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (index : Nat) (bound : index < before.length) (fallback : Nat) :
    (embedSourceTail before statement witness hashes).getD index fallback = before.getD index fallback := by
  simp only [embedSourceTail, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_left bound]


end HegemonCrypto.SmallWood.V8Smz9SourceStableTail

