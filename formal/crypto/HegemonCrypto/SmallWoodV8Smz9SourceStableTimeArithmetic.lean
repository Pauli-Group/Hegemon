import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeParts
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceTailCheckedSubtractions

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTimeArithmetic
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeNatural
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeParts
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def timeValue (statement : V8PublicStatement) (witness : V8Witness) (aux : SourceAux) : Nat → Nat
  | 0 => (decodeV8StablecoinConfig witness.stablecoin).enabledAt
  | 1 => (decodeV8StablecoinConfig witness.stablecoin).retiredAt
  | 2 => (decodeV8StablecoinConfig witness.stablecoin).oracleSubmittedAt
  | 3 => (decodeV8StablecoinConfig witness.stablecoin).oracleMaxAge
  | 4 => (decodeV8StablecoinConfig witness.stablecoin).attestationCreatedAt
  | 5 => (decodeV8StablecoinConfig witness.stablecoin).attestationMaxAge
  | 6 => statement.stablecoin.parentHeight
  | 7 => aux.enabledAge
  | 8 => aux.retirementOrderGap
  | 9 => aux.retirementHeightGap
  | 10 => aux.oracleAge
  | 11 => aux.oracleSlack
  | 12 => aux.attestationAge
  | 13 => aux.attestationSlack
  | _ => 0

theorem source_range_time_value (statement : V8PublicStatement) (witness : V8Witness) (index : Fin 14) :
    (sourceRangeEntry statement witness (timeSpec index.val).localIndex).1 =
      timeValue statement witness (sourceAux statement.stablecoin witness.stablecoin) index.val := by
  fin_cases index <;> rfl

theorem mint_time_addition_values (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (mint : statement.stablecoin.direction = .mint)
    (index : Fin 5) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    let spec := timeAddition index.val
    timeValue statement witness aux spec.x + timeValue statement witness aux spec.y =
      timeValue statement witness aux spec.z := by
  have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
  have checked := (valid_source_aux_checked_arithmetic statement witness valid active).2.2.2.2.2 mint
  fin_cases index <;> simp only [timeValue,timeAddition,timeAdditions,List.getD_cons_zero,List.getD_cons_succ]
  all_goals omega

def timeCarryIndex (index : Nat) : Nat := if index = 0 then 0 else index+2

theorem time_boolean_carry (statement : V8PublicStatement) (witness : V8Witness) (aux : SourceAux)
    (index : Fin 5) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD (timeAddition index.val).carry 0 =
      aux.timeCarries (timeCarryIndex index.val) := by
  fin_cases index <;> rfl

theorem mint_time_carry (statement : V8PublicStatement) (witness : V8Witness)
    (mint : statement.stablecoin.direction = .mint) (index : Fin 5) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    aux.timeCarries (timeCarryIndex index.val) =
      sourceTimeCarry (timeValue statement witness aux (timeAddition index.val).x)
        (timeValue statement witness aux (timeAddition index.val).y) 0 := by
  have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
  fin_cases index <;>
    simp [sourceAux,mint,timeCarryIndex,timeValue,timeAddition,timeAdditions]

theorem nonmint_time_carry_zero (statement : V8PublicStatement) (witness : V8Witness)
    (nonmint : statement.stablecoin.direction ≠ .mint) (index : Nat) :
    (sourceAux statement.stablecoin witness.stablecoin).timeCarries index = 0 := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simp [sourceAux,disabled,disabledSourceAux]
  · simp [sourceAux,disabled,nonmint]

theorem source_time_carry_zero_extra (x y z : Nat) (sum : x+y=z) :
    x % limbBase + y % limbBase = z % limbBase + limbBase * sourceTimeCarry x y 0 ∧
    x / limbBase + y / limbBase + sourceTimeCarry x y 0 = z / limbBase := by
  have hx := Nat.mod_add_div x limbBase
  have hy := Nat.mod_add_div y limbBase
  have hz := Nat.mod_add_div z limbBase
  have hm := Nat.mod_add_div (x % limbBase + y % limbBase) limbBase
  have mx := Nat.mod_lt x (by decide : 0 < limbBase)
  have my := Nat.mod_lt y (by decide : 0 < limbBase)
  have mz := Nat.mod_lt z (by decide : 0 < limbBase)
  have mm := Nat.mod_lt (x % limbBase + y % limbBase) (by decide : 0 < limbBase)
  have modulo : z % limbBase = (x % limbBase + y % limbBase) % limbBase := by
    rw [←sum]; simp [Nat.add_mod]
  simp only [sourceTimeCarry,limbBase,Nat.add_zero] at *
  constructor <;> omega

theorem full_candidate_mint_time_parts (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (mint : statement.stablecoin.direction = .mint)
    (index : Fin 5) :
    let packed := fullTypedSourceCandidate statement witness
    let spec := timeAddition index.val
    timeLow packed (timeSpec spec.x).start + timeLow packed (timeSpec spec.y).start =
      timeLow packed (timeSpec spec.z).start + 2^32 * packed.getD (42112+spec.carry) 0 ∧
    timeHigh packed (timeSpec spec.x).start (timeSpec spec.x).topLane +
      timeHigh packed (timeSpec spec.y).start (timeSpec spec.y).topLane + packed.getD (42112+spec.carry) 0 =
      timeHigh packed (timeSpec spec.z).start (timeSpec spec.z).topLane := by
  have bounds := (exact_time_addition_attempts index.val index.isLt).2.2
  have x := source_time_parts_mod_div statement witness valid ⟨(timeAddition index.val).x,bounds.1⟩
  have y := source_time_parts_mod_div statement witness valid ⟨(timeAddition index.val).y,bounds.2.1⟩
  have z := source_time_parts_mod_div statement witness valid ⟨(timeAddition index.val).z,bounds.2.2.1⟩
  rw [source_range_time_value statement witness ⟨_,bounds.1⟩] at x
  rw [source_range_time_value statement witness ⟨_,bounds.2.1⟩] at y
  rw [source_range_time_value statement witness ⟨_,bounds.2.2.1⟩] at z
  have carry := full_candidate_boolean_at statement witness ⟨(timeAddition index.val).carry,bounds.2.2.2⟩
  rw [time_boolean_carry statement witness _ index,mint_time_carry statement witness mint index] at carry
  dsimp only
  rw [x.1,x.2,y.1,y.2,z.1,z.2,carry]
  exact source_time_carry_zero_extra _ _ _ (mint_time_addition_values statement witness valid mint index)

end HegemonCrypto.SmallWood.V8Smz9SourceStableTimeArithmetic
