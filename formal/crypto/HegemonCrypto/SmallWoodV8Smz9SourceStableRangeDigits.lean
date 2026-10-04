import HegemonCrypto.SmallWoodV8Smz9SourceDenseMaterialization
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrReadbacks

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8RelationProgram (packedWitnessLaneRows packingFactor relationRowCount)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (radixFourSum)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_radix_digit_eq (value digit : Nat) : sourceRadixDigit value digit=sourceDigit value digit := by
  simp only [sourceRadixDigit,sourceDigit,pow_mul,show (2:Nat)^2=4 by decide]

theorem source_radix_even_reconstruct (value digits : Nat) (bound : value<2^(2*digits)) :
    radixFourSum (sourceRadixDigit value) digits=value := by
  have bound' : value<4^digits := by simpa only [pow_mul,show (2:Nat)^2=4 by decide] using bound
  have reconstruction := source_radix_reconstruction value digits
  rw [Nat.div_eq_of_lt bound',Nat.mul_zero,Nat.add_zero] at reconstruction
  rw [show sourceRadixDigit value=sourceDigit value from funext (source_radix_digit_eq value)]
  exact reconstruction

theorem source_radix_odd_reconstruct (value digits : Nat) (bound : value<2^(2*digits+1)) :
    radixFourSum (sourceRadixDigit value) digits+4^digits*sourceBit value (2*digits)=value := by
  have power : (2:Nat)^(2*digits)=4^digits := by rw [pow_mul]; rfl
  have oddPower : (2:Nat)^(2*digits+1)=2*4^digits := by rw [pow_succ,power]; omega
  have bound' : value<2*4^digits := by rwa [oddPower] at bound
  have quotient : value/4^digits<2 := (Nat.div_lt_iff_lt_mul (by positivity)).mpr bound'
  have top : sourceBit value (2*digits)=value/4^digits := by
    simp only [sourceBit,pow_mul,show (2:Nat)^2=4 by decide,Nat.mod_eq_of_lt quotient]
  rw [show sourceRadixDigit value=sourceDigit value from funext (source_radix_digit_eq value),top]
  exact source_radix_reconstruction value digits

theorem flat_map_getD_at {α : Type} (entries : List α) (encode : α → List Nat)
    (defaultEntry : α) (index digit : Nat) (indexBound : index<entries.length)
    (digitBound : digit<(encode (entries.getD index defaultEntry)).length) :
    (entries.flatMap encode).getD
        (((entries.take index).map (fun entry => (encode entry).length)).sum+digit) 0 =
      (encode (entries.getD index defaultEntry)).getD digit 0 := by
  induction entries generalizing index with
  | nil => simp at indexBound
  | cons head tail ih =>
    cases index with
    | zero =>
      simp only [List.getD_cons_zero] at digitBound
      simp only [List.flatMap_cons,List.take_zero,List.map_nil,List.sum_nil,Nat.zero_add,List.getD_cons_zero]
      simp only [List.getD_eq_getElem?_getD,List.getElem?_append_left digitBound]
    | succ index =>
      have indexTail : index<tail.length := by simpa only [List.length_cons,Nat.succ_lt_succ_iff] using indexBound
      simp only [List.getD_cons_succ] at digitBound
      have prior := ih index indexTail digitBound
      simp only [List.flatMap_cons,List.take_succ_cons,List.map_cons,List.sum_cons,List.getD_cons_succ]
      have shift : (encode head).length+((tail.take index).map (fun entry => (encode entry).length)).sum+digit =
          (encode head).length+(((tail.take index).map (fun entry => (encode entry).length)).sum+digit) := by omega
      rw [shift]
      simpa only [List.getD_eq_getElem?_getD,List.getElem?_append_right (Nat.le_add_right _ _),
        Nat.add_sub_cancel_left] using prior

def sourceRangeEntry (statement : V8PublicStatement) (witness : V8Witness) (slot : Nat) : Nat × Nat :=
  (sourceRangeValues statement.stablecoin witness.stablecoin (sourceAux statement.stablecoin witness.stablecoin)).getD slot (0,0)

def sourceRangeWidth (slot : Nat) : Nat :=
  if slot<7 then 32 else if slot<24 then 63 else if slot<27 then 51 else
  if slot<36 then 56 else if slot=36 then 12 else if slot=37 then 28 else 32

def sourceRangeStart (slot : Nat) : Nat :=
  if slot<7 then 16*slot else if slot<24 then 112+31*(slot-7) else
  if slot<27 then 639+25*(slot-24) else if slot<36 then 714+28*(slot-27) else
  if slot=36 then 966 else if slot=37 then 972 else 986+16*(slot-38)

theorem source_range_entry_width (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 66) :
    (sourceRangeEntry statement witness slot.val).2=sourceRangeWidth slot.val := by
  fin_cases slot <;> rfl

theorem source_range_prefix_length (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 66) :
    (((sourceRangeValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).take slot.val).map (fun entry => entry.2/2)).sum =
      sourceRangeStart slot.val := by
  have widths : (sourceRangeValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).map (fun entry => entry.2/2) =
      List.replicate 7 16 ++ List.replicate 17 31 ++ List.replicate 3 25 ++
      List.replicate 9 28 ++ [6,14] ++ List.replicate 28 16 := by
    simp [sourceRangeValues,SourceMul3.rangeValues,List.ofFn_succ]
  rw [List.map_take,widths]
  fin_cases slot <;> decide

theorem source_range_digit_readback (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 66) (digit : Nat) (digitBound : digit<sourceRangeWidth slot.val/2) :
    (sourceRangeDigits statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD (sourceRangeStart slot.val+digit) 0 =
      sourceRadixDigit (sourceRangeEntry statement witness slot.val).1 digit := by
  let entries := sourceRangeValues statement.stablecoin witness.stablecoin (sourceAux statement.stablecoin witness.stablecoin)
  let encode (entry : Nat × Nat) := (List.range (entry.2/2)).map (sourceRadixDigit entry.1)
  have width : (encode (entries.getD slot.val (0,0))).length=sourceRangeWidth slot.val/2 := by
    simp only [encode,List.length_map,List.length_range]
    change (sourceRangeEntry statement witness slot.val).2/2=sourceRangeWidth slot.val/2
    rw [source_range_entry_width]
  have readback := flat_map_getD_at entries encode (0,0) slot.val digit
    (by rw [source_ranges_shape]; exact slot.isLt) (by rw [width]; exact digitBound)
  have priorSize : ((entries.take slot.val).map (fun entry => (encode entry).length)).sum=sourceRangeStart slot.val := by
    simp only [encode,List.length_map,List.length_range]
    exact source_range_prefix_length statement witness slot
  rw [priorSize] at readback
  change (sourceRangeDigits _ _ _).getD (sourceRangeStart slot.val+digit) 0 = _ at readback
  rw [readback]
  have bound : digit<(sourceRangeEntry statement witness slot.val).2/2 := by
    rw [source_range_entry_width]; exact digitBound
  change ((List.range ((sourceRangeEntry statement witness slot.val).2/2)).map
      (sourceRadixDigit (sourceRangeEntry statement witness slot.val).1)).getD digit 0 = _
  simp [List.getD_eq_getElem?_getD,bound]

theorem full_candidate_tail_flat_nat_readback (statement : V8PublicStatement) (witness : V8Witness)
    (family : TailFamily) (offset : Nat) (bound : offset<family.width) (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD ((647+family.base+offset)*64+lane.val) 0 =
      tailFamilyWord statement witness (typedSourceFinals statement witness) family offset lane.val := by
  have source := full_candidate_tail_family_readback statement witness family offset bound lane
  have rowBound : 647+family.base+offset<686 := by have extent := tail_family_extent family; omega
  simpa [packedWitnessLaneRows,List.getD_eq_getElem?_getD,relationRowCount,packingFactor,rowBound] using source

theorem full_candidate_range_digit (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index<1472) :
    (fullTypedSourceCandidate statement witness).getD (42432+index) 0 =
      (sourceRangeDigits statement.stablecoin witness.stablecoin
        (sourceAux statement.stablecoin witness.stablecoin)).getD index 0 := by
  have source := full_candidate_tail_flat_nat_readback statement witness .ranges (index/64)
    (by change index/64<23; omega) ⟨index%64,by omega⟩
  have address : (647+TailFamily.ranges.base+index/64)*64+index%64=42432+index := by
    simp only [TailFamily.base]; omega
  rw [address] at source
  simpa only [tailFamilyWord,show index/64*64+index%64=index by omega] using source

end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
