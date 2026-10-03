import HegemonCrypto.SmallWoodV8Smz9AccumulatorSponge

namespace HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup

open Hegemon.Transaction
open HegemonCrypto.SmallWood.V8Smz9AccumulatorSponge

theorem ofFn_getD {width : Nat} (words : Fin width → Nat) (word : Fin width) :
    (List.ofFn words).getD word.val 0 = words word := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    word.isLt, dif_pos, Option.getD_some]

theorem firstFrame_getD (inputs : List Nat) (lane : Nat) (bound : lane < 8) :
    (accumulatorFirstFrame inputs).getD lane 0 =
      Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0) := by
  have laneBound : lane < 16 := Nat.lt_trans bound (by decide)
  simp only [accumulatorFirstFrame, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some]
  simp [bound]

theorem firstFrame_getElemD (inputs : List Nat) (lane : Nat) (bound : lane < 8) :
    (accumulatorFirstFrame inputs)[lane]?.getD 0 =
      Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0) := by
  simpa only [List.getD_eq_getElem?_getD] using firstFrame_getD inputs lane bound

theorem middleFrame_getD (inputs state : List Nat) (lane : Nat) (bound : lane < 8) :
    (accumulatorMiddleFrame inputs state).getD lane 0 =
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (8 + lane) 0) := by
  have laneBound : lane < 16 := Nat.lt_trans bound (by decide)
  simp only [accumulatorMiddleFrame, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some]
  simp [bound]

theorem middleFrame_getElemD (inputs state : List Nat) (lane : Nat) (bound : lane < 8) :
    (accumulatorMiddleFrame inputs state)[lane]?.getD 0 =
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (8 + lane) 0) := by
  simpa only [List.getD_eq_getElem?_getD] using middleFrame_getD inputs state lane bound

theorem lastFrame_getD (inputs state : List Nat) (lane : Nat) (bound : lane < 7) :
    (accumulatorLastFrame inputs state).getD lane 0 =
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (16 + lane) 0) := by
  have laneBound : lane < 16 := Nat.lt_trans bound (by decide)
  simp only [accumulatorLastFrame, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range laneBound,
    Option.map_some, Option.getD_some]
  simp [bound]

theorem lastFrame_getElemD (inputs state : List Nat) (lane : Nat) (bound : lane < 7) :
    (accumulatorLastFrame inputs state)[lane]?.getD 0 =
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (16 + lane) 0) := by
  simpa only [List.getD_eq_getElem?_getD] using lastFrame_getD inputs state lane bound

end HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup
