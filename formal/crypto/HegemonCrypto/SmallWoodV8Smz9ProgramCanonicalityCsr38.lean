import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr37

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr38
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 19456 47 112 0 [(41552, 1)] 325, attempt 19457 47 113 0 [(41616, 1)] 0, attempt 19458 47 114 0 [(41680, 1)] 0, attempt 19459 47 115 0 [(41744, 1)] 0, attempt 19460 47 116 0 [(41808, 1)] 0, attempt 19461 47 117 0 [(41872, 1)] 0, attempt 19462 47 118 0 [(41936, 1)] 0, attempt 19463 47 119 0 [(41553, 1), (41425, 323)] 308, attempt 19464 47 120 0 [(41617, 1), (41425, 0)] 0, attempt 19465 47 121 0 [(41681, 1), (41425, 0)] 0, attempt 19466 47 122 0 [(41745, 1), (41425, 0)] 0, attempt 19467 47 123 0 [(41809, 1), (41425, 0)] 0, attempt 19468 47 124 0 [(41873, 1), (41425, 0)] 0, attempt 19469 47 125 0 [(41937, 1), (41425, 0)] 0, attempt 19470 47 126 0 [(41554, 1), (41426, 323)] 308, attempt 19471 47 127 0 [(41618, 1), (41426, 0)] 0, attempt 19472 47 128 0 [(41682, 1), (41426, 0)] 0, attempt 19473 47 129 0 [(41746, 1), (41426, 0)] 0, attempt 19474 47 130 0 [(41810, 1), (41426, 0)] 0, attempt 19475 47 131 0 [(41874, 1), (41426, 0)] 0, attempt 19476 47 132 0 [(41938, 1), (41426, 0)] 0, attempt 19477 47 133 0 [(41555, 1), (41408, 320)] 307, attempt 19478 47 134 0 [(41619, 1), (41408, 0)] 0, attempt 19479 47 135 0 [(41683, 1), (41408, 0)] 0, attempt 19480 47 136 0 [(41747, 1), (41408, 0)] 0, attempt 19481 47 137 0 [(41811, 1), (41408, 0)] 0, attempt 19482 47 138 0 [(41875, 1), (41408, 0)] 0, attempt 19483 47 139 0 [(41939, 1), (41408, 0)] 0, attempt 19484 47 140 0 [(41556, 1)] 327, attempt 19485 47 141 0 [(41620, 1)] 328, attempt 19486 47 142 0 [(41684, 1)] 329, attempt 19487 47 143 0 [(41748, 1)] 330]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19456
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 19488 47 144 0 [(41812, 1)] 331, attempt 19489 47 145 0 [(41876, 1)] 332, attempt 19490 47 146 0 [(41940, 1)] 333, attempt 19491 47 147 0 [(41557, 1), (41520, 339), (41524, 340)] 338, attempt 19492 47 148 0 [(41621, 1), (41521, 339), (41525, 340)] 0, attempt 19493 47 149 0 [(41685, 1), (41522, 339), (41526, 340)] 0, attempt 19494 47 150 0 [(41749, 1), (41523, 339), (41527, 340)] 0, attempt 19495 47 151 0 [(41813, 1)] 0, attempt 19496 47 152 0 [(41877, 1)] 0, attempt 19497 47 153 0 [(41941, 1)] 0, attempt 19498 47 154 0 [(41558, 1), (8832, 158), (5952, 265), (6016, 265)] 1, attempt 19499 47 155 0 [(41622, 1), (8896, 158), (5952, 0), (6016, 0)] 0, attempt 19500 47 156 0 [(41686, 1), (8960, 158), (5952, 0), (6016, 0)] 0, attempt 19501 47 157 0 [(41750, 1), (9024, 158), (5952, 0), (6016, 0)] 0, attempt 19502 47 158 0 [(41814, 1), (9088, 158), (5952, 0), (6016, 0)] 0, attempt 19503 47 159 0 [(41878, 1), (9152, 158), (5952, 0), (6016, 0)] 0, attempt 19504 47 160 0 [(41942, 1), (9216, 158), (5952, 0), (6016, 0)] 0, attempt 19505 47 161 0 [(41559, 1), (9280, 158), (5952, 265), (6016, 265)] 1, attempt 19506 47 162 0 [(41623, 1), (9344, 158), (5952, 0), (6016, 0)] 0, attempt 19507 47 163 0 [(41687, 1), (9408, 158), (5952, 0), (6016, 0)] 0, attempt 19508 47 164 0 [(41751, 1), (9472, 158), (5952, 0), (6016, 0)] 0, attempt 19509 47 165 0 [(41815, 1), (9536, 158), (5952, 0), (6016, 0)] 0, attempt 19510 47 166 0 [(41879, 1), (9600, 158), (5952, 0), (6016, 0)] 0, attempt 19511 47 167 0 [(41943, 1), (9664, 158), (5952, 0), (6016, 0)] 0, attempt 19512 47 168 0 [(41560, 1), (12544, 158), (11264, 265), (11328, 265), (11392, 265), (11456, 265), (11520, 265), (11584, 265)] 1, attempt 19513 47 169 0 [(41624, 1), (12608, 158), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19514 47 170 0 [(41688, 1), (12672, 158), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19515 47 171 0 [(41752, 1), (12736, 158), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19516 47 172 0 [(41816, 1), (12800, 158), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19517 47 173 0 [(41880, 1), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19518 47 174 0 [(41944, 1), (11264, 0), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19519 47 175 0 [(41561, 1), (12864, 158), (11328, 265), (11392, 265), (11456, 265), (11520, 265), (11584, 265)] 1]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19488
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 19520 47 176 0 [(41625, 1), (12928, 158), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19521 47 177 0 [(41689, 1), (12992, 158), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19522 47 178 0 [(41753, 1), (13056, 158), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19523 47 179 0 [(41817, 1), (13120, 158), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19524 47 180 0 [(41881, 1), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19525 47 181 0 [(41945, 1), (11328, 0), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19526 47 182 0 [(41562, 1), (13184, 158), (11392, 265), (11456, 265), (11520, 265), (11584, 265)] 1, attempt 19527 47 183 0 [(41626, 1), (13248, 158), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19528 47 184 0 [(41690, 1), (13312, 158), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19529 47 185 0 [(41754, 1), (13376, 158), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19530 47 186 0 [(41818, 1), (13440, 158), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19531 47 187 0 [(41882, 1), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19532 47 188 0 [(41946, 1), (11392, 0), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19533 47 189 0 [(41563, 1), (13504, 158), (11456, 265), (11520, 265), (11584, 265)] 1, attempt 19534 47 190 0 [(41627, 1), (13568, 158), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19535 47 191 0 [(41691, 1), (13632, 158), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19536 47 192 0 [(41755, 1), (13696, 158), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19537 47 193 0 [(41819, 1), (13760, 158), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19538 47 194 0 [(41883, 1), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19539 47 195 0 [(41947, 1), (11456, 0), (11520, 0), (11584, 0)] 0, attempt 19540 47 196 0 [(41564, 1), (13824, 158), (11520, 265), (11584, 265)] 1, attempt 19541 47 197 0 [(41628, 1), (13888, 158), (11520, 0), (11584, 0)] 0, attempt 19542 47 198 0 [(41692, 1), (13952, 158), (11520, 0), (11584, 0)] 0, attempt 19543 47 199 0 [(41756, 1), (14016, 158), (11520, 0), (11584, 0)] 0, attempt 19544 47 200 0 [(41820, 1), (14080, 158), (11520, 0), (11584, 0)] 0, attempt 19545 47 201 0 [(41884, 1), (11520, 0), (11584, 0)] 0, attempt 19546 47 202 0 [(41948, 1), (11520, 0), (11584, 0)] 0, attempt 19547 47 203 0 [(41565, 1), (14144, 158), (11584, 265)] 1, attempt 19548 47 204 0 [(41629, 1), (14208, 158), (11584, 0)] 0, attempt 19549 47 205 0 [(41693, 1), (14272, 158), (11584, 0)] 0, attempt 19550 47 206 0 [(41757, 1), (14336, 158), (11584, 0)] 0, attempt 19551 47 207 0 [(41821, 1), (14400, 158), (11584, 0)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19520
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 19552 47 208 0 [(41885, 1), (11584, 0)] 0, attempt 19553 47 209 0 [(41949, 1), (11584, 0)] 0, attempt 19554 48 0 0 [(41566, 1)] 1, attempt 19555 48 1 0 [(41567, 1)] 1, attempt 19556 48 2 0 [(41568, 1)] 1, attempt 19557 48 3 0 [(41569, 1)] 1, attempt 19558 48 4 0 [(41570, 1)] 1, attempt 19559 48 5 0 [(41571, 1)] 1, attempt 19560 48 6 0 [(41572, 1)] 1, attempt 19561 48 7 0 [(41573, 1)] 1, attempt 19562 48 8 0 [(41574, 1)] 1, attempt 19563 48 9 0 [(41575, 1)] 1, attempt 19564 48 10 0 [(41576, 1)] 1, attempt 19565 48 11 0 [(41577, 1)] 1, attempt 19566 48 12 0 [(41578, 1)] 1, attempt 19567 48 13 0 [(41579, 1)] 1, attempt 19568 48 14 0 [(41580, 1)] 1, attempt 19569 48 15 0 [(41581, 1)] 1, attempt 19570 48 16 0 [(41582, 1)] 1, attempt 19571 48 17 0 [(41583, 1)] 1, attempt 19572 48 18 0 [(41584, 1)] 1, attempt 19573 48 19 0 [(41585, 1)] 1, attempt 19574 48 20 0 [(41586, 1)] 1, attempt 19575 48 21 0 [(41587, 1)] 1, attempt 19576 48 22 0 [(41588, 1)] 1, attempt 19577 48 23 0 [(41589, 1)] 1, attempt 19578 48 24 0 [(41590, 1)] 1, attempt 19579 48 25 0 [(41591, 1)] 1, attempt 19580 48 26 0 [(41592, 1)] 1, attempt 19581 48 27 0 [(41593, 1)] 1, attempt 19582 48 28 0 [(41594, 1)] 1, attempt 19583 48 29 0 [(41595, 1)] 1]
def counters004 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19552
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 19584 48 30 0 [(41596, 1)] 1, attempt 19585 48 31 0 [(41597, 1)] 1, attempt 19586 48 32 0 [(41598, 1)] 1, attempt 19587 48 33 0 [(41599, 1)] 1, attempt 19588 49 0 0 [(41630, 1)] 0, attempt 19589 49 1 0 [(41694, 1)] 0, attempt 19590 49 2 0 [(41758, 1)] 0, attempt 19591 49 3 0 [(41822, 1)] 0, attempt 19592 49 4 0 [(41886, 1)] 0, attempt 19593 49 5 0 [(41950, 1)] 0, attempt 19594 49 6 0 [(41631, 1)] 0, attempt 19595 49 7 0 [(41695, 1)] 0, attempt 19596 49 8 0 [(41759, 1)] 0, attempt 19597 49 9 0 [(41823, 1)] 0, attempt 19598 49 10 0 [(41887, 1)] 0, attempt 19599 49 11 0 [(41951, 1)] 0, attempt 19600 49 12 0 [(41632, 1)] 0, attempt 19601 49 13 0 [(41696, 1)] 0, attempt 19602 49 14 0 [(41760, 1)] 0, attempt 19603 49 15 0 [(41824, 1)] 0, attempt 19604 49 16 0 [(41888, 1)] 0, attempt 19605 49 17 0 [(41952, 1)] 0, attempt 19606 49 18 0 [(41633, 1)] 0, attempt 19607 49 19 0 [(41697, 1)] 0, attempt 19608 49 20 0 [(41761, 1)] 0, attempt 19609 49 21 0 [(41825, 1)] 0, attempt 19610 49 22 0 [(41889, 1)] 0, attempt 19611 49 23 0 [(41953, 1)] 0, attempt 19612 49 24 0 [(41634, 1)] 0, attempt 19613 49 25 0 [(41698, 1)] 0, attempt 19614 49 26 0 [(41762, 1)] 0, attempt 19615 49 27 0 [(41826, 1)] 0]
def counters005 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19584
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 19616 49 28 0 [(41890, 1)] 0, attempt 19617 49 29 0 [(41954, 1)] 0, attempt 19618 49 30 0 [(41635, 1)] 0, attempt 19619 49 31 0 [(41699, 1)] 0, attempt 19620 49 32 0 [(41763, 1)] 0, attempt 19621 49 33 0 [(41827, 1)] 0, attempt 19622 49 34 0 [(41891, 1)] 0, attempt 19623 49 35 0 [(41955, 1)] 0, attempt 19624 49 36 0 [(41636, 1)] 0, attempt 19625 49 37 0 [(41700, 1)] 0, attempt 19626 49 38 0 [(41764, 1)] 0, attempt 19627 49 39 0 [(41828, 1)] 0, attempt 19628 49 40 0 [(41892, 1)] 0, attempt 19629 49 41 0 [(41956, 1)] 0, attempt 19630 49 42 0 [(41637, 1)] 0, attempt 19631 49 43 0 [(41701, 1)] 0, attempt 19632 49 44 0 [(41765, 1)] 0, attempt 19633 49 45 0 [(41829, 1)] 0, attempt 19634 49 46 0 [(41893, 1)] 0, attempt 19635 49 47 0 [(41957, 1)] 0, attempt 19636 49 48 0 [(41638, 1)] 0, attempt 19637 49 49 0 [(41702, 1)] 0, attempt 19638 49 50 0 [(41766, 1)] 0, attempt 19639 49 51 0 [(41830, 1)] 0, attempt 19640 49 52 0 [(41894, 1)] 0, attempt 19641 49 53 0 [(41958, 1)] 0, attempt 19642 49 54 0 [(41639, 1)] 0, attempt 19643 49 55 0 [(41703, 1)] 0, attempt 19644 49 56 0 [(41767, 1)] 0, attempt 19645 49 57 0 [(41831, 1)] 0, attempt 19646 49 58 0 [(41895, 1)] 0, attempt 19647 49 59 0 [(41959, 1)] 0]
def counters006 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19616
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 19648 49 60 0 [(41640, 1)] 0, attempt 19649 49 61 0 [(41704, 1)] 0, attempt 19650 49 62 0 [(41768, 1)] 0, attempt 19651 49 63 0 [(41832, 1)] 0, attempt 19652 49 64 0 [(41896, 1)] 0, attempt 19653 49 65 0 [(41960, 1)] 0, attempt 19654 49 66 0 [(41641, 1)] 0, attempt 19655 49 67 0 [(41705, 1)] 0, attempt 19656 49 68 0 [(41769, 1)] 0, attempt 19657 49 69 0 [(41833, 1)] 0, attempt 19658 49 70 0 [(41897, 1)] 0, attempt 19659 49 71 0 [(41961, 1)] 0, attempt 19660 49 72 0 [(41642, 1)] 0, attempt 19661 49 73 0 [(41706, 1)] 0, attempt 19662 49 74 0 [(41770, 1)] 0, attempt 19663 49 75 0 [(41834, 1)] 0, attempt 19664 49 76 0 [(41898, 1)] 0, attempt 19665 49 77 0 [(41962, 1)] 0, attempt 19666 49 78 0 [(41643, 1)] 0, attempt 19667 49 79 0 [(41707, 1)] 0, attempt 19668 49 80 0 [(41771, 1)] 0, attempt 19669 49 81 0 [(41835, 1)] 0, attempt 19670 49 82 0 [(41899, 1)] 0, attempt 19671 49 83 0 [(41963, 1)] 0, attempt 19672 49 84 0 [(41644, 1)] 0, attempt 19673 49 85 0 [(41708, 1)] 0, attempt 19674 49 86 0 [(41772, 1)] 0, attempt 19675 49 87 0 [(41836, 1)] 0, attempt 19676 49 88 0 [(41900, 1)] 0, attempt 19677 49 89 0 [(41964, 1)] 0, attempt 19678 49 90 0 [(41645, 1)] 0, attempt 19679 49 91 0 [(41709, 1)] 0]
def counters007 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19648
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 19680 49 92 0 [(41773, 1)] 0, attempt 19681 49 93 0 [(41837, 1)] 0, attempt 19682 49 94 0 [(41901, 1)] 0, attempt 19683 49 95 0 [(41965, 1)] 0, attempt 19684 49 96 0 [(41646, 1)] 0, attempt 19685 49 97 0 [(41710, 1)] 0, attempt 19686 49 98 0 [(41774, 1)] 0, attempt 19687 49 99 0 [(41838, 1)] 0, attempt 19688 49 100 0 [(41902, 1)] 0, attempt 19689 49 101 0 [(41966, 1)] 0, attempt 19690 49 102 0 [(41647, 1)] 0, attempt 19691 49 103 0 [(41711, 1)] 0, attempt 19692 49 104 0 [(41775, 1)] 0, attempt 19693 49 105 0 [(41839, 1)] 0, attempt 19694 49 106 0 [(41903, 1)] 0, attempt 19695 49 107 0 [(41967, 1)] 0, attempt 19696 49 108 0 [(41648, 1)] 0, attempt 19697 49 109 0 [(41712, 1)] 0, attempt 19698 49 110 0 [(41776, 1)] 0, attempt 19699 49 111 0 [(41840, 1)] 0, attempt 19700 49 112 0 [(41904, 1)] 0, attempt 19701 49 113 0 [(41968, 1)] 0, attempt 19702 49 114 0 [(41649, 1)] 0, attempt 19703 49 115 0 [(41713, 1)] 0, attempt 19704 49 116 0 [(41777, 1)] 0, attempt 19705 49 117 0 [(41841, 1)] 0, attempt 19706 49 118 0 [(41905, 1)] 0, attempt 19707 49 119 0 [(41969, 1)] 0, attempt 19708 49 120 0 [(41650, 1)] 0, attempt 19709 49 121 0 [(41714, 1)] 0, attempt 19710 49 122 0 [(41778, 1)] 0, attempt 19711 49 123 0 [(41842, 1)] 0]
def counters008 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19680
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 19712 49 124 0 [(41906, 1)] 0, attempt 19713 49 125 0 [(41970, 1)] 0, attempt 19714 49 126 0 [(41651, 1)] 0, attempt 19715 49 127 0 [(41715, 1)] 0, attempt 19716 49 128 0 [(41779, 1)] 0, attempt 19717 49 129 0 [(41843, 1)] 0, attempt 19718 49 130 0 [(41907, 1)] 0, attempt 19719 49 131 0 [(41971, 1)] 0, attempt 19720 49 132 0 [(41652, 1)] 0, attempt 19721 49 133 0 [(41716, 1)] 0, attempt 19722 49 134 0 [(41780, 1)] 0, attempt 19723 49 135 0 [(41844, 1)] 0, attempt 19724 49 136 0 [(41908, 1)] 0, attempt 19725 49 137 0 [(41972, 1)] 0, attempt 19726 49 138 0 [(41653, 1)] 0, attempt 19727 49 139 0 [(41717, 1)] 0, attempt 19728 49 140 0 [(41781, 1)] 0, attempt 19729 49 141 0 [(41845, 1)] 0, attempt 19730 49 142 0 [(41909, 1)] 0, attempt 19731 49 143 0 [(41973, 1)] 0, attempt 19732 49 144 0 [(41654, 1)] 0, attempt 19733 49 145 0 [(41718, 1)] 0, attempt 19734 49 146 0 [(41782, 1)] 0, attempt 19735 49 147 0 [(41846, 1)] 0, attempt 19736 49 148 0 [(41910, 1)] 0, attempt 19737 49 149 0 [(41974, 1)] 0, attempt 19738 49 150 0 [(41655, 1)] 0, attempt 19739 49 151 0 [(41719, 1)] 0, attempt 19740 49 152 0 [(41783, 1)] 0, attempt 19741 49 153 0 [(41847, 1)] 0, attempt 19742 49 154 0 [(41911, 1)] 0, attempt 19743 49 155 0 [(41975, 1)] 0]
def counters009 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19712
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 19744 49 156 0 [(41656, 1)] 0, attempt 19745 49 157 0 [(41720, 1)] 0, attempt 19746 49 158 0 [(41784, 1)] 0, attempt 19747 49 159 0 [(41848, 1)] 0, attempt 19748 49 160 0 [(41912, 1)] 0, attempt 19749 49 161 0 [(41976, 1)] 0, attempt 19750 49 162 0 [(41657, 1)] 0, attempt 19751 49 163 0 [(41721, 1)] 0, attempt 19752 49 164 0 [(41785, 1)] 0, attempt 19753 49 165 0 [(41849, 1)] 0, attempt 19754 49 166 0 [(41913, 1)] 0, attempt 19755 49 167 0 [(41977, 1)] 0, attempt 19756 49 168 0 [(41658, 1)] 0, attempt 19757 49 169 0 [(41722, 1)] 0, attempt 19758 49 170 0 [(41786, 1)] 0, attempt 19759 49 171 0 [(41850, 1)] 0, attempt 19760 49 172 0 [(41914, 1)] 0, attempt 19761 49 173 0 [(41978, 1)] 0, attempt 19762 49 174 0 [(41659, 1)] 0, attempt 19763 49 175 0 [(41723, 1)] 0, attempt 19764 49 176 0 [(41787, 1)] 0, attempt 19765 49 177 0 [(41851, 1)] 0, attempt 19766 49 178 0 [(41915, 1)] 0, attempt 19767 49 179 0 [(41979, 1)] 0, attempt 19768 49 180 0 [(41660, 1)] 0, attempt 19769 49 181 0 [(41724, 1)] 0, attempt 19770 49 182 0 [(41788, 1)] 0, attempt 19771 49 183 0 [(41852, 1)] 0, attempt 19772 49 184 0 [(41916, 1)] 0, attempt 19773 49 185 0 [(41980, 1)] 0, attempt 19774 49 186 0 [(41661, 1)] 0, attempt 19775 49 187 0 [(41725, 1)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19744
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 19776 49 188 0 [(41789, 1)] 0, attempt 19777 49 189 0 [(41853, 1)] 0, attempt 19778 49 190 0 [(41917, 1)] 0, attempt 19779 49 191 0 [(41981, 1)] 0, attempt 19780 49 192 0 [(41662, 1)] 0, attempt 19781 49 193 0 [(41726, 1)] 0, attempt 19782 49 194 0 [(41790, 1)] 0, attempt 19783 49 195 0 [(41854, 1)] 0, attempt 19784 49 196 0 [(41918, 1)] 0, attempt 19785 49 197 0 [(41982, 1)] 0, attempt 19786 49 198 0 [(41663, 1)] 0, attempt 19787 49 199 0 [(41727, 1)] 0, attempt 19788 49 200 0 [(41791, 1)] 0, attempt 19789 49 201 0 [(41855, 1)] 0, attempt 19790 49 202 0 [(41919, 1)] 0, attempt 19791 49 203 0 [(41983, 1)] 0, attempt 19792 50 0 0 [(42014, 1)] 0, attempt 19793 50 1 0 [(42015, 1)] 0, attempt 19794 50 2 0 [(42016, 1)] 0, attempt 19795 50 3 0 [(42017, 1)] 0, attempt 19796 50 4 0 [(42018, 1)] 0, attempt 19797 50 5 0 [(42019, 1)] 0, attempt 19798 50 6 0 [(42020, 1)] 0, attempt 19799 50 7 0 [(42021, 1)] 0, attempt 19800 50 8 0 [(42022, 1)] 0, attempt 19801 50 9 0 [(42023, 1)] 0, attempt 19802 50 10 0 [(42024, 1)] 0, attempt 19803 50 11 0 [(42025, 1)] 0, attempt 19804 50 12 0 [(42026, 1)] 0, attempt 19805 50 13 0 [(42027, 1)] 0, attempt 19806 50 14 0 [(42028, 1)] 0, attempt 19807 50 15 0 [(42029, 1)] 0]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19776
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 19808 50 16 0 [(42030, 1)] 0, attempt 19809 50 17 0 [(42031, 1)] 0, attempt 19810 50 18 0 [(42032, 1)] 0, attempt 19811 50 19 0 [(42033, 1)] 0, attempt 19812 50 20 0 [(42034, 1)] 0, attempt 19813 50 21 0 [(42035, 1)] 0, attempt 19814 50 22 0 [(42036, 1)] 0, attempt 19815 50 23 0 [(42037, 1)] 0, attempt 19816 50 24 0 [(42038, 1)] 0, attempt 19817 50 25 0 [(42039, 1)] 0, attempt 19818 50 26 0 [(42040, 1)] 0, attempt 19819 50 27 0 [(42041, 1)] 0, attempt 19820 50 28 0 [(42042, 1)] 0, attempt 19821 50 29 0 [(42043, 1)] 0, attempt 19822 50 30 0 [(42044, 1)] 0, attempt 19823 50 31 0 [(42045, 1)] 0, attempt 19824 50 32 0 [(42046, 1)] 0, attempt 19825 50 33 0 [(42047, 1)] 0, attempt 19826 51 0 0 [(42078, 1)] 1, attempt 19827 51 1 0 [(42079, 1)] 1, attempt 19828 51 2 0 [(42080, 1)] 1, attempt 19829 51 3 0 [(42081, 1)] 1, attempt 19830 51 4 0 [(42082, 1)] 1, attempt 19831 51 5 0 [(42083, 1)] 1, attempt 19832 51 6 0 [(42084, 1)] 1, attempt 19833 51 7 0 [(42085, 1)] 1, attempt 19834 51 8 0 [(42086, 1)] 1, attempt 19835 51 9 0 [(42087, 1)] 1, attempt 19836 51 10 0 [(42088, 1)] 1, attempt 19837 51 11 0 [(42089, 1)] 1, attempt 19838 51 12 0 [(42090, 1)] 1, attempt 19839 51 13 0 [(42091, 1)] 1]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19808
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 19840 51 14 0 [(42092, 1)] 1, attempt 19841 51 15 0 [(42093, 1)] 1, attempt 19842 51 16 0 [(42094, 1)] 1, attempt 19843 51 17 0 [(42095, 1)] 1, attempt 19844 51 18 0 [(42096, 1)] 1, attempt 19845 51 19 0 [(42097, 1)] 1, attempt 19846 51 20 0 [(42098, 1)] 1, attempt 19847 51 21 0 [(42099, 1)] 1, attempt 19848 51 22 0 [(42100, 1)] 1, attempt 19849 51 23 0 [(42101, 1)] 1, attempt 19850 51 24 0 [(42102, 1)] 1, attempt 19851 51 25 0 [(42103, 1)] 1, attempt 19852 51 26 0 [(42104, 1)] 1, attempt 19853 51 27 0 [(42105, 1)] 1, attempt 19854 51 28 0 [(42106, 1)] 1, attempt 19855 51 29 0 [(42107, 1)] 1, attempt 19856 51 30 0 [(42108, 1)] 1, attempt 19857 51 31 0 [(42109, 1)] 1, attempt 19858 51 32 0 [(42110, 1)] 1, attempt 19859 51 33 0 [(42111, 1)] 1, attempt 19860 52 0 0 [(29802, 1), (41408, 158)] 0, attempt 19861 52 1 0 [(29866, 1), (41409, 158)] 0, attempt 19862 52 2 0 [(29930, 1), (41410, 158)] 0, attempt 19863 52 3 0 [(29994, 1), (41411, 158)] 0, attempt 19864 52 4 0 [(30058, 1), (41412, 158)] 0, attempt 19865 52 5 0 [(30122, 1), (41413, 158)] 0, attempt 19866 52 6 0 [(30186, 1), (41414, 158)] 0, attempt 19867 52 7 0 [(30250, 1), (41415, 158)] 0, attempt 19868 52 8 0 [(30314, 1), (41416, 158)] 0, attempt 19869 52 9 0 [(30378, 1), (41417, 158)] 0, attempt 19870 52 10 0 [(30442, 1), (41418, 158)] 0, attempt 19871 52 11 0 [(30506, 1), (41419, 158)] 0]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19840
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 19872 52 12 0 [(30570, 1), (41420, 158)] 0, attempt 19873 52 13 0 [(30634, 1), (41421, 158)] 0, attempt 19874 52 14 0 [(30698, 1)] 551, attempt 19875 52 15 0 [(30762, 1)] 544, attempt 19876 52 16 0 [(29803, 1), (41422, 158)] 0, attempt 19877 52 17 0 [(29867, 1), (41423, 158)] 0, attempt 19878 52 18 0 [(29931, 1), (41424, 158)] 0, attempt 19879 52 19 0 [(29995, 1), (41425, 158)] 0, attempt 19880 52 20 0 [(30059, 1), (41426, 158)] 0, attempt 19881 52 21 0 [(30123, 1), (41427, 158)] 0, attempt 19882 52 22 0 [(30187, 1), (41428, 158)] 0, attempt 19883 52 23 0 [(30251, 1), (41429, 158)] 0, attempt 19884 52 24 0 [(30315, 1), (41430, 158)] 0, attempt 19885 52 25 0 [(30379, 1), (41431, 158)] 0, attempt 19886 52 26 0 [(30443, 1), (41432, 158)] 0, attempt 19887 52 27 0 [(30507, 1), (41433, 158)] 0, attempt 19888 52 28 0 [(30571, 1), (41434, 158)] 0, attempt 19889 52 29 0 [(30635, 1), (41435, 158)] 0, attempt 19890 52 30 0 [(30699, 1)] 552, attempt 19891 52 31 0 [(30763, 1)] 544, attempt 19892 52 32 0 [(29804, 1), (41436, 158)] 0, attempt 19893 52 33 0 [(29868, 1), (41437, 158)] 0, attempt 19894 52 34 0 [(29932, 1), (41438, 158)] 0, attempt 19895 52 35 0 [(29996, 1), (41439, 158)] 0, attempt 19896 52 36 0 [(30060, 1), (41440, 158)] 0, attempt 19897 52 37 0 [(30124, 1), (41441, 158)] 0, attempt 19898 52 38 0 [(30188, 1), (41442, 158)] 0, attempt 19899 52 39 0 [(30252, 1), (41443, 158)] 0, attempt 19900 52 40 0 [(30316, 1), (41444, 158)] 0, attempt 19901 52 41 0 [(30380, 1), (41445, 158)] 0, attempt 19902 52 42 0 [(30444, 1), (41446, 158)] 0, attempt 19903 52 43 0 [(30508, 1), (41447, 158)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19872
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 19904 52 44 0 [(30572, 1), (41448, 158)] 0, attempt 19905 52 45 0 [(30636, 1), (41449, 158)] 0, attempt 19906 52 46 0 [(30700, 1)] 553, attempt 19907 52 47 0 [(30764, 1)] 544, attempt 19908 52 48 0 [(29805, 1), (41450, 158)] 0, attempt 19909 52 49 0 [(29869, 1), (41451, 158)] 0, attempt 19910 52 50 0 [(29933, 1), (41452, 158)] 0, attempt 19911 52 51 0 [(29997, 1), (41453, 158)] 0, attempt 19912 52 52 0 [(30061, 1), (41454, 158)] 0, attempt 19913 52 53 0 [(30125, 1), (41455, 158)] 0, attempt 19914 52 54 0 [(30189, 1), (41456, 158)] 0, attempt 19915 52 55 0 [(30253, 1), (41457, 158)] 0, attempt 19916 52 56 0 [(30317, 1), (41458, 158)] 0, attempt 19917 52 57 0 [(30381, 1), (41459, 158)] 0, attempt 19918 52 58 0 [(30445, 1), (41460, 158)] 0, attempt 19919 52 59 0 [(30509, 1), (41461, 158)] 0, attempt 19920 52 60 0 [(30573, 1), (41462, 158)] 0, attempt 19921 52 61 0 [(30637, 1)] 0, attempt 19922 52 62 0 [(30701, 1)] 554, attempt 19923 52 63 0 [(30765, 1)] 544, attempt 19924 53 0 0 [(29806, 1), (40426, 158)] 0, attempt 19925 53 1 0 [(29870, 1), (40490, 158)] 0, attempt 19926 53 2 0 [(29934, 1), (40554, 158)] 0, attempt 19927 53 3 0 [(29998, 1), (40618, 158)] 0, attempt 19928 53 4 0 [(30062, 1), (40682, 158)] 0, attempt 19929 53 5 0 [(30126, 1), (40746, 158)] 0, attempt 19930 53 6 0 [(30190, 1), (40810, 158)] 0, attempt 19931 53 7 0 [(30254, 1), (40427, 158)] 0, attempt 19932 53 8 0 [(30318, 1), (40491, 158)] 0, attempt 19933 53 9 0 [(30382, 1), (40555, 158)] 0, attempt 19934 53 10 0 [(30446, 1), (40619, 158)] 0, attempt 19935 53 11 0 [(30510, 1), (40683, 158)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19904
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 19936 53 12 0 [(30574, 1), (40747, 158)] 0, attempt 19937 53 13 0 [(30638, 1), (40811, 158)] 0, attempt 19938 53 14 0 [(30702, 1)] 555, attempt 19939 53 15 0 [(30766, 1)] 544, attempt 19940 53 16 0 [(29807, 1), (40428, 158)] 0, attempt 19941 53 17 0 [(29871, 1), (40492, 158)] 0, attempt 19942 53 18 0 [(29935, 1), (40556, 158)] 0, attempt 19943 53 19 0 [(29999, 1), (40620, 158)] 0, attempt 19944 53 20 0 [(30063, 1), (40684, 158)] 0, attempt 19945 53 21 0 [(30127, 1), (40748, 158)] 0, attempt 19946 53 22 0 [(30191, 1), (40812, 158)] 0, attempt 19947 53 23 0 [(30255, 1), (40429, 158)] 0, attempt 19948 53 24 0 [(30319, 1), (40493, 158)] 0, attempt 19949 53 25 0 [(30383, 1), (40557, 158)] 0, attempt 19950 53 26 0 [(30447, 1), (40621, 158)] 0, attempt 19951 53 27 0 [(30511, 1), (40685, 158)] 0, attempt 19952 53 28 0 [(30575, 1), (40749, 158)] 0, attempt 19953 53 29 0 [(30639, 1), (40813, 158)] 0, attempt 19954 53 30 0 [(30703, 1)] 556, attempt 19955 53 31 0 [(30767, 1)] 544, attempt 19956 53 32 0 [(29808, 1), (40430, 158)] 0, attempt 19957 53 33 0 [(29872, 1), (40494, 158)] 0, attempt 19958 53 34 0 [(29936, 1), (40558, 158)] 0, attempt 19959 53 35 0 [(30000, 1), (40622, 158)] 0, attempt 19960 53 36 0 [(30064, 1), (40686, 158)] 0, attempt 19961 53 37 0 [(30128, 1), (40750, 158)] 0, attempt 19962 53 38 0 [(30192, 1), (40814, 158)] 0, attempt 19963 53 39 0 [(30256, 1), (40431, 158)] 0, attempt 19964 53 40 0 [(30320, 1), (40495, 158)] 0, attempt 19965 53 41 0 [(30384, 1), (40559, 158)] 0, attempt 19966 53 42 0 [(30448, 1), (40623, 158)] 0, attempt 19967 53 43 0 [(30512, 1), (40687, 158)] 0]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 171, 48, 7, 48, 7, 32, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 210, 34, 204, 34, 34, 64, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19936
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19968
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19936
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 19936 19968 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 19936) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19904
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 19904 19936 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 19904) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19872
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 19872 19904 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 19872) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19840
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 19840 19872 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 19840) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19808
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 19808 19840 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 19808) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19776
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 19776 19808 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 19776) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19744
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 19744 19776 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 19744) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19712
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 19712 19744 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 19712) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19680
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 19680 19712 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 19680) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19648
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 19648 19680 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 19648) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19616
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 19616 19648 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 19616) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19584
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 19584 19616 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 19584) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19552
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 19552 19584 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 19552) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19520
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 19520 19552 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 19520) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19488
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 19488 19520 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 19488) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19456
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 19456 19488 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 19456) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr38
