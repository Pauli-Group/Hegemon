import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr33

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr34
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 17408 16 18 0 [(16338, 1), (256, 158)] 0, attempt 17409 16 19 0 [(16339, 1), (256, 158)] 0, attempt 17410 16 20 0 [(16340, 1), (256, 158)] 0, attempt 17411 16 21 0 [(16341, 1), (320, 158)] 0, attempt 17412 16 22 0 [(16342, 1), (320, 158)] 0, attempt 17413 16 23 0 [(16343, 1), (320, 158)] 0, attempt 17414 16 24 0 [(16344, 1), (320, 158)] 0, attempt 17415 16 25 0 [(16345, 1), (320, 158)] 0, attempt 17416 16 26 0 [(16346, 1), (320, 158)] 0, attempt 17417 16 27 0 [(16347, 1), (320, 158)] 0, attempt 17418 16 28 0 [(16348, 1), (384, 158)] 0, attempt 17419 16 29 0 [(16349, 1), (384, 158)] 0, attempt 17420 16 30 0 [(16350, 1), (384, 158)] 0, attempt 17421 16 31 0 [(16351, 1), (384, 158)] 0, attempt 17422 16 32 0 [(16352, 1), (384, 158)] 0, attempt 17423 16 33 0 [(16353, 1), (384, 158)] 0, attempt 17424 16 34 0 [(16354, 1), (384, 158)] 0, attempt 17425 16 35 0 [(16355, 1), (448, 158)] 0, attempt 17426 16 36 0 [(16356, 1), (448, 158)] 0, attempt 17427 16 37 0 [(16357, 1), (448, 158)] 0, attempt 17428 16 38 0 [(16358, 1), (448, 158)] 0, attempt 17429 16 39 0 [(16359, 1), (448, 158)] 0, attempt 17430 16 40 0 [(16360, 1), (448, 158)] 0, attempt 17431 16 41 0 [(16361, 1), (448, 158)] 0, attempt 17432 16 42 0 [(16362, 1), (512, 158)] 0, attempt 17433 16 43 0 [(16363, 1), (512, 158)] 0, attempt 17434 16 44 0 [(16364, 1), (512, 158)] 0, attempt 17435 16 45 0 [(16365, 1), (512, 158)] 0, attempt 17436 16 46 0 [(16366, 1), (512, 158)] 0, attempt 17437 16 47 0 [(16367, 1), (512, 158)] 0, attempt 17438 16 48 0 [(16368, 1), (512, 158)] 0, attempt 17439 16 49 0 [(16369, 1), (576, 158)] 0]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17408
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 17440 16 50 0 [(16370, 1), (576, 158)] 0, attempt 17441 16 51 0 [(16371, 1), (576, 158)] 0, attempt 17442 16 52 0 [(16372, 1), (576, 158)] 0, attempt 17443 16 53 0 [(16373, 1), (576, 158)] 0, attempt 17444 16 54 0 [(16374, 1), (576, 158)] 0, attempt 17445 16 55 0 [(16375, 1), (576, 158)] 0, attempt 17446 16 56 0 [(16376, 1), (640, 158)] 0, attempt 17447 16 57 0 [(16377, 1), (640, 158)] 0, attempt 17448 16 58 0 [(16378, 1), (640, 158)] 0, attempt 17449 16 59 0 [(16379, 1), (640, 158)] 0, attempt 17450 16 60 0 [(16380, 1), (640, 158)] 0, attempt 17451 16 61 0 [(16381, 1), (640, 158)] 0, attempt 17452 16 62 0 [(16382, 1), (640, 158)] 0, attempt 17453 16 63 0 [(16383, 1), (704, 158)] 0, attempt 17454 16 64 0 [(16576, 1), (704, 158)] 0, attempt 17455 16 65 0 [(16577, 1), (704, 158)] 0, attempt 17456 16 66 0 [(16578, 1), (704, 158)] 0, attempt 17457 16 67 0 [(16579, 1), (704, 158)] 0, attempt 17458 16 68 0 [(16580, 1), (704, 158)] 0, attempt 17459 16 69 0 [(16581, 1), (704, 158)] 0, attempt 17460 16 70 0 [(16582, 1), (768, 158)] 0, attempt 17461 16 71 0 [(16583, 1), (768, 158)] 0, attempt 17462 16 72 0 [(16584, 1), (768, 158)] 0, attempt 17463 16 73 0 [(16585, 1), (768, 158)] 0, attempt 17464 16 74 0 [(16586, 1), (768, 158)] 0, attempt 17465 16 75 0 [(16587, 1), (768, 158)] 0, attempt 17466 16 76 0 [(16588, 1), (768, 158)] 0, attempt 17467 16 77 0 [(16589, 1), (832, 158)] 0, attempt 17468 16 78 0 [(16590, 1), (832, 158)] 0, attempt 17469 16 79 0 [(16591, 1), (832, 158)] 0, attempt 17470 16 80 0 [(16592, 1), (832, 158)] 0, attempt 17471 16 81 0 [(16593, 1), (832, 158)] 0]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17440
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 17472 16 82 0 [(16594, 1), (832, 158)] 0, attempt 17473 16 83 0 [(16595, 1), (832, 158)] 0, attempt 17474 16 84 0 [(16596, 1), (896, 158)] 0, attempt 17475 16 85 0 [(16597, 1), (896, 158)] 0, attempt 17476 16 86 0 [(16598, 1), (896, 158)] 0, attempt 17477 16 87 0 [(16599, 1), (896, 158)] 0, attempt 17478 16 88 0 [(16600, 1), (896, 158)] 0, attempt 17479 16 89 0 [(16601, 1), (896, 158)] 0, attempt 17480 16 90 0 [(16602, 1), (896, 158)] 0, attempt 17481 16 91 0 [(16603, 1), (960, 158)] 0, attempt 17482 16 92 0 [(16604, 1), (960, 158)] 0, attempt 17483 16 93 0 [(16605, 1), (960, 158)] 0, attempt 17484 16 94 0 [(16606, 1), (960, 158)] 0, attempt 17485 16 95 0 [(16607, 1), (960, 158)] 0, attempt 17486 16 96 0 [(16608, 1), (960, 158)] 0, attempt 17487 16 97 0 [(16609, 1), (960, 158)] 0, attempt 17488 16 98 0 [(16610, 1), (1024, 158)] 0, attempt 17489 16 99 0 [(16611, 1), (1024, 158)] 0, attempt 17490 16 100 0 [(16612, 1), (1024, 158)] 0, attempt 17491 16 101 0 [(16613, 1), (1024, 158)] 0, attempt 17492 16 102 0 [(16614, 1), (1024, 158)] 0, attempt 17493 16 103 0 [(16615, 1), (1024, 158)] 0, attempt 17494 16 104 0 [(16616, 1), (1024, 158)] 0, attempt 17495 16 105 0 [(16617, 1), (1088, 158)] 0, attempt 17496 16 106 0 [(16618, 1), (1088, 158)] 0, attempt 17497 16 107 0 [(16619, 1), (1088, 158)] 0, attempt 17498 16 108 0 [(16620, 1), (1088, 158)] 0, attempt 17499 16 109 0 [(16621, 1), (1088, 158)] 0, attempt 17500 16 110 0 [(16622, 1), (1088, 158)] 0, attempt 17501 16 111 0 [(16623, 1), (1088, 158)] 0, attempt 17502 16 112 0 [(16624, 1), (1152, 158)] 0, attempt 17503 16 113 0 [(16625, 1), (1152, 158)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17472
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 17504 16 114 0 [(16626, 1), (1152, 158)] 0, attempt 17505 16 115 0 [(16627, 1), (1152, 158)] 0, attempt 17506 16 116 0 [(16628, 1), (1152, 158)] 0, attempt 17507 16 117 0 [(16629, 1), (1152, 158)] 0, attempt 17508 16 118 0 [(16630, 1), (1152, 158)] 0, attempt 17509 16 119 0 [(16631, 1), (1216, 158)] 0, attempt 17510 16 120 0 [(16632, 1), (1216, 158)] 0, attempt 17511 16 121 0 [(16633, 1), (1216, 158)] 0, attempt 17512 16 122 0 [(16634, 1), (1216, 158)] 0, attempt 17513 16 123 0 [(16635, 1), (1216, 158)] 0, attempt 17514 16 124 0 [(16636, 1), (1216, 158)] 0, attempt 17515 16 125 0 [(16637, 1), (1216, 158)] 0, attempt 17516 16 126 0 [(16638, 1), (1280, 158)] 0, attempt 17517 16 127 0 [(16639, 1), (1280, 158)] 0, attempt 17518 16 128 0 [(16832, 1), (1280, 158)] 0, attempt 17519 16 129 0 [(16833, 1), (1280, 158)] 0, attempt 17520 16 130 0 [(16834, 1), (1280, 158)] 0, attempt 17521 16 131 0 [(16835, 1), (1280, 158)] 0, attempt 17522 16 132 0 [(16836, 1), (1280, 158)] 0, attempt 17523 16 133 0 [(16837, 1), (1344, 158)] 0, attempt 17524 16 134 0 [(16838, 1), (1344, 158)] 0, attempt 17525 16 135 0 [(16839, 1), (1344, 158)] 0, attempt 17526 16 136 0 [(16840, 1), (1344, 158)] 0, attempt 17527 16 137 0 [(16841, 1), (1344, 158)] 0, attempt 17528 16 138 0 [(16842, 1), (1344, 158)] 0, attempt 17529 16 139 0 [(16843, 1), (1344, 158)] 0, attempt 17530 16 140 0 [(16844, 1), (1408, 158)] 0, attempt 17531 16 141 0 [(16845, 1), (1408, 158)] 0, attempt 17532 16 142 0 [(16846, 1), (1408, 158)] 0, attempt 17533 16 143 0 [(16847, 1), (1408, 158)] 0, attempt 17534 16 144 0 [(16848, 1), (1408, 158)] 0, attempt 17535 16 145 0 [(16849, 1), (1408, 158)] 0]
def counters004 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17504
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 17536 16 146 0 [(16850, 1), (1408, 158)] 0, attempt 17537 16 147 0 [(16851, 1), (1472, 158)] 0, attempt 17538 16 148 0 [(16852, 1), (1472, 158)] 0, attempt 17539 16 149 0 [(16853, 1), (1472, 158)] 0, attempt 17540 16 150 0 [(16854, 1), (1472, 158)] 0, attempt 17541 16 151 0 [(16855, 1), (1472, 158)] 0, attempt 17542 16 152 0 [(16856, 1), (1472, 158)] 0, attempt 17543 16 153 0 [(16857, 1), (1472, 158)] 0, attempt 17544 16 154 0 [(16858, 1), (1536, 158)] 0, attempt 17545 16 155 0 [(16859, 1), (1536, 158)] 0, attempt 17546 16 156 0 [(16860, 1), (1536, 158)] 0, attempt 17547 16 157 0 [(16861, 1), (1536, 158)] 0, attempt 17548 16 158 0 [(16862, 1), (1536, 158)] 0, attempt 17549 16 159 0 [(16863, 1), (1536, 158)] 0, attempt 17550 16 160 0 [(16864, 1), (1536, 158)] 0, attempt 17551 16 161 0 [(16865, 1), (1600, 158)] 0, attempt 17552 16 162 0 [(16866, 1), (1600, 158)] 0, attempt 17553 16 163 0 [(16867, 1), (1600, 158)] 0, attempt 17554 16 164 0 [(16868, 1), (1600, 158)] 0, attempt 17555 16 165 0 [(16869, 1), (1600, 158)] 0, attempt 17556 16 166 0 [(16870, 1), (1600, 158)] 0, attempt 17557 16 167 0 [(16871, 1), (1600, 158)] 0, attempt 17558 16 168 0 [(16872, 1), (1664, 158)] 0, attempt 17559 16 169 0 [(16873, 1), (1664, 158)] 0, attempt 17560 16 170 0 [(16874, 1), (1664, 158)] 0, attempt 17561 16 171 0 [(16875, 1), (1664, 158)] 0, attempt 17562 16 172 0 [(16876, 1), (1664, 158)] 0, attempt 17563 16 173 0 [(16877, 1), (1664, 158)] 0, attempt 17564 16 174 0 [(16878, 1), (1664, 158)] 0, attempt 17565 16 175 0 [(16879, 1), (1728, 158)] 0, attempt 17566 16 176 0 [(16880, 1), (1728, 158)] 0, attempt 17567 16 177 0 [(16881, 1), (1728, 158)] 0]
def counters005 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17536
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 17568 16 178 0 [(16882, 1), (1728, 158)] 0, attempt 17569 16 179 0 [(16883, 1), (1728, 158)] 0, attempt 17570 16 180 0 [(16884, 1), (1728, 158)] 0, attempt 17571 16 181 0 [(16885, 1), (1728, 158)] 0, attempt 17572 16 182 0 [(16886, 1), (1792, 158)] 0, attempt 17573 16 183 0 [(16887, 1), (1792, 158)] 0, attempt 17574 16 184 0 [(16888, 1), (1792, 158)] 0, attempt 17575 16 185 0 [(16889, 1), (1792, 158)] 0, attempt 17576 16 186 0 [(16890, 1), (1792, 158)] 0, attempt 17577 16 187 0 [(16891, 1), (1792, 158)] 0, attempt 17578 16 188 0 [(16892, 1), (1792, 158)] 0, attempt 17579 16 189 0 [(16893, 1), (1856, 158)] 0, attempt 17580 16 190 0 [(16894, 1), (1856, 158)] 0, attempt 17581 16 191 0 [(16895, 1), (1856, 158)] 0, attempt 17582 16 192 0 [(17088, 1), (1856, 158)] 0, attempt 17583 16 193 0 [(17089, 1), (1856, 158)] 0, attempt 17584 16 194 0 [(17090, 1), (1856, 158)] 0, attempt 17585 16 195 0 [(17091, 1), (1856, 158)] 0, attempt 17586 16 196 0 [(17092, 1), (1920, 158)] 0, attempt 17587 16 197 0 [(17093, 1), (1920, 158)] 0, attempt 17588 16 198 0 [(17094, 1), (1920, 158)] 0, attempt 17589 16 199 0 [(17095, 1), (1920, 158)] 0, attempt 17590 16 200 0 [(17096, 1), (1920, 158)] 0, attempt 17591 16 201 0 [(17097, 1), (1920, 158)] 0, attempt 17592 16 202 0 [(17098, 1), (1920, 158)] 0, attempt 17593 16 203 0 [(17099, 1), (1984, 158)] 0, attempt 17594 16 204 0 [(17100, 1), (1984, 158)] 0, attempt 17595 16 205 0 [(17101, 1), (1984, 158)] 0, attempt 17596 16 206 0 [(17102, 1), (1984, 158)] 0, attempt 17597 16 207 0 [(17103, 1), (1984, 158)] 0, attempt 17598 16 208 0 [(17104, 1), (1984, 158)] 0, attempt 17599 16 209 0 [(17105, 1), (1984, 158)] 0]
def counters006 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17568
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 17600 16 210 0 [(17106, 1), (2048, 158)] 0, attempt 17601 16 211 0 [(17107, 1), (2048, 158)] 0, attempt 17602 16 212 0 [(17108, 1), (2048, 158)] 0, attempt 17603 16 213 0 [(17109, 1), (2048, 158)] 0, attempt 17604 16 214 0 [(17110, 1), (2048, 158)] 0, attempt 17605 16 215 0 [(17111, 1), (2048, 158)] 0, attempt 17606 16 216 0 [(17112, 1), (2048, 158)] 0, attempt 17607 16 217 0 [(17113, 1), (2112, 158)] 0, attempt 17608 16 218 0 [(17114, 1), (2112, 158)] 0, attempt 17609 16 219 0 [(17115, 1), (2112, 158)] 0, attempt 17610 16 220 0 [(17116, 1), (2112, 158)] 0, attempt 17611 16 221 0 [(17117, 1), (2112, 158)] 0, attempt 17612 16 222 0 [(17118, 1), (2112, 158)] 0, attempt 17613 16 223 0 [(17119, 1), (2112, 158)] 0, attempt 17614 16 224 0 [(17120, 1), (2304, 158)] 0, attempt 17615 16 225 0 [(17121, 1), (2304, 158)] 0, attempt 17616 16 226 0 [(17122, 1), (2304, 158)] 0, attempt 17617 16 227 0 [(17123, 1), (2304, 158)] 0, attempt 17618 16 228 0 [(17124, 1), (2304, 158)] 0, attempt 17619 16 229 0 [(17125, 1), (2304, 158)] 0, attempt 17620 16 230 0 [(17126, 1), (2304, 158)] 0, attempt 17621 16 231 0 [(17127, 1), (2368, 158)] 0, attempt 17622 16 232 0 [(17128, 1), (2368, 158)] 0, attempt 17623 16 233 0 [(17129, 1), (2368, 158)] 0, attempt 17624 16 234 0 [(17130, 1), (2368, 158)] 0, attempt 17625 16 235 0 [(17131, 1), (2368, 158)] 0, attempt 17626 16 236 0 [(17132, 1), (2368, 158)] 0, attempt 17627 16 237 0 [(17133, 1), (2368, 158)] 0, attempt 17628 16 238 0 [(17134, 1), (2432, 158)] 0, attempt 17629 16 239 0 [(17135, 1), (2432, 158)] 0, attempt 17630 16 240 0 [(17136, 1), (2432, 158)] 0, attempt 17631 16 241 0 [(17137, 1), (2432, 158)] 0]
def counters007 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17600
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 17632 16 242 0 [(17138, 1), (2432, 158)] 0, attempt 17633 16 243 0 [(17139, 1), (2432, 158)] 0, attempt 17634 16 244 0 [(17140, 1), (2432, 158)] 0, attempt 17635 16 245 0 [(17141, 1), (2496, 158)] 0, attempt 17636 16 246 0 [(17142, 1), (2496, 158)] 0, attempt 17637 16 247 0 [(17143, 1), (2496, 158)] 0, attempt 17638 16 248 0 [(17144, 1), (2496, 158)] 0, attempt 17639 16 249 0 [(17145, 1), (2496, 158)] 0, attempt 17640 16 250 0 [(17146, 1), (2496, 158)] 0, attempt 17641 16 251 0 [(17147, 1), (2496, 158)] 0, attempt 17642 16 252 0 [(17148, 1), (2560, 158)] 0, attempt 17643 16 253 0 [(17149, 1), (2560, 158)] 0, attempt 17644 16 254 0 [(17150, 1), (2560, 158)] 0, attempt 17645 16 255 0 [(17151, 1), (2560, 158)] 0, attempt 17646 16 256 0 [(17344, 1), (2560, 158)] 0, attempt 17647 16 257 0 [(17345, 1), (2560, 158)] 0, attempt 17648 16 258 0 [(17346, 1), (2560, 158)] 0, attempt 17649 16 259 0 [(17347, 1), (2624, 158)] 0, attempt 17650 16 260 0 [(17348, 1), (2624, 158)] 0, attempt 17651 16 261 0 [(17349, 1), (2624, 158)] 0, attempt 17652 16 262 0 [(17350, 1), (2624, 158)] 0, attempt 17653 16 263 0 [(17351, 1), (2624, 158)] 0, attempt 17654 16 264 0 [(17352, 1), (2624, 158)] 0, attempt 17655 16 265 0 [(17353, 1), (2624, 158)] 0, attempt 17656 16 266 0 [(17354, 1), (2688, 158)] 0, attempt 17657 16 267 0 [(17355, 1), (2688, 158)] 0, attempt 17658 16 268 0 [(17356, 1), (2688, 158)] 0, attempt 17659 16 269 0 [(17357, 1), (2688, 158)] 0, attempt 17660 16 270 0 [(17358, 1), (2688, 158)] 0, attempt 17661 16 271 0 [(17359, 1), (2688, 158)] 0, attempt 17662 16 272 0 [(17360, 1), (2688, 158)] 0, attempt 17663 16 273 0 [(17361, 1), (2752, 158)] 0]
def counters008 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 274, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17632
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 17664 16 274 0 [(17362, 1), (2752, 158)] 0, attempt 17665 16 275 0 [(17363, 1), (2752, 158)] 0, attempt 17666 16 276 0 [(17364, 1), (2752, 158)] 0, attempt 17667 16 277 0 [(17365, 1), (2752, 158)] 0, attempt 17668 16 278 0 [(17366, 1), (2752, 158)] 0, attempt 17669 16 279 0 [(17367, 1), (2752, 158)] 0, attempt 17670 16 280 0 [(17368, 1), (2816, 158)] 0, attempt 17671 16 281 0 [(17369, 1), (2816, 158)] 0, attempt 17672 16 282 0 [(17370, 1), (2816, 158)] 0, attempt 17673 16 283 0 [(17371, 1), (2816, 158)] 0, attempt 17674 16 284 0 [(17372, 1), (2816, 158)] 0, attempt 17675 16 285 0 [(17373, 1), (2816, 158)] 0, attempt 17676 16 286 0 [(17374, 1), (2816, 158)] 0, attempt 17677 16 287 0 [(17375, 1), (2880, 158)] 0, attempt 17678 16 288 0 [(17376, 1), (2880, 158)] 0, attempt 17679 16 289 0 [(17377, 1), (2880, 158)] 0, attempt 17680 16 290 0 [(17378, 1), (2880, 158)] 0, attempt 17681 16 291 0 [(17379, 1), (2880, 158)] 0, attempt 17682 16 292 0 [(17380, 1), (2880, 158)] 0, attempt 17683 16 293 0 [(17381, 1), (2880, 158)] 0, attempt 17684 16 294 0 [(17382, 1), (2944, 158)] 0, attempt 17685 16 295 0 [(17383, 1), (2944, 158)] 0, attempt 17686 16 296 0 [(17384, 1), (2944, 158)] 0, attempt 17687 16 297 0 [(17385, 1), (2944, 158)] 0, attempt 17688 16 298 0 [(17386, 1), (2944, 158)] 0, attempt 17689 16 299 0 [(17387, 1), (2944, 158)] 0, attempt 17690 16 300 0 [(17388, 1), (2944, 158)] 0, attempt 17691 16 301 0 [(17389, 1), (3008, 158)] 0, attempt 17692 16 302 0 [(17390, 1), (3008, 158)] 0, attempt 17693 16 303 0 [(17391, 1), (3008, 158)] 0, attempt 17694 16 304 0 [(17392, 1), (3008, 158)] 0, attempt 17695 16 305 0 [(17393, 1), (3008, 158)] 0]
def counters009 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 306, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17664
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 17696 16 306 0 [(17394, 1), (3008, 158)] 0, attempt 17697 16 307 0 [(17395, 1), (3008, 158)] 0, attempt 17698 16 308 0 [(17396, 1), (3072, 158)] 0, attempt 17699 16 309 0 [(17397, 1), (3072, 158)] 0, attempt 17700 16 310 0 [(17398, 1), (3072, 158)] 0, attempt 17701 16 311 0 [(17399, 1), (3072, 158)] 0, attempt 17702 16 312 0 [(17400, 1), (3072, 158)] 0, attempt 17703 16 313 0 [(17401, 1), (3072, 158)] 0, attempt 17704 16 314 0 [(17402, 1), (3072, 158)] 0, attempt 17705 16 315 0 [(17403, 1), (3136, 158)] 0, attempt 17706 16 316 0 [(17404, 1), (3136, 158)] 0, attempt 17707 16 317 0 [(17405, 1), (3136, 158)] 0, attempt 17708 16 318 0 [(17406, 1), (3136, 158)] 0, attempt 17709 16 319 0 [(17407, 1), (3136, 158)] 0, attempt 17710 16 320 0 [(17600, 1), (3136, 158)] 0, attempt 17711 16 321 0 [(17601, 1), (3136, 158)] 0, attempt 17712 16 322 0 [(17602, 1), (3200, 158)] 0, attempt 17713 16 323 0 [(17603, 1), (3200, 158)] 0, attempt 17714 16 324 0 [(17604, 1), (3200, 158)] 0, attempt 17715 16 325 0 [(17605, 1), (3200, 158)] 0, attempt 17716 16 326 0 [(17606, 1), (3200, 158)] 0, attempt 17717 16 327 0 [(17607, 1), (3200, 158)] 0, attempt 17718 16 328 0 [(17608, 1), (3200, 158)] 0, attempt 17719 16 329 0 [(17609, 1), (3264, 158)] 0, attempt 17720 16 330 0 [(17610, 1), (3264, 158)] 0, attempt 17721 16 331 0 [(17611, 1), (3264, 158)] 0, attempt 17722 16 332 0 [(17612, 1), (3264, 158)] 0, attempt 17723 16 333 0 [(17613, 1), (3264, 158)] 0, attempt 17724 16 334 0 [(17614, 1), (3264, 158)] 0, attempt 17725 16 335 0 [(17615, 1), (3264, 158)] 0, attempt 17726 16 336 0 [(17616, 1), (3328, 158)] 0, attempt 17727 16 337 0 [(17617, 1), (3328, 158)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 338, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17696
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 17728 16 338 0 [(17618, 1), (3328, 158)] 0, attempt 17729 16 339 0 [(17619, 1), (3328, 158)] 0, attempt 17730 16 340 0 [(17620, 1), (3328, 158)] 0, attempt 17731 16 341 0 [(17621, 1), (3328, 158)] 0, attempt 17732 16 342 0 [(17622, 1), (3328, 158)] 0, attempt 17733 16 343 0 [(17623, 1), (3392, 158)] 0, attempt 17734 16 344 0 [(17624, 1), (3392, 158)] 0, attempt 17735 16 345 0 [(17625, 1), (3392, 158)] 0, attempt 17736 16 346 0 [(17626, 1), (3392, 158)] 0, attempt 17737 16 347 0 [(17627, 1), (3392, 158)] 0, attempt 17738 16 348 0 [(17628, 1), (3392, 158)] 0, attempt 17739 16 349 0 [(17629, 1), (3392, 158)] 0, attempt 17740 16 350 0 [(17630, 1), (3456, 158)] 0, attempt 17741 16 351 0 [(17631, 1), (3456, 158)] 0, attempt 17742 16 352 0 [(17632, 1), (3456, 158)] 0, attempt 17743 16 353 0 [(17633, 1), (3456, 158)] 0, attempt 17744 16 354 0 [(17634, 1), (3456, 158)] 0, attempt 17745 16 355 0 [(17635, 1), (3456, 158)] 0, attempt 17746 16 356 0 [(17636, 1), (3456, 158)] 0, attempt 17747 16 357 0 [(17637, 1), (3520, 158)] 0, attempt 17748 16 358 0 [(17638, 1), (3520, 158)] 0, attempt 17749 16 359 0 [(17639, 1), (3520, 158)] 0, attempt 17750 16 360 0 [(17640, 1), (3520, 158)] 0, attempt 17751 16 361 0 [(17641, 1), (3520, 158)] 0, attempt 17752 16 362 0 [(17642, 1), (3520, 158)] 0, attempt 17753 16 363 0 [(17643, 1), (3520, 158)] 0, attempt 17754 16 364 0 [(17644, 1), (3584, 158)] 0, attempt 17755 16 365 0 [(17645, 1), (3584, 158)] 0, attempt 17756 16 366 0 [(17646, 1), (3584, 158)] 0, attempt 17757 16 367 0 [(17647, 1), (3584, 158)] 0, attempt 17758 16 368 0 [(17648, 1), (3584, 158)] 0, attempt 17759 16 369 0 [(17649, 1), (3584, 158)] 0]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 370, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17728
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 17760 16 370 0 [(17650, 1), (3584, 158)] 0, attempt 17761 16 371 0 [(17651, 1), (3648, 158)] 0, attempt 17762 16 372 0 [(17652, 1), (3648, 158)] 0, attempt 17763 16 373 0 [(17653, 1), (3648, 158)] 0, attempt 17764 16 374 0 [(17654, 1), (3648, 158)] 0, attempt 17765 16 375 0 [(17655, 1), (3648, 158)] 0, attempt 17766 16 376 0 [(17656, 1), (3648, 158)] 0, attempt 17767 16 377 0 [(17657, 1), (3648, 158)] 0, attempt 17768 16 378 0 [(17658, 1), (3712, 158)] 0, attempt 17769 16 379 0 [(17659, 1), (3712, 158)] 0, attempt 17770 16 380 0 [(17660, 1), (3712, 158)] 0, attempt 17771 16 381 0 [(17661, 1), (3712, 158)] 0, attempt 17772 16 382 0 [(17662, 1), (3712, 158)] 0, attempt 17773 16 383 0 [(17663, 1), (3712, 158)] 0, attempt 17774 16 384 0 [(17856, 1), (3712, 158)] 0, attempt 17775 16 385 0 [(17857, 1), (3776, 158)] 0, attempt 17776 16 386 0 [(17858, 1), (3776, 158)] 0, attempt 17777 16 387 0 [(17859, 1), (3776, 158)] 0, attempt 17778 16 388 0 [(17860, 1), (3776, 158)] 0, attempt 17779 16 389 0 [(17861, 1), (3776, 158)] 0, attempt 17780 16 390 0 [(17862, 1), (3776, 158)] 0, attempt 17781 16 391 0 [(17863, 1), (3776, 158)] 0, attempt 17782 16 392 0 [(17864, 1), (3840, 158)] 0, attempt 17783 16 393 0 [(17865, 1), (3840, 158)] 0, attempt 17784 16 394 0 [(17866, 1), (3840, 158)] 0, attempt 17785 16 395 0 [(17867, 1), (3840, 158)] 0, attempt 17786 16 396 0 [(17868, 1), (3840, 158)] 0, attempt 17787 16 397 0 [(17869, 1), (3840, 158)] 0, attempt 17788 16 398 0 [(17870, 1), (3840, 158)] 0, attempt 17789 16 399 0 [(17871, 1), (3904, 158)] 0, attempt 17790 16 400 0 [(17872, 1), (3904, 158)] 0, attempt 17791 16 401 0 [(17873, 1), (3904, 158)] 0]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 402, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17760
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 17792 16 402 0 [(17874, 1), (3904, 158)] 0, attempt 17793 16 403 0 [(17875, 1), (3904, 158)] 0, attempt 17794 16 404 0 [(17876, 1), (3904, 158)] 0, attempt 17795 16 405 0 [(17877, 1), (3904, 158)] 0, attempt 17796 16 406 0 [(17878, 1), (3968, 158)] 0, attempt 17797 16 407 0 [(17879, 1), (3968, 158)] 0, attempt 17798 16 408 0 [(17880, 1), (3968, 158)] 0, attempt 17799 16 409 0 [(17881, 1), (3968, 158)] 0, attempt 17800 16 410 0 [(17882, 1), (3968, 158)] 0, attempt 17801 16 411 0 [(17883, 1), (3968, 158)] 0, attempt 17802 16 412 0 [(17884, 1), (3968, 158)] 0, attempt 17803 16 413 0 [(17885, 1), (4032, 158)] 0, attempt 17804 16 414 0 [(17886, 1), (4032, 158)] 0, attempt 17805 16 415 0 [(17887, 1), (4032, 158)] 0, attempt 17806 16 416 0 [(17888, 1), (4032, 158)] 0, attempt 17807 16 417 0 [(17889, 1), (4032, 158)] 0, attempt 17808 16 418 0 [(17890, 1), (4032, 158)] 0, attempt 17809 16 419 0 [(17891, 1), (4032, 158)] 0, attempt 17810 16 420 0 [(17892, 1), (4096, 158)] 0, attempt 17811 16 421 0 [(17893, 1), (4096, 158)] 0, attempt 17812 16 422 0 [(17894, 1), (4096, 158)] 0, attempt 17813 16 423 0 [(17895, 1), (4096, 158)] 0, attempt 17814 16 424 0 [(17896, 1), (4096, 158)] 0, attempt 17815 16 425 0 [(17897, 1), (4096, 158)] 0, attempt 17816 16 426 0 [(17898, 1), (4096, 158)] 0, attempt 17817 16 427 0 [(17899, 1), (4160, 158)] 0, attempt 17818 16 428 0 [(17900, 1), (4160, 158)] 0, attempt 17819 16 429 0 [(17901, 1), (4160, 158)] 0, attempt 17820 16 430 0 [(17902, 1), (4160, 158)] 0, attempt 17821 16 431 0 [(17903, 1), (4160, 158)] 0, attempt 17822 16 432 0 [(17904, 1), (4160, 158)] 0, attempt 17823 16 433 0 [(17905, 1), (4160, 158)] 0]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 434, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17792
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 17824 16 434 0 [(17906, 1), (4224, 158)] 0, attempt 17825 16 435 0 [(17907, 1), (4224, 158)] 0, attempt 17826 16 436 0 [(17908, 1), (4224, 158)] 0, attempt 17827 16 437 0 [(17909, 1), (4224, 158)] 0, attempt 17828 16 438 0 [(17910, 1), (4224, 158)] 0, attempt 17829 16 439 0 [(17911, 1), (4224, 158)] 0, attempt 17830 16 440 0 [(17912, 1), (4224, 158)] 0, attempt 17831 16 441 0 [(17913, 1), (4288, 158)] 0, attempt 17832 16 442 0 [(17914, 1), (4288, 158)] 0, attempt 17833 16 443 0 [(17915, 1), (4288, 158)] 0, attempt 17834 16 444 0 [(17916, 1), (4288, 158)] 0, attempt 17835 16 445 0 [(17917, 1), (4288, 158)] 0, attempt 17836 16 446 0 [(17918, 1), (4288, 158)] 0, attempt 17837 16 447 0 [(17919, 1), (4288, 158)] 0, attempt 17838 17 0 1 [(16256, 124)] 0, attempt 17839 17 1 1 [(16257, 124)] 0, attempt 17840 17 2 1 [(16258, 124)] 0, attempt 17841 17 3 1 [(16259, 124)] 0, attempt 17842 17 4 1 [(16260, 124)] 0, attempt 17843 17 5 1 [(16261, 124)] 0, attempt 17844 17 6 1 [(16262, 124)] 0, attempt 17845 17 7 1 [(16263, 124)] 0, attempt 17846 17 8 1 [(16264, 124)] 0, attempt 17847 17 9 1 [(16265, 124)] 0, attempt 17848 17 10 1 [(16266, 124)] 0, attempt 17849 17 11 1 [(16267, 124)] 0, attempt 17850 17 12 1 [(16268, 124)] 0, attempt 17851 17 13 1 [(16269, 124)] 0, attempt 17852 17 14 1 [(16270, 124)] 0, attempt 17853 17 15 1 [(16271, 124)] 0, attempt 17854 17 16 1 [(16272, 124)] 0, attempt 17855 17 17 1 [(16273, 124)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17824
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 17856 17 18 1 [(16274, 124)] 0, attempt 17857 17 19 1 [(16275, 124)] 0, attempt 17858 17 20 1 [(16276, 124)] 0, attempt 17859 17 21 1 [(16277, 124)] 0, attempt 17860 17 22 1 [(16278, 124)] 0, attempt 17861 17 23 1 [(16279, 124)] 0, attempt 17862 17 24 1 [(16280, 124)] 0, attempt 17863 17 25 1 [(16281, 124)] 0, attempt 17864 17 26 1 [(16282, 124)] 0, attempt 17865 17 27 1 [(16283, 124)] 0, attempt 17866 17 28 1 [(16284, 124)] 0, attempt 17867 17 29 1 [(16285, 124)] 0, attempt 17868 17 30 1 [(16286, 124)] 0, attempt 17869 17 31 1 [(16287, 124)] 0, attempt 17870 17 32 1 [(16288, 124)] 0, attempt 17871 17 33 1 [(16289, 124)] 0, attempt 17872 17 34 1 [(16290, 124)] 0, attempt 17873 17 35 1 [(16291, 124)] 0, attempt 17874 17 36 1 [(16292, 124)] 0, attempt 17875 17 37 1 [(16293, 124)] 0, attempt 17876 17 38 1 [(16294, 124)] 0, attempt 17877 17 39 1 [(16295, 124)] 0, attempt 17878 17 40 1 [(16296, 124)] 0, attempt 17879 17 41 1 [(16297, 124)] 0, attempt 17880 17 42 1 [(16298, 124)] 0, attempt 17881 17 43 1 [(16299, 124)] 0, attempt 17882 17 44 1 [(16300, 124)] 0, attempt 17883 17 45 1 [(16301, 124)] 0, attempt 17884 17 46 1 [(16302, 124)] 0, attempt 17885 17 47 1 [(16303, 124)] 0, attempt 17886 17 48 1 [(16304, 124)] 0, attempt 17887 17 49 1 [(16305, 124)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17856
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 17888 17 50 1 [(16306, 124)] 0, attempt 17889 17 51 1 [(16307, 124)] 0, attempt 17890 17 52 1 [(16308, 124)] 0, attempt 17891 17 53 1 [(16309, 124)] 0, attempt 17892 17 54 1 [(16310, 124)] 0, attempt 17893 17 55 1 [(16311, 124)] 0, attempt 17894 17 56 1 [(16312, 124)] 0, attempt 17895 17 57 1 [(16313, 124)] 0, attempt 17896 17 58 1 [(16314, 124)] 0, attempt 17897 17 59 1 [(16315, 124)] 0, attempt 17898 17 60 1 [(16316, 124)] 0, attempt 17899 17 61 1 [(16317, 124)] 0, attempt 17900 17 62 1 [(16318, 124)] 0, attempt 17901 17 63 1 [(16319, 124)] 0, attempt 17902 17 64 1 [(16512, 124)] 0, attempt 17903 17 65 1 [(16513, 124)] 0, attempt 17904 17 66 1 [(16514, 124)] 0, attempt 17905 17 67 1 [(16515, 124)] 0, attempt 17906 17 68 1 [(16516, 124)] 0, attempt 17907 17 69 1 [(16517, 124)] 0, attempt 17908 17 70 1 [(16518, 124)] 0, attempt 17909 17 71 1 [(16519, 124)] 0, attempt 17910 17 72 1 [(16520, 124)] 0, attempt 17911 17 73 1 [(16521, 124)] 0, attempt 17912 17 74 1 [(16522, 124)] 0, attempt 17913 17 75 1 [(16523, 124)] 0, attempt 17914 17 76 1 [(16524, 124)] 0, attempt 17915 17 77 1 [(16525, 124)] 0, attempt 17916 17 78 1 [(16526, 124)] 0, attempt 17917 17 79 1 [(16527, 124)] 0, attempt 17918 17 80 1 [(16528, 124)] 0, attempt 17919 17 81 1 [(16529, 124)] 0]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17888
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17920
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17888
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 17888 17920 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 17888) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17856
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 17856 17888 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 17856) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17824
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 17824 17856 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 17824) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17792
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 17792 17824 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 17792) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17760
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 17760 17792 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 17760) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17728
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 17728 17760 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 17728) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17696
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 17696 17728 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 17696) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17664
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 17664 17696 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 17664) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17632
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 17632 17664 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 17632) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17600
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 17600 17632 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 17600) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17568
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 17568 17600 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 17568) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17536
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 17536 17568 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 17536) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17504
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 17504 17536 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 17504) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17472
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 17472 17504 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 17472) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17440
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 17440 17472 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 17440) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17408
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 17408 17440 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 17408) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr34
