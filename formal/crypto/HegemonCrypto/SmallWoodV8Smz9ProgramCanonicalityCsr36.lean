import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr35

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr36
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 18432 22 14 1 [(30154, 126), (40777, 288)] 0, attempt 18433 22 15 1 [(30218, 126), (40841, 288)] 0, attempt 18434 22 16 1 [(29771, 126), (40394, 288)] 0, attempt 18435 22 17 1 [(29835, 126), (40458, 288)] 0, attempt 18436 22 18 1 [(29772, 127)] 0, attempt 18437 22 19 1 [(29836, 127)] 0, attempt 18438 22 20 1 [(29900, 127)] 0, attempt 18439 22 21 1 [(29964, 127)] 0, attempt 18440 22 22 1 [(30028, 127)] 0, attempt 18441 22 23 1 [(30092, 127)] 0, attempt 18442 22 24 1 [(30156, 127)] 0, attempt 18443 22 25 1 [(30220, 127)] 0, attempt 18444 22 26 1 [(29773, 127), (40396, 296)] 0, attempt 18445 22 27 1 [(29837, 127), (40460, 296)] 0, attempt 18446 22 28 1 [(29901, 127), (40524, 296)] 0, attempt 18447 22 29 1 [(29965, 127), (40588, 296)] 0, attempt 18448 22 30 1 [(30029, 127), (40652, 296)] 0, attempt 18449 22 31 1 [(30093, 127), (40716, 296)] 0, attempt 18450 22 32 1 [(30157, 127), (40780, 296)] 0, attempt 18451 22 33 1 [(30221, 127), (40844, 296)] 0, attempt 18452 22 34 1 [(29774, 127), (40397, 296)] 0, attempt 18453 22 35 1 [(29838, 127), (40461, 296)] 0, attempt 18454 23 0 1 [(40395, 6)] 289, attempt 18455 23 1 1 [(40459, 6)] 290, attempt 18456 23 2 1 [(40523, 6)] 291, attempt 18457 23 3 1 [(40587, 6)] 292, attempt 18458 23 4 1 [(40651, 6)] 293, attempt 18459 23 5 1 [(40715, 6)] 294, attempt 18460 23 6 1 [(40779, 6)] 295, attempt 18461 23 7 1 [(40398, 7)] 297, attempt 18462 23 8 1 [(40462, 7)] 298, attempt 18463 23 9 1 [(40526, 7)] 299]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18432
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 18464 23 10 1 [(40590, 7)] 300, attempt 18465 23 11 1 [(40654, 7)] 301, attempt 18466 23 12 1 [(40718, 7)] 302, attempt 18467 23 13 1 [(40782, 7)] 303, attempt 18468 24 0 0 [(29775, 1)] 4, attempt 18469 24 1 0 [(29839, 1)] 5, attempt 18470 24 2 0 [(29903, 1)] 6, attempt 18471 24 3 0 [(29967, 1)] 7, attempt 18472 24 4 0 [(30031, 1)] 0, attempt 18473 24 5 0 [(30095, 1)] 0, attempt 18474 24 6 0 [(30159, 1)] 0, attempt 18475 24 7 0 [(30223, 1)] 0, attempt 18476 24 8 0 [(30287, 1)] 546, attempt 18477 24 9 0 [(30351, 1)] 547, attempt 18478 24 10 0 [(30415, 1)] 543, attempt 18479 24 11 0 [(30479, 1)] 0, attempt 18480 24 12 0 [(30543, 1)] 0, attempt 18481 24 13 0 [(30607, 1)] 0, attempt 18482 24 14 0 [(30671, 1)] 0, attempt 18483 24 15 0 [(30735, 1)] 544, attempt 18484 24 16 0 [(29776, 1), (40399, 158)] 0, attempt 18485 24 17 0 [(29840, 1), (40463, 158)] 0, attempt 18486 24 18 0 [(29904, 1), (40527, 158)] 0, attempt 18487 24 19 0 [(29968, 1), (40591, 158)] 0, attempt 18488 24 20 0 [(30032, 1), (40655, 158)] 0, attempt 18489 24 21 0 [(30096, 1), (40719, 158)] 0, attempt 18490 24 22 0 [(30160, 1), (40783, 158)] 0, attempt 18491 24 23 0 [(30224, 1), (40847, 158)] 0, attempt 18492 24 24 0 [(30288, 1), (40911, 158)] 0, attempt 18493 24 25 0 [(30352, 1), (40975, 158)] 0, attempt 18494 24 26 0 [(30416, 1), (41039, 158)] 0, attempt 18495 24 27 0 [(30480, 1), (41103, 158)] 0]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18464
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 18496 24 28 0 [(30544, 1), (41167, 158)] 0, attempt 18497 24 29 0 [(30608, 1), (41231, 158)] 0, attempt 18498 24 30 0 [(30672, 1), (41295, 158)] 0, attempt 18499 24 31 0 [(30736, 1), (41359, 158)] 0, attempt 18500 24 32 0 [(29777, 1), (40400, 158)] 0, attempt 18501 24 33 0 [(29841, 1), (40464, 158)] 0, attempt 18502 24 34 0 [(29905, 1), (40528, 158)] 22, attempt 18503 24 35 0 [(29969, 1), (40592, 158)] 23, attempt 18504 24 36 0 [(30033, 1), (40656, 158)] 24, attempt 18505 24 37 0 [(30097, 1), (40720, 158)] 25, attempt 18506 24 38 0 [(30161, 1), (40784, 158)] 26, attempt 18507 24 39 0 [(30225, 1), (40848, 158)] 27, attempt 18508 24 40 0 [(30289, 1), (40912, 158)] 0, attempt 18509 24 41 0 [(30353, 1), (40976, 158)] 0, attempt 18510 24 42 0 [(30417, 1), (41040, 158)] 0, attempt 18511 24 43 0 [(30481, 1), (41104, 158)] 0, attempt 18512 24 44 0 [(30545, 1), (41168, 158)] 0, attempt 18513 24 45 0 [(30609, 1), (41232, 158)] 0, attempt 18514 24 46 0 [(30673, 1), (41296, 158)] 0, attempt 18515 24 47 0 [(30737, 1), (41360, 158)] 0, attempt 18516 24 48 0 [(29778, 1), (40401, 158)] 28, attempt 18517 24 49 0 [(29842, 1), (40465, 158)] 29, attempt 18518 24 50 0 [(29906, 1), (40529, 158)] 30, attempt 18519 24 51 0 [(29970, 1), (40593, 158)] 31, attempt 18520 24 52 0 [(30034, 1), (40657, 158)] 32, attempt 18521 24 53 0 [(30098, 1), (40721, 158)] 33, attempt 18522 24 54 0 [(30162, 1), (40785, 158)] 34, attempt 18523 24 55 0 [(30226, 1), (40849, 158)] 35, attempt 18524 24 56 0 [(30290, 1), (40913, 158)] 0, attempt 18525 24 57 0 [(30354, 1), (40977, 158)] 0, attempt 18526 24 58 0 [(30418, 1), (41041, 158)] 0, attempt 18527 24 59 0 [(30482, 1), (41105, 158)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18496
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 18528 24 60 0 [(30546, 1), (41169, 158)] 0, attempt 18529 24 61 0 [(30610, 1), (41233, 158)] 0, attempt 18530 24 62 0 [(30674, 1), (41297, 158)] 0, attempt 18531 24 63 0 [(30738, 1), (41361, 158)] 0, attempt 18532 24 64 0 [(29779, 1), (40402, 158)] 36, attempt 18533 24 65 0 [(29843, 1), (40466, 158)] 37, attempt 18534 24 66 0 [(29907, 1), (40530, 158)] 38, attempt 18535 24 67 0 [(29971, 1), (40594, 158)] 39, attempt 18536 24 68 0 [(30035, 1), (40658, 158)] 40, attempt 18537 24 69 0 [(30099, 1), (40722, 158)] 41, attempt 18538 24 70 0 [(30163, 1), (40786, 158)] 42, attempt 18539 24 71 0 [(30227, 1), (40850, 158)] 43, attempt 18540 24 72 0 [(30291, 1), (40914, 158)] 0, attempt 18541 24 73 0 [(30355, 1), (40978, 158)] 0, attempt 18542 24 74 0 [(30419, 1), (41042, 158)] 0, attempt 18543 24 75 0 [(30483, 1), (41106, 158)] 0, attempt 18544 24 76 0 [(30547, 1), (41170, 158)] 0, attempt 18545 24 77 0 [(30611, 1), (41234, 158)] 0, attempt 18546 24 78 0 [(30675, 1), (41298, 158)] 0, attempt 18547 24 79 0 [(30739, 1), (41362, 158)] 0, attempt 18548 24 80 0 [(29780, 1), (40403, 158)] 44, attempt 18549 24 81 0 [(29844, 1), (40467, 158)] 45, attempt 18550 24 82 0 [(29908, 1), (40531, 158)] 46, attempt 18551 24 83 0 [(29972, 1), (40595, 158)] 47, attempt 18552 24 84 0 [(30036, 1), (40659, 158)] 48, attempt 18553 24 85 0 [(30100, 1), (40723, 158)] 49, attempt 18554 24 86 0 [(30164, 1), (40787, 158)] 50, attempt 18555 24 87 0 [(30228, 1), (40851, 158)] 0, attempt 18556 24 88 0 [(30292, 1), (40915, 158)] 0, attempt 18557 24 89 0 [(30356, 1), (40979, 158)] 0, attempt 18558 24 90 0 [(30420, 1), (41043, 158)] 0, attempt 18559 24 91 0 [(30484, 1), (41107, 158)] 0]
def counters004 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18528
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 18560 24 92 0 [(30548, 1), (41171, 158)] 0, attempt 18561 24 93 0 [(30612, 1), (41235, 158)] 0, attempt 18562 24 94 0 [(30676, 1), (41299, 158)] 0, attempt 18563 24 95 0 [(30740, 1), (41363, 158)] 0, attempt 18564 24 96 0 [(29781, 1), (40404, 158)] 0, attempt 18565 24 97 0 [(29845, 1), (40468, 158)] 0, attempt 18566 24 98 0 [(29909, 1), (40532, 158)] 0, attempt 18567 24 99 0 [(29973, 1), (40596, 158)] 0, attempt 18568 24 100 0 [(30037, 1), (40660, 158)] 0, attempt 18569 24 101 0 [(30101, 1), (40724, 158)] 0, attempt 18570 24 102 0 [(30165, 1), (40788, 158)] 58, attempt 18571 24 103 0 [(30229, 1), (40852, 158)] 59, attempt 18572 24 104 0 [(30293, 1), (40916, 158)] 0, attempt 18573 24 105 0 [(30357, 1), (40980, 158)] 0, attempt 18574 24 106 0 [(30421, 1), (41044, 158)] 0, attempt 18575 24 107 0 [(30485, 1), (41108, 158)] 0, attempt 18576 24 108 0 [(30549, 1), (41172, 158)] 0, attempt 18577 24 109 0 [(30613, 1), (41236, 158)] 0, attempt 18578 24 110 0 [(30677, 1), (41300, 158)] 0, attempt 18579 24 111 0 [(30741, 1), (41364, 158)] 0, attempt 18580 24 112 0 [(29782, 1), (40405, 158)] 60, attempt 18581 24 113 0 [(29846, 1), (40469, 158)] 61, attempt 18582 24 114 0 [(29910, 1), (40533, 158)] 62, attempt 18583 24 115 0 [(29974, 1), (40597, 158)] 63, attempt 18584 24 116 0 [(30038, 1), (40661, 158)] 64, attempt 18585 24 117 0 [(30102, 1), (40725, 158)] 65, attempt 18586 24 118 0 [(30166, 1), (40789, 158)] 66, attempt 18587 24 119 0 [(30230, 1), (40853, 158)] 67, attempt 18588 24 120 0 [(30294, 1), (40917, 158)] 0, attempt 18589 24 121 0 [(30358, 1), (40981, 158)] 0, attempt 18590 24 122 0 [(30422, 1), (41045, 158)] 0, attempt 18591 24 123 0 [(30486, 1), (41109, 158)] 0]
def counters005 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18560
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 18592 24 124 0 [(30550, 1), (41173, 158)] 0, attempt 18593 24 125 0 [(30614, 1), (41237, 158)] 0, attempt 18594 24 126 0 [(30678, 1), (41301, 158)] 0, attempt 18595 24 127 0 [(30742, 1), (41365, 158)] 0, attempt 18596 24 128 0 [(29783, 1), (40406, 158)] 68, attempt 18597 24 129 0 [(29847, 1), (40470, 158)] 69, attempt 18598 24 130 0 [(29911, 1), (40534, 158)] 70, attempt 18599 24 131 0 [(29975, 1), (40598, 158)] 71, attempt 18600 24 132 0 [(30039, 1), (40662, 158)] 72, attempt 18601 24 133 0 [(30103, 1), (40726, 158)] 73, attempt 18602 24 134 0 [(30167, 1), (40790, 158)] 74, attempt 18603 24 135 0 [(30231, 1), (40854, 158)] 75, attempt 18604 24 136 0 [(30295, 1), (40918, 158)] 0, attempt 18605 24 137 0 [(30359, 1), (40982, 158)] 0, attempt 18606 24 138 0 [(30423, 1), (41046, 158)] 0, attempt 18607 24 139 0 [(30487, 1), (41110, 158)] 0, attempt 18608 24 140 0 [(30551, 1), (41174, 158)] 0, attempt 18609 24 141 0 [(30615, 1), (41238, 158)] 0, attempt 18610 24 142 0 [(30679, 1), (41302, 158)] 0, attempt 18611 24 143 0 [(30743, 1), (41366, 158)] 0, attempt 18612 24 144 0 [(29784, 1), (40407, 158)] 76, attempt 18613 24 145 0 [(29848, 1), (40471, 158)] 77, attempt 18614 24 146 0 [(29912, 1), (40535, 158)] 78, attempt 18615 24 147 0 [(29976, 1), (40599, 158)] 79, attempt 18616 24 148 0 [(30040, 1), (40663, 158)] 80, attempt 18617 24 149 0 [(30104, 1), (40727, 158)] 81, attempt 18618 24 150 0 [(30168, 1), (40791, 158)] 82, attempt 18619 24 151 0 [(30232, 1), (40855, 158)] 83, attempt 18620 24 152 0 [(30296, 1), (40919, 158)] 0, attempt 18621 24 153 0 [(30360, 1), (40983, 158)] 0, attempt 18622 24 154 0 [(30424, 1), (41047, 158)] 0, attempt 18623 24 155 0 [(30488, 1), (41111, 158)] 0]
def counters006 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18592
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 18624 24 156 0 [(30552, 1), (41175, 158)] 0, attempt 18625 24 157 0 [(30616, 1), (41239, 158)] 0, attempt 18626 24 158 0 [(30680, 1), (41303, 158)] 0, attempt 18627 24 159 0 [(30744, 1), (41367, 158)] 0, attempt 18628 24 160 0 [(29785, 1), (40408, 158)] 84, attempt 18629 24 161 0 [(29849, 1), (40472, 158)] 85, attempt 18630 24 162 0 [(29913, 1), (40536, 158)] 86, attempt 18631 24 163 0 [(29977, 1), (40600, 158)] 87, attempt 18632 24 164 0 [(30041, 1), (40664, 158)] 88, attempt 18633 24 165 0 [(30105, 1), (40728, 158)] 89, attempt 18634 24 166 0 [(30169, 1), (40792, 158)] 90, attempt 18635 24 167 0 [(30233, 1), (40856, 158)] 0, attempt 18636 24 168 0 [(30297, 1), (40920, 158)] 0, attempt 18637 24 169 0 [(30361, 1), (40984, 158)] 0, attempt 18638 24 170 0 [(30425, 1), (41048, 158)] 0, attempt 18639 24 171 0 [(30489, 1), (41112, 158)] 0, attempt 18640 24 172 0 [(30553, 1), (41176, 158)] 0, attempt 18641 24 173 0 [(30617, 1), (41240, 158)] 0, attempt 18642 24 174 0 [(30681, 1), (41304, 158)] 0, attempt 18643 24 175 0 [(30745, 1), (41368, 158)] 0, attempt 18644 24 176 0 [(29786, 1), (40409, 158)] 0, attempt 18645 24 177 0 [(29850, 1), (40473, 158)] 0, attempt 18646 24 178 0 [(29914, 1), (40537, 158)] 0, attempt 18647 24 179 0 [(29978, 1), (40601, 158)] 0, attempt 18648 24 180 0 [(30042, 1), (40665, 158)] 0, attempt 18649 24 181 0 [(30106, 1), (40729, 158)] 0, attempt 18650 24 182 0 [(30170, 1), (40793, 158)] 98, attempt 18651 24 183 0 [(30234, 1), (40857, 158)] 99, attempt 18652 24 184 0 [(30298, 1), (40921, 158)] 0, attempt 18653 24 185 0 [(30362, 1), (40985, 158)] 0, attempt 18654 24 186 0 [(30426, 1), (41049, 158)] 0, attempt 18655 24 187 0 [(30490, 1), (41113, 158)] 0]
def counters007 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18624
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 18656 24 188 0 [(30554, 1), (41177, 158)] 0, attempt 18657 24 189 0 [(30618, 1), (41241, 158)] 0, attempt 18658 24 190 0 [(30682, 1), (41305, 158)] 0, attempt 18659 24 191 0 [(30746, 1), (41369, 158)] 0, attempt 18660 24 192 0 [(29787, 1), (40410, 158)] 100, attempt 18661 24 193 0 [(29851, 1), (40474, 158)] 101, attempt 18662 24 194 0 [(29915, 1), (40538, 158)] 102, attempt 18663 24 195 0 [(29979, 1), (40602, 158)] 103, attempt 18664 24 196 0 [(30043, 1), (40666, 158)] 104, attempt 18665 24 197 0 [(30107, 1), (40730, 158)] 105, attempt 18666 24 198 0 [(30171, 1), (40794, 158)] 106, attempt 18667 24 199 0 [(30235, 1), (40858, 158)] 107, attempt 18668 24 200 0 [(30299, 1), (40922, 158)] 0, attempt 18669 24 201 0 [(30363, 1), (40986, 158)] 0, attempt 18670 24 202 0 [(30427, 1), (41050, 158)] 0, attempt 18671 24 203 0 [(30491, 1), (41114, 158)] 0, attempt 18672 24 204 0 [(30555, 1), (41178, 158)] 0, attempt 18673 24 205 0 [(30619, 1), (41242, 158)] 0, attempt 18674 24 206 0 [(30683, 1), (41306, 158)] 0, attempt 18675 24 207 0 [(30747, 1), (41370, 158)] 0, attempt 18676 24 208 0 [(29788, 1), (40411, 158)] 108, attempt 18677 24 209 0 [(29852, 1), (40475, 158)] 109, attempt 18678 24 210 0 [(29916, 1), (40539, 158)] 110, attempt 18679 24 211 0 [(29980, 1), (40603, 158)] 111, attempt 18680 24 212 0 [(30044, 1), (40667, 158)] 112, attempt 18681 24 213 0 [(30108, 1), (40731, 158)] 113, attempt 18682 24 214 0 [(30172, 1), (40795, 158)] 114, attempt 18683 24 215 0 [(30236, 1), (40859, 158)] 115, attempt 18684 24 216 0 [(30300, 1), (40923, 158)] 0, attempt 18685 24 217 0 [(30364, 1), (40987, 158)] 0, attempt 18686 24 218 0 [(30428, 1), (41051, 158)] 0, attempt 18687 24 219 0 [(30492, 1), (41115, 158)] 0]
def counters008 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18656
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 18688 24 220 0 [(30556, 1), (41179, 158)] 0, attempt 18689 24 221 0 [(30620, 1), (41243, 158)] 0, attempt 18690 24 222 0 [(30684, 1), (41307, 158)] 0, attempt 18691 24 223 0 [(30748, 1), (41371, 158)] 0, attempt 18692 24 224 0 [(29789, 1), (40412, 158)] 116, attempt 18693 24 225 0 [(29853, 1), (40476, 158)] 0, attempt 18694 24 226 0 [(29917, 1), (40540, 158)] 0, attempt 18695 24 227 0 [(29981, 1), (40604, 158)] 0, attempt 18696 24 228 0 [(30045, 1), (40668, 158)] 0, attempt 18697 24 229 0 [(30109, 1), (40732, 158)] 0, attempt 18698 24 230 0 [(30173, 1), (40796, 158)] 0, attempt 18699 24 231 0 [(30237, 1), (40860, 158)] 0, attempt 18700 24 232 0 [(30301, 1), (40924, 158)] 0, attempt 18701 24 233 0 [(30365, 1), (40988, 158)] 0, attempt 18702 24 234 0 [(30429, 1), (41052, 158)] 0, attempt 18703 24 235 0 [(30493, 1), (41116, 158)] 1, attempt 18704 24 236 0 [(30557, 1), (41180, 158)] 0, attempt 18705 24 237 0 [(30621, 1), (41244, 158)] 0, attempt 18706 24 238 0 [(30685, 1), (41308, 158)] 0, attempt 18707 24 239 0 [(30749, 1), (41372, 158)] 0, attempt 18708 25 0 0 [(8384, 1), (40413, 3)] 0, attempt 18709 25 1 0 [(8448, 1), (40477, 3)] 0, attempt 18710 25 2 0 [(8512, 1), (40541, 3)] 0, attempt 18711 25 3 0 [(8576, 1), (40605, 3)] 0, attempt 18712 25 4 0 [(8640, 1), (40669, 3)] 0, attempt 18713 25 5 0 [(8704, 1), (40733, 3)] 0, attempt 18714 25 6 0 [(8768, 1), (40797, 3)] 0, attempt 18715 26 0 0 [(29790, 1), (9728, 158)] 0, attempt 18716 26 1 0 [(29854, 1), (9792, 158)] 0, attempt 18717 26 2 0 [(29918, 1), (12544, 158)] 0, attempt 18718 26 3 0 [(29982, 1), (12608, 158)] 0, attempt 18719 26 4 0 [(30046, 1), (12672, 158)] 0]
def counters009 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18688
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 18720 26 5 0 [(30110, 1), (12736, 158)] 0, attempt 18721 26 6 0 [(30174, 1), (12800, 158)] 0, attempt 18722 26 7 0 [(30238, 1), (12864, 158)] 0, attempt 18723 26 8 0 [(30302, 1)] 548, attempt 18724 26 9 0 [(30366, 1)] 211, attempt 18725 26 10 0 [(30430, 1)] 543, attempt 18726 26 11 0 [(30494, 1)] 0, attempt 18727 26 12 0 [(30558, 1)] 0, attempt 18728 26 13 0 [(30622, 1)] 0, attempt 18729 26 14 0 [(30686, 1)] 0, attempt 18730 26 15 0 [(30750, 1)] 544, attempt 18731 26 16 0 [(29791, 1), (40414, 158), (12928, 158)] 0, attempt 18732 26 17 0 [(29855, 1), (40478, 158), (12992, 158)] 0, attempt 18733 26 18 0 [(29919, 1), (40542, 158), (13056, 158)] 0, attempt 18734 26 19 0 [(29983, 1), (40606, 158), (13120, 158)] 0, attempt 18735 26 20 0 [(30047, 1), (40670, 158), (13184, 158)] 0, attempt 18736 26 21 0 [(30111, 1), (40734, 158), (13248, 158)] 0, attempt 18737 26 22 0 [(30175, 1), (40798, 158), (13312, 158)] 0, attempt 18738 26 23 0 [(30239, 1), (40862, 158), (13376, 158)] 0, attempt 18739 26 24 0 [(30303, 1), (40926, 158)] 0, attempt 18740 26 25 0 [(30367, 1), (40990, 158)] 0, attempt 18741 26 26 0 [(30431, 1), (41054, 158)] 0, attempt 18742 26 27 0 [(30495, 1), (41118, 158)] 0, attempt 18743 26 28 0 [(30559, 1), (41182, 158)] 0, attempt 18744 26 29 0 [(30623, 1), (41246, 158)] 0, attempt 18745 26 30 0 [(30687, 1), (41310, 158)] 0, attempt 18746 26 31 0 [(30751, 1), (41374, 158)] 0, attempt 18747 26 32 0 [(29792, 1), (40415, 158), (13440, 158)] 0, attempt 18748 26 33 0 [(29856, 1), (40479, 158), (13504, 158)] 0, attempt 18749 26 34 0 [(29920, 1), (40543, 158), (13568, 158)] 0, attempt 18750 26 35 0 [(29984, 1), (40607, 158), (13632, 158)] 0, attempt 18751 26 36 0 [(30048, 1), (40671, 158), (13696, 158)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18720
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 18752 26 37 0 [(30112, 1), (40735, 158), (13760, 158)] 0, attempt 18753 26 38 0 [(30176, 1), (40799, 158), (13824, 158)] 0, attempt 18754 26 39 0 [(30240, 1), (40863, 158), (13888, 158)] 0, attempt 18755 26 40 0 [(30304, 1), (40927, 158)] 0, attempt 18756 26 41 0 [(30368, 1), (40991, 158)] 0, attempt 18757 26 42 0 [(30432, 1), (41055, 158)] 0, attempt 18758 26 43 0 [(30496, 1), (41119, 158)] 0, attempt 18759 26 44 0 [(30560, 1), (41183, 158)] 0, attempt 18760 26 45 0 [(30624, 1), (41247, 158)] 0, attempt 18761 26 46 0 [(30688, 1), (41311, 158)] 0, attempt 18762 26 47 0 [(30752, 1), (41375, 158)] 0, attempt 18763 26 48 0 [(29793, 1), (40416, 158), (13952, 158)] 0, attempt 18764 26 49 0 [(29857, 1), (40480, 158), (14016, 158)] 0, attempt 18765 26 50 0 [(29921, 1), (40544, 158), (14080, 158)] 0, attempt 18766 26 51 0 [(29985, 1), (40608, 158), (14144, 158)] 0, attempt 18767 26 52 0 [(30049, 1), (40672, 158), (14208, 158)] 0, attempt 18768 26 53 0 [(30113, 1), (40736, 158), (14272, 158)] 0, attempt 18769 26 54 0 [(30177, 1), (40800, 158), (14336, 158)] 0, attempt 18770 26 55 0 [(30241, 1), (40864, 158), (14400, 158)] 0, attempt 18771 26 56 0 [(30305, 1), (40928, 158)] 0, attempt 18772 26 57 0 [(30369, 1), (40992, 158)] 0, attempt 18773 26 58 0 [(30433, 1), (41056, 158)] 0, attempt 18774 26 59 0 [(30497, 1), (41120, 158)] 1, attempt 18775 26 60 0 [(30561, 1), (41184, 158)] 0, attempt 18776 26 61 0 [(30625, 1), (41248, 158)] 0, attempt 18777 26 62 0 [(30689, 1), (41312, 158)] 0, attempt 18778 26 63 0 [(30753, 1), (41376, 158)] 0, attempt 18779 27 0 0 [(17920, 1), (8832, 158)] 0, attempt 18780 27 1 0 [(17984, 1), (40417, 158)] 0, attempt 18781 27 2 0 [(18048, 1), (5952, 158), (6016, 158)] 0, attempt 18782 27 3 0 [(17921, 1), (8896, 158)] 0, attempt 18783 27 4 0 [(17985, 1), (40481, 158)] 0]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18752
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 18784 27 5 0 [(18049, 1), (5952, 158), (6016, 158)] 0, attempt 18785 27 6 0 [(17922, 1), (8960, 158)] 0, attempt 18786 27 7 0 [(17986, 1), (40545, 158)] 0, attempt 18787 27 8 0 [(18050, 1), (5952, 158), (6016, 158)] 0, attempt 18788 27 9 0 [(17923, 1), (9024, 158)] 0, attempt 18789 27 10 0 [(17987, 1), (40609, 158)] 0, attempt 18790 27 11 0 [(18051, 1), (5952, 158), (6016, 158)] 0, attempt 18791 27 12 0 [(17924, 1), (9088, 158)] 0, attempt 18792 27 13 0 [(17988, 1), (40673, 158)] 0, attempt 18793 27 14 0 [(18052, 1), (5952, 158), (6016, 158)] 0, attempt 18794 27 15 0 [(17925, 1), (9152, 158)] 0, attempt 18795 27 16 0 [(17989, 1), (40737, 158)] 0, attempt 18796 27 17 0 [(18053, 1), (5952, 158), (6016, 158)] 0, attempt 18797 27 18 0 [(17926, 1), (9216, 158)] 0, attempt 18798 27 19 0 [(17990, 1), (40801, 158)] 0, attempt 18799 27 20 0 [(18054, 1), (5952, 158), (6016, 158)] 0, attempt 18800 28 0 0 [(17927, 1)] 0, attempt 18801 28 1 0 [(17928, 1)] 0, attempt 18802 28 2 0 [(17929, 1)] 0, attempt 18803 28 3 0 [(17930, 1)] 0, attempt 18804 28 4 0 [(17931, 1)] 0, attempt 18805 28 5 0 [(17932, 1)] 0, attempt 18806 28 6 0 [(17933, 1)] 0, attempt 18807 28 7 0 [(17934, 1)] 0, attempt 18808 28 8 0 [(17935, 1)] 0, attempt 18809 28 9 0 [(17936, 1)] 0, attempt 18810 28 10 0 [(17937, 1)] 0, attempt 18811 28 11 0 [(17938, 1)] 0, attempt 18812 28 12 0 [(17939, 1)] 0, attempt 18813 28 13 0 [(17940, 1)] 0, attempt 18814 28 14 0 [(17941, 1)] 0, attempt 18815 28 15 0 [(17942, 1)] 0]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18784
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 18816 28 16 0 [(17943, 1)] 0, attempt 18817 28 17 0 [(17944, 1)] 0, attempt 18818 28 18 0 [(17945, 1)] 0, attempt 18819 28 19 0 [(17946, 1)] 0, attempt 18820 28 20 0 [(17947, 1)] 0, attempt 18821 28 21 0 [(17948, 1)] 0, attempt 18822 28 22 0 [(17949, 1)] 0, attempt 18823 28 23 0 [(17950, 1)] 0, attempt 18824 28 24 0 [(17951, 1)] 0, attempt 18825 28 25 0 [(17952, 1)] 0, attempt 18826 28 26 0 [(17953, 1)] 0, attempt 18827 28 27 0 [(17954, 1)] 0, attempt 18828 28 28 0 [(17955, 1)] 0, attempt 18829 28 29 0 [(17956, 1)] 0, attempt 18830 28 30 0 [(17957, 1)] 0, attempt 18831 28 31 0 [(17958, 1)] 0, attempt 18832 28 32 0 [(17959, 1)] 0, attempt 18833 28 33 0 [(17960, 1)] 0, attempt 18834 28 34 0 [(17961, 1)] 0, attempt 18835 28 35 0 [(17962, 1)] 0, attempt 18836 28 36 0 [(17963, 1)] 0, attempt 18837 28 37 0 [(17964, 1)] 0, attempt 18838 28 38 0 [(17965, 1)] 0, attempt 18839 28 39 0 [(17966, 1)] 0, attempt 18840 28 40 0 [(17967, 1)] 0, attempt 18841 28 41 0 [(17968, 1)] 0, attempt 18842 28 42 0 [(17969, 1)] 0, attempt 18843 28 43 0 [(17970, 1)] 0, attempt 18844 28 44 0 [(17971, 1)] 0, attempt 18845 28 45 0 [(17972, 1)] 0, attempt 18846 28 46 0 [(17973, 1)] 0, attempt 18847 28 47 0 [(17974, 1)] 0]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18816
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 18848 28 48 0 [(17975, 1)] 0, attempt 18849 28 49 0 [(17976, 1)] 0, attempt 18850 28 50 0 [(17977, 1)] 0, attempt 18851 28 51 0 [(17978, 1)] 0, attempt 18852 28 52 0 [(17979, 1)] 0, attempt 18853 28 53 0 [(17980, 1)] 0, attempt 18854 28 54 0 [(17981, 1)] 0, attempt 18855 28 55 0 [(17982, 1)] 0, attempt 18856 28 56 0 [(17983, 1)] 0, attempt 18857 28 57 0 [(17991, 1)] 0, attempt 18858 28 58 0 [(17992, 1)] 0, attempt 18859 28 59 0 [(17993, 1)] 0, attempt 18860 28 60 0 [(17994, 1)] 0, attempt 18861 28 61 0 [(17995, 1)] 0, attempt 18862 28 62 0 [(17996, 1)] 0, attempt 18863 28 63 0 [(17997, 1)] 0, attempt 18864 28 64 0 [(17998, 1)] 0, attempt 18865 28 65 0 [(17999, 1)] 0, attempt 18866 28 66 0 [(18000, 1)] 0, attempt 18867 28 67 0 [(18001, 1)] 0, attempt 18868 28 68 0 [(18002, 1)] 0, attempt 18869 28 69 0 [(18003, 1)] 0, attempt 18870 28 70 0 [(18004, 1)] 0, attempt 18871 28 71 0 [(18005, 1)] 0, attempt 18872 28 72 0 [(18006, 1)] 0, attempt 18873 28 73 0 [(18007, 1)] 0, attempt 18874 28 74 0 [(18008, 1)] 0, attempt 18875 28 75 0 [(18009, 1)] 0, attempt 18876 28 76 0 [(18010, 1)] 0, attempt 18877 28 77 0 [(18011, 1)] 0, attempt 18878 28 78 0 [(18012, 1)] 0, attempt 18879 28 79 0 [(18013, 1)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18848
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 18880 28 80 0 [(18014, 1)] 0, attempt 18881 28 81 0 [(18015, 1)] 0, attempt 18882 28 82 0 [(18016, 1)] 0, attempt 18883 28 83 0 [(18017, 1)] 0, attempt 18884 28 84 0 [(18018, 1)] 0, attempt 18885 28 85 0 [(18019, 1)] 0, attempt 18886 28 86 0 [(18020, 1)] 0, attempt 18887 28 87 0 [(18021, 1)] 0, attempt 18888 28 88 0 [(18022, 1)] 0, attempt 18889 28 89 0 [(18023, 1)] 0, attempt 18890 28 90 0 [(18024, 1)] 0, attempt 18891 28 91 0 [(18025, 1)] 0, attempt 18892 28 92 0 [(18026, 1)] 0, attempt 18893 28 93 0 [(18027, 1)] 0, attempt 18894 28 94 0 [(18028, 1)] 0, attempt 18895 28 95 0 [(18029, 1)] 0, attempt 18896 28 96 0 [(18030, 1)] 0, attempt 18897 28 97 0 [(18031, 1)] 0, attempt 18898 28 98 0 [(18032, 1)] 0, attempt 18899 28 99 0 [(18033, 1)] 0, attempt 18900 28 100 0 [(18034, 1)] 0, attempt 18901 28 101 0 [(18035, 1)] 0, attempt 18902 28 102 0 [(18036, 1)] 0, attempt 18903 28 103 0 [(18037, 1)] 0, attempt 18904 28 104 0 [(18038, 1)] 0, attempt 18905 28 105 0 [(18039, 1)] 0, attempt 18906 28 106 0 [(18040, 1)] 0, attempt 18907 28 107 0 [(18041, 1)] 0, attempt 18908 28 108 0 [(18042, 1)] 0, attempt 18909 28 109 0 [(18043, 1)] 0, attempt 18910 28 110 0 [(18044, 1)] 0, attempt 18911 28 111 0 [(18045, 1)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18880
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 18912 28 112 0 [(18046, 1)] 0, attempt 18913 28 113 0 [(18047, 1)] 0, attempt 18914 28 114 0 [(18055, 1)] 0, attempt 18915 28 115 0 [(18056, 1)] 0, attempt 18916 28 116 0 [(18057, 1)] 0, attempt 18917 28 117 0 [(18058, 1)] 0, attempt 18918 28 118 0 [(18059, 1)] 0, attempt 18919 28 119 0 [(18060, 1)] 0, attempt 18920 28 120 0 [(18061, 1)] 0, attempt 18921 28 121 0 [(18062, 1)] 0, attempt 18922 28 122 0 [(18063, 1)] 0, attempt 18923 28 123 0 [(18064, 1)] 0, attempt 18924 28 124 0 [(18065, 1)] 0, attempt 18925 28 125 0 [(18066, 1)] 0, attempt 18926 28 126 0 [(18067, 1)] 0, attempt 18927 28 127 0 [(18068, 1)] 0, attempt 18928 28 128 0 [(18069, 1)] 0, attempt 18929 28 129 0 [(18070, 1)] 0, attempt 18930 28 130 0 [(18071, 1)] 0, attempt 18931 28 131 0 [(18072, 1)] 0, attempt 18932 28 132 0 [(18073, 1)] 0, attempt 18933 28 133 0 [(18074, 1)] 0, attempt 18934 28 134 0 [(18075, 1)] 0, attempt 18935 28 135 0 [(18076, 1)] 0, attempt 18936 28 136 0 [(18077, 1)] 0, attempt 18937 28 137 0 [(18078, 1)] 0, attempt 18938 28 138 0 [(18079, 1)] 0, attempt 18939 28 139 0 [(18080, 1)] 0, attempt 18940 28 140 0 [(18081, 1)] 0, attempt 18941 28 141 0 [(18082, 1)] 0, attempt 18942 28 142 0 [(18083, 1)] 0, attempt 18943 28 143 0 [(18084, 1)] 0]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 36, 14, 240, 7, 64, 21, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18912
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18944
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18912
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 18912 18944 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 18912) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18880
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 18880 18912 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 18880) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18848
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 18848 18880 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 18848) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18816
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 18816 18848 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 18816) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18784
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 18784 18816 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 18784) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18752
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 18752 18784 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 18752) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18720
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 18720 18752 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 18720) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18688
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 18688 18720 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 18688) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18656
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 18656 18688 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 18656) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18624
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 18624 18656 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 18624) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18592
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 18592 18624 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 18592) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18560
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 18560 18592 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 18560) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18528
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 18528 18560 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 18528) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18496
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 18496 18528 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 18496) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18464
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 18464 18496 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 18464) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18432
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 18432 18464 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 18432) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr36
