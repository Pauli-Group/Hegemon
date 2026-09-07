import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr29

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr30
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15360, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 15360 0 15360 0 [(15604, 1), (15552, 3)] 0, attempt 15361 0 15361 0 [(15605, 1), (15552, 3)] 0, attempt 15362 0 15362 0 [(15606, 1), (15552, 3)] 0, attempt 15363 0 15363 0 [(15607, 1), (15552, 3)] 0, attempt 15364 0 15364 0 [(15608, 1), (15552, 3)] 0, attempt 15365 0 15365 0 [(15609, 1), (15552, 3)] 0, attempt 15366 0 15366 0 [(15610, 1), (15552, 3)] 0, attempt 15367 0 15367 0 [(15611, 1), (15552, 3)] 0, attempt 15368 0 15368 0 [(15612, 1), (15552, 3)] 0, attempt 15369 0 15369 0 [(15613, 1), (15552, 3)] 0, attempt 15370 0 15370 0 [(15614, 1), (15552, 3)] 0, attempt 15371 0 15371 0 [(15615, 1), (15552, 3)] 0, attempt 15372 0 15372 0 [(15617, 1), (15616, 3)] 0, attempt 15373 0 15373 0 [(15618, 1), (15616, 3)] 0, attempt 15374 0 15374 0 [(15619, 1), (15616, 3)] 0, attempt 15375 0 15375 0 [(15620, 1), (15616, 3)] 0, attempt 15376 0 15376 0 [(15621, 1), (15616, 3)] 0, attempt 15377 0 15377 0 [(15622, 1), (15616, 3)] 0, attempt 15378 0 15378 0 [(15623, 1), (15616, 3)] 0, attempt 15379 0 15379 0 [(15624, 1), (15616, 3)] 0, attempt 15380 0 15380 0 [(15625, 1), (15616, 3)] 0, attempt 15381 0 15381 0 [(15626, 1), (15616, 3)] 0, attempt 15382 0 15382 0 [(15627, 1), (15616, 3)] 0, attempt 15383 0 15383 0 [(15628, 1), (15616, 3)] 0, attempt 15384 0 15384 0 [(15629, 1), (15616, 3)] 0, attempt 15385 0 15385 0 [(15630, 1), (15616, 3)] 0, attempt 15386 0 15386 0 [(15631, 1), (15616, 3)] 0, attempt 15387 0 15387 0 [(15632, 1), (15616, 3)] 0, attempt 15388 0 15388 0 [(15633, 1), (15616, 3)] 0, attempt 15389 0 15389 0 [(15634, 1), (15616, 3)] 0, attempt 15390 0 15390 0 [(15635, 1), (15616, 3)] 0, attempt 15391 0 15391 0 [(15636, 1), (15616, 3)] 0]
def counters001 : List Nat := [15392, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15360
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 15392 0 15392 0 [(15637, 1), (15616, 3)] 0, attempt 15393 0 15393 0 [(15638, 1), (15616, 3)] 0, attempt 15394 0 15394 0 [(15639, 1), (15616, 3)] 0, attempt 15395 0 15395 0 [(15640, 1), (15616, 3)] 0, attempt 15396 0 15396 0 [(15641, 1), (15616, 3)] 0, attempt 15397 0 15397 0 [(15642, 1), (15616, 3)] 0, attempt 15398 0 15398 0 [(15643, 1), (15616, 3)] 0, attempt 15399 0 15399 0 [(15644, 1), (15616, 3)] 0, attempt 15400 0 15400 0 [(15645, 1), (15616, 3)] 0, attempt 15401 0 15401 0 [(15646, 1), (15616, 3)] 0, attempt 15402 0 15402 0 [(15647, 1), (15616, 3)] 0, attempt 15403 0 15403 0 [(15648, 1), (15616, 3)] 0, attempt 15404 0 15404 0 [(15649, 1), (15616, 3)] 0, attempt 15405 0 15405 0 [(15650, 1), (15616, 3)] 0, attempt 15406 0 15406 0 [(15651, 1), (15616, 3)] 0, attempt 15407 0 15407 0 [(15652, 1), (15616, 3)] 0, attempt 15408 0 15408 0 [(15653, 1), (15616, 3)] 0, attempt 15409 0 15409 0 [(15654, 1), (15616, 3)] 0, attempt 15410 0 15410 0 [(15655, 1), (15616, 3)] 0, attempt 15411 0 15411 0 [(15656, 1), (15616, 3)] 0, attempt 15412 0 15412 0 [(15657, 1), (15616, 3)] 0, attempt 15413 0 15413 0 [(15658, 1), (15616, 3)] 0, attempt 15414 0 15414 0 [(15659, 1), (15616, 3)] 0, attempt 15415 0 15415 0 [(15660, 1), (15616, 3)] 0, attempt 15416 0 15416 0 [(15661, 1), (15616, 3)] 0, attempt 15417 0 15417 0 [(15662, 1), (15616, 3)] 0, attempt 15418 0 15418 0 [(15663, 1), (15616, 3)] 0, attempt 15419 0 15419 0 [(15664, 1), (15616, 3)] 0, attempt 15420 0 15420 0 [(15665, 1), (15616, 3)] 0, attempt 15421 0 15421 0 [(15666, 1), (15616, 3)] 0, attempt 15422 0 15422 0 [(15667, 1), (15616, 3)] 0, attempt 15423 0 15423 0 [(15668, 1), (15616, 3)] 0]
def counters002 : List Nat := [15424, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15392
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 15424 0 15424 0 [(15669, 1), (15616, 3)] 0, attempt 15425 0 15425 0 [(15670, 1), (15616, 3)] 0, attempt 15426 0 15426 0 [(15671, 1), (15616, 3)] 0, attempt 15427 0 15427 0 [(15672, 1), (15616, 3)] 0, attempt 15428 0 15428 0 [(15673, 1), (15616, 3)] 0, attempt 15429 0 15429 0 [(15674, 1), (15616, 3)] 0, attempt 15430 0 15430 0 [(15675, 1), (15616, 3)] 0, attempt 15431 0 15431 0 [(15676, 1), (15616, 3)] 0, attempt 15432 0 15432 0 [(15677, 1), (15616, 3)] 0, attempt 15433 0 15433 0 [(15678, 1), (15616, 3)] 0, attempt 15434 0 15434 0 [(15679, 1), (15616, 3)] 0, attempt 15435 0 15435 0 [(15681, 1), (15680, 3)] 0, attempt 15436 0 15436 0 [(15682, 1), (15680, 3)] 0, attempt 15437 0 15437 0 [(15683, 1), (15680, 3)] 0, attempt 15438 0 15438 0 [(15684, 1), (15680, 3)] 0, attempt 15439 0 15439 0 [(15685, 1), (15680, 3)] 0, attempt 15440 0 15440 0 [(15686, 1), (15680, 3)] 0, attempt 15441 0 15441 0 [(15687, 1), (15680, 3)] 0, attempt 15442 0 15442 0 [(15688, 1), (15680, 3)] 0, attempt 15443 0 15443 0 [(15689, 1), (15680, 3)] 0, attempt 15444 0 15444 0 [(15690, 1), (15680, 3)] 0, attempt 15445 0 15445 0 [(15691, 1), (15680, 3)] 0, attempt 15446 0 15446 0 [(15692, 1), (15680, 3)] 0, attempt 15447 0 15447 0 [(15693, 1), (15680, 3)] 0, attempt 15448 0 15448 0 [(15694, 1), (15680, 3)] 0, attempt 15449 0 15449 0 [(15695, 1), (15680, 3)] 0, attempt 15450 0 15450 0 [(15696, 1), (15680, 3)] 0, attempt 15451 0 15451 0 [(15697, 1), (15680, 3)] 0, attempt 15452 0 15452 0 [(15698, 1), (15680, 3)] 0, attempt 15453 0 15453 0 [(15699, 1), (15680, 3)] 0, attempt 15454 0 15454 0 [(15700, 1), (15680, 3)] 0, attempt 15455 0 15455 0 [(15701, 1), (15680, 3)] 0]
def counters003 : List Nat := [15456, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15424
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 15456 0 15456 0 [(15702, 1), (15680, 3)] 0, attempt 15457 0 15457 0 [(15703, 1), (15680, 3)] 0, attempt 15458 0 15458 0 [(15704, 1), (15680, 3)] 0, attempt 15459 0 15459 0 [(15705, 1), (15680, 3)] 0, attempt 15460 0 15460 0 [(15706, 1), (15680, 3)] 0, attempt 15461 0 15461 0 [(15707, 1), (15680, 3)] 0, attempt 15462 0 15462 0 [(15708, 1), (15680, 3)] 0, attempt 15463 0 15463 0 [(15709, 1), (15680, 3)] 0, attempt 15464 0 15464 0 [(15710, 1), (15680, 3)] 0, attempt 15465 0 15465 0 [(15711, 1), (15680, 3)] 0, attempt 15466 0 15466 0 [(15712, 1), (15680, 3)] 0, attempt 15467 0 15467 0 [(15713, 1), (15680, 3)] 0, attempt 15468 0 15468 0 [(15714, 1), (15680, 3)] 0, attempt 15469 0 15469 0 [(15715, 1), (15680, 3)] 0, attempt 15470 0 15470 0 [(15716, 1), (15680, 3)] 0, attempt 15471 0 15471 0 [(15717, 1), (15680, 3)] 0, attempt 15472 0 15472 0 [(15718, 1), (15680, 3)] 0, attempt 15473 0 15473 0 [(15719, 1), (15680, 3)] 0, attempt 15474 0 15474 0 [(15720, 1), (15680, 3)] 0, attempt 15475 0 15475 0 [(15721, 1), (15680, 3)] 0, attempt 15476 0 15476 0 [(15722, 1), (15680, 3)] 0, attempt 15477 0 15477 0 [(15723, 1), (15680, 3)] 0, attempt 15478 0 15478 0 [(15724, 1), (15680, 3)] 0, attempt 15479 0 15479 0 [(15725, 1), (15680, 3)] 0, attempt 15480 0 15480 0 [(15726, 1), (15680, 3)] 0, attempt 15481 0 15481 0 [(15727, 1), (15680, 3)] 0, attempt 15482 0 15482 0 [(15728, 1), (15680, 3)] 0, attempt 15483 0 15483 0 [(15729, 1), (15680, 3)] 0, attempt 15484 0 15484 0 [(15730, 1), (15680, 3)] 0, attempt 15485 0 15485 0 [(15731, 1), (15680, 3)] 0, attempt 15486 0 15486 0 [(15732, 1), (15680, 3)] 0, attempt 15487 0 15487 0 [(15733, 1), (15680, 3)] 0]
def counters004 : List Nat := [15488, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15456
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 15488 0 15488 0 [(15734, 1), (15680, 3)] 0, attempt 15489 0 15489 0 [(15735, 1), (15680, 3)] 0, attempt 15490 0 15490 0 [(15736, 1), (15680, 3)] 0, attempt 15491 0 15491 0 [(15737, 1), (15680, 3)] 0, attempt 15492 0 15492 0 [(15738, 1), (15680, 3)] 0, attempt 15493 0 15493 0 [(15739, 1), (15680, 3)] 0, attempt 15494 0 15494 0 [(15740, 1), (15680, 3)] 0, attempt 15495 0 15495 0 [(15741, 1), (15680, 3)] 0, attempt 15496 0 15496 0 [(15742, 1), (15680, 3)] 0, attempt 15497 0 15497 0 [(15743, 1), (15680, 3)] 0, attempt 15498 0 15498 0 [(15745, 1), (15744, 3)] 0, attempt 15499 0 15499 0 [(15746, 1), (15744, 3)] 0, attempt 15500 0 15500 0 [(15747, 1), (15744, 3)] 0, attempt 15501 0 15501 0 [(15748, 1), (15744, 3)] 0, attempt 15502 0 15502 0 [(15749, 1), (15744, 3)] 0, attempt 15503 0 15503 0 [(15750, 1), (15744, 3)] 0, attempt 15504 0 15504 0 [(15751, 1), (15744, 3)] 0, attempt 15505 0 15505 0 [(15752, 1), (15744, 3)] 0, attempt 15506 0 15506 0 [(15753, 1), (15744, 3)] 0, attempt 15507 0 15507 0 [(15754, 1), (15744, 3)] 0, attempt 15508 0 15508 0 [(15755, 1), (15744, 3)] 0, attempt 15509 0 15509 0 [(15756, 1), (15744, 3)] 0, attempt 15510 0 15510 0 [(15757, 1), (15744, 3)] 0, attempt 15511 0 15511 0 [(15758, 1), (15744, 3)] 0, attempt 15512 0 15512 0 [(15759, 1), (15744, 3)] 0, attempt 15513 0 15513 0 [(15760, 1), (15744, 3)] 0, attempt 15514 0 15514 0 [(15761, 1), (15744, 3)] 0, attempt 15515 0 15515 0 [(15762, 1), (15744, 3)] 0, attempt 15516 0 15516 0 [(15763, 1), (15744, 3)] 0, attempt 15517 0 15517 0 [(15764, 1), (15744, 3)] 0, attempt 15518 0 15518 0 [(15765, 1), (15744, 3)] 0, attempt 15519 0 15519 0 [(15766, 1), (15744, 3)] 0]
def counters005 : List Nat := [15520, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15488
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 15520 0 15520 0 [(15767, 1), (15744, 3)] 0, attempt 15521 0 15521 0 [(15768, 1), (15744, 3)] 0, attempt 15522 0 15522 0 [(15769, 1), (15744, 3)] 0, attempt 15523 0 15523 0 [(15770, 1), (15744, 3)] 0, attempt 15524 0 15524 0 [(15771, 1), (15744, 3)] 0, attempt 15525 0 15525 0 [(15772, 1), (15744, 3)] 0, attempt 15526 0 15526 0 [(15773, 1), (15744, 3)] 0, attempt 15527 0 15527 0 [(15774, 1), (15744, 3)] 0, attempt 15528 0 15528 0 [(15775, 1), (15744, 3)] 0, attempt 15529 0 15529 0 [(15776, 1), (15744, 3)] 0, attempt 15530 0 15530 0 [(15777, 1), (15744, 3)] 0, attempt 15531 0 15531 0 [(15778, 1), (15744, 3)] 0, attempt 15532 0 15532 0 [(15779, 1), (15744, 3)] 0, attempt 15533 0 15533 0 [(15780, 1), (15744, 3)] 0, attempt 15534 0 15534 0 [(15781, 1), (15744, 3)] 0, attempt 15535 0 15535 0 [(15782, 1), (15744, 3)] 0, attempt 15536 0 15536 0 [(15783, 1), (15744, 3)] 0, attempt 15537 0 15537 0 [(15784, 1), (15744, 3)] 0, attempt 15538 0 15538 0 [(15785, 1), (15744, 3)] 0, attempt 15539 0 15539 0 [(15786, 1), (15744, 3)] 0, attempt 15540 0 15540 0 [(15787, 1), (15744, 3)] 0, attempt 15541 0 15541 0 [(15788, 1), (15744, 3)] 0, attempt 15542 0 15542 0 [(15789, 1), (15744, 3)] 0, attempt 15543 0 15543 0 [(15790, 1), (15744, 3)] 0, attempt 15544 0 15544 0 [(15791, 1), (15744, 3)] 0, attempt 15545 0 15545 0 [(15792, 1), (15744, 3)] 0, attempt 15546 0 15546 0 [(15793, 1), (15744, 3)] 0, attempt 15547 0 15547 0 [(15794, 1), (15744, 3)] 0, attempt 15548 0 15548 0 [(15795, 1), (15744, 3)] 0, attempt 15549 0 15549 0 [(15796, 1), (15744, 3)] 0, attempt 15550 0 15550 0 [(15797, 1), (15744, 3)] 0, attempt 15551 0 15551 0 [(15798, 1), (15744, 3)] 0]
def counters006 : List Nat := [15552, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15520
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 15552 0 15552 0 [(15799, 1), (15744, 3)] 0, attempt 15553 0 15553 0 [(15800, 1), (15744, 3)] 0, attempt 15554 0 15554 0 [(15801, 1), (15744, 3)] 0, attempt 15555 0 15555 0 [(15802, 1), (15744, 3)] 0, attempt 15556 0 15556 0 [(15803, 1), (15744, 3)] 0, attempt 15557 0 15557 0 [(15804, 1), (15744, 3)] 0, attempt 15558 0 15558 0 [(15805, 1), (15744, 3)] 0, attempt 15559 0 15559 0 [(15806, 1), (15744, 3)] 0, attempt 15560 0 15560 0 [(15807, 1), (15744, 3)] 0, attempt 15561 1 0 1 [(0, 124)] 0, attempt 15562 1 1 1 [(64, 124)] 0, attempt 15563 1 2 1 [(128, 124)] 0, attempt 15564 1 3 1 [(192, 124)] 0, attempt 15565 1 4 1 [(256, 124)] 0, attempt 15566 1 5 1 [(320, 124)] 0, attempt 15567 1 6 1 [(384, 124)] 0, attempt 15568 1 7 1 [(448, 124)] 0, attempt 15569 1 8 1 [(512, 124)] 0, attempt 15570 1 9 1 [(576, 124)] 0, attempt 15571 1 10 1 [(640, 124)] 0, attempt 15572 1 11 1 [(704, 124)] 0, attempt 15573 1 12 1 [(768, 124)] 0, attempt 15574 1 13 1 [(832, 124)] 0, attempt 15575 1 14 1 [(896, 124)] 0, attempt 15576 1 15 1 [(960, 124)] 0, attempt 15577 1 16 1 [(1024, 124)] 0, attempt 15578 1 17 1 [(1088, 124)] 0, attempt 15579 1 18 1 [(1152, 124)] 0, attempt 15580 1 19 1 [(1216, 124)] 0, attempt 15581 1 20 1 [(1280, 124)] 0, attempt 15582 1 21 1 [(1344, 124)] 0, attempt 15583 1 22 1 [(1408, 124)] 0]
def counters007 : List Nat := [15561, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15552
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 15584 1 23 1 [(1472, 124)] 0, attempt 15585 1 24 1 [(1536, 124)] 0, attempt 15586 1 25 1 [(1600, 124)] 0, attempt 15587 1 26 1 [(1664, 124)] 0, attempt 15588 1 27 1 [(1728, 124)] 0, attempt 15589 1 28 1 [(1792, 124)] 0, attempt 15590 1 29 1 [(1856, 124)] 0, attempt 15591 1 30 1 [(1920, 124)] 0, attempt 15592 1 31 1 [(1984, 124)] 0, attempt 15593 1 32 1 [(2048, 124)] 0, attempt 15594 1 33 1 [(2112, 124)] 0, attempt 15595 1 34 1 [(2176, 125)] 0, attempt 15596 1 35 1 [(2240, 125)] 0, attempt 15597 1 36 1 [(2304, 125)] 0, attempt 15598 1 37 1 [(2368, 125)] 0, attempt 15599 1 38 1 [(2432, 125)] 0, attempt 15600 1 39 1 [(2496, 125)] 0, attempt 15601 1 40 1 [(2560, 125)] 0, attempt 15602 1 41 1 [(2624, 125)] 0, attempt 15603 1 42 1 [(2688, 125)] 0, attempt 15604 1 43 1 [(2752, 125)] 0, attempt 15605 1 44 1 [(2816, 125)] 0, attempt 15606 1 45 1 [(2880, 125)] 0, attempt 15607 1 46 1 [(2944, 125)] 0, attempt 15608 1 47 1 [(3008, 125)] 0, attempt 15609 1 48 1 [(3072, 125)] 0, attempt 15610 1 49 1 [(3136, 125)] 0, attempt 15611 1 50 1 [(3200, 125)] 0, attempt 15612 1 51 1 [(3264, 125)] 0, attempt 15613 1 52 1 [(3328, 125)] 0, attempt 15614 1 53 1 [(3392, 125)] 0, attempt 15615 1 54 1 [(3456, 125)] 0]
def counters008 : List Nat := [15561, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15584
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 15616 1 55 1 [(3520, 125)] 0, attempt 15617 1 56 1 [(3584, 125)] 0, attempt 15618 1 57 1 [(3648, 125)] 0, attempt 15619 1 58 1 [(3712, 125)] 0, attempt 15620 1 59 1 [(3776, 125)] 0, attempt 15621 1 60 1 [(3840, 125)] 0, attempt 15622 1 61 1 [(3904, 125)] 0, attempt 15623 1 62 1 [(3968, 125)] 0, attempt 15624 1 63 1 [(4032, 125)] 0, attempt 15625 1 64 1 [(4096, 125)] 0, attempt 15626 1 65 1 [(4160, 125)] 0, attempt 15627 1 66 1 [(4224, 125)] 0, attempt 15628 1 67 1 [(4288, 125)] 0, attempt 15629 2 0 1 [(4352, 126)] 0, attempt 15630 2 1 1 [(4416, 126)] 0, attempt 15631 2 2 1 [(4480, 126)] 0, attempt 15632 2 3 1 [(4544, 126)] 0, attempt 15633 2 4 1 [(4608, 126)] 0, attempt 15634 2 5 1 [(4672, 126)] 0, attempt 15635 2 6 1 [(4736, 126)] 0, attempt 15636 2 7 1 [(4800, 126)] 0, attempt 15637 2 8 1 [(4864, 126)] 0, attempt 15638 2 9 1 [(4928, 126)] 0, attempt 15639 2 10 1 [(4992, 126)] 0, attempt 15640 2 11 1 [(5056, 126)] 0, attempt 15641 2 12 1 [(5120, 127)] 0, attempt 15642 2 13 1 [(5184, 127)] 0, attempt 15643 2 14 1 [(5248, 127)] 0, attempt 15644 2 15 1 [(5312, 127)] 0, attempt 15645 2 16 1 [(5376, 127)] 0, attempt 15646 2 17 1 [(5440, 127)] 0, attempt 15647 2 18 1 [(5504, 127)] 0]
def counters009 : List Nat := [15561, 68, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15616
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 15648 2 19 1 [(5568, 127)] 0, attempt 15649 2 20 1 [(5632, 127)] 0, attempt 15650 2 21 1 [(5696, 127)] 0, attempt 15651 2 22 1 [(5760, 127)] 0, attempt 15652 2 23 1 [(5824, 127)] 0, attempt 15653 3 0 0 [(4480, 1)] 36, attempt 15654 3 1 0 [(4544, 1)] 37, attempt 15655 3 2 0 [(4608, 1)] 38, attempt 15656 3 3 0 [(4672, 1)] 39, attempt 15657 3 4 0 [(4736, 1)] 40, attempt 15658 3 5 0 [(4800, 1)] 41, attempt 15659 3 6 0 [(5248, 1)] 42, attempt 15660 3 7 0 [(5312, 1)] 43, attempt 15661 3 8 0 [(5376, 1)] 44, attempt 15662 3 9 0 [(5440, 1)] 45, attempt 15663 3 10 0 [(5504, 1)] 46, attempt 15664 3 11 0 [(5568, 1)] 47, attempt 15665 4 0 0 [(0, 1), (15808, 158), (15809, 159), (15810, 160), (15811, 161), (15812, 162), (15813, 163), (15814, 164), (15815, 165), (15816, 166), (15817, 167), (15818, 168), (15819, 169), (15820, 170), (15821, 171), (15822, 172), (15823, 173), (15824, 174), (15825, 175), (15826, 176), (15827, 177), (15828, 178), (15829, 179), (15830, 180), (15831, 181), (15832, 182), (15833, 183), (15834, 184), (15835, 185), (15836, 186), (15837, 187), (16064, 189)] 0, attempt 15666 4 1 0 [(2176, 1), (15838, 158), (15839, 159), (15840, 160), (15841, 161), (15842, 162), (15843, 163), (15844, 164), (15845, 165), (15846, 166), (15847, 167), (15848, 168), (15849, 169), (15850, 170), (15851, 171), (15852, 172), (15853, 173), (15854, 174), (15855, 175), (15856, 176), (15857, 177), (15858, 178), (15859, 179), (15860, 180), (15861, 181), (15862, 182), (15863, 183), (15864, 184), (15865, 185), (15866, 186), (15867, 187), (16065, 189)] 0, attempt 15667 4 2 0 [(4352, 1), (15868, 158), (15869, 159), (15870, 160), (15871, 161), (15872, 162), (15873, 163), (15874, 164), (15875, 165), (15876, 166), (15877, 167), (15878, 168), (15879, 169), (15880, 170), (15881, 171), (15882, 172), (15883, 173), (15884, 174), (15885, 175), (15886, 176), (15887, 177), (15888, 178), (15889, 179), (15890, 180), (15891, 181), (15892, 182), (15893, 183), (15894, 184), (15895, 185), (15896, 186), (15897, 187), (16066, 189)] 0, attempt 15668 4 3 0 [(5120, 1), (15898, 158), (15899, 159), (15900, 160), (15901, 161), (15902, 162), (15903, 163), (15904, 164), (15905, 165), (15906, 166), (15907, 167), (15908, 168), (15909, 169), (15910, 170), (15911, 171), (15912, 172), (15913, 173), (15914, 174), (15915, 175), (15916, 176), (15917, 177), (15918, 178), (15919, 179), (15920, 180), (15921, 181), (15922, 182), (15923, 183), (15924, 184), (15925, 185), (15926, 186), (15927, 187), (16067, 189)] 0, attempt 15669 4 4 0 [(15928, 158), (15929, 159), (15930, 160), (15931, 161), (15932, 162), (15933, 163), (15934, 164), (15935, 165), (15936, 166), (15937, 167), (15938, 168), (15939, 169), (15940, 170), (15941, 171), (15942, 172), (15943, 173), (15944, 174), (15945, 175), (15946, 176), (15947, 177), (15948, 178), (15949, 179), (15950, 180), (15951, 181), (15952, 182), (15953, 183), (15954, 184), (15955, 185), (15956, 186), (15957, 187), (16068, 189)] 190, attempt 15670 4 5 0 [(15958, 158), (15959, 159), (15960, 160), (15961, 161), (15962, 162), (15963, 163), (15964, 164), (15965, 165), (15966, 166), (15967, 167), (15968, 168), (15969, 169), (15970, 170), (15971, 171), (15972, 172), (15973, 173), (15974, 174), (15975, 175), (15976, 176), (15977, 177), (15978, 178), (15979, 179), (15980, 180), (15981, 181), (15982, 182), (15983, 183), (15984, 184), (15985, 185), (15986, 186), (15987, 187), (16069, 189)] 191, attempt 15671 4 6 0 [(15988, 158), (15989, 159), (15990, 160), (15991, 161), (15992, 162), (15993, 163), (15994, 164), (15995, 165), (15996, 166), (15997, 167), (15998, 168), (15999, 169), (16000, 170), (16001, 171), (16002, 172), (16003, 173), (16004, 174), (16005, 175), (16006, 176), (16007, 177), (16008, 178), (16009, 179), (16010, 180), (16011, 181), (16012, 182), (16013, 183), (16014, 184), (16015, 185), (16016, 186), (16017, 187), (16070, 189)] 192, attempt 15672 5 0 0 [(41528, 1)] 49, attempt 15673 5 1 0 [(41528, 1)] 50, attempt 15674 6 0 0 [(16018, 1)] 0, attempt 15675 6 1 0 [(16019, 1)] 0, attempt 15676 6 2 0 [(16020, 1)] 0, attempt 15677 6 3 0 [(16021, 1)] 0, attempt 15678 6 4 0 [(16022, 1)] 0, attempt 15679 6 5 0 [(16023, 1)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15648
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 15680 6 6 0 [(16024, 1)] 0, attempt 15681 6 7 0 [(16025, 1)] 0, attempt 15682 6 8 0 [(16026, 1)] 0, attempt 15683 6 9 0 [(16027, 1)] 0, attempt 15684 6 10 0 [(16028, 1)] 0, attempt 15685 6 11 0 [(16029, 1)] 0, attempt 15686 6 12 0 [(16030, 1)] 0, attempt 15687 6 13 0 [(16031, 1)] 0, attempt 15688 6 14 0 [(16032, 1)] 0, attempt 15689 6 15 0 [(16033, 1)] 0, attempt 15690 6 16 0 [(16034, 1)] 0, attempt 15691 6 17 0 [(16035, 1)] 0, attempt 15692 6 18 0 [(16036, 1)] 0, attempt 15693 6 19 0 [(16037, 1)] 0, attempt 15694 6 20 0 [(16038, 1)] 0, attempt 15695 6 21 0 [(16039, 1)] 0, attempt 15696 6 22 0 [(16040, 1)] 0, attempt 15697 6 23 0 [(16041, 1)] 0, attempt 15698 6 24 0 [(16042, 1)] 0, attempt 15699 6 25 0 [(16043, 1)] 0, attempt 15700 6 26 0 [(16044, 1)] 0, attempt 15701 6 27 0 [(16045, 1)] 0, attempt 15702 6 28 0 [(16046, 1)] 0, attempt 15703 6 29 0 [(16047, 1)] 0, attempt 15704 6 30 0 [(16048, 1)] 0, attempt 15705 6 31 0 [(16049, 1)] 0, attempt 15706 6 32 0 [(16050, 1)] 0, attempt 15707 6 33 0 [(16051, 1)] 0, attempt 15708 6 34 0 [(16052, 1)] 0, attempt 15709 6 35 0 [(16053, 1)] 0, attempt 15710 6 36 0 [(16054, 1)] 0, attempt 15711 6 37 0 [(16055, 1)] 0]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15680
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 15712 6 38 0 [(16056, 1)] 0, attempt 15713 6 39 0 [(16057, 1)] 0, attempt 15714 6 40 0 [(16058, 1)] 0, attempt 15715 6 41 0 [(16059, 1)] 0, attempt 15716 6 42 0 [(16060, 1)] 0, attempt 15717 6 43 0 [(16061, 1)] 0, attempt 15718 6 44 0 [(16062, 1)] 0, attempt 15719 6 45 0 [(16063, 1)] 0, attempt 15720 7 0 0 [(16071, 1)] 0, attempt 15721 7 1 0 [(16072, 1)] 0, attempt 15722 7 2 0 [(16073, 1)] 0, attempt 15723 7 3 0 [(16074, 1)] 0, attempt 15724 7 4 0 [(16075, 1)] 0, attempt 15725 7 5 0 [(16076, 1)] 0, attempt 15726 7 6 0 [(16077, 1)] 0, attempt 15727 7 7 0 [(16078, 1)] 0, attempt 15728 7 8 0 [(16079, 1)] 0, attempt 15729 7 9 0 [(16080, 1)] 0, attempt 15730 7 10 0 [(16081, 1)] 0, attempt 15731 7 11 0 [(16082, 1)] 0, attempt 15732 7 12 0 [(16083, 1)] 0, attempt 15733 7 13 0 [(16084, 1)] 0, attempt 15734 7 14 0 [(16085, 1)] 0, attempt 15735 7 15 0 [(16086, 1)] 0, attempt 15736 7 16 0 [(16087, 1)] 0, attempt 15737 7 17 0 [(16088, 1)] 0, attempt 15738 7 18 0 [(16089, 1)] 0, attempt 15739 7 19 0 [(16090, 1)] 0, attempt 15740 7 20 0 [(16091, 1)] 0, attempt 15741 7 21 0 [(16092, 1)] 0, attempt 15742 7 22 0 [(16093, 1)] 0, attempt 15743 7 23 0 [(16094, 1)] 0]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15712
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 15744 7 24 0 [(16095, 1)] 0, attempt 15745 7 25 0 [(16096, 1)] 0, attempt 15746 7 26 0 [(16097, 1)] 0, attempt 15747 7 27 0 [(16098, 1)] 0, attempt 15748 7 28 0 [(16099, 1)] 0, attempt 15749 7 29 0 [(16100, 1)] 0, attempt 15750 7 30 0 [(16101, 1)] 0, attempt 15751 7 31 0 [(16102, 1)] 0, attempt 15752 7 32 0 [(16103, 1)] 0, attempt 15753 7 33 0 [(16104, 1)] 0, attempt 15754 7 34 0 [(16105, 1)] 0, attempt 15755 7 35 0 [(16106, 1)] 0, attempt 15756 7 36 0 [(16107, 1)] 0, attempt 15757 7 37 0 [(16108, 1)] 0, attempt 15758 7 38 0 [(16109, 1)] 0, attempt 15759 7 39 0 [(16110, 1)] 0, attempt 15760 7 40 0 [(16111, 1)] 0, attempt 15761 7 41 0 [(16112, 1)] 0, attempt 15762 7 42 0 [(16113, 1)] 0, attempt 15763 7 43 0 [(16114, 1)] 0, attempt 15764 7 44 0 [(16115, 1)] 0, attempt 15765 7 45 0 [(16116, 1)] 0, attempt 15766 7 46 0 [(16117, 1)] 0, attempt 15767 7 47 0 [(16118, 1)] 0, attempt 15768 7 48 0 [(16119, 1)] 0, attempt 15769 7 49 0 [(16120, 1)] 0, attempt 15770 7 50 0 [(16121, 1)] 0, attempt 15771 7 51 0 [(16122, 1)] 0, attempt 15772 7 52 0 [(16123, 1)] 0, attempt 15773 7 53 0 [(16124, 1)] 0, attempt 15774 7 54 0 [(16125, 1)] 0, attempt 15775 7 55 0 [(16126, 1)] 0]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15744
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 15776 7 56 0 [(16127, 1)] 0, attempt 15777 8 0 1 [(41520, 124)] 0, attempt 15778 8 1 1 [(41524, 125)] 0, attempt 15779 8 2 1 [(41521, 124)] 0, attempt 15780 8 3 1 [(41525, 125)] 0, attempt 15781 8 4 1 [(41522, 124)] 0, attempt 15782 8 5 1 [(41526, 125)] 0, attempt 15783 8 6 1 [(41523, 124)] 0, attempt 15784 8 7 1 [(41527, 125)] 0, attempt 15785 9 0 1 [(41520, 193), (41524, 194)] 0, attempt 15786 9 1 1 [(41521, 193), (41525, 194)] 0, attempt 15787 9 2 1 [(41522, 193), (41526, 194)] 0, attempt 15788 9 3 1 [(41523, 193), (41527, 194)] 0, attempt 15789 10 0 0 [(18112, 1), (41520, 196), (41524, 197)] 0, attempt 15790 10 1 0 [(18176, 1), (41521, 196), (41525, 197)] 0, attempt 15791 10 2 0 [(18240, 1), (41522, 196), (41526, 197)] 0, attempt 15792 10 3 0 [(18304, 1), (41523, 196), (41527, 197)] 0, attempt 15793 10 4 0 [(18368, 1)] 0, attempt 15794 10 5 0 [(18432, 1)] 0, attempt 15795 10 6 0 [(18496, 1)] 0, attempt 15796 10 7 0 [(18560, 1)] 0, attempt 15797 10 8 0 [(18624, 1)] 2, attempt 15798 10 9 0 [(18688, 1)] 128, attempt 15799 10 10 0 [(18752, 1)] 543, attempt 15800 10 11 0 [(18816, 1)] 1, attempt 15801 10 12 0 [(18880, 1)] 0, attempt 15802 10 13 0 [(18944, 1)] 0, attempt 15803 10 14 0 [(19008, 1)] 0, attempt 15804 10 15 0 [(19072, 1)] 544, attempt 15805 11 0 0 [(6720, 1), (28736, 3)] 0, attempt 15806 11 1 0 [(6784, 1), (28800, 3)] 0, attempt 15807 11 2 0 [(6848, 1), (28864, 3)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15776
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 15808 11 3 0 [(6912, 1), (28928, 3)] 0, attempt 15809 11 4 0 [(6976, 1), (28992, 3)] 0, attempt 15810 12 0 0 [(18113, 1), (0, 158)] 0, attempt 15811 12 1 0 [(18177, 1), (64, 158)] 0, attempt 15812 12 2 0 [(18625, 1)] 1, attempt 15813 12 3 0 [(18689, 1)] 414, attempt 15814 12 4 0 [(18753, 1)] 543, attempt 15815 12 5 0 [(18817, 1)] 0, attempt 15816 12 6 0 [(18881, 1)] 0, attempt 15817 12 7 0 [(18945, 1)] 0, attempt 15818 12 8 0 [(19009, 1)] 0, attempt 15819 12 9 0 [(19073, 1)] 544, attempt 15820 12 10 0 [(18498, 1), (29121, 158), (6208, 158)] 0, attempt 15821 12 11 0 [(18562, 1), (29185, 158), (6272, 158)] 0, attempt 15822 12 12 0 [(18626, 1), (29249, 158)] 0, attempt 15823 12 13 0 [(18690, 1), (29313, 158)] 0, attempt 15824 12 14 0 [(18754, 1), (29377, 158)] 0, attempt 15825 12 15 0 [(18818, 1), (29441, 158)] 0, attempt 15826 12 16 0 [(18882, 1), (29505, 158)] 0, attempt 15827 12 17 0 [(18946, 1), (29569, 158)] 0, attempt 15828 12 18 0 [(19010, 1), (29633, 158)] 0, attempt 15829 12 19 0 [(19074, 1), (29697, 158)] 0, attempt 15830 12 20 0 [(18115, 1), (28738, 158), (6336, 158)] 0, attempt 15831 12 21 0 [(18179, 1), (28802, 158), (6400, 158)] 0, attempt 15832 12 22 0 [(18243, 1), (28866, 158)] 0, attempt 15833 12 23 0 [(18307, 1), (28930, 158)] 0, attempt 15834 12 24 0 [(18371, 1), (28994, 158)] 0, attempt 15835 12 25 0 [(18435, 1), (29058, 158)] 0, attempt 15836 12 26 0 [(18499, 1), (29122, 158)] 0, attempt 15837 12 27 0 [(18563, 1), (29186, 158)] 0, attempt 15838 12 28 0 [(18627, 1), (29250, 158)] 0, attempt 15839 12 29 0 [(18691, 1), (29314, 158)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15808
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 15840 12 30 0 [(18755, 1), (29378, 158)] 0, attempt 15841 12 31 0 [(18819, 1), (29442, 158)] 1, attempt 15842 12 32 0 [(18883, 1), (29506, 158)] 0, attempt 15843 12 33 0 [(18947, 1), (29570, 158)] 0, attempt 15844 12 34 0 [(19011, 1), (29634, 158)] 0, attempt 15845 12 35 0 [(19075, 1), (29698, 158)] 0, attempt 15846 12 36 0 [(18149, 1), (2176, 158)] 0, attempt 15847 12 37 0 [(18213, 1), (2240, 158)] 0, attempt 15848 12 38 0 [(18661, 1)] 1, attempt 15849 12 39 0 [(18725, 1)] 414, attempt 15850 12 40 0 [(18789, 1)] 543, attempt 15851 12 41 0 [(18853, 1)] 0, attempt 15852 12 42 0 [(18917, 1)] 0, attempt 15853 12 43 0 [(18981, 1)] 0, attempt 15854 12 44 0 [(19045, 1)] 0, attempt 15855 12 45 0 [(19109, 1)] 544, attempt 15856 12 46 0 [(18534, 1), (29157, 158), (6464, 158)] 0, attempt 15857 12 47 0 [(18598, 1), (29221, 158), (6528, 158)] 0, attempt 15858 12 48 0 [(18662, 1), (29285, 158)] 0, attempt 15859 12 49 0 [(18726, 1), (29349, 158)] 0, attempt 15860 12 50 0 [(18790, 1), (29413, 158)] 0, attempt 15861 12 51 0 [(18854, 1), (29477, 158)] 0, attempt 15862 12 52 0 [(18918, 1), (29541, 158)] 0, attempt 15863 12 53 0 [(18982, 1), (29605, 158)] 0, attempt 15864 12 54 0 [(19046, 1), (29669, 158)] 0, attempt 15865 12 55 0 [(19110, 1), (29733, 158)] 0, attempt 15866 12 56 0 [(18151, 1), (28774, 158), (6592, 158)] 0, attempt 15867 12 57 0 [(18215, 1), (28838, 158), (6656, 158)] 0, attempt 15868 12 58 0 [(18279, 1), (28902, 158)] 0, attempt 15869 12 59 0 [(18343, 1), (28966, 158)] 0, attempt 15870 12 60 0 [(18407, 1), (29030, 158)] 0, attempt 15871 12 61 0 [(18471, 1), (29094, 158)] 0]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15840
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15872
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15840
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 15840 15872 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 15840) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15808
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 15808 15840 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 15808) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15776
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 15776 15808 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 15776) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15744
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 15744 15776 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 15744) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15712
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 15712 15744 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 15712) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15680
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 15680 15712 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 15680) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15648
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 15648 15680 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 15648) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15616
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 15616 15648 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 15616) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15584
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 15584 15616 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 15584) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15552
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 15552 15584 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 15552) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15520
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 15520 15552 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 15520) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15488
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 15488 15520 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 15488) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15456
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 15456 15488 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 15456) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15424
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 15424 15456 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 15424) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15392
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 15392 15424 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 15392) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 15360
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 15360 15392 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 15360) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr30
