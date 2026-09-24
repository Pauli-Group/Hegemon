import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr00

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr01
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 512 0 512 0 [(521, 1), (512, 3)] 0, attempt 513 0 513 0 [(522, 1), (512, 3)] 0, attempt 514 0 514 0 [(523, 1), (512, 3)] 0, attempt 515 0 515 0 [(524, 1), (512, 3)] 0, attempt 516 0 516 0 [(525, 1), (512, 3)] 0, attempt 517 0 517 0 [(526, 1), (512, 3)] 0, attempt 518 0 518 0 [(527, 1), (512, 3)] 0, attempt 519 0 519 0 [(528, 1), (512, 3)] 0, attempt 520 0 520 0 [(529, 1), (512, 3)] 0, attempt 521 0 521 0 [(530, 1), (512, 3)] 0, attempt 522 0 522 0 [(531, 1), (512, 3)] 0, attempt 523 0 523 0 [(532, 1), (512, 3)] 0, attempt 524 0 524 0 [(533, 1), (512, 3)] 0, attempt 525 0 525 0 [(534, 1), (512, 3)] 0, attempt 526 0 526 0 [(535, 1), (512, 3)] 0, attempt 527 0 527 0 [(536, 1), (512, 3)] 0, attempt 528 0 528 0 [(537, 1), (512, 3)] 0, attempt 529 0 529 0 [(538, 1), (512, 3)] 0, attempt 530 0 530 0 [(539, 1), (512, 3)] 0, attempt 531 0 531 0 [(540, 1), (512, 3)] 0, attempt 532 0 532 0 [(541, 1), (512, 3)] 0, attempt 533 0 533 0 [(542, 1), (512, 3)] 0, attempt 534 0 534 0 [(543, 1), (512, 3)] 0, attempt 535 0 535 0 [(544, 1), (512, 3)] 0, attempt 536 0 536 0 [(545, 1), (512, 3)] 0, attempt 537 0 537 0 [(546, 1), (512, 3)] 0, attempt 538 0 538 0 [(547, 1), (512, 3)] 0, attempt 539 0 539 0 [(548, 1), (512, 3)] 0, attempt 540 0 540 0 [(549, 1), (512, 3)] 0, attempt 541 0 541 0 [(550, 1), (512, 3)] 0, attempt 542 0 542 0 [(551, 1), (512, 3)] 0, attempt 543 0 543 0 [(552, 1), (512, 3)] 0]
def counters001 : List Nat := [544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 512
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 544 0 544 0 [(553, 1), (512, 3)] 0, attempt 545 0 545 0 [(554, 1), (512, 3)] 0, attempt 546 0 546 0 [(555, 1), (512, 3)] 0, attempt 547 0 547 0 [(556, 1), (512, 3)] 0, attempt 548 0 548 0 [(557, 1), (512, 3)] 0, attempt 549 0 549 0 [(558, 1), (512, 3)] 0, attempt 550 0 550 0 [(559, 1), (512, 3)] 0, attempt 551 0 551 0 [(560, 1), (512, 3)] 0, attempt 552 0 552 0 [(561, 1), (512, 3)] 0, attempt 553 0 553 0 [(562, 1), (512, 3)] 0, attempt 554 0 554 0 [(563, 1), (512, 3)] 0, attempt 555 0 555 0 [(564, 1), (512, 3)] 0, attempt 556 0 556 0 [(565, 1), (512, 3)] 0, attempt 557 0 557 0 [(566, 1), (512, 3)] 0, attempt 558 0 558 0 [(567, 1), (512, 3)] 0, attempt 559 0 559 0 [(568, 1), (512, 3)] 0, attempt 560 0 560 0 [(569, 1), (512, 3)] 0, attempt 561 0 561 0 [(570, 1), (512, 3)] 0, attempt 562 0 562 0 [(571, 1), (512, 3)] 0, attempt 563 0 563 0 [(572, 1), (512, 3)] 0, attempt 564 0 564 0 [(573, 1), (512, 3)] 0, attempt 565 0 565 0 [(574, 1), (512, 3)] 0, attempt 566 0 566 0 [(575, 1), (512, 3)] 0, attempt 567 0 567 0 [(577, 1), (576, 3)] 0, attempt 568 0 568 0 [(578, 1), (576, 3)] 0, attempt 569 0 569 0 [(579, 1), (576, 3)] 0, attempt 570 0 570 0 [(580, 1), (576, 3)] 0, attempt 571 0 571 0 [(581, 1), (576, 3)] 0, attempt 572 0 572 0 [(582, 1), (576, 3)] 0, attempt 573 0 573 0 [(583, 1), (576, 3)] 0, attempt 574 0 574 0 [(584, 1), (576, 3)] 0, attempt 575 0 575 0 [(585, 1), (576, 3)] 0]
def counters002 : List Nat := [576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 544
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 576 0 576 0 [(586, 1), (576, 3)] 0, attempt 577 0 577 0 [(587, 1), (576, 3)] 0, attempt 578 0 578 0 [(588, 1), (576, 3)] 0, attempt 579 0 579 0 [(589, 1), (576, 3)] 0, attempt 580 0 580 0 [(590, 1), (576, 3)] 0, attempt 581 0 581 0 [(591, 1), (576, 3)] 0, attempt 582 0 582 0 [(592, 1), (576, 3)] 0, attempt 583 0 583 0 [(593, 1), (576, 3)] 0, attempt 584 0 584 0 [(594, 1), (576, 3)] 0, attempt 585 0 585 0 [(595, 1), (576, 3)] 0, attempt 586 0 586 0 [(596, 1), (576, 3)] 0, attempt 587 0 587 0 [(597, 1), (576, 3)] 0, attempt 588 0 588 0 [(598, 1), (576, 3)] 0, attempt 589 0 589 0 [(599, 1), (576, 3)] 0, attempt 590 0 590 0 [(600, 1), (576, 3)] 0, attempt 591 0 591 0 [(601, 1), (576, 3)] 0, attempt 592 0 592 0 [(602, 1), (576, 3)] 0, attempt 593 0 593 0 [(603, 1), (576, 3)] 0, attempt 594 0 594 0 [(604, 1), (576, 3)] 0, attempt 595 0 595 0 [(605, 1), (576, 3)] 0, attempt 596 0 596 0 [(606, 1), (576, 3)] 0, attempt 597 0 597 0 [(607, 1), (576, 3)] 0, attempt 598 0 598 0 [(608, 1), (576, 3)] 0, attempt 599 0 599 0 [(609, 1), (576, 3)] 0, attempt 600 0 600 0 [(610, 1), (576, 3)] 0, attempt 601 0 601 0 [(611, 1), (576, 3)] 0, attempt 602 0 602 0 [(612, 1), (576, 3)] 0, attempt 603 0 603 0 [(613, 1), (576, 3)] 0, attempt 604 0 604 0 [(614, 1), (576, 3)] 0, attempt 605 0 605 0 [(615, 1), (576, 3)] 0, attempt 606 0 606 0 [(616, 1), (576, 3)] 0, attempt 607 0 607 0 [(617, 1), (576, 3)] 0]
def counters003 : List Nat := [608, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 576
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 608 0 608 0 [(618, 1), (576, 3)] 0, attempt 609 0 609 0 [(619, 1), (576, 3)] 0, attempt 610 0 610 0 [(620, 1), (576, 3)] 0, attempt 611 0 611 0 [(621, 1), (576, 3)] 0, attempt 612 0 612 0 [(622, 1), (576, 3)] 0, attempt 613 0 613 0 [(623, 1), (576, 3)] 0, attempt 614 0 614 0 [(624, 1), (576, 3)] 0, attempt 615 0 615 0 [(625, 1), (576, 3)] 0, attempt 616 0 616 0 [(626, 1), (576, 3)] 0, attempt 617 0 617 0 [(627, 1), (576, 3)] 0, attempt 618 0 618 0 [(628, 1), (576, 3)] 0, attempt 619 0 619 0 [(629, 1), (576, 3)] 0, attempt 620 0 620 0 [(630, 1), (576, 3)] 0, attempt 621 0 621 0 [(631, 1), (576, 3)] 0, attempt 622 0 622 0 [(632, 1), (576, 3)] 0, attempt 623 0 623 0 [(633, 1), (576, 3)] 0, attempt 624 0 624 0 [(634, 1), (576, 3)] 0, attempt 625 0 625 0 [(635, 1), (576, 3)] 0, attempt 626 0 626 0 [(636, 1), (576, 3)] 0, attempt 627 0 627 0 [(637, 1), (576, 3)] 0, attempt 628 0 628 0 [(638, 1), (576, 3)] 0, attempt 629 0 629 0 [(639, 1), (576, 3)] 0, attempt 630 0 630 0 [(641, 1), (640, 3)] 0, attempt 631 0 631 0 [(642, 1), (640, 3)] 0, attempt 632 0 632 0 [(643, 1), (640, 3)] 0, attempt 633 0 633 0 [(644, 1), (640, 3)] 0, attempt 634 0 634 0 [(645, 1), (640, 3)] 0, attempt 635 0 635 0 [(646, 1), (640, 3)] 0, attempt 636 0 636 0 [(647, 1), (640, 3)] 0, attempt 637 0 637 0 [(648, 1), (640, 3)] 0, attempt 638 0 638 0 [(649, 1), (640, 3)] 0, attempt 639 0 639 0 [(650, 1), (640, 3)] 0]
def counters004 : List Nat := [640, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 608
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 640 0 640 0 [(651, 1), (640, 3)] 0, attempt 641 0 641 0 [(652, 1), (640, 3)] 0, attempt 642 0 642 0 [(653, 1), (640, 3)] 0, attempt 643 0 643 0 [(654, 1), (640, 3)] 0, attempt 644 0 644 0 [(655, 1), (640, 3)] 0, attempt 645 0 645 0 [(656, 1), (640, 3)] 0, attempt 646 0 646 0 [(657, 1), (640, 3)] 0, attempt 647 0 647 0 [(658, 1), (640, 3)] 0, attempt 648 0 648 0 [(659, 1), (640, 3)] 0, attempt 649 0 649 0 [(660, 1), (640, 3)] 0, attempt 650 0 650 0 [(661, 1), (640, 3)] 0, attempt 651 0 651 0 [(662, 1), (640, 3)] 0, attempt 652 0 652 0 [(663, 1), (640, 3)] 0, attempt 653 0 653 0 [(664, 1), (640, 3)] 0, attempt 654 0 654 0 [(665, 1), (640, 3)] 0, attempt 655 0 655 0 [(666, 1), (640, 3)] 0, attempt 656 0 656 0 [(667, 1), (640, 3)] 0, attempt 657 0 657 0 [(668, 1), (640, 3)] 0, attempt 658 0 658 0 [(669, 1), (640, 3)] 0, attempt 659 0 659 0 [(670, 1), (640, 3)] 0, attempt 660 0 660 0 [(671, 1), (640, 3)] 0, attempt 661 0 661 0 [(672, 1), (640, 3)] 0, attempt 662 0 662 0 [(673, 1), (640, 3)] 0, attempt 663 0 663 0 [(674, 1), (640, 3)] 0, attempt 664 0 664 0 [(675, 1), (640, 3)] 0, attempt 665 0 665 0 [(676, 1), (640, 3)] 0, attempt 666 0 666 0 [(677, 1), (640, 3)] 0, attempt 667 0 667 0 [(678, 1), (640, 3)] 0, attempt 668 0 668 0 [(679, 1), (640, 3)] 0, attempt 669 0 669 0 [(680, 1), (640, 3)] 0, attempt 670 0 670 0 [(681, 1), (640, 3)] 0, attempt 671 0 671 0 [(682, 1), (640, 3)] 0]
def counters005 : List Nat := [672, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 640
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 672 0 672 0 [(683, 1), (640, 3)] 0, attempt 673 0 673 0 [(684, 1), (640, 3)] 0, attempt 674 0 674 0 [(685, 1), (640, 3)] 0, attempt 675 0 675 0 [(686, 1), (640, 3)] 0, attempt 676 0 676 0 [(687, 1), (640, 3)] 0, attempt 677 0 677 0 [(688, 1), (640, 3)] 0, attempt 678 0 678 0 [(689, 1), (640, 3)] 0, attempt 679 0 679 0 [(690, 1), (640, 3)] 0, attempt 680 0 680 0 [(691, 1), (640, 3)] 0, attempt 681 0 681 0 [(692, 1), (640, 3)] 0, attempt 682 0 682 0 [(693, 1), (640, 3)] 0, attempt 683 0 683 0 [(694, 1), (640, 3)] 0, attempt 684 0 684 0 [(695, 1), (640, 3)] 0, attempt 685 0 685 0 [(696, 1), (640, 3)] 0, attempt 686 0 686 0 [(697, 1), (640, 3)] 0, attempt 687 0 687 0 [(698, 1), (640, 3)] 0, attempt 688 0 688 0 [(699, 1), (640, 3)] 0, attempt 689 0 689 0 [(700, 1), (640, 3)] 0, attempt 690 0 690 0 [(701, 1), (640, 3)] 0, attempt 691 0 691 0 [(702, 1), (640, 3)] 0, attempt 692 0 692 0 [(703, 1), (640, 3)] 0, attempt 693 0 693 0 [(705, 1), (704, 3)] 0, attempt 694 0 694 0 [(706, 1), (704, 3)] 0, attempt 695 0 695 0 [(707, 1), (704, 3)] 0, attempt 696 0 696 0 [(708, 1), (704, 3)] 0, attempt 697 0 697 0 [(709, 1), (704, 3)] 0, attempt 698 0 698 0 [(710, 1), (704, 3)] 0, attempt 699 0 699 0 [(711, 1), (704, 3)] 0, attempt 700 0 700 0 [(712, 1), (704, 3)] 0, attempt 701 0 701 0 [(713, 1), (704, 3)] 0, attempt 702 0 702 0 [(714, 1), (704, 3)] 0, attempt 703 0 703 0 [(715, 1), (704, 3)] 0]
def counters006 : List Nat := [704, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 672
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 704 0 704 0 [(716, 1), (704, 3)] 0, attempt 705 0 705 0 [(717, 1), (704, 3)] 0, attempt 706 0 706 0 [(718, 1), (704, 3)] 0, attempt 707 0 707 0 [(719, 1), (704, 3)] 0, attempt 708 0 708 0 [(720, 1), (704, 3)] 0, attempt 709 0 709 0 [(721, 1), (704, 3)] 0, attempt 710 0 710 0 [(722, 1), (704, 3)] 0, attempt 711 0 711 0 [(723, 1), (704, 3)] 0, attempt 712 0 712 0 [(724, 1), (704, 3)] 0, attempt 713 0 713 0 [(725, 1), (704, 3)] 0, attempt 714 0 714 0 [(726, 1), (704, 3)] 0, attempt 715 0 715 0 [(727, 1), (704, 3)] 0, attempt 716 0 716 0 [(728, 1), (704, 3)] 0, attempt 717 0 717 0 [(729, 1), (704, 3)] 0, attempt 718 0 718 0 [(730, 1), (704, 3)] 0, attempt 719 0 719 0 [(731, 1), (704, 3)] 0, attempt 720 0 720 0 [(732, 1), (704, 3)] 0, attempt 721 0 721 0 [(733, 1), (704, 3)] 0, attempt 722 0 722 0 [(734, 1), (704, 3)] 0, attempt 723 0 723 0 [(735, 1), (704, 3)] 0, attempt 724 0 724 0 [(736, 1), (704, 3)] 0, attempt 725 0 725 0 [(737, 1), (704, 3)] 0, attempt 726 0 726 0 [(738, 1), (704, 3)] 0, attempt 727 0 727 0 [(739, 1), (704, 3)] 0, attempt 728 0 728 0 [(740, 1), (704, 3)] 0, attempt 729 0 729 0 [(741, 1), (704, 3)] 0, attempt 730 0 730 0 [(742, 1), (704, 3)] 0, attempt 731 0 731 0 [(743, 1), (704, 3)] 0, attempt 732 0 732 0 [(744, 1), (704, 3)] 0, attempt 733 0 733 0 [(745, 1), (704, 3)] 0, attempt 734 0 734 0 [(746, 1), (704, 3)] 0, attempt 735 0 735 0 [(747, 1), (704, 3)] 0]
def counters007 : List Nat := [736, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 704
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 736 0 736 0 [(748, 1), (704, 3)] 0, attempt 737 0 737 0 [(749, 1), (704, 3)] 0, attempt 738 0 738 0 [(750, 1), (704, 3)] 0, attempt 739 0 739 0 [(751, 1), (704, 3)] 0, attempt 740 0 740 0 [(752, 1), (704, 3)] 0, attempt 741 0 741 0 [(753, 1), (704, 3)] 0, attempt 742 0 742 0 [(754, 1), (704, 3)] 0, attempt 743 0 743 0 [(755, 1), (704, 3)] 0, attempt 744 0 744 0 [(756, 1), (704, 3)] 0, attempt 745 0 745 0 [(757, 1), (704, 3)] 0, attempt 746 0 746 0 [(758, 1), (704, 3)] 0, attempt 747 0 747 0 [(759, 1), (704, 3)] 0, attempt 748 0 748 0 [(760, 1), (704, 3)] 0, attempt 749 0 749 0 [(761, 1), (704, 3)] 0, attempt 750 0 750 0 [(762, 1), (704, 3)] 0, attempt 751 0 751 0 [(763, 1), (704, 3)] 0, attempt 752 0 752 0 [(764, 1), (704, 3)] 0, attempt 753 0 753 0 [(765, 1), (704, 3)] 0, attempt 754 0 754 0 [(766, 1), (704, 3)] 0, attempt 755 0 755 0 [(767, 1), (704, 3)] 0, attempt 756 0 756 0 [(769, 1), (768, 3)] 0, attempt 757 0 757 0 [(770, 1), (768, 3)] 0, attempt 758 0 758 0 [(771, 1), (768, 3)] 0, attempt 759 0 759 0 [(772, 1), (768, 3)] 0, attempt 760 0 760 0 [(773, 1), (768, 3)] 0, attempt 761 0 761 0 [(774, 1), (768, 3)] 0, attempt 762 0 762 0 [(775, 1), (768, 3)] 0, attempt 763 0 763 0 [(776, 1), (768, 3)] 0, attempt 764 0 764 0 [(777, 1), (768, 3)] 0, attempt 765 0 765 0 [(778, 1), (768, 3)] 0, attempt 766 0 766 0 [(779, 1), (768, 3)] 0, attempt 767 0 767 0 [(780, 1), (768, 3)] 0]
def counters008 : List Nat := [768, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 736
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 768 0 768 0 [(781, 1), (768, 3)] 0, attempt 769 0 769 0 [(782, 1), (768, 3)] 0, attempt 770 0 770 0 [(783, 1), (768, 3)] 0, attempt 771 0 771 0 [(784, 1), (768, 3)] 0, attempt 772 0 772 0 [(785, 1), (768, 3)] 0, attempt 773 0 773 0 [(786, 1), (768, 3)] 0, attempt 774 0 774 0 [(787, 1), (768, 3)] 0, attempt 775 0 775 0 [(788, 1), (768, 3)] 0, attempt 776 0 776 0 [(789, 1), (768, 3)] 0, attempt 777 0 777 0 [(790, 1), (768, 3)] 0, attempt 778 0 778 0 [(791, 1), (768, 3)] 0, attempt 779 0 779 0 [(792, 1), (768, 3)] 0, attempt 780 0 780 0 [(793, 1), (768, 3)] 0, attempt 781 0 781 0 [(794, 1), (768, 3)] 0, attempt 782 0 782 0 [(795, 1), (768, 3)] 0, attempt 783 0 783 0 [(796, 1), (768, 3)] 0, attempt 784 0 784 0 [(797, 1), (768, 3)] 0, attempt 785 0 785 0 [(798, 1), (768, 3)] 0, attempt 786 0 786 0 [(799, 1), (768, 3)] 0, attempt 787 0 787 0 [(800, 1), (768, 3)] 0, attempt 788 0 788 0 [(801, 1), (768, 3)] 0, attempt 789 0 789 0 [(802, 1), (768, 3)] 0, attempt 790 0 790 0 [(803, 1), (768, 3)] 0, attempt 791 0 791 0 [(804, 1), (768, 3)] 0, attempt 792 0 792 0 [(805, 1), (768, 3)] 0, attempt 793 0 793 0 [(806, 1), (768, 3)] 0, attempt 794 0 794 0 [(807, 1), (768, 3)] 0, attempt 795 0 795 0 [(808, 1), (768, 3)] 0, attempt 796 0 796 0 [(809, 1), (768, 3)] 0, attempt 797 0 797 0 [(810, 1), (768, 3)] 0, attempt 798 0 798 0 [(811, 1), (768, 3)] 0, attempt 799 0 799 0 [(812, 1), (768, 3)] 0]
def counters009 : List Nat := [800, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 768
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 800 0 800 0 [(813, 1), (768, 3)] 0, attempt 801 0 801 0 [(814, 1), (768, 3)] 0, attempt 802 0 802 0 [(815, 1), (768, 3)] 0, attempt 803 0 803 0 [(816, 1), (768, 3)] 0, attempt 804 0 804 0 [(817, 1), (768, 3)] 0, attempt 805 0 805 0 [(818, 1), (768, 3)] 0, attempt 806 0 806 0 [(819, 1), (768, 3)] 0, attempt 807 0 807 0 [(820, 1), (768, 3)] 0, attempt 808 0 808 0 [(821, 1), (768, 3)] 0, attempt 809 0 809 0 [(822, 1), (768, 3)] 0, attempt 810 0 810 0 [(823, 1), (768, 3)] 0, attempt 811 0 811 0 [(824, 1), (768, 3)] 0, attempt 812 0 812 0 [(825, 1), (768, 3)] 0, attempt 813 0 813 0 [(826, 1), (768, 3)] 0, attempt 814 0 814 0 [(827, 1), (768, 3)] 0, attempt 815 0 815 0 [(828, 1), (768, 3)] 0, attempt 816 0 816 0 [(829, 1), (768, 3)] 0, attempt 817 0 817 0 [(830, 1), (768, 3)] 0, attempt 818 0 818 0 [(831, 1), (768, 3)] 0, attempt 819 0 819 0 [(833, 1), (832, 3)] 0, attempt 820 0 820 0 [(834, 1), (832, 3)] 0, attempt 821 0 821 0 [(835, 1), (832, 3)] 0, attempt 822 0 822 0 [(836, 1), (832, 3)] 0, attempt 823 0 823 0 [(837, 1), (832, 3)] 0, attempt 824 0 824 0 [(838, 1), (832, 3)] 0, attempt 825 0 825 0 [(839, 1), (832, 3)] 0, attempt 826 0 826 0 [(840, 1), (832, 3)] 0, attempt 827 0 827 0 [(841, 1), (832, 3)] 0, attempt 828 0 828 0 [(842, 1), (832, 3)] 0, attempt 829 0 829 0 [(843, 1), (832, 3)] 0, attempt 830 0 830 0 [(844, 1), (832, 3)] 0, attempt 831 0 831 0 [(845, 1), (832, 3)] 0]
def counters010 : List Nat := [832, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 800
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 832 0 832 0 [(846, 1), (832, 3)] 0, attempt 833 0 833 0 [(847, 1), (832, 3)] 0, attempt 834 0 834 0 [(848, 1), (832, 3)] 0, attempt 835 0 835 0 [(849, 1), (832, 3)] 0, attempt 836 0 836 0 [(850, 1), (832, 3)] 0, attempt 837 0 837 0 [(851, 1), (832, 3)] 0, attempt 838 0 838 0 [(852, 1), (832, 3)] 0, attempt 839 0 839 0 [(853, 1), (832, 3)] 0, attempt 840 0 840 0 [(854, 1), (832, 3)] 0, attempt 841 0 841 0 [(855, 1), (832, 3)] 0, attempt 842 0 842 0 [(856, 1), (832, 3)] 0, attempt 843 0 843 0 [(857, 1), (832, 3)] 0, attempt 844 0 844 0 [(858, 1), (832, 3)] 0, attempt 845 0 845 0 [(859, 1), (832, 3)] 0, attempt 846 0 846 0 [(860, 1), (832, 3)] 0, attempt 847 0 847 0 [(861, 1), (832, 3)] 0, attempt 848 0 848 0 [(862, 1), (832, 3)] 0, attempt 849 0 849 0 [(863, 1), (832, 3)] 0, attempt 850 0 850 0 [(864, 1), (832, 3)] 0, attempt 851 0 851 0 [(865, 1), (832, 3)] 0, attempt 852 0 852 0 [(866, 1), (832, 3)] 0, attempt 853 0 853 0 [(867, 1), (832, 3)] 0, attempt 854 0 854 0 [(868, 1), (832, 3)] 0, attempt 855 0 855 0 [(869, 1), (832, 3)] 0, attempt 856 0 856 0 [(870, 1), (832, 3)] 0, attempt 857 0 857 0 [(871, 1), (832, 3)] 0, attempt 858 0 858 0 [(872, 1), (832, 3)] 0, attempt 859 0 859 0 [(873, 1), (832, 3)] 0, attempt 860 0 860 0 [(874, 1), (832, 3)] 0, attempt 861 0 861 0 [(875, 1), (832, 3)] 0, attempt 862 0 862 0 [(876, 1), (832, 3)] 0, attempt 863 0 863 0 [(877, 1), (832, 3)] 0]
def counters011 : List Nat := [864, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 832
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 864 0 864 0 [(878, 1), (832, 3)] 0, attempt 865 0 865 0 [(879, 1), (832, 3)] 0, attempt 866 0 866 0 [(880, 1), (832, 3)] 0, attempt 867 0 867 0 [(881, 1), (832, 3)] 0, attempt 868 0 868 0 [(882, 1), (832, 3)] 0, attempt 869 0 869 0 [(883, 1), (832, 3)] 0, attempt 870 0 870 0 [(884, 1), (832, 3)] 0, attempt 871 0 871 0 [(885, 1), (832, 3)] 0, attempt 872 0 872 0 [(886, 1), (832, 3)] 0, attempt 873 0 873 0 [(887, 1), (832, 3)] 0, attempt 874 0 874 0 [(888, 1), (832, 3)] 0, attempt 875 0 875 0 [(889, 1), (832, 3)] 0, attempt 876 0 876 0 [(890, 1), (832, 3)] 0, attempt 877 0 877 0 [(891, 1), (832, 3)] 0, attempt 878 0 878 0 [(892, 1), (832, 3)] 0, attempt 879 0 879 0 [(893, 1), (832, 3)] 0, attempt 880 0 880 0 [(894, 1), (832, 3)] 0, attempt 881 0 881 0 [(895, 1), (832, 3)] 0, attempt 882 0 882 0 [(897, 1), (896, 3)] 0, attempt 883 0 883 0 [(898, 1), (896, 3)] 0, attempt 884 0 884 0 [(899, 1), (896, 3)] 0, attempt 885 0 885 0 [(900, 1), (896, 3)] 0, attempt 886 0 886 0 [(901, 1), (896, 3)] 0, attempt 887 0 887 0 [(902, 1), (896, 3)] 0, attempt 888 0 888 0 [(903, 1), (896, 3)] 0, attempt 889 0 889 0 [(904, 1), (896, 3)] 0, attempt 890 0 890 0 [(905, 1), (896, 3)] 0, attempt 891 0 891 0 [(906, 1), (896, 3)] 0, attempt 892 0 892 0 [(907, 1), (896, 3)] 0, attempt 893 0 893 0 [(908, 1), (896, 3)] 0, attempt 894 0 894 0 [(909, 1), (896, 3)] 0, attempt 895 0 895 0 [(910, 1), (896, 3)] 0]
def counters012 : List Nat := [896, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 864
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 896 0 896 0 [(911, 1), (896, 3)] 0, attempt 897 0 897 0 [(912, 1), (896, 3)] 0, attempt 898 0 898 0 [(913, 1), (896, 3)] 0, attempt 899 0 899 0 [(914, 1), (896, 3)] 0, attempt 900 0 900 0 [(915, 1), (896, 3)] 0, attempt 901 0 901 0 [(916, 1), (896, 3)] 0, attempt 902 0 902 0 [(917, 1), (896, 3)] 0, attempt 903 0 903 0 [(918, 1), (896, 3)] 0, attempt 904 0 904 0 [(919, 1), (896, 3)] 0, attempt 905 0 905 0 [(920, 1), (896, 3)] 0, attempt 906 0 906 0 [(921, 1), (896, 3)] 0, attempt 907 0 907 0 [(922, 1), (896, 3)] 0, attempt 908 0 908 0 [(923, 1), (896, 3)] 0, attempt 909 0 909 0 [(924, 1), (896, 3)] 0, attempt 910 0 910 0 [(925, 1), (896, 3)] 0, attempt 911 0 911 0 [(926, 1), (896, 3)] 0, attempt 912 0 912 0 [(927, 1), (896, 3)] 0, attempt 913 0 913 0 [(928, 1), (896, 3)] 0, attempt 914 0 914 0 [(929, 1), (896, 3)] 0, attempt 915 0 915 0 [(930, 1), (896, 3)] 0, attempt 916 0 916 0 [(931, 1), (896, 3)] 0, attempt 917 0 917 0 [(932, 1), (896, 3)] 0, attempt 918 0 918 0 [(933, 1), (896, 3)] 0, attempt 919 0 919 0 [(934, 1), (896, 3)] 0, attempt 920 0 920 0 [(935, 1), (896, 3)] 0, attempt 921 0 921 0 [(936, 1), (896, 3)] 0, attempt 922 0 922 0 [(937, 1), (896, 3)] 0, attempt 923 0 923 0 [(938, 1), (896, 3)] 0, attempt 924 0 924 0 [(939, 1), (896, 3)] 0, attempt 925 0 925 0 [(940, 1), (896, 3)] 0, attempt 926 0 926 0 [(941, 1), (896, 3)] 0, attempt 927 0 927 0 [(942, 1), (896, 3)] 0]
def counters013 : List Nat := [928, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 896
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 928 0 928 0 [(943, 1), (896, 3)] 0, attempt 929 0 929 0 [(944, 1), (896, 3)] 0, attempt 930 0 930 0 [(945, 1), (896, 3)] 0, attempt 931 0 931 0 [(946, 1), (896, 3)] 0, attempt 932 0 932 0 [(947, 1), (896, 3)] 0, attempt 933 0 933 0 [(948, 1), (896, 3)] 0, attempt 934 0 934 0 [(949, 1), (896, 3)] 0, attempt 935 0 935 0 [(950, 1), (896, 3)] 0, attempt 936 0 936 0 [(951, 1), (896, 3)] 0, attempt 937 0 937 0 [(952, 1), (896, 3)] 0, attempt 938 0 938 0 [(953, 1), (896, 3)] 0, attempt 939 0 939 0 [(954, 1), (896, 3)] 0, attempt 940 0 940 0 [(955, 1), (896, 3)] 0, attempt 941 0 941 0 [(956, 1), (896, 3)] 0, attempt 942 0 942 0 [(957, 1), (896, 3)] 0, attempt 943 0 943 0 [(958, 1), (896, 3)] 0, attempt 944 0 944 0 [(959, 1), (896, 3)] 0, attempt 945 0 945 0 [(961, 1), (960, 3)] 0, attempt 946 0 946 0 [(962, 1), (960, 3)] 0, attempt 947 0 947 0 [(963, 1), (960, 3)] 0, attempt 948 0 948 0 [(964, 1), (960, 3)] 0, attempt 949 0 949 0 [(965, 1), (960, 3)] 0, attempt 950 0 950 0 [(966, 1), (960, 3)] 0, attempt 951 0 951 0 [(967, 1), (960, 3)] 0, attempt 952 0 952 0 [(968, 1), (960, 3)] 0, attempt 953 0 953 0 [(969, 1), (960, 3)] 0, attempt 954 0 954 0 [(970, 1), (960, 3)] 0, attempt 955 0 955 0 [(971, 1), (960, 3)] 0, attempt 956 0 956 0 [(972, 1), (960, 3)] 0, attempt 957 0 957 0 [(973, 1), (960, 3)] 0, attempt 958 0 958 0 [(974, 1), (960, 3)] 0, attempt 959 0 959 0 [(975, 1), (960, 3)] 0]
def counters014 : List Nat := [960, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 928
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 960 0 960 0 [(976, 1), (960, 3)] 0, attempt 961 0 961 0 [(977, 1), (960, 3)] 0, attempt 962 0 962 0 [(978, 1), (960, 3)] 0, attempt 963 0 963 0 [(979, 1), (960, 3)] 0, attempt 964 0 964 0 [(980, 1), (960, 3)] 0, attempt 965 0 965 0 [(981, 1), (960, 3)] 0, attempt 966 0 966 0 [(982, 1), (960, 3)] 0, attempt 967 0 967 0 [(983, 1), (960, 3)] 0, attempt 968 0 968 0 [(984, 1), (960, 3)] 0, attempt 969 0 969 0 [(985, 1), (960, 3)] 0, attempt 970 0 970 0 [(986, 1), (960, 3)] 0, attempt 971 0 971 0 [(987, 1), (960, 3)] 0, attempt 972 0 972 0 [(988, 1), (960, 3)] 0, attempt 973 0 973 0 [(989, 1), (960, 3)] 0, attempt 974 0 974 0 [(990, 1), (960, 3)] 0, attempt 975 0 975 0 [(991, 1), (960, 3)] 0, attempt 976 0 976 0 [(992, 1), (960, 3)] 0, attempt 977 0 977 0 [(993, 1), (960, 3)] 0, attempt 978 0 978 0 [(994, 1), (960, 3)] 0, attempt 979 0 979 0 [(995, 1), (960, 3)] 0, attempt 980 0 980 0 [(996, 1), (960, 3)] 0, attempt 981 0 981 0 [(997, 1), (960, 3)] 0, attempt 982 0 982 0 [(998, 1), (960, 3)] 0, attempt 983 0 983 0 [(999, 1), (960, 3)] 0, attempt 984 0 984 0 [(1000, 1), (960, 3)] 0, attempt 985 0 985 0 [(1001, 1), (960, 3)] 0, attempt 986 0 986 0 [(1002, 1), (960, 3)] 0, attempt 987 0 987 0 [(1003, 1), (960, 3)] 0, attempt 988 0 988 0 [(1004, 1), (960, 3)] 0, attempt 989 0 989 0 [(1005, 1), (960, 3)] 0, attempt 990 0 990 0 [(1006, 1), (960, 3)] 0, attempt 991 0 991 0 [(1007, 1), (960, 3)] 0]
def counters015 : List Nat := [992, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 960
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 992 0 992 0 [(1008, 1), (960, 3)] 0, attempt 993 0 993 0 [(1009, 1), (960, 3)] 0, attempt 994 0 994 0 [(1010, 1), (960, 3)] 0, attempt 995 0 995 0 [(1011, 1), (960, 3)] 0, attempt 996 0 996 0 [(1012, 1), (960, 3)] 0, attempt 997 0 997 0 [(1013, 1), (960, 3)] 0, attempt 998 0 998 0 [(1014, 1), (960, 3)] 0, attempt 999 0 999 0 [(1015, 1), (960, 3)] 0, attempt 1000 0 1000 0 [(1016, 1), (960, 3)] 0, attempt 1001 0 1001 0 [(1017, 1), (960, 3)] 0, attempt 1002 0 1002 0 [(1018, 1), (960, 3)] 0, attempt 1003 0 1003 0 [(1019, 1), (960, 3)] 0, attempt 1004 0 1004 0 [(1020, 1), (960, 3)] 0, attempt 1005 0 1005 0 [(1021, 1), (960, 3)] 0, attempt 1006 0 1006 0 [(1022, 1), (960, 3)] 0, attempt 1007 0 1007 0 [(1023, 1), (960, 3)] 0, attempt 1008 0 1008 0 [(1025, 1), (1024, 3)] 0, attempt 1009 0 1009 0 [(1026, 1), (1024, 3)] 0, attempt 1010 0 1010 0 [(1027, 1), (1024, 3)] 0, attempt 1011 0 1011 0 [(1028, 1), (1024, 3)] 0, attempt 1012 0 1012 0 [(1029, 1), (1024, 3)] 0, attempt 1013 0 1013 0 [(1030, 1), (1024, 3)] 0, attempt 1014 0 1014 0 [(1031, 1), (1024, 3)] 0, attempt 1015 0 1015 0 [(1032, 1), (1024, 3)] 0, attempt 1016 0 1016 0 [(1033, 1), (1024, 3)] 0, attempt 1017 0 1017 0 [(1034, 1), (1024, 3)] 0, attempt 1018 0 1018 0 [(1035, 1), (1024, 3)] 0, attempt 1019 0 1019 0 [(1036, 1), (1024, 3)] 0, attempt 1020 0 1020 0 [(1037, 1), (1024, 3)] 0, attempt 1021 0 1021 0 [(1038, 1), (1024, 3)] 0, attempt 1022 0 1022 0 [(1039, 1), (1024, 3)] 0, attempt 1023 0 1023 0 [(1040, 1), (1024, 3)] 0]
def counters016 : List Nat := [1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 992
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1024
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 992
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 992 1024 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 992) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 960
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 960 992 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 960) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 928
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 928 960 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 928) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 896
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 896 928 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 896) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 864
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 864 896 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 864) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 832
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 832 864 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 832) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 800
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 800 832 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 800) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 768
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 768 800 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 768) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 736
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 736 768 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 736) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 704
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 704 736 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 704) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 672
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 672 704 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 672) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 640
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 640 672 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 640) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 608
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 608 640 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 608) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 576
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 576 608 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 576) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 544
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 544 576 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 544) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 512
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 512 544 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 512) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr01
