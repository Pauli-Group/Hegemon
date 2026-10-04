import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr10

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr11
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [5632, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 5632 0 5632 0 [(5722, 1), (5696, 3)] 0, attempt 5633 0 5633 0 [(5723, 1), (5696, 3)] 0, attempt 5634 0 5634 0 [(5724, 1), (5696, 3)] 0, attempt 5635 0 5635 0 [(5725, 1), (5696, 3)] 0, attempt 5636 0 5636 0 [(5726, 1), (5696, 3)] 0, attempt 5637 0 5637 0 [(5727, 1), (5696, 3)] 0, attempt 5638 0 5638 0 [(5728, 1), (5696, 3)] 0, attempt 5639 0 5639 0 [(5729, 1), (5696, 3)] 0, attempt 5640 0 5640 0 [(5730, 1), (5696, 3)] 0, attempt 5641 0 5641 0 [(5731, 1), (5696, 3)] 0, attempt 5642 0 5642 0 [(5732, 1), (5696, 3)] 0, attempt 5643 0 5643 0 [(5733, 1), (5696, 3)] 0, attempt 5644 0 5644 0 [(5734, 1), (5696, 3)] 0, attempt 5645 0 5645 0 [(5735, 1), (5696, 3)] 0, attempt 5646 0 5646 0 [(5736, 1), (5696, 3)] 0, attempt 5647 0 5647 0 [(5737, 1), (5696, 3)] 0, attempt 5648 0 5648 0 [(5738, 1), (5696, 3)] 0, attempt 5649 0 5649 0 [(5739, 1), (5696, 3)] 0, attempt 5650 0 5650 0 [(5740, 1), (5696, 3)] 0, attempt 5651 0 5651 0 [(5741, 1), (5696, 3)] 0, attempt 5652 0 5652 0 [(5742, 1), (5696, 3)] 0, attempt 5653 0 5653 0 [(5743, 1), (5696, 3)] 0, attempt 5654 0 5654 0 [(5744, 1), (5696, 3)] 0, attempt 5655 0 5655 0 [(5745, 1), (5696, 3)] 0, attempt 5656 0 5656 0 [(5746, 1), (5696, 3)] 0, attempt 5657 0 5657 0 [(5747, 1), (5696, 3)] 0, attempt 5658 0 5658 0 [(5748, 1), (5696, 3)] 0, attempt 5659 0 5659 0 [(5749, 1), (5696, 3)] 0, attempt 5660 0 5660 0 [(5750, 1), (5696, 3)] 0, attempt 5661 0 5661 0 [(5751, 1), (5696, 3)] 0, attempt 5662 0 5662 0 [(5752, 1), (5696, 3)] 0, attempt 5663 0 5663 0 [(5753, 1), (5696, 3)] 0]
def counters001 : List Nat := [5664, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5632
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 5664 0 5664 0 [(5754, 1), (5696, 3)] 0, attempt 5665 0 5665 0 [(5755, 1), (5696, 3)] 0, attempt 5666 0 5666 0 [(5756, 1), (5696, 3)] 0, attempt 5667 0 5667 0 [(5757, 1), (5696, 3)] 0, attempt 5668 0 5668 0 [(5758, 1), (5696, 3)] 0, attempt 5669 0 5669 0 [(5759, 1), (5696, 3)] 0, attempt 5670 0 5670 0 [(5761, 1), (5760, 3)] 0, attempt 5671 0 5671 0 [(5762, 1), (5760, 3)] 0, attempt 5672 0 5672 0 [(5763, 1), (5760, 3)] 0, attempt 5673 0 5673 0 [(5764, 1), (5760, 3)] 0, attempt 5674 0 5674 0 [(5765, 1), (5760, 3)] 0, attempt 5675 0 5675 0 [(5766, 1), (5760, 3)] 0, attempt 5676 0 5676 0 [(5767, 1), (5760, 3)] 0, attempt 5677 0 5677 0 [(5768, 1), (5760, 3)] 0, attempt 5678 0 5678 0 [(5769, 1), (5760, 3)] 0, attempt 5679 0 5679 0 [(5770, 1), (5760, 3)] 0, attempt 5680 0 5680 0 [(5771, 1), (5760, 3)] 0, attempt 5681 0 5681 0 [(5772, 1), (5760, 3)] 0, attempt 5682 0 5682 0 [(5773, 1), (5760, 3)] 0, attempt 5683 0 5683 0 [(5774, 1), (5760, 3)] 0, attempt 5684 0 5684 0 [(5775, 1), (5760, 3)] 0, attempt 5685 0 5685 0 [(5776, 1), (5760, 3)] 0, attempt 5686 0 5686 0 [(5777, 1), (5760, 3)] 0, attempt 5687 0 5687 0 [(5778, 1), (5760, 3)] 0, attempt 5688 0 5688 0 [(5779, 1), (5760, 3)] 0, attempt 5689 0 5689 0 [(5780, 1), (5760, 3)] 0, attempt 5690 0 5690 0 [(5781, 1), (5760, 3)] 0, attempt 5691 0 5691 0 [(5782, 1), (5760, 3)] 0, attempt 5692 0 5692 0 [(5783, 1), (5760, 3)] 0, attempt 5693 0 5693 0 [(5784, 1), (5760, 3)] 0, attempt 5694 0 5694 0 [(5785, 1), (5760, 3)] 0, attempt 5695 0 5695 0 [(5786, 1), (5760, 3)] 0]
def counters002 : List Nat := [5696, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5664
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 5696 0 5696 0 [(5787, 1), (5760, 3)] 0, attempt 5697 0 5697 0 [(5788, 1), (5760, 3)] 0, attempt 5698 0 5698 0 [(5789, 1), (5760, 3)] 0, attempt 5699 0 5699 0 [(5790, 1), (5760, 3)] 0, attempt 5700 0 5700 0 [(5791, 1), (5760, 3)] 0, attempt 5701 0 5701 0 [(5792, 1), (5760, 3)] 0, attempt 5702 0 5702 0 [(5793, 1), (5760, 3)] 0, attempt 5703 0 5703 0 [(5794, 1), (5760, 3)] 0, attempt 5704 0 5704 0 [(5795, 1), (5760, 3)] 0, attempt 5705 0 5705 0 [(5796, 1), (5760, 3)] 0, attempt 5706 0 5706 0 [(5797, 1), (5760, 3)] 0, attempt 5707 0 5707 0 [(5798, 1), (5760, 3)] 0, attempt 5708 0 5708 0 [(5799, 1), (5760, 3)] 0, attempt 5709 0 5709 0 [(5800, 1), (5760, 3)] 0, attempt 5710 0 5710 0 [(5801, 1), (5760, 3)] 0, attempt 5711 0 5711 0 [(5802, 1), (5760, 3)] 0, attempt 5712 0 5712 0 [(5803, 1), (5760, 3)] 0, attempt 5713 0 5713 0 [(5804, 1), (5760, 3)] 0, attempt 5714 0 5714 0 [(5805, 1), (5760, 3)] 0, attempt 5715 0 5715 0 [(5806, 1), (5760, 3)] 0, attempt 5716 0 5716 0 [(5807, 1), (5760, 3)] 0, attempt 5717 0 5717 0 [(5808, 1), (5760, 3)] 0, attempt 5718 0 5718 0 [(5809, 1), (5760, 3)] 0, attempt 5719 0 5719 0 [(5810, 1), (5760, 3)] 0, attempt 5720 0 5720 0 [(5811, 1), (5760, 3)] 0, attempt 5721 0 5721 0 [(5812, 1), (5760, 3)] 0, attempt 5722 0 5722 0 [(5813, 1), (5760, 3)] 0, attempt 5723 0 5723 0 [(5814, 1), (5760, 3)] 0, attempt 5724 0 5724 0 [(5815, 1), (5760, 3)] 0, attempt 5725 0 5725 0 [(5816, 1), (5760, 3)] 0, attempt 5726 0 5726 0 [(5817, 1), (5760, 3)] 0, attempt 5727 0 5727 0 [(5818, 1), (5760, 3)] 0]
def counters003 : List Nat := [5728, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5696
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 5728 0 5728 0 [(5819, 1), (5760, 3)] 0, attempt 5729 0 5729 0 [(5820, 1), (5760, 3)] 0, attempt 5730 0 5730 0 [(5821, 1), (5760, 3)] 0, attempt 5731 0 5731 0 [(5822, 1), (5760, 3)] 0, attempt 5732 0 5732 0 [(5823, 1), (5760, 3)] 0, attempt 5733 0 5733 0 [(5825, 1), (5824, 3)] 0, attempt 5734 0 5734 0 [(5826, 1), (5824, 3)] 0, attempt 5735 0 5735 0 [(5827, 1), (5824, 3)] 0, attempt 5736 0 5736 0 [(5828, 1), (5824, 3)] 0, attempt 5737 0 5737 0 [(5829, 1), (5824, 3)] 0, attempt 5738 0 5738 0 [(5830, 1), (5824, 3)] 0, attempt 5739 0 5739 0 [(5831, 1), (5824, 3)] 0, attempt 5740 0 5740 0 [(5832, 1), (5824, 3)] 0, attempt 5741 0 5741 0 [(5833, 1), (5824, 3)] 0, attempt 5742 0 5742 0 [(5834, 1), (5824, 3)] 0, attempt 5743 0 5743 0 [(5835, 1), (5824, 3)] 0, attempt 5744 0 5744 0 [(5836, 1), (5824, 3)] 0, attempt 5745 0 5745 0 [(5837, 1), (5824, 3)] 0, attempt 5746 0 5746 0 [(5838, 1), (5824, 3)] 0, attempt 5747 0 5747 0 [(5839, 1), (5824, 3)] 0, attempt 5748 0 5748 0 [(5840, 1), (5824, 3)] 0, attempt 5749 0 5749 0 [(5841, 1), (5824, 3)] 0, attempt 5750 0 5750 0 [(5842, 1), (5824, 3)] 0, attempt 5751 0 5751 0 [(5843, 1), (5824, 3)] 0, attempt 5752 0 5752 0 [(5844, 1), (5824, 3)] 0, attempt 5753 0 5753 0 [(5845, 1), (5824, 3)] 0, attempt 5754 0 5754 0 [(5846, 1), (5824, 3)] 0, attempt 5755 0 5755 0 [(5847, 1), (5824, 3)] 0, attempt 5756 0 5756 0 [(5848, 1), (5824, 3)] 0, attempt 5757 0 5757 0 [(5849, 1), (5824, 3)] 0, attempt 5758 0 5758 0 [(5850, 1), (5824, 3)] 0, attempt 5759 0 5759 0 [(5851, 1), (5824, 3)] 0]
def counters004 : List Nat := [5760, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5728
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 5760 0 5760 0 [(5852, 1), (5824, 3)] 0, attempt 5761 0 5761 0 [(5853, 1), (5824, 3)] 0, attempt 5762 0 5762 0 [(5854, 1), (5824, 3)] 0, attempt 5763 0 5763 0 [(5855, 1), (5824, 3)] 0, attempt 5764 0 5764 0 [(5856, 1), (5824, 3)] 0, attempt 5765 0 5765 0 [(5857, 1), (5824, 3)] 0, attempt 5766 0 5766 0 [(5858, 1), (5824, 3)] 0, attempt 5767 0 5767 0 [(5859, 1), (5824, 3)] 0, attempt 5768 0 5768 0 [(5860, 1), (5824, 3)] 0, attempt 5769 0 5769 0 [(5861, 1), (5824, 3)] 0, attempt 5770 0 5770 0 [(5862, 1), (5824, 3)] 0, attempt 5771 0 5771 0 [(5863, 1), (5824, 3)] 0, attempt 5772 0 5772 0 [(5864, 1), (5824, 3)] 0, attempt 5773 0 5773 0 [(5865, 1), (5824, 3)] 0, attempt 5774 0 5774 0 [(5866, 1), (5824, 3)] 0, attempt 5775 0 5775 0 [(5867, 1), (5824, 3)] 0, attempt 5776 0 5776 0 [(5868, 1), (5824, 3)] 0, attempt 5777 0 5777 0 [(5869, 1), (5824, 3)] 0, attempt 5778 0 5778 0 [(5870, 1), (5824, 3)] 0, attempt 5779 0 5779 0 [(5871, 1), (5824, 3)] 0, attempt 5780 0 5780 0 [(5872, 1), (5824, 3)] 0, attempt 5781 0 5781 0 [(5873, 1), (5824, 3)] 0, attempt 5782 0 5782 0 [(5874, 1), (5824, 3)] 0, attempt 5783 0 5783 0 [(5875, 1), (5824, 3)] 0, attempt 5784 0 5784 0 [(5876, 1), (5824, 3)] 0, attempt 5785 0 5785 0 [(5877, 1), (5824, 3)] 0, attempt 5786 0 5786 0 [(5878, 1), (5824, 3)] 0, attempt 5787 0 5787 0 [(5879, 1), (5824, 3)] 0, attempt 5788 0 5788 0 [(5880, 1), (5824, 3)] 0, attempt 5789 0 5789 0 [(5881, 1), (5824, 3)] 0, attempt 5790 0 5790 0 [(5882, 1), (5824, 3)] 0, attempt 5791 0 5791 0 [(5883, 1), (5824, 3)] 0]
def counters005 : List Nat := [5792, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5760
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 5792 0 5792 0 [(5884, 1), (5824, 3)] 0, attempt 5793 0 5793 0 [(5885, 1), (5824, 3)] 0, attempt 5794 0 5794 0 [(5886, 1), (5824, 3)] 0, attempt 5795 0 5795 0 [(5887, 1), (5824, 3)] 0, attempt 5796 0 5796 0 [(5889, 1), (5888, 3)] 0, attempt 5797 0 5797 0 [(5890, 1), (5888, 3)] 0, attempt 5798 0 5798 0 [(5891, 1), (5888, 3)] 0, attempt 5799 0 5799 0 [(5892, 1), (5888, 3)] 0, attempt 5800 0 5800 0 [(5893, 1), (5888, 3)] 0, attempt 5801 0 5801 0 [(5894, 1), (5888, 3)] 0, attempt 5802 0 5802 0 [(5895, 1), (5888, 3)] 0, attempt 5803 0 5803 0 [(5896, 1), (5888, 3)] 0, attempt 5804 0 5804 0 [(5897, 1), (5888, 3)] 0, attempt 5805 0 5805 0 [(5898, 1), (5888, 3)] 0, attempt 5806 0 5806 0 [(5899, 1), (5888, 3)] 0, attempt 5807 0 5807 0 [(5900, 1), (5888, 3)] 0, attempt 5808 0 5808 0 [(5901, 1), (5888, 3)] 0, attempt 5809 0 5809 0 [(5902, 1), (5888, 3)] 0, attempt 5810 0 5810 0 [(5903, 1), (5888, 3)] 0, attempt 5811 0 5811 0 [(5904, 1), (5888, 3)] 0, attempt 5812 0 5812 0 [(5905, 1), (5888, 3)] 0, attempt 5813 0 5813 0 [(5906, 1), (5888, 3)] 0, attempt 5814 0 5814 0 [(5907, 1), (5888, 3)] 0, attempt 5815 0 5815 0 [(5908, 1), (5888, 3)] 0, attempt 5816 0 5816 0 [(5909, 1), (5888, 3)] 0, attempt 5817 0 5817 0 [(5910, 1), (5888, 3)] 0, attempt 5818 0 5818 0 [(5911, 1), (5888, 3)] 0, attempt 5819 0 5819 0 [(5912, 1), (5888, 3)] 0, attempt 5820 0 5820 0 [(5913, 1), (5888, 3)] 0, attempt 5821 0 5821 0 [(5914, 1), (5888, 3)] 0, attempt 5822 0 5822 0 [(5915, 1), (5888, 3)] 0, attempt 5823 0 5823 0 [(5916, 1), (5888, 3)] 0]
def counters006 : List Nat := [5824, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5792
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 5824 0 5824 0 [(5917, 1), (5888, 3)] 0, attempt 5825 0 5825 0 [(5918, 1), (5888, 3)] 0, attempt 5826 0 5826 0 [(5919, 1), (5888, 3)] 0, attempt 5827 0 5827 0 [(5920, 1), (5888, 3)] 0, attempt 5828 0 5828 0 [(5921, 1), (5888, 3)] 0, attempt 5829 0 5829 0 [(5922, 1), (5888, 3)] 0, attempt 5830 0 5830 0 [(5923, 1), (5888, 3)] 0, attempt 5831 0 5831 0 [(5924, 1), (5888, 3)] 0, attempt 5832 0 5832 0 [(5925, 1), (5888, 3)] 0, attempt 5833 0 5833 0 [(5926, 1), (5888, 3)] 0, attempt 5834 0 5834 0 [(5927, 1), (5888, 3)] 0, attempt 5835 0 5835 0 [(5928, 1), (5888, 3)] 0, attempt 5836 0 5836 0 [(5929, 1), (5888, 3)] 0, attempt 5837 0 5837 0 [(5930, 1), (5888, 3)] 0, attempt 5838 0 5838 0 [(5931, 1), (5888, 3)] 0, attempt 5839 0 5839 0 [(5932, 1), (5888, 3)] 0, attempt 5840 0 5840 0 [(5933, 1), (5888, 3)] 0, attempt 5841 0 5841 0 [(5934, 1), (5888, 3)] 0, attempt 5842 0 5842 0 [(5935, 1), (5888, 3)] 0, attempt 5843 0 5843 0 [(5936, 1), (5888, 3)] 0, attempt 5844 0 5844 0 [(5937, 1), (5888, 3)] 0, attempt 5845 0 5845 0 [(5938, 1), (5888, 3)] 0, attempt 5846 0 5846 0 [(5939, 1), (5888, 3)] 0, attempt 5847 0 5847 0 [(5940, 1), (5888, 3)] 0, attempt 5848 0 5848 0 [(5941, 1), (5888, 3)] 0, attempt 5849 0 5849 0 [(5942, 1), (5888, 3)] 0, attempt 5850 0 5850 0 [(5943, 1), (5888, 3)] 0, attempt 5851 0 5851 0 [(5944, 1), (5888, 3)] 0, attempt 5852 0 5852 0 [(5945, 1), (5888, 3)] 0, attempt 5853 0 5853 0 [(5946, 1), (5888, 3)] 0, attempt 5854 0 5854 0 [(5947, 1), (5888, 3)] 0, attempt 5855 0 5855 0 [(5948, 1), (5888, 3)] 0]
def counters007 : List Nat := [5856, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5824
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 5856 0 5856 0 [(5949, 1), (5888, 3)] 0, attempt 5857 0 5857 0 [(5950, 1), (5888, 3)] 0, attempt 5858 0 5858 0 [(5951, 1), (5888, 3)] 0, attempt 5859 0 5859 0 [(5953, 1), (5952, 3)] 0, attempt 5860 0 5860 0 [(5954, 1), (5952, 3)] 0, attempt 5861 0 5861 0 [(5955, 1), (5952, 3)] 0, attempt 5862 0 5862 0 [(5956, 1), (5952, 3)] 0, attempt 5863 0 5863 0 [(5957, 1), (5952, 3)] 0, attempt 5864 0 5864 0 [(5958, 1), (5952, 3)] 0, attempt 5865 0 5865 0 [(5959, 1), (5952, 3)] 0, attempt 5866 0 5866 0 [(5960, 1), (5952, 3)] 0, attempt 5867 0 5867 0 [(5961, 1), (5952, 3)] 0, attempt 5868 0 5868 0 [(5962, 1), (5952, 3)] 0, attempt 5869 0 5869 0 [(5963, 1), (5952, 3)] 0, attempt 5870 0 5870 0 [(5964, 1), (5952, 3)] 0, attempt 5871 0 5871 0 [(5965, 1), (5952, 3)] 0, attempt 5872 0 5872 0 [(5966, 1), (5952, 3)] 0, attempt 5873 0 5873 0 [(5967, 1), (5952, 3)] 0, attempt 5874 0 5874 0 [(5968, 1), (5952, 3)] 0, attempt 5875 0 5875 0 [(5969, 1), (5952, 3)] 0, attempt 5876 0 5876 0 [(5970, 1), (5952, 3)] 0, attempt 5877 0 5877 0 [(5971, 1), (5952, 3)] 0, attempt 5878 0 5878 0 [(5972, 1), (5952, 3)] 0, attempt 5879 0 5879 0 [(5973, 1), (5952, 3)] 0, attempt 5880 0 5880 0 [(5974, 1), (5952, 3)] 0, attempt 5881 0 5881 0 [(5975, 1), (5952, 3)] 0, attempt 5882 0 5882 0 [(5976, 1), (5952, 3)] 0, attempt 5883 0 5883 0 [(5977, 1), (5952, 3)] 0, attempt 5884 0 5884 0 [(5978, 1), (5952, 3)] 0, attempt 5885 0 5885 0 [(5979, 1), (5952, 3)] 0, attempt 5886 0 5886 0 [(5980, 1), (5952, 3)] 0, attempt 5887 0 5887 0 [(5981, 1), (5952, 3)] 0]
def counters008 : List Nat := [5888, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5856
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 5888 0 5888 0 [(5982, 1), (5952, 3)] 0, attempt 5889 0 5889 0 [(5983, 1), (5952, 3)] 0, attempt 5890 0 5890 0 [(5984, 1), (5952, 3)] 0, attempt 5891 0 5891 0 [(5985, 1), (5952, 3)] 0, attempt 5892 0 5892 0 [(5986, 1), (5952, 3)] 0, attempt 5893 0 5893 0 [(5987, 1), (5952, 3)] 0, attempt 5894 0 5894 0 [(5988, 1), (5952, 3)] 0, attempt 5895 0 5895 0 [(5989, 1), (5952, 3)] 0, attempt 5896 0 5896 0 [(5990, 1), (5952, 3)] 0, attempt 5897 0 5897 0 [(5991, 1), (5952, 3)] 0, attempt 5898 0 5898 0 [(5992, 1), (5952, 3)] 0, attempt 5899 0 5899 0 [(5993, 1), (5952, 3)] 0, attempt 5900 0 5900 0 [(5994, 1), (5952, 3)] 0, attempt 5901 0 5901 0 [(5995, 1), (5952, 3)] 0, attempt 5902 0 5902 0 [(5996, 1), (5952, 3)] 0, attempt 5903 0 5903 0 [(5997, 1), (5952, 3)] 0, attempt 5904 0 5904 0 [(5998, 1), (5952, 3)] 0, attempt 5905 0 5905 0 [(5999, 1), (5952, 3)] 0, attempt 5906 0 5906 0 [(6000, 1), (5952, 3)] 0, attempt 5907 0 5907 0 [(6001, 1), (5952, 3)] 0, attempt 5908 0 5908 0 [(6002, 1), (5952, 3)] 0, attempt 5909 0 5909 0 [(6003, 1), (5952, 3)] 0, attempt 5910 0 5910 0 [(6004, 1), (5952, 3)] 0, attempt 5911 0 5911 0 [(6005, 1), (5952, 3)] 0, attempt 5912 0 5912 0 [(6006, 1), (5952, 3)] 0, attempt 5913 0 5913 0 [(6007, 1), (5952, 3)] 0, attempt 5914 0 5914 0 [(6008, 1), (5952, 3)] 0, attempt 5915 0 5915 0 [(6009, 1), (5952, 3)] 0, attempt 5916 0 5916 0 [(6010, 1), (5952, 3)] 0, attempt 5917 0 5917 0 [(6011, 1), (5952, 3)] 0, attempt 5918 0 5918 0 [(6012, 1), (5952, 3)] 0, attempt 5919 0 5919 0 [(6013, 1), (5952, 3)] 0]
def counters009 : List Nat := [5920, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5888
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 5920 0 5920 0 [(6014, 1), (5952, 3)] 0, attempt 5921 0 5921 0 [(6015, 1), (5952, 3)] 0, attempt 5922 0 5922 0 [(6017, 1), (6016, 3)] 0, attempt 5923 0 5923 0 [(6018, 1), (6016, 3)] 0, attempt 5924 0 5924 0 [(6019, 1), (6016, 3)] 0, attempt 5925 0 5925 0 [(6020, 1), (6016, 3)] 0, attempt 5926 0 5926 0 [(6021, 1), (6016, 3)] 0, attempt 5927 0 5927 0 [(6022, 1), (6016, 3)] 0, attempt 5928 0 5928 0 [(6023, 1), (6016, 3)] 0, attempt 5929 0 5929 0 [(6024, 1), (6016, 3)] 0, attempt 5930 0 5930 0 [(6025, 1), (6016, 3)] 0, attempt 5931 0 5931 0 [(6026, 1), (6016, 3)] 0, attempt 5932 0 5932 0 [(6027, 1), (6016, 3)] 0, attempt 5933 0 5933 0 [(6028, 1), (6016, 3)] 0, attempt 5934 0 5934 0 [(6029, 1), (6016, 3)] 0, attempt 5935 0 5935 0 [(6030, 1), (6016, 3)] 0, attempt 5936 0 5936 0 [(6031, 1), (6016, 3)] 0, attempt 5937 0 5937 0 [(6032, 1), (6016, 3)] 0, attempt 5938 0 5938 0 [(6033, 1), (6016, 3)] 0, attempt 5939 0 5939 0 [(6034, 1), (6016, 3)] 0, attempt 5940 0 5940 0 [(6035, 1), (6016, 3)] 0, attempt 5941 0 5941 0 [(6036, 1), (6016, 3)] 0, attempt 5942 0 5942 0 [(6037, 1), (6016, 3)] 0, attempt 5943 0 5943 0 [(6038, 1), (6016, 3)] 0, attempt 5944 0 5944 0 [(6039, 1), (6016, 3)] 0, attempt 5945 0 5945 0 [(6040, 1), (6016, 3)] 0, attempt 5946 0 5946 0 [(6041, 1), (6016, 3)] 0, attempt 5947 0 5947 0 [(6042, 1), (6016, 3)] 0, attempt 5948 0 5948 0 [(6043, 1), (6016, 3)] 0, attempt 5949 0 5949 0 [(6044, 1), (6016, 3)] 0, attempt 5950 0 5950 0 [(6045, 1), (6016, 3)] 0, attempt 5951 0 5951 0 [(6046, 1), (6016, 3)] 0]
def counters010 : List Nat := [5952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5920
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 5952 0 5952 0 [(6047, 1), (6016, 3)] 0, attempt 5953 0 5953 0 [(6048, 1), (6016, 3)] 0, attempt 5954 0 5954 0 [(6049, 1), (6016, 3)] 0, attempt 5955 0 5955 0 [(6050, 1), (6016, 3)] 0, attempt 5956 0 5956 0 [(6051, 1), (6016, 3)] 0, attempt 5957 0 5957 0 [(6052, 1), (6016, 3)] 0, attempt 5958 0 5958 0 [(6053, 1), (6016, 3)] 0, attempt 5959 0 5959 0 [(6054, 1), (6016, 3)] 0, attempt 5960 0 5960 0 [(6055, 1), (6016, 3)] 0, attempt 5961 0 5961 0 [(6056, 1), (6016, 3)] 0, attempt 5962 0 5962 0 [(6057, 1), (6016, 3)] 0, attempt 5963 0 5963 0 [(6058, 1), (6016, 3)] 0, attempt 5964 0 5964 0 [(6059, 1), (6016, 3)] 0, attempt 5965 0 5965 0 [(6060, 1), (6016, 3)] 0, attempt 5966 0 5966 0 [(6061, 1), (6016, 3)] 0, attempt 5967 0 5967 0 [(6062, 1), (6016, 3)] 0, attempt 5968 0 5968 0 [(6063, 1), (6016, 3)] 0, attempt 5969 0 5969 0 [(6064, 1), (6016, 3)] 0, attempt 5970 0 5970 0 [(6065, 1), (6016, 3)] 0, attempt 5971 0 5971 0 [(6066, 1), (6016, 3)] 0, attempt 5972 0 5972 0 [(6067, 1), (6016, 3)] 0, attempt 5973 0 5973 0 [(6068, 1), (6016, 3)] 0, attempt 5974 0 5974 0 [(6069, 1), (6016, 3)] 0, attempt 5975 0 5975 0 [(6070, 1), (6016, 3)] 0, attempt 5976 0 5976 0 [(6071, 1), (6016, 3)] 0, attempt 5977 0 5977 0 [(6072, 1), (6016, 3)] 0, attempt 5978 0 5978 0 [(6073, 1), (6016, 3)] 0, attempt 5979 0 5979 0 [(6074, 1), (6016, 3)] 0, attempt 5980 0 5980 0 [(6075, 1), (6016, 3)] 0, attempt 5981 0 5981 0 [(6076, 1), (6016, 3)] 0, attempt 5982 0 5982 0 [(6077, 1), (6016, 3)] 0, attempt 5983 0 5983 0 [(6078, 1), (6016, 3)] 0]
def counters011 : List Nat := [5984, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5952
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 5984 0 5984 0 [(6079, 1), (6016, 3)] 0, attempt 5985 0 5985 0 [(6081, 1), (6080, 3)] 0, attempt 5986 0 5986 0 [(6082, 1), (6080, 3)] 0, attempt 5987 0 5987 0 [(6083, 1), (6080, 3)] 0, attempt 5988 0 5988 0 [(6084, 1), (6080, 3)] 0, attempt 5989 0 5989 0 [(6085, 1), (6080, 3)] 0, attempt 5990 0 5990 0 [(6086, 1), (6080, 3)] 0, attempt 5991 0 5991 0 [(6087, 1), (6080, 3)] 0, attempt 5992 0 5992 0 [(6088, 1), (6080, 3)] 0, attempt 5993 0 5993 0 [(6089, 1), (6080, 3)] 0, attempt 5994 0 5994 0 [(6090, 1), (6080, 3)] 0, attempt 5995 0 5995 0 [(6091, 1), (6080, 3)] 0, attempt 5996 0 5996 0 [(6092, 1), (6080, 3)] 0, attempt 5997 0 5997 0 [(6093, 1), (6080, 3)] 0, attempt 5998 0 5998 0 [(6094, 1), (6080, 3)] 0, attempt 5999 0 5999 0 [(6095, 1), (6080, 3)] 0, attempt 6000 0 6000 0 [(6096, 1), (6080, 3)] 0, attempt 6001 0 6001 0 [(6097, 1), (6080, 3)] 0, attempt 6002 0 6002 0 [(6098, 1), (6080, 3)] 0, attempt 6003 0 6003 0 [(6099, 1), (6080, 3)] 0, attempt 6004 0 6004 0 [(6100, 1), (6080, 3)] 0, attempt 6005 0 6005 0 [(6101, 1), (6080, 3)] 0, attempt 6006 0 6006 0 [(6102, 1), (6080, 3)] 0, attempt 6007 0 6007 0 [(6103, 1), (6080, 3)] 0, attempt 6008 0 6008 0 [(6104, 1), (6080, 3)] 0, attempt 6009 0 6009 0 [(6105, 1), (6080, 3)] 0, attempt 6010 0 6010 0 [(6106, 1), (6080, 3)] 0, attempt 6011 0 6011 0 [(6107, 1), (6080, 3)] 0, attempt 6012 0 6012 0 [(6108, 1), (6080, 3)] 0, attempt 6013 0 6013 0 [(6109, 1), (6080, 3)] 0, attempt 6014 0 6014 0 [(6110, 1), (6080, 3)] 0, attempt 6015 0 6015 0 [(6111, 1), (6080, 3)] 0]
def counters012 : List Nat := [6016, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5984
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 6016 0 6016 0 [(6112, 1), (6080, 3)] 0, attempt 6017 0 6017 0 [(6113, 1), (6080, 3)] 0, attempt 6018 0 6018 0 [(6114, 1), (6080, 3)] 0, attempt 6019 0 6019 0 [(6115, 1), (6080, 3)] 0, attempt 6020 0 6020 0 [(6116, 1), (6080, 3)] 0, attempt 6021 0 6021 0 [(6117, 1), (6080, 3)] 0, attempt 6022 0 6022 0 [(6118, 1), (6080, 3)] 0, attempt 6023 0 6023 0 [(6119, 1), (6080, 3)] 0, attempt 6024 0 6024 0 [(6120, 1), (6080, 3)] 0, attempt 6025 0 6025 0 [(6121, 1), (6080, 3)] 0, attempt 6026 0 6026 0 [(6122, 1), (6080, 3)] 0, attempt 6027 0 6027 0 [(6123, 1), (6080, 3)] 0, attempt 6028 0 6028 0 [(6124, 1), (6080, 3)] 0, attempt 6029 0 6029 0 [(6125, 1), (6080, 3)] 0, attempt 6030 0 6030 0 [(6126, 1), (6080, 3)] 0, attempt 6031 0 6031 0 [(6127, 1), (6080, 3)] 0, attempt 6032 0 6032 0 [(6128, 1), (6080, 3)] 0, attempt 6033 0 6033 0 [(6129, 1), (6080, 3)] 0, attempt 6034 0 6034 0 [(6130, 1), (6080, 3)] 0, attempt 6035 0 6035 0 [(6131, 1), (6080, 3)] 0, attempt 6036 0 6036 0 [(6132, 1), (6080, 3)] 0, attempt 6037 0 6037 0 [(6133, 1), (6080, 3)] 0, attempt 6038 0 6038 0 [(6134, 1), (6080, 3)] 0, attempt 6039 0 6039 0 [(6135, 1), (6080, 3)] 0, attempt 6040 0 6040 0 [(6136, 1), (6080, 3)] 0, attempt 6041 0 6041 0 [(6137, 1), (6080, 3)] 0, attempt 6042 0 6042 0 [(6138, 1), (6080, 3)] 0, attempt 6043 0 6043 0 [(6139, 1), (6080, 3)] 0, attempt 6044 0 6044 0 [(6140, 1), (6080, 3)] 0, attempt 6045 0 6045 0 [(6141, 1), (6080, 3)] 0, attempt 6046 0 6046 0 [(6142, 1), (6080, 3)] 0, attempt 6047 0 6047 0 [(6143, 1), (6080, 3)] 0]
def counters013 : List Nat := [6048, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6016
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 6048 0 6048 0 [(6145, 1), (6144, 3)] 0, attempt 6049 0 6049 0 [(6146, 1), (6144, 3)] 0, attempt 6050 0 6050 0 [(6147, 1), (6144, 3)] 0, attempt 6051 0 6051 0 [(6148, 1), (6144, 3)] 0, attempt 6052 0 6052 0 [(6149, 1), (6144, 3)] 0, attempt 6053 0 6053 0 [(6150, 1), (6144, 3)] 0, attempt 6054 0 6054 0 [(6151, 1), (6144, 3)] 0, attempt 6055 0 6055 0 [(6152, 1), (6144, 3)] 0, attempt 6056 0 6056 0 [(6153, 1), (6144, 3)] 0, attempt 6057 0 6057 0 [(6154, 1), (6144, 3)] 0, attempt 6058 0 6058 0 [(6155, 1), (6144, 3)] 0, attempt 6059 0 6059 0 [(6156, 1), (6144, 3)] 0, attempt 6060 0 6060 0 [(6157, 1), (6144, 3)] 0, attempt 6061 0 6061 0 [(6158, 1), (6144, 3)] 0, attempt 6062 0 6062 0 [(6159, 1), (6144, 3)] 0, attempt 6063 0 6063 0 [(6160, 1), (6144, 3)] 0, attempt 6064 0 6064 0 [(6161, 1), (6144, 3)] 0, attempt 6065 0 6065 0 [(6162, 1), (6144, 3)] 0, attempt 6066 0 6066 0 [(6163, 1), (6144, 3)] 0, attempt 6067 0 6067 0 [(6164, 1), (6144, 3)] 0, attempt 6068 0 6068 0 [(6165, 1), (6144, 3)] 0, attempt 6069 0 6069 0 [(6166, 1), (6144, 3)] 0, attempt 6070 0 6070 0 [(6167, 1), (6144, 3)] 0, attempt 6071 0 6071 0 [(6168, 1), (6144, 3)] 0, attempt 6072 0 6072 0 [(6169, 1), (6144, 3)] 0, attempt 6073 0 6073 0 [(6170, 1), (6144, 3)] 0, attempt 6074 0 6074 0 [(6171, 1), (6144, 3)] 0, attempt 6075 0 6075 0 [(6172, 1), (6144, 3)] 0, attempt 6076 0 6076 0 [(6173, 1), (6144, 3)] 0, attempt 6077 0 6077 0 [(6174, 1), (6144, 3)] 0, attempt 6078 0 6078 0 [(6175, 1), (6144, 3)] 0, attempt 6079 0 6079 0 [(6176, 1), (6144, 3)] 0]
def counters014 : List Nat := [6080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6048
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 6080 0 6080 0 [(6177, 1), (6144, 3)] 0, attempt 6081 0 6081 0 [(6178, 1), (6144, 3)] 0, attempt 6082 0 6082 0 [(6179, 1), (6144, 3)] 0, attempt 6083 0 6083 0 [(6180, 1), (6144, 3)] 0, attempt 6084 0 6084 0 [(6181, 1), (6144, 3)] 0, attempt 6085 0 6085 0 [(6182, 1), (6144, 3)] 0, attempt 6086 0 6086 0 [(6183, 1), (6144, 3)] 0, attempt 6087 0 6087 0 [(6184, 1), (6144, 3)] 0, attempt 6088 0 6088 0 [(6185, 1), (6144, 3)] 0, attempt 6089 0 6089 0 [(6186, 1), (6144, 3)] 0, attempt 6090 0 6090 0 [(6187, 1), (6144, 3)] 0, attempt 6091 0 6091 0 [(6188, 1), (6144, 3)] 0, attempt 6092 0 6092 0 [(6189, 1), (6144, 3)] 0, attempt 6093 0 6093 0 [(6190, 1), (6144, 3)] 0, attempt 6094 0 6094 0 [(6191, 1), (6144, 3)] 0, attempt 6095 0 6095 0 [(6192, 1), (6144, 3)] 0, attempt 6096 0 6096 0 [(6193, 1), (6144, 3)] 0, attempt 6097 0 6097 0 [(6194, 1), (6144, 3)] 0, attempt 6098 0 6098 0 [(6195, 1), (6144, 3)] 0, attempt 6099 0 6099 0 [(6196, 1), (6144, 3)] 0, attempt 6100 0 6100 0 [(6197, 1), (6144, 3)] 0, attempt 6101 0 6101 0 [(6198, 1), (6144, 3)] 0, attempt 6102 0 6102 0 [(6199, 1), (6144, 3)] 0, attempt 6103 0 6103 0 [(6200, 1), (6144, 3)] 0, attempt 6104 0 6104 0 [(6201, 1), (6144, 3)] 0, attempt 6105 0 6105 0 [(6202, 1), (6144, 3)] 0, attempt 6106 0 6106 0 [(6203, 1), (6144, 3)] 0, attempt 6107 0 6107 0 [(6204, 1), (6144, 3)] 0, attempt 6108 0 6108 0 [(6205, 1), (6144, 3)] 0, attempt 6109 0 6109 0 [(6206, 1), (6144, 3)] 0, attempt 6110 0 6110 0 [(6207, 1), (6144, 3)] 0, attempt 6111 0 6111 0 [(6209, 1), (6208, 3)] 0]
def counters015 : List Nat := [6112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6080
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 6112 0 6112 0 [(6210, 1), (6208, 3)] 0, attempt 6113 0 6113 0 [(6211, 1), (6208, 3)] 0, attempt 6114 0 6114 0 [(6212, 1), (6208, 3)] 0, attempt 6115 0 6115 0 [(6213, 1), (6208, 3)] 0, attempt 6116 0 6116 0 [(6214, 1), (6208, 3)] 0, attempt 6117 0 6117 0 [(6215, 1), (6208, 3)] 0, attempt 6118 0 6118 0 [(6216, 1), (6208, 3)] 0, attempt 6119 0 6119 0 [(6217, 1), (6208, 3)] 0, attempt 6120 0 6120 0 [(6218, 1), (6208, 3)] 0, attempt 6121 0 6121 0 [(6219, 1), (6208, 3)] 0, attempt 6122 0 6122 0 [(6220, 1), (6208, 3)] 0, attempt 6123 0 6123 0 [(6221, 1), (6208, 3)] 0, attempt 6124 0 6124 0 [(6222, 1), (6208, 3)] 0, attempt 6125 0 6125 0 [(6223, 1), (6208, 3)] 0, attempt 6126 0 6126 0 [(6224, 1), (6208, 3)] 0, attempt 6127 0 6127 0 [(6225, 1), (6208, 3)] 0, attempt 6128 0 6128 0 [(6226, 1), (6208, 3)] 0, attempt 6129 0 6129 0 [(6227, 1), (6208, 3)] 0, attempt 6130 0 6130 0 [(6228, 1), (6208, 3)] 0, attempt 6131 0 6131 0 [(6229, 1), (6208, 3)] 0, attempt 6132 0 6132 0 [(6230, 1), (6208, 3)] 0, attempt 6133 0 6133 0 [(6231, 1), (6208, 3)] 0, attempt 6134 0 6134 0 [(6232, 1), (6208, 3)] 0, attempt 6135 0 6135 0 [(6233, 1), (6208, 3)] 0, attempt 6136 0 6136 0 [(6234, 1), (6208, 3)] 0, attempt 6137 0 6137 0 [(6235, 1), (6208, 3)] 0, attempt 6138 0 6138 0 [(6236, 1), (6208, 3)] 0, attempt 6139 0 6139 0 [(6237, 1), (6208, 3)] 0, attempt 6140 0 6140 0 [(6238, 1), (6208, 3)] 0, attempt 6141 0 6141 0 [(6239, 1), (6208, 3)] 0, attempt 6142 0 6142 0 [(6240, 1), (6208, 3)] 0, attempt 6143 0 6143 0 [(6241, 1), (6208, 3)] 0]
def counters016 : List Nat := [6144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6112
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6144
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6112
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 6112 6144 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 6112) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6080
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 6080 6112 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 6080) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6048
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 6048 6080 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 6048) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6016
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 6016 6048 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 6016) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5984
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 5984 6016 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 5984) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5952
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 5952 5984 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 5952) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5920
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 5920 5952 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 5920) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5888
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 5888 5920 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 5888) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5856
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 5856 5888 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 5856) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5824
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 5824 5856 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 5824) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5792
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 5792 5824 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 5792) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5760
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 5760 5792 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 5760) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5728
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 5728 5760 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 5728) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5696
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 5696 5728 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 5696) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5664
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 5664 5696 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 5664) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5632
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 5632 5664 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 5632) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr11
