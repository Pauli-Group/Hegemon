import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr12

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr13
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [6656, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 6656 0 6656 0 [(6762, 1), (6720, 3)] 0, attempt 6657 0 6657 0 [(6763, 1), (6720, 3)] 0, attempt 6658 0 6658 0 [(6764, 1), (6720, 3)] 0, attempt 6659 0 6659 0 [(6765, 1), (6720, 3)] 0, attempt 6660 0 6660 0 [(6766, 1), (6720, 3)] 0, attempt 6661 0 6661 0 [(6767, 1), (6720, 3)] 0, attempt 6662 0 6662 0 [(6768, 1), (6720, 3)] 0, attempt 6663 0 6663 0 [(6769, 1), (6720, 3)] 0, attempt 6664 0 6664 0 [(6770, 1), (6720, 3)] 0, attempt 6665 0 6665 0 [(6771, 1), (6720, 3)] 0, attempt 6666 0 6666 0 [(6772, 1), (6720, 3)] 0, attempt 6667 0 6667 0 [(6773, 1), (6720, 3)] 0, attempt 6668 0 6668 0 [(6774, 1), (6720, 3)] 0, attempt 6669 0 6669 0 [(6775, 1), (6720, 3)] 0, attempt 6670 0 6670 0 [(6776, 1), (6720, 3)] 0, attempt 6671 0 6671 0 [(6777, 1), (6720, 3)] 0, attempt 6672 0 6672 0 [(6778, 1), (6720, 3)] 0, attempt 6673 0 6673 0 [(6779, 1), (6720, 3)] 0, attempt 6674 0 6674 0 [(6780, 1), (6720, 3)] 0, attempt 6675 0 6675 0 [(6781, 1), (6720, 3)] 0, attempt 6676 0 6676 0 [(6782, 1), (6720, 3)] 0, attempt 6677 0 6677 0 [(6783, 1), (6720, 3)] 0, attempt 6678 0 6678 0 [(6785, 1), (6784, 3)] 0, attempt 6679 0 6679 0 [(6786, 1), (6784, 3)] 0, attempt 6680 0 6680 0 [(6787, 1), (6784, 3)] 0, attempt 6681 0 6681 0 [(6788, 1), (6784, 3)] 0, attempt 6682 0 6682 0 [(6789, 1), (6784, 3)] 0, attempt 6683 0 6683 0 [(6790, 1), (6784, 3)] 0, attempt 6684 0 6684 0 [(6791, 1), (6784, 3)] 0, attempt 6685 0 6685 0 [(6792, 1), (6784, 3)] 0, attempt 6686 0 6686 0 [(6793, 1), (6784, 3)] 0, attempt 6687 0 6687 0 [(6794, 1), (6784, 3)] 0]
def counters001 : List Nat := [6688, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6656
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 6688 0 6688 0 [(6795, 1), (6784, 3)] 0, attempt 6689 0 6689 0 [(6796, 1), (6784, 3)] 0, attempt 6690 0 6690 0 [(6797, 1), (6784, 3)] 0, attempt 6691 0 6691 0 [(6798, 1), (6784, 3)] 0, attempt 6692 0 6692 0 [(6799, 1), (6784, 3)] 0, attempt 6693 0 6693 0 [(6800, 1), (6784, 3)] 0, attempt 6694 0 6694 0 [(6801, 1), (6784, 3)] 0, attempt 6695 0 6695 0 [(6802, 1), (6784, 3)] 0, attempt 6696 0 6696 0 [(6803, 1), (6784, 3)] 0, attempt 6697 0 6697 0 [(6804, 1), (6784, 3)] 0, attempt 6698 0 6698 0 [(6805, 1), (6784, 3)] 0, attempt 6699 0 6699 0 [(6806, 1), (6784, 3)] 0, attempt 6700 0 6700 0 [(6807, 1), (6784, 3)] 0, attempt 6701 0 6701 0 [(6808, 1), (6784, 3)] 0, attempt 6702 0 6702 0 [(6809, 1), (6784, 3)] 0, attempt 6703 0 6703 0 [(6810, 1), (6784, 3)] 0, attempt 6704 0 6704 0 [(6811, 1), (6784, 3)] 0, attempt 6705 0 6705 0 [(6812, 1), (6784, 3)] 0, attempt 6706 0 6706 0 [(6813, 1), (6784, 3)] 0, attempt 6707 0 6707 0 [(6814, 1), (6784, 3)] 0, attempt 6708 0 6708 0 [(6815, 1), (6784, 3)] 0, attempt 6709 0 6709 0 [(6816, 1), (6784, 3)] 0, attempt 6710 0 6710 0 [(6817, 1), (6784, 3)] 0, attempt 6711 0 6711 0 [(6818, 1), (6784, 3)] 0, attempt 6712 0 6712 0 [(6819, 1), (6784, 3)] 0, attempt 6713 0 6713 0 [(6820, 1), (6784, 3)] 0, attempt 6714 0 6714 0 [(6821, 1), (6784, 3)] 0, attempt 6715 0 6715 0 [(6822, 1), (6784, 3)] 0, attempt 6716 0 6716 0 [(6823, 1), (6784, 3)] 0, attempt 6717 0 6717 0 [(6824, 1), (6784, 3)] 0, attempt 6718 0 6718 0 [(6825, 1), (6784, 3)] 0, attempt 6719 0 6719 0 [(6826, 1), (6784, 3)] 0]
def counters002 : List Nat := [6720, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6688
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 6720 0 6720 0 [(6827, 1), (6784, 3)] 0, attempt 6721 0 6721 0 [(6828, 1), (6784, 3)] 0, attempt 6722 0 6722 0 [(6829, 1), (6784, 3)] 0, attempt 6723 0 6723 0 [(6830, 1), (6784, 3)] 0, attempt 6724 0 6724 0 [(6831, 1), (6784, 3)] 0, attempt 6725 0 6725 0 [(6832, 1), (6784, 3)] 0, attempt 6726 0 6726 0 [(6833, 1), (6784, 3)] 0, attempt 6727 0 6727 0 [(6834, 1), (6784, 3)] 0, attempt 6728 0 6728 0 [(6835, 1), (6784, 3)] 0, attempt 6729 0 6729 0 [(6836, 1), (6784, 3)] 0, attempt 6730 0 6730 0 [(6837, 1), (6784, 3)] 0, attempt 6731 0 6731 0 [(6838, 1), (6784, 3)] 0, attempt 6732 0 6732 0 [(6839, 1), (6784, 3)] 0, attempt 6733 0 6733 0 [(6840, 1), (6784, 3)] 0, attempt 6734 0 6734 0 [(6841, 1), (6784, 3)] 0, attempt 6735 0 6735 0 [(6842, 1), (6784, 3)] 0, attempt 6736 0 6736 0 [(6843, 1), (6784, 3)] 0, attempt 6737 0 6737 0 [(6844, 1), (6784, 3)] 0, attempt 6738 0 6738 0 [(6845, 1), (6784, 3)] 0, attempt 6739 0 6739 0 [(6846, 1), (6784, 3)] 0, attempt 6740 0 6740 0 [(6847, 1), (6784, 3)] 0, attempt 6741 0 6741 0 [(6849, 1), (6848, 3)] 0, attempt 6742 0 6742 0 [(6850, 1), (6848, 3)] 0, attempt 6743 0 6743 0 [(6851, 1), (6848, 3)] 0, attempt 6744 0 6744 0 [(6852, 1), (6848, 3)] 0, attempt 6745 0 6745 0 [(6853, 1), (6848, 3)] 0, attempt 6746 0 6746 0 [(6854, 1), (6848, 3)] 0, attempt 6747 0 6747 0 [(6855, 1), (6848, 3)] 0, attempt 6748 0 6748 0 [(6856, 1), (6848, 3)] 0, attempt 6749 0 6749 0 [(6857, 1), (6848, 3)] 0, attempt 6750 0 6750 0 [(6858, 1), (6848, 3)] 0, attempt 6751 0 6751 0 [(6859, 1), (6848, 3)] 0]
def counters003 : List Nat := [6752, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6720
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 6752 0 6752 0 [(6860, 1), (6848, 3)] 0, attempt 6753 0 6753 0 [(6861, 1), (6848, 3)] 0, attempt 6754 0 6754 0 [(6862, 1), (6848, 3)] 0, attempt 6755 0 6755 0 [(6863, 1), (6848, 3)] 0, attempt 6756 0 6756 0 [(6864, 1), (6848, 3)] 0, attempt 6757 0 6757 0 [(6865, 1), (6848, 3)] 0, attempt 6758 0 6758 0 [(6866, 1), (6848, 3)] 0, attempt 6759 0 6759 0 [(6867, 1), (6848, 3)] 0, attempt 6760 0 6760 0 [(6868, 1), (6848, 3)] 0, attempt 6761 0 6761 0 [(6869, 1), (6848, 3)] 0, attempt 6762 0 6762 0 [(6870, 1), (6848, 3)] 0, attempt 6763 0 6763 0 [(6871, 1), (6848, 3)] 0, attempt 6764 0 6764 0 [(6872, 1), (6848, 3)] 0, attempt 6765 0 6765 0 [(6873, 1), (6848, 3)] 0, attempt 6766 0 6766 0 [(6874, 1), (6848, 3)] 0, attempt 6767 0 6767 0 [(6875, 1), (6848, 3)] 0, attempt 6768 0 6768 0 [(6876, 1), (6848, 3)] 0, attempt 6769 0 6769 0 [(6877, 1), (6848, 3)] 0, attempt 6770 0 6770 0 [(6878, 1), (6848, 3)] 0, attempt 6771 0 6771 0 [(6879, 1), (6848, 3)] 0, attempt 6772 0 6772 0 [(6880, 1), (6848, 3)] 0, attempt 6773 0 6773 0 [(6881, 1), (6848, 3)] 0, attempt 6774 0 6774 0 [(6882, 1), (6848, 3)] 0, attempt 6775 0 6775 0 [(6883, 1), (6848, 3)] 0, attempt 6776 0 6776 0 [(6884, 1), (6848, 3)] 0, attempt 6777 0 6777 0 [(6885, 1), (6848, 3)] 0, attempt 6778 0 6778 0 [(6886, 1), (6848, 3)] 0, attempt 6779 0 6779 0 [(6887, 1), (6848, 3)] 0, attempt 6780 0 6780 0 [(6888, 1), (6848, 3)] 0, attempt 6781 0 6781 0 [(6889, 1), (6848, 3)] 0, attempt 6782 0 6782 0 [(6890, 1), (6848, 3)] 0, attempt 6783 0 6783 0 [(6891, 1), (6848, 3)] 0]
def counters004 : List Nat := [6784, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6752
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 6784 0 6784 0 [(6892, 1), (6848, 3)] 0, attempt 6785 0 6785 0 [(6893, 1), (6848, 3)] 0, attempt 6786 0 6786 0 [(6894, 1), (6848, 3)] 0, attempt 6787 0 6787 0 [(6895, 1), (6848, 3)] 0, attempt 6788 0 6788 0 [(6896, 1), (6848, 3)] 0, attempt 6789 0 6789 0 [(6897, 1), (6848, 3)] 0, attempt 6790 0 6790 0 [(6898, 1), (6848, 3)] 0, attempt 6791 0 6791 0 [(6899, 1), (6848, 3)] 0, attempt 6792 0 6792 0 [(6900, 1), (6848, 3)] 0, attempt 6793 0 6793 0 [(6901, 1), (6848, 3)] 0, attempt 6794 0 6794 0 [(6902, 1), (6848, 3)] 0, attempt 6795 0 6795 0 [(6903, 1), (6848, 3)] 0, attempt 6796 0 6796 0 [(6904, 1), (6848, 3)] 0, attempt 6797 0 6797 0 [(6905, 1), (6848, 3)] 0, attempt 6798 0 6798 0 [(6906, 1), (6848, 3)] 0, attempt 6799 0 6799 0 [(6907, 1), (6848, 3)] 0, attempt 6800 0 6800 0 [(6908, 1), (6848, 3)] 0, attempt 6801 0 6801 0 [(6909, 1), (6848, 3)] 0, attempt 6802 0 6802 0 [(6910, 1), (6848, 3)] 0, attempt 6803 0 6803 0 [(6911, 1), (6848, 3)] 0, attempt 6804 0 6804 0 [(6913, 1), (6912, 3)] 0, attempt 6805 0 6805 0 [(6914, 1), (6912, 3)] 0, attempt 6806 0 6806 0 [(6915, 1), (6912, 3)] 0, attempt 6807 0 6807 0 [(6916, 1), (6912, 3)] 0, attempt 6808 0 6808 0 [(6917, 1), (6912, 3)] 0, attempt 6809 0 6809 0 [(6918, 1), (6912, 3)] 0, attempt 6810 0 6810 0 [(6919, 1), (6912, 3)] 0, attempt 6811 0 6811 0 [(6920, 1), (6912, 3)] 0, attempt 6812 0 6812 0 [(6921, 1), (6912, 3)] 0, attempt 6813 0 6813 0 [(6922, 1), (6912, 3)] 0, attempt 6814 0 6814 0 [(6923, 1), (6912, 3)] 0, attempt 6815 0 6815 0 [(6924, 1), (6912, 3)] 0]
def counters005 : List Nat := [6816, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6784
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 6816 0 6816 0 [(6925, 1), (6912, 3)] 0, attempt 6817 0 6817 0 [(6926, 1), (6912, 3)] 0, attempt 6818 0 6818 0 [(6927, 1), (6912, 3)] 0, attempt 6819 0 6819 0 [(6928, 1), (6912, 3)] 0, attempt 6820 0 6820 0 [(6929, 1), (6912, 3)] 0, attempt 6821 0 6821 0 [(6930, 1), (6912, 3)] 0, attempt 6822 0 6822 0 [(6931, 1), (6912, 3)] 0, attempt 6823 0 6823 0 [(6932, 1), (6912, 3)] 0, attempt 6824 0 6824 0 [(6933, 1), (6912, 3)] 0, attempt 6825 0 6825 0 [(6934, 1), (6912, 3)] 0, attempt 6826 0 6826 0 [(6935, 1), (6912, 3)] 0, attempt 6827 0 6827 0 [(6936, 1), (6912, 3)] 0, attempt 6828 0 6828 0 [(6937, 1), (6912, 3)] 0, attempt 6829 0 6829 0 [(6938, 1), (6912, 3)] 0, attempt 6830 0 6830 0 [(6939, 1), (6912, 3)] 0, attempt 6831 0 6831 0 [(6940, 1), (6912, 3)] 0, attempt 6832 0 6832 0 [(6941, 1), (6912, 3)] 0, attempt 6833 0 6833 0 [(6942, 1), (6912, 3)] 0, attempt 6834 0 6834 0 [(6943, 1), (6912, 3)] 0, attempt 6835 0 6835 0 [(6944, 1), (6912, 3)] 0, attempt 6836 0 6836 0 [(6945, 1), (6912, 3)] 0, attempt 6837 0 6837 0 [(6946, 1), (6912, 3)] 0, attempt 6838 0 6838 0 [(6947, 1), (6912, 3)] 0, attempt 6839 0 6839 0 [(6948, 1), (6912, 3)] 0, attempt 6840 0 6840 0 [(6949, 1), (6912, 3)] 0, attempt 6841 0 6841 0 [(6950, 1), (6912, 3)] 0, attempt 6842 0 6842 0 [(6951, 1), (6912, 3)] 0, attempt 6843 0 6843 0 [(6952, 1), (6912, 3)] 0, attempt 6844 0 6844 0 [(6953, 1), (6912, 3)] 0, attempt 6845 0 6845 0 [(6954, 1), (6912, 3)] 0, attempt 6846 0 6846 0 [(6955, 1), (6912, 3)] 0, attempt 6847 0 6847 0 [(6956, 1), (6912, 3)] 0]
def counters006 : List Nat := [6848, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6816
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 6848 0 6848 0 [(6957, 1), (6912, 3)] 0, attempt 6849 0 6849 0 [(6958, 1), (6912, 3)] 0, attempt 6850 0 6850 0 [(6959, 1), (6912, 3)] 0, attempt 6851 0 6851 0 [(6960, 1), (6912, 3)] 0, attempt 6852 0 6852 0 [(6961, 1), (6912, 3)] 0, attempt 6853 0 6853 0 [(6962, 1), (6912, 3)] 0, attempt 6854 0 6854 0 [(6963, 1), (6912, 3)] 0, attempt 6855 0 6855 0 [(6964, 1), (6912, 3)] 0, attempt 6856 0 6856 0 [(6965, 1), (6912, 3)] 0, attempt 6857 0 6857 0 [(6966, 1), (6912, 3)] 0, attempt 6858 0 6858 0 [(6967, 1), (6912, 3)] 0, attempt 6859 0 6859 0 [(6968, 1), (6912, 3)] 0, attempt 6860 0 6860 0 [(6969, 1), (6912, 3)] 0, attempt 6861 0 6861 0 [(6970, 1), (6912, 3)] 0, attempt 6862 0 6862 0 [(6971, 1), (6912, 3)] 0, attempt 6863 0 6863 0 [(6972, 1), (6912, 3)] 0, attempt 6864 0 6864 0 [(6973, 1), (6912, 3)] 0, attempt 6865 0 6865 0 [(6974, 1), (6912, 3)] 0, attempt 6866 0 6866 0 [(6975, 1), (6912, 3)] 0, attempt 6867 0 6867 0 [(6977, 1), (6976, 3)] 0, attempt 6868 0 6868 0 [(6978, 1), (6976, 3)] 0, attempt 6869 0 6869 0 [(6979, 1), (6976, 3)] 0, attempt 6870 0 6870 0 [(6980, 1), (6976, 3)] 0, attempt 6871 0 6871 0 [(6981, 1), (6976, 3)] 0, attempt 6872 0 6872 0 [(6982, 1), (6976, 3)] 0, attempt 6873 0 6873 0 [(6983, 1), (6976, 3)] 0, attempt 6874 0 6874 0 [(6984, 1), (6976, 3)] 0, attempt 6875 0 6875 0 [(6985, 1), (6976, 3)] 0, attempt 6876 0 6876 0 [(6986, 1), (6976, 3)] 0, attempt 6877 0 6877 0 [(6987, 1), (6976, 3)] 0, attempt 6878 0 6878 0 [(6988, 1), (6976, 3)] 0, attempt 6879 0 6879 0 [(6989, 1), (6976, 3)] 0]
def counters007 : List Nat := [6880, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6848
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 6880 0 6880 0 [(6990, 1), (6976, 3)] 0, attempt 6881 0 6881 0 [(6991, 1), (6976, 3)] 0, attempt 6882 0 6882 0 [(6992, 1), (6976, 3)] 0, attempt 6883 0 6883 0 [(6993, 1), (6976, 3)] 0, attempt 6884 0 6884 0 [(6994, 1), (6976, 3)] 0, attempt 6885 0 6885 0 [(6995, 1), (6976, 3)] 0, attempt 6886 0 6886 0 [(6996, 1), (6976, 3)] 0, attempt 6887 0 6887 0 [(6997, 1), (6976, 3)] 0, attempt 6888 0 6888 0 [(6998, 1), (6976, 3)] 0, attempt 6889 0 6889 0 [(6999, 1), (6976, 3)] 0, attempt 6890 0 6890 0 [(7000, 1), (6976, 3)] 0, attempt 6891 0 6891 0 [(7001, 1), (6976, 3)] 0, attempt 6892 0 6892 0 [(7002, 1), (6976, 3)] 0, attempt 6893 0 6893 0 [(7003, 1), (6976, 3)] 0, attempt 6894 0 6894 0 [(7004, 1), (6976, 3)] 0, attempt 6895 0 6895 0 [(7005, 1), (6976, 3)] 0, attempt 6896 0 6896 0 [(7006, 1), (6976, 3)] 0, attempt 6897 0 6897 0 [(7007, 1), (6976, 3)] 0, attempt 6898 0 6898 0 [(7008, 1), (6976, 3)] 0, attempt 6899 0 6899 0 [(7009, 1), (6976, 3)] 0, attempt 6900 0 6900 0 [(7010, 1), (6976, 3)] 0, attempt 6901 0 6901 0 [(7011, 1), (6976, 3)] 0, attempt 6902 0 6902 0 [(7012, 1), (6976, 3)] 0, attempt 6903 0 6903 0 [(7013, 1), (6976, 3)] 0, attempt 6904 0 6904 0 [(7014, 1), (6976, 3)] 0, attempt 6905 0 6905 0 [(7015, 1), (6976, 3)] 0, attempt 6906 0 6906 0 [(7016, 1), (6976, 3)] 0, attempt 6907 0 6907 0 [(7017, 1), (6976, 3)] 0, attempt 6908 0 6908 0 [(7018, 1), (6976, 3)] 0, attempt 6909 0 6909 0 [(7019, 1), (6976, 3)] 0, attempt 6910 0 6910 0 [(7020, 1), (6976, 3)] 0, attempt 6911 0 6911 0 [(7021, 1), (6976, 3)] 0]
def counters008 : List Nat := [6912, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6880
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 6912 0 6912 0 [(7022, 1), (6976, 3)] 0, attempt 6913 0 6913 0 [(7023, 1), (6976, 3)] 0, attempt 6914 0 6914 0 [(7024, 1), (6976, 3)] 0, attempt 6915 0 6915 0 [(7025, 1), (6976, 3)] 0, attempt 6916 0 6916 0 [(7026, 1), (6976, 3)] 0, attempt 6917 0 6917 0 [(7027, 1), (6976, 3)] 0, attempt 6918 0 6918 0 [(7028, 1), (6976, 3)] 0, attempt 6919 0 6919 0 [(7029, 1), (6976, 3)] 0, attempt 6920 0 6920 0 [(7030, 1), (6976, 3)] 0, attempt 6921 0 6921 0 [(7031, 1), (6976, 3)] 0, attempt 6922 0 6922 0 [(7032, 1), (6976, 3)] 0, attempt 6923 0 6923 0 [(7033, 1), (6976, 3)] 0, attempt 6924 0 6924 0 [(7034, 1), (6976, 3)] 0, attempt 6925 0 6925 0 [(7035, 1), (6976, 3)] 0, attempt 6926 0 6926 0 [(7036, 1), (6976, 3)] 0, attempt 6927 0 6927 0 [(7037, 1), (6976, 3)] 0, attempt 6928 0 6928 0 [(7038, 1), (6976, 3)] 0, attempt 6929 0 6929 0 [(7039, 1), (6976, 3)] 0, attempt 6930 0 6930 0 [(7041, 1), (7040, 3)] 0, attempt 6931 0 6931 0 [(7042, 1), (7040, 3)] 0, attempt 6932 0 6932 0 [(7043, 1), (7040, 3)] 0, attempt 6933 0 6933 0 [(7044, 1), (7040, 3)] 0, attempt 6934 0 6934 0 [(7045, 1), (7040, 3)] 0, attempt 6935 0 6935 0 [(7046, 1), (7040, 3)] 0, attempt 6936 0 6936 0 [(7047, 1), (7040, 3)] 0, attempt 6937 0 6937 0 [(7048, 1), (7040, 3)] 0, attempt 6938 0 6938 0 [(7049, 1), (7040, 3)] 0, attempt 6939 0 6939 0 [(7050, 1), (7040, 3)] 0, attempt 6940 0 6940 0 [(7051, 1), (7040, 3)] 0, attempt 6941 0 6941 0 [(7052, 1), (7040, 3)] 0, attempt 6942 0 6942 0 [(7053, 1), (7040, 3)] 0, attempt 6943 0 6943 0 [(7054, 1), (7040, 3)] 0]
def counters009 : List Nat := [6944, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6912
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 6944 0 6944 0 [(7055, 1), (7040, 3)] 0, attempt 6945 0 6945 0 [(7056, 1), (7040, 3)] 0, attempt 6946 0 6946 0 [(7057, 1), (7040, 3)] 0, attempt 6947 0 6947 0 [(7058, 1), (7040, 3)] 0, attempt 6948 0 6948 0 [(7059, 1), (7040, 3)] 0, attempt 6949 0 6949 0 [(7060, 1), (7040, 3)] 0, attempt 6950 0 6950 0 [(7061, 1), (7040, 3)] 0, attempt 6951 0 6951 0 [(7062, 1), (7040, 3)] 0, attempt 6952 0 6952 0 [(7063, 1), (7040, 3)] 0, attempt 6953 0 6953 0 [(7064, 1), (7040, 3)] 0, attempt 6954 0 6954 0 [(7065, 1), (7040, 3)] 0, attempt 6955 0 6955 0 [(7066, 1), (7040, 3)] 0, attempt 6956 0 6956 0 [(7067, 1), (7040, 3)] 0, attempt 6957 0 6957 0 [(7068, 1), (7040, 3)] 0, attempt 6958 0 6958 0 [(7069, 1), (7040, 3)] 0, attempt 6959 0 6959 0 [(7070, 1), (7040, 3)] 0, attempt 6960 0 6960 0 [(7071, 1), (7040, 3)] 0, attempt 6961 0 6961 0 [(7072, 1), (7040, 3)] 0, attempt 6962 0 6962 0 [(7073, 1), (7040, 3)] 0, attempt 6963 0 6963 0 [(7074, 1), (7040, 3)] 0, attempt 6964 0 6964 0 [(7075, 1), (7040, 3)] 0, attempt 6965 0 6965 0 [(7076, 1), (7040, 3)] 0, attempt 6966 0 6966 0 [(7077, 1), (7040, 3)] 0, attempt 6967 0 6967 0 [(7078, 1), (7040, 3)] 0, attempt 6968 0 6968 0 [(7079, 1), (7040, 3)] 0, attempt 6969 0 6969 0 [(7080, 1), (7040, 3)] 0, attempt 6970 0 6970 0 [(7081, 1), (7040, 3)] 0, attempt 6971 0 6971 0 [(7082, 1), (7040, 3)] 0, attempt 6972 0 6972 0 [(7083, 1), (7040, 3)] 0, attempt 6973 0 6973 0 [(7084, 1), (7040, 3)] 0, attempt 6974 0 6974 0 [(7085, 1), (7040, 3)] 0, attempt 6975 0 6975 0 [(7086, 1), (7040, 3)] 0]
def counters010 : List Nat := [6976, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6944
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 6976 0 6976 0 [(7087, 1), (7040, 3)] 0, attempt 6977 0 6977 0 [(7088, 1), (7040, 3)] 0, attempt 6978 0 6978 0 [(7089, 1), (7040, 3)] 0, attempt 6979 0 6979 0 [(7090, 1), (7040, 3)] 0, attempt 6980 0 6980 0 [(7091, 1), (7040, 3)] 0, attempt 6981 0 6981 0 [(7092, 1), (7040, 3)] 0, attempt 6982 0 6982 0 [(7093, 1), (7040, 3)] 0, attempt 6983 0 6983 0 [(7094, 1), (7040, 3)] 0, attempt 6984 0 6984 0 [(7095, 1), (7040, 3)] 0, attempt 6985 0 6985 0 [(7096, 1), (7040, 3)] 0, attempt 6986 0 6986 0 [(7097, 1), (7040, 3)] 0, attempt 6987 0 6987 0 [(7098, 1), (7040, 3)] 0, attempt 6988 0 6988 0 [(7099, 1), (7040, 3)] 0, attempt 6989 0 6989 0 [(7100, 1), (7040, 3)] 0, attempt 6990 0 6990 0 [(7101, 1), (7040, 3)] 0, attempt 6991 0 6991 0 [(7102, 1), (7040, 3)] 0, attempt 6992 0 6992 0 [(7103, 1), (7040, 3)] 0, attempt 6993 0 6993 0 [(7105, 1), (7104, 3)] 0, attempt 6994 0 6994 0 [(7106, 1), (7104, 3)] 0, attempt 6995 0 6995 0 [(7107, 1), (7104, 3)] 0, attempt 6996 0 6996 0 [(7108, 1), (7104, 3)] 0, attempt 6997 0 6997 0 [(7109, 1), (7104, 3)] 0, attempt 6998 0 6998 0 [(7110, 1), (7104, 3)] 0, attempt 6999 0 6999 0 [(7111, 1), (7104, 3)] 0, attempt 7000 0 7000 0 [(7112, 1), (7104, 3)] 0, attempt 7001 0 7001 0 [(7113, 1), (7104, 3)] 0, attempt 7002 0 7002 0 [(7114, 1), (7104, 3)] 0, attempt 7003 0 7003 0 [(7115, 1), (7104, 3)] 0, attempt 7004 0 7004 0 [(7116, 1), (7104, 3)] 0, attempt 7005 0 7005 0 [(7117, 1), (7104, 3)] 0, attempt 7006 0 7006 0 [(7118, 1), (7104, 3)] 0, attempt 7007 0 7007 0 [(7119, 1), (7104, 3)] 0]
def counters011 : List Nat := [7008, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6976
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 7008 0 7008 0 [(7120, 1), (7104, 3)] 0, attempt 7009 0 7009 0 [(7121, 1), (7104, 3)] 0, attempt 7010 0 7010 0 [(7122, 1), (7104, 3)] 0, attempt 7011 0 7011 0 [(7123, 1), (7104, 3)] 0, attempt 7012 0 7012 0 [(7124, 1), (7104, 3)] 0, attempt 7013 0 7013 0 [(7125, 1), (7104, 3)] 0, attempt 7014 0 7014 0 [(7126, 1), (7104, 3)] 0, attempt 7015 0 7015 0 [(7127, 1), (7104, 3)] 0, attempt 7016 0 7016 0 [(7128, 1), (7104, 3)] 0, attempt 7017 0 7017 0 [(7129, 1), (7104, 3)] 0, attempt 7018 0 7018 0 [(7130, 1), (7104, 3)] 0, attempt 7019 0 7019 0 [(7131, 1), (7104, 3)] 0, attempt 7020 0 7020 0 [(7132, 1), (7104, 3)] 0, attempt 7021 0 7021 0 [(7133, 1), (7104, 3)] 0, attempt 7022 0 7022 0 [(7134, 1), (7104, 3)] 0, attempt 7023 0 7023 0 [(7135, 1), (7104, 3)] 0, attempt 7024 0 7024 0 [(7136, 1), (7104, 3)] 0, attempt 7025 0 7025 0 [(7137, 1), (7104, 3)] 0, attempt 7026 0 7026 0 [(7138, 1), (7104, 3)] 0, attempt 7027 0 7027 0 [(7139, 1), (7104, 3)] 0, attempt 7028 0 7028 0 [(7140, 1), (7104, 3)] 0, attempt 7029 0 7029 0 [(7141, 1), (7104, 3)] 0, attempt 7030 0 7030 0 [(7142, 1), (7104, 3)] 0, attempt 7031 0 7031 0 [(7143, 1), (7104, 3)] 0, attempt 7032 0 7032 0 [(7144, 1), (7104, 3)] 0, attempt 7033 0 7033 0 [(7145, 1), (7104, 3)] 0, attempt 7034 0 7034 0 [(7146, 1), (7104, 3)] 0, attempt 7035 0 7035 0 [(7147, 1), (7104, 3)] 0, attempt 7036 0 7036 0 [(7148, 1), (7104, 3)] 0, attempt 7037 0 7037 0 [(7149, 1), (7104, 3)] 0, attempt 7038 0 7038 0 [(7150, 1), (7104, 3)] 0, attempt 7039 0 7039 0 [(7151, 1), (7104, 3)] 0]
def counters012 : List Nat := [7040, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7008
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 7040 0 7040 0 [(7152, 1), (7104, 3)] 0, attempt 7041 0 7041 0 [(7153, 1), (7104, 3)] 0, attempt 7042 0 7042 0 [(7154, 1), (7104, 3)] 0, attempt 7043 0 7043 0 [(7155, 1), (7104, 3)] 0, attempt 7044 0 7044 0 [(7156, 1), (7104, 3)] 0, attempt 7045 0 7045 0 [(7157, 1), (7104, 3)] 0, attempt 7046 0 7046 0 [(7158, 1), (7104, 3)] 0, attempt 7047 0 7047 0 [(7159, 1), (7104, 3)] 0, attempt 7048 0 7048 0 [(7160, 1), (7104, 3)] 0, attempt 7049 0 7049 0 [(7161, 1), (7104, 3)] 0, attempt 7050 0 7050 0 [(7162, 1), (7104, 3)] 0, attempt 7051 0 7051 0 [(7163, 1), (7104, 3)] 0, attempt 7052 0 7052 0 [(7164, 1), (7104, 3)] 0, attempt 7053 0 7053 0 [(7165, 1), (7104, 3)] 0, attempt 7054 0 7054 0 [(7166, 1), (7104, 3)] 0, attempt 7055 0 7055 0 [(7167, 1), (7104, 3)] 0, attempt 7056 0 7056 0 [(7169, 1), (7168, 3)] 0, attempt 7057 0 7057 0 [(7170, 1), (7168, 3)] 0, attempt 7058 0 7058 0 [(7171, 1), (7168, 3)] 0, attempt 7059 0 7059 0 [(7172, 1), (7168, 3)] 0, attempt 7060 0 7060 0 [(7173, 1), (7168, 3)] 0, attempt 7061 0 7061 0 [(7174, 1), (7168, 3)] 0, attempt 7062 0 7062 0 [(7175, 1), (7168, 3)] 0, attempt 7063 0 7063 0 [(7176, 1), (7168, 3)] 0, attempt 7064 0 7064 0 [(7177, 1), (7168, 3)] 0, attempt 7065 0 7065 0 [(7178, 1), (7168, 3)] 0, attempt 7066 0 7066 0 [(7179, 1), (7168, 3)] 0, attempt 7067 0 7067 0 [(7180, 1), (7168, 3)] 0, attempt 7068 0 7068 0 [(7181, 1), (7168, 3)] 0, attempt 7069 0 7069 0 [(7182, 1), (7168, 3)] 0, attempt 7070 0 7070 0 [(7183, 1), (7168, 3)] 0, attempt 7071 0 7071 0 [(7184, 1), (7168, 3)] 0]
def counters013 : List Nat := [7072, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7040
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 7072 0 7072 0 [(7185, 1), (7168, 3)] 0, attempt 7073 0 7073 0 [(7186, 1), (7168, 3)] 0, attempt 7074 0 7074 0 [(7187, 1), (7168, 3)] 0, attempt 7075 0 7075 0 [(7188, 1), (7168, 3)] 0, attempt 7076 0 7076 0 [(7189, 1), (7168, 3)] 0, attempt 7077 0 7077 0 [(7190, 1), (7168, 3)] 0, attempt 7078 0 7078 0 [(7191, 1), (7168, 3)] 0, attempt 7079 0 7079 0 [(7192, 1), (7168, 3)] 0, attempt 7080 0 7080 0 [(7193, 1), (7168, 3)] 0, attempt 7081 0 7081 0 [(7194, 1), (7168, 3)] 0, attempt 7082 0 7082 0 [(7195, 1), (7168, 3)] 0, attempt 7083 0 7083 0 [(7196, 1), (7168, 3)] 0, attempt 7084 0 7084 0 [(7197, 1), (7168, 3)] 0, attempt 7085 0 7085 0 [(7198, 1), (7168, 3)] 0, attempt 7086 0 7086 0 [(7199, 1), (7168, 3)] 0, attempt 7087 0 7087 0 [(7200, 1), (7168, 3)] 0, attempt 7088 0 7088 0 [(7201, 1), (7168, 3)] 0, attempt 7089 0 7089 0 [(7202, 1), (7168, 3)] 0, attempt 7090 0 7090 0 [(7203, 1), (7168, 3)] 0, attempt 7091 0 7091 0 [(7204, 1), (7168, 3)] 0, attempt 7092 0 7092 0 [(7205, 1), (7168, 3)] 0, attempt 7093 0 7093 0 [(7206, 1), (7168, 3)] 0, attempt 7094 0 7094 0 [(7207, 1), (7168, 3)] 0, attempt 7095 0 7095 0 [(7208, 1), (7168, 3)] 0, attempt 7096 0 7096 0 [(7209, 1), (7168, 3)] 0, attempt 7097 0 7097 0 [(7210, 1), (7168, 3)] 0, attempt 7098 0 7098 0 [(7211, 1), (7168, 3)] 0, attempt 7099 0 7099 0 [(7212, 1), (7168, 3)] 0, attempt 7100 0 7100 0 [(7213, 1), (7168, 3)] 0, attempt 7101 0 7101 0 [(7214, 1), (7168, 3)] 0, attempt 7102 0 7102 0 [(7215, 1), (7168, 3)] 0, attempt 7103 0 7103 0 [(7216, 1), (7168, 3)] 0]
def counters014 : List Nat := [7104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7072
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 7104 0 7104 0 [(7217, 1), (7168, 3)] 0, attempt 7105 0 7105 0 [(7218, 1), (7168, 3)] 0, attempt 7106 0 7106 0 [(7219, 1), (7168, 3)] 0, attempt 7107 0 7107 0 [(7220, 1), (7168, 3)] 0, attempt 7108 0 7108 0 [(7221, 1), (7168, 3)] 0, attempt 7109 0 7109 0 [(7222, 1), (7168, 3)] 0, attempt 7110 0 7110 0 [(7223, 1), (7168, 3)] 0, attempt 7111 0 7111 0 [(7224, 1), (7168, 3)] 0, attempt 7112 0 7112 0 [(7225, 1), (7168, 3)] 0, attempt 7113 0 7113 0 [(7226, 1), (7168, 3)] 0, attempt 7114 0 7114 0 [(7227, 1), (7168, 3)] 0, attempt 7115 0 7115 0 [(7228, 1), (7168, 3)] 0, attempt 7116 0 7116 0 [(7229, 1), (7168, 3)] 0, attempt 7117 0 7117 0 [(7230, 1), (7168, 3)] 0, attempt 7118 0 7118 0 [(7231, 1), (7168, 3)] 0, attempt 7119 0 7119 0 [(7233, 1), (7232, 3)] 0, attempt 7120 0 7120 0 [(7234, 1), (7232, 3)] 0, attempt 7121 0 7121 0 [(7235, 1), (7232, 3)] 0, attempt 7122 0 7122 0 [(7236, 1), (7232, 3)] 0, attempt 7123 0 7123 0 [(7237, 1), (7232, 3)] 0, attempt 7124 0 7124 0 [(7238, 1), (7232, 3)] 0, attempt 7125 0 7125 0 [(7239, 1), (7232, 3)] 0, attempt 7126 0 7126 0 [(7240, 1), (7232, 3)] 0, attempt 7127 0 7127 0 [(7241, 1), (7232, 3)] 0, attempt 7128 0 7128 0 [(7242, 1), (7232, 3)] 0, attempt 7129 0 7129 0 [(7243, 1), (7232, 3)] 0, attempt 7130 0 7130 0 [(7244, 1), (7232, 3)] 0, attempt 7131 0 7131 0 [(7245, 1), (7232, 3)] 0, attempt 7132 0 7132 0 [(7246, 1), (7232, 3)] 0, attempt 7133 0 7133 0 [(7247, 1), (7232, 3)] 0, attempt 7134 0 7134 0 [(7248, 1), (7232, 3)] 0, attempt 7135 0 7135 0 [(7249, 1), (7232, 3)] 0]
def counters015 : List Nat := [7136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7104
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 7136 0 7136 0 [(7250, 1), (7232, 3)] 0, attempt 7137 0 7137 0 [(7251, 1), (7232, 3)] 0, attempt 7138 0 7138 0 [(7252, 1), (7232, 3)] 0, attempt 7139 0 7139 0 [(7253, 1), (7232, 3)] 0, attempt 7140 0 7140 0 [(7254, 1), (7232, 3)] 0, attempt 7141 0 7141 0 [(7255, 1), (7232, 3)] 0, attempt 7142 0 7142 0 [(7256, 1), (7232, 3)] 0, attempt 7143 0 7143 0 [(7257, 1), (7232, 3)] 0, attempt 7144 0 7144 0 [(7258, 1), (7232, 3)] 0, attempt 7145 0 7145 0 [(7259, 1), (7232, 3)] 0, attempt 7146 0 7146 0 [(7260, 1), (7232, 3)] 0, attempt 7147 0 7147 0 [(7261, 1), (7232, 3)] 0, attempt 7148 0 7148 0 [(7262, 1), (7232, 3)] 0, attempt 7149 0 7149 0 [(7263, 1), (7232, 3)] 0, attempt 7150 0 7150 0 [(7264, 1), (7232, 3)] 0, attempt 7151 0 7151 0 [(7265, 1), (7232, 3)] 0, attempt 7152 0 7152 0 [(7266, 1), (7232, 3)] 0, attempt 7153 0 7153 0 [(7267, 1), (7232, 3)] 0, attempt 7154 0 7154 0 [(7268, 1), (7232, 3)] 0, attempt 7155 0 7155 0 [(7269, 1), (7232, 3)] 0, attempt 7156 0 7156 0 [(7270, 1), (7232, 3)] 0, attempt 7157 0 7157 0 [(7271, 1), (7232, 3)] 0, attempt 7158 0 7158 0 [(7272, 1), (7232, 3)] 0, attempt 7159 0 7159 0 [(7273, 1), (7232, 3)] 0, attempt 7160 0 7160 0 [(7274, 1), (7232, 3)] 0, attempt 7161 0 7161 0 [(7275, 1), (7232, 3)] 0, attempt 7162 0 7162 0 [(7276, 1), (7232, 3)] 0, attempt 7163 0 7163 0 [(7277, 1), (7232, 3)] 0, attempt 7164 0 7164 0 [(7278, 1), (7232, 3)] 0, attempt 7165 0 7165 0 [(7279, 1), (7232, 3)] 0, attempt 7166 0 7166 0 [(7280, 1), (7232, 3)] 0, attempt 7167 0 7167 0 [(7281, 1), (7232, 3)] 0]
def counters016 : List Nat := [7168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7136
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7168
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7136
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 7136 7168 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 7136) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7104
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 7104 7136 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 7104) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7072
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 7072 7104 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 7072) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7040
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 7040 7072 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 7040) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7008
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 7008 7040 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 7008) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6976
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 6976 7008 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 6976) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6944
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 6944 6976 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 6944) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6912
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 6912 6944 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 6912) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6880
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 6880 6912 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 6880) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6848
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 6848 6880 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 6848) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6816
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 6816 6848 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 6816) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6784
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 6784 6816 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 6784) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6752
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 6752 6784 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 6752) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6720
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 6720 6752 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 6720) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6688
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 6688 6720 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 6688) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6656
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 6656 6688 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 6656) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr13
