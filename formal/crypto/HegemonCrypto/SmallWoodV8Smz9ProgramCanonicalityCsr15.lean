import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr14

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr15
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [7680, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 7680 0 7680 0 [(7802, 1), (7744, 3)] 0, attempt 7681 0 7681 0 [(7803, 1), (7744, 3)] 0, attempt 7682 0 7682 0 [(7804, 1), (7744, 3)] 0, attempt 7683 0 7683 0 [(7805, 1), (7744, 3)] 0, attempt 7684 0 7684 0 [(7806, 1), (7744, 3)] 0, attempt 7685 0 7685 0 [(7807, 1), (7744, 3)] 0, attempt 7686 0 7686 0 [(7809, 1), (7808, 3)] 0, attempt 7687 0 7687 0 [(7810, 1), (7808, 3)] 0, attempt 7688 0 7688 0 [(7811, 1), (7808, 3)] 0, attempt 7689 0 7689 0 [(7812, 1), (7808, 3)] 0, attempt 7690 0 7690 0 [(7813, 1), (7808, 3)] 0, attempt 7691 0 7691 0 [(7814, 1), (7808, 3)] 0, attempt 7692 0 7692 0 [(7815, 1), (7808, 3)] 0, attempt 7693 0 7693 0 [(7816, 1), (7808, 3)] 0, attempt 7694 0 7694 0 [(7817, 1), (7808, 3)] 0, attempt 7695 0 7695 0 [(7818, 1), (7808, 3)] 0, attempt 7696 0 7696 0 [(7819, 1), (7808, 3)] 0, attempt 7697 0 7697 0 [(7820, 1), (7808, 3)] 0, attempt 7698 0 7698 0 [(7821, 1), (7808, 3)] 0, attempt 7699 0 7699 0 [(7822, 1), (7808, 3)] 0, attempt 7700 0 7700 0 [(7823, 1), (7808, 3)] 0, attempt 7701 0 7701 0 [(7824, 1), (7808, 3)] 0, attempt 7702 0 7702 0 [(7825, 1), (7808, 3)] 0, attempt 7703 0 7703 0 [(7826, 1), (7808, 3)] 0, attempt 7704 0 7704 0 [(7827, 1), (7808, 3)] 0, attempt 7705 0 7705 0 [(7828, 1), (7808, 3)] 0, attempt 7706 0 7706 0 [(7829, 1), (7808, 3)] 0, attempt 7707 0 7707 0 [(7830, 1), (7808, 3)] 0, attempt 7708 0 7708 0 [(7831, 1), (7808, 3)] 0, attempt 7709 0 7709 0 [(7832, 1), (7808, 3)] 0, attempt 7710 0 7710 0 [(7833, 1), (7808, 3)] 0, attempt 7711 0 7711 0 [(7834, 1), (7808, 3)] 0]
def counters001 : List Nat := [7712, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7680
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 7712 0 7712 0 [(7835, 1), (7808, 3)] 0, attempt 7713 0 7713 0 [(7836, 1), (7808, 3)] 0, attempt 7714 0 7714 0 [(7837, 1), (7808, 3)] 0, attempt 7715 0 7715 0 [(7838, 1), (7808, 3)] 0, attempt 7716 0 7716 0 [(7839, 1), (7808, 3)] 0, attempt 7717 0 7717 0 [(7840, 1), (7808, 3)] 0, attempt 7718 0 7718 0 [(7841, 1), (7808, 3)] 0, attempt 7719 0 7719 0 [(7842, 1), (7808, 3)] 0, attempt 7720 0 7720 0 [(7843, 1), (7808, 3)] 0, attempt 7721 0 7721 0 [(7844, 1), (7808, 3)] 0, attempt 7722 0 7722 0 [(7845, 1), (7808, 3)] 0, attempt 7723 0 7723 0 [(7846, 1), (7808, 3)] 0, attempt 7724 0 7724 0 [(7847, 1), (7808, 3)] 0, attempt 7725 0 7725 0 [(7848, 1), (7808, 3)] 0, attempt 7726 0 7726 0 [(7849, 1), (7808, 3)] 0, attempt 7727 0 7727 0 [(7850, 1), (7808, 3)] 0, attempt 7728 0 7728 0 [(7851, 1), (7808, 3)] 0, attempt 7729 0 7729 0 [(7852, 1), (7808, 3)] 0, attempt 7730 0 7730 0 [(7853, 1), (7808, 3)] 0, attempt 7731 0 7731 0 [(7854, 1), (7808, 3)] 0, attempt 7732 0 7732 0 [(7855, 1), (7808, 3)] 0, attempt 7733 0 7733 0 [(7856, 1), (7808, 3)] 0, attempt 7734 0 7734 0 [(7857, 1), (7808, 3)] 0, attempt 7735 0 7735 0 [(7858, 1), (7808, 3)] 0, attempt 7736 0 7736 0 [(7859, 1), (7808, 3)] 0, attempt 7737 0 7737 0 [(7860, 1), (7808, 3)] 0, attempt 7738 0 7738 0 [(7861, 1), (7808, 3)] 0, attempt 7739 0 7739 0 [(7862, 1), (7808, 3)] 0, attempt 7740 0 7740 0 [(7863, 1), (7808, 3)] 0, attempt 7741 0 7741 0 [(7864, 1), (7808, 3)] 0, attempt 7742 0 7742 0 [(7865, 1), (7808, 3)] 0, attempt 7743 0 7743 0 [(7866, 1), (7808, 3)] 0]
def counters002 : List Nat := [7744, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7712
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 7744 0 7744 0 [(7867, 1), (7808, 3)] 0, attempt 7745 0 7745 0 [(7868, 1), (7808, 3)] 0, attempt 7746 0 7746 0 [(7869, 1), (7808, 3)] 0, attempt 7747 0 7747 0 [(7870, 1), (7808, 3)] 0, attempt 7748 0 7748 0 [(7871, 1), (7808, 3)] 0, attempt 7749 0 7749 0 [(7873, 1), (7872, 3)] 0, attempt 7750 0 7750 0 [(7874, 1), (7872, 3)] 0, attempt 7751 0 7751 0 [(7875, 1), (7872, 3)] 0, attempt 7752 0 7752 0 [(7876, 1), (7872, 3)] 0, attempt 7753 0 7753 0 [(7877, 1), (7872, 3)] 0, attempt 7754 0 7754 0 [(7878, 1), (7872, 3)] 0, attempt 7755 0 7755 0 [(7879, 1), (7872, 3)] 0, attempt 7756 0 7756 0 [(7880, 1), (7872, 3)] 0, attempt 7757 0 7757 0 [(7881, 1), (7872, 3)] 0, attempt 7758 0 7758 0 [(7882, 1), (7872, 3)] 0, attempt 7759 0 7759 0 [(7883, 1), (7872, 3)] 0, attempt 7760 0 7760 0 [(7884, 1), (7872, 3)] 0, attempt 7761 0 7761 0 [(7885, 1), (7872, 3)] 0, attempt 7762 0 7762 0 [(7886, 1), (7872, 3)] 0, attempt 7763 0 7763 0 [(7887, 1), (7872, 3)] 0, attempt 7764 0 7764 0 [(7888, 1), (7872, 3)] 0, attempt 7765 0 7765 0 [(7889, 1), (7872, 3)] 0, attempt 7766 0 7766 0 [(7890, 1), (7872, 3)] 0, attempt 7767 0 7767 0 [(7891, 1), (7872, 3)] 0, attempt 7768 0 7768 0 [(7892, 1), (7872, 3)] 0, attempt 7769 0 7769 0 [(7893, 1), (7872, 3)] 0, attempt 7770 0 7770 0 [(7894, 1), (7872, 3)] 0, attempt 7771 0 7771 0 [(7895, 1), (7872, 3)] 0, attempt 7772 0 7772 0 [(7896, 1), (7872, 3)] 0, attempt 7773 0 7773 0 [(7897, 1), (7872, 3)] 0, attempt 7774 0 7774 0 [(7898, 1), (7872, 3)] 0, attempt 7775 0 7775 0 [(7899, 1), (7872, 3)] 0]
def counters003 : List Nat := [7776, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7744
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 7776 0 7776 0 [(7900, 1), (7872, 3)] 0, attempt 7777 0 7777 0 [(7901, 1), (7872, 3)] 0, attempt 7778 0 7778 0 [(7902, 1), (7872, 3)] 0, attempt 7779 0 7779 0 [(7903, 1), (7872, 3)] 0, attempt 7780 0 7780 0 [(7904, 1), (7872, 3)] 0, attempt 7781 0 7781 0 [(7905, 1), (7872, 3)] 0, attempt 7782 0 7782 0 [(7906, 1), (7872, 3)] 0, attempt 7783 0 7783 0 [(7907, 1), (7872, 3)] 0, attempt 7784 0 7784 0 [(7908, 1), (7872, 3)] 0, attempt 7785 0 7785 0 [(7909, 1), (7872, 3)] 0, attempt 7786 0 7786 0 [(7910, 1), (7872, 3)] 0, attempt 7787 0 7787 0 [(7911, 1), (7872, 3)] 0, attempt 7788 0 7788 0 [(7912, 1), (7872, 3)] 0, attempt 7789 0 7789 0 [(7913, 1), (7872, 3)] 0, attempt 7790 0 7790 0 [(7914, 1), (7872, 3)] 0, attempt 7791 0 7791 0 [(7915, 1), (7872, 3)] 0, attempt 7792 0 7792 0 [(7916, 1), (7872, 3)] 0, attempt 7793 0 7793 0 [(7917, 1), (7872, 3)] 0, attempt 7794 0 7794 0 [(7918, 1), (7872, 3)] 0, attempt 7795 0 7795 0 [(7919, 1), (7872, 3)] 0, attempt 7796 0 7796 0 [(7920, 1), (7872, 3)] 0, attempt 7797 0 7797 0 [(7921, 1), (7872, 3)] 0, attempt 7798 0 7798 0 [(7922, 1), (7872, 3)] 0, attempt 7799 0 7799 0 [(7923, 1), (7872, 3)] 0, attempt 7800 0 7800 0 [(7924, 1), (7872, 3)] 0, attempt 7801 0 7801 0 [(7925, 1), (7872, 3)] 0, attempt 7802 0 7802 0 [(7926, 1), (7872, 3)] 0, attempt 7803 0 7803 0 [(7927, 1), (7872, 3)] 0, attempt 7804 0 7804 0 [(7928, 1), (7872, 3)] 0, attempt 7805 0 7805 0 [(7929, 1), (7872, 3)] 0, attempt 7806 0 7806 0 [(7930, 1), (7872, 3)] 0, attempt 7807 0 7807 0 [(7931, 1), (7872, 3)] 0]
def counters004 : List Nat := [7808, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7776
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 7808 0 7808 0 [(7932, 1), (7872, 3)] 0, attempt 7809 0 7809 0 [(7933, 1), (7872, 3)] 0, attempt 7810 0 7810 0 [(7934, 1), (7872, 3)] 0, attempt 7811 0 7811 0 [(7935, 1), (7872, 3)] 0, attempt 7812 0 7812 0 [(7937, 1), (7936, 3)] 0, attempt 7813 0 7813 0 [(7938, 1), (7936, 3)] 0, attempt 7814 0 7814 0 [(7939, 1), (7936, 3)] 0, attempt 7815 0 7815 0 [(7940, 1), (7936, 3)] 0, attempt 7816 0 7816 0 [(7941, 1), (7936, 3)] 0, attempt 7817 0 7817 0 [(7942, 1), (7936, 3)] 0, attempt 7818 0 7818 0 [(7943, 1), (7936, 3)] 0, attempt 7819 0 7819 0 [(7944, 1), (7936, 3)] 0, attempt 7820 0 7820 0 [(7945, 1), (7936, 3)] 0, attempt 7821 0 7821 0 [(7946, 1), (7936, 3)] 0, attempt 7822 0 7822 0 [(7947, 1), (7936, 3)] 0, attempt 7823 0 7823 0 [(7948, 1), (7936, 3)] 0, attempt 7824 0 7824 0 [(7949, 1), (7936, 3)] 0, attempt 7825 0 7825 0 [(7950, 1), (7936, 3)] 0, attempt 7826 0 7826 0 [(7951, 1), (7936, 3)] 0, attempt 7827 0 7827 0 [(7952, 1), (7936, 3)] 0, attempt 7828 0 7828 0 [(7953, 1), (7936, 3)] 0, attempt 7829 0 7829 0 [(7954, 1), (7936, 3)] 0, attempt 7830 0 7830 0 [(7955, 1), (7936, 3)] 0, attempt 7831 0 7831 0 [(7956, 1), (7936, 3)] 0, attempt 7832 0 7832 0 [(7957, 1), (7936, 3)] 0, attempt 7833 0 7833 0 [(7958, 1), (7936, 3)] 0, attempt 7834 0 7834 0 [(7959, 1), (7936, 3)] 0, attempt 7835 0 7835 0 [(7960, 1), (7936, 3)] 0, attempt 7836 0 7836 0 [(7961, 1), (7936, 3)] 0, attempt 7837 0 7837 0 [(7962, 1), (7936, 3)] 0, attempt 7838 0 7838 0 [(7963, 1), (7936, 3)] 0, attempt 7839 0 7839 0 [(7964, 1), (7936, 3)] 0]
def counters005 : List Nat := [7840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7808
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 7840 0 7840 0 [(7965, 1), (7936, 3)] 0, attempt 7841 0 7841 0 [(7966, 1), (7936, 3)] 0, attempt 7842 0 7842 0 [(7967, 1), (7936, 3)] 0, attempt 7843 0 7843 0 [(7968, 1), (7936, 3)] 0, attempt 7844 0 7844 0 [(7969, 1), (7936, 3)] 0, attempt 7845 0 7845 0 [(7970, 1), (7936, 3)] 0, attempt 7846 0 7846 0 [(7971, 1), (7936, 3)] 0, attempt 7847 0 7847 0 [(7972, 1), (7936, 3)] 0, attempt 7848 0 7848 0 [(7973, 1), (7936, 3)] 0, attempt 7849 0 7849 0 [(7974, 1), (7936, 3)] 0, attempt 7850 0 7850 0 [(7975, 1), (7936, 3)] 0, attempt 7851 0 7851 0 [(7976, 1), (7936, 3)] 0, attempt 7852 0 7852 0 [(7977, 1), (7936, 3)] 0, attempt 7853 0 7853 0 [(7978, 1), (7936, 3)] 0, attempt 7854 0 7854 0 [(7979, 1), (7936, 3)] 0, attempt 7855 0 7855 0 [(7980, 1), (7936, 3)] 0, attempt 7856 0 7856 0 [(7981, 1), (7936, 3)] 0, attempt 7857 0 7857 0 [(7982, 1), (7936, 3)] 0, attempt 7858 0 7858 0 [(7983, 1), (7936, 3)] 0, attempt 7859 0 7859 0 [(7984, 1), (7936, 3)] 0, attempt 7860 0 7860 0 [(7985, 1), (7936, 3)] 0, attempt 7861 0 7861 0 [(7986, 1), (7936, 3)] 0, attempt 7862 0 7862 0 [(7987, 1), (7936, 3)] 0, attempt 7863 0 7863 0 [(7988, 1), (7936, 3)] 0, attempt 7864 0 7864 0 [(7989, 1), (7936, 3)] 0, attempt 7865 0 7865 0 [(7990, 1), (7936, 3)] 0, attempt 7866 0 7866 0 [(7991, 1), (7936, 3)] 0, attempt 7867 0 7867 0 [(7992, 1), (7936, 3)] 0, attempt 7868 0 7868 0 [(7993, 1), (7936, 3)] 0, attempt 7869 0 7869 0 [(7994, 1), (7936, 3)] 0, attempt 7870 0 7870 0 [(7995, 1), (7936, 3)] 0, attempt 7871 0 7871 0 [(7996, 1), (7936, 3)] 0]
def counters006 : List Nat := [7872, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7840
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 7872 0 7872 0 [(7997, 1), (7936, 3)] 0, attempt 7873 0 7873 0 [(7998, 1), (7936, 3)] 0, attempt 7874 0 7874 0 [(7999, 1), (7936, 3)] 0, attempt 7875 0 7875 0 [(8001, 1), (8000, 3)] 0, attempt 7876 0 7876 0 [(8002, 1), (8000, 3)] 0, attempt 7877 0 7877 0 [(8003, 1), (8000, 3)] 0, attempt 7878 0 7878 0 [(8004, 1), (8000, 3)] 0, attempt 7879 0 7879 0 [(8005, 1), (8000, 3)] 0, attempt 7880 0 7880 0 [(8006, 1), (8000, 3)] 0, attempt 7881 0 7881 0 [(8007, 1), (8000, 3)] 0, attempt 7882 0 7882 0 [(8008, 1), (8000, 3)] 0, attempt 7883 0 7883 0 [(8009, 1), (8000, 3)] 0, attempt 7884 0 7884 0 [(8010, 1), (8000, 3)] 0, attempt 7885 0 7885 0 [(8011, 1), (8000, 3)] 0, attempt 7886 0 7886 0 [(8012, 1), (8000, 3)] 0, attempt 7887 0 7887 0 [(8013, 1), (8000, 3)] 0, attempt 7888 0 7888 0 [(8014, 1), (8000, 3)] 0, attempt 7889 0 7889 0 [(8015, 1), (8000, 3)] 0, attempt 7890 0 7890 0 [(8016, 1), (8000, 3)] 0, attempt 7891 0 7891 0 [(8017, 1), (8000, 3)] 0, attempt 7892 0 7892 0 [(8018, 1), (8000, 3)] 0, attempt 7893 0 7893 0 [(8019, 1), (8000, 3)] 0, attempt 7894 0 7894 0 [(8020, 1), (8000, 3)] 0, attempt 7895 0 7895 0 [(8021, 1), (8000, 3)] 0, attempt 7896 0 7896 0 [(8022, 1), (8000, 3)] 0, attempt 7897 0 7897 0 [(8023, 1), (8000, 3)] 0, attempt 7898 0 7898 0 [(8024, 1), (8000, 3)] 0, attempt 7899 0 7899 0 [(8025, 1), (8000, 3)] 0, attempt 7900 0 7900 0 [(8026, 1), (8000, 3)] 0, attempt 7901 0 7901 0 [(8027, 1), (8000, 3)] 0, attempt 7902 0 7902 0 [(8028, 1), (8000, 3)] 0, attempt 7903 0 7903 0 [(8029, 1), (8000, 3)] 0]
def counters007 : List Nat := [7904, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7872
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 7904 0 7904 0 [(8030, 1), (8000, 3)] 0, attempt 7905 0 7905 0 [(8031, 1), (8000, 3)] 0, attempt 7906 0 7906 0 [(8032, 1), (8000, 3)] 0, attempt 7907 0 7907 0 [(8033, 1), (8000, 3)] 0, attempt 7908 0 7908 0 [(8034, 1), (8000, 3)] 0, attempt 7909 0 7909 0 [(8035, 1), (8000, 3)] 0, attempt 7910 0 7910 0 [(8036, 1), (8000, 3)] 0, attempt 7911 0 7911 0 [(8037, 1), (8000, 3)] 0, attempt 7912 0 7912 0 [(8038, 1), (8000, 3)] 0, attempt 7913 0 7913 0 [(8039, 1), (8000, 3)] 0, attempt 7914 0 7914 0 [(8040, 1), (8000, 3)] 0, attempt 7915 0 7915 0 [(8041, 1), (8000, 3)] 0, attempt 7916 0 7916 0 [(8042, 1), (8000, 3)] 0, attempt 7917 0 7917 0 [(8043, 1), (8000, 3)] 0, attempt 7918 0 7918 0 [(8044, 1), (8000, 3)] 0, attempt 7919 0 7919 0 [(8045, 1), (8000, 3)] 0, attempt 7920 0 7920 0 [(8046, 1), (8000, 3)] 0, attempt 7921 0 7921 0 [(8047, 1), (8000, 3)] 0, attempt 7922 0 7922 0 [(8048, 1), (8000, 3)] 0, attempt 7923 0 7923 0 [(8049, 1), (8000, 3)] 0, attempt 7924 0 7924 0 [(8050, 1), (8000, 3)] 0, attempt 7925 0 7925 0 [(8051, 1), (8000, 3)] 0, attempt 7926 0 7926 0 [(8052, 1), (8000, 3)] 0, attempt 7927 0 7927 0 [(8053, 1), (8000, 3)] 0, attempt 7928 0 7928 0 [(8054, 1), (8000, 3)] 0, attempt 7929 0 7929 0 [(8055, 1), (8000, 3)] 0, attempt 7930 0 7930 0 [(8056, 1), (8000, 3)] 0, attempt 7931 0 7931 0 [(8057, 1), (8000, 3)] 0, attempt 7932 0 7932 0 [(8058, 1), (8000, 3)] 0, attempt 7933 0 7933 0 [(8059, 1), (8000, 3)] 0, attempt 7934 0 7934 0 [(8060, 1), (8000, 3)] 0, attempt 7935 0 7935 0 [(8061, 1), (8000, 3)] 0]
def counters008 : List Nat := [7936, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7904
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 7936 0 7936 0 [(8062, 1), (8000, 3)] 0, attempt 7937 0 7937 0 [(8063, 1), (8000, 3)] 0, attempt 7938 0 7938 0 [(8065, 1), (8064, 3)] 0, attempt 7939 0 7939 0 [(8066, 1), (8064, 3)] 0, attempt 7940 0 7940 0 [(8067, 1), (8064, 3)] 0, attempt 7941 0 7941 0 [(8068, 1), (8064, 3)] 0, attempt 7942 0 7942 0 [(8069, 1), (8064, 3)] 0, attempt 7943 0 7943 0 [(8070, 1), (8064, 3)] 0, attempt 7944 0 7944 0 [(8071, 1), (8064, 3)] 0, attempt 7945 0 7945 0 [(8072, 1), (8064, 3)] 0, attempt 7946 0 7946 0 [(8073, 1), (8064, 3)] 0, attempt 7947 0 7947 0 [(8074, 1), (8064, 3)] 0, attempt 7948 0 7948 0 [(8075, 1), (8064, 3)] 0, attempt 7949 0 7949 0 [(8076, 1), (8064, 3)] 0, attempt 7950 0 7950 0 [(8077, 1), (8064, 3)] 0, attempt 7951 0 7951 0 [(8078, 1), (8064, 3)] 0, attempt 7952 0 7952 0 [(8079, 1), (8064, 3)] 0, attempt 7953 0 7953 0 [(8080, 1), (8064, 3)] 0, attempt 7954 0 7954 0 [(8081, 1), (8064, 3)] 0, attempt 7955 0 7955 0 [(8082, 1), (8064, 3)] 0, attempt 7956 0 7956 0 [(8083, 1), (8064, 3)] 0, attempt 7957 0 7957 0 [(8084, 1), (8064, 3)] 0, attempt 7958 0 7958 0 [(8085, 1), (8064, 3)] 0, attempt 7959 0 7959 0 [(8086, 1), (8064, 3)] 0, attempt 7960 0 7960 0 [(8087, 1), (8064, 3)] 0, attempt 7961 0 7961 0 [(8088, 1), (8064, 3)] 0, attempt 7962 0 7962 0 [(8089, 1), (8064, 3)] 0, attempt 7963 0 7963 0 [(8090, 1), (8064, 3)] 0, attempt 7964 0 7964 0 [(8091, 1), (8064, 3)] 0, attempt 7965 0 7965 0 [(8092, 1), (8064, 3)] 0, attempt 7966 0 7966 0 [(8093, 1), (8064, 3)] 0, attempt 7967 0 7967 0 [(8094, 1), (8064, 3)] 0]
def counters009 : List Nat := [7968, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7936
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 7968 0 7968 0 [(8095, 1), (8064, 3)] 0, attempt 7969 0 7969 0 [(8096, 1), (8064, 3)] 0, attempt 7970 0 7970 0 [(8097, 1), (8064, 3)] 0, attempt 7971 0 7971 0 [(8098, 1), (8064, 3)] 0, attempt 7972 0 7972 0 [(8099, 1), (8064, 3)] 0, attempt 7973 0 7973 0 [(8100, 1), (8064, 3)] 0, attempt 7974 0 7974 0 [(8101, 1), (8064, 3)] 0, attempt 7975 0 7975 0 [(8102, 1), (8064, 3)] 0, attempt 7976 0 7976 0 [(8103, 1), (8064, 3)] 0, attempt 7977 0 7977 0 [(8104, 1), (8064, 3)] 0, attempt 7978 0 7978 0 [(8105, 1), (8064, 3)] 0, attempt 7979 0 7979 0 [(8106, 1), (8064, 3)] 0, attempt 7980 0 7980 0 [(8107, 1), (8064, 3)] 0, attempt 7981 0 7981 0 [(8108, 1), (8064, 3)] 0, attempt 7982 0 7982 0 [(8109, 1), (8064, 3)] 0, attempt 7983 0 7983 0 [(8110, 1), (8064, 3)] 0, attempt 7984 0 7984 0 [(8111, 1), (8064, 3)] 0, attempt 7985 0 7985 0 [(8112, 1), (8064, 3)] 0, attempt 7986 0 7986 0 [(8113, 1), (8064, 3)] 0, attempt 7987 0 7987 0 [(8114, 1), (8064, 3)] 0, attempt 7988 0 7988 0 [(8115, 1), (8064, 3)] 0, attempt 7989 0 7989 0 [(8116, 1), (8064, 3)] 0, attempt 7990 0 7990 0 [(8117, 1), (8064, 3)] 0, attempt 7991 0 7991 0 [(8118, 1), (8064, 3)] 0, attempt 7992 0 7992 0 [(8119, 1), (8064, 3)] 0, attempt 7993 0 7993 0 [(8120, 1), (8064, 3)] 0, attempt 7994 0 7994 0 [(8121, 1), (8064, 3)] 0, attempt 7995 0 7995 0 [(8122, 1), (8064, 3)] 0, attempt 7996 0 7996 0 [(8123, 1), (8064, 3)] 0, attempt 7997 0 7997 0 [(8124, 1), (8064, 3)] 0, attempt 7998 0 7998 0 [(8125, 1), (8064, 3)] 0, attempt 7999 0 7999 0 [(8126, 1), (8064, 3)] 0]
def counters010 : List Nat := [8000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7968
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 8000 0 8000 0 [(8127, 1), (8064, 3)] 0, attempt 8001 0 8001 0 [(8129, 1), (8128, 3)] 0, attempt 8002 0 8002 0 [(8130, 1), (8128, 3)] 0, attempt 8003 0 8003 0 [(8131, 1), (8128, 3)] 0, attempt 8004 0 8004 0 [(8132, 1), (8128, 3)] 0, attempt 8005 0 8005 0 [(8133, 1), (8128, 3)] 0, attempt 8006 0 8006 0 [(8134, 1), (8128, 3)] 0, attempt 8007 0 8007 0 [(8135, 1), (8128, 3)] 0, attempt 8008 0 8008 0 [(8136, 1), (8128, 3)] 0, attempt 8009 0 8009 0 [(8137, 1), (8128, 3)] 0, attempt 8010 0 8010 0 [(8138, 1), (8128, 3)] 0, attempt 8011 0 8011 0 [(8139, 1), (8128, 3)] 0, attempt 8012 0 8012 0 [(8140, 1), (8128, 3)] 0, attempt 8013 0 8013 0 [(8141, 1), (8128, 3)] 0, attempt 8014 0 8014 0 [(8142, 1), (8128, 3)] 0, attempt 8015 0 8015 0 [(8143, 1), (8128, 3)] 0, attempt 8016 0 8016 0 [(8144, 1), (8128, 3)] 0, attempt 8017 0 8017 0 [(8145, 1), (8128, 3)] 0, attempt 8018 0 8018 0 [(8146, 1), (8128, 3)] 0, attempt 8019 0 8019 0 [(8147, 1), (8128, 3)] 0, attempt 8020 0 8020 0 [(8148, 1), (8128, 3)] 0, attempt 8021 0 8021 0 [(8149, 1), (8128, 3)] 0, attempt 8022 0 8022 0 [(8150, 1), (8128, 3)] 0, attempt 8023 0 8023 0 [(8151, 1), (8128, 3)] 0, attempt 8024 0 8024 0 [(8152, 1), (8128, 3)] 0, attempt 8025 0 8025 0 [(8153, 1), (8128, 3)] 0, attempt 8026 0 8026 0 [(8154, 1), (8128, 3)] 0, attempt 8027 0 8027 0 [(8155, 1), (8128, 3)] 0, attempt 8028 0 8028 0 [(8156, 1), (8128, 3)] 0, attempt 8029 0 8029 0 [(8157, 1), (8128, 3)] 0, attempt 8030 0 8030 0 [(8158, 1), (8128, 3)] 0, attempt 8031 0 8031 0 [(8159, 1), (8128, 3)] 0]
def counters011 : List Nat := [8032, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8000
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 8032 0 8032 0 [(8160, 1), (8128, 3)] 0, attempt 8033 0 8033 0 [(8161, 1), (8128, 3)] 0, attempt 8034 0 8034 0 [(8162, 1), (8128, 3)] 0, attempt 8035 0 8035 0 [(8163, 1), (8128, 3)] 0, attempt 8036 0 8036 0 [(8164, 1), (8128, 3)] 0, attempt 8037 0 8037 0 [(8165, 1), (8128, 3)] 0, attempt 8038 0 8038 0 [(8166, 1), (8128, 3)] 0, attempt 8039 0 8039 0 [(8167, 1), (8128, 3)] 0, attempt 8040 0 8040 0 [(8168, 1), (8128, 3)] 0, attempt 8041 0 8041 0 [(8169, 1), (8128, 3)] 0, attempt 8042 0 8042 0 [(8170, 1), (8128, 3)] 0, attempt 8043 0 8043 0 [(8171, 1), (8128, 3)] 0, attempt 8044 0 8044 0 [(8172, 1), (8128, 3)] 0, attempt 8045 0 8045 0 [(8173, 1), (8128, 3)] 0, attempt 8046 0 8046 0 [(8174, 1), (8128, 3)] 0, attempt 8047 0 8047 0 [(8175, 1), (8128, 3)] 0, attempt 8048 0 8048 0 [(8176, 1), (8128, 3)] 0, attempt 8049 0 8049 0 [(8177, 1), (8128, 3)] 0, attempt 8050 0 8050 0 [(8178, 1), (8128, 3)] 0, attempt 8051 0 8051 0 [(8179, 1), (8128, 3)] 0, attempt 8052 0 8052 0 [(8180, 1), (8128, 3)] 0, attempt 8053 0 8053 0 [(8181, 1), (8128, 3)] 0, attempt 8054 0 8054 0 [(8182, 1), (8128, 3)] 0, attempt 8055 0 8055 0 [(8183, 1), (8128, 3)] 0, attempt 8056 0 8056 0 [(8184, 1), (8128, 3)] 0, attempt 8057 0 8057 0 [(8185, 1), (8128, 3)] 0, attempt 8058 0 8058 0 [(8186, 1), (8128, 3)] 0, attempt 8059 0 8059 0 [(8187, 1), (8128, 3)] 0, attempt 8060 0 8060 0 [(8188, 1), (8128, 3)] 0, attempt 8061 0 8061 0 [(8189, 1), (8128, 3)] 0, attempt 8062 0 8062 0 [(8190, 1), (8128, 3)] 0, attempt 8063 0 8063 0 [(8191, 1), (8128, 3)] 0]
def counters012 : List Nat := [8064, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8032
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 8064 0 8064 0 [(8193, 1), (8192, 3)] 0, attempt 8065 0 8065 0 [(8194, 1), (8192, 3)] 0, attempt 8066 0 8066 0 [(8195, 1), (8192, 3)] 0, attempt 8067 0 8067 0 [(8196, 1), (8192, 3)] 0, attempt 8068 0 8068 0 [(8197, 1), (8192, 3)] 0, attempt 8069 0 8069 0 [(8198, 1), (8192, 3)] 0, attempt 8070 0 8070 0 [(8199, 1), (8192, 3)] 0, attempt 8071 0 8071 0 [(8200, 1), (8192, 3)] 0, attempt 8072 0 8072 0 [(8201, 1), (8192, 3)] 0, attempt 8073 0 8073 0 [(8202, 1), (8192, 3)] 0, attempt 8074 0 8074 0 [(8203, 1), (8192, 3)] 0, attempt 8075 0 8075 0 [(8204, 1), (8192, 3)] 0, attempt 8076 0 8076 0 [(8205, 1), (8192, 3)] 0, attempt 8077 0 8077 0 [(8206, 1), (8192, 3)] 0, attempt 8078 0 8078 0 [(8207, 1), (8192, 3)] 0, attempt 8079 0 8079 0 [(8208, 1), (8192, 3)] 0, attempt 8080 0 8080 0 [(8209, 1), (8192, 3)] 0, attempt 8081 0 8081 0 [(8210, 1), (8192, 3)] 0, attempt 8082 0 8082 0 [(8211, 1), (8192, 3)] 0, attempt 8083 0 8083 0 [(8212, 1), (8192, 3)] 0, attempt 8084 0 8084 0 [(8213, 1), (8192, 3)] 0, attempt 8085 0 8085 0 [(8214, 1), (8192, 3)] 0, attempt 8086 0 8086 0 [(8215, 1), (8192, 3)] 0, attempt 8087 0 8087 0 [(8216, 1), (8192, 3)] 0, attempt 8088 0 8088 0 [(8217, 1), (8192, 3)] 0, attempt 8089 0 8089 0 [(8218, 1), (8192, 3)] 0, attempt 8090 0 8090 0 [(8219, 1), (8192, 3)] 0, attempt 8091 0 8091 0 [(8220, 1), (8192, 3)] 0, attempt 8092 0 8092 0 [(8221, 1), (8192, 3)] 0, attempt 8093 0 8093 0 [(8222, 1), (8192, 3)] 0, attempt 8094 0 8094 0 [(8223, 1), (8192, 3)] 0, attempt 8095 0 8095 0 [(8224, 1), (8192, 3)] 0]
def counters013 : List Nat := [8096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8064
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 8096 0 8096 0 [(8225, 1), (8192, 3)] 0, attempt 8097 0 8097 0 [(8226, 1), (8192, 3)] 0, attempt 8098 0 8098 0 [(8227, 1), (8192, 3)] 0, attempt 8099 0 8099 0 [(8228, 1), (8192, 3)] 0, attempt 8100 0 8100 0 [(8229, 1), (8192, 3)] 0, attempt 8101 0 8101 0 [(8230, 1), (8192, 3)] 0, attempt 8102 0 8102 0 [(8231, 1), (8192, 3)] 0, attempt 8103 0 8103 0 [(8232, 1), (8192, 3)] 0, attempt 8104 0 8104 0 [(8233, 1), (8192, 3)] 0, attempt 8105 0 8105 0 [(8234, 1), (8192, 3)] 0, attempt 8106 0 8106 0 [(8235, 1), (8192, 3)] 0, attempt 8107 0 8107 0 [(8236, 1), (8192, 3)] 0, attempt 8108 0 8108 0 [(8237, 1), (8192, 3)] 0, attempt 8109 0 8109 0 [(8238, 1), (8192, 3)] 0, attempt 8110 0 8110 0 [(8239, 1), (8192, 3)] 0, attempt 8111 0 8111 0 [(8240, 1), (8192, 3)] 0, attempt 8112 0 8112 0 [(8241, 1), (8192, 3)] 0, attempt 8113 0 8113 0 [(8242, 1), (8192, 3)] 0, attempt 8114 0 8114 0 [(8243, 1), (8192, 3)] 0, attempt 8115 0 8115 0 [(8244, 1), (8192, 3)] 0, attempt 8116 0 8116 0 [(8245, 1), (8192, 3)] 0, attempt 8117 0 8117 0 [(8246, 1), (8192, 3)] 0, attempt 8118 0 8118 0 [(8247, 1), (8192, 3)] 0, attempt 8119 0 8119 0 [(8248, 1), (8192, 3)] 0, attempt 8120 0 8120 0 [(8249, 1), (8192, 3)] 0, attempt 8121 0 8121 0 [(8250, 1), (8192, 3)] 0, attempt 8122 0 8122 0 [(8251, 1), (8192, 3)] 0, attempt 8123 0 8123 0 [(8252, 1), (8192, 3)] 0, attempt 8124 0 8124 0 [(8253, 1), (8192, 3)] 0, attempt 8125 0 8125 0 [(8254, 1), (8192, 3)] 0, attempt 8126 0 8126 0 [(8255, 1), (8192, 3)] 0, attempt 8127 0 8127 0 [(8257, 1), (8256, 3)] 0]
def counters014 : List Nat := [8128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8096
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 8128 0 8128 0 [(8258, 1), (8256, 3)] 0, attempt 8129 0 8129 0 [(8259, 1), (8256, 3)] 0, attempt 8130 0 8130 0 [(8260, 1), (8256, 3)] 0, attempt 8131 0 8131 0 [(8261, 1), (8256, 3)] 0, attempt 8132 0 8132 0 [(8262, 1), (8256, 3)] 0, attempt 8133 0 8133 0 [(8263, 1), (8256, 3)] 0, attempt 8134 0 8134 0 [(8264, 1), (8256, 3)] 0, attempt 8135 0 8135 0 [(8265, 1), (8256, 3)] 0, attempt 8136 0 8136 0 [(8266, 1), (8256, 3)] 0, attempt 8137 0 8137 0 [(8267, 1), (8256, 3)] 0, attempt 8138 0 8138 0 [(8268, 1), (8256, 3)] 0, attempt 8139 0 8139 0 [(8269, 1), (8256, 3)] 0, attempt 8140 0 8140 0 [(8270, 1), (8256, 3)] 0, attempt 8141 0 8141 0 [(8271, 1), (8256, 3)] 0, attempt 8142 0 8142 0 [(8272, 1), (8256, 3)] 0, attempt 8143 0 8143 0 [(8273, 1), (8256, 3)] 0, attempt 8144 0 8144 0 [(8274, 1), (8256, 3)] 0, attempt 8145 0 8145 0 [(8275, 1), (8256, 3)] 0, attempt 8146 0 8146 0 [(8276, 1), (8256, 3)] 0, attempt 8147 0 8147 0 [(8277, 1), (8256, 3)] 0, attempt 8148 0 8148 0 [(8278, 1), (8256, 3)] 0, attempt 8149 0 8149 0 [(8279, 1), (8256, 3)] 0, attempt 8150 0 8150 0 [(8280, 1), (8256, 3)] 0, attempt 8151 0 8151 0 [(8281, 1), (8256, 3)] 0, attempt 8152 0 8152 0 [(8282, 1), (8256, 3)] 0, attempt 8153 0 8153 0 [(8283, 1), (8256, 3)] 0, attempt 8154 0 8154 0 [(8284, 1), (8256, 3)] 0, attempt 8155 0 8155 0 [(8285, 1), (8256, 3)] 0, attempt 8156 0 8156 0 [(8286, 1), (8256, 3)] 0, attempt 8157 0 8157 0 [(8287, 1), (8256, 3)] 0, attempt 8158 0 8158 0 [(8288, 1), (8256, 3)] 0, attempt 8159 0 8159 0 [(8289, 1), (8256, 3)] 0]
def counters015 : List Nat := [8160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8128
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 8160 0 8160 0 [(8290, 1), (8256, 3)] 0, attempt 8161 0 8161 0 [(8291, 1), (8256, 3)] 0, attempt 8162 0 8162 0 [(8292, 1), (8256, 3)] 0, attempt 8163 0 8163 0 [(8293, 1), (8256, 3)] 0, attempt 8164 0 8164 0 [(8294, 1), (8256, 3)] 0, attempt 8165 0 8165 0 [(8295, 1), (8256, 3)] 0, attempt 8166 0 8166 0 [(8296, 1), (8256, 3)] 0, attempt 8167 0 8167 0 [(8297, 1), (8256, 3)] 0, attempt 8168 0 8168 0 [(8298, 1), (8256, 3)] 0, attempt 8169 0 8169 0 [(8299, 1), (8256, 3)] 0, attempt 8170 0 8170 0 [(8300, 1), (8256, 3)] 0, attempt 8171 0 8171 0 [(8301, 1), (8256, 3)] 0, attempt 8172 0 8172 0 [(8302, 1), (8256, 3)] 0, attempt 8173 0 8173 0 [(8303, 1), (8256, 3)] 0, attempt 8174 0 8174 0 [(8304, 1), (8256, 3)] 0, attempt 8175 0 8175 0 [(8305, 1), (8256, 3)] 0, attempt 8176 0 8176 0 [(8306, 1), (8256, 3)] 0, attempt 8177 0 8177 0 [(8307, 1), (8256, 3)] 0, attempt 8178 0 8178 0 [(8308, 1), (8256, 3)] 0, attempt 8179 0 8179 0 [(8309, 1), (8256, 3)] 0, attempt 8180 0 8180 0 [(8310, 1), (8256, 3)] 0, attempt 8181 0 8181 0 [(8311, 1), (8256, 3)] 0, attempt 8182 0 8182 0 [(8312, 1), (8256, 3)] 0, attempt 8183 0 8183 0 [(8313, 1), (8256, 3)] 0, attempt 8184 0 8184 0 [(8314, 1), (8256, 3)] 0, attempt 8185 0 8185 0 [(8315, 1), (8256, 3)] 0, attempt 8186 0 8186 0 [(8316, 1), (8256, 3)] 0, attempt 8187 0 8187 0 [(8317, 1), (8256, 3)] 0, attempt 8188 0 8188 0 [(8318, 1), (8256, 3)] 0, attempt 8189 0 8189 0 [(8319, 1), (8256, 3)] 0, attempt 8190 0 8190 0 [(8321, 1), (8320, 3)] 0, attempt 8191 0 8191 0 [(8322, 1), (8320, 3)] 0]
def counters016 : List Nat := [8192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8160
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8192
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8160
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 8160 8192 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 8160) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8128
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 8128 8160 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 8128) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8096
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 8096 8128 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 8096) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8064
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 8064 8096 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 8064) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8032
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 8032 8064 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 8032) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8000
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 8000 8032 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 8000) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7968
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 7968 8000 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 7968) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7936
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 7936 7968 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 7936) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7904
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 7904 7936 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 7904) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7872
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 7872 7904 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 7872) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7840
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 7840 7872 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 7840) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7808
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 7808 7840 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 7808) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7776
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 7776 7808 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 7776) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7744
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 7744 7776 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 7744) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7712
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 7712 7744 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 7712) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 7680
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 7680 7712 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 7680) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr15
