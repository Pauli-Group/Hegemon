import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr18

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr19
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [9728, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 9728 0 9728 0 [(9883, 1), (9856, 3)] 0, attempt 9729 0 9729 0 [(9884, 1), (9856, 3)] 0, attempt 9730 0 9730 0 [(9885, 1), (9856, 3)] 0, attempt 9731 0 9731 0 [(9886, 1), (9856, 3)] 0, attempt 9732 0 9732 0 [(9887, 1), (9856, 3)] 0, attempt 9733 0 9733 0 [(9888, 1), (9856, 3)] 0, attempt 9734 0 9734 0 [(9889, 1), (9856, 3)] 0, attempt 9735 0 9735 0 [(9890, 1), (9856, 3)] 0, attempt 9736 0 9736 0 [(9891, 1), (9856, 3)] 0, attempt 9737 0 9737 0 [(9892, 1), (9856, 3)] 0, attempt 9738 0 9738 0 [(9893, 1), (9856, 3)] 0, attempt 9739 0 9739 0 [(9894, 1), (9856, 3)] 0, attempt 9740 0 9740 0 [(9895, 1), (9856, 3)] 0, attempt 9741 0 9741 0 [(9896, 1), (9856, 3)] 0, attempt 9742 0 9742 0 [(9897, 1), (9856, 3)] 0, attempt 9743 0 9743 0 [(9898, 1), (9856, 3)] 0, attempt 9744 0 9744 0 [(9899, 1), (9856, 3)] 0, attempt 9745 0 9745 0 [(9900, 1), (9856, 3)] 0, attempt 9746 0 9746 0 [(9901, 1), (9856, 3)] 0, attempt 9747 0 9747 0 [(9902, 1), (9856, 3)] 0, attempt 9748 0 9748 0 [(9903, 1), (9856, 3)] 0, attempt 9749 0 9749 0 [(9904, 1), (9856, 3)] 0, attempt 9750 0 9750 0 [(9905, 1), (9856, 3)] 0, attempt 9751 0 9751 0 [(9906, 1), (9856, 3)] 0, attempt 9752 0 9752 0 [(9907, 1), (9856, 3)] 0, attempt 9753 0 9753 0 [(9908, 1), (9856, 3)] 0, attempt 9754 0 9754 0 [(9909, 1), (9856, 3)] 0, attempt 9755 0 9755 0 [(9910, 1), (9856, 3)] 0, attempt 9756 0 9756 0 [(9911, 1), (9856, 3)] 0, attempt 9757 0 9757 0 [(9912, 1), (9856, 3)] 0, attempt 9758 0 9758 0 [(9913, 1), (9856, 3)] 0, attempt 9759 0 9759 0 [(9914, 1), (9856, 3)] 0]
def counters001 : List Nat := [9760, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9728
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 9760 0 9760 0 [(9915, 1), (9856, 3)] 0, attempt 9761 0 9761 0 [(9916, 1), (9856, 3)] 0, attempt 9762 0 9762 0 [(9917, 1), (9856, 3)] 0, attempt 9763 0 9763 0 [(9918, 1), (9856, 3)] 0, attempt 9764 0 9764 0 [(9919, 1), (9856, 3)] 0, attempt 9765 0 9765 0 [(9921, 1), (9920, 3)] 0, attempt 9766 0 9766 0 [(9922, 1), (9920, 3)] 0, attempt 9767 0 9767 0 [(9923, 1), (9920, 3)] 0, attempt 9768 0 9768 0 [(9924, 1), (9920, 3)] 0, attempt 9769 0 9769 0 [(9925, 1), (9920, 3)] 0, attempt 9770 0 9770 0 [(9926, 1), (9920, 3)] 0, attempt 9771 0 9771 0 [(9927, 1), (9920, 3)] 0, attempt 9772 0 9772 0 [(9928, 1), (9920, 3)] 0, attempt 9773 0 9773 0 [(9929, 1), (9920, 3)] 0, attempt 9774 0 9774 0 [(9930, 1), (9920, 3)] 0, attempt 9775 0 9775 0 [(9931, 1), (9920, 3)] 0, attempt 9776 0 9776 0 [(9932, 1), (9920, 3)] 0, attempt 9777 0 9777 0 [(9933, 1), (9920, 3)] 0, attempt 9778 0 9778 0 [(9934, 1), (9920, 3)] 0, attempt 9779 0 9779 0 [(9935, 1), (9920, 3)] 0, attempt 9780 0 9780 0 [(9936, 1), (9920, 3)] 0, attempt 9781 0 9781 0 [(9937, 1), (9920, 3)] 0, attempt 9782 0 9782 0 [(9938, 1), (9920, 3)] 0, attempt 9783 0 9783 0 [(9939, 1), (9920, 3)] 0, attempt 9784 0 9784 0 [(9940, 1), (9920, 3)] 0, attempt 9785 0 9785 0 [(9941, 1), (9920, 3)] 0, attempt 9786 0 9786 0 [(9942, 1), (9920, 3)] 0, attempt 9787 0 9787 0 [(9943, 1), (9920, 3)] 0, attempt 9788 0 9788 0 [(9944, 1), (9920, 3)] 0, attempt 9789 0 9789 0 [(9945, 1), (9920, 3)] 0, attempt 9790 0 9790 0 [(9946, 1), (9920, 3)] 0, attempt 9791 0 9791 0 [(9947, 1), (9920, 3)] 0]
def counters002 : List Nat := [9792, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9760
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 9792 0 9792 0 [(9948, 1), (9920, 3)] 0, attempt 9793 0 9793 0 [(9949, 1), (9920, 3)] 0, attempt 9794 0 9794 0 [(9950, 1), (9920, 3)] 0, attempt 9795 0 9795 0 [(9951, 1), (9920, 3)] 0, attempt 9796 0 9796 0 [(9952, 1), (9920, 3)] 0, attempt 9797 0 9797 0 [(9953, 1), (9920, 3)] 0, attempt 9798 0 9798 0 [(9954, 1), (9920, 3)] 0, attempt 9799 0 9799 0 [(9955, 1), (9920, 3)] 0, attempt 9800 0 9800 0 [(9956, 1), (9920, 3)] 0, attempt 9801 0 9801 0 [(9957, 1), (9920, 3)] 0, attempt 9802 0 9802 0 [(9958, 1), (9920, 3)] 0, attempt 9803 0 9803 0 [(9959, 1), (9920, 3)] 0, attempt 9804 0 9804 0 [(9960, 1), (9920, 3)] 0, attempt 9805 0 9805 0 [(9961, 1), (9920, 3)] 0, attempt 9806 0 9806 0 [(9962, 1), (9920, 3)] 0, attempt 9807 0 9807 0 [(9963, 1), (9920, 3)] 0, attempt 9808 0 9808 0 [(9964, 1), (9920, 3)] 0, attempt 9809 0 9809 0 [(9965, 1), (9920, 3)] 0, attempt 9810 0 9810 0 [(9966, 1), (9920, 3)] 0, attempt 9811 0 9811 0 [(9967, 1), (9920, 3)] 0, attempt 9812 0 9812 0 [(9968, 1), (9920, 3)] 0, attempt 9813 0 9813 0 [(9969, 1), (9920, 3)] 0, attempt 9814 0 9814 0 [(9970, 1), (9920, 3)] 0, attempt 9815 0 9815 0 [(9971, 1), (9920, 3)] 0, attempt 9816 0 9816 0 [(9972, 1), (9920, 3)] 0, attempt 9817 0 9817 0 [(9973, 1), (9920, 3)] 0, attempt 9818 0 9818 0 [(9974, 1), (9920, 3)] 0, attempt 9819 0 9819 0 [(9975, 1), (9920, 3)] 0, attempt 9820 0 9820 0 [(9976, 1), (9920, 3)] 0, attempt 9821 0 9821 0 [(9977, 1), (9920, 3)] 0, attempt 9822 0 9822 0 [(9978, 1), (9920, 3)] 0, attempt 9823 0 9823 0 [(9979, 1), (9920, 3)] 0]
def counters003 : List Nat := [9824, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9792
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 9824 0 9824 0 [(9980, 1), (9920, 3)] 0, attempt 9825 0 9825 0 [(9981, 1), (9920, 3)] 0, attempt 9826 0 9826 0 [(9982, 1), (9920, 3)] 0, attempt 9827 0 9827 0 [(9983, 1), (9920, 3)] 0, attempt 9828 0 9828 0 [(9985, 1), (9984, 3)] 0, attempt 9829 0 9829 0 [(9986, 1), (9984, 3)] 0, attempt 9830 0 9830 0 [(9987, 1), (9984, 3)] 0, attempt 9831 0 9831 0 [(9988, 1), (9984, 3)] 0, attempt 9832 0 9832 0 [(9989, 1), (9984, 3)] 0, attempt 9833 0 9833 0 [(9990, 1), (9984, 3)] 0, attempt 9834 0 9834 0 [(9991, 1), (9984, 3)] 0, attempt 9835 0 9835 0 [(9992, 1), (9984, 3)] 0, attempt 9836 0 9836 0 [(9993, 1), (9984, 3)] 0, attempt 9837 0 9837 0 [(9994, 1), (9984, 3)] 0, attempt 9838 0 9838 0 [(9995, 1), (9984, 3)] 0, attempt 9839 0 9839 0 [(9996, 1), (9984, 3)] 0, attempt 9840 0 9840 0 [(9997, 1), (9984, 3)] 0, attempt 9841 0 9841 0 [(9998, 1), (9984, 3)] 0, attempt 9842 0 9842 0 [(9999, 1), (9984, 3)] 0, attempt 9843 0 9843 0 [(10000, 1), (9984, 3)] 0, attempt 9844 0 9844 0 [(10001, 1), (9984, 3)] 0, attempt 9845 0 9845 0 [(10002, 1), (9984, 3)] 0, attempt 9846 0 9846 0 [(10003, 1), (9984, 3)] 0, attempt 9847 0 9847 0 [(10004, 1), (9984, 3)] 0, attempt 9848 0 9848 0 [(10005, 1), (9984, 3)] 0, attempt 9849 0 9849 0 [(10006, 1), (9984, 3)] 0, attempt 9850 0 9850 0 [(10007, 1), (9984, 3)] 0, attempt 9851 0 9851 0 [(10008, 1), (9984, 3)] 0, attempt 9852 0 9852 0 [(10009, 1), (9984, 3)] 0, attempt 9853 0 9853 0 [(10010, 1), (9984, 3)] 0, attempt 9854 0 9854 0 [(10011, 1), (9984, 3)] 0, attempt 9855 0 9855 0 [(10012, 1), (9984, 3)] 0]
def counters004 : List Nat := [9856, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9824
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 9856 0 9856 0 [(10013, 1), (9984, 3)] 0, attempt 9857 0 9857 0 [(10014, 1), (9984, 3)] 0, attempt 9858 0 9858 0 [(10015, 1), (9984, 3)] 0, attempt 9859 0 9859 0 [(10016, 1), (9984, 3)] 0, attempt 9860 0 9860 0 [(10017, 1), (9984, 3)] 0, attempt 9861 0 9861 0 [(10018, 1), (9984, 3)] 0, attempt 9862 0 9862 0 [(10019, 1), (9984, 3)] 0, attempt 9863 0 9863 0 [(10020, 1), (9984, 3)] 0, attempt 9864 0 9864 0 [(10021, 1), (9984, 3)] 0, attempt 9865 0 9865 0 [(10022, 1), (9984, 3)] 0, attempt 9866 0 9866 0 [(10023, 1), (9984, 3)] 0, attempt 9867 0 9867 0 [(10024, 1), (9984, 3)] 0, attempt 9868 0 9868 0 [(10025, 1), (9984, 3)] 0, attempt 9869 0 9869 0 [(10026, 1), (9984, 3)] 0, attempt 9870 0 9870 0 [(10027, 1), (9984, 3)] 0, attempt 9871 0 9871 0 [(10028, 1), (9984, 3)] 0, attempt 9872 0 9872 0 [(10029, 1), (9984, 3)] 0, attempt 9873 0 9873 0 [(10030, 1), (9984, 3)] 0, attempt 9874 0 9874 0 [(10031, 1), (9984, 3)] 0, attempt 9875 0 9875 0 [(10032, 1), (9984, 3)] 0, attempt 9876 0 9876 0 [(10033, 1), (9984, 3)] 0, attempt 9877 0 9877 0 [(10034, 1), (9984, 3)] 0, attempt 9878 0 9878 0 [(10035, 1), (9984, 3)] 0, attempt 9879 0 9879 0 [(10036, 1), (9984, 3)] 0, attempt 9880 0 9880 0 [(10037, 1), (9984, 3)] 0, attempt 9881 0 9881 0 [(10038, 1), (9984, 3)] 0, attempt 9882 0 9882 0 [(10039, 1), (9984, 3)] 0, attempt 9883 0 9883 0 [(10040, 1), (9984, 3)] 0, attempt 9884 0 9884 0 [(10041, 1), (9984, 3)] 0, attempt 9885 0 9885 0 [(10042, 1), (9984, 3)] 0, attempt 9886 0 9886 0 [(10043, 1), (9984, 3)] 0, attempt 9887 0 9887 0 [(10044, 1), (9984, 3)] 0]
def counters005 : List Nat := [9888, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9856
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 9888 0 9888 0 [(10045, 1), (9984, 3)] 0, attempt 9889 0 9889 0 [(10046, 1), (9984, 3)] 0, attempt 9890 0 9890 0 [(10047, 1), (9984, 3)] 0, attempt 9891 0 9891 0 [(10049, 1), (10048, 3)] 0, attempt 9892 0 9892 0 [(10050, 1), (10048, 3)] 0, attempt 9893 0 9893 0 [(10051, 1), (10048, 3)] 0, attempt 9894 0 9894 0 [(10052, 1), (10048, 3)] 0, attempt 9895 0 9895 0 [(10053, 1), (10048, 3)] 0, attempt 9896 0 9896 0 [(10054, 1), (10048, 3)] 0, attempt 9897 0 9897 0 [(10055, 1), (10048, 3)] 0, attempt 9898 0 9898 0 [(10056, 1), (10048, 3)] 0, attempt 9899 0 9899 0 [(10057, 1), (10048, 3)] 0, attempt 9900 0 9900 0 [(10058, 1), (10048, 3)] 0, attempt 9901 0 9901 0 [(10059, 1), (10048, 3)] 0, attempt 9902 0 9902 0 [(10060, 1), (10048, 3)] 0, attempt 9903 0 9903 0 [(10061, 1), (10048, 3)] 0, attempt 9904 0 9904 0 [(10062, 1), (10048, 3)] 0, attempt 9905 0 9905 0 [(10063, 1), (10048, 3)] 0, attempt 9906 0 9906 0 [(10064, 1), (10048, 3)] 0, attempt 9907 0 9907 0 [(10065, 1), (10048, 3)] 0, attempt 9908 0 9908 0 [(10066, 1), (10048, 3)] 0, attempt 9909 0 9909 0 [(10067, 1), (10048, 3)] 0, attempt 9910 0 9910 0 [(10068, 1), (10048, 3)] 0, attempt 9911 0 9911 0 [(10069, 1), (10048, 3)] 0, attempt 9912 0 9912 0 [(10070, 1), (10048, 3)] 0, attempt 9913 0 9913 0 [(10071, 1), (10048, 3)] 0, attempt 9914 0 9914 0 [(10072, 1), (10048, 3)] 0, attempt 9915 0 9915 0 [(10073, 1), (10048, 3)] 0, attempt 9916 0 9916 0 [(10074, 1), (10048, 3)] 0, attempt 9917 0 9917 0 [(10075, 1), (10048, 3)] 0, attempt 9918 0 9918 0 [(10076, 1), (10048, 3)] 0, attempt 9919 0 9919 0 [(10077, 1), (10048, 3)] 0]
def counters006 : List Nat := [9920, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9888
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 9920 0 9920 0 [(10078, 1), (10048, 3)] 0, attempt 9921 0 9921 0 [(10079, 1), (10048, 3)] 0, attempt 9922 0 9922 0 [(10080, 1), (10048, 3)] 0, attempt 9923 0 9923 0 [(10081, 1), (10048, 3)] 0, attempt 9924 0 9924 0 [(10082, 1), (10048, 3)] 0, attempt 9925 0 9925 0 [(10083, 1), (10048, 3)] 0, attempt 9926 0 9926 0 [(10084, 1), (10048, 3)] 0, attempt 9927 0 9927 0 [(10085, 1), (10048, 3)] 0, attempt 9928 0 9928 0 [(10086, 1), (10048, 3)] 0, attempt 9929 0 9929 0 [(10087, 1), (10048, 3)] 0, attempt 9930 0 9930 0 [(10088, 1), (10048, 3)] 0, attempt 9931 0 9931 0 [(10089, 1), (10048, 3)] 0, attempt 9932 0 9932 0 [(10090, 1), (10048, 3)] 0, attempt 9933 0 9933 0 [(10091, 1), (10048, 3)] 0, attempt 9934 0 9934 0 [(10092, 1), (10048, 3)] 0, attempt 9935 0 9935 0 [(10093, 1), (10048, 3)] 0, attempt 9936 0 9936 0 [(10094, 1), (10048, 3)] 0, attempt 9937 0 9937 0 [(10095, 1), (10048, 3)] 0, attempt 9938 0 9938 0 [(10096, 1), (10048, 3)] 0, attempt 9939 0 9939 0 [(10097, 1), (10048, 3)] 0, attempt 9940 0 9940 0 [(10098, 1), (10048, 3)] 0, attempt 9941 0 9941 0 [(10099, 1), (10048, 3)] 0, attempt 9942 0 9942 0 [(10100, 1), (10048, 3)] 0, attempt 9943 0 9943 0 [(10101, 1), (10048, 3)] 0, attempt 9944 0 9944 0 [(10102, 1), (10048, 3)] 0, attempt 9945 0 9945 0 [(10103, 1), (10048, 3)] 0, attempt 9946 0 9946 0 [(10104, 1), (10048, 3)] 0, attempt 9947 0 9947 0 [(10105, 1), (10048, 3)] 0, attempt 9948 0 9948 0 [(10106, 1), (10048, 3)] 0, attempt 9949 0 9949 0 [(10107, 1), (10048, 3)] 0, attempt 9950 0 9950 0 [(10108, 1), (10048, 3)] 0, attempt 9951 0 9951 0 [(10109, 1), (10048, 3)] 0]
def counters007 : List Nat := [9952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9920
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 9952 0 9952 0 [(10110, 1), (10048, 3)] 0, attempt 9953 0 9953 0 [(10111, 1), (10048, 3)] 0, attempt 9954 0 9954 0 [(10113, 1), (10112, 3)] 0, attempt 9955 0 9955 0 [(10114, 1), (10112, 3)] 0, attempt 9956 0 9956 0 [(10115, 1), (10112, 3)] 0, attempt 9957 0 9957 0 [(10116, 1), (10112, 3)] 0, attempt 9958 0 9958 0 [(10117, 1), (10112, 3)] 0, attempt 9959 0 9959 0 [(10118, 1), (10112, 3)] 0, attempt 9960 0 9960 0 [(10119, 1), (10112, 3)] 0, attempt 9961 0 9961 0 [(10120, 1), (10112, 3)] 0, attempt 9962 0 9962 0 [(10121, 1), (10112, 3)] 0, attempt 9963 0 9963 0 [(10122, 1), (10112, 3)] 0, attempt 9964 0 9964 0 [(10123, 1), (10112, 3)] 0, attempt 9965 0 9965 0 [(10124, 1), (10112, 3)] 0, attempt 9966 0 9966 0 [(10125, 1), (10112, 3)] 0, attempt 9967 0 9967 0 [(10126, 1), (10112, 3)] 0, attempt 9968 0 9968 0 [(10127, 1), (10112, 3)] 0, attempt 9969 0 9969 0 [(10128, 1), (10112, 3)] 0, attempt 9970 0 9970 0 [(10129, 1), (10112, 3)] 0, attempt 9971 0 9971 0 [(10130, 1), (10112, 3)] 0, attempt 9972 0 9972 0 [(10131, 1), (10112, 3)] 0, attempt 9973 0 9973 0 [(10132, 1), (10112, 3)] 0, attempt 9974 0 9974 0 [(10133, 1), (10112, 3)] 0, attempt 9975 0 9975 0 [(10134, 1), (10112, 3)] 0, attempt 9976 0 9976 0 [(10135, 1), (10112, 3)] 0, attempt 9977 0 9977 0 [(10136, 1), (10112, 3)] 0, attempt 9978 0 9978 0 [(10137, 1), (10112, 3)] 0, attempt 9979 0 9979 0 [(10138, 1), (10112, 3)] 0, attempt 9980 0 9980 0 [(10139, 1), (10112, 3)] 0, attempt 9981 0 9981 0 [(10140, 1), (10112, 3)] 0, attempt 9982 0 9982 0 [(10141, 1), (10112, 3)] 0, attempt 9983 0 9983 0 [(10142, 1), (10112, 3)] 0]
def counters008 : List Nat := [9984, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9952
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 9984 0 9984 0 [(10143, 1), (10112, 3)] 0, attempt 9985 0 9985 0 [(10144, 1), (10112, 3)] 0, attempt 9986 0 9986 0 [(10145, 1), (10112, 3)] 0, attempt 9987 0 9987 0 [(10146, 1), (10112, 3)] 0, attempt 9988 0 9988 0 [(10147, 1), (10112, 3)] 0, attempt 9989 0 9989 0 [(10148, 1), (10112, 3)] 0, attempt 9990 0 9990 0 [(10149, 1), (10112, 3)] 0, attempt 9991 0 9991 0 [(10150, 1), (10112, 3)] 0, attempt 9992 0 9992 0 [(10151, 1), (10112, 3)] 0, attempt 9993 0 9993 0 [(10152, 1), (10112, 3)] 0, attempt 9994 0 9994 0 [(10153, 1), (10112, 3)] 0, attempt 9995 0 9995 0 [(10154, 1), (10112, 3)] 0, attempt 9996 0 9996 0 [(10155, 1), (10112, 3)] 0, attempt 9997 0 9997 0 [(10156, 1), (10112, 3)] 0, attempt 9998 0 9998 0 [(10157, 1), (10112, 3)] 0, attempt 9999 0 9999 0 [(10158, 1), (10112, 3)] 0, attempt 10000 0 10000 0 [(10159, 1), (10112, 3)] 0, attempt 10001 0 10001 0 [(10160, 1), (10112, 3)] 0, attempt 10002 0 10002 0 [(10161, 1), (10112, 3)] 0, attempt 10003 0 10003 0 [(10162, 1), (10112, 3)] 0, attempt 10004 0 10004 0 [(10163, 1), (10112, 3)] 0, attempt 10005 0 10005 0 [(10164, 1), (10112, 3)] 0, attempt 10006 0 10006 0 [(10165, 1), (10112, 3)] 0, attempt 10007 0 10007 0 [(10166, 1), (10112, 3)] 0, attempt 10008 0 10008 0 [(10167, 1), (10112, 3)] 0, attempt 10009 0 10009 0 [(10168, 1), (10112, 3)] 0, attempt 10010 0 10010 0 [(10169, 1), (10112, 3)] 0, attempt 10011 0 10011 0 [(10170, 1), (10112, 3)] 0, attempt 10012 0 10012 0 [(10171, 1), (10112, 3)] 0, attempt 10013 0 10013 0 [(10172, 1), (10112, 3)] 0, attempt 10014 0 10014 0 [(10173, 1), (10112, 3)] 0, attempt 10015 0 10015 0 [(10174, 1), (10112, 3)] 0]
def counters009 : List Nat := [10016, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9984
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 10016 0 10016 0 [(10175, 1), (10112, 3)] 0, attempt 10017 0 10017 0 [(10177, 1), (10176, 3)] 0, attempt 10018 0 10018 0 [(10178, 1), (10176, 3)] 0, attempt 10019 0 10019 0 [(10179, 1), (10176, 3)] 0, attempt 10020 0 10020 0 [(10180, 1), (10176, 3)] 0, attempt 10021 0 10021 0 [(10181, 1), (10176, 3)] 0, attempt 10022 0 10022 0 [(10182, 1), (10176, 3)] 0, attempt 10023 0 10023 0 [(10183, 1), (10176, 3)] 0, attempt 10024 0 10024 0 [(10184, 1), (10176, 3)] 0, attempt 10025 0 10025 0 [(10185, 1), (10176, 3)] 0, attempt 10026 0 10026 0 [(10186, 1), (10176, 3)] 0, attempt 10027 0 10027 0 [(10187, 1), (10176, 3)] 0, attempt 10028 0 10028 0 [(10188, 1), (10176, 3)] 0, attempt 10029 0 10029 0 [(10189, 1), (10176, 3)] 0, attempt 10030 0 10030 0 [(10190, 1), (10176, 3)] 0, attempt 10031 0 10031 0 [(10191, 1), (10176, 3)] 0, attempt 10032 0 10032 0 [(10192, 1), (10176, 3)] 0, attempt 10033 0 10033 0 [(10193, 1), (10176, 3)] 0, attempt 10034 0 10034 0 [(10194, 1), (10176, 3)] 0, attempt 10035 0 10035 0 [(10195, 1), (10176, 3)] 0, attempt 10036 0 10036 0 [(10196, 1), (10176, 3)] 0, attempt 10037 0 10037 0 [(10197, 1), (10176, 3)] 0, attempt 10038 0 10038 0 [(10198, 1), (10176, 3)] 0, attempt 10039 0 10039 0 [(10199, 1), (10176, 3)] 0, attempt 10040 0 10040 0 [(10200, 1), (10176, 3)] 0, attempt 10041 0 10041 0 [(10201, 1), (10176, 3)] 0, attempt 10042 0 10042 0 [(10202, 1), (10176, 3)] 0, attempt 10043 0 10043 0 [(10203, 1), (10176, 3)] 0, attempt 10044 0 10044 0 [(10204, 1), (10176, 3)] 0, attempt 10045 0 10045 0 [(10205, 1), (10176, 3)] 0, attempt 10046 0 10046 0 [(10206, 1), (10176, 3)] 0, attempt 10047 0 10047 0 [(10207, 1), (10176, 3)] 0]
def counters010 : List Nat := [10048, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10016
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 10048 0 10048 0 [(10208, 1), (10176, 3)] 0, attempt 10049 0 10049 0 [(10209, 1), (10176, 3)] 0, attempt 10050 0 10050 0 [(10210, 1), (10176, 3)] 0, attempt 10051 0 10051 0 [(10211, 1), (10176, 3)] 0, attempt 10052 0 10052 0 [(10212, 1), (10176, 3)] 0, attempt 10053 0 10053 0 [(10213, 1), (10176, 3)] 0, attempt 10054 0 10054 0 [(10214, 1), (10176, 3)] 0, attempt 10055 0 10055 0 [(10215, 1), (10176, 3)] 0, attempt 10056 0 10056 0 [(10216, 1), (10176, 3)] 0, attempt 10057 0 10057 0 [(10217, 1), (10176, 3)] 0, attempt 10058 0 10058 0 [(10218, 1), (10176, 3)] 0, attempt 10059 0 10059 0 [(10219, 1), (10176, 3)] 0, attempt 10060 0 10060 0 [(10220, 1), (10176, 3)] 0, attempt 10061 0 10061 0 [(10221, 1), (10176, 3)] 0, attempt 10062 0 10062 0 [(10222, 1), (10176, 3)] 0, attempt 10063 0 10063 0 [(10223, 1), (10176, 3)] 0, attempt 10064 0 10064 0 [(10224, 1), (10176, 3)] 0, attempt 10065 0 10065 0 [(10225, 1), (10176, 3)] 0, attempt 10066 0 10066 0 [(10226, 1), (10176, 3)] 0, attempt 10067 0 10067 0 [(10227, 1), (10176, 3)] 0, attempt 10068 0 10068 0 [(10228, 1), (10176, 3)] 0, attempt 10069 0 10069 0 [(10229, 1), (10176, 3)] 0, attempt 10070 0 10070 0 [(10230, 1), (10176, 3)] 0, attempt 10071 0 10071 0 [(10231, 1), (10176, 3)] 0, attempt 10072 0 10072 0 [(10232, 1), (10176, 3)] 0, attempt 10073 0 10073 0 [(10233, 1), (10176, 3)] 0, attempt 10074 0 10074 0 [(10234, 1), (10176, 3)] 0, attempt 10075 0 10075 0 [(10235, 1), (10176, 3)] 0, attempt 10076 0 10076 0 [(10236, 1), (10176, 3)] 0, attempt 10077 0 10077 0 [(10237, 1), (10176, 3)] 0, attempt 10078 0 10078 0 [(10238, 1), (10176, 3)] 0, attempt 10079 0 10079 0 [(10239, 1), (10176, 3)] 0]
def counters011 : List Nat := [10080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10048
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 10080 0 10080 0 [(10241, 1), (10240, 3)] 0, attempt 10081 0 10081 0 [(10242, 1), (10240, 3)] 0, attempt 10082 0 10082 0 [(10243, 1), (10240, 3)] 0, attempt 10083 0 10083 0 [(10244, 1), (10240, 3)] 0, attempt 10084 0 10084 0 [(10245, 1), (10240, 3)] 0, attempt 10085 0 10085 0 [(10246, 1), (10240, 3)] 0, attempt 10086 0 10086 0 [(10247, 1), (10240, 3)] 0, attempt 10087 0 10087 0 [(10248, 1), (10240, 3)] 0, attempt 10088 0 10088 0 [(10249, 1), (10240, 3)] 0, attempt 10089 0 10089 0 [(10250, 1), (10240, 3)] 0, attempt 10090 0 10090 0 [(10251, 1), (10240, 3)] 0, attempt 10091 0 10091 0 [(10252, 1), (10240, 3)] 0, attempt 10092 0 10092 0 [(10253, 1), (10240, 3)] 0, attempt 10093 0 10093 0 [(10254, 1), (10240, 3)] 0, attempt 10094 0 10094 0 [(10255, 1), (10240, 3)] 0, attempt 10095 0 10095 0 [(10256, 1), (10240, 3)] 0, attempt 10096 0 10096 0 [(10257, 1), (10240, 3)] 0, attempt 10097 0 10097 0 [(10258, 1), (10240, 3)] 0, attempt 10098 0 10098 0 [(10259, 1), (10240, 3)] 0, attempt 10099 0 10099 0 [(10260, 1), (10240, 3)] 0, attempt 10100 0 10100 0 [(10261, 1), (10240, 3)] 0, attempt 10101 0 10101 0 [(10262, 1), (10240, 3)] 0, attempt 10102 0 10102 0 [(10263, 1), (10240, 3)] 0, attempt 10103 0 10103 0 [(10264, 1), (10240, 3)] 0, attempt 10104 0 10104 0 [(10265, 1), (10240, 3)] 0, attempt 10105 0 10105 0 [(10266, 1), (10240, 3)] 0, attempt 10106 0 10106 0 [(10267, 1), (10240, 3)] 0, attempt 10107 0 10107 0 [(10268, 1), (10240, 3)] 0, attempt 10108 0 10108 0 [(10269, 1), (10240, 3)] 0, attempt 10109 0 10109 0 [(10270, 1), (10240, 3)] 0, attempt 10110 0 10110 0 [(10271, 1), (10240, 3)] 0, attempt 10111 0 10111 0 [(10272, 1), (10240, 3)] 0]
def counters012 : List Nat := [10112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10080
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 10112 0 10112 0 [(10273, 1), (10240, 3)] 0, attempt 10113 0 10113 0 [(10274, 1), (10240, 3)] 0, attempt 10114 0 10114 0 [(10275, 1), (10240, 3)] 0, attempt 10115 0 10115 0 [(10276, 1), (10240, 3)] 0, attempt 10116 0 10116 0 [(10277, 1), (10240, 3)] 0, attempt 10117 0 10117 0 [(10278, 1), (10240, 3)] 0, attempt 10118 0 10118 0 [(10279, 1), (10240, 3)] 0, attempt 10119 0 10119 0 [(10280, 1), (10240, 3)] 0, attempt 10120 0 10120 0 [(10281, 1), (10240, 3)] 0, attempt 10121 0 10121 0 [(10282, 1), (10240, 3)] 0, attempt 10122 0 10122 0 [(10283, 1), (10240, 3)] 0, attempt 10123 0 10123 0 [(10284, 1), (10240, 3)] 0, attempt 10124 0 10124 0 [(10285, 1), (10240, 3)] 0, attempt 10125 0 10125 0 [(10286, 1), (10240, 3)] 0, attempt 10126 0 10126 0 [(10287, 1), (10240, 3)] 0, attempt 10127 0 10127 0 [(10288, 1), (10240, 3)] 0, attempt 10128 0 10128 0 [(10289, 1), (10240, 3)] 0, attempt 10129 0 10129 0 [(10290, 1), (10240, 3)] 0, attempt 10130 0 10130 0 [(10291, 1), (10240, 3)] 0, attempt 10131 0 10131 0 [(10292, 1), (10240, 3)] 0, attempt 10132 0 10132 0 [(10293, 1), (10240, 3)] 0, attempt 10133 0 10133 0 [(10294, 1), (10240, 3)] 0, attempt 10134 0 10134 0 [(10295, 1), (10240, 3)] 0, attempt 10135 0 10135 0 [(10296, 1), (10240, 3)] 0, attempt 10136 0 10136 0 [(10297, 1), (10240, 3)] 0, attempt 10137 0 10137 0 [(10298, 1), (10240, 3)] 0, attempt 10138 0 10138 0 [(10299, 1), (10240, 3)] 0, attempt 10139 0 10139 0 [(10300, 1), (10240, 3)] 0, attempt 10140 0 10140 0 [(10301, 1), (10240, 3)] 0, attempt 10141 0 10141 0 [(10302, 1), (10240, 3)] 0, attempt 10142 0 10142 0 [(10303, 1), (10240, 3)] 0, attempt 10143 0 10143 0 [(10305, 1), (10304, 3)] 0]
def counters013 : List Nat := [10144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10112
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 10144 0 10144 0 [(10306, 1), (10304, 3)] 0, attempt 10145 0 10145 0 [(10307, 1), (10304, 3)] 0, attempt 10146 0 10146 0 [(10308, 1), (10304, 3)] 0, attempt 10147 0 10147 0 [(10309, 1), (10304, 3)] 0, attempt 10148 0 10148 0 [(10310, 1), (10304, 3)] 0, attempt 10149 0 10149 0 [(10311, 1), (10304, 3)] 0, attempt 10150 0 10150 0 [(10312, 1), (10304, 3)] 0, attempt 10151 0 10151 0 [(10313, 1), (10304, 3)] 0, attempt 10152 0 10152 0 [(10314, 1), (10304, 3)] 0, attempt 10153 0 10153 0 [(10315, 1), (10304, 3)] 0, attempt 10154 0 10154 0 [(10316, 1), (10304, 3)] 0, attempt 10155 0 10155 0 [(10317, 1), (10304, 3)] 0, attempt 10156 0 10156 0 [(10318, 1), (10304, 3)] 0, attempt 10157 0 10157 0 [(10319, 1), (10304, 3)] 0, attempt 10158 0 10158 0 [(10320, 1), (10304, 3)] 0, attempt 10159 0 10159 0 [(10321, 1), (10304, 3)] 0, attempt 10160 0 10160 0 [(10322, 1), (10304, 3)] 0, attempt 10161 0 10161 0 [(10323, 1), (10304, 3)] 0, attempt 10162 0 10162 0 [(10324, 1), (10304, 3)] 0, attempt 10163 0 10163 0 [(10325, 1), (10304, 3)] 0, attempt 10164 0 10164 0 [(10326, 1), (10304, 3)] 0, attempt 10165 0 10165 0 [(10327, 1), (10304, 3)] 0, attempt 10166 0 10166 0 [(10328, 1), (10304, 3)] 0, attempt 10167 0 10167 0 [(10329, 1), (10304, 3)] 0, attempt 10168 0 10168 0 [(10330, 1), (10304, 3)] 0, attempt 10169 0 10169 0 [(10331, 1), (10304, 3)] 0, attempt 10170 0 10170 0 [(10332, 1), (10304, 3)] 0, attempt 10171 0 10171 0 [(10333, 1), (10304, 3)] 0, attempt 10172 0 10172 0 [(10334, 1), (10304, 3)] 0, attempt 10173 0 10173 0 [(10335, 1), (10304, 3)] 0, attempt 10174 0 10174 0 [(10336, 1), (10304, 3)] 0, attempt 10175 0 10175 0 [(10337, 1), (10304, 3)] 0]
def counters014 : List Nat := [10176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10144
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 10176 0 10176 0 [(10338, 1), (10304, 3)] 0, attempt 10177 0 10177 0 [(10339, 1), (10304, 3)] 0, attempt 10178 0 10178 0 [(10340, 1), (10304, 3)] 0, attempt 10179 0 10179 0 [(10341, 1), (10304, 3)] 0, attempt 10180 0 10180 0 [(10342, 1), (10304, 3)] 0, attempt 10181 0 10181 0 [(10343, 1), (10304, 3)] 0, attempt 10182 0 10182 0 [(10344, 1), (10304, 3)] 0, attempt 10183 0 10183 0 [(10345, 1), (10304, 3)] 0, attempt 10184 0 10184 0 [(10346, 1), (10304, 3)] 0, attempt 10185 0 10185 0 [(10347, 1), (10304, 3)] 0, attempt 10186 0 10186 0 [(10348, 1), (10304, 3)] 0, attempt 10187 0 10187 0 [(10349, 1), (10304, 3)] 0, attempt 10188 0 10188 0 [(10350, 1), (10304, 3)] 0, attempt 10189 0 10189 0 [(10351, 1), (10304, 3)] 0, attempt 10190 0 10190 0 [(10352, 1), (10304, 3)] 0, attempt 10191 0 10191 0 [(10353, 1), (10304, 3)] 0, attempt 10192 0 10192 0 [(10354, 1), (10304, 3)] 0, attempt 10193 0 10193 0 [(10355, 1), (10304, 3)] 0, attempt 10194 0 10194 0 [(10356, 1), (10304, 3)] 0, attempt 10195 0 10195 0 [(10357, 1), (10304, 3)] 0, attempt 10196 0 10196 0 [(10358, 1), (10304, 3)] 0, attempt 10197 0 10197 0 [(10359, 1), (10304, 3)] 0, attempt 10198 0 10198 0 [(10360, 1), (10304, 3)] 0, attempt 10199 0 10199 0 [(10361, 1), (10304, 3)] 0, attempt 10200 0 10200 0 [(10362, 1), (10304, 3)] 0, attempt 10201 0 10201 0 [(10363, 1), (10304, 3)] 0, attempt 10202 0 10202 0 [(10364, 1), (10304, 3)] 0, attempt 10203 0 10203 0 [(10365, 1), (10304, 3)] 0, attempt 10204 0 10204 0 [(10366, 1), (10304, 3)] 0, attempt 10205 0 10205 0 [(10367, 1), (10304, 3)] 0, attempt 10206 0 10206 0 [(10369, 1), (10368, 3)] 0, attempt 10207 0 10207 0 [(10370, 1), (10368, 3)] 0]
def counters015 : List Nat := [10208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10176
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 10208 0 10208 0 [(10371, 1), (10368, 3)] 0, attempt 10209 0 10209 0 [(10372, 1), (10368, 3)] 0, attempt 10210 0 10210 0 [(10373, 1), (10368, 3)] 0, attempt 10211 0 10211 0 [(10374, 1), (10368, 3)] 0, attempt 10212 0 10212 0 [(10375, 1), (10368, 3)] 0, attempt 10213 0 10213 0 [(10376, 1), (10368, 3)] 0, attempt 10214 0 10214 0 [(10377, 1), (10368, 3)] 0, attempt 10215 0 10215 0 [(10378, 1), (10368, 3)] 0, attempt 10216 0 10216 0 [(10379, 1), (10368, 3)] 0, attempt 10217 0 10217 0 [(10380, 1), (10368, 3)] 0, attempt 10218 0 10218 0 [(10381, 1), (10368, 3)] 0, attempt 10219 0 10219 0 [(10382, 1), (10368, 3)] 0, attempt 10220 0 10220 0 [(10383, 1), (10368, 3)] 0, attempt 10221 0 10221 0 [(10384, 1), (10368, 3)] 0, attempt 10222 0 10222 0 [(10385, 1), (10368, 3)] 0, attempt 10223 0 10223 0 [(10386, 1), (10368, 3)] 0, attempt 10224 0 10224 0 [(10387, 1), (10368, 3)] 0, attempt 10225 0 10225 0 [(10388, 1), (10368, 3)] 0, attempt 10226 0 10226 0 [(10389, 1), (10368, 3)] 0, attempt 10227 0 10227 0 [(10390, 1), (10368, 3)] 0, attempt 10228 0 10228 0 [(10391, 1), (10368, 3)] 0, attempt 10229 0 10229 0 [(10392, 1), (10368, 3)] 0, attempt 10230 0 10230 0 [(10393, 1), (10368, 3)] 0, attempt 10231 0 10231 0 [(10394, 1), (10368, 3)] 0, attempt 10232 0 10232 0 [(10395, 1), (10368, 3)] 0, attempt 10233 0 10233 0 [(10396, 1), (10368, 3)] 0, attempt 10234 0 10234 0 [(10397, 1), (10368, 3)] 0, attempt 10235 0 10235 0 [(10398, 1), (10368, 3)] 0, attempt 10236 0 10236 0 [(10399, 1), (10368, 3)] 0, attempt 10237 0 10237 0 [(10400, 1), (10368, 3)] 0, attempt 10238 0 10238 0 [(10401, 1), (10368, 3)] 0, attempt 10239 0 10239 0 [(10402, 1), (10368, 3)] 0]
def counters016 : List Nat := [10240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10208
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10240
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10208
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 10208 10240 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 10208) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10176
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 10176 10208 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 10176) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10144
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 10144 10176 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 10144) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10112
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 10112 10144 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 10112) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10080
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 10080 10112 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 10080) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10048
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 10048 10080 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 10048) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 10016
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 10016 10048 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 10016) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9984
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 9984 10016 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 9984) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9952
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 9952 9984 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 9952) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9920
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 9920 9952 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 9920) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9888
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 9888 9920 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 9888) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9856
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 9856 9888 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 9856) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9824
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 9824 9856 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 9824) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9792
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 9792 9824 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 9792) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9760
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 9760 9792 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 9760) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 9728
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 9728 9760 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 9728) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr19
