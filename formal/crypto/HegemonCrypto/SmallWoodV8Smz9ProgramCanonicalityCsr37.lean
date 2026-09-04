import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr36

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 18944 29 5 0 [(30114, 1), (9152, 158)] 0, attempt 18945 29 6 0 [(30178, 1), (9216, 158)] 0, attempt 18946 29 7 0 [(30242, 1), (9280, 158)] 0, attempt 18947 29 8 0 [(30306, 1)] 545, attempt 18948 29 9 0 [(30370, 1)] 549, attempt 18949 29 10 0 [(30434, 1)] 543, attempt 18950 29 11 0 [(30498, 1)] 0, attempt 18951 29 12 0 [(30562, 1)] 0, attempt 18952 29 13 0 [(30626, 1)] 0, attempt 18953 29 14 0 [(30690, 1)] 0, attempt 18954 29 15 0 [(30754, 1)] 544, attempt 18955 29 16 0 [(29795, 1), (40418, 158), (9344, 158)] 0, attempt 18956 29 17 0 [(29859, 1), (40482, 158), (9408, 158)] 0, attempt 18957 29 18 0 [(29923, 1), (40546, 158), (9472, 158)] 0, attempt 18958 29 19 0 [(29987, 1), (40610, 158), (9536, 158)] 0, attempt 18959 29 20 0 [(30051, 1), (40674, 158), (9600, 158)] 0, attempt 18960 29 21 0 [(30115, 1), (40738, 158), (9664, 158)] 0, attempt 18961 29 22 0 [(30179, 1), (40802, 158), (9728, 158)] 0, attempt 18962 29 23 0 [(30243, 1), (40866, 158), (9792, 158)] 0, attempt 18963 29 24 0 [(30307, 1), (40930, 158)] 0, attempt 18964 29 25 0 [(30371, 1), (40994, 158)] 0, attempt 18965 29 26 0 [(30435, 1), (41058, 158)] 0, attempt 18966 29 27 0 [(30499, 1), (41122, 158)] 0, attempt 18967 29 28 0 [(30563, 1), (41186, 158)] 0, attempt 18968 29 29 0 [(30627, 1), (41250, 158)] 0, attempt 18969 29 30 0 [(30691, 1), (41314, 158)] 0, attempt 18970 29 31 0 [(30755, 1), (41378, 158)] 0, attempt 18971 29 32 0 [(29796, 1), (40419, 158), (9856, 158)] 0, attempt 18972 29 33 0 [(29860, 1), (40483, 158), (9920, 158)] 0, attempt 18973 29 34 0 [(29924, 1), (40547, 158), (9984, 158)] 0, attempt 18974 29 35 0 [(29988, 1), (40611, 158), (10048, 158)] 0, attempt 18975 29 36 0 [(30052, 1), (40675, 158), (10112, 158)] 0]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18944
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 18976 29 37 0 [(30116, 1), (40739, 158), (10176, 158)] 0, attempt 18977 29 38 0 [(30180, 1), (40803, 158), (10240, 158)] 0, attempt 18978 29 39 0 [(30308, 1), (40931, 158)] 0, attempt 18979 29 40 0 [(30372, 1), (40995, 158)] 0, attempt 18980 29 41 0 [(30436, 1), (41059, 158)] 0, attempt 18981 29 42 0 [(30500, 1), (41123, 158)] 1, attempt 18982 29 43 0 [(30564, 1), (41187, 158)] 0, attempt 18983 29 44 0 [(30628, 1), (41251, 158)] 0, attempt 18984 29 45 0 [(30692, 1), (41315, 158)] 0, attempt 18985 29 46 0 [(30756, 1), (41379, 158)] 0, attempt 18986 30 0 0 [(7040, 1), (40420, 3)] 0, attempt 18987 30 1 0 [(7104, 1), (40484, 3)] 0, attempt 18988 30 2 0 [(7168, 1), (40548, 3)] 0, attempt 18989 30 3 0 [(7232, 1), (40612, 3)] 0, attempt 18990 30 4 0 [(7296, 1), (40676, 3)] 0, attempt 18991 30 5 0 [(7360, 1), (40740, 3)] 0, attempt 18992 30 6 0 [(7424, 1), (40804, 3)] 0, attempt 18993 31 0 0 [(29797, 1), (8832, 158)] 0, attempt 18994 31 1 0 [(29861, 1), (8896, 158)] 0, attempt 18995 31 2 0 [(29925, 1), (8960, 158)] 0, attempt 18996 31 3 0 [(29989, 1), (9024, 158)] 0, attempt 18997 31 4 0 [(30053, 1), (9088, 158)] 0, attempt 18998 31 5 0 [(30117, 1), (9152, 158)] 0, attempt 18999 31 6 0 [(30181, 1), (9216, 158)] 0, attempt 19000 31 7 0 [(30245, 1), (9280, 158)] 0, attempt 19001 31 8 0 [(30309, 1)] 545, attempt 19002 31 9 0 [(30373, 1)] 549, attempt 19003 31 10 0 [(30437, 1)] 543, attempt 19004 31 11 0 [(30501, 1)] 0, attempt 19005 31 12 0 [(30565, 1)] 0, attempt 19006 31 13 0 [(30629, 1)] 0, attempt 19007 31 14 0 [(30693, 1)] 0]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18976
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 19008 31 15 0 [(30757, 1)] 544, attempt 19009 31 16 0 [(29798, 1), (40421, 158), (9344, 158)] 0, attempt 19010 31 17 0 [(29862, 1), (40485, 158), (9408, 158)] 0, attempt 19011 31 18 0 [(29926, 1), (40549, 158), (9472, 158)] 0, attempt 19012 31 19 0 [(29990, 1), (40613, 158), (9536, 158)] 0, attempt 19013 31 20 0 [(30054, 1), (40677, 158), (9600, 158)] 0, attempt 19014 31 21 0 [(30118, 1), (40741, 158), (9664, 158)] 0, attempt 19015 31 22 0 [(30182, 1), (40805, 158), (9728, 158)] 0, attempt 19016 31 23 0 [(30246, 1), (40869, 158), (9792, 158)] 0, attempt 19017 31 24 0 [(30310, 1), (40933, 158)] 0, attempt 19018 31 25 0 [(30374, 1), (40997, 158)] 0, attempt 19019 31 26 0 [(30438, 1), (41061, 158)] 0, attempt 19020 31 27 0 [(30502, 1), (41125, 158)] 0, attempt 19021 31 28 0 [(30566, 1), (41189, 158)] 0, attempt 19022 31 29 0 [(30630, 1), (41253, 158)] 0, attempt 19023 31 30 0 [(30694, 1), (41317, 158)] 0, attempt 19024 31 31 0 [(30758, 1), (41381, 158)] 0, attempt 19025 31 32 0 [(29799, 1), (40422, 158), (10304, 158)] 0, attempt 19026 31 33 0 [(29863, 1), (40486, 158), (10368, 158)] 0, attempt 19027 31 34 0 [(29927, 1), (40550, 158), (10432, 158)] 0, attempt 19028 31 35 0 [(29991, 1), (40614, 158), (10496, 158)] 0, attempt 19029 31 36 0 [(30055, 1), (40678, 158), (10560, 158)] 0, attempt 19030 31 37 0 [(30119, 1), (40742, 158), (10624, 158)] 0, attempt 19031 31 38 0 [(30183, 1), (40806, 158), (10688, 158)] 0, attempt 19032 31 39 0 [(30311, 1), (40934, 158)] 0, attempt 19033 31 40 0 [(30375, 1), (40998, 158)] 0, attempt 19034 31 41 0 [(30439, 1), (41062, 158)] 0, attempt 19035 31 42 0 [(30503, 1), (41126, 158)] 1, attempt 19036 31 43 0 [(30567, 1), (41190, 158)] 0, attempt 19037 31 44 0 [(30631, 1), (41254, 158)] 0, attempt 19038 31 45 0 [(30695, 1), (41318, 158)] 0, attempt 19039 31 46 0 [(30759, 1), (41382, 158)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19008
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 19040 32 0 0 [(7488, 1), (40423, 3)] 0, attempt 19041 32 1 0 [(7552, 1), (40487, 3)] 0, attempt 19042 32 2 0 [(7616, 1), (40551, 3)] 0, attempt 19043 32 3 0 [(7680, 1), (40615, 3)] 0, attempt 19044 32 4 0 [(7744, 1), (40679, 3)] 0, attempt 19045 32 5 0 [(7808, 1), (40743, 3)] 0, attempt 19046 32 6 0 [(7872, 1), (40807, 3)] 0, attempt 19047 33 0 0 [(29800, 1), (8832, 158)] 0, attempt 19048 33 1 0 [(29864, 1), (8896, 158)] 0, attempt 19049 33 2 0 [(29928, 1), (8960, 158)] 0, attempt 19050 33 3 0 [(29992, 1), (9024, 158)] 0, attempt 19051 33 4 0 [(30056, 1), (9088, 158)] 0, attempt 19052 33 5 0 [(30120, 1), (9152, 158)] 0, attempt 19053 33 6 0 [(30184, 1), (9216, 158)] 0, attempt 19054 33 7 0 [(30248, 1), (9280, 158)] 0, attempt 19055 33 8 0 [(30312, 1)] 207, attempt 19056 33 9 0 [(30376, 1)] 550, attempt 19057 33 10 0 [(30440, 1)] 543, attempt 19058 33 11 0 [(30504, 1)] 0, attempt 19059 33 12 0 [(30568, 1)] 0, attempt 19060 33 13 0 [(30632, 1)] 0, attempt 19061 33 14 0 [(30696, 1)] 0, attempt 19062 33 15 0 [(30760, 1)] 544, attempt 19063 33 16 0 [(29801, 1), (40424, 158), (9344, 158)] 0, attempt 19064 33 17 0 [(29865, 1), (40488, 158), (9408, 158)] 0, attempt 19065 33 18 0 [(29929, 1), (40552, 158), (9472, 158)] 0, attempt 19066 33 19 0 [(29993, 1), (40616, 158), (9536, 158)] 0, attempt 19067 33 20 0 [(30057, 1), (40680, 158), (9600, 158)] 0, attempt 19068 33 21 0 [(30121, 1), (40744, 158), (9664, 158)] 0, attempt 19069 33 22 0 [(30313, 1), (40936, 158)] 0, attempt 19070 33 23 0 [(30377, 1), (41000, 158)] 0, attempt 19071 33 24 0 [(30441, 1), (41064, 158)] 0]
def counters004 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19040
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 19072 33 25 0 [(30505, 1), (41128, 158)] 1, attempt 19073 33 26 0 [(30569, 1), (41192, 158)] 0, attempt 19074 33 27 0 [(30633, 1), (41256, 158)] 0, attempt 19075 33 28 0 [(30697, 1), (41320, 158)] 0, attempt 19076 33 29 0 [(30761, 1), (41384, 158)] 0, attempt 19077 34 0 0 [(7936, 1), (40425, 3)] 0, attempt 19078 34 1 0 [(8000, 1), (40489, 3)] 0, attempt 19079 34 2 0 [(8064, 1), (40553, 3)] 0, attempt 19080 34 3 0 [(8128, 1), (40617, 3)] 0, attempt 19081 34 4 0 [(8192, 1), (40681, 3)] 0, attempt 19082 34 5 0 [(8256, 1), (40745, 3)] 0, attempt 19083 34 6 0 [(8320, 1), (40809, 3)] 0, attempt 19084 35 0 0 [(29821, 1)] 0, attempt 19085 35 1 0 [(29885, 1)] 0, attempt 19086 35 2 0 [(29949, 1)] 0, attempt 19087 35 3 0 [(30013, 1)] 0, attempt 19088 35 4 0 [(30077, 1)] 0, attempt 19089 35 5 0 [(30141, 1)] 0, attempt 19090 35 6 0 [(30205, 1)] 0, attempt 19091 35 7 0 [(30269, 1)] 0, attempt 19092 35 8 0 [(30333, 1)] 0, attempt 19093 35 9 0 [(30397, 1)] 0, attempt 19094 35 10 0 [(30461, 1)] 0, attempt 19095 35 11 0 [(30525, 1)] 0, attempt 19096 35 12 0 [(30589, 1)] 0, attempt 19097 35 13 0 [(30653, 1)] 0, attempt 19098 35 14 0 [(30717, 1)] 0, attempt 19099 35 15 0 [(30781, 1)] 0, attempt 19100 35 16 0 [(29822, 1)] 0, attempt 19101 35 17 0 [(29886, 1)] 0, attempt 19102 35 18 0 [(29950, 1)] 0, attempt 19103 35 19 0 [(30014, 1)] 0]
def counters005 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19072
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 19104 35 20 0 [(30078, 1)] 0, attempt 19105 35 21 0 [(30142, 1)] 0, attempt 19106 35 22 0 [(30206, 1)] 0, attempt 19107 35 23 0 [(30270, 1)] 0, attempt 19108 35 24 0 [(30334, 1)] 0, attempt 19109 35 25 0 [(30398, 1)] 0, attempt 19110 35 26 0 [(30462, 1)] 0, attempt 19111 35 27 0 [(30526, 1)] 0, attempt 19112 35 28 0 [(30590, 1)] 0, attempt 19113 35 29 0 [(30654, 1)] 0, attempt 19114 35 30 0 [(30718, 1)] 0, attempt 19115 35 31 0 [(30782, 1)] 0, attempt 19116 35 32 0 [(29823, 1)] 0, attempt 19117 35 33 0 [(29887, 1)] 0, attempt 19118 35 34 0 [(29951, 1)] 0, attempt 19119 35 35 0 [(30015, 1)] 0, attempt 19120 35 36 0 [(30079, 1)] 0, attempt 19121 35 37 0 [(30143, 1)] 0, attempt 19122 35 38 0 [(30207, 1)] 0, attempt 19123 35 39 0 [(30271, 1)] 0, attempt 19124 35 40 0 [(30335, 1)] 0, attempt 19125 35 41 0 [(30399, 1)] 0, attempt 19126 35 42 0 [(30463, 1)] 0, attempt 19127 35 43 0 [(30527, 1)] 0, attempt 19128 35 44 0 [(30591, 1)] 0, attempt 19129 35 45 0 [(30655, 1)] 0, attempt 19130 35 46 0 [(30719, 1)] 0, attempt 19131 35 47 0 [(30783, 1)] 0, attempt 19132 36 0 1 [(41408, 307)] 0, attempt 19133 36 1 1 [(41409, 307)] 0, attempt 19134 36 2 1 [(41410, 307)] 0, attempt 19135 36 3 1 [(41411, 307)] 0]
def counters006 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19104
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 19136 36 4 1 [(41412, 307)] 0, attempt 19137 36 5 1 [(41413, 307)] 0, attempt 19138 36 6 1 [(41414, 307)] 0, attempt 19139 36 7 1 [(41415, 307)] 0, attempt 19140 36 8 1 [(41416, 307)] 0, attempt 19141 36 9 1 [(41417, 307)] 0, attempt 19142 36 10 1 [(41418, 307)] 0, attempt 19143 36 11 1 [(41419, 307)] 0, attempt 19144 36 12 1 [(41420, 307)] 0, attempt 19145 36 13 1 [(41421, 307)] 0, attempt 19146 36 14 1 [(41422, 307)] 0, attempt 19147 36 15 1 [(41423, 307)] 0, attempt 19148 36 16 1 [(41424, 307)] 0, attempt 19149 36 17 1 [(41425, 307)] 0, attempt 19150 36 18 1 [(41426, 307)] 0, attempt 19151 36 19 1 [(41427, 307)] 0, attempt 19152 36 20 1 [(41428, 307)] 0, attempt 19153 36 21 1 [(41429, 307)] 0, attempt 19154 36 22 1 [(41430, 307)] 0, attempt 19155 36 23 1 [(41431, 307)] 0, attempt 19156 36 24 1 [(41432, 307)] 0, attempt 19157 36 25 1 [(41433, 307)] 0, attempt 19158 36 26 1 [(41434, 307)] 0, attempt 19159 36 27 1 [(41435, 307)] 0, attempt 19160 36 28 1 [(41436, 307)] 0, attempt 19161 36 29 1 [(41437, 307)] 0, attempt 19162 36 30 1 [(41438, 307)] 0, attempt 19163 36 31 1 [(41439, 307)] 0, attempt 19164 36 32 1 [(41440, 307)] 0, attempt 19165 36 33 1 [(41441, 307)] 0, attempt 19166 36 34 1 [(41442, 307)] 0, attempt 19167 36 35 1 [(41443, 307)] 0]
def counters007 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19136
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 19168 36 36 1 [(41444, 307)] 0, attempt 19169 36 37 1 [(41445, 307)] 0, attempt 19170 36 38 1 [(41446, 307)] 0, attempt 19171 36 39 1 [(41447, 307)] 0, attempt 19172 36 40 1 [(41448, 307)] 0, attempt 19173 36 41 1 [(41449, 307)] 0, attempt 19174 36 42 1 [(41450, 307)] 0, attempt 19175 36 43 1 [(41451, 307)] 0, attempt 19176 36 44 1 [(41452, 307)] 0, attempt 19177 36 45 1 [(41453, 307)] 0, attempt 19178 36 46 1 [(41454, 307)] 0, attempt 19179 36 47 1 [(41455, 307)] 0, attempt 19180 36 48 1 [(41456, 307)] 0, attempt 19181 36 49 1 [(41457, 307)] 0, attempt 19182 36 50 1 [(41458, 307)] 0, attempt 19183 36 51 1 [(41459, 307)] 0, attempt 19184 36 52 1 [(41460, 307)] 0, attempt 19185 36 53 1 [(41461, 307)] 0, attempt 19186 36 54 1 [(41462, 307)] 0, attempt 19187 36 55 1 [(41463, 307)] 0, attempt 19188 36 56 1 [(41464, 307)] 0, attempt 19189 36 57 1 [(41465, 307)] 0, attempt 19190 36 58 1 [(41466, 307)] 0, attempt 19191 36 59 1 [(41467, 307)] 0, attempt 19192 36 60 1 [(41468, 307)] 0, attempt 19193 36 61 1 [(41469, 307)] 0, attempt 19194 36 62 1 [(41470, 307)] 0, attempt 19195 36 63 1 [(41471, 307)] 0, attempt 19196 36 64 1 [(41472, 307)] 0, attempt 19197 36 65 1 [(41473, 307)] 0, attempt 19198 36 66 1 [(41474, 307)] 0, attempt 19199 36 67 1 [(41475, 307)] 0]
def counters008 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19168
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 19200 36 68 1 [(41476, 307)] 0, attempt 19201 36 69 1 [(41477, 307)] 0, attempt 19202 36 70 1 [(41478, 307)] 0, attempt 19203 36 71 1 [(41479, 307)] 0, attempt 19204 36 72 1 [(41480, 307)] 0, attempt 19205 36 73 1 [(41481, 307)] 0, attempt 19206 36 74 1 [(41482, 307)] 0, attempt 19207 36 75 1 [(41483, 307)] 0, attempt 19208 36 76 1 [(41484, 307)] 0, attempt 19209 36 77 1 [(41485, 307)] 0, attempt 19210 36 78 1 [(41486, 307)] 0, attempt 19211 36 79 1 [(41487, 307)] 0, attempt 19212 36 80 1 [(41488, 307)] 0, attempt 19213 36 81 1 [(41489, 307)] 0, attempt 19214 36 82 1 [(41490, 307)] 0, attempt 19215 36 83 1 [(41491, 307)] 0, attempt 19216 36 84 1 [(41492, 307)] 0, attempt 19217 36 85 1 [(41493, 307)] 0, attempt 19218 36 86 1 [(41494, 307)] 0, attempt 19219 36 87 1 [(41495, 307)] 0, attempt 19220 36 88 1 [(41496, 307)] 0, attempt 19221 36 89 1 [(41497, 307)] 0, attempt 19222 36 90 1 [(41498, 307)] 0, attempt 19223 36 91 1 [(41499, 307)] 0, attempt 19224 36 92 1 [(41500, 307)] 0, attempt 19225 36 93 1 [(41501, 307)] 0, attempt 19226 37 0 0 [(41502, 1)] 67, attempt 19227 37 1 0 [(41503, 1)] 68, attempt 19228 37 2 0 [(41504, 1)] 69, attempt 19229 37 3 0 [(41505, 1)] 70, attempt 19230 37 4 0 [(41506, 1)] 71, attempt 19231 37 5 0 [(41507, 1)] 72]
def counters009 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19200
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 19232 37 6 0 [(41508, 1)] 73, attempt 19233 37 7 0 [(41509, 1)] 74, attempt 19234 37 8 0 [(41510, 1)] 75, attempt 19235 37 9 0 [(41511, 1)] 76, attempt 19236 37 10 0 [(41512, 1)] 77, attempt 19237 37 11 0 [(41513, 1)] 78, attempt 19238 37 12 0 [(41514, 1)] 79, attempt 19239 37 13 0 [(41515, 1)] 80, attempt 19240 37 14 0 [(41516, 1)] 81, attempt 19241 37 15 0 [(41517, 1)] 82, attempt 19242 37 16 0 [(41518, 1)] 83, attempt 19243 37 17 0 [(41519, 1)] 84, attempt 19244 38 0 0 [(41502, 1)] 0, attempt 19245 38 1 0 [(41503, 1)] 0, attempt 19246 38 2 0 [(41504, 1)] 0, attempt 19247 38 3 0 [(41505, 1)] 0, attempt 19248 38 4 0 [(41506, 1)] 0, attempt 19249 38 5 0 [(41507, 1)] 0, attempt 19250 38 6 0 [(41508, 1)] 0, attempt 19251 38 7 0 [(41509, 1)] 0, attempt 19252 38 8 0 [(41510, 1)] 0, attempt 19253 38 9 0 [(41511, 1)] 0, attempt 19254 38 10 0 [(41512, 1)] 0, attempt 19255 38 11 0 [(41513, 1)] 0, attempt 19256 38 12 0 [(41514, 1)] 0, attempt 19257 38 13 0 [(41515, 1)] 0, attempt 19258 38 14 0 [(41516, 1)] 0, attempt 19259 38 15 0 [(41517, 1)] 0, attempt 19260 38 16 0 [(41518, 1)] 0, attempt 19261 38 17 0 [(41519, 1)] 0, attempt 19262 39 0 0 [(41528, 1)] 0, attempt 19263 39 1 0 [(41529, 1)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19232
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 19264 39 2 0 [(41530, 1)] 0, attempt 19265 39 3 0 [(41531, 1)] 0, attempt 19266 39 4 0 [(41532, 1)] 0, attempt 19267 39 5 0 [(41533, 1)] 0, attempt 19268 39 6 0 [(41534, 1)] 0, attempt 19269 39 7 0 [(41535, 1)] 0, attempt 19270 40 0 1 [(41491, 308)] 0, attempt 19271 40 1 1 [(41492, 308)] 0, attempt 19272 40 2 1 [(41493, 308)] 0, attempt 19273 40 3 1 [(41494, 308)] 0, attempt 19274 40 4 1 [(41495, 308)] 0, attempt 19275 40 5 1 [(41496, 308)] 0, attempt 19276 40 6 1 [(41497, 308)] 0, attempt 19277 41 0 0 [(41528, 1)] 309, attempt 19278 41 1 0 [(41528, 1)] 310, attempt 19279 41 2 0 [(41528, 1)] 311, attempt 19280 41 3 0 [(41528, 1)] 312, attempt 19281 41 4 0 [(41528, 1)] 313, attempt 19282 41 5 0 [(41528, 1)] 314, attempt 19283 41 6 0 [(41528, 1)] 315, attempt 19284 42 0 0 [(41408, 1)] 88, attempt 19285 42 1 0 [(41409, 1)] 89, attempt 19286 43 0 0 [(42112, 1)] 306, attempt 19287 43 1 0 [(42113, 1)] 304, attempt 19288 43 2 0 [(42114, 1)] 305, attempt 19289 44 0 0 [(42115, 1), (41410, 3)] 0, attempt 19290 44 1 0 [(42116, 1), (41412, 3)] 0, attempt 19291 44 2 0 [(42117, 1), (41429, 3)] 0, attempt 19292 44 3 0 [(42118, 1), (41430, 3)] 0, attempt 19293 45 0 0 [(42119, 1)] 316, attempt 19294 45 1 0 [(42120, 1)] 317, attempt 19295 45 2 0 [(42121, 1)] 318]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19264
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 19296 45 3 0 [(42122, 1)] 319, attempt 19297 46 0 0 [(42165, 1)] 0, attempt 19298 46 1 0 [(42166, 1)] 0, attempt 19299 46 2 0 [(42167, 1)] 0, attempt 19300 46 3 0 [(42168, 1)] 0, attempt 19301 46 4 0 [(42169, 1)] 0, attempt 19302 46 5 0 [(42170, 1)] 0, attempt 19303 46 6 0 [(42171, 1)] 0, attempt 19304 46 7 0 [(42172, 1)] 0, attempt 19305 46 8 0 [(42173, 1)] 0, attempt 19306 46 9 0 [(42174, 1)] 0, attempt 19307 46 10 0 [(42175, 1)] 0, attempt 19308 47 0 0 [(41536, 1), (41414, 320)] 307, attempt 19309 47 1 0 [(41600, 1), (41415, 320)] 0, attempt 19310 47 2 0 [(41664, 1), (41416, 320)] 0, attempt 19311 47 3 0 [(41728, 1), (41417, 320)] 0, attempt 19312 47 4 0 [(41792, 1), (41418, 320)] 0, attempt 19313 47 5 0 [(41856, 1), (41419, 320)] 0, attempt 19314 47 6 0 [(41920, 1), (41420, 320)] 0, attempt 19315 47 7 0 [(41537, 1), (41432, 320)] 307, attempt 19316 47 8 0 [(41601, 1), (41433, 320)] 0, attempt 19317 47 9 0 [(41665, 1), (41434, 320)] 0, attempt 19318 47 10 0 [(41729, 1), (41435, 320)] 0, attempt 19319 47 11 0 [(41793, 1), (41436, 320)] 0, attempt 19320 47 12 0 [(41857, 1), (41437, 320)] 0, attempt 19321 47 13 0 [(41921, 1), (41438, 320)] 0, attempt 19322 47 14 0 [(41538, 1), (41439, 320)] 307, attempt 19323 47 15 0 [(41602, 1), (41440, 320)] 0, attempt 19324 47 16 0 [(41666, 1), (41441, 320)] 0, attempt 19325 47 17 0 [(41730, 1), (41442, 320)] 0, attempt 19326 47 18 0 [(41794, 1), (41443, 320)] 0, attempt 19327 47 19 0 [(41858, 1), (41444, 320)] 0]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19296
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 19328 47 20 0 [(41922, 1), (41445, 320)] 0, attempt 19329 47 21 0 [(41539, 1), (41446, 320)] 307, attempt 19330 47 22 0 [(41603, 1), (41447, 320)] 0, attempt 19331 47 23 0 [(41667, 1), (41448, 320)] 0, attempt 19332 47 24 0 [(41731, 1), (41449, 320)] 0, attempt 19333 47 25 0 [(41795, 1), (41450, 320)] 0, attempt 19334 47 26 0 [(41859, 1), (41451, 320)] 0, attempt 19335 47 27 0 [(41923, 1), (41452, 320)] 0, attempt 19336 47 28 0 [(41540, 1), (41456, 320)] 307, attempt 19337 47 29 0 [(41604, 1), (41457, 320)] 0, attempt 19338 47 30 0 [(41668, 1), (41458, 320)] 0, attempt 19339 47 31 0 [(41732, 1), (41459, 320)] 0, attempt 19340 47 32 0 [(41796, 1), (41460, 320)] 0, attempt 19341 47 33 0 [(41860, 1), (41461, 320)] 0, attempt 19342 47 34 0 [(41924, 1), (41462, 320)] 0, attempt 19343 47 35 0 [(41541, 1), (41414, 320), (41432, 322)] 307, attempt 19344 47 36 0 [(41605, 1), (41415, 320), (41433, 322)] 0, attempt 19345 47 37 0 [(41669, 1), (41416, 320), (41434, 322)] 0, attempt 19346 47 38 0 [(41733, 1), (41417, 320), (41435, 322)] 0, attempt 19347 47 39 0 [(41797, 1), (41418, 320), (41436, 322)] 0, attempt 19348 47 40 0 [(41861, 1), (41419, 320), (41437, 322)] 0, attempt 19349 47 41 0 [(41925, 1), (41420, 320), (41438, 322)] 0, attempt 19350 47 42 0 [(41542, 1), (41414, 320), (41439, 322)] 307, attempt 19351 47 43 0 [(41606, 1), (41415, 320), (41440, 322)] 0, attempt 19352 47 44 0 [(41670, 1), (41416, 320), (41441, 322)] 0, attempt 19353 47 45 0 [(41734, 1), (41417, 320), (41442, 322)] 0, attempt 19354 47 46 0 [(41798, 1), (41418, 320), (41443, 322)] 0, attempt 19355 47 47 0 [(41862, 1), (41419, 320), (41444, 322)] 0, attempt 19356 47 48 0 [(41926, 1), (41420, 320), (41445, 322)] 0, attempt 19357 47 49 0 [(41543, 1), (41414, 320), (41446, 322)] 307, attempt 19358 47 50 0 [(41607, 1), (41415, 320), (41447, 322)] 0, attempt 19359 47 51 0 [(41671, 1), (41416, 320), (41448, 322)] 0]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19328
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 19360 47 52 0 [(41735, 1), (41417, 320), (41449, 322)] 0, attempt 19361 47 53 0 [(41799, 1), (41418, 320), (41450, 322)] 0, attempt 19362 47 54 0 [(41863, 1), (41419, 320), (41451, 322)] 0, attempt 19363 47 55 0 [(41927, 1), (41420, 320), (41452, 322)] 0, attempt 19364 47 56 0 [(41544, 1), (41414, 320), (41456, 322)] 307, attempt 19365 47 57 0 [(41608, 1), (41415, 320), (41457, 322)] 0, attempt 19366 47 58 0 [(41672, 1), (41416, 320), (41458, 322)] 0, attempt 19367 47 59 0 [(41736, 1), (41417, 320), (41459, 322)] 0, attempt 19368 47 60 0 [(41800, 1), (41418, 320), (41460, 322)] 0, attempt 19369 47 61 0 [(41864, 1), (41419, 320), (41461, 322)] 0, attempt 19370 47 62 0 [(41928, 1), (41420, 320), (41462, 322)] 0, attempt 19371 47 63 0 [(41545, 1), (41432, 320), (41439, 322)] 307, attempt 19372 47 64 0 [(41609, 1), (41433, 320), (41440, 322)] 0, attempt 19373 47 65 0 [(41673, 1), (41434, 320), (41441, 322)] 0, attempt 19374 47 66 0 [(41737, 1), (41435, 320), (41442, 322)] 0, attempt 19375 47 67 0 [(41801, 1), (41436, 320), (41443, 322)] 0, attempt 19376 47 68 0 [(41865, 1), (41437, 320), (41444, 322)] 0, attempt 19377 47 69 0 [(41929, 1), (41438, 320), (41445, 322)] 0, attempt 19378 47 70 0 [(41546, 1), (41432, 320), (41446, 322)] 307, attempt 19379 47 71 0 [(41610, 1), (41433, 320), (41447, 322)] 0, attempt 19380 47 72 0 [(41674, 1), (41434, 320), (41448, 322)] 0, attempt 19381 47 73 0 [(41738, 1), (41435, 320), (41449, 322)] 0, attempt 19382 47 74 0 [(41802, 1), (41436, 320), (41450, 322)] 0, attempt 19383 47 75 0 [(41866, 1), (41437, 320), (41451, 322)] 0, attempt 19384 47 76 0 [(41930, 1), (41438, 320), (41452, 322)] 0, attempt 19385 47 77 0 [(41547, 1), (41432, 320), (41456, 322)] 307, attempt 19386 47 78 0 [(41611, 1), (41433, 320), (41457, 322)] 0, attempt 19387 47 79 0 [(41675, 1), (41434, 320), (41458, 322)] 0, attempt 19388 47 80 0 [(41739, 1), (41435, 320), (41459, 322)] 0, attempt 19389 47 81 0 [(41803, 1), (41436, 320), (41460, 322)] 0, attempt 19390 47 82 0 [(41867, 1), (41437, 320), (41461, 322)] 0, attempt 19391 47 83 0 [(41931, 1), (41438, 320), (41462, 322)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19360
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 19392 47 84 0 [(41548, 1), (41439, 320), (41446, 322)] 307, attempt 19393 47 85 0 [(41612, 1), (41440, 320), (41447, 322)] 0, attempt 19394 47 86 0 [(41676, 1), (41441, 320), (41448, 322)] 0, attempt 19395 47 87 0 [(41740, 1), (41442, 320), (41449, 322)] 0, attempt 19396 47 88 0 [(41804, 1), (41443, 320), (41450, 322)] 0, attempt 19397 47 89 0 [(41868, 1), (41444, 320), (41451, 322)] 0, attempt 19398 47 90 0 [(41932, 1), (41445, 320), (41452, 322)] 0, attempt 19399 47 91 0 [(41549, 1), (41439, 320), (41456, 322)] 307, attempt 19400 47 92 0 [(41613, 1), (41440, 320), (41457, 322)] 0, attempt 19401 47 93 0 [(41677, 1), (41441, 320), (41458, 322)] 0, attempt 19402 47 94 0 [(41741, 1), (41442, 320), (41459, 322)] 0, attempt 19403 47 95 0 [(41805, 1), (41443, 320), (41460, 322)] 0, attempt 19404 47 96 0 [(41869, 1), (41444, 320), (41461, 322)] 0, attempt 19405 47 97 0 [(41933, 1), (41445, 320), (41462, 322)] 0, attempt 19406 47 98 0 [(41550, 1), (41446, 320), (41456, 322)] 307, attempt 19407 47 99 0 [(41614, 1), (41447, 320), (41457, 322)] 0, attempt 19408 47 100 0 [(41678, 1), (41448, 320), (41458, 322)] 0, attempt 19409 47 101 0 [(41742, 1), (41449, 320), (41459, 322)] 0, attempt 19410 47 102 0 [(41806, 1), (41450, 320), (41460, 322)] 0, attempt 19411 47 103 0 [(41870, 1), (41451, 320), (41461, 322)] 0, attempt 19412 47 104 0 [(41934, 1), (41452, 320), (41462, 322)] 0, attempt 19413 47 105 0 [(41551, 1), (41491, 323)] 308, attempt 19414 47 106 0 [(41615, 1), (41492, 323)] 0, attempt 19415 47 107 0 [(41679, 1), (41493, 323)] 0, attempt 19416 47 108 0 [(41743, 1), (41494, 323)] 0, attempt 19417 47 109 0 [(41807, 1), (41495, 323)] 0, attempt 19418 47 110 0 [(41871, 1), (41496, 323)] 0, attempt 19419 47 111 0 [(41935, 1), (41497, 323)] 0, attempt 19420 47 112 0 [(41552, 1)] 325, attempt 19421 47 113 0 [(41616, 1)] 0, attempt 19422 47 114 0 [(41680, 1)] 0, attempt 19423 47 115 0 [(41744, 1)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19392
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 19424 47 116 0 [(41808, 1)] 0, attempt 19425 47 117 0 [(41872, 1)] 0, attempt 19426 47 118 0 [(41936, 1)] 0, attempt 19427 47 119 0 [(41553, 1), (41425, 323)] 308, attempt 19428 47 120 0 [(41617, 1), (41425, 0)] 0, attempt 19429 47 121 0 [(41681, 1), (41425, 0)] 0, attempt 19430 47 122 0 [(41745, 1), (41425, 0)] 0, attempt 19431 47 123 0 [(41809, 1), (41425, 0)] 0, attempt 19432 47 124 0 [(41873, 1), (41425, 0)] 0, attempt 19433 47 125 0 [(41937, 1), (41425, 0)] 0, attempt 19434 47 126 0 [(41554, 1), (41426, 323)] 308, attempt 19435 47 127 0 [(41618, 1), (41426, 0)] 0, attempt 19436 47 128 0 [(41682, 1), (41426, 0)] 0, attempt 19437 47 129 0 [(41746, 1), (41426, 0)] 0, attempt 19438 47 130 0 [(41810, 1), (41426, 0)] 0, attempt 19439 47 131 0 [(41874, 1), (41426, 0)] 0, attempt 19440 47 132 0 [(41938, 1), (41426, 0)] 0, attempt 19441 47 133 0 [(41555, 1), (41408, 320)] 307, attempt 19442 47 134 0 [(41619, 1), (41408, 0)] 0, attempt 19443 47 135 0 [(41683, 1), (41408, 0)] 0, attempt 19444 47 136 0 [(41747, 1), (41408, 0)] 0, attempt 19445 47 137 0 [(41811, 1), (41408, 0)] 0, attempt 19446 47 138 0 [(41875, 1), (41408, 0)] 0, attempt 19447 47 139 0 [(41939, 1), (41408, 0)] 0, attempt 19448 47 140 0 [(41556, 1)] 327, attempt 19449 47 141 0 [(41620, 1)] 328, attempt 19450 47 142 0 [(41684, 1)] 329, attempt 19451 47 143 0 [(41748, 1)] 330, attempt 19452 47 144 0 [(41812, 1)] 331, attempt 19453 47 145 0 [(41876, 1)] 332, attempt 19454 47 146 0 [(41940, 1)] 333, attempt 19455 47 147 0 [(41557, 1), (41520, 339), (41524, 340)] 338]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 12, 5, 60, 36, 1024, 448, 448, 448, 14, 28, 14, 60, 36, 14, 240, 7, 64, 21, 171, 47, 7, 47, 7, 30, 7, 48, 94, 18, 18, 8, 7, 7, 2, 3, 4, 4, 11, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19424
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19456
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19424
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 19424 19456 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 19424) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19392
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 19392 19424 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 19392) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19360
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 19360 19392 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 19360) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19328
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 19328 19360 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 19328) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19296
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 19296 19328 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 19296) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19264
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 19264 19296 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 19264) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19232
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 19232 19264 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 19232) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19200
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 19200 19232 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 19200) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19168
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 19168 19200 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 19168) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19136
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 19136 19168 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 19136) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19104
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 19104 19136 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 19104) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19072
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 19072 19104 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 19072) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19040
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 19040 19072 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 19040) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 19008
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 19008 19040 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 19008) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18976
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 18976 19008 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 18976) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18944
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 18944 18976 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 18944) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr37
