import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr34

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr35
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 17920 17 82 1 [(16530, 124)] 0, attempt 17921 17 83 1 [(16531, 124)] 0, attempt 17922 17 84 1 [(16532, 124)] 0, attempt 17923 17 85 1 [(16533, 124)] 0, attempt 17924 17 86 1 [(16534, 124)] 0, attempt 17925 17 87 1 [(16535, 124)] 0, attempt 17926 17 88 1 [(16536, 124)] 0, attempt 17927 17 89 1 [(16537, 124)] 0, attempt 17928 17 90 1 [(16538, 124)] 0, attempt 17929 17 91 1 [(16539, 124)] 0, attempt 17930 17 92 1 [(16540, 124)] 0, attempt 17931 17 93 1 [(16541, 124)] 0, attempt 17932 17 94 1 [(16542, 124)] 0, attempt 17933 17 95 1 [(16543, 124)] 0, attempt 17934 17 96 1 [(16544, 124)] 0, attempt 17935 17 97 1 [(16545, 124)] 0, attempt 17936 17 98 1 [(16546, 124)] 0, attempt 17937 17 99 1 [(16547, 124)] 0, attempt 17938 17 100 1 [(16548, 124)] 0, attempt 17939 17 101 1 [(16549, 124)] 0, attempt 17940 17 102 1 [(16550, 124)] 0, attempt 17941 17 103 1 [(16551, 124)] 0, attempt 17942 17 104 1 [(16552, 124)] 0, attempt 17943 17 105 1 [(16553, 124)] 0, attempt 17944 17 106 1 [(16554, 124)] 0, attempt 17945 17 107 1 [(16555, 124)] 0, attempt 17946 17 108 1 [(16556, 124)] 0, attempt 17947 17 109 1 [(16557, 124)] 0, attempt 17948 17 110 1 [(16558, 124)] 0, attempt 17949 17 111 1 [(16559, 124)] 0, attempt 17950 17 112 1 [(16560, 124)] 0, attempt 17951 17 113 1 [(16561, 124)] 0]
def counters001 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17920
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 17952 17 114 1 [(16562, 124)] 0, attempt 17953 17 115 1 [(16563, 124)] 0, attempt 17954 17 116 1 [(16564, 124)] 0, attempt 17955 17 117 1 [(16565, 124)] 0, attempt 17956 17 118 1 [(16566, 124)] 0, attempt 17957 17 119 1 [(16567, 124)] 0, attempt 17958 17 120 1 [(16568, 124)] 0, attempt 17959 17 121 1 [(16569, 124)] 0, attempt 17960 17 122 1 [(16570, 124)] 0, attempt 17961 17 123 1 [(16571, 124)] 0, attempt 17962 17 124 1 [(16572, 124)] 0, attempt 17963 17 125 1 [(16573, 124)] 0, attempt 17964 17 126 1 [(16574, 124)] 0, attempt 17965 17 127 1 [(16575, 124)] 0, attempt 17966 17 128 1 [(16768, 124)] 0, attempt 17967 17 129 1 [(16769, 124)] 0, attempt 17968 17 130 1 [(16770, 124)] 0, attempt 17969 17 131 1 [(16771, 124)] 0, attempt 17970 17 132 1 [(16772, 124)] 0, attempt 17971 17 133 1 [(16773, 124)] 0, attempt 17972 17 134 1 [(16774, 124)] 0, attempt 17973 17 135 1 [(16775, 124)] 0, attempt 17974 17 136 1 [(16776, 124)] 0, attempt 17975 17 137 1 [(16777, 124)] 0, attempt 17976 17 138 1 [(16778, 124)] 0, attempt 17977 17 139 1 [(16779, 124)] 0, attempt 17978 17 140 1 [(16780, 124)] 0, attempt 17979 17 141 1 [(16781, 124)] 0, attempt 17980 17 142 1 [(16782, 124)] 0, attempt 17981 17 143 1 [(16783, 124)] 0, attempt 17982 17 144 1 [(16784, 124)] 0, attempt 17983 17 145 1 [(16785, 124)] 0]
def counters002 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17952
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 17984 17 146 1 [(16786, 124)] 0, attempt 17985 17 147 1 [(16787, 124)] 0, attempt 17986 17 148 1 [(16788, 124)] 0, attempt 17987 17 149 1 [(16789, 124)] 0, attempt 17988 17 150 1 [(16790, 124)] 0, attempt 17989 17 151 1 [(16791, 124)] 0, attempt 17990 17 152 1 [(16792, 124)] 0, attempt 17991 17 153 1 [(16793, 124)] 0, attempt 17992 17 154 1 [(16794, 124)] 0, attempt 17993 17 155 1 [(16795, 124)] 0, attempt 17994 17 156 1 [(16796, 124)] 0, attempt 17995 17 157 1 [(16797, 124)] 0, attempt 17996 17 158 1 [(16798, 124)] 0, attempt 17997 17 159 1 [(16799, 124)] 0, attempt 17998 17 160 1 [(16800, 124)] 0, attempt 17999 17 161 1 [(16801, 124)] 0, attempt 18000 17 162 1 [(16802, 124)] 0, attempt 18001 17 163 1 [(16803, 124)] 0, attempt 18002 17 164 1 [(16804, 124)] 0, attempt 18003 17 165 1 [(16805, 124)] 0, attempt 18004 17 166 1 [(16806, 124)] 0, attempt 18005 17 167 1 [(16807, 124)] 0, attempt 18006 17 168 1 [(16808, 124)] 0, attempt 18007 17 169 1 [(16809, 124)] 0, attempt 18008 17 170 1 [(16810, 124)] 0, attempt 18009 17 171 1 [(16811, 124)] 0, attempt 18010 17 172 1 [(16812, 124)] 0, attempt 18011 17 173 1 [(16813, 124)] 0, attempt 18012 17 174 1 [(16814, 124)] 0, attempt 18013 17 175 1 [(16815, 124)] 0, attempt 18014 17 176 1 [(16816, 124)] 0, attempt 18015 17 177 1 [(16817, 124)] 0]
def counters003 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17984
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 18016 17 178 1 [(16818, 124)] 0, attempt 18017 17 179 1 [(16819, 124)] 0, attempt 18018 17 180 1 [(16820, 124)] 0, attempt 18019 17 181 1 [(16821, 124)] 0, attempt 18020 17 182 1 [(16822, 124)] 0, attempt 18021 17 183 1 [(16823, 124)] 0, attempt 18022 17 184 1 [(16824, 124)] 0, attempt 18023 17 185 1 [(16825, 124)] 0, attempt 18024 17 186 1 [(16826, 124)] 0, attempt 18025 17 187 1 [(16827, 124)] 0, attempt 18026 17 188 1 [(16828, 124)] 0, attempt 18027 17 189 1 [(16829, 124)] 0, attempt 18028 17 190 1 [(16830, 124)] 0, attempt 18029 17 191 1 [(16831, 124)] 0, attempt 18030 17 192 1 [(17024, 124)] 0, attempt 18031 17 193 1 [(17025, 124)] 0, attempt 18032 17 194 1 [(17026, 124)] 0, attempt 18033 17 195 1 [(17027, 124)] 0, attempt 18034 17 196 1 [(17028, 124)] 0, attempt 18035 17 197 1 [(17029, 124)] 0, attempt 18036 17 198 1 [(17030, 124)] 0, attempt 18037 17 199 1 [(17031, 124)] 0, attempt 18038 17 200 1 [(17032, 124)] 0, attempt 18039 17 201 1 [(17033, 124)] 0, attempt 18040 17 202 1 [(17034, 124)] 0, attempt 18041 17 203 1 [(17035, 124)] 0, attempt 18042 17 204 1 [(17036, 124)] 0, attempt 18043 17 205 1 [(17037, 124)] 0, attempt 18044 17 206 1 [(17038, 124)] 0, attempt 18045 17 207 1 [(17039, 124)] 0, attempt 18046 17 208 1 [(17040, 124)] 0, attempt 18047 17 209 1 [(17041, 124)] 0]
def counters004 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18016
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 18048 17 210 1 [(17042, 124)] 0, attempt 18049 17 211 1 [(17043, 124)] 0, attempt 18050 17 212 1 [(17044, 124)] 0, attempt 18051 17 213 1 [(17045, 124)] 0, attempt 18052 17 214 1 [(17046, 124)] 0, attempt 18053 17 215 1 [(17047, 124)] 0, attempt 18054 17 216 1 [(17048, 124)] 0, attempt 18055 17 217 1 [(17049, 124)] 0, attempt 18056 17 218 1 [(17050, 124)] 0, attempt 18057 17 219 1 [(17051, 124)] 0, attempt 18058 17 220 1 [(17052, 124)] 0, attempt 18059 17 221 1 [(17053, 124)] 0, attempt 18060 17 222 1 [(17054, 124)] 0, attempt 18061 17 223 1 [(17055, 124)] 0, attempt 18062 17 224 1 [(17056, 125)] 0, attempt 18063 17 225 1 [(17057, 125)] 0, attempt 18064 17 226 1 [(17058, 125)] 0, attempt 18065 17 227 1 [(17059, 125)] 0, attempt 18066 17 228 1 [(17060, 125)] 0, attempt 18067 17 229 1 [(17061, 125)] 0, attempt 18068 17 230 1 [(17062, 125)] 0, attempt 18069 17 231 1 [(17063, 125)] 0, attempt 18070 17 232 1 [(17064, 125)] 0, attempt 18071 17 233 1 [(17065, 125)] 0, attempt 18072 17 234 1 [(17066, 125)] 0, attempt 18073 17 235 1 [(17067, 125)] 0, attempt 18074 17 236 1 [(17068, 125)] 0, attempt 18075 17 237 1 [(17069, 125)] 0, attempt 18076 17 238 1 [(17070, 125)] 0, attempt 18077 17 239 1 [(17071, 125)] 0, attempt 18078 17 240 1 [(17072, 125)] 0, attempt 18079 17 241 1 [(17073, 125)] 0]
def counters005 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18048
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 18080 17 242 1 [(17074, 125)] 0, attempt 18081 17 243 1 [(17075, 125)] 0, attempt 18082 17 244 1 [(17076, 125)] 0, attempt 18083 17 245 1 [(17077, 125)] 0, attempt 18084 17 246 1 [(17078, 125)] 0, attempt 18085 17 247 1 [(17079, 125)] 0, attempt 18086 17 248 1 [(17080, 125)] 0, attempt 18087 17 249 1 [(17081, 125)] 0, attempt 18088 17 250 1 [(17082, 125)] 0, attempt 18089 17 251 1 [(17083, 125)] 0, attempt 18090 17 252 1 [(17084, 125)] 0, attempt 18091 17 253 1 [(17085, 125)] 0, attempt 18092 17 254 1 [(17086, 125)] 0, attempt 18093 17 255 1 [(17087, 125)] 0, attempt 18094 17 256 1 [(17280, 125)] 0, attempt 18095 17 257 1 [(17281, 125)] 0, attempt 18096 17 258 1 [(17282, 125)] 0, attempt 18097 17 259 1 [(17283, 125)] 0, attempt 18098 17 260 1 [(17284, 125)] 0, attempt 18099 17 261 1 [(17285, 125)] 0, attempt 18100 17 262 1 [(17286, 125)] 0, attempt 18101 17 263 1 [(17287, 125)] 0, attempt 18102 17 264 1 [(17288, 125)] 0, attempt 18103 17 265 1 [(17289, 125)] 0, attempt 18104 17 266 1 [(17290, 125)] 0, attempt 18105 17 267 1 [(17291, 125)] 0, attempt 18106 17 268 1 [(17292, 125)] 0, attempt 18107 17 269 1 [(17293, 125)] 0, attempt 18108 17 270 1 [(17294, 125)] 0, attempt 18109 17 271 1 [(17295, 125)] 0, attempt 18110 17 272 1 [(17296, 125)] 0, attempt 18111 17 273 1 [(17297, 125)] 0]
def counters006 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 274, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18080
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 18112 17 274 1 [(17298, 125)] 0, attempt 18113 17 275 1 [(17299, 125)] 0, attempt 18114 17 276 1 [(17300, 125)] 0, attempt 18115 17 277 1 [(17301, 125)] 0, attempt 18116 17 278 1 [(17302, 125)] 0, attempt 18117 17 279 1 [(17303, 125)] 0, attempt 18118 17 280 1 [(17304, 125)] 0, attempt 18119 17 281 1 [(17305, 125)] 0, attempt 18120 17 282 1 [(17306, 125)] 0, attempt 18121 17 283 1 [(17307, 125)] 0, attempt 18122 17 284 1 [(17308, 125)] 0, attempt 18123 17 285 1 [(17309, 125)] 0, attempt 18124 17 286 1 [(17310, 125)] 0, attempt 18125 17 287 1 [(17311, 125)] 0, attempt 18126 17 288 1 [(17312, 125)] 0, attempt 18127 17 289 1 [(17313, 125)] 0, attempt 18128 17 290 1 [(17314, 125)] 0, attempt 18129 17 291 1 [(17315, 125)] 0, attempt 18130 17 292 1 [(17316, 125)] 0, attempt 18131 17 293 1 [(17317, 125)] 0, attempt 18132 17 294 1 [(17318, 125)] 0, attempt 18133 17 295 1 [(17319, 125)] 0, attempt 18134 17 296 1 [(17320, 125)] 0, attempt 18135 17 297 1 [(17321, 125)] 0, attempt 18136 17 298 1 [(17322, 125)] 0, attempt 18137 17 299 1 [(17323, 125)] 0, attempt 18138 17 300 1 [(17324, 125)] 0, attempt 18139 17 301 1 [(17325, 125)] 0, attempt 18140 17 302 1 [(17326, 125)] 0, attempt 18141 17 303 1 [(17327, 125)] 0, attempt 18142 17 304 1 [(17328, 125)] 0, attempt 18143 17 305 1 [(17329, 125)] 0]
def counters007 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 306, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18112
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 18144 17 306 1 [(17330, 125)] 0, attempt 18145 17 307 1 [(17331, 125)] 0, attempt 18146 17 308 1 [(17332, 125)] 0, attempt 18147 17 309 1 [(17333, 125)] 0, attempt 18148 17 310 1 [(17334, 125)] 0, attempt 18149 17 311 1 [(17335, 125)] 0, attempt 18150 17 312 1 [(17336, 125)] 0, attempt 18151 17 313 1 [(17337, 125)] 0, attempt 18152 17 314 1 [(17338, 125)] 0, attempt 18153 17 315 1 [(17339, 125)] 0, attempt 18154 17 316 1 [(17340, 125)] 0, attempt 18155 17 317 1 [(17341, 125)] 0, attempt 18156 17 318 1 [(17342, 125)] 0, attempt 18157 17 319 1 [(17343, 125)] 0, attempt 18158 17 320 1 [(17536, 125)] 0, attempt 18159 17 321 1 [(17537, 125)] 0, attempt 18160 17 322 1 [(17538, 125)] 0, attempt 18161 17 323 1 [(17539, 125)] 0, attempt 18162 17 324 1 [(17540, 125)] 0, attempt 18163 17 325 1 [(17541, 125)] 0, attempt 18164 17 326 1 [(17542, 125)] 0, attempt 18165 17 327 1 [(17543, 125)] 0, attempt 18166 17 328 1 [(17544, 125)] 0, attempt 18167 17 329 1 [(17545, 125)] 0, attempt 18168 17 330 1 [(17546, 125)] 0, attempt 18169 17 331 1 [(17547, 125)] 0, attempt 18170 17 332 1 [(17548, 125)] 0, attempt 18171 17 333 1 [(17549, 125)] 0, attempt 18172 17 334 1 [(17550, 125)] 0, attempt 18173 17 335 1 [(17551, 125)] 0, attempt 18174 17 336 1 [(17552, 125)] 0, attempt 18175 17 337 1 [(17553, 125)] 0]
def counters008 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 338, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18144
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 18176 17 338 1 [(17554, 125)] 0, attempt 18177 17 339 1 [(17555, 125)] 0, attempt 18178 17 340 1 [(17556, 125)] 0, attempt 18179 17 341 1 [(17557, 125)] 0, attempt 18180 17 342 1 [(17558, 125)] 0, attempt 18181 17 343 1 [(17559, 125)] 0, attempt 18182 17 344 1 [(17560, 125)] 0, attempt 18183 17 345 1 [(17561, 125)] 0, attempt 18184 17 346 1 [(17562, 125)] 0, attempt 18185 17 347 1 [(17563, 125)] 0, attempt 18186 17 348 1 [(17564, 125)] 0, attempt 18187 17 349 1 [(17565, 125)] 0, attempt 18188 17 350 1 [(17566, 125)] 0, attempt 18189 17 351 1 [(17567, 125)] 0, attempt 18190 17 352 1 [(17568, 125)] 0, attempt 18191 17 353 1 [(17569, 125)] 0, attempt 18192 17 354 1 [(17570, 125)] 0, attempt 18193 17 355 1 [(17571, 125)] 0, attempt 18194 17 356 1 [(17572, 125)] 0, attempt 18195 17 357 1 [(17573, 125)] 0, attempt 18196 17 358 1 [(17574, 125)] 0, attempt 18197 17 359 1 [(17575, 125)] 0, attempt 18198 17 360 1 [(17576, 125)] 0, attempt 18199 17 361 1 [(17577, 125)] 0, attempt 18200 17 362 1 [(17578, 125)] 0, attempt 18201 17 363 1 [(17579, 125)] 0, attempt 18202 17 364 1 [(17580, 125)] 0, attempt 18203 17 365 1 [(17581, 125)] 0, attempt 18204 17 366 1 [(17582, 125)] 0, attempt 18205 17 367 1 [(17583, 125)] 0, attempt 18206 17 368 1 [(17584, 125)] 0, attempt 18207 17 369 1 [(17585, 125)] 0]
def counters009 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 370, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18176
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 18208 17 370 1 [(17586, 125)] 0, attempt 18209 17 371 1 [(17587, 125)] 0, attempt 18210 17 372 1 [(17588, 125)] 0, attempt 18211 17 373 1 [(17589, 125)] 0, attempt 18212 17 374 1 [(17590, 125)] 0, attempt 18213 17 375 1 [(17591, 125)] 0, attempt 18214 17 376 1 [(17592, 125)] 0, attempt 18215 17 377 1 [(17593, 125)] 0, attempt 18216 17 378 1 [(17594, 125)] 0, attempt 18217 17 379 1 [(17595, 125)] 0, attempt 18218 17 380 1 [(17596, 125)] 0, attempt 18219 17 381 1 [(17597, 125)] 0, attempt 18220 17 382 1 [(17598, 125)] 0, attempt 18221 17 383 1 [(17599, 125)] 0, attempt 18222 17 384 1 [(17792, 125)] 0, attempt 18223 17 385 1 [(17793, 125)] 0, attempt 18224 17 386 1 [(17794, 125)] 0, attempt 18225 17 387 1 [(17795, 125)] 0, attempt 18226 17 388 1 [(17796, 125)] 0, attempt 18227 17 389 1 [(17797, 125)] 0, attempt 18228 17 390 1 [(17798, 125)] 0, attempt 18229 17 391 1 [(17799, 125)] 0, attempt 18230 17 392 1 [(17800, 125)] 0, attempt 18231 17 393 1 [(17801, 125)] 0, attempt 18232 17 394 1 [(17802, 125)] 0, attempt 18233 17 395 1 [(17803, 125)] 0, attempt 18234 17 396 1 [(17804, 125)] 0, attempt 18235 17 397 1 [(17805, 125)] 0, attempt 18236 17 398 1 [(17806, 125)] 0, attempt 18237 17 399 1 [(17807, 125)] 0, attempt 18238 17 400 1 [(17808, 125)] 0, attempt 18239 17 401 1 [(17809, 125)] 0]
def counters010 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 402, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18208
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 18240 17 402 1 [(17810, 125)] 0, attempt 18241 17 403 1 [(17811, 125)] 0, attempt 18242 17 404 1 [(17812, 125)] 0, attempt 18243 17 405 1 [(17813, 125)] 0, attempt 18244 17 406 1 [(17814, 125)] 0, attempt 18245 17 407 1 [(17815, 125)] 0, attempt 18246 17 408 1 [(17816, 125)] 0, attempt 18247 17 409 1 [(17817, 125)] 0, attempt 18248 17 410 1 [(17818, 125)] 0, attempt 18249 17 411 1 [(17819, 125)] 0, attempt 18250 17 412 1 [(17820, 125)] 0, attempt 18251 17 413 1 [(17821, 125)] 0, attempt 18252 17 414 1 [(17822, 125)] 0, attempt 18253 17 415 1 [(17823, 125)] 0, attempt 18254 17 416 1 [(17824, 125)] 0, attempt 18255 17 417 1 [(17825, 125)] 0, attempt 18256 17 418 1 [(17826, 125)] 0, attempt 18257 17 419 1 [(17827, 125)] 0, attempt 18258 17 420 1 [(17828, 125)] 0, attempt 18259 17 421 1 [(17829, 125)] 0, attempt 18260 17 422 1 [(17830, 125)] 0, attempt 18261 17 423 1 [(17831, 125)] 0, attempt 18262 17 424 1 [(17832, 125)] 0, attempt 18263 17 425 1 [(17833, 125)] 0, attempt 18264 17 426 1 [(17834, 125)] 0, attempt 18265 17 427 1 [(17835, 125)] 0, attempt 18266 17 428 1 [(17836, 125)] 0, attempt 18267 17 429 1 [(17837, 125)] 0, attempt 18268 17 430 1 [(17838, 125)] 0, attempt 18269 17 431 1 [(17839, 125)] 0, attempt 18270 17 432 1 [(17840, 125)] 0, attempt 18271 17 433 1 [(17841, 125)] 0]
def counters011 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 434, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18240
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 18272 17 434 1 [(17842, 125)] 0, attempt 18273 17 435 1 [(17843, 125)] 0, attempt 18274 17 436 1 [(17844, 125)] 0, attempt 18275 17 437 1 [(17845, 125)] 0, attempt 18276 17 438 1 [(17846, 125)] 0, attempt 18277 17 439 1 [(17847, 125)] 0, attempt 18278 17 440 1 [(17848, 125)] 0, attempt 18279 17 441 1 [(17849, 125)] 0, attempt 18280 17 442 1 [(17850, 125)] 0, attempt 18281 17 443 1 [(17851, 125)] 0, attempt 18282 17 444 1 [(17852, 125)] 0, attempt 18283 17 445 1 [(17853, 125)] 0, attempt 18284 17 446 1 [(17854, 125)] 0, attempt 18285 17 447 1 [(17855, 125)] 0, attempt 18286 18 0 1 [(28771, 4)] 199, attempt 18287 18 1 1 [(28835, 4)] 200, attempt 18288 18 2 1 [(28899, 4)] 201, attempt 18289 18 3 1 [(28963, 4)] 202, attempt 18290 18 4 1 [(29027, 4)] 203, attempt 18291 18 5 1 [(29091, 4)] 204, attempt 18292 18 6 1 [(29155, 4)] 205, attempt 18293 18 7 1 [(40391, 5)] 274, attempt 18294 18 8 1 [(40455, 5)] 275, attempt 18295 18 9 1 [(40519, 5)] 276, attempt 18296 18 10 1 [(40583, 5)] 277, attempt 18297 18 11 1 [(40647, 5)] 278, attempt 18298 18 12 1 [(40711, 5)] 279, attempt 18299 18 13 1 [(40775, 5)] 280, attempt 18300 19 0 0 [(18148, 1), (6080, 158)] 0, attempt 18301 19 1 0 [(18212, 1), (128, 158), (192, 206), (256, 159), (320, 208), (384, 210), (448, 212), (512, 214), (576, 216), (640, 218), (704, 220), (768, 222), (832, 224), (896, 226), (960, 228), (1024, 230), (1088, 232), (1152, 234), (1216, 236), (1280, 238), (1344, 240), (1408, 242), (1472, 244), (1536, 246), (1600, 248), (1664, 250), (1728, 252), (1792, 254), (1856, 256), (1920, 258), (1984, 260), (2048, 262), (2112, 264)] 0, attempt 18302 19 2 0 [(18276, 1), (18497, 158)] 0, attempt 18303 19 3 0 [(18340, 1), (18561, 158)] 0]
def counters012 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18272
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 18304 19 4 0 [(18404, 1), (18114, 158), (28737, 265)] 0, attempt 18305 19 5 0 [(18468, 1), (18178, 158), (28801, 265)] 0, attempt 18306 19 6 0 [(18532, 1)] 0, attempt 18307 19 7 0 [(18596, 1)] 0, attempt 18308 19 8 0 [(18660, 1)] 2, attempt 18309 19 9 0 [(18724, 1)] 545, attempt 18310 19 10 0 [(18788, 1)] 543, attempt 18311 19 11 0 [(18852, 1)] 1, attempt 18312 19 12 0 [(18916, 1)] 0, attempt 18313 19 13 0 [(18980, 1)] 0, attempt 18314 19 14 0 [(19044, 1)] 0, attempt 18315 19 15 0 [(19108, 1)] 544, attempt 18316 19 16 0 [(29768, 1), (6144, 158)] 0, attempt 18317 19 17 0 [(29832, 1), (2304, 158), (2368, 206), (2432, 159), (2496, 208), (2560, 210), (2624, 212), (2688, 214), (2752, 216), (2816, 218), (2880, 220), (2944, 222), (3008, 224), (3072, 226), (3136, 228), (3200, 230), (3264, 232), (3328, 234), (3392, 236), (3456, 238), (3520, 240), (3584, 242), (3648, 244), (3712, 246), (3776, 248), (3840, 250), (3904, 252), (3968, 254), (4032, 256), (4096, 258), (4160, 260), (4224, 262), (4288, 264)] 0, attempt 18318 19 18 0 [(29896, 1), (18533, 158)] 0, attempt 18319 19 19 0 [(29960, 1), (18597, 158)] 0, attempt 18320 19 20 0 [(30024, 1), (18150, 158), (28773, 265)] 0, attempt 18321 19 21 0 [(30088, 1), (18214, 158), (28837, 265)] 0, attempt 18322 19 22 0 [(30152, 1)] 0, attempt 18323 19 23 0 [(30216, 1)] 0, attempt 18324 19 24 0 [(30280, 1)] 2, attempt 18325 19 25 0 [(30344, 1)] 545, attempt 18326 19 26 0 [(30408, 1)] 543, attempt 18327 19 27 0 [(30472, 1)] 1, attempt 18328 19 28 0 [(30536, 1)] 0, attempt 18329 19 29 0 [(30600, 1)] 0, attempt 18330 19 30 0 [(30664, 1)] 0, attempt 18331 19 31 0 [(30728, 1)] 544, attempt 18332 20 0 1 [(28772, 4)] 266, attempt 18333 20 1 1 [(28836, 4)] 267, attempt 18334 20 2 1 [(28900, 4)] 268, attempt 18335 20 3 1 [(28964, 4)] 269]
def counters013 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18304
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 18336 20 4 1 [(29028, 4)] 270, attempt 18337 20 5 1 [(29092, 4)] 271, attempt 18338 20 6 1 [(29156, 4)] 272, attempt 18339 20 7 1 [(40392, 5)] 281, attempt 18340 20 8 1 [(40456, 5)] 282, attempt 18341 20 9 1 [(40520, 5)] 283, attempt 18342 20 10 1 [(40584, 5)] 284, attempt 18343 20 11 1 [(40648, 5)] 285, attempt 18344 20 12 1 [(40712, 5)] 286, attempt 18345 20 13 1 [(40776, 5)] 287, attempt 18346 21 0 0 [(29769, 1), (4352, 158)] 0, attempt 18347 21 1 0 [(29833, 1), (4416, 158)] 0, attempt 18348 21 2 0 [(30281, 1)] 1, attempt 18349 21 3 0 [(30345, 1)] 414, attempt 18350 21 4 0 [(30409, 1)] 543, attempt 18351 21 5 0 [(30473, 1)] 0, attempt 18352 21 6 0 [(30537, 1)] 0, attempt 18353 21 7 0 [(30601, 1)] 0, attempt 18354 21 8 0 [(30665, 1)] 0, attempt 18355 21 9 0 [(30729, 1)] 544, attempt 18356 21 10 0 [(30154, 1), (40777, 158), (4864, 158)] 0, attempt 18357 21 11 0 [(30218, 1), (40841, 158), (4928, 158)] 0, attempt 18358 21 12 0 [(30282, 1), (40905, 158)] 0, attempt 18359 21 13 0 [(30346, 1), (40969, 158)] 0, attempt 18360 21 14 0 [(30410, 1), (41033, 158)] 0, attempt 18361 21 15 0 [(30474, 1), (41097, 158)] 0, attempt 18362 21 16 0 [(30538, 1), (41161, 158)] 0, attempt 18363 21 17 0 [(30602, 1), (41225, 158)] 0, attempt 18364 21 18 0 [(30666, 1), (41289, 158)] 0, attempt 18365 21 19 0 [(30730, 1), (41353, 158)] 0, attempt 18366 21 20 0 [(29771, 1), (40394, 158), (4992, 158)] 0, attempt 18367 21 21 0 [(29835, 1), (40458, 158), (5056, 158)] 0]
def counters014 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18336
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 18368 21 22 0 [(29899, 1), (40522, 158)] 0, attempt 18369 21 23 0 [(29963, 1), (40586, 158)] 0, attempt 18370 21 24 0 [(30027, 1), (40650, 158)] 0, attempt 18371 21 25 0 [(30091, 1), (40714, 158)] 0, attempt 18372 21 26 0 [(30155, 1), (40778, 158)] 0, attempt 18373 21 27 0 [(30219, 1), (40842, 158)] 0, attempt 18374 21 28 0 [(30283, 1), (40906, 158)] 0, attempt 18375 21 29 0 [(30347, 1), (40970, 158)] 0, attempt 18376 21 30 0 [(30411, 1), (41034, 158)] 0, attempt 18377 21 31 0 [(30475, 1), (41098, 158)] 1, attempt 18378 21 32 0 [(30539, 1), (41162, 158)] 0, attempt 18379 21 33 0 [(30603, 1), (41226, 158)] 0, attempt 18380 21 34 0 [(30667, 1), (41290, 158)] 0, attempt 18381 21 35 0 [(30731, 1), (41354, 158)] 0, attempt 18382 21 36 0 [(29772, 1), (5120, 158)] 0, attempt 18383 21 37 0 [(29836, 1), (5184, 158)] 0, attempt 18384 21 38 0 [(30284, 1)] 1, attempt 18385 21 39 0 [(30348, 1)] 414, attempt 18386 21 40 0 [(30412, 1)] 543, attempt 18387 21 41 0 [(30476, 1)] 0, attempt 18388 21 42 0 [(30540, 1)] 0, attempt 18389 21 43 0 [(30604, 1)] 0, attempt 18390 21 44 0 [(30668, 1)] 0, attempt 18391 21 45 0 [(30732, 1)] 544, attempt 18392 21 46 0 [(30157, 1), (40780, 158), (5632, 158)] 0, attempt 18393 21 47 0 [(30221, 1), (40844, 158), (5696, 158)] 0, attempt 18394 21 48 0 [(30285, 1), (40908, 158)] 0, attempt 18395 21 49 0 [(30349, 1), (40972, 158)] 0, attempt 18396 21 50 0 [(30413, 1), (41036, 158)] 0, attempt 18397 21 51 0 [(30477, 1), (41100, 158)] 0, attempt 18398 21 52 0 [(30541, 1), (41164, 158)] 0, attempt 18399 21 53 0 [(30605, 1), (41228, 158)] 0]
def counters015 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18368
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 18400 21 54 0 [(30669, 1), (41292, 158)] 0, attempt 18401 21 55 0 [(30733, 1), (41356, 158)] 0, attempt 18402 21 56 0 [(29774, 1), (40397, 158), (5760, 158)] 0, attempt 18403 21 57 0 [(29838, 1), (40461, 158), (5824, 158)] 0, attempt 18404 21 58 0 [(29902, 1), (40525, 158)] 0, attempt 18405 21 59 0 [(29966, 1), (40589, 158)] 0, attempt 18406 21 60 0 [(30030, 1), (40653, 158)] 0, attempt 18407 21 61 0 [(30094, 1), (40717, 158)] 0, attempt 18408 21 62 0 [(30158, 1), (40781, 158)] 0, attempt 18409 21 63 0 [(30222, 1), (40845, 158)] 0, attempt 18410 21 64 0 [(30286, 1), (40909, 158)] 0, attempt 18411 21 65 0 [(30350, 1), (40973, 158)] 0, attempt 18412 21 66 0 [(30414, 1), (41037, 158)] 0, attempt 18413 21 67 0 [(30478, 1), (41101, 158)] 1, attempt 18414 21 68 0 [(30542, 1), (41165, 158)] 0, attempt 18415 21 69 0 [(30606, 1), (41229, 158)] 0, attempt 18416 21 70 0 [(30670, 1), (41293, 158)] 0, attempt 18417 21 71 0 [(30734, 1), (41357, 158)] 0, attempt 18418 22 0 1 [(29769, 126)] 0, attempt 18419 22 1 1 [(29833, 126)] 0, attempt 18420 22 2 1 [(29897, 126)] 0, attempt 18421 22 3 1 [(29961, 126)] 0, attempt 18422 22 4 1 [(30025, 126)] 0, attempt 18423 22 5 1 [(30089, 126)] 0, attempt 18424 22 6 1 [(30153, 126)] 0, attempt 18425 22 7 1 [(30217, 126)] 0, attempt 18426 22 8 1 [(29770, 126), (40393, 288)] 0, attempt 18427 22 9 1 [(29834, 126), (40457, 288)] 0, attempt 18428 22 10 1 [(29898, 126), (40521, 288)] 0, attempt 18429 22 11 1 [(29962, 126), (40585, 288)] 0, attempt 18430 22 12 1 [(30026, 126), (40649, 288)] 0, attempt 18431 22 13 1 [(30090, 126), (40713, 288)] 0]
def counters016 : List Nat := [15561, 68, 24, 12, 7, 2, 46, 57, 8, 4, 16, 5, 72, 36, 1024, 448, 448, 448, 14, 32, 14, 72, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18400
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18432
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18400
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 18400 18432 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 18400) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18368
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 18368 18400 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 18368) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18336
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 18336 18368 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 18336) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18304
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 18304 18336 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 18304) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18272
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 18272 18304 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 18272) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18240
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 18240 18272 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 18240) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18208
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 18208 18240 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 18208) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18176
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 18176 18208 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 18176) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18144
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 18144 18176 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 18144) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18112
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 18112 18144 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 18112) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18080
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 18080 18112 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 18080) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18048
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 18048 18080 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 18048) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 18016
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 18016 18048 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 18016) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17984
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 17984 18016 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 17984) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17952
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 17952 17984 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 17952) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 17920
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 17920 17952 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 17920) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr35
