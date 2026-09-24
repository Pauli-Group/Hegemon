import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr00
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 0 0 0 0 [(1, 1), (0, 3)] 0, attempt 1 0 1 0 [(2, 1), (0, 3)] 0, attempt 2 0 2 0 [(3, 1), (0, 3)] 0, attempt 3 0 3 0 [(4, 1), (0, 3)] 0, attempt 4 0 4 0 [(5, 1), (0, 3)] 0, attempt 5 0 5 0 [(6, 1), (0, 3)] 0, attempt 6 0 6 0 [(7, 1), (0, 3)] 0, attempt 7 0 7 0 [(8, 1), (0, 3)] 0, attempt 8 0 8 0 [(9, 1), (0, 3)] 0, attempt 9 0 9 0 [(10, 1), (0, 3)] 0, attempt 10 0 10 0 [(11, 1), (0, 3)] 0, attempt 11 0 11 0 [(12, 1), (0, 3)] 0, attempt 12 0 12 0 [(13, 1), (0, 3)] 0, attempt 13 0 13 0 [(14, 1), (0, 3)] 0, attempt 14 0 14 0 [(15, 1), (0, 3)] 0, attempt 15 0 15 0 [(16, 1), (0, 3)] 0, attempt 16 0 16 0 [(17, 1), (0, 3)] 0, attempt 17 0 17 0 [(18, 1), (0, 3)] 0, attempt 18 0 18 0 [(19, 1), (0, 3)] 0, attempt 19 0 19 0 [(20, 1), (0, 3)] 0, attempt 20 0 20 0 [(21, 1), (0, 3)] 0, attempt 21 0 21 0 [(22, 1), (0, 3)] 0, attempt 22 0 22 0 [(23, 1), (0, 3)] 0, attempt 23 0 23 0 [(24, 1), (0, 3)] 0, attempt 24 0 24 0 [(25, 1), (0, 3)] 0, attempt 25 0 25 0 [(26, 1), (0, 3)] 0, attempt 26 0 26 0 [(27, 1), (0, 3)] 0, attempt 27 0 27 0 [(28, 1), (0, 3)] 0, attempt 28 0 28 0 [(29, 1), (0, 3)] 0, attempt 29 0 29 0 [(30, 1), (0, 3)] 0, attempt 30 0 30 0 [(31, 1), (0, 3)] 0, attempt 31 0 31 0 [(32, 1), (0, 3)] 0]
def counters001 : List Nat := [32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 0
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 32 0 32 0 [(33, 1), (0, 3)] 0, attempt 33 0 33 0 [(34, 1), (0, 3)] 0, attempt 34 0 34 0 [(35, 1), (0, 3)] 0, attempt 35 0 35 0 [(36, 1), (0, 3)] 0, attempt 36 0 36 0 [(37, 1), (0, 3)] 0, attempt 37 0 37 0 [(38, 1), (0, 3)] 0, attempt 38 0 38 0 [(39, 1), (0, 3)] 0, attempt 39 0 39 0 [(40, 1), (0, 3)] 0, attempt 40 0 40 0 [(41, 1), (0, 3)] 0, attempt 41 0 41 0 [(42, 1), (0, 3)] 0, attempt 42 0 42 0 [(43, 1), (0, 3)] 0, attempt 43 0 43 0 [(44, 1), (0, 3)] 0, attempt 44 0 44 0 [(45, 1), (0, 3)] 0, attempt 45 0 45 0 [(46, 1), (0, 3)] 0, attempt 46 0 46 0 [(47, 1), (0, 3)] 0, attempt 47 0 47 0 [(48, 1), (0, 3)] 0, attempt 48 0 48 0 [(49, 1), (0, 3)] 0, attempt 49 0 49 0 [(50, 1), (0, 3)] 0, attempt 50 0 50 0 [(51, 1), (0, 3)] 0, attempt 51 0 51 0 [(52, 1), (0, 3)] 0, attempt 52 0 52 0 [(53, 1), (0, 3)] 0, attempt 53 0 53 0 [(54, 1), (0, 3)] 0, attempt 54 0 54 0 [(55, 1), (0, 3)] 0, attempt 55 0 55 0 [(56, 1), (0, 3)] 0, attempt 56 0 56 0 [(57, 1), (0, 3)] 0, attempt 57 0 57 0 [(58, 1), (0, 3)] 0, attempt 58 0 58 0 [(59, 1), (0, 3)] 0, attempt 59 0 59 0 [(60, 1), (0, 3)] 0, attempt 60 0 60 0 [(61, 1), (0, 3)] 0, attempt 61 0 61 0 [(62, 1), (0, 3)] 0, attempt 62 0 62 0 [(63, 1), (0, 3)] 0, attempt 63 0 63 0 [(65, 1), (64, 3)] 0]
def counters002 : List Nat := [64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 32
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 64 0 64 0 [(66, 1), (64, 3)] 0, attempt 65 0 65 0 [(67, 1), (64, 3)] 0, attempt 66 0 66 0 [(68, 1), (64, 3)] 0, attempt 67 0 67 0 [(69, 1), (64, 3)] 0, attempt 68 0 68 0 [(70, 1), (64, 3)] 0, attempt 69 0 69 0 [(71, 1), (64, 3)] 0, attempt 70 0 70 0 [(72, 1), (64, 3)] 0, attempt 71 0 71 0 [(73, 1), (64, 3)] 0, attempt 72 0 72 0 [(74, 1), (64, 3)] 0, attempt 73 0 73 0 [(75, 1), (64, 3)] 0, attempt 74 0 74 0 [(76, 1), (64, 3)] 0, attempt 75 0 75 0 [(77, 1), (64, 3)] 0, attempt 76 0 76 0 [(78, 1), (64, 3)] 0, attempt 77 0 77 0 [(79, 1), (64, 3)] 0, attempt 78 0 78 0 [(80, 1), (64, 3)] 0, attempt 79 0 79 0 [(81, 1), (64, 3)] 0, attempt 80 0 80 0 [(82, 1), (64, 3)] 0, attempt 81 0 81 0 [(83, 1), (64, 3)] 0, attempt 82 0 82 0 [(84, 1), (64, 3)] 0, attempt 83 0 83 0 [(85, 1), (64, 3)] 0, attempt 84 0 84 0 [(86, 1), (64, 3)] 0, attempt 85 0 85 0 [(87, 1), (64, 3)] 0, attempt 86 0 86 0 [(88, 1), (64, 3)] 0, attempt 87 0 87 0 [(89, 1), (64, 3)] 0, attempt 88 0 88 0 [(90, 1), (64, 3)] 0, attempt 89 0 89 0 [(91, 1), (64, 3)] 0, attempt 90 0 90 0 [(92, 1), (64, 3)] 0, attempt 91 0 91 0 [(93, 1), (64, 3)] 0, attempt 92 0 92 0 [(94, 1), (64, 3)] 0, attempt 93 0 93 0 [(95, 1), (64, 3)] 0, attempt 94 0 94 0 [(96, 1), (64, 3)] 0, attempt 95 0 95 0 [(97, 1), (64, 3)] 0]
def counters003 : List Nat := [96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 64
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 96 0 96 0 [(98, 1), (64, 3)] 0, attempt 97 0 97 0 [(99, 1), (64, 3)] 0, attempt 98 0 98 0 [(100, 1), (64, 3)] 0, attempt 99 0 99 0 [(101, 1), (64, 3)] 0, attempt 100 0 100 0 [(102, 1), (64, 3)] 0, attempt 101 0 101 0 [(103, 1), (64, 3)] 0, attempt 102 0 102 0 [(104, 1), (64, 3)] 0, attempt 103 0 103 0 [(105, 1), (64, 3)] 0, attempt 104 0 104 0 [(106, 1), (64, 3)] 0, attempt 105 0 105 0 [(107, 1), (64, 3)] 0, attempt 106 0 106 0 [(108, 1), (64, 3)] 0, attempt 107 0 107 0 [(109, 1), (64, 3)] 0, attempt 108 0 108 0 [(110, 1), (64, 3)] 0, attempt 109 0 109 0 [(111, 1), (64, 3)] 0, attempt 110 0 110 0 [(112, 1), (64, 3)] 0, attempt 111 0 111 0 [(113, 1), (64, 3)] 0, attempt 112 0 112 0 [(114, 1), (64, 3)] 0, attempt 113 0 113 0 [(115, 1), (64, 3)] 0, attempt 114 0 114 0 [(116, 1), (64, 3)] 0, attempt 115 0 115 0 [(117, 1), (64, 3)] 0, attempt 116 0 116 0 [(118, 1), (64, 3)] 0, attempt 117 0 117 0 [(119, 1), (64, 3)] 0, attempt 118 0 118 0 [(120, 1), (64, 3)] 0, attempt 119 0 119 0 [(121, 1), (64, 3)] 0, attempt 120 0 120 0 [(122, 1), (64, 3)] 0, attempt 121 0 121 0 [(123, 1), (64, 3)] 0, attempt 122 0 122 0 [(124, 1), (64, 3)] 0, attempt 123 0 123 0 [(125, 1), (64, 3)] 0, attempt 124 0 124 0 [(126, 1), (64, 3)] 0, attempt 125 0 125 0 [(127, 1), (64, 3)] 0, attempt 126 0 126 0 [(129, 1), (128, 3)] 0, attempt 127 0 127 0 [(130, 1), (128, 3)] 0]
def counters004 : List Nat := [128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 96
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 128 0 128 0 [(131, 1), (128, 3)] 0, attempt 129 0 129 0 [(132, 1), (128, 3)] 0, attempt 130 0 130 0 [(133, 1), (128, 3)] 0, attempt 131 0 131 0 [(134, 1), (128, 3)] 0, attempt 132 0 132 0 [(135, 1), (128, 3)] 0, attempt 133 0 133 0 [(136, 1), (128, 3)] 0, attempt 134 0 134 0 [(137, 1), (128, 3)] 0, attempt 135 0 135 0 [(138, 1), (128, 3)] 0, attempt 136 0 136 0 [(139, 1), (128, 3)] 0, attempt 137 0 137 0 [(140, 1), (128, 3)] 0, attempt 138 0 138 0 [(141, 1), (128, 3)] 0, attempt 139 0 139 0 [(142, 1), (128, 3)] 0, attempt 140 0 140 0 [(143, 1), (128, 3)] 0, attempt 141 0 141 0 [(144, 1), (128, 3)] 0, attempt 142 0 142 0 [(145, 1), (128, 3)] 0, attempt 143 0 143 0 [(146, 1), (128, 3)] 0, attempt 144 0 144 0 [(147, 1), (128, 3)] 0, attempt 145 0 145 0 [(148, 1), (128, 3)] 0, attempt 146 0 146 0 [(149, 1), (128, 3)] 0, attempt 147 0 147 0 [(150, 1), (128, 3)] 0, attempt 148 0 148 0 [(151, 1), (128, 3)] 0, attempt 149 0 149 0 [(152, 1), (128, 3)] 0, attempt 150 0 150 0 [(153, 1), (128, 3)] 0, attempt 151 0 151 0 [(154, 1), (128, 3)] 0, attempt 152 0 152 0 [(155, 1), (128, 3)] 0, attempt 153 0 153 0 [(156, 1), (128, 3)] 0, attempt 154 0 154 0 [(157, 1), (128, 3)] 0, attempt 155 0 155 0 [(158, 1), (128, 3)] 0, attempt 156 0 156 0 [(159, 1), (128, 3)] 0, attempt 157 0 157 0 [(160, 1), (128, 3)] 0, attempt 158 0 158 0 [(161, 1), (128, 3)] 0, attempt 159 0 159 0 [(162, 1), (128, 3)] 0]
def counters005 : List Nat := [160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 128
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 160 0 160 0 [(163, 1), (128, 3)] 0, attempt 161 0 161 0 [(164, 1), (128, 3)] 0, attempt 162 0 162 0 [(165, 1), (128, 3)] 0, attempt 163 0 163 0 [(166, 1), (128, 3)] 0, attempt 164 0 164 0 [(167, 1), (128, 3)] 0, attempt 165 0 165 0 [(168, 1), (128, 3)] 0, attempt 166 0 166 0 [(169, 1), (128, 3)] 0, attempt 167 0 167 0 [(170, 1), (128, 3)] 0, attempt 168 0 168 0 [(171, 1), (128, 3)] 0, attempt 169 0 169 0 [(172, 1), (128, 3)] 0, attempt 170 0 170 0 [(173, 1), (128, 3)] 0, attempt 171 0 171 0 [(174, 1), (128, 3)] 0, attempt 172 0 172 0 [(175, 1), (128, 3)] 0, attempt 173 0 173 0 [(176, 1), (128, 3)] 0, attempt 174 0 174 0 [(177, 1), (128, 3)] 0, attempt 175 0 175 0 [(178, 1), (128, 3)] 0, attempt 176 0 176 0 [(179, 1), (128, 3)] 0, attempt 177 0 177 0 [(180, 1), (128, 3)] 0, attempt 178 0 178 0 [(181, 1), (128, 3)] 0, attempt 179 0 179 0 [(182, 1), (128, 3)] 0, attempt 180 0 180 0 [(183, 1), (128, 3)] 0, attempt 181 0 181 0 [(184, 1), (128, 3)] 0, attempt 182 0 182 0 [(185, 1), (128, 3)] 0, attempt 183 0 183 0 [(186, 1), (128, 3)] 0, attempt 184 0 184 0 [(187, 1), (128, 3)] 0, attempt 185 0 185 0 [(188, 1), (128, 3)] 0, attempt 186 0 186 0 [(189, 1), (128, 3)] 0, attempt 187 0 187 0 [(190, 1), (128, 3)] 0, attempt 188 0 188 0 [(191, 1), (128, 3)] 0, attempt 189 0 189 0 [(193, 1), (192, 3)] 0, attempt 190 0 190 0 [(194, 1), (192, 3)] 0, attempt 191 0 191 0 [(195, 1), (192, 3)] 0]
def counters006 : List Nat := [192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 160
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 192 0 192 0 [(196, 1), (192, 3)] 0, attempt 193 0 193 0 [(197, 1), (192, 3)] 0, attempt 194 0 194 0 [(198, 1), (192, 3)] 0, attempt 195 0 195 0 [(199, 1), (192, 3)] 0, attempt 196 0 196 0 [(200, 1), (192, 3)] 0, attempt 197 0 197 0 [(201, 1), (192, 3)] 0, attempt 198 0 198 0 [(202, 1), (192, 3)] 0, attempt 199 0 199 0 [(203, 1), (192, 3)] 0, attempt 200 0 200 0 [(204, 1), (192, 3)] 0, attempt 201 0 201 0 [(205, 1), (192, 3)] 0, attempt 202 0 202 0 [(206, 1), (192, 3)] 0, attempt 203 0 203 0 [(207, 1), (192, 3)] 0, attempt 204 0 204 0 [(208, 1), (192, 3)] 0, attempt 205 0 205 0 [(209, 1), (192, 3)] 0, attempt 206 0 206 0 [(210, 1), (192, 3)] 0, attempt 207 0 207 0 [(211, 1), (192, 3)] 0, attempt 208 0 208 0 [(212, 1), (192, 3)] 0, attempt 209 0 209 0 [(213, 1), (192, 3)] 0, attempt 210 0 210 0 [(214, 1), (192, 3)] 0, attempt 211 0 211 0 [(215, 1), (192, 3)] 0, attempt 212 0 212 0 [(216, 1), (192, 3)] 0, attempt 213 0 213 0 [(217, 1), (192, 3)] 0, attempt 214 0 214 0 [(218, 1), (192, 3)] 0, attempt 215 0 215 0 [(219, 1), (192, 3)] 0, attempt 216 0 216 0 [(220, 1), (192, 3)] 0, attempt 217 0 217 0 [(221, 1), (192, 3)] 0, attempt 218 0 218 0 [(222, 1), (192, 3)] 0, attempt 219 0 219 0 [(223, 1), (192, 3)] 0, attempt 220 0 220 0 [(224, 1), (192, 3)] 0, attempt 221 0 221 0 [(225, 1), (192, 3)] 0, attempt 222 0 222 0 [(226, 1), (192, 3)] 0, attempt 223 0 223 0 [(227, 1), (192, 3)] 0]
def counters007 : List Nat := [224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 192
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 224 0 224 0 [(228, 1), (192, 3)] 0, attempt 225 0 225 0 [(229, 1), (192, 3)] 0, attempt 226 0 226 0 [(230, 1), (192, 3)] 0, attempt 227 0 227 0 [(231, 1), (192, 3)] 0, attempt 228 0 228 0 [(232, 1), (192, 3)] 0, attempt 229 0 229 0 [(233, 1), (192, 3)] 0, attempt 230 0 230 0 [(234, 1), (192, 3)] 0, attempt 231 0 231 0 [(235, 1), (192, 3)] 0, attempt 232 0 232 0 [(236, 1), (192, 3)] 0, attempt 233 0 233 0 [(237, 1), (192, 3)] 0, attempt 234 0 234 0 [(238, 1), (192, 3)] 0, attempt 235 0 235 0 [(239, 1), (192, 3)] 0, attempt 236 0 236 0 [(240, 1), (192, 3)] 0, attempt 237 0 237 0 [(241, 1), (192, 3)] 0, attempt 238 0 238 0 [(242, 1), (192, 3)] 0, attempt 239 0 239 0 [(243, 1), (192, 3)] 0, attempt 240 0 240 0 [(244, 1), (192, 3)] 0, attempt 241 0 241 0 [(245, 1), (192, 3)] 0, attempt 242 0 242 0 [(246, 1), (192, 3)] 0, attempt 243 0 243 0 [(247, 1), (192, 3)] 0, attempt 244 0 244 0 [(248, 1), (192, 3)] 0, attempt 245 0 245 0 [(249, 1), (192, 3)] 0, attempt 246 0 246 0 [(250, 1), (192, 3)] 0, attempt 247 0 247 0 [(251, 1), (192, 3)] 0, attempt 248 0 248 0 [(252, 1), (192, 3)] 0, attempt 249 0 249 0 [(253, 1), (192, 3)] 0, attempt 250 0 250 0 [(254, 1), (192, 3)] 0, attempt 251 0 251 0 [(255, 1), (192, 3)] 0, attempt 252 0 252 0 [(257, 1), (256, 3)] 0, attempt 253 0 253 0 [(258, 1), (256, 3)] 0, attempt 254 0 254 0 [(259, 1), (256, 3)] 0, attempt 255 0 255 0 [(260, 1), (256, 3)] 0]
def counters008 : List Nat := [256, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 224
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 256 0 256 0 [(261, 1), (256, 3)] 0, attempt 257 0 257 0 [(262, 1), (256, 3)] 0, attempt 258 0 258 0 [(263, 1), (256, 3)] 0, attempt 259 0 259 0 [(264, 1), (256, 3)] 0, attempt 260 0 260 0 [(265, 1), (256, 3)] 0, attempt 261 0 261 0 [(266, 1), (256, 3)] 0, attempt 262 0 262 0 [(267, 1), (256, 3)] 0, attempt 263 0 263 0 [(268, 1), (256, 3)] 0, attempt 264 0 264 0 [(269, 1), (256, 3)] 0, attempt 265 0 265 0 [(270, 1), (256, 3)] 0, attempt 266 0 266 0 [(271, 1), (256, 3)] 0, attempt 267 0 267 0 [(272, 1), (256, 3)] 0, attempt 268 0 268 0 [(273, 1), (256, 3)] 0, attempt 269 0 269 0 [(274, 1), (256, 3)] 0, attempt 270 0 270 0 [(275, 1), (256, 3)] 0, attempt 271 0 271 0 [(276, 1), (256, 3)] 0, attempt 272 0 272 0 [(277, 1), (256, 3)] 0, attempt 273 0 273 0 [(278, 1), (256, 3)] 0, attempt 274 0 274 0 [(279, 1), (256, 3)] 0, attempt 275 0 275 0 [(280, 1), (256, 3)] 0, attempt 276 0 276 0 [(281, 1), (256, 3)] 0, attempt 277 0 277 0 [(282, 1), (256, 3)] 0, attempt 278 0 278 0 [(283, 1), (256, 3)] 0, attempt 279 0 279 0 [(284, 1), (256, 3)] 0, attempt 280 0 280 0 [(285, 1), (256, 3)] 0, attempt 281 0 281 0 [(286, 1), (256, 3)] 0, attempt 282 0 282 0 [(287, 1), (256, 3)] 0, attempt 283 0 283 0 [(288, 1), (256, 3)] 0, attempt 284 0 284 0 [(289, 1), (256, 3)] 0, attempt 285 0 285 0 [(290, 1), (256, 3)] 0, attempt 286 0 286 0 [(291, 1), (256, 3)] 0, attempt 287 0 287 0 [(292, 1), (256, 3)] 0]
def counters009 : List Nat := [288, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 256
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 288 0 288 0 [(293, 1), (256, 3)] 0, attempt 289 0 289 0 [(294, 1), (256, 3)] 0, attempt 290 0 290 0 [(295, 1), (256, 3)] 0, attempt 291 0 291 0 [(296, 1), (256, 3)] 0, attempt 292 0 292 0 [(297, 1), (256, 3)] 0, attempt 293 0 293 0 [(298, 1), (256, 3)] 0, attempt 294 0 294 0 [(299, 1), (256, 3)] 0, attempt 295 0 295 0 [(300, 1), (256, 3)] 0, attempt 296 0 296 0 [(301, 1), (256, 3)] 0, attempt 297 0 297 0 [(302, 1), (256, 3)] 0, attempt 298 0 298 0 [(303, 1), (256, 3)] 0, attempt 299 0 299 0 [(304, 1), (256, 3)] 0, attempt 300 0 300 0 [(305, 1), (256, 3)] 0, attempt 301 0 301 0 [(306, 1), (256, 3)] 0, attempt 302 0 302 0 [(307, 1), (256, 3)] 0, attempt 303 0 303 0 [(308, 1), (256, 3)] 0, attempt 304 0 304 0 [(309, 1), (256, 3)] 0, attempt 305 0 305 0 [(310, 1), (256, 3)] 0, attempt 306 0 306 0 [(311, 1), (256, 3)] 0, attempt 307 0 307 0 [(312, 1), (256, 3)] 0, attempt 308 0 308 0 [(313, 1), (256, 3)] 0, attempt 309 0 309 0 [(314, 1), (256, 3)] 0, attempt 310 0 310 0 [(315, 1), (256, 3)] 0, attempt 311 0 311 0 [(316, 1), (256, 3)] 0, attempt 312 0 312 0 [(317, 1), (256, 3)] 0, attempt 313 0 313 0 [(318, 1), (256, 3)] 0, attempt 314 0 314 0 [(319, 1), (256, 3)] 0, attempt 315 0 315 0 [(321, 1), (320, 3)] 0, attempt 316 0 316 0 [(322, 1), (320, 3)] 0, attempt 317 0 317 0 [(323, 1), (320, 3)] 0, attempt 318 0 318 0 [(324, 1), (320, 3)] 0, attempt 319 0 319 0 [(325, 1), (320, 3)] 0]
def counters010 : List Nat := [320, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 288
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 320 0 320 0 [(326, 1), (320, 3)] 0, attempt 321 0 321 0 [(327, 1), (320, 3)] 0, attempt 322 0 322 0 [(328, 1), (320, 3)] 0, attempt 323 0 323 0 [(329, 1), (320, 3)] 0, attempt 324 0 324 0 [(330, 1), (320, 3)] 0, attempt 325 0 325 0 [(331, 1), (320, 3)] 0, attempt 326 0 326 0 [(332, 1), (320, 3)] 0, attempt 327 0 327 0 [(333, 1), (320, 3)] 0, attempt 328 0 328 0 [(334, 1), (320, 3)] 0, attempt 329 0 329 0 [(335, 1), (320, 3)] 0, attempt 330 0 330 0 [(336, 1), (320, 3)] 0, attempt 331 0 331 0 [(337, 1), (320, 3)] 0, attempt 332 0 332 0 [(338, 1), (320, 3)] 0, attempt 333 0 333 0 [(339, 1), (320, 3)] 0, attempt 334 0 334 0 [(340, 1), (320, 3)] 0, attempt 335 0 335 0 [(341, 1), (320, 3)] 0, attempt 336 0 336 0 [(342, 1), (320, 3)] 0, attempt 337 0 337 0 [(343, 1), (320, 3)] 0, attempt 338 0 338 0 [(344, 1), (320, 3)] 0, attempt 339 0 339 0 [(345, 1), (320, 3)] 0, attempt 340 0 340 0 [(346, 1), (320, 3)] 0, attempt 341 0 341 0 [(347, 1), (320, 3)] 0, attempt 342 0 342 0 [(348, 1), (320, 3)] 0, attempt 343 0 343 0 [(349, 1), (320, 3)] 0, attempt 344 0 344 0 [(350, 1), (320, 3)] 0, attempt 345 0 345 0 [(351, 1), (320, 3)] 0, attempt 346 0 346 0 [(352, 1), (320, 3)] 0, attempt 347 0 347 0 [(353, 1), (320, 3)] 0, attempt 348 0 348 0 [(354, 1), (320, 3)] 0, attempt 349 0 349 0 [(355, 1), (320, 3)] 0, attempt 350 0 350 0 [(356, 1), (320, 3)] 0, attempt 351 0 351 0 [(357, 1), (320, 3)] 0]
def counters011 : List Nat := [352, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 320
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 352 0 352 0 [(358, 1), (320, 3)] 0, attempt 353 0 353 0 [(359, 1), (320, 3)] 0, attempt 354 0 354 0 [(360, 1), (320, 3)] 0, attempt 355 0 355 0 [(361, 1), (320, 3)] 0, attempt 356 0 356 0 [(362, 1), (320, 3)] 0, attempt 357 0 357 0 [(363, 1), (320, 3)] 0, attempt 358 0 358 0 [(364, 1), (320, 3)] 0, attempt 359 0 359 0 [(365, 1), (320, 3)] 0, attempt 360 0 360 0 [(366, 1), (320, 3)] 0, attempt 361 0 361 0 [(367, 1), (320, 3)] 0, attempt 362 0 362 0 [(368, 1), (320, 3)] 0, attempt 363 0 363 0 [(369, 1), (320, 3)] 0, attempt 364 0 364 0 [(370, 1), (320, 3)] 0, attempt 365 0 365 0 [(371, 1), (320, 3)] 0, attempt 366 0 366 0 [(372, 1), (320, 3)] 0, attempt 367 0 367 0 [(373, 1), (320, 3)] 0, attempt 368 0 368 0 [(374, 1), (320, 3)] 0, attempt 369 0 369 0 [(375, 1), (320, 3)] 0, attempt 370 0 370 0 [(376, 1), (320, 3)] 0, attempt 371 0 371 0 [(377, 1), (320, 3)] 0, attempt 372 0 372 0 [(378, 1), (320, 3)] 0, attempt 373 0 373 0 [(379, 1), (320, 3)] 0, attempt 374 0 374 0 [(380, 1), (320, 3)] 0, attempt 375 0 375 0 [(381, 1), (320, 3)] 0, attempt 376 0 376 0 [(382, 1), (320, 3)] 0, attempt 377 0 377 0 [(383, 1), (320, 3)] 0, attempt 378 0 378 0 [(385, 1), (384, 3)] 0, attempt 379 0 379 0 [(386, 1), (384, 3)] 0, attempt 380 0 380 0 [(387, 1), (384, 3)] 0, attempt 381 0 381 0 [(388, 1), (384, 3)] 0, attempt 382 0 382 0 [(389, 1), (384, 3)] 0, attempt 383 0 383 0 [(390, 1), (384, 3)] 0]
def counters012 : List Nat := [384, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 352
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 384 0 384 0 [(391, 1), (384, 3)] 0, attempt 385 0 385 0 [(392, 1), (384, 3)] 0, attempt 386 0 386 0 [(393, 1), (384, 3)] 0, attempt 387 0 387 0 [(394, 1), (384, 3)] 0, attempt 388 0 388 0 [(395, 1), (384, 3)] 0, attempt 389 0 389 0 [(396, 1), (384, 3)] 0, attempt 390 0 390 0 [(397, 1), (384, 3)] 0, attempt 391 0 391 0 [(398, 1), (384, 3)] 0, attempt 392 0 392 0 [(399, 1), (384, 3)] 0, attempt 393 0 393 0 [(400, 1), (384, 3)] 0, attempt 394 0 394 0 [(401, 1), (384, 3)] 0, attempt 395 0 395 0 [(402, 1), (384, 3)] 0, attempt 396 0 396 0 [(403, 1), (384, 3)] 0, attempt 397 0 397 0 [(404, 1), (384, 3)] 0, attempt 398 0 398 0 [(405, 1), (384, 3)] 0, attempt 399 0 399 0 [(406, 1), (384, 3)] 0, attempt 400 0 400 0 [(407, 1), (384, 3)] 0, attempt 401 0 401 0 [(408, 1), (384, 3)] 0, attempt 402 0 402 0 [(409, 1), (384, 3)] 0, attempt 403 0 403 0 [(410, 1), (384, 3)] 0, attempt 404 0 404 0 [(411, 1), (384, 3)] 0, attempt 405 0 405 0 [(412, 1), (384, 3)] 0, attempt 406 0 406 0 [(413, 1), (384, 3)] 0, attempt 407 0 407 0 [(414, 1), (384, 3)] 0, attempt 408 0 408 0 [(415, 1), (384, 3)] 0, attempt 409 0 409 0 [(416, 1), (384, 3)] 0, attempt 410 0 410 0 [(417, 1), (384, 3)] 0, attempt 411 0 411 0 [(418, 1), (384, 3)] 0, attempt 412 0 412 0 [(419, 1), (384, 3)] 0, attempt 413 0 413 0 [(420, 1), (384, 3)] 0, attempt 414 0 414 0 [(421, 1), (384, 3)] 0, attempt 415 0 415 0 [(422, 1), (384, 3)] 0]
def counters013 : List Nat := [416, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 384
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 416 0 416 0 [(423, 1), (384, 3)] 0, attempt 417 0 417 0 [(424, 1), (384, 3)] 0, attempt 418 0 418 0 [(425, 1), (384, 3)] 0, attempt 419 0 419 0 [(426, 1), (384, 3)] 0, attempt 420 0 420 0 [(427, 1), (384, 3)] 0, attempt 421 0 421 0 [(428, 1), (384, 3)] 0, attempt 422 0 422 0 [(429, 1), (384, 3)] 0, attempt 423 0 423 0 [(430, 1), (384, 3)] 0, attempt 424 0 424 0 [(431, 1), (384, 3)] 0, attempt 425 0 425 0 [(432, 1), (384, 3)] 0, attempt 426 0 426 0 [(433, 1), (384, 3)] 0, attempt 427 0 427 0 [(434, 1), (384, 3)] 0, attempt 428 0 428 0 [(435, 1), (384, 3)] 0, attempt 429 0 429 0 [(436, 1), (384, 3)] 0, attempt 430 0 430 0 [(437, 1), (384, 3)] 0, attempt 431 0 431 0 [(438, 1), (384, 3)] 0, attempt 432 0 432 0 [(439, 1), (384, 3)] 0, attempt 433 0 433 0 [(440, 1), (384, 3)] 0, attempt 434 0 434 0 [(441, 1), (384, 3)] 0, attempt 435 0 435 0 [(442, 1), (384, 3)] 0, attempt 436 0 436 0 [(443, 1), (384, 3)] 0, attempt 437 0 437 0 [(444, 1), (384, 3)] 0, attempt 438 0 438 0 [(445, 1), (384, 3)] 0, attempt 439 0 439 0 [(446, 1), (384, 3)] 0, attempt 440 0 440 0 [(447, 1), (384, 3)] 0, attempt 441 0 441 0 [(449, 1), (448, 3)] 0, attempt 442 0 442 0 [(450, 1), (448, 3)] 0, attempt 443 0 443 0 [(451, 1), (448, 3)] 0, attempt 444 0 444 0 [(452, 1), (448, 3)] 0, attempt 445 0 445 0 [(453, 1), (448, 3)] 0, attempt 446 0 446 0 [(454, 1), (448, 3)] 0, attempt 447 0 447 0 [(455, 1), (448, 3)] 0]
def counters014 : List Nat := [448, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 416
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 448 0 448 0 [(456, 1), (448, 3)] 0, attempt 449 0 449 0 [(457, 1), (448, 3)] 0, attempt 450 0 450 0 [(458, 1), (448, 3)] 0, attempt 451 0 451 0 [(459, 1), (448, 3)] 0, attempt 452 0 452 0 [(460, 1), (448, 3)] 0, attempt 453 0 453 0 [(461, 1), (448, 3)] 0, attempt 454 0 454 0 [(462, 1), (448, 3)] 0, attempt 455 0 455 0 [(463, 1), (448, 3)] 0, attempt 456 0 456 0 [(464, 1), (448, 3)] 0, attempt 457 0 457 0 [(465, 1), (448, 3)] 0, attempt 458 0 458 0 [(466, 1), (448, 3)] 0, attempt 459 0 459 0 [(467, 1), (448, 3)] 0, attempt 460 0 460 0 [(468, 1), (448, 3)] 0, attempt 461 0 461 0 [(469, 1), (448, 3)] 0, attempt 462 0 462 0 [(470, 1), (448, 3)] 0, attempt 463 0 463 0 [(471, 1), (448, 3)] 0, attempt 464 0 464 0 [(472, 1), (448, 3)] 0, attempt 465 0 465 0 [(473, 1), (448, 3)] 0, attempt 466 0 466 0 [(474, 1), (448, 3)] 0, attempt 467 0 467 0 [(475, 1), (448, 3)] 0, attempt 468 0 468 0 [(476, 1), (448, 3)] 0, attempt 469 0 469 0 [(477, 1), (448, 3)] 0, attempt 470 0 470 0 [(478, 1), (448, 3)] 0, attempt 471 0 471 0 [(479, 1), (448, 3)] 0, attempt 472 0 472 0 [(480, 1), (448, 3)] 0, attempt 473 0 473 0 [(481, 1), (448, 3)] 0, attempt 474 0 474 0 [(482, 1), (448, 3)] 0, attempt 475 0 475 0 [(483, 1), (448, 3)] 0, attempt 476 0 476 0 [(484, 1), (448, 3)] 0, attempt 477 0 477 0 [(485, 1), (448, 3)] 0, attempt 478 0 478 0 [(486, 1), (448, 3)] 0, attempt 479 0 479 0 [(487, 1), (448, 3)] 0]
def counters015 : List Nat := [480, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 448
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 480 0 480 0 [(488, 1), (448, 3)] 0, attempt 481 0 481 0 [(489, 1), (448, 3)] 0, attempt 482 0 482 0 [(490, 1), (448, 3)] 0, attempt 483 0 483 0 [(491, 1), (448, 3)] 0, attempt 484 0 484 0 [(492, 1), (448, 3)] 0, attempt 485 0 485 0 [(493, 1), (448, 3)] 0, attempt 486 0 486 0 [(494, 1), (448, 3)] 0, attempt 487 0 487 0 [(495, 1), (448, 3)] 0, attempt 488 0 488 0 [(496, 1), (448, 3)] 0, attempt 489 0 489 0 [(497, 1), (448, 3)] 0, attempt 490 0 490 0 [(498, 1), (448, 3)] 0, attempt 491 0 491 0 [(499, 1), (448, 3)] 0, attempt 492 0 492 0 [(500, 1), (448, 3)] 0, attempt 493 0 493 0 [(501, 1), (448, 3)] 0, attempt 494 0 494 0 [(502, 1), (448, 3)] 0, attempt 495 0 495 0 [(503, 1), (448, 3)] 0, attempt 496 0 496 0 [(504, 1), (448, 3)] 0, attempt 497 0 497 0 [(505, 1), (448, 3)] 0, attempt 498 0 498 0 [(506, 1), (448, 3)] 0, attempt 499 0 499 0 [(507, 1), (448, 3)] 0, attempt 500 0 500 0 [(508, 1), (448, 3)] 0, attempt 501 0 501 0 [(509, 1), (448, 3)] 0, attempt 502 0 502 0 [(510, 1), (448, 3)] 0, attempt 503 0 503 0 [(511, 1), (448, 3)] 0, attempt 504 0 504 0 [(513, 1), (512, 3)] 0, attempt 505 0 505 0 [(514, 1), (512, 3)] 0, attempt 506 0 506 0 [(515, 1), (512, 3)] 0, attempt 507 0 507 0 [(516, 1), (512, 3)] 0, attempt 508 0 508 0 [(517, 1), (512, 3)] 0, attempt 509 0 509 0 [(518, 1), (512, 3)] 0, attempt 510 0 510 0 [(519, 1), (512, 3)] 0, attempt 511 0 511 0 [(520, 1), (512, 3)] 0]
def counters016 : List Nat := [512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 480
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 512
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 480
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 480 512 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 480) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 448
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 448 480 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 448) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 416
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 416 448 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 416) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 384
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 384 416 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 384) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 352
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 352 384 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 352) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 320
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 320 352 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 320) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 288
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 288 320 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 288) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 256
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 256 288 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 256) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 224
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 224 256 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 224) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 192
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 192 224 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 192) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 160
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 160 192 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 160) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 128
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 128 160 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 128) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 96
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 96 128 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 96) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 64
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 64 96 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 64) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 32
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 32 64 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 32) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 0
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 0 32 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 0) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr00
