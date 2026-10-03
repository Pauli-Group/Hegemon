import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr11

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr12
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [6144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 6144 0 6144 0 [(6242, 1), (6208, 3)] 0, attempt 6145 0 6145 0 [(6243, 1), (6208, 3)] 0, attempt 6146 0 6146 0 [(6244, 1), (6208, 3)] 0, attempt 6147 0 6147 0 [(6245, 1), (6208, 3)] 0, attempt 6148 0 6148 0 [(6246, 1), (6208, 3)] 0, attempt 6149 0 6149 0 [(6247, 1), (6208, 3)] 0, attempt 6150 0 6150 0 [(6248, 1), (6208, 3)] 0, attempt 6151 0 6151 0 [(6249, 1), (6208, 3)] 0, attempt 6152 0 6152 0 [(6250, 1), (6208, 3)] 0, attempt 6153 0 6153 0 [(6251, 1), (6208, 3)] 0, attempt 6154 0 6154 0 [(6252, 1), (6208, 3)] 0, attempt 6155 0 6155 0 [(6253, 1), (6208, 3)] 0, attempt 6156 0 6156 0 [(6254, 1), (6208, 3)] 0, attempt 6157 0 6157 0 [(6255, 1), (6208, 3)] 0, attempt 6158 0 6158 0 [(6256, 1), (6208, 3)] 0, attempt 6159 0 6159 0 [(6257, 1), (6208, 3)] 0, attempt 6160 0 6160 0 [(6258, 1), (6208, 3)] 0, attempt 6161 0 6161 0 [(6259, 1), (6208, 3)] 0, attempt 6162 0 6162 0 [(6260, 1), (6208, 3)] 0, attempt 6163 0 6163 0 [(6261, 1), (6208, 3)] 0, attempt 6164 0 6164 0 [(6262, 1), (6208, 3)] 0, attempt 6165 0 6165 0 [(6263, 1), (6208, 3)] 0, attempt 6166 0 6166 0 [(6264, 1), (6208, 3)] 0, attempt 6167 0 6167 0 [(6265, 1), (6208, 3)] 0, attempt 6168 0 6168 0 [(6266, 1), (6208, 3)] 0, attempt 6169 0 6169 0 [(6267, 1), (6208, 3)] 0, attempt 6170 0 6170 0 [(6268, 1), (6208, 3)] 0, attempt 6171 0 6171 0 [(6269, 1), (6208, 3)] 0, attempt 6172 0 6172 0 [(6270, 1), (6208, 3)] 0, attempt 6173 0 6173 0 [(6271, 1), (6208, 3)] 0, attempt 6174 0 6174 0 [(6273, 1), (6272, 3)] 0, attempt 6175 0 6175 0 [(6274, 1), (6272, 3)] 0]
def counters001 : List Nat := [6176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6144
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 6176 0 6176 0 [(6275, 1), (6272, 3)] 0, attempt 6177 0 6177 0 [(6276, 1), (6272, 3)] 0, attempt 6178 0 6178 0 [(6277, 1), (6272, 3)] 0, attempt 6179 0 6179 0 [(6278, 1), (6272, 3)] 0, attempt 6180 0 6180 0 [(6279, 1), (6272, 3)] 0, attempt 6181 0 6181 0 [(6280, 1), (6272, 3)] 0, attempt 6182 0 6182 0 [(6281, 1), (6272, 3)] 0, attempt 6183 0 6183 0 [(6282, 1), (6272, 3)] 0, attempt 6184 0 6184 0 [(6283, 1), (6272, 3)] 0, attempt 6185 0 6185 0 [(6284, 1), (6272, 3)] 0, attempt 6186 0 6186 0 [(6285, 1), (6272, 3)] 0, attempt 6187 0 6187 0 [(6286, 1), (6272, 3)] 0, attempt 6188 0 6188 0 [(6287, 1), (6272, 3)] 0, attempt 6189 0 6189 0 [(6288, 1), (6272, 3)] 0, attempt 6190 0 6190 0 [(6289, 1), (6272, 3)] 0, attempt 6191 0 6191 0 [(6290, 1), (6272, 3)] 0, attempt 6192 0 6192 0 [(6291, 1), (6272, 3)] 0, attempt 6193 0 6193 0 [(6292, 1), (6272, 3)] 0, attempt 6194 0 6194 0 [(6293, 1), (6272, 3)] 0, attempt 6195 0 6195 0 [(6294, 1), (6272, 3)] 0, attempt 6196 0 6196 0 [(6295, 1), (6272, 3)] 0, attempt 6197 0 6197 0 [(6296, 1), (6272, 3)] 0, attempt 6198 0 6198 0 [(6297, 1), (6272, 3)] 0, attempt 6199 0 6199 0 [(6298, 1), (6272, 3)] 0, attempt 6200 0 6200 0 [(6299, 1), (6272, 3)] 0, attempt 6201 0 6201 0 [(6300, 1), (6272, 3)] 0, attempt 6202 0 6202 0 [(6301, 1), (6272, 3)] 0, attempt 6203 0 6203 0 [(6302, 1), (6272, 3)] 0, attempt 6204 0 6204 0 [(6303, 1), (6272, 3)] 0, attempt 6205 0 6205 0 [(6304, 1), (6272, 3)] 0, attempt 6206 0 6206 0 [(6305, 1), (6272, 3)] 0, attempt 6207 0 6207 0 [(6306, 1), (6272, 3)] 0]
def counters002 : List Nat := [6208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6176
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 6208 0 6208 0 [(6307, 1), (6272, 3)] 0, attempt 6209 0 6209 0 [(6308, 1), (6272, 3)] 0, attempt 6210 0 6210 0 [(6309, 1), (6272, 3)] 0, attempt 6211 0 6211 0 [(6310, 1), (6272, 3)] 0, attempt 6212 0 6212 0 [(6311, 1), (6272, 3)] 0, attempt 6213 0 6213 0 [(6312, 1), (6272, 3)] 0, attempt 6214 0 6214 0 [(6313, 1), (6272, 3)] 0, attempt 6215 0 6215 0 [(6314, 1), (6272, 3)] 0, attempt 6216 0 6216 0 [(6315, 1), (6272, 3)] 0, attempt 6217 0 6217 0 [(6316, 1), (6272, 3)] 0, attempt 6218 0 6218 0 [(6317, 1), (6272, 3)] 0, attempt 6219 0 6219 0 [(6318, 1), (6272, 3)] 0, attempt 6220 0 6220 0 [(6319, 1), (6272, 3)] 0, attempt 6221 0 6221 0 [(6320, 1), (6272, 3)] 0, attempt 6222 0 6222 0 [(6321, 1), (6272, 3)] 0, attempt 6223 0 6223 0 [(6322, 1), (6272, 3)] 0, attempt 6224 0 6224 0 [(6323, 1), (6272, 3)] 0, attempt 6225 0 6225 0 [(6324, 1), (6272, 3)] 0, attempt 6226 0 6226 0 [(6325, 1), (6272, 3)] 0, attempt 6227 0 6227 0 [(6326, 1), (6272, 3)] 0, attempt 6228 0 6228 0 [(6327, 1), (6272, 3)] 0, attempt 6229 0 6229 0 [(6328, 1), (6272, 3)] 0, attempt 6230 0 6230 0 [(6329, 1), (6272, 3)] 0, attempt 6231 0 6231 0 [(6330, 1), (6272, 3)] 0, attempt 6232 0 6232 0 [(6331, 1), (6272, 3)] 0, attempt 6233 0 6233 0 [(6332, 1), (6272, 3)] 0, attempt 6234 0 6234 0 [(6333, 1), (6272, 3)] 0, attempt 6235 0 6235 0 [(6334, 1), (6272, 3)] 0, attempt 6236 0 6236 0 [(6335, 1), (6272, 3)] 0, attempt 6237 0 6237 0 [(6337, 1), (6336, 3)] 0, attempt 6238 0 6238 0 [(6338, 1), (6336, 3)] 0, attempt 6239 0 6239 0 [(6339, 1), (6336, 3)] 0]
def counters003 : List Nat := [6240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6208
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 6240 0 6240 0 [(6340, 1), (6336, 3)] 0, attempt 6241 0 6241 0 [(6341, 1), (6336, 3)] 0, attempt 6242 0 6242 0 [(6342, 1), (6336, 3)] 0, attempt 6243 0 6243 0 [(6343, 1), (6336, 3)] 0, attempt 6244 0 6244 0 [(6344, 1), (6336, 3)] 0, attempt 6245 0 6245 0 [(6345, 1), (6336, 3)] 0, attempt 6246 0 6246 0 [(6346, 1), (6336, 3)] 0, attempt 6247 0 6247 0 [(6347, 1), (6336, 3)] 0, attempt 6248 0 6248 0 [(6348, 1), (6336, 3)] 0, attempt 6249 0 6249 0 [(6349, 1), (6336, 3)] 0, attempt 6250 0 6250 0 [(6350, 1), (6336, 3)] 0, attempt 6251 0 6251 0 [(6351, 1), (6336, 3)] 0, attempt 6252 0 6252 0 [(6352, 1), (6336, 3)] 0, attempt 6253 0 6253 0 [(6353, 1), (6336, 3)] 0, attempt 6254 0 6254 0 [(6354, 1), (6336, 3)] 0, attempt 6255 0 6255 0 [(6355, 1), (6336, 3)] 0, attempt 6256 0 6256 0 [(6356, 1), (6336, 3)] 0, attempt 6257 0 6257 0 [(6357, 1), (6336, 3)] 0, attempt 6258 0 6258 0 [(6358, 1), (6336, 3)] 0, attempt 6259 0 6259 0 [(6359, 1), (6336, 3)] 0, attempt 6260 0 6260 0 [(6360, 1), (6336, 3)] 0, attempt 6261 0 6261 0 [(6361, 1), (6336, 3)] 0, attempt 6262 0 6262 0 [(6362, 1), (6336, 3)] 0, attempt 6263 0 6263 0 [(6363, 1), (6336, 3)] 0, attempt 6264 0 6264 0 [(6364, 1), (6336, 3)] 0, attempt 6265 0 6265 0 [(6365, 1), (6336, 3)] 0, attempt 6266 0 6266 0 [(6366, 1), (6336, 3)] 0, attempt 6267 0 6267 0 [(6367, 1), (6336, 3)] 0, attempt 6268 0 6268 0 [(6368, 1), (6336, 3)] 0, attempt 6269 0 6269 0 [(6369, 1), (6336, 3)] 0, attempt 6270 0 6270 0 [(6370, 1), (6336, 3)] 0, attempt 6271 0 6271 0 [(6371, 1), (6336, 3)] 0]
def counters004 : List Nat := [6272, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6240
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 6272 0 6272 0 [(6372, 1), (6336, 3)] 0, attempt 6273 0 6273 0 [(6373, 1), (6336, 3)] 0, attempt 6274 0 6274 0 [(6374, 1), (6336, 3)] 0, attempt 6275 0 6275 0 [(6375, 1), (6336, 3)] 0, attempt 6276 0 6276 0 [(6376, 1), (6336, 3)] 0, attempt 6277 0 6277 0 [(6377, 1), (6336, 3)] 0, attempt 6278 0 6278 0 [(6378, 1), (6336, 3)] 0, attempt 6279 0 6279 0 [(6379, 1), (6336, 3)] 0, attempt 6280 0 6280 0 [(6380, 1), (6336, 3)] 0, attempt 6281 0 6281 0 [(6381, 1), (6336, 3)] 0, attempt 6282 0 6282 0 [(6382, 1), (6336, 3)] 0, attempt 6283 0 6283 0 [(6383, 1), (6336, 3)] 0, attempt 6284 0 6284 0 [(6384, 1), (6336, 3)] 0, attempt 6285 0 6285 0 [(6385, 1), (6336, 3)] 0, attempt 6286 0 6286 0 [(6386, 1), (6336, 3)] 0, attempt 6287 0 6287 0 [(6387, 1), (6336, 3)] 0, attempt 6288 0 6288 0 [(6388, 1), (6336, 3)] 0, attempt 6289 0 6289 0 [(6389, 1), (6336, 3)] 0, attempt 6290 0 6290 0 [(6390, 1), (6336, 3)] 0, attempt 6291 0 6291 0 [(6391, 1), (6336, 3)] 0, attempt 6292 0 6292 0 [(6392, 1), (6336, 3)] 0, attempt 6293 0 6293 0 [(6393, 1), (6336, 3)] 0, attempt 6294 0 6294 0 [(6394, 1), (6336, 3)] 0, attempt 6295 0 6295 0 [(6395, 1), (6336, 3)] 0, attempt 6296 0 6296 0 [(6396, 1), (6336, 3)] 0, attempt 6297 0 6297 0 [(6397, 1), (6336, 3)] 0, attempt 6298 0 6298 0 [(6398, 1), (6336, 3)] 0, attempt 6299 0 6299 0 [(6399, 1), (6336, 3)] 0, attempt 6300 0 6300 0 [(6401, 1), (6400, 3)] 0, attempt 6301 0 6301 0 [(6402, 1), (6400, 3)] 0, attempt 6302 0 6302 0 [(6403, 1), (6400, 3)] 0, attempt 6303 0 6303 0 [(6404, 1), (6400, 3)] 0]
def counters005 : List Nat := [6304, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6272
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 6304 0 6304 0 [(6405, 1), (6400, 3)] 0, attempt 6305 0 6305 0 [(6406, 1), (6400, 3)] 0, attempt 6306 0 6306 0 [(6407, 1), (6400, 3)] 0, attempt 6307 0 6307 0 [(6408, 1), (6400, 3)] 0, attempt 6308 0 6308 0 [(6409, 1), (6400, 3)] 0, attempt 6309 0 6309 0 [(6410, 1), (6400, 3)] 0, attempt 6310 0 6310 0 [(6411, 1), (6400, 3)] 0, attempt 6311 0 6311 0 [(6412, 1), (6400, 3)] 0, attempt 6312 0 6312 0 [(6413, 1), (6400, 3)] 0, attempt 6313 0 6313 0 [(6414, 1), (6400, 3)] 0, attempt 6314 0 6314 0 [(6415, 1), (6400, 3)] 0, attempt 6315 0 6315 0 [(6416, 1), (6400, 3)] 0, attempt 6316 0 6316 0 [(6417, 1), (6400, 3)] 0, attempt 6317 0 6317 0 [(6418, 1), (6400, 3)] 0, attempt 6318 0 6318 0 [(6419, 1), (6400, 3)] 0, attempt 6319 0 6319 0 [(6420, 1), (6400, 3)] 0, attempt 6320 0 6320 0 [(6421, 1), (6400, 3)] 0, attempt 6321 0 6321 0 [(6422, 1), (6400, 3)] 0, attempt 6322 0 6322 0 [(6423, 1), (6400, 3)] 0, attempt 6323 0 6323 0 [(6424, 1), (6400, 3)] 0, attempt 6324 0 6324 0 [(6425, 1), (6400, 3)] 0, attempt 6325 0 6325 0 [(6426, 1), (6400, 3)] 0, attempt 6326 0 6326 0 [(6427, 1), (6400, 3)] 0, attempt 6327 0 6327 0 [(6428, 1), (6400, 3)] 0, attempt 6328 0 6328 0 [(6429, 1), (6400, 3)] 0, attempt 6329 0 6329 0 [(6430, 1), (6400, 3)] 0, attempt 6330 0 6330 0 [(6431, 1), (6400, 3)] 0, attempt 6331 0 6331 0 [(6432, 1), (6400, 3)] 0, attempt 6332 0 6332 0 [(6433, 1), (6400, 3)] 0, attempt 6333 0 6333 0 [(6434, 1), (6400, 3)] 0, attempt 6334 0 6334 0 [(6435, 1), (6400, 3)] 0, attempt 6335 0 6335 0 [(6436, 1), (6400, 3)] 0]
def counters006 : List Nat := [6336, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6304
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 6336 0 6336 0 [(6437, 1), (6400, 3)] 0, attempt 6337 0 6337 0 [(6438, 1), (6400, 3)] 0, attempt 6338 0 6338 0 [(6439, 1), (6400, 3)] 0, attempt 6339 0 6339 0 [(6440, 1), (6400, 3)] 0, attempt 6340 0 6340 0 [(6441, 1), (6400, 3)] 0, attempt 6341 0 6341 0 [(6442, 1), (6400, 3)] 0, attempt 6342 0 6342 0 [(6443, 1), (6400, 3)] 0, attempt 6343 0 6343 0 [(6444, 1), (6400, 3)] 0, attempt 6344 0 6344 0 [(6445, 1), (6400, 3)] 0, attempt 6345 0 6345 0 [(6446, 1), (6400, 3)] 0, attempt 6346 0 6346 0 [(6447, 1), (6400, 3)] 0, attempt 6347 0 6347 0 [(6448, 1), (6400, 3)] 0, attempt 6348 0 6348 0 [(6449, 1), (6400, 3)] 0, attempt 6349 0 6349 0 [(6450, 1), (6400, 3)] 0, attempt 6350 0 6350 0 [(6451, 1), (6400, 3)] 0, attempt 6351 0 6351 0 [(6452, 1), (6400, 3)] 0, attempt 6352 0 6352 0 [(6453, 1), (6400, 3)] 0, attempt 6353 0 6353 0 [(6454, 1), (6400, 3)] 0, attempt 6354 0 6354 0 [(6455, 1), (6400, 3)] 0, attempt 6355 0 6355 0 [(6456, 1), (6400, 3)] 0, attempt 6356 0 6356 0 [(6457, 1), (6400, 3)] 0, attempt 6357 0 6357 0 [(6458, 1), (6400, 3)] 0, attempt 6358 0 6358 0 [(6459, 1), (6400, 3)] 0, attempt 6359 0 6359 0 [(6460, 1), (6400, 3)] 0, attempt 6360 0 6360 0 [(6461, 1), (6400, 3)] 0, attempt 6361 0 6361 0 [(6462, 1), (6400, 3)] 0, attempt 6362 0 6362 0 [(6463, 1), (6400, 3)] 0, attempt 6363 0 6363 0 [(6465, 1), (6464, 3)] 0, attempt 6364 0 6364 0 [(6466, 1), (6464, 3)] 0, attempt 6365 0 6365 0 [(6467, 1), (6464, 3)] 0, attempt 6366 0 6366 0 [(6468, 1), (6464, 3)] 0, attempt 6367 0 6367 0 [(6469, 1), (6464, 3)] 0]
def counters007 : List Nat := [6368, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6336
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 6368 0 6368 0 [(6470, 1), (6464, 3)] 0, attempt 6369 0 6369 0 [(6471, 1), (6464, 3)] 0, attempt 6370 0 6370 0 [(6472, 1), (6464, 3)] 0, attempt 6371 0 6371 0 [(6473, 1), (6464, 3)] 0, attempt 6372 0 6372 0 [(6474, 1), (6464, 3)] 0, attempt 6373 0 6373 0 [(6475, 1), (6464, 3)] 0, attempt 6374 0 6374 0 [(6476, 1), (6464, 3)] 0, attempt 6375 0 6375 0 [(6477, 1), (6464, 3)] 0, attempt 6376 0 6376 0 [(6478, 1), (6464, 3)] 0, attempt 6377 0 6377 0 [(6479, 1), (6464, 3)] 0, attempt 6378 0 6378 0 [(6480, 1), (6464, 3)] 0, attempt 6379 0 6379 0 [(6481, 1), (6464, 3)] 0, attempt 6380 0 6380 0 [(6482, 1), (6464, 3)] 0, attempt 6381 0 6381 0 [(6483, 1), (6464, 3)] 0, attempt 6382 0 6382 0 [(6484, 1), (6464, 3)] 0, attempt 6383 0 6383 0 [(6485, 1), (6464, 3)] 0, attempt 6384 0 6384 0 [(6486, 1), (6464, 3)] 0, attempt 6385 0 6385 0 [(6487, 1), (6464, 3)] 0, attempt 6386 0 6386 0 [(6488, 1), (6464, 3)] 0, attempt 6387 0 6387 0 [(6489, 1), (6464, 3)] 0, attempt 6388 0 6388 0 [(6490, 1), (6464, 3)] 0, attempt 6389 0 6389 0 [(6491, 1), (6464, 3)] 0, attempt 6390 0 6390 0 [(6492, 1), (6464, 3)] 0, attempt 6391 0 6391 0 [(6493, 1), (6464, 3)] 0, attempt 6392 0 6392 0 [(6494, 1), (6464, 3)] 0, attempt 6393 0 6393 0 [(6495, 1), (6464, 3)] 0, attempt 6394 0 6394 0 [(6496, 1), (6464, 3)] 0, attempt 6395 0 6395 0 [(6497, 1), (6464, 3)] 0, attempt 6396 0 6396 0 [(6498, 1), (6464, 3)] 0, attempt 6397 0 6397 0 [(6499, 1), (6464, 3)] 0, attempt 6398 0 6398 0 [(6500, 1), (6464, 3)] 0, attempt 6399 0 6399 0 [(6501, 1), (6464, 3)] 0]
def counters008 : List Nat := [6400, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6368
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 6400 0 6400 0 [(6502, 1), (6464, 3)] 0, attempt 6401 0 6401 0 [(6503, 1), (6464, 3)] 0, attempt 6402 0 6402 0 [(6504, 1), (6464, 3)] 0, attempt 6403 0 6403 0 [(6505, 1), (6464, 3)] 0, attempt 6404 0 6404 0 [(6506, 1), (6464, 3)] 0, attempt 6405 0 6405 0 [(6507, 1), (6464, 3)] 0, attempt 6406 0 6406 0 [(6508, 1), (6464, 3)] 0, attempt 6407 0 6407 0 [(6509, 1), (6464, 3)] 0, attempt 6408 0 6408 0 [(6510, 1), (6464, 3)] 0, attempt 6409 0 6409 0 [(6511, 1), (6464, 3)] 0, attempt 6410 0 6410 0 [(6512, 1), (6464, 3)] 0, attempt 6411 0 6411 0 [(6513, 1), (6464, 3)] 0, attempt 6412 0 6412 0 [(6514, 1), (6464, 3)] 0, attempt 6413 0 6413 0 [(6515, 1), (6464, 3)] 0, attempt 6414 0 6414 0 [(6516, 1), (6464, 3)] 0, attempt 6415 0 6415 0 [(6517, 1), (6464, 3)] 0, attempt 6416 0 6416 0 [(6518, 1), (6464, 3)] 0, attempt 6417 0 6417 0 [(6519, 1), (6464, 3)] 0, attempt 6418 0 6418 0 [(6520, 1), (6464, 3)] 0, attempt 6419 0 6419 0 [(6521, 1), (6464, 3)] 0, attempt 6420 0 6420 0 [(6522, 1), (6464, 3)] 0, attempt 6421 0 6421 0 [(6523, 1), (6464, 3)] 0, attempt 6422 0 6422 0 [(6524, 1), (6464, 3)] 0, attempt 6423 0 6423 0 [(6525, 1), (6464, 3)] 0, attempt 6424 0 6424 0 [(6526, 1), (6464, 3)] 0, attempt 6425 0 6425 0 [(6527, 1), (6464, 3)] 0, attempt 6426 0 6426 0 [(6529, 1), (6528, 3)] 0, attempt 6427 0 6427 0 [(6530, 1), (6528, 3)] 0, attempt 6428 0 6428 0 [(6531, 1), (6528, 3)] 0, attempt 6429 0 6429 0 [(6532, 1), (6528, 3)] 0, attempt 6430 0 6430 0 [(6533, 1), (6528, 3)] 0, attempt 6431 0 6431 0 [(6534, 1), (6528, 3)] 0]
def counters009 : List Nat := [6432, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6400
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 6432 0 6432 0 [(6535, 1), (6528, 3)] 0, attempt 6433 0 6433 0 [(6536, 1), (6528, 3)] 0, attempt 6434 0 6434 0 [(6537, 1), (6528, 3)] 0, attempt 6435 0 6435 0 [(6538, 1), (6528, 3)] 0, attempt 6436 0 6436 0 [(6539, 1), (6528, 3)] 0, attempt 6437 0 6437 0 [(6540, 1), (6528, 3)] 0, attempt 6438 0 6438 0 [(6541, 1), (6528, 3)] 0, attempt 6439 0 6439 0 [(6542, 1), (6528, 3)] 0, attempt 6440 0 6440 0 [(6543, 1), (6528, 3)] 0, attempt 6441 0 6441 0 [(6544, 1), (6528, 3)] 0, attempt 6442 0 6442 0 [(6545, 1), (6528, 3)] 0, attempt 6443 0 6443 0 [(6546, 1), (6528, 3)] 0, attempt 6444 0 6444 0 [(6547, 1), (6528, 3)] 0, attempt 6445 0 6445 0 [(6548, 1), (6528, 3)] 0, attempt 6446 0 6446 0 [(6549, 1), (6528, 3)] 0, attempt 6447 0 6447 0 [(6550, 1), (6528, 3)] 0, attempt 6448 0 6448 0 [(6551, 1), (6528, 3)] 0, attempt 6449 0 6449 0 [(6552, 1), (6528, 3)] 0, attempt 6450 0 6450 0 [(6553, 1), (6528, 3)] 0, attempt 6451 0 6451 0 [(6554, 1), (6528, 3)] 0, attempt 6452 0 6452 0 [(6555, 1), (6528, 3)] 0, attempt 6453 0 6453 0 [(6556, 1), (6528, 3)] 0, attempt 6454 0 6454 0 [(6557, 1), (6528, 3)] 0, attempt 6455 0 6455 0 [(6558, 1), (6528, 3)] 0, attempt 6456 0 6456 0 [(6559, 1), (6528, 3)] 0, attempt 6457 0 6457 0 [(6560, 1), (6528, 3)] 0, attempt 6458 0 6458 0 [(6561, 1), (6528, 3)] 0, attempt 6459 0 6459 0 [(6562, 1), (6528, 3)] 0, attempt 6460 0 6460 0 [(6563, 1), (6528, 3)] 0, attempt 6461 0 6461 0 [(6564, 1), (6528, 3)] 0, attempt 6462 0 6462 0 [(6565, 1), (6528, 3)] 0, attempt 6463 0 6463 0 [(6566, 1), (6528, 3)] 0]
def counters010 : List Nat := [6464, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6432
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 6464 0 6464 0 [(6567, 1), (6528, 3)] 0, attempt 6465 0 6465 0 [(6568, 1), (6528, 3)] 0, attempt 6466 0 6466 0 [(6569, 1), (6528, 3)] 0, attempt 6467 0 6467 0 [(6570, 1), (6528, 3)] 0, attempt 6468 0 6468 0 [(6571, 1), (6528, 3)] 0, attempt 6469 0 6469 0 [(6572, 1), (6528, 3)] 0, attempt 6470 0 6470 0 [(6573, 1), (6528, 3)] 0, attempt 6471 0 6471 0 [(6574, 1), (6528, 3)] 0, attempt 6472 0 6472 0 [(6575, 1), (6528, 3)] 0, attempt 6473 0 6473 0 [(6576, 1), (6528, 3)] 0, attempt 6474 0 6474 0 [(6577, 1), (6528, 3)] 0, attempt 6475 0 6475 0 [(6578, 1), (6528, 3)] 0, attempt 6476 0 6476 0 [(6579, 1), (6528, 3)] 0, attempt 6477 0 6477 0 [(6580, 1), (6528, 3)] 0, attempt 6478 0 6478 0 [(6581, 1), (6528, 3)] 0, attempt 6479 0 6479 0 [(6582, 1), (6528, 3)] 0, attempt 6480 0 6480 0 [(6583, 1), (6528, 3)] 0, attempt 6481 0 6481 0 [(6584, 1), (6528, 3)] 0, attempt 6482 0 6482 0 [(6585, 1), (6528, 3)] 0, attempt 6483 0 6483 0 [(6586, 1), (6528, 3)] 0, attempt 6484 0 6484 0 [(6587, 1), (6528, 3)] 0, attempt 6485 0 6485 0 [(6588, 1), (6528, 3)] 0, attempt 6486 0 6486 0 [(6589, 1), (6528, 3)] 0, attempt 6487 0 6487 0 [(6590, 1), (6528, 3)] 0, attempt 6488 0 6488 0 [(6591, 1), (6528, 3)] 0, attempt 6489 0 6489 0 [(6593, 1), (6592, 3)] 0, attempt 6490 0 6490 0 [(6594, 1), (6592, 3)] 0, attempt 6491 0 6491 0 [(6595, 1), (6592, 3)] 0, attempt 6492 0 6492 0 [(6596, 1), (6592, 3)] 0, attempt 6493 0 6493 0 [(6597, 1), (6592, 3)] 0, attempt 6494 0 6494 0 [(6598, 1), (6592, 3)] 0, attempt 6495 0 6495 0 [(6599, 1), (6592, 3)] 0]
def counters011 : List Nat := [6496, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6464
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 6496 0 6496 0 [(6600, 1), (6592, 3)] 0, attempt 6497 0 6497 0 [(6601, 1), (6592, 3)] 0, attempt 6498 0 6498 0 [(6602, 1), (6592, 3)] 0, attempt 6499 0 6499 0 [(6603, 1), (6592, 3)] 0, attempt 6500 0 6500 0 [(6604, 1), (6592, 3)] 0, attempt 6501 0 6501 0 [(6605, 1), (6592, 3)] 0, attempt 6502 0 6502 0 [(6606, 1), (6592, 3)] 0, attempt 6503 0 6503 0 [(6607, 1), (6592, 3)] 0, attempt 6504 0 6504 0 [(6608, 1), (6592, 3)] 0, attempt 6505 0 6505 0 [(6609, 1), (6592, 3)] 0, attempt 6506 0 6506 0 [(6610, 1), (6592, 3)] 0, attempt 6507 0 6507 0 [(6611, 1), (6592, 3)] 0, attempt 6508 0 6508 0 [(6612, 1), (6592, 3)] 0, attempt 6509 0 6509 0 [(6613, 1), (6592, 3)] 0, attempt 6510 0 6510 0 [(6614, 1), (6592, 3)] 0, attempt 6511 0 6511 0 [(6615, 1), (6592, 3)] 0, attempt 6512 0 6512 0 [(6616, 1), (6592, 3)] 0, attempt 6513 0 6513 0 [(6617, 1), (6592, 3)] 0, attempt 6514 0 6514 0 [(6618, 1), (6592, 3)] 0, attempt 6515 0 6515 0 [(6619, 1), (6592, 3)] 0, attempt 6516 0 6516 0 [(6620, 1), (6592, 3)] 0, attempt 6517 0 6517 0 [(6621, 1), (6592, 3)] 0, attempt 6518 0 6518 0 [(6622, 1), (6592, 3)] 0, attempt 6519 0 6519 0 [(6623, 1), (6592, 3)] 0, attempt 6520 0 6520 0 [(6624, 1), (6592, 3)] 0, attempt 6521 0 6521 0 [(6625, 1), (6592, 3)] 0, attempt 6522 0 6522 0 [(6626, 1), (6592, 3)] 0, attempt 6523 0 6523 0 [(6627, 1), (6592, 3)] 0, attempt 6524 0 6524 0 [(6628, 1), (6592, 3)] 0, attempt 6525 0 6525 0 [(6629, 1), (6592, 3)] 0, attempt 6526 0 6526 0 [(6630, 1), (6592, 3)] 0, attempt 6527 0 6527 0 [(6631, 1), (6592, 3)] 0]
def counters012 : List Nat := [6528, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6496
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 6528 0 6528 0 [(6632, 1), (6592, 3)] 0, attempt 6529 0 6529 0 [(6633, 1), (6592, 3)] 0, attempt 6530 0 6530 0 [(6634, 1), (6592, 3)] 0, attempt 6531 0 6531 0 [(6635, 1), (6592, 3)] 0, attempt 6532 0 6532 0 [(6636, 1), (6592, 3)] 0, attempt 6533 0 6533 0 [(6637, 1), (6592, 3)] 0, attempt 6534 0 6534 0 [(6638, 1), (6592, 3)] 0, attempt 6535 0 6535 0 [(6639, 1), (6592, 3)] 0, attempt 6536 0 6536 0 [(6640, 1), (6592, 3)] 0, attempt 6537 0 6537 0 [(6641, 1), (6592, 3)] 0, attempt 6538 0 6538 0 [(6642, 1), (6592, 3)] 0, attempt 6539 0 6539 0 [(6643, 1), (6592, 3)] 0, attempt 6540 0 6540 0 [(6644, 1), (6592, 3)] 0, attempt 6541 0 6541 0 [(6645, 1), (6592, 3)] 0, attempt 6542 0 6542 0 [(6646, 1), (6592, 3)] 0, attempt 6543 0 6543 0 [(6647, 1), (6592, 3)] 0, attempt 6544 0 6544 0 [(6648, 1), (6592, 3)] 0, attempt 6545 0 6545 0 [(6649, 1), (6592, 3)] 0, attempt 6546 0 6546 0 [(6650, 1), (6592, 3)] 0, attempt 6547 0 6547 0 [(6651, 1), (6592, 3)] 0, attempt 6548 0 6548 0 [(6652, 1), (6592, 3)] 0, attempt 6549 0 6549 0 [(6653, 1), (6592, 3)] 0, attempt 6550 0 6550 0 [(6654, 1), (6592, 3)] 0, attempt 6551 0 6551 0 [(6655, 1), (6592, 3)] 0, attempt 6552 0 6552 0 [(6657, 1), (6656, 3)] 0, attempt 6553 0 6553 0 [(6658, 1), (6656, 3)] 0, attempt 6554 0 6554 0 [(6659, 1), (6656, 3)] 0, attempt 6555 0 6555 0 [(6660, 1), (6656, 3)] 0, attempt 6556 0 6556 0 [(6661, 1), (6656, 3)] 0, attempt 6557 0 6557 0 [(6662, 1), (6656, 3)] 0, attempt 6558 0 6558 0 [(6663, 1), (6656, 3)] 0, attempt 6559 0 6559 0 [(6664, 1), (6656, 3)] 0]
def counters013 : List Nat := [6560, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6528
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 6560 0 6560 0 [(6665, 1), (6656, 3)] 0, attempt 6561 0 6561 0 [(6666, 1), (6656, 3)] 0, attempt 6562 0 6562 0 [(6667, 1), (6656, 3)] 0, attempt 6563 0 6563 0 [(6668, 1), (6656, 3)] 0, attempt 6564 0 6564 0 [(6669, 1), (6656, 3)] 0, attempt 6565 0 6565 0 [(6670, 1), (6656, 3)] 0, attempt 6566 0 6566 0 [(6671, 1), (6656, 3)] 0, attempt 6567 0 6567 0 [(6672, 1), (6656, 3)] 0, attempt 6568 0 6568 0 [(6673, 1), (6656, 3)] 0, attempt 6569 0 6569 0 [(6674, 1), (6656, 3)] 0, attempt 6570 0 6570 0 [(6675, 1), (6656, 3)] 0, attempt 6571 0 6571 0 [(6676, 1), (6656, 3)] 0, attempt 6572 0 6572 0 [(6677, 1), (6656, 3)] 0, attempt 6573 0 6573 0 [(6678, 1), (6656, 3)] 0, attempt 6574 0 6574 0 [(6679, 1), (6656, 3)] 0, attempt 6575 0 6575 0 [(6680, 1), (6656, 3)] 0, attempt 6576 0 6576 0 [(6681, 1), (6656, 3)] 0, attempt 6577 0 6577 0 [(6682, 1), (6656, 3)] 0, attempt 6578 0 6578 0 [(6683, 1), (6656, 3)] 0, attempt 6579 0 6579 0 [(6684, 1), (6656, 3)] 0, attempt 6580 0 6580 0 [(6685, 1), (6656, 3)] 0, attempt 6581 0 6581 0 [(6686, 1), (6656, 3)] 0, attempt 6582 0 6582 0 [(6687, 1), (6656, 3)] 0, attempt 6583 0 6583 0 [(6688, 1), (6656, 3)] 0, attempt 6584 0 6584 0 [(6689, 1), (6656, 3)] 0, attempt 6585 0 6585 0 [(6690, 1), (6656, 3)] 0, attempt 6586 0 6586 0 [(6691, 1), (6656, 3)] 0, attempt 6587 0 6587 0 [(6692, 1), (6656, 3)] 0, attempt 6588 0 6588 0 [(6693, 1), (6656, 3)] 0, attempt 6589 0 6589 0 [(6694, 1), (6656, 3)] 0, attempt 6590 0 6590 0 [(6695, 1), (6656, 3)] 0, attempt 6591 0 6591 0 [(6696, 1), (6656, 3)] 0]
def counters014 : List Nat := [6592, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6560
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 6592 0 6592 0 [(6697, 1), (6656, 3)] 0, attempt 6593 0 6593 0 [(6698, 1), (6656, 3)] 0, attempt 6594 0 6594 0 [(6699, 1), (6656, 3)] 0, attempt 6595 0 6595 0 [(6700, 1), (6656, 3)] 0, attempt 6596 0 6596 0 [(6701, 1), (6656, 3)] 0, attempt 6597 0 6597 0 [(6702, 1), (6656, 3)] 0, attempt 6598 0 6598 0 [(6703, 1), (6656, 3)] 0, attempt 6599 0 6599 0 [(6704, 1), (6656, 3)] 0, attempt 6600 0 6600 0 [(6705, 1), (6656, 3)] 0, attempt 6601 0 6601 0 [(6706, 1), (6656, 3)] 0, attempt 6602 0 6602 0 [(6707, 1), (6656, 3)] 0, attempt 6603 0 6603 0 [(6708, 1), (6656, 3)] 0, attempt 6604 0 6604 0 [(6709, 1), (6656, 3)] 0, attempt 6605 0 6605 0 [(6710, 1), (6656, 3)] 0, attempt 6606 0 6606 0 [(6711, 1), (6656, 3)] 0, attempt 6607 0 6607 0 [(6712, 1), (6656, 3)] 0, attempt 6608 0 6608 0 [(6713, 1), (6656, 3)] 0, attempt 6609 0 6609 0 [(6714, 1), (6656, 3)] 0, attempt 6610 0 6610 0 [(6715, 1), (6656, 3)] 0, attempt 6611 0 6611 0 [(6716, 1), (6656, 3)] 0, attempt 6612 0 6612 0 [(6717, 1), (6656, 3)] 0, attempt 6613 0 6613 0 [(6718, 1), (6656, 3)] 0, attempt 6614 0 6614 0 [(6719, 1), (6656, 3)] 0, attempt 6615 0 6615 0 [(6721, 1), (6720, 3)] 0, attempt 6616 0 6616 0 [(6722, 1), (6720, 3)] 0, attempt 6617 0 6617 0 [(6723, 1), (6720, 3)] 0, attempt 6618 0 6618 0 [(6724, 1), (6720, 3)] 0, attempt 6619 0 6619 0 [(6725, 1), (6720, 3)] 0, attempt 6620 0 6620 0 [(6726, 1), (6720, 3)] 0, attempt 6621 0 6621 0 [(6727, 1), (6720, 3)] 0, attempt 6622 0 6622 0 [(6728, 1), (6720, 3)] 0, attempt 6623 0 6623 0 [(6729, 1), (6720, 3)] 0]
def counters015 : List Nat := [6624, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6592
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 6624 0 6624 0 [(6730, 1), (6720, 3)] 0, attempt 6625 0 6625 0 [(6731, 1), (6720, 3)] 0, attempt 6626 0 6626 0 [(6732, 1), (6720, 3)] 0, attempt 6627 0 6627 0 [(6733, 1), (6720, 3)] 0, attempt 6628 0 6628 0 [(6734, 1), (6720, 3)] 0, attempt 6629 0 6629 0 [(6735, 1), (6720, 3)] 0, attempt 6630 0 6630 0 [(6736, 1), (6720, 3)] 0, attempt 6631 0 6631 0 [(6737, 1), (6720, 3)] 0, attempt 6632 0 6632 0 [(6738, 1), (6720, 3)] 0, attempt 6633 0 6633 0 [(6739, 1), (6720, 3)] 0, attempt 6634 0 6634 0 [(6740, 1), (6720, 3)] 0, attempt 6635 0 6635 0 [(6741, 1), (6720, 3)] 0, attempt 6636 0 6636 0 [(6742, 1), (6720, 3)] 0, attempt 6637 0 6637 0 [(6743, 1), (6720, 3)] 0, attempt 6638 0 6638 0 [(6744, 1), (6720, 3)] 0, attempt 6639 0 6639 0 [(6745, 1), (6720, 3)] 0, attempt 6640 0 6640 0 [(6746, 1), (6720, 3)] 0, attempt 6641 0 6641 0 [(6747, 1), (6720, 3)] 0, attempt 6642 0 6642 0 [(6748, 1), (6720, 3)] 0, attempt 6643 0 6643 0 [(6749, 1), (6720, 3)] 0, attempt 6644 0 6644 0 [(6750, 1), (6720, 3)] 0, attempt 6645 0 6645 0 [(6751, 1), (6720, 3)] 0, attempt 6646 0 6646 0 [(6752, 1), (6720, 3)] 0, attempt 6647 0 6647 0 [(6753, 1), (6720, 3)] 0, attempt 6648 0 6648 0 [(6754, 1), (6720, 3)] 0, attempt 6649 0 6649 0 [(6755, 1), (6720, 3)] 0, attempt 6650 0 6650 0 [(6756, 1), (6720, 3)] 0, attempt 6651 0 6651 0 [(6757, 1), (6720, 3)] 0, attempt 6652 0 6652 0 [(6758, 1), (6720, 3)] 0, attempt 6653 0 6653 0 [(6759, 1), (6720, 3)] 0, attempt 6654 0 6654 0 [(6760, 1), (6720, 3)] 0, attempt 6655 0 6655 0 [(6761, 1), (6720, 3)] 0]
def counters016 : List Nat := [6656, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6624
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6656
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6624
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 6624 6656 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 6624) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6592
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 6592 6624 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 6592) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6560
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 6560 6592 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 6560) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6528
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 6528 6560 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 6528) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6496
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 6496 6528 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 6496) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6464
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 6464 6496 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 6464) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6432
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 6432 6464 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 6432) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6400
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 6400 6432 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 6400) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6368
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 6368 6400 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 6368) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6336
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 6336 6368 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 6336) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6304
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 6304 6336 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 6304) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6272
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 6272 6304 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 6272) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6240
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 6240 6272 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 6240) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6208
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 6208 6240 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 6208) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6176
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 6176 6208 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 6176) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 6144
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 6144 6176 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 6144) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr12
