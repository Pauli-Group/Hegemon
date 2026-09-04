import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr15

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr16
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [8192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 8192 0 8192 0 [(8323, 1), (8320, 3)] 0, attempt 8193 0 8193 0 [(8324, 1), (8320, 3)] 0, attempt 8194 0 8194 0 [(8325, 1), (8320, 3)] 0, attempt 8195 0 8195 0 [(8326, 1), (8320, 3)] 0, attempt 8196 0 8196 0 [(8327, 1), (8320, 3)] 0, attempt 8197 0 8197 0 [(8328, 1), (8320, 3)] 0, attempt 8198 0 8198 0 [(8329, 1), (8320, 3)] 0, attempt 8199 0 8199 0 [(8330, 1), (8320, 3)] 0, attempt 8200 0 8200 0 [(8331, 1), (8320, 3)] 0, attempt 8201 0 8201 0 [(8332, 1), (8320, 3)] 0, attempt 8202 0 8202 0 [(8333, 1), (8320, 3)] 0, attempt 8203 0 8203 0 [(8334, 1), (8320, 3)] 0, attempt 8204 0 8204 0 [(8335, 1), (8320, 3)] 0, attempt 8205 0 8205 0 [(8336, 1), (8320, 3)] 0, attempt 8206 0 8206 0 [(8337, 1), (8320, 3)] 0, attempt 8207 0 8207 0 [(8338, 1), (8320, 3)] 0, attempt 8208 0 8208 0 [(8339, 1), (8320, 3)] 0, attempt 8209 0 8209 0 [(8340, 1), (8320, 3)] 0, attempt 8210 0 8210 0 [(8341, 1), (8320, 3)] 0, attempt 8211 0 8211 0 [(8342, 1), (8320, 3)] 0, attempt 8212 0 8212 0 [(8343, 1), (8320, 3)] 0, attempt 8213 0 8213 0 [(8344, 1), (8320, 3)] 0, attempt 8214 0 8214 0 [(8345, 1), (8320, 3)] 0, attempt 8215 0 8215 0 [(8346, 1), (8320, 3)] 0, attempt 8216 0 8216 0 [(8347, 1), (8320, 3)] 0, attempt 8217 0 8217 0 [(8348, 1), (8320, 3)] 0, attempt 8218 0 8218 0 [(8349, 1), (8320, 3)] 0, attempt 8219 0 8219 0 [(8350, 1), (8320, 3)] 0, attempt 8220 0 8220 0 [(8351, 1), (8320, 3)] 0, attempt 8221 0 8221 0 [(8352, 1), (8320, 3)] 0, attempt 8222 0 8222 0 [(8353, 1), (8320, 3)] 0, attempt 8223 0 8223 0 [(8354, 1), (8320, 3)] 0]
def counters001 : List Nat := [8224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8192
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 8224 0 8224 0 [(8355, 1), (8320, 3)] 0, attempt 8225 0 8225 0 [(8356, 1), (8320, 3)] 0, attempt 8226 0 8226 0 [(8357, 1), (8320, 3)] 0, attempt 8227 0 8227 0 [(8358, 1), (8320, 3)] 0, attempt 8228 0 8228 0 [(8359, 1), (8320, 3)] 0, attempt 8229 0 8229 0 [(8360, 1), (8320, 3)] 0, attempt 8230 0 8230 0 [(8361, 1), (8320, 3)] 0, attempt 8231 0 8231 0 [(8362, 1), (8320, 3)] 0, attempt 8232 0 8232 0 [(8363, 1), (8320, 3)] 0, attempt 8233 0 8233 0 [(8364, 1), (8320, 3)] 0, attempt 8234 0 8234 0 [(8365, 1), (8320, 3)] 0, attempt 8235 0 8235 0 [(8366, 1), (8320, 3)] 0, attempt 8236 0 8236 0 [(8367, 1), (8320, 3)] 0, attempt 8237 0 8237 0 [(8368, 1), (8320, 3)] 0, attempt 8238 0 8238 0 [(8369, 1), (8320, 3)] 0, attempt 8239 0 8239 0 [(8370, 1), (8320, 3)] 0, attempt 8240 0 8240 0 [(8371, 1), (8320, 3)] 0, attempt 8241 0 8241 0 [(8372, 1), (8320, 3)] 0, attempt 8242 0 8242 0 [(8373, 1), (8320, 3)] 0, attempt 8243 0 8243 0 [(8374, 1), (8320, 3)] 0, attempt 8244 0 8244 0 [(8375, 1), (8320, 3)] 0, attempt 8245 0 8245 0 [(8376, 1), (8320, 3)] 0, attempt 8246 0 8246 0 [(8377, 1), (8320, 3)] 0, attempt 8247 0 8247 0 [(8378, 1), (8320, 3)] 0, attempt 8248 0 8248 0 [(8379, 1), (8320, 3)] 0, attempt 8249 0 8249 0 [(8380, 1), (8320, 3)] 0, attempt 8250 0 8250 0 [(8381, 1), (8320, 3)] 0, attempt 8251 0 8251 0 [(8382, 1), (8320, 3)] 0, attempt 8252 0 8252 0 [(8383, 1), (8320, 3)] 0, attempt 8253 0 8253 0 [(8385, 1), (8384, 3)] 0, attempt 8254 0 8254 0 [(8386, 1), (8384, 3)] 0, attempt 8255 0 8255 0 [(8387, 1), (8384, 3)] 0]
def counters002 : List Nat := [8256, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8224
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 8256 0 8256 0 [(8388, 1), (8384, 3)] 0, attempt 8257 0 8257 0 [(8389, 1), (8384, 3)] 0, attempt 8258 0 8258 0 [(8390, 1), (8384, 3)] 0, attempt 8259 0 8259 0 [(8391, 1), (8384, 3)] 0, attempt 8260 0 8260 0 [(8392, 1), (8384, 3)] 0, attempt 8261 0 8261 0 [(8393, 1), (8384, 3)] 0, attempt 8262 0 8262 0 [(8394, 1), (8384, 3)] 0, attempt 8263 0 8263 0 [(8395, 1), (8384, 3)] 0, attempt 8264 0 8264 0 [(8396, 1), (8384, 3)] 0, attempt 8265 0 8265 0 [(8397, 1), (8384, 3)] 0, attempt 8266 0 8266 0 [(8398, 1), (8384, 3)] 0, attempt 8267 0 8267 0 [(8399, 1), (8384, 3)] 0, attempt 8268 0 8268 0 [(8400, 1), (8384, 3)] 0, attempt 8269 0 8269 0 [(8401, 1), (8384, 3)] 0, attempt 8270 0 8270 0 [(8402, 1), (8384, 3)] 0, attempt 8271 0 8271 0 [(8403, 1), (8384, 3)] 0, attempt 8272 0 8272 0 [(8404, 1), (8384, 3)] 0, attempt 8273 0 8273 0 [(8405, 1), (8384, 3)] 0, attempt 8274 0 8274 0 [(8406, 1), (8384, 3)] 0, attempt 8275 0 8275 0 [(8407, 1), (8384, 3)] 0, attempt 8276 0 8276 0 [(8408, 1), (8384, 3)] 0, attempt 8277 0 8277 0 [(8409, 1), (8384, 3)] 0, attempt 8278 0 8278 0 [(8410, 1), (8384, 3)] 0, attempt 8279 0 8279 0 [(8411, 1), (8384, 3)] 0, attempt 8280 0 8280 0 [(8412, 1), (8384, 3)] 0, attempt 8281 0 8281 0 [(8413, 1), (8384, 3)] 0, attempt 8282 0 8282 0 [(8414, 1), (8384, 3)] 0, attempt 8283 0 8283 0 [(8415, 1), (8384, 3)] 0, attempt 8284 0 8284 0 [(8416, 1), (8384, 3)] 0, attempt 8285 0 8285 0 [(8417, 1), (8384, 3)] 0, attempt 8286 0 8286 0 [(8418, 1), (8384, 3)] 0, attempt 8287 0 8287 0 [(8419, 1), (8384, 3)] 0]
def counters003 : List Nat := [8288, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8256
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 8288 0 8288 0 [(8420, 1), (8384, 3)] 0, attempt 8289 0 8289 0 [(8421, 1), (8384, 3)] 0, attempt 8290 0 8290 0 [(8422, 1), (8384, 3)] 0, attempt 8291 0 8291 0 [(8423, 1), (8384, 3)] 0, attempt 8292 0 8292 0 [(8424, 1), (8384, 3)] 0, attempt 8293 0 8293 0 [(8425, 1), (8384, 3)] 0, attempt 8294 0 8294 0 [(8426, 1), (8384, 3)] 0, attempt 8295 0 8295 0 [(8427, 1), (8384, 3)] 0, attempt 8296 0 8296 0 [(8428, 1), (8384, 3)] 0, attempt 8297 0 8297 0 [(8429, 1), (8384, 3)] 0, attempt 8298 0 8298 0 [(8430, 1), (8384, 3)] 0, attempt 8299 0 8299 0 [(8431, 1), (8384, 3)] 0, attempt 8300 0 8300 0 [(8432, 1), (8384, 3)] 0, attempt 8301 0 8301 0 [(8433, 1), (8384, 3)] 0, attempt 8302 0 8302 0 [(8434, 1), (8384, 3)] 0, attempt 8303 0 8303 0 [(8435, 1), (8384, 3)] 0, attempt 8304 0 8304 0 [(8436, 1), (8384, 3)] 0, attempt 8305 0 8305 0 [(8437, 1), (8384, 3)] 0, attempt 8306 0 8306 0 [(8438, 1), (8384, 3)] 0, attempt 8307 0 8307 0 [(8439, 1), (8384, 3)] 0, attempt 8308 0 8308 0 [(8440, 1), (8384, 3)] 0, attempt 8309 0 8309 0 [(8441, 1), (8384, 3)] 0, attempt 8310 0 8310 0 [(8442, 1), (8384, 3)] 0, attempt 8311 0 8311 0 [(8443, 1), (8384, 3)] 0, attempt 8312 0 8312 0 [(8444, 1), (8384, 3)] 0, attempt 8313 0 8313 0 [(8445, 1), (8384, 3)] 0, attempt 8314 0 8314 0 [(8446, 1), (8384, 3)] 0, attempt 8315 0 8315 0 [(8447, 1), (8384, 3)] 0, attempt 8316 0 8316 0 [(8449, 1), (8448, 3)] 0, attempt 8317 0 8317 0 [(8450, 1), (8448, 3)] 0, attempt 8318 0 8318 0 [(8451, 1), (8448, 3)] 0, attempt 8319 0 8319 0 [(8452, 1), (8448, 3)] 0]
def counters004 : List Nat := [8320, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8288
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 8320 0 8320 0 [(8453, 1), (8448, 3)] 0, attempt 8321 0 8321 0 [(8454, 1), (8448, 3)] 0, attempt 8322 0 8322 0 [(8455, 1), (8448, 3)] 0, attempt 8323 0 8323 0 [(8456, 1), (8448, 3)] 0, attempt 8324 0 8324 0 [(8457, 1), (8448, 3)] 0, attempt 8325 0 8325 0 [(8458, 1), (8448, 3)] 0, attempt 8326 0 8326 0 [(8459, 1), (8448, 3)] 0, attempt 8327 0 8327 0 [(8460, 1), (8448, 3)] 0, attempt 8328 0 8328 0 [(8461, 1), (8448, 3)] 0, attempt 8329 0 8329 0 [(8462, 1), (8448, 3)] 0, attempt 8330 0 8330 0 [(8463, 1), (8448, 3)] 0, attempt 8331 0 8331 0 [(8464, 1), (8448, 3)] 0, attempt 8332 0 8332 0 [(8465, 1), (8448, 3)] 0, attempt 8333 0 8333 0 [(8466, 1), (8448, 3)] 0, attempt 8334 0 8334 0 [(8467, 1), (8448, 3)] 0, attempt 8335 0 8335 0 [(8468, 1), (8448, 3)] 0, attempt 8336 0 8336 0 [(8469, 1), (8448, 3)] 0, attempt 8337 0 8337 0 [(8470, 1), (8448, 3)] 0, attempt 8338 0 8338 0 [(8471, 1), (8448, 3)] 0, attempt 8339 0 8339 0 [(8472, 1), (8448, 3)] 0, attempt 8340 0 8340 0 [(8473, 1), (8448, 3)] 0, attempt 8341 0 8341 0 [(8474, 1), (8448, 3)] 0, attempt 8342 0 8342 0 [(8475, 1), (8448, 3)] 0, attempt 8343 0 8343 0 [(8476, 1), (8448, 3)] 0, attempt 8344 0 8344 0 [(8477, 1), (8448, 3)] 0, attempt 8345 0 8345 0 [(8478, 1), (8448, 3)] 0, attempt 8346 0 8346 0 [(8479, 1), (8448, 3)] 0, attempt 8347 0 8347 0 [(8480, 1), (8448, 3)] 0, attempt 8348 0 8348 0 [(8481, 1), (8448, 3)] 0, attempt 8349 0 8349 0 [(8482, 1), (8448, 3)] 0, attempt 8350 0 8350 0 [(8483, 1), (8448, 3)] 0, attempt 8351 0 8351 0 [(8484, 1), (8448, 3)] 0]
def counters005 : List Nat := [8352, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8320
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 8352 0 8352 0 [(8485, 1), (8448, 3)] 0, attempt 8353 0 8353 0 [(8486, 1), (8448, 3)] 0, attempt 8354 0 8354 0 [(8487, 1), (8448, 3)] 0, attempt 8355 0 8355 0 [(8488, 1), (8448, 3)] 0, attempt 8356 0 8356 0 [(8489, 1), (8448, 3)] 0, attempt 8357 0 8357 0 [(8490, 1), (8448, 3)] 0, attempt 8358 0 8358 0 [(8491, 1), (8448, 3)] 0, attempt 8359 0 8359 0 [(8492, 1), (8448, 3)] 0, attempt 8360 0 8360 0 [(8493, 1), (8448, 3)] 0, attempt 8361 0 8361 0 [(8494, 1), (8448, 3)] 0, attempt 8362 0 8362 0 [(8495, 1), (8448, 3)] 0, attempt 8363 0 8363 0 [(8496, 1), (8448, 3)] 0, attempt 8364 0 8364 0 [(8497, 1), (8448, 3)] 0, attempt 8365 0 8365 0 [(8498, 1), (8448, 3)] 0, attempt 8366 0 8366 0 [(8499, 1), (8448, 3)] 0, attempt 8367 0 8367 0 [(8500, 1), (8448, 3)] 0, attempt 8368 0 8368 0 [(8501, 1), (8448, 3)] 0, attempt 8369 0 8369 0 [(8502, 1), (8448, 3)] 0, attempt 8370 0 8370 0 [(8503, 1), (8448, 3)] 0, attempt 8371 0 8371 0 [(8504, 1), (8448, 3)] 0, attempt 8372 0 8372 0 [(8505, 1), (8448, 3)] 0, attempt 8373 0 8373 0 [(8506, 1), (8448, 3)] 0, attempt 8374 0 8374 0 [(8507, 1), (8448, 3)] 0, attempt 8375 0 8375 0 [(8508, 1), (8448, 3)] 0, attempt 8376 0 8376 0 [(8509, 1), (8448, 3)] 0, attempt 8377 0 8377 0 [(8510, 1), (8448, 3)] 0, attempt 8378 0 8378 0 [(8511, 1), (8448, 3)] 0, attempt 8379 0 8379 0 [(8513, 1), (8512, 3)] 0, attempt 8380 0 8380 0 [(8514, 1), (8512, 3)] 0, attempt 8381 0 8381 0 [(8515, 1), (8512, 3)] 0, attempt 8382 0 8382 0 [(8516, 1), (8512, 3)] 0, attempt 8383 0 8383 0 [(8517, 1), (8512, 3)] 0]
def counters006 : List Nat := [8384, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8352
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 8384 0 8384 0 [(8518, 1), (8512, 3)] 0, attempt 8385 0 8385 0 [(8519, 1), (8512, 3)] 0, attempt 8386 0 8386 0 [(8520, 1), (8512, 3)] 0, attempt 8387 0 8387 0 [(8521, 1), (8512, 3)] 0, attempt 8388 0 8388 0 [(8522, 1), (8512, 3)] 0, attempt 8389 0 8389 0 [(8523, 1), (8512, 3)] 0, attempt 8390 0 8390 0 [(8524, 1), (8512, 3)] 0, attempt 8391 0 8391 0 [(8525, 1), (8512, 3)] 0, attempt 8392 0 8392 0 [(8526, 1), (8512, 3)] 0, attempt 8393 0 8393 0 [(8527, 1), (8512, 3)] 0, attempt 8394 0 8394 0 [(8528, 1), (8512, 3)] 0, attempt 8395 0 8395 0 [(8529, 1), (8512, 3)] 0, attempt 8396 0 8396 0 [(8530, 1), (8512, 3)] 0, attempt 8397 0 8397 0 [(8531, 1), (8512, 3)] 0, attempt 8398 0 8398 0 [(8532, 1), (8512, 3)] 0, attempt 8399 0 8399 0 [(8533, 1), (8512, 3)] 0, attempt 8400 0 8400 0 [(8534, 1), (8512, 3)] 0, attempt 8401 0 8401 0 [(8535, 1), (8512, 3)] 0, attempt 8402 0 8402 0 [(8536, 1), (8512, 3)] 0, attempt 8403 0 8403 0 [(8537, 1), (8512, 3)] 0, attempt 8404 0 8404 0 [(8538, 1), (8512, 3)] 0, attempt 8405 0 8405 0 [(8539, 1), (8512, 3)] 0, attempt 8406 0 8406 0 [(8540, 1), (8512, 3)] 0, attempt 8407 0 8407 0 [(8541, 1), (8512, 3)] 0, attempt 8408 0 8408 0 [(8542, 1), (8512, 3)] 0, attempt 8409 0 8409 0 [(8543, 1), (8512, 3)] 0, attempt 8410 0 8410 0 [(8544, 1), (8512, 3)] 0, attempt 8411 0 8411 0 [(8545, 1), (8512, 3)] 0, attempt 8412 0 8412 0 [(8546, 1), (8512, 3)] 0, attempt 8413 0 8413 0 [(8547, 1), (8512, 3)] 0, attempt 8414 0 8414 0 [(8548, 1), (8512, 3)] 0, attempt 8415 0 8415 0 [(8549, 1), (8512, 3)] 0]
def counters007 : List Nat := [8416, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8384
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 8416 0 8416 0 [(8550, 1), (8512, 3)] 0, attempt 8417 0 8417 0 [(8551, 1), (8512, 3)] 0, attempt 8418 0 8418 0 [(8552, 1), (8512, 3)] 0, attempt 8419 0 8419 0 [(8553, 1), (8512, 3)] 0, attempt 8420 0 8420 0 [(8554, 1), (8512, 3)] 0, attempt 8421 0 8421 0 [(8555, 1), (8512, 3)] 0, attempt 8422 0 8422 0 [(8556, 1), (8512, 3)] 0, attempt 8423 0 8423 0 [(8557, 1), (8512, 3)] 0, attempt 8424 0 8424 0 [(8558, 1), (8512, 3)] 0, attempt 8425 0 8425 0 [(8559, 1), (8512, 3)] 0, attempt 8426 0 8426 0 [(8560, 1), (8512, 3)] 0, attempt 8427 0 8427 0 [(8561, 1), (8512, 3)] 0, attempt 8428 0 8428 0 [(8562, 1), (8512, 3)] 0, attempt 8429 0 8429 0 [(8563, 1), (8512, 3)] 0, attempt 8430 0 8430 0 [(8564, 1), (8512, 3)] 0, attempt 8431 0 8431 0 [(8565, 1), (8512, 3)] 0, attempt 8432 0 8432 0 [(8566, 1), (8512, 3)] 0, attempt 8433 0 8433 0 [(8567, 1), (8512, 3)] 0, attempt 8434 0 8434 0 [(8568, 1), (8512, 3)] 0, attempt 8435 0 8435 0 [(8569, 1), (8512, 3)] 0, attempt 8436 0 8436 0 [(8570, 1), (8512, 3)] 0, attempt 8437 0 8437 0 [(8571, 1), (8512, 3)] 0, attempt 8438 0 8438 0 [(8572, 1), (8512, 3)] 0, attempt 8439 0 8439 0 [(8573, 1), (8512, 3)] 0, attempt 8440 0 8440 0 [(8574, 1), (8512, 3)] 0, attempt 8441 0 8441 0 [(8575, 1), (8512, 3)] 0, attempt 8442 0 8442 0 [(8577, 1), (8576, 3)] 0, attempt 8443 0 8443 0 [(8578, 1), (8576, 3)] 0, attempt 8444 0 8444 0 [(8579, 1), (8576, 3)] 0, attempt 8445 0 8445 0 [(8580, 1), (8576, 3)] 0, attempt 8446 0 8446 0 [(8581, 1), (8576, 3)] 0, attempt 8447 0 8447 0 [(8582, 1), (8576, 3)] 0]
def counters008 : List Nat := [8448, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8416
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 8448 0 8448 0 [(8583, 1), (8576, 3)] 0, attempt 8449 0 8449 0 [(8584, 1), (8576, 3)] 0, attempt 8450 0 8450 0 [(8585, 1), (8576, 3)] 0, attempt 8451 0 8451 0 [(8586, 1), (8576, 3)] 0, attempt 8452 0 8452 0 [(8587, 1), (8576, 3)] 0, attempt 8453 0 8453 0 [(8588, 1), (8576, 3)] 0, attempt 8454 0 8454 0 [(8589, 1), (8576, 3)] 0, attempt 8455 0 8455 0 [(8590, 1), (8576, 3)] 0, attempt 8456 0 8456 0 [(8591, 1), (8576, 3)] 0, attempt 8457 0 8457 0 [(8592, 1), (8576, 3)] 0, attempt 8458 0 8458 0 [(8593, 1), (8576, 3)] 0, attempt 8459 0 8459 0 [(8594, 1), (8576, 3)] 0, attempt 8460 0 8460 0 [(8595, 1), (8576, 3)] 0, attempt 8461 0 8461 0 [(8596, 1), (8576, 3)] 0, attempt 8462 0 8462 0 [(8597, 1), (8576, 3)] 0, attempt 8463 0 8463 0 [(8598, 1), (8576, 3)] 0, attempt 8464 0 8464 0 [(8599, 1), (8576, 3)] 0, attempt 8465 0 8465 0 [(8600, 1), (8576, 3)] 0, attempt 8466 0 8466 0 [(8601, 1), (8576, 3)] 0, attempt 8467 0 8467 0 [(8602, 1), (8576, 3)] 0, attempt 8468 0 8468 0 [(8603, 1), (8576, 3)] 0, attempt 8469 0 8469 0 [(8604, 1), (8576, 3)] 0, attempt 8470 0 8470 0 [(8605, 1), (8576, 3)] 0, attempt 8471 0 8471 0 [(8606, 1), (8576, 3)] 0, attempt 8472 0 8472 0 [(8607, 1), (8576, 3)] 0, attempt 8473 0 8473 0 [(8608, 1), (8576, 3)] 0, attempt 8474 0 8474 0 [(8609, 1), (8576, 3)] 0, attempt 8475 0 8475 0 [(8610, 1), (8576, 3)] 0, attempt 8476 0 8476 0 [(8611, 1), (8576, 3)] 0, attempt 8477 0 8477 0 [(8612, 1), (8576, 3)] 0, attempt 8478 0 8478 0 [(8613, 1), (8576, 3)] 0, attempt 8479 0 8479 0 [(8614, 1), (8576, 3)] 0]
def counters009 : List Nat := [8480, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8448
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 8480 0 8480 0 [(8615, 1), (8576, 3)] 0, attempt 8481 0 8481 0 [(8616, 1), (8576, 3)] 0, attempt 8482 0 8482 0 [(8617, 1), (8576, 3)] 0, attempt 8483 0 8483 0 [(8618, 1), (8576, 3)] 0, attempt 8484 0 8484 0 [(8619, 1), (8576, 3)] 0, attempt 8485 0 8485 0 [(8620, 1), (8576, 3)] 0, attempt 8486 0 8486 0 [(8621, 1), (8576, 3)] 0, attempt 8487 0 8487 0 [(8622, 1), (8576, 3)] 0, attempt 8488 0 8488 0 [(8623, 1), (8576, 3)] 0, attempt 8489 0 8489 0 [(8624, 1), (8576, 3)] 0, attempt 8490 0 8490 0 [(8625, 1), (8576, 3)] 0, attempt 8491 0 8491 0 [(8626, 1), (8576, 3)] 0, attempt 8492 0 8492 0 [(8627, 1), (8576, 3)] 0, attempt 8493 0 8493 0 [(8628, 1), (8576, 3)] 0, attempt 8494 0 8494 0 [(8629, 1), (8576, 3)] 0, attempt 8495 0 8495 0 [(8630, 1), (8576, 3)] 0, attempt 8496 0 8496 0 [(8631, 1), (8576, 3)] 0, attempt 8497 0 8497 0 [(8632, 1), (8576, 3)] 0, attempt 8498 0 8498 0 [(8633, 1), (8576, 3)] 0, attempt 8499 0 8499 0 [(8634, 1), (8576, 3)] 0, attempt 8500 0 8500 0 [(8635, 1), (8576, 3)] 0, attempt 8501 0 8501 0 [(8636, 1), (8576, 3)] 0, attempt 8502 0 8502 0 [(8637, 1), (8576, 3)] 0, attempt 8503 0 8503 0 [(8638, 1), (8576, 3)] 0, attempt 8504 0 8504 0 [(8639, 1), (8576, 3)] 0, attempt 8505 0 8505 0 [(8641, 1), (8640, 3)] 0, attempt 8506 0 8506 0 [(8642, 1), (8640, 3)] 0, attempt 8507 0 8507 0 [(8643, 1), (8640, 3)] 0, attempt 8508 0 8508 0 [(8644, 1), (8640, 3)] 0, attempt 8509 0 8509 0 [(8645, 1), (8640, 3)] 0, attempt 8510 0 8510 0 [(8646, 1), (8640, 3)] 0, attempt 8511 0 8511 0 [(8647, 1), (8640, 3)] 0]
def counters010 : List Nat := [8512, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8480
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 8512 0 8512 0 [(8648, 1), (8640, 3)] 0, attempt 8513 0 8513 0 [(8649, 1), (8640, 3)] 0, attempt 8514 0 8514 0 [(8650, 1), (8640, 3)] 0, attempt 8515 0 8515 0 [(8651, 1), (8640, 3)] 0, attempt 8516 0 8516 0 [(8652, 1), (8640, 3)] 0, attempt 8517 0 8517 0 [(8653, 1), (8640, 3)] 0, attempt 8518 0 8518 0 [(8654, 1), (8640, 3)] 0, attempt 8519 0 8519 0 [(8655, 1), (8640, 3)] 0, attempt 8520 0 8520 0 [(8656, 1), (8640, 3)] 0, attempt 8521 0 8521 0 [(8657, 1), (8640, 3)] 0, attempt 8522 0 8522 0 [(8658, 1), (8640, 3)] 0, attempt 8523 0 8523 0 [(8659, 1), (8640, 3)] 0, attempt 8524 0 8524 0 [(8660, 1), (8640, 3)] 0, attempt 8525 0 8525 0 [(8661, 1), (8640, 3)] 0, attempt 8526 0 8526 0 [(8662, 1), (8640, 3)] 0, attempt 8527 0 8527 0 [(8663, 1), (8640, 3)] 0, attempt 8528 0 8528 0 [(8664, 1), (8640, 3)] 0, attempt 8529 0 8529 0 [(8665, 1), (8640, 3)] 0, attempt 8530 0 8530 0 [(8666, 1), (8640, 3)] 0, attempt 8531 0 8531 0 [(8667, 1), (8640, 3)] 0, attempt 8532 0 8532 0 [(8668, 1), (8640, 3)] 0, attempt 8533 0 8533 0 [(8669, 1), (8640, 3)] 0, attempt 8534 0 8534 0 [(8670, 1), (8640, 3)] 0, attempt 8535 0 8535 0 [(8671, 1), (8640, 3)] 0, attempt 8536 0 8536 0 [(8672, 1), (8640, 3)] 0, attempt 8537 0 8537 0 [(8673, 1), (8640, 3)] 0, attempt 8538 0 8538 0 [(8674, 1), (8640, 3)] 0, attempt 8539 0 8539 0 [(8675, 1), (8640, 3)] 0, attempt 8540 0 8540 0 [(8676, 1), (8640, 3)] 0, attempt 8541 0 8541 0 [(8677, 1), (8640, 3)] 0, attempt 8542 0 8542 0 [(8678, 1), (8640, 3)] 0, attempt 8543 0 8543 0 [(8679, 1), (8640, 3)] 0]
def counters011 : List Nat := [8544, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8512
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 8544 0 8544 0 [(8680, 1), (8640, 3)] 0, attempt 8545 0 8545 0 [(8681, 1), (8640, 3)] 0, attempt 8546 0 8546 0 [(8682, 1), (8640, 3)] 0, attempt 8547 0 8547 0 [(8683, 1), (8640, 3)] 0, attempt 8548 0 8548 0 [(8684, 1), (8640, 3)] 0, attempt 8549 0 8549 0 [(8685, 1), (8640, 3)] 0, attempt 8550 0 8550 0 [(8686, 1), (8640, 3)] 0, attempt 8551 0 8551 0 [(8687, 1), (8640, 3)] 0, attempt 8552 0 8552 0 [(8688, 1), (8640, 3)] 0, attempt 8553 0 8553 0 [(8689, 1), (8640, 3)] 0, attempt 8554 0 8554 0 [(8690, 1), (8640, 3)] 0, attempt 8555 0 8555 0 [(8691, 1), (8640, 3)] 0, attempt 8556 0 8556 0 [(8692, 1), (8640, 3)] 0, attempt 8557 0 8557 0 [(8693, 1), (8640, 3)] 0, attempt 8558 0 8558 0 [(8694, 1), (8640, 3)] 0, attempt 8559 0 8559 0 [(8695, 1), (8640, 3)] 0, attempt 8560 0 8560 0 [(8696, 1), (8640, 3)] 0, attempt 8561 0 8561 0 [(8697, 1), (8640, 3)] 0, attempt 8562 0 8562 0 [(8698, 1), (8640, 3)] 0, attempt 8563 0 8563 0 [(8699, 1), (8640, 3)] 0, attempt 8564 0 8564 0 [(8700, 1), (8640, 3)] 0, attempt 8565 0 8565 0 [(8701, 1), (8640, 3)] 0, attempt 8566 0 8566 0 [(8702, 1), (8640, 3)] 0, attempt 8567 0 8567 0 [(8703, 1), (8640, 3)] 0, attempt 8568 0 8568 0 [(8705, 1), (8704, 3)] 0, attempt 8569 0 8569 0 [(8706, 1), (8704, 3)] 0, attempt 8570 0 8570 0 [(8707, 1), (8704, 3)] 0, attempt 8571 0 8571 0 [(8708, 1), (8704, 3)] 0, attempt 8572 0 8572 0 [(8709, 1), (8704, 3)] 0, attempt 8573 0 8573 0 [(8710, 1), (8704, 3)] 0, attempt 8574 0 8574 0 [(8711, 1), (8704, 3)] 0, attempt 8575 0 8575 0 [(8712, 1), (8704, 3)] 0]
def counters012 : List Nat := [8576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8544
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 8576 0 8576 0 [(8713, 1), (8704, 3)] 0, attempt 8577 0 8577 0 [(8714, 1), (8704, 3)] 0, attempt 8578 0 8578 0 [(8715, 1), (8704, 3)] 0, attempt 8579 0 8579 0 [(8716, 1), (8704, 3)] 0, attempt 8580 0 8580 0 [(8717, 1), (8704, 3)] 0, attempt 8581 0 8581 0 [(8718, 1), (8704, 3)] 0, attempt 8582 0 8582 0 [(8719, 1), (8704, 3)] 0, attempt 8583 0 8583 0 [(8720, 1), (8704, 3)] 0, attempt 8584 0 8584 0 [(8721, 1), (8704, 3)] 0, attempt 8585 0 8585 0 [(8722, 1), (8704, 3)] 0, attempt 8586 0 8586 0 [(8723, 1), (8704, 3)] 0, attempt 8587 0 8587 0 [(8724, 1), (8704, 3)] 0, attempt 8588 0 8588 0 [(8725, 1), (8704, 3)] 0, attempt 8589 0 8589 0 [(8726, 1), (8704, 3)] 0, attempt 8590 0 8590 0 [(8727, 1), (8704, 3)] 0, attempt 8591 0 8591 0 [(8728, 1), (8704, 3)] 0, attempt 8592 0 8592 0 [(8729, 1), (8704, 3)] 0, attempt 8593 0 8593 0 [(8730, 1), (8704, 3)] 0, attempt 8594 0 8594 0 [(8731, 1), (8704, 3)] 0, attempt 8595 0 8595 0 [(8732, 1), (8704, 3)] 0, attempt 8596 0 8596 0 [(8733, 1), (8704, 3)] 0, attempt 8597 0 8597 0 [(8734, 1), (8704, 3)] 0, attempt 8598 0 8598 0 [(8735, 1), (8704, 3)] 0, attempt 8599 0 8599 0 [(8736, 1), (8704, 3)] 0, attempt 8600 0 8600 0 [(8737, 1), (8704, 3)] 0, attempt 8601 0 8601 0 [(8738, 1), (8704, 3)] 0, attempt 8602 0 8602 0 [(8739, 1), (8704, 3)] 0, attempt 8603 0 8603 0 [(8740, 1), (8704, 3)] 0, attempt 8604 0 8604 0 [(8741, 1), (8704, 3)] 0, attempt 8605 0 8605 0 [(8742, 1), (8704, 3)] 0, attempt 8606 0 8606 0 [(8743, 1), (8704, 3)] 0, attempt 8607 0 8607 0 [(8744, 1), (8704, 3)] 0]
def counters013 : List Nat := [8608, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8576
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 8608 0 8608 0 [(8745, 1), (8704, 3)] 0, attempt 8609 0 8609 0 [(8746, 1), (8704, 3)] 0, attempt 8610 0 8610 0 [(8747, 1), (8704, 3)] 0, attempt 8611 0 8611 0 [(8748, 1), (8704, 3)] 0, attempt 8612 0 8612 0 [(8749, 1), (8704, 3)] 0, attempt 8613 0 8613 0 [(8750, 1), (8704, 3)] 0, attempt 8614 0 8614 0 [(8751, 1), (8704, 3)] 0, attempt 8615 0 8615 0 [(8752, 1), (8704, 3)] 0, attempt 8616 0 8616 0 [(8753, 1), (8704, 3)] 0, attempt 8617 0 8617 0 [(8754, 1), (8704, 3)] 0, attempt 8618 0 8618 0 [(8755, 1), (8704, 3)] 0, attempt 8619 0 8619 0 [(8756, 1), (8704, 3)] 0, attempt 8620 0 8620 0 [(8757, 1), (8704, 3)] 0, attempt 8621 0 8621 0 [(8758, 1), (8704, 3)] 0, attempt 8622 0 8622 0 [(8759, 1), (8704, 3)] 0, attempt 8623 0 8623 0 [(8760, 1), (8704, 3)] 0, attempt 8624 0 8624 0 [(8761, 1), (8704, 3)] 0, attempt 8625 0 8625 0 [(8762, 1), (8704, 3)] 0, attempt 8626 0 8626 0 [(8763, 1), (8704, 3)] 0, attempt 8627 0 8627 0 [(8764, 1), (8704, 3)] 0, attempt 8628 0 8628 0 [(8765, 1), (8704, 3)] 0, attempt 8629 0 8629 0 [(8766, 1), (8704, 3)] 0, attempt 8630 0 8630 0 [(8767, 1), (8704, 3)] 0, attempt 8631 0 8631 0 [(8769, 1), (8768, 3)] 0, attempt 8632 0 8632 0 [(8770, 1), (8768, 3)] 0, attempt 8633 0 8633 0 [(8771, 1), (8768, 3)] 0, attempt 8634 0 8634 0 [(8772, 1), (8768, 3)] 0, attempt 8635 0 8635 0 [(8773, 1), (8768, 3)] 0, attempt 8636 0 8636 0 [(8774, 1), (8768, 3)] 0, attempt 8637 0 8637 0 [(8775, 1), (8768, 3)] 0, attempt 8638 0 8638 0 [(8776, 1), (8768, 3)] 0, attempt 8639 0 8639 0 [(8777, 1), (8768, 3)] 0]
def counters014 : List Nat := [8640, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8608
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 8640 0 8640 0 [(8778, 1), (8768, 3)] 0, attempt 8641 0 8641 0 [(8779, 1), (8768, 3)] 0, attempt 8642 0 8642 0 [(8780, 1), (8768, 3)] 0, attempt 8643 0 8643 0 [(8781, 1), (8768, 3)] 0, attempt 8644 0 8644 0 [(8782, 1), (8768, 3)] 0, attempt 8645 0 8645 0 [(8783, 1), (8768, 3)] 0, attempt 8646 0 8646 0 [(8784, 1), (8768, 3)] 0, attempt 8647 0 8647 0 [(8785, 1), (8768, 3)] 0, attempt 8648 0 8648 0 [(8786, 1), (8768, 3)] 0, attempt 8649 0 8649 0 [(8787, 1), (8768, 3)] 0, attempt 8650 0 8650 0 [(8788, 1), (8768, 3)] 0, attempt 8651 0 8651 0 [(8789, 1), (8768, 3)] 0, attempt 8652 0 8652 0 [(8790, 1), (8768, 3)] 0, attempt 8653 0 8653 0 [(8791, 1), (8768, 3)] 0, attempt 8654 0 8654 0 [(8792, 1), (8768, 3)] 0, attempt 8655 0 8655 0 [(8793, 1), (8768, 3)] 0, attempt 8656 0 8656 0 [(8794, 1), (8768, 3)] 0, attempt 8657 0 8657 0 [(8795, 1), (8768, 3)] 0, attempt 8658 0 8658 0 [(8796, 1), (8768, 3)] 0, attempt 8659 0 8659 0 [(8797, 1), (8768, 3)] 0, attempt 8660 0 8660 0 [(8798, 1), (8768, 3)] 0, attempt 8661 0 8661 0 [(8799, 1), (8768, 3)] 0, attempt 8662 0 8662 0 [(8800, 1), (8768, 3)] 0, attempt 8663 0 8663 0 [(8801, 1), (8768, 3)] 0, attempt 8664 0 8664 0 [(8802, 1), (8768, 3)] 0, attempt 8665 0 8665 0 [(8803, 1), (8768, 3)] 0, attempt 8666 0 8666 0 [(8804, 1), (8768, 3)] 0, attempt 8667 0 8667 0 [(8805, 1), (8768, 3)] 0, attempt 8668 0 8668 0 [(8806, 1), (8768, 3)] 0, attempt 8669 0 8669 0 [(8807, 1), (8768, 3)] 0, attempt 8670 0 8670 0 [(8808, 1), (8768, 3)] 0, attempt 8671 0 8671 0 [(8809, 1), (8768, 3)] 0]
def counters015 : List Nat := [8672, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8640
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 8672 0 8672 0 [(8810, 1), (8768, 3)] 0, attempt 8673 0 8673 0 [(8811, 1), (8768, 3)] 0, attempt 8674 0 8674 0 [(8812, 1), (8768, 3)] 0, attempt 8675 0 8675 0 [(8813, 1), (8768, 3)] 0, attempt 8676 0 8676 0 [(8814, 1), (8768, 3)] 0, attempt 8677 0 8677 0 [(8815, 1), (8768, 3)] 0, attempt 8678 0 8678 0 [(8816, 1), (8768, 3)] 0, attempt 8679 0 8679 0 [(8817, 1), (8768, 3)] 0, attempt 8680 0 8680 0 [(8818, 1), (8768, 3)] 0, attempt 8681 0 8681 0 [(8819, 1), (8768, 3)] 0, attempt 8682 0 8682 0 [(8820, 1), (8768, 3)] 0, attempt 8683 0 8683 0 [(8821, 1), (8768, 3)] 0, attempt 8684 0 8684 0 [(8822, 1), (8768, 3)] 0, attempt 8685 0 8685 0 [(8823, 1), (8768, 3)] 0, attempt 8686 0 8686 0 [(8824, 1), (8768, 3)] 0, attempt 8687 0 8687 0 [(8825, 1), (8768, 3)] 0, attempt 8688 0 8688 0 [(8826, 1), (8768, 3)] 0, attempt 8689 0 8689 0 [(8827, 1), (8768, 3)] 0, attempt 8690 0 8690 0 [(8828, 1), (8768, 3)] 0, attempt 8691 0 8691 0 [(8829, 1), (8768, 3)] 0, attempt 8692 0 8692 0 [(8830, 1), (8768, 3)] 0, attempt 8693 0 8693 0 [(8831, 1), (8768, 3)] 0, attempt 8694 0 8694 0 [(8833, 1), (8832, 3)] 0, attempt 8695 0 8695 0 [(8834, 1), (8832, 3)] 0, attempt 8696 0 8696 0 [(8835, 1), (8832, 3)] 0, attempt 8697 0 8697 0 [(8836, 1), (8832, 3)] 0, attempt 8698 0 8698 0 [(8837, 1), (8832, 3)] 0, attempt 8699 0 8699 0 [(8838, 1), (8832, 3)] 0, attempt 8700 0 8700 0 [(8839, 1), (8832, 3)] 0, attempt 8701 0 8701 0 [(8840, 1), (8832, 3)] 0, attempt 8702 0 8702 0 [(8841, 1), (8832, 3)] 0, attempt 8703 0 8703 0 [(8842, 1), (8832, 3)] 0]
def counters016 : List Nat := [8704, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8672
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8704
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8672
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 8672 8704 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 8672) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8640
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 8640 8672 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 8640) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8608
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 8608 8640 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 8608) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8576
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 8576 8608 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 8576) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8544
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 8544 8576 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 8544) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8512
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 8512 8544 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 8512) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8480
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 8480 8512 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 8480) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8448
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 8448 8480 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 8448) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8416
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 8416 8448 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 8416) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8384
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 8384 8416 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 8384) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8352
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 8352 8384 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 8352) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8320
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 8320 8352 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 8320) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8288
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 8288 8320 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 8288) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8256
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 8256 8288 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 8256) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8224
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 8224 8256 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 8224) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 8192
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 8192 8224 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 8192) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr16
