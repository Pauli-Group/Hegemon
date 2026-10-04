import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr09

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr10
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [5120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 5120 0 5120 0 [(5202, 1), (5184, 3)] 0, attempt 5121 0 5121 0 [(5203, 1), (5184, 3)] 0, attempt 5122 0 5122 0 [(5204, 1), (5184, 3)] 0, attempt 5123 0 5123 0 [(5205, 1), (5184, 3)] 0, attempt 5124 0 5124 0 [(5206, 1), (5184, 3)] 0, attempt 5125 0 5125 0 [(5207, 1), (5184, 3)] 0, attempt 5126 0 5126 0 [(5208, 1), (5184, 3)] 0, attempt 5127 0 5127 0 [(5209, 1), (5184, 3)] 0, attempt 5128 0 5128 0 [(5210, 1), (5184, 3)] 0, attempt 5129 0 5129 0 [(5211, 1), (5184, 3)] 0, attempt 5130 0 5130 0 [(5212, 1), (5184, 3)] 0, attempt 5131 0 5131 0 [(5213, 1), (5184, 3)] 0, attempt 5132 0 5132 0 [(5214, 1), (5184, 3)] 0, attempt 5133 0 5133 0 [(5215, 1), (5184, 3)] 0, attempt 5134 0 5134 0 [(5216, 1), (5184, 3)] 0, attempt 5135 0 5135 0 [(5217, 1), (5184, 3)] 0, attempt 5136 0 5136 0 [(5218, 1), (5184, 3)] 0, attempt 5137 0 5137 0 [(5219, 1), (5184, 3)] 0, attempt 5138 0 5138 0 [(5220, 1), (5184, 3)] 0, attempt 5139 0 5139 0 [(5221, 1), (5184, 3)] 0, attempt 5140 0 5140 0 [(5222, 1), (5184, 3)] 0, attempt 5141 0 5141 0 [(5223, 1), (5184, 3)] 0, attempt 5142 0 5142 0 [(5224, 1), (5184, 3)] 0, attempt 5143 0 5143 0 [(5225, 1), (5184, 3)] 0, attempt 5144 0 5144 0 [(5226, 1), (5184, 3)] 0, attempt 5145 0 5145 0 [(5227, 1), (5184, 3)] 0, attempt 5146 0 5146 0 [(5228, 1), (5184, 3)] 0, attempt 5147 0 5147 0 [(5229, 1), (5184, 3)] 0, attempt 5148 0 5148 0 [(5230, 1), (5184, 3)] 0, attempt 5149 0 5149 0 [(5231, 1), (5184, 3)] 0, attempt 5150 0 5150 0 [(5232, 1), (5184, 3)] 0, attempt 5151 0 5151 0 [(5233, 1), (5184, 3)] 0]
def counters001 : List Nat := [5152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5120
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 5152 0 5152 0 [(5234, 1), (5184, 3)] 0, attempt 5153 0 5153 0 [(5235, 1), (5184, 3)] 0, attempt 5154 0 5154 0 [(5236, 1), (5184, 3)] 0, attempt 5155 0 5155 0 [(5237, 1), (5184, 3)] 0, attempt 5156 0 5156 0 [(5238, 1), (5184, 3)] 0, attempt 5157 0 5157 0 [(5239, 1), (5184, 3)] 0, attempt 5158 0 5158 0 [(5240, 1), (5184, 3)] 0, attempt 5159 0 5159 0 [(5241, 1), (5184, 3)] 0, attempt 5160 0 5160 0 [(5242, 1), (5184, 3)] 0, attempt 5161 0 5161 0 [(5243, 1), (5184, 3)] 0, attempt 5162 0 5162 0 [(5244, 1), (5184, 3)] 0, attempt 5163 0 5163 0 [(5245, 1), (5184, 3)] 0, attempt 5164 0 5164 0 [(5246, 1), (5184, 3)] 0, attempt 5165 0 5165 0 [(5247, 1), (5184, 3)] 0, attempt 5166 0 5166 0 [(5249, 1), (5248, 3)] 0, attempt 5167 0 5167 0 [(5250, 1), (5248, 3)] 0, attempt 5168 0 5168 0 [(5251, 1), (5248, 3)] 0, attempt 5169 0 5169 0 [(5252, 1), (5248, 3)] 0, attempt 5170 0 5170 0 [(5253, 1), (5248, 3)] 0, attempt 5171 0 5171 0 [(5254, 1), (5248, 3)] 0, attempt 5172 0 5172 0 [(5255, 1), (5248, 3)] 0, attempt 5173 0 5173 0 [(5256, 1), (5248, 3)] 0, attempt 5174 0 5174 0 [(5257, 1), (5248, 3)] 0, attempt 5175 0 5175 0 [(5258, 1), (5248, 3)] 0, attempt 5176 0 5176 0 [(5259, 1), (5248, 3)] 0, attempt 5177 0 5177 0 [(5260, 1), (5248, 3)] 0, attempt 5178 0 5178 0 [(5261, 1), (5248, 3)] 0, attempt 5179 0 5179 0 [(5262, 1), (5248, 3)] 0, attempt 5180 0 5180 0 [(5263, 1), (5248, 3)] 0, attempt 5181 0 5181 0 [(5264, 1), (5248, 3)] 0, attempt 5182 0 5182 0 [(5265, 1), (5248, 3)] 0, attempt 5183 0 5183 0 [(5266, 1), (5248, 3)] 0]
def counters002 : List Nat := [5184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5152
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 5184 0 5184 0 [(5267, 1), (5248, 3)] 0, attempt 5185 0 5185 0 [(5268, 1), (5248, 3)] 0, attempt 5186 0 5186 0 [(5269, 1), (5248, 3)] 0, attempt 5187 0 5187 0 [(5270, 1), (5248, 3)] 0, attempt 5188 0 5188 0 [(5271, 1), (5248, 3)] 0, attempt 5189 0 5189 0 [(5272, 1), (5248, 3)] 0, attempt 5190 0 5190 0 [(5273, 1), (5248, 3)] 0, attempt 5191 0 5191 0 [(5274, 1), (5248, 3)] 0, attempt 5192 0 5192 0 [(5275, 1), (5248, 3)] 0, attempt 5193 0 5193 0 [(5276, 1), (5248, 3)] 0, attempt 5194 0 5194 0 [(5277, 1), (5248, 3)] 0, attempt 5195 0 5195 0 [(5278, 1), (5248, 3)] 0, attempt 5196 0 5196 0 [(5279, 1), (5248, 3)] 0, attempt 5197 0 5197 0 [(5280, 1), (5248, 3)] 0, attempt 5198 0 5198 0 [(5281, 1), (5248, 3)] 0, attempt 5199 0 5199 0 [(5282, 1), (5248, 3)] 0, attempt 5200 0 5200 0 [(5283, 1), (5248, 3)] 0, attempt 5201 0 5201 0 [(5284, 1), (5248, 3)] 0, attempt 5202 0 5202 0 [(5285, 1), (5248, 3)] 0, attempt 5203 0 5203 0 [(5286, 1), (5248, 3)] 0, attempt 5204 0 5204 0 [(5287, 1), (5248, 3)] 0, attempt 5205 0 5205 0 [(5288, 1), (5248, 3)] 0, attempt 5206 0 5206 0 [(5289, 1), (5248, 3)] 0, attempt 5207 0 5207 0 [(5290, 1), (5248, 3)] 0, attempt 5208 0 5208 0 [(5291, 1), (5248, 3)] 0, attempt 5209 0 5209 0 [(5292, 1), (5248, 3)] 0, attempt 5210 0 5210 0 [(5293, 1), (5248, 3)] 0, attempt 5211 0 5211 0 [(5294, 1), (5248, 3)] 0, attempt 5212 0 5212 0 [(5295, 1), (5248, 3)] 0, attempt 5213 0 5213 0 [(5296, 1), (5248, 3)] 0, attempt 5214 0 5214 0 [(5297, 1), (5248, 3)] 0, attempt 5215 0 5215 0 [(5298, 1), (5248, 3)] 0]
def counters003 : List Nat := [5216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5184
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 5216 0 5216 0 [(5299, 1), (5248, 3)] 0, attempt 5217 0 5217 0 [(5300, 1), (5248, 3)] 0, attempt 5218 0 5218 0 [(5301, 1), (5248, 3)] 0, attempt 5219 0 5219 0 [(5302, 1), (5248, 3)] 0, attempt 5220 0 5220 0 [(5303, 1), (5248, 3)] 0, attempt 5221 0 5221 0 [(5304, 1), (5248, 3)] 0, attempt 5222 0 5222 0 [(5305, 1), (5248, 3)] 0, attempt 5223 0 5223 0 [(5306, 1), (5248, 3)] 0, attempt 5224 0 5224 0 [(5307, 1), (5248, 3)] 0, attempt 5225 0 5225 0 [(5308, 1), (5248, 3)] 0, attempt 5226 0 5226 0 [(5309, 1), (5248, 3)] 0, attempt 5227 0 5227 0 [(5310, 1), (5248, 3)] 0, attempt 5228 0 5228 0 [(5311, 1), (5248, 3)] 0, attempt 5229 0 5229 0 [(5313, 1), (5312, 3)] 0, attempt 5230 0 5230 0 [(5314, 1), (5312, 3)] 0, attempt 5231 0 5231 0 [(5315, 1), (5312, 3)] 0, attempt 5232 0 5232 0 [(5316, 1), (5312, 3)] 0, attempt 5233 0 5233 0 [(5317, 1), (5312, 3)] 0, attempt 5234 0 5234 0 [(5318, 1), (5312, 3)] 0, attempt 5235 0 5235 0 [(5319, 1), (5312, 3)] 0, attempt 5236 0 5236 0 [(5320, 1), (5312, 3)] 0, attempt 5237 0 5237 0 [(5321, 1), (5312, 3)] 0, attempt 5238 0 5238 0 [(5322, 1), (5312, 3)] 0, attempt 5239 0 5239 0 [(5323, 1), (5312, 3)] 0, attempt 5240 0 5240 0 [(5324, 1), (5312, 3)] 0, attempt 5241 0 5241 0 [(5325, 1), (5312, 3)] 0, attempt 5242 0 5242 0 [(5326, 1), (5312, 3)] 0, attempt 5243 0 5243 0 [(5327, 1), (5312, 3)] 0, attempt 5244 0 5244 0 [(5328, 1), (5312, 3)] 0, attempt 5245 0 5245 0 [(5329, 1), (5312, 3)] 0, attempt 5246 0 5246 0 [(5330, 1), (5312, 3)] 0, attempt 5247 0 5247 0 [(5331, 1), (5312, 3)] 0]
def counters004 : List Nat := [5248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5216
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 5248 0 5248 0 [(5332, 1), (5312, 3)] 0, attempt 5249 0 5249 0 [(5333, 1), (5312, 3)] 0, attempt 5250 0 5250 0 [(5334, 1), (5312, 3)] 0, attempt 5251 0 5251 0 [(5335, 1), (5312, 3)] 0, attempt 5252 0 5252 0 [(5336, 1), (5312, 3)] 0, attempt 5253 0 5253 0 [(5337, 1), (5312, 3)] 0, attempt 5254 0 5254 0 [(5338, 1), (5312, 3)] 0, attempt 5255 0 5255 0 [(5339, 1), (5312, 3)] 0, attempt 5256 0 5256 0 [(5340, 1), (5312, 3)] 0, attempt 5257 0 5257 0 [(5341, 1), (5312, 3)] 0, attempt 5258 0 5258 0 [(5342, 1), (5312, 3)] 0, attempt 5259 0 5259 0 [(5343, 1), (5312, 3)] 0, attempt 5260 0 5260 0 [(5344, 1), (5312, 3)] 0, attempt 5261 0 5261 0 [(5345, 1), (5312, 3)] 0, attempt 5262 0 5262 0 [(5346, 1), (5312, 3)] 0, attempt 5263 0 5263 0 [(5347, 1), (5312, 3)] 0, attempt 5264 0 5264 0 [(5348, 1), (5312, 3)] 0, attempt 5265 0 5265 0 [(5349, 1), (5312, 3)] 0, attempt 5266 0 5266 0 [(5350, 1), (5312, 3)] 0, attempt 5267 0 5267 0 [(5351, 1), (5312, 3)] 0, attempt 5268 0 5268 0 [(5352, 1), (5312, 3)] 0, attempt 5269 0 5269 0 [(5353, 1), (5312, 3)] 0, attempt 5270 0 5270 0 [(5354, 1), (5312, 3)] 0, attempt 5271 0 5271 0 [(5355, 1), (5312, 3)] 0, attempt 5272 0 5272 0 [(5356, 1), (5312, 3)] 0, attempt 5273 0 5273 0 [(5357, 1), (5312, 3)] 0, attempt 5274 0 5274 0 [(5358, 1), (5312, 3)] 0, attempt 5275 0 5275 0 [(5359, 1), (5312, 3)] 0, attempt 5276 0 5276 0 [(5360, 1), (5312, 3)] 0, attempt 5277 0 5277 0 [(5361, 1), (5312, 3)] 0, attempt 5278 0 5278 0 [(5362, 1), (5312, 3)] 0, attempt 5279 0 5279 0 [(5363, 1), (5312, 3)] 0]
def counters005 : List Nat := [5280, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5248
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 5280 0 5280 0 [(5364, 1), (5312, 3)] 0, attempt 5281 0 5281 0 [(5365, 1), (5312, 3)] 0, attempt 5282 0 5282 0 [(5366, 1), (5312, 3)] 0, attempt 5283 0 5283 0 [(5367, 1), (5312, 3)] 0, attempt 5284 0 5284 0 [(5368, 1), (5312, 3)] 0, attempt 5285 0 5285 0 [(5369, 1), (5312, 3)] 0, attempt 5286 0 5286 0 [(5370, 1), (5312, 3)] 0, attempt 5287 0 5287 0 [(5371, 1), (5312, 3)] 0, attempt 5288 0 5288 0 [(5372, 1), (5312, 3)] 0, attempt 5289 0 5289 0 [(5373, 1), (5312, 3)] 0, attempt 5290 0 5290 0 [(5374, 1), (5312, 3)] 0, attempt 5291 0 5291 0 [(5375, 1), (5312, 3)] 0, attempt 5292 0 5292 0 [(5377, 1), (5376, 3)] 0, attempt 5293 0 5293 0 [(5378, 1), (5376, 3)] 0, attempt 5294 0 5294 0 [(5379, 1), (5376, 3)] 0, attempt 5295 0 5295 0 [(5380, 1), (5376, 3)] 0, attempt 5296 0 5296 0 [(5381, 1), (5376, 3)] 0, attempt 5297 0 5297 0 [(5382, 1), (5376, 3)] 0, attempt 5298 0 5298 0 [(5383, 1), (5376, 3)] 0, attempt 5299 0 5299 0 [(5384, 1), (5376, 3)] 0, attempt 5300 0 5300 0 [(5385, 1), (5376, 3)] 0, attempt 5301 0 5301 0 [(5386, 1), (5376, 3)] 0, attempt 5302 0 5302 0 [(5387, 1), (5376, 3)] 0, attempt 5303 0 5303 0 [(5388, 1), (5376, 3)] 0, attempt 5304 0 5304 0 [(5389, 1), (5376, 3)] 0, attempt 5305 0 5305 0 [(5390, 1), (5376, 3)] 0, attempt 5306 0 5306 0 [(5391, 1), (5376, 3)] 0, attempt 5307 0 5307 0 [(5392, 1), (5376, 3)] 0, attempt 5308 0 5308 0 [(5393, 1), (5376, 3)] 0, attempt 5309 0 5309 0 [(5394, 1), (5376, 3)] 0, attempt 5310 0 5310 0 [(5395, 1), (5376, 3)] 0, attempt 5311 0 5311 0 [(5396, 1), (5376, 3)] 0]
def counters006 : List Nat := [5312, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5280
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 5312 0 5312 0 [(5397, 1), (5376, 3)] 0, attempt 5313 0 5313 0 [(5398, 1), (5376, 3)] 0, attempt 5314 0 5314 0 [(5399, 1), (5376, 3)] 0, attempt 5315 0 5315 0 [(5400, 1), (5376, 3)] 0, attempt 5316 0 5316 0 [(5401, 1), (5376, 3)] 0, attempt 5317 0 5317 0 [(5402, 1), (5376, 3)] 0, attempt 5318 0 5318 0 [(5403, 1), (5376, 3)] 0, attempt 5319 0 5319 0 [(5404, 1), (5376, 3)] 0, attempt 5320 0 5320 0 [(5405, 1), (5376, 3)] 0, attempt 5321 0 5321 0 [(5406, 1), (5376, 3)] 0, attempt 5322 0 5322 0 [(5407, 1), (5376, 3)] 0, attempt 5323 0 5323 0 [(5408, 1), (5376, 3)] 0, attempt 5324 0 5324 0 [(5409, 1), (5376, 3)] 0, attempt 5325 0 5325 0 [(5410, 1), (5376, 3)] 0, attempt 5326 0 5326 0 [(5411, 1), (5376, 3)] 0, attempt 5327 0 5327 0 [(5412, 1), (5376, 3)] 0, attempt 5328 0 5328 0 [(5413, 1), (5376, 3)] 0, attempt 5329 0 5329 0 [(5414, 1), (5376, 3)] 0, attempt 5330 0 5330 0 [(5415, 1), (5376, 3)] 0, attempt 5331 0 5331 0 [(5416, 1), (5376, 3)] 0, attempt 5332 0 5332 0 [(5417, 1), (5376, 3)] 0, attempt 5333 0 5333 0 [(5418, 1), (5376, 3)] 0, attempt 5334 0 5334 0 [(5419, 1), (5376, 3)] 0, attempt 5335 0 5335 0 [(5420, 1), (5376, 3)] 0, attempt 5336 0 5336 0 [(5421, 1), (5376, 3)] 0, attempt 5337 0 5337 0 [(5422, 1), (5376, 3)] 0, attempt 5338 0 5338 0 [(5423, 1), (5376, 3)] 0, attempt 5339 0 5339 0 [(5424, 1), (5376, 3)] 0, attempt 5340 0 5340 0 [(5425, 1), (5376, 3)] 0, attempt 5341 0 5341 0 [(5426, 1), (5376, 3)] 0, attempt 5342 0 5342 0 [(5427, 1), (5376, 3)] 0, attempt 5343 0 5343 0 [(5428, 1), (5376, 3)] 0]
def counters007 : List Nat := [5344, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5312
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 5344 0 5344 0 [(5429, 1), (5376, 3)] 0, attempt 5345 0 5345 0 [(5430, 1), (5376, 3)] 0, attempt 5346 0 5346 0 [(5431, 1), (5376, 3)] 0, attempt 5347 0 5347 0 [(5432, 1), (5376, 3)] 0, attempt 5348 0 5348 0 [(5433, 1), (5376, 3)] 0, attempt 5349 0 5349 0 [(5434, 1), (5376, 3)] 0, attempt 5350 0 5350 0 [(5435, 1), (5376, 3)] 0, attempt 5351 0 5351 0 [(5436, 1), (5376, 3)] 0, attempt 5352 0 5352 0 [(5437, 1), (5376, 3)] 0, attempt 5353 0 5353 0 [(5438, 1), (5376, 3)] 0, attempt 5354 0 5354 0 [(5439, 1), (5376, 3)] 0, attempt 5355 0 5355 0 [(5441, 1), (5440, 3)] 0, attempt 5356 0 5356 0 [(5442, 1), (5440, 3)] 0, attempt 5357 0 5357 0 [(5443, 1), (5440, 3)] 0, attempt 5358 0 5358 0 [(5444, 1), (5440, 3)] 0, attempt 5359 0 5359 0 [(5445, 1), (5440, 3)] 0, attempt 5360 0 5360 0 [(5446, 1), (5440, 3)] 0, attempt 5361 0 5361 0 [(5447, 1), (5440, 3)] 0, attempt 5362 0 5362 0 [(5448, 1), (5440, 3)] 0, attempt 5363 0 5363 0 [(5449, 1), (5440, 3)] 0, attempt 5364 0 5364 0 [(5450, 1), (5440, 3)] 0, attempt 5365 0 5365 0 [(5451, 1), (5440, 3)] 0, attempt 5366 0 5366 0 [(5452, 1), (5440, 3)] 0, attempt 5367 0 5367 0 [(5453, 1), (5440, 3)] 0, attempt 5368 0 5368 0 [(5454, 1), (5440, 3)] 0, attempt 5369 0 5369 0 [(5455, 1), (5440, 3)] 0, attempt 5370 0 5370 0 [(5456, 1), (5440, 3)] 0, attempt 5371 0 5371 0 [(5457, 1), (5440, 3)] 0, attempt 5372 0 5372 0 [(5458, 1), (5440, 3)] 0, attempt 5373 0 5373 0 [(5459, 1), (5440, 3)] 0, attempt 5374 0 5374 0 [(5460, 1), (5440, 3)] 0, attempt 5375 0 5375 0 [(5461, 1), (5440, 3)] 0]
def counters008 : List Nat := [5376, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5344
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 5376 0 5376 0 [(5462, 1), (5440, 3)] 0, attempt 5377 0 5377 0 [(5463, 1), (5440, 3)] 0, attempt 5378 0 5378 0 [(5464, 1), (5440, 3)] 0, attempt 5379 0 5379 0 [(5465, 1), (5440, 3)] 0, attempt 5380 0 5380 0 [(5466, 1), (5440, 3)] 0, attempt 5381 0 5381 0 [(5467, 1), (5440, 3)] 0, attempt 5382 0 5382 0 [(5468, 1), (5440, 3)] 0, attempt 5383 0 5383 0 [(5469, 1), (5440, 3)] 0, attempt 5384 0 5384 0 [(5470, 1), (5440, 3)] 0, attempt 5385 0 5385 0 [(5471, 1), (5440, 3)] 0, attempt 5386 0 5386 0 [(5472, 1), (5440, 3)] 0, attempt 5387 0 5387 0 [(5473, 1), (5440, 3)] 0, attempt 5388 0 5388 0 [(5474, 1), (5440, 3)] 0, attempt 5389 0 5389 0 [(5475, 1), (5440, 3)] 0, attempt 5390 0 5390 0 [(5476, 1), (5440, 3)] 0, attempt 5391 0 5391 0 [(5477, 1), (5440, 3)] 0, attempt 5392 0 5392 0 [(5478, 1), (5440, 3)] 0, attempt 5393 0 5393 0 [(5479, 1), (5440, 3)] 0, attempt 5394 0 5394 0 [(5480, 1), (5440, 3)] 0, attempt 5395 0 5395 0 [(5481, 1), (5440, 3)] 0, attempt 5396 0 5396 0 [(5482, 1), (5440, 3)] 0, attempt 5397 0 5397 0 [(5483, 1), (5440, 3)] 0, attempt 5398 0 5398 0 [(5484, 1), (5440, 3)] 0, attempt 5399 0 5399 0 [(5485, 1), (5440, 3)] 0, attempt 5400 0 5400 0 [(5486, 1), (5440, 3)] 0, attempt 5401 0 5401 0 [(5487, 1), (5440, 3)] 0, attempt 5402 0 5402 0 [(5488, 1), (5440, 3)] 0, attempt 5403 0 5403 0 [(5489, 1), (5440, 3)] 0, attempt 5404 0 5404 0 [(5490, 1), (5440, 3)] 0, attempt 5405 0 5405 0 [(5491, 1), (5440, 3)] 0, attempt 5406 0 5406 0 [(5492, 1), (5440, 3)] 0, attempt 5407 0 5407 0 [(5493, 1), (5440, 3)] 0]
def counters009 : List Nat := [5408, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5376
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 5408 0 5408 0 [(5494, 1), (5440, 3)] 0, attempt 5409 0 5409 0 [(5495, 1), (5440, 3)] 0, attempt 5410 0 5410 0 [(5496, 1), (5440, 3)] 0, attempt 5411 0 5411 0 [(5497, 1), (5440, 3)] 0, attempt 5412 0 5412 0 [(5498, 1), (5440, 3)] 0, attempt 5413 0 5413 0 [(5499, 1), (5440, 3)] 0, attempt 5414 0 5414 0 [(5500, 1), (5440, 3)] 0, attempt 5415 0 5415 0 [(5501, 1), (5440, 3)] 0, attempt 5416 0 5416 0 [(5502, 1), (5440, 3)] 0, attempt 5417 0 5417 0 [(5503, 1), (5440, 3)] 0, attempt 5418 0 5418 0 [(5505, 1), (5504, 3)] 0, attempt 5419 0 5419 0 [(5506, 1), (5504, 3)] 0, attempt 5420 0 5420 0 [(5507, 1), (5504, 3)] 0, attempt 5421 0 5421 0 [(5508, 1), (5504, 3)] 0, attempt 5422 0 5422 0 [(5509, 1), (5504, 3)] 0, attempt 5423 0 5423 0 [(5510, 1), (5504, 3)] 0, attempt 5424 0 5424 0 [(5511, 1), (5504, 3)] 0, attempt 5425 0 5425 0 [(5512, 1), (5504, 3)] 0, attempt 5426 0 5426 0 [(5513, 1), (5504, 3)] 0, attempt 5427 0 5427 0 [(5514, 1), (5504, 3)] 0, attempt 5428 0 5428 0 [(5515, 1), (5504, 3)] 0, attempt 5429 0 5429 0 [(5516, 1), (5504, 3)] 0, attempt 5430 0 5430 0 [(5517, 1), (5504, 3)] 0, attempt 5431 0 5431 0 [(5518, 1), (5504, 3)] 0, attempt 5432 0 5432 0 [(5519, 1), (5504, 3)] 0, attempt 5433 0 5433 0 [(5520, 1), (5504, 3)] 0, attempt 5434 0 5434 0 [(5521, 1), (5504, 3)] 0, attempt 5435 0 5435 0 [(5522, 1), (5504, 3)] 0, attempt 5436 0 5436 0 [(5523, 1), (5504, 3)] 0, attempt 5437 0 5437 0 [(5524, 1), (5504, 3)] 0, attempt 5438 0 5438 0 [(5525, 1), (5504, 3)] 0, attempt 5439 0 5439 0 [(5526, 1), (5504, 3)] 0]
def counters010 : List Nat := [5440, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5408
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 5440 0 5440 0 [(5527, 1), (5504, 3)] 0, attempt 5441 0 5441 0 [(5528, 1), (5504, 3)] 0, attempt 5442 0 5442 0 [(5529, 1), (5504, 3)] 0, attempt 5443 0 5443 0 [(5530, 1), (5504, 3)] 0, attempt 5444 0 5444 0 [(5531, 1), (5504, 3)] 0, attempt 5445 0 5445 0 [(5532, 1), (5504, 3)] 0, attempt 5446 0 5446 0 [(5533, 1), (5504, 3)] 0, attempt 5447 0 5447 0 [(5534, 1), (5504, 3)] 0, attempt 5448 0 5448 0 [(5535, 1), (5504, 3)] 0, attempt 5449 0 5449 0 [(5536, 1), (5504, 3)] 0, attempt 5450 0 5450 0 [(5537, 1), (5504, 3)] 0, attempt 5451 0 5451 0 [(5538, 1), (5504, 3)] 0, attempt 5452 0 5452 0 [(5539, 1), (5504, 3)] 0, attempt 5453 0 5453 0 [(5540, 1), (5504, 3)] 0, attempt 5454 0 5454 0 [(5541, 1), (5504, 3)] 0, attempt 5455 0 5455 0 [(5542, 1), (5504, 3)] 0, attempt 5456 0 5456 0 [(5543, 1), (5504, 3)] 0, attempt 5457 0 5457 0 [(5544, 1), (5504, 3)] 0, attempt 5458 0 5458 0 [(5545, 1), (5504, 3)] 0, attempt 5459 0 5459 0 [(5546, 1), (5504, 3)] 0, attempt 5460 0 5460 0 [(5547, 1), (5504, 3)] 0, attempt 5461 0 5461 0 [(5548, 1), (5504, 3)] 0, attempt 5462 0 5462 0 [(5549, 1), (5504, 3)] 0, attempt 5463 0 5463 0 [(5550, 1), (5504, 3)] 0, attempt 5464 0 5464 0 [(5551, 1), (5504, 3)] 0, attempt 5465 0 5465 0 [(5552, 1), (5504, 3)] 0, attempt 5466 0 5466 0 [(5553, 1), (5504, 3)] 0, attempt 5467 0 5467 0 [(5554, 1), (5504, 3)] 0, attempt 5468 0 5468 0 [(5555, 1), (5504, 3)] 0, attempt 5469 0 5469 0 [(5556, 1), (5504, 3)] 0, attempt 5470 0 5470 0 [(5557, 1), (5504, 3)] 0, attempt 5471 0 5471 0 [(5558, 1), (5504, 3)] 0]
def counters011 : List Nat := [5472, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5440
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 5472 0 5472 0 [(5559, 1), (5504, 3)] 0, attempt 5473 0 5473 0 [(5560, 1), (5504, 3)] 0, attempt 5474 0 5474 0 [(5561, 1), (5504, 3)] 0, attempt 5475 0 5475 0 [(5562, 1), (5504, 3)] 0, attempt 5476 0 5476 0 [(5563, 1), (5504, 3)] 0, attempt 5477 0 5477 0 [(5564, 1), (5504, 3)] 0, attempt 5478 0 5478 0 [(5565, 1), (5504, 3)] 0, attempt 5479 0 5479 0 [(5566, 1), (5504, 3)] 0, attempt 5480 0 5480 0 [(5567, 1), (5504, 3)] 0, attempt 5481 0 5481 0 [(5569, 1), (5568, 3)] 0, attempt 5482 0 5482 0 [(5570, 1), (5568, 3)] 0, attempt 5483 0 5483 0 [(5571, 1), (5568, 3)] 0, attempt 5484 0 5484 0 [(5572, 1), (5568, 3)] 0, attempt 5485 0 5485 0 [(5573, 1), (5568, 3)] 0, attempt 5486 0 5486 0 [(5574, 1), (5568, 3)] 0, attempt 5487 0 5487 0 [(5575, 1), (5568, 3)] 0, attempt 5488 0 5488 0 [(5576, 1), (5568, 3)] 0, attempt 5489 0 5489 0 [(5577, 1), (5568, 3)] 0, attempt 5490 0 5490 0 [(5578, 1), (5568, 3)] 0, attempt 5491 0 5491 0 [(5579, 1), (5568, 3)] 0, attempt 5492 0 5492 0 [(5580, 1), (5568, 3)] 0, attempt 5493 0 5493 0 [(5581, 1), (5568, 3)] 0, attempt 5494 0 5494 0 [(5582, 1), (5568, 3)] 0, attempt 5495 0 5495 0 [(5583, 1), (5568, 3)] 0, attempt 5496 0 5496 0 [(5584, 1), (5568, 3)] 0, attempt 5497 0 5497 0 [(5585, 1), (5568, 3)] 0, attempt 5498 0 5498 0 [(5586, 1), (5568, 3)] 0, attempt 5499 0 5499 0 [(5587, 1), (5568, 3)] 0, attempt 5500 0 5500 0 [(5588, 1), (5568, 3)] 0, attempt 5501 0 5501 0 [(5589, 1), (5568, 3)] 0, attempt 5502 0 5502 0 [(5590, 1), (5568, 3)] 0, attempt 5503 0 5503 0 [(5591, 1), (5568, 3)] 0]
def counters012 : List Nat := [5504, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5472
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 5504 0 5504 0 [(5592, 1), (5568, 3)] 0, attempt 5505 0 5505 0 [(5593, 1), (5568, 3)] 0, attempt 5506 0 5506 0 [(5594, 1), (5568, 3)] 0, attempt 5507 0 5507 0 [(5595, 1), (5568, 3)] 0, attempt 5508 0 5508 0 [(5596, 1), (5568, 3)] 0, attempt 5509 0 5509 0 [(5597, 1), (5568, 3)] 0, attempt 5510 0 5510 0 [(5598, 1), (5568, 3)] 0, attempt 5511 0 5511 0 [(5599, 1), (5568, 3)] 0, attempt 5512 0 5512 0 [(5600, 1), (5568, 3)] 0, attempt 5513 0 5513 0 [(5601, 1), (5568, 3)] 0, attempt 5514 0 5514 0 [(5602, 1), (5568, 3)] 0, attempt 5515 0 5515 0 [(5603, 1), (5568, 3)] 0, attempt 5516 0 5516 0 [(5604, 1), (5568, 3)] 0, attempt 5517 0 5517 0 [(5605, 1), (5568, 3)] 0, attempt 5518 0 5518 0 [(5606, 1), (5568, 3)] 0, attempt 5519 0 5519 0 [(5607, 1), (5568, 3)] 0, attempt 5520 0 5520 0 [(5608, 1), (5568, 3)] 0, attempt 5521 0 5521 0 [(5609, 1), (5568, 3)] 0, attempt 5522 0 5522 0 [(5610, 1), (5568, 3)] 0, attempt 5523 0 5523 0 [(5611, 1), (5568, 3)] 0, attempt 5524 0 5524 0 [(5612, 1), (5568, 3)] 0, attempt 5525 0 5525 0 [(5613, 1), (5568, 3)] 0, attempt 5526 0 5526 0 [(5614, 1), (5568, 3)] 0, attempt 5527 0 5527 0 [(5615, 1), (5568, 3)] 0, attempt 5528 0 5528 0 [(5616, 1), (5568, 3)] 0, attempt 5529 0 5529 0 [(5617, 1), (5568, 3)] 0, attempt 5530 0 5530 0 [(5618, 1), (5568, 3)] 0, attempt 5531 0 5531 0 [(5619, 1), (5568, 3)] 0, attempt 5532 0 5532 0 [(5620, 1), (5568, 3)] 0, attempt 5533 0 5533 0 [(5621, 1), (5568, 3)] 0, attempt 5534 0 5534 0 [(5622, 1), (5568, 3)] 0, attempt 5535 0 5535 0 [(5623, 1), (5568, 3)] 0]
def counters013 : List Nat := [5536, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5504
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 5536 0 5536 0 [(5624, 1), (5568, 3)] 0, attempt 5537 0 5537 0 [(5625, 1), (5568, 3)] 0, attempt 5538 0 5538 0 [(5626, 1), (5568, 3)] 0, attempt 5539 0 5539 0 [(5627, 1), (5568, 3)] 0, attempt 5540 0 5540 0 [(5628, 1), (5568, 3)] 0, attempt 5541 0 5541 0 [(5629, 1), (5568, 3)] 0, attempt 5542 0 5542 0 [(5630, 1), (5568, 3)] 0, attempt 5543 0 5543 0 [(5631, 1), (5568, 3)] 0, attempt 5544 0 5544 0 [(5633, 1), (5632, 3)] 0, attempt 5545 0 5545 0 [(5634, 1), (5632, 3)] 0, attempt 5546 0 5546 0 [(5635, 1), (5632, 3)] 0, attempt 5547 0 5547 0 [(5636, 1), (5632, 3)] 0, attempt 5548 0 5548 0 [(5637, 1), (5632, 3)] 0, attempt 5549 0 5549 0 [(5638, 1), (5632, 3)] 0, attempt 5550 0 5550 0 [(5639, 1), (5632, 3)] 0, attempt 5551 0 5551 0 [(5640, 1), (5632, 3)] 0, attempt 5552 0 5552 0 [(5641, 1), (5632, 3)] 0, attempt 5553 0 5553 0 [(5642, 1), (5632, 3)] 0, attempt 5554 0 5554 0 [(5643, 1), (5632, 3)] 0, attempt 5555 0 5555 0 [(5644, 1), (5632, 3)] 0, attempt 5556 0 5556 0 [(5645, 1), (5632, 3)] 0, attempt 5557 0 5557 0 [(5646, 1), (5632, 3)] 0, attempt 5558 0 5558 0 [(5647, 1), (5632, 3)] 0, attempt 5559 0 5559 0 [(5648, 1), (5632, 3)] 0, attempt 5560 0 5560 0 [(5649, 1), (5632, 3)] 0, attempt 5561 0 5561 0 [(5650, 1), (5632, 3)] 0, attempt 5562 0 5562 0 [(5651, 1), (5632, 3)] 0, attempt 5563 0 5563 0 [(5652, 1), (5632, 3)] 0, attempt 5564 0 5564 0 [(5653, 1), (5632, 3)] 0, attempt 5565 0 5565 0 [(5654, 1), (5632, 3)] 0, attempt 5566 0 5566 0 [(5655, 1), (5632, 3)] 0, attempt 5567 0 5567 0 [(5656, 1), (5632, 3)] 0]
def counters014 : List Nat := [5568, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5536
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 5568 0 5568 0 [(5657, 1), (5632, 3)] 0, attempt 5569 0 5569 0 [(5658, 1), (5632, 3)] 0, attempt 5570 0 5570 0 [(5659, 1), (5632, 3)] 0, attempt 5571 0 5571 0 [(5660, 1), (5632, 3)] 0, attempt 5572 0 5572 0 [(5661, 1), (5632, 3)] 0, attempt 5573 0 5573 0 [(5662, 1), (5632, 3)] 0, attempt 5574 0 5574 0 [(5663, 1), (5632, 3)] 0, attempt 5575 0 5575 0 [(5664, 1), (5632, 3)] 0, attempt 5576 0 5576 0 [(5665, 1), (5632, 3)] 0, attempt 5577 0 5577 0 [(5666, 1), (5632, 3)] 0, attempt 5578 0 5578 0 [(5667, 1), (5632, 3)] 0, attempt 5579 0 5579 0 [(5668, 1), (5632, 3)] 0, attempt 5580 0 5580 0 [(5669, 1), (5632, 3)] 0, attempt 5581 0 5581 0 [(5670, 1), (5632, 3)] 0, attempt 5582 0 5582 0 [(5671, 1), (5632, 3)] 0, attempt 5583 0 5583 0 [(5672, 1), (5632, 3)] 0, attempt 5584 0 5584 0 [(5673, 1), (5632, 3)] 0, attempt 5585 0 5585 0 [(5674, 1), (5632, 3)] 0, attempt 5586 0 5586 0 [(5675, 1), (5632, 3)] 0, attempt 5587 0 5587 0 [(5676, 1), (5632, 3)] 0, attempt 5588 0 5588 0 [(5677, 1), (5632, 3)] 0, attempt 5589 0 5589 0 [(5678, 1), (5632, 3)] 0, attempt 5590 0 5590 0 [(5679, 1), (5632, 3)] 0, attempt 5591 0 5591 0 [(5680, 1), (5632, 3)] 0, attempt 5592 0 5592 0 [(5681, 1), (5632, 3)] 0, attempt 5593 0 5593 0 [(5682, 1), (5632, 3)] 0, attempt 5594 0 5594 0 [(5683, 1), (5632, 3)] 0, attempt 5595 0 5595 0 [(5684, 1), (5632, 3)] 0, attempt 5596 0 5596 0 [(5685, 1), (5632, 3)] 0, attempt 5597 0 5597 0 [(5686, 1), (5632, 3)] 0, attempt 5598 0 5598 0 [(5687, 1), (5632, 3)] 0, attempt 5599 0 5599 0 [(5688, 1), (5632, 3)] 0]
def counters015 : List Nat := [5600, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5568
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 5600 0 5600 0 [(5689, 1), (5632, 3)] 0, attempt 5601 0 5601 0 [(5690, 1), (5632, 3)] 0, attempt 5602 0 5602 0 [(5691, 1), (5632, 3)] 0, attempt 5603 0 5603 0 [(5692, 1), (5632, 3)] 0, attempt 5604 0 5604 0 [(5693, 1), (5632, 3)] 0, attempt 5605 0 5605 0 [(5694, 1), (5632, 3)] 0, attempt 5606 0 5606 0 [(5695, 1), (5632, 3)] 0, attempt 5607 0 5607 0 [(5697, 1), (5696, 3)] 0, attempt 5608 0 5608 0 [(5698, 1), (5696, 3)] 0, attempt 5609 0 5609 0 [(5699, 1), (5696, 3)] 0, attempt 5610 0 5610 0 [(5700, 1), (5696, 3)] 0, attempt 5611 0 5611 0 [(5701, 1), (5696, 3)] 0, attempt 5612 0 5612 0 [(5702, 1), (5696, 3)] 0, attempt 5613 0 5613 0 [(5703, 1), (5696, 3)] 0, attempt 5614 0 5614 0 [(5704, 1), (5696, 3)] 0, attempt 5615 0 5615 0 [(5705, 1), (5696, 3)] 0, attempt 5616 0 5616 0 [(5706, 1), (5696, 3)] 0, attempt 5617 0 5617 0 [(5707, 1), (5696, 3)] 0, attempt 5618 0 5618 0 [(5708, 1), (5696, 3)] 0, attempt 5619 0 5619 0 [(5709, 1), (5696, 3)] 0, attempt 5620 0 5620 0 [(5710, 1), (5696, 3)] 0, attempt 5621 0 5621 0 [(5711, 1), (5696, 3)] 0, attempt 5622 0 5622 0 [(5712, 1), (5696, 3)] 0, attempt 5623 0 5623 0 [(5713, 1), (5696, 3)] 0, attempt 5624 0 5624 0 [(5714, 1), (5696, 3)] 0, attempt 5625 0 5625 0 [(5715, 1), (5696, 3)] 0, attempt 5626 0 5626 0 [(5716, 1), (5696, 3)] 0, attempt 5627 0 5627 0 [(5717, 1), (5696, 3)] 0, attempt 5628 0 5628 0 [(5718, 1), (5696, 3)] 0, attempt 5629 0 5629 0 [(5719, 1), (5696, 3)] 0, attempt 5630 0 5630 0 [(5720, 1), (5696, 3)] 0, attempt 5631 0 5631 0 [(5721, 1), (5696, 3)] 0]
def counters016 : List Nat := [5632, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5600
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5632
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5600
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 5600 5632 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 5600) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5568
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 5568 5600 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 5568) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5536
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 5536 5568 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 5536) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5504
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 5504 5536 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 5504) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5472
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 5472 5504 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 5472) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5440
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 5440 5472 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 5440) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5408
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 5408 5440 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 5408) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5376
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 5376 5408 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 5376) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5344
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 5344 5376 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 5344) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5312
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 5312 5344 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 5312) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5280
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 5280 5312 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 5280) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5248
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 5248 5280 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 5248) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5216
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 5216 5248 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 5216) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5184
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 5184 5216 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 5184) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5152
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 5152 5184 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 5152) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 5120
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 5120 5152 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 5120) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr10
