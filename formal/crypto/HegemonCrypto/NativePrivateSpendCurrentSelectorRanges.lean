import HegemonCrypto.NativePrivateSpendCurrentFiniteConstructors
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
namespace HegemonCrypto.NativePrivateSpendCurrentSelectorRanges
open NativePrivateSpendSelectedNullifier NativePrivateSpendPackedLowering
open NativePrivateSpendArithmeticTopology NativeLaunchConstraintAdapterBridge
open NativePrivateSpendLocalSemantics
noncomputable section
variable [Fact (Nat.Prime modulus)]
structure SliceFacts (g : Graph K) (count : g.count = 676622) : Prop where
  node_6931 : g.nodes ⟨6931, by omega⟩ = .linear (.wire 6913) (.wire 6914) false
  node_6932 : g.nodes ⟨6932, by omega⟩ = .linear (.wire 6931) (.wire 6915) false
  node_6933 : g.nodes ⟨6933, by omega⟩ = .linear (.wire 6932) (.wire 6916) false
  node_6934 : g.nodes ⟨6934, by omega⟩ = .linear (.wire 6933) (.wire 6917) false
  node_6935 : g.nodes ⟨6935, by omega⟩ = .linear (.wire 6934) (.wire 6918) false
  node_458110 : g.nodes ⟨458110, by omega⟩ = .bit (.wire 6960) 0
  node_458111 : g.nodes ⟨458111, by omega⟩ = .linear (.wire 458110) (.constant (1 : K)) true
  node_458112 : g.nodes ⟨458112, by omega⟩ = .product (.wire 458110) (.wire 458111)
  node_458113 : g.nodes ⟨458113, by omega⟩ = .bit (.wire 6960) 1
  node_458114 : g.nodes ⟨458114, by omega⟩ = .linear (.wire 458113) (.constant (1 : K)) true
  node_458115 : g.nodes ⟨458115, by omega⟩ = .product (.wire 458113) (.wire 458114)
  node_458116 : g.nodes ⟨458116, by omega⟩ = .product (.wire 458113) (.constant (2 : K))
  node_458117 : g.nodes ⟨458117, by omega⟩ = .linear (.wire 458110) (.wire 458116) false
  node_458118 : g.nodes ⟨458118, by omega⟩ = .bit (.wire 6960) 2
  node_458119 : g.nodes ⟨458119, by omega⟩ = .linear (.wire 458118) (.constant (1 : K)) true
  node_458120 : g.nodes ⟨458120, by omega⟩ = .product (.wire 458118) (.wire 458119)
  node_458121 : g.nodes ⟨458121, by omega⟩ = .product (.wire 458118) (.constant (4 : K))
  node_458122 : g.nodes ⟨458122, by omega⟩ = .linear (.wire 458117) (.wire 458121) false
  node_458123 : g.nodes ⟨458123, by omega⟩ = .bit (.wire 6960) 3
  node_458124 : g.nodes ⟨458124, by omega⟩ = .linear (.wire 458123) (.constant (1 : K)) true
  node_458125 : g.nodes ⟨458125, by omega⟩ = .product (.wire 458123) (.wire 458124)
  node_458126 : g.nodes ⟨458126, by omega⟩ = .product (.wire 458123) (.constant (8 : K))
  node_458127 : g.nodes ⟨458127, by omega⟩ = .linear (.wire 458122) (.wire 458126) false
  node_458128 : g.nodes ⟨458128, by omega⟩ = .bit (.wire 6960) 4
  node_458129 : g.nodes ⟨458129, by omega⟩ = .linear (.wire 458128) (.constant (1 : K)) true
  node_458130 : g.nodes ⟨458130, by omega⟩ = .product (.wire 458128) (.wire 458129)
  node_458131 : g.nodes ⟨458131, by omega⟩ = .product (.wire 458128) (.constant (16 : K))
  node_458132 : g.nodes ⟨458132, by omega⟩ = .linear (.wire 458127) (.wire 458131) false
  node_458133 : g.nodes ⟨458133, by omega⟩ = .bit (.wire 6960) 5
  node_458134 : g.nodes ⟨458134, by omega⟩ = .linear (.wire 458133) (.constant (1 : K)) true
  node_458135 : g.nodes ⟨458135, by omega⟩ = .product (.wire 458133) (.wire 458134)
  node_458136 : g.nodes ⟨458136, by omega⟩ = .product (.wire 458133) (.constant (32 : K))
  node_458137 : g.nodes ⟨458137, by omega⟩ = .linear (.wire 458132) (.wire 458136) false
  node_458138 : g.nodes ⟨458138, by omega⟩ = .bit (.wire 6960) 6
  node_458139 : g.nodes ⟨458139, by omega⟩ = .linear (.wire 458138) (.constant (1 : K)) true
  node_458140 : g.nodes ⟨458140, by omega⟩ = .product (.wire 458138) (.wire 458139)
  node_458141 : g.nodes ⟨458141, by omega⟩ = .product (.wire 458138) (.constant (64 : K))
  node_458142 : g.nodes ⟨458142, by omega⟩ = .linear (.wire 458137) (.wire 458141) false
  node_458143 : g.nodes ⟨458143, by omega⟩ = .bit (.wire 6960) 7
  node_458144 : g.nodes ⟨458144, by omega⟩ = .linear (.wire 458143) (.constant (1 : K)) true
  node_458145 : g.nodes ⟨458145, by omega⟩ = .product (.wire 458143) (.wire 458144)
  node_458146 : g.nodes ⟨458146, by omega⟩ = .product (.wire 458143) (.constant (128 : K))
  node_458147 : g.nodes ⟨458147, by omega⟩ = .linear (.wire 458142) (.wire 458146) false
  node_458148 : g.nodes ⟨458148, by omega⟩ = .bit (.wire 6960) 8
  node_458149 : g.nodes ⟨458149, by omega⟩ = .linear (.wire 458148) (.constant (1 : K)) true
  node_458150 : g.nodes ⟨458150, by omega⟩ = .product (.wire 458148) (.wire 458149)
  node_458151 : g.nodes ⟨458151, by omega⟩ = .product (.wire 458148) (.constant (256 : K))
  node_458152 : g.nodes ⟨458152, by omega⟩ = .linear (.wire 458147) (.wire 458151) false
  node_458153 : g.nodes ⟨458153, by omega⟩ = .bit (.wire 6960) 9
  node_458154 : g.nodes ⟨458154, by omega⟩ = .linear (.wire 458153) (.constant (1 : K)) true
  node_458155 : g.nodes ⟨458155, by omega⟩ = .product (.wire 458153) (.wire 458154)
  node_458156 : g.nodes ⟨458156, by omega⟩ = .product (.wire 458153) (.constant (512 : K))
  node_458157 : g.nodes ⟨458157, by omega⟩ = .linear (.wire 458152) (.wire 458156) false
  node_458158 : g.nodes ⟨458158, by omega⟩ = .bit (.wire 6960) 10
  node_458159 : g.nodes ⟨458159, by omega⟩ = .linear (.wire 458158) (.constant (1 : K)) true
  node_458160 : g.nodes ⟨458160, by omega⟩ = .product (.wire 458158) (.wire 458159)
  node_458161 : g.nodes ⟨458161, by omega⟩ = .product (.wire 458158) (.constant (1024 : K))
  node_458162 : g.nodes ⟨458162, by omega⟩ = .linear (.wire 458157) (.wire 458161) false
  node_458163 : g.nodes ⟨458163, by omega⟩ = .bit (.wire 6960) 11
  node_458164 : g.nodes ⟨458164, by omega⟩ = .linear (.wire 458163) (.constant (1 : K)) true
  node_458165 : g.nodes ⟨458165, by omega⟩ = .product (.wire 458163) (.wire 458164)
  node_458166 : g.nodes ⟨458166, by omega⟩ = .product (.wire 458163) (.constant (2048 : K))
  node_458167 : g.nodes ⟨458167, by omega⟩ = .linear (.wire 458162) (.wire 458166) false
  node_458168 : g.nodes ⟨458168, by omega⟩ = .bit (.wire 6960) 12
  node_458169 : g.nodes ⟨458169, by omega⟩ = .linear (.wire 458168) (.constant (1 : K)) true
  node_458170 : g.nodes ⟨458170, by omega⟩ = .product (.wire 458168) (.wire 458169)
  node_458171 : g.nodes ⟨458171, by omega⟩ = .product (.wire 458168) (.constant (4096 : K))
  node_458172 : g.nodes ⟨458172, by omega⟩ = .linear (.wire 458167) (.wire 458171) false
  node_458173 : g.nodes ⟨458173, by omega⟩ = .bit (.wire 6960) 13
  node_458174 : g.nodes ⟨458174, by omega⟩ = .linear (.wire 458173) (.constant (1 : K)) true
  node_458175 : g.nodes ⟨458175, by omega⟩ = .product (.wire 458173) (.wire 458174)
  node_458176 : g.nodes ⟨458176, by omega⟩ = .product (.wire 458173) (.constant (8192 : K))
  node_458177 : g.nodes ⟨458177, by omega⟩ = .linear (.wire 458172) (.wire 458176) false
  node_458178 : g.nodes ⟨458178, by omega⟩ = .bit (.wire 6960) 14
  node_458179 : g.nodes ⟨458179, by omega⟩ = .linear (.wire 458178) (.constant (1 : K)) true
  node_458180 : g.nodes ⟨458180, by omega⟩ = .product (.wire 458178) (.wire 458179)
  node_458181 : g.nodes ⟨458181, by omega⟩ = .product (.wire 458178) (.constant (16384 : K))
  node_458182 : g.nodes ⟨458182, by omega⟩ = .linear (.wire 458177) (.wire 458181) false
  node_458183 : g.nodes ⟨458183, by omega⟩ = .bit (.wire 6960) 15
  node_458184 : g.nodes ⟨458184, by omega⟩ = .linear (.wire 458183) (.constant (1 : K)) true
  node_458185 : g.nodes ⟨458185, by omega⟩ = .product (.wire 458183) (.wire 458184)
  node_458186 : g.nodes ⟨458186, by omega⟩ = .product (.wire 458183) (.constant (32768 : K))
  node_458187 : g.nodes ⟨458187, by omega⟩ = .linear (.wire 458182) (.wire 458186) false
  node_458188 : g.nodes ⟨458188, by omega⟩ = .bit (.wire 6960) 16
  node_458189 : g.nodes ⟨458189, by omega⟩ = .linear (.wire 458188) (.constant (1 : K)) true
  node_458190 : g.nodes ⟨458190, by omega⟩ = .product (.wire 458188) (.wire 458189)
  node_458191 : g.nodes ⟨458191, by omega⟩ = .product (.wire 458188) (.constant (65536 : K))
  node_458192 : g.nodes ⟨458192, by omega⟩ = .linear (.wire 458187) (.wire 458191) false
  node_458193 : g.nodes ⟨458193, by omega⟩ = .bit (.wire 6960) 17
  node_458194 : g.nodes ⟨458194, by omega⟩ = .linear (.wire 458193) (.constant (1 : K)) true
  node_458195 : g.nodes ⟨458195, by omega⟩ = .product (.wire 458193) (.wire 458194)
  node_458196 : g.nodes ⟨458196, by omega⟩ = .product (.wire 458193) (.constant (131072 : K))
  node_458197 : g.nodes ⟨458197, by omega⟩ = .linear (.wire 458192) (.wire 458196) false
  node_458198 : g.nodes ⟨458198, by omega⟩ = .bit (.wire 6960) 18
  node_458199 : g.nodes ⟨458199, by omega⟩ = .linear (.wire 458198) (.constant (1 : K)) true
  node_458200 : g.nodes ⟨458200, by omega⟩ = .product (.wire 458198) (.wire 458199)
  node_458201 : g.nodes ⟨458201, by omega⟩ = .product (.wire 458198) (.constant (262144 : K))
  node_458202 : g.nodes ⟨458202, by omega⟩ = .linear (.wire 458197) (.wire 458201) false
  node_458203 : g.nodes ⟨458203, by omega⟩ = .bit (.wire 6960) 19
  node_458204 : g.nodes ⟨458204, by omega⟩ = .linear (.wire 458203) (.constant (1 : K)) true
  node_458205 : g.nodes ⟨458205, by omega⟩ = .product (.wire 458203) (.wire 458204)
  node_458206 : g.nodes ⟨458206, by omega⟩ = .product (.wire 458203) (.constant (524288 : K))
  node_458207 : g.nodes ⟨458207, by omega⟩ = .linear (.wire 458202) (.wire 458206) false
  node_458208 : g.nodes ⟨458208, by omega⟩ = .bit (.wire 6960) 20
  node_458209 : g.nodes ⟨458209, by omega⟩ = .linear (.wire 458208) (.constant (1 : K)) true
  node_458210 : g.nodes ⟨458210, by omega⟩ = .product (.wire 458208) (.wire 458209)
  node_458211 : g.nodes ⟨458211, by omega⟩ = .product (.wire 458208) (.constant (1048576 : K))
  node_458212 : g.nodes ⟨458212, by omega⟩ = .linear (.wire 458207) (.wire 458211) false
  node_458213 : g.nodes ⟨458213, by omega⟩ = .bit (.wire 6960) 21
  node_458214 : g.nodes ⟨458214, by omega⟩ = .linear (.wire 458213) (.constant (1 : K)) true
  node_458215 : g.nodes ⟨458215, by omega⟩ = .product (.wire 458213) (.wire 458214)
  node_458216 : g.nodes ⟨458216, by omega⟩ = .product (.wire 458213) (.constant (2097152 : K))
  node_458217 : g.nodes ⟨458217, by omega⟩ = .linear (.wire 458212) (.wire 458216) false
  node_458218 : g.nodes ⟨458218, by omega⟩ = .bit (.wire 6960) 22
  node_458219 : g.nodes ⟨458219, by omega⟩ = .linear (.wire 458218) (.constant (1 : K)) true
  node_458220 : g.nodes ⟨458220, by omega⟩ = .product (.wire 458218) (.wire 458219)
  node_458221 : g.nodes ⟨458221, by omega⟩ = .product (.wire 458218) (.constant (4194304 : K))
  node_458222 : g.nodes ⟨458222, by omega⟩ = .linear (.wire 458217) (.wire 458221) false
  node_458223 : g.nodes ⟨458223, by omega⟩ = .bit (.wire 6960) 23
  node_458224 : g.nodes ⟨458224, by omega⟩ = .linear (.wire 458223) (.constant (1 : K)) true
  node_458225 : g.nodes ⟨458225, by omega⟩ = .product (.wire 458223) (.wire 458224)
  node_458226 : g.nodes ⟨458226, by omega⟩ = .product (.wire 458223) (.constant (8388608 : K))
  node_458227 : g.nodes ⟨458227, by omega⟩ = .linear (.wire 458222) (.wire 458226) false
  node_458228 : g.nodes ⟨458228, by omega⟩ = .bit (.wire 6960) 24
  node_458229 : g.nodes ⟨458229, by omega⟩ = .linear (.wire 458228) (.constant (1 : K)) true
  node_458230 : g.nodes ⟨458230, by omega⟩ = .product (.wire 458228) (.wire 458229)
  node_458231 : g.nodes ⟨458231, by omega⟩ = .product (.wire 458228) (.constant (16777216 : K))
  node_458232 : g.nodes ⟨458232, by omega⟩ = .linear (.wire 458227) (.wire 458231) false
  node_458233 : g.nodes ⟨458233, by omega⟩ = .bit (.wire 6960) 25
  node_458234 : g.nodes ⟨458234, by omega⟩ = .linear (.wire 458233) (.constant (1 : K)) true
  node_458235 : g.nodes ⟨458235, by omega⟩ = .product (.wire 458233) (.wire 458234)
  node_458236 : g.nodes ⟨458236, by omega⟩ = .product (.wire 458233) (.constant (33554432 : K))
  node_458237 : g.nodes ⟨458237, by omega⟩ = .linear (.wire 458232) (.wire 458236) false
  node_458238 : g.nodes ⟨458238, by omega⟩ = .bit (.wire 6960) 26
  node_458239 : g.nodes ⟨458239, by omega⟩ = .linear (.wire 458238) (.constant (1 : K)) true
  node_458240 : g.nodes ⟨458240, by omega⟩ = .product (.wire 458238) (.wire 458239)
  node_458241 : g.nodes ⟨458241, by omega⟩ = .product (.wire 458238) (.constant (67108864 : K))
  node_458242 : g.nodes ⟨458242, by omega⟩ = .linear (.wire 458237) (.wire 458241) false
  node_458243 : g.nodes ⟨458243, by omega⟩ = .bit (.wire 6960) 27
  node_458244 : g.nodes ⟨458244, by omega⟩ = .linear (.wire 458243) (.constant (1 : K)) true
  node_458245 : g.nodes ⟨458245, by omega⟩ = .product (.wire 458243) (.wire 458244)
  node_458246 : g.nodes ⟨458246, by omega⟩ = .product (.wire 458243) (.constant (134217728 : K))
  node_458247 : g.nodes ⟨458247, by omega⟩ = .linear (.wire 458242) (.wire 458246) false
  node_458248 : g.nodes ⟨458248, by omega⟩ = .bit (.wire 6960) 28
  node_458249 : g.nodes ⟨458249, by omega⟩ = .linear (.wire 458248) (.constant (1 : K)) true
  node_458250 : g.nodes ⟨458250, by omega⟩ = .product (.wire 458248) (.wire 458249)
  node_458251 : g.nodes ⟨458251, by omega⟩ = .product (.wire 458248) (.constant (268435456 : K))
  node_458252 : g.nodes ⟨458252, by omega⟩ = .linear (.wire 458247) (.wire 458251) false
  node_458253 : g.nodes ⟨458253, by omega⟩ = .bit (.wire 6960) 29
  node_458254 : g.nodes ⟨458254, by omega⟩ = .linear (.wire 458253) (.constant (1 : K)) true
  node_458255 : g.nodes ⟨458255, by omega⟩ = .product (.wire 458253) (.wire 458254)
  node_458256 : g.nodes ⟨458256, by omega⟩ = .product (.wire 458253) (.constant (536870912 : K))
  node_458257 : g.nodes ⟨458257, by omega⟩ = .linear (.wire 458252) (.wire 458256) false
  node_458258 : g.nodes ⟨458258, by omega⟩ = .bit (.wire 6960) 30
  node_458259 : g.nodes ⟨458259, by omega⟩ = .linear (.wire 458258) (.constant (1 : K)) true
  node_458260 : g.nodes ⟨458260, by omega⟩ = .product (.wire 458258) (.wire 458259)
  node_458261 : g.nodes ⟨458261, by omega⟩ = .product (.wire 458258) (.constant (1073741824 : K))
  node_458262 : g.nodes ⟨458262, by omega⟩ = .linear (.wire 458257) (.wire 458261) false
  node_458263 : g.nodes ⟨458263, by omega⟩ = .bit (.wire 6960) 31
  node_458264 : g.nodes ⟨458264, by omega⟩ = .linear (.wire 458263) (.constant (1 : K)) true
  node_458265 : g.nodes ⟨458265, by omega⟩ = .product (.wire 458263) (.wire 458264)
  node_458266 : g.nodes ⟨458266, by omega⟩ = .product (.wire 458263) (.constant (2147483648 : K))
  node_458267 : g.nodes ⟨458267, by omega⟩ = .linear (.wire 458262) (.wire 458266) false
  node_560192 : g.nodes ⟨560192, by omega⟩ = .bit (.wire 7215) 0
  node_560193 : g.nodes ⟨560193, by omega⟩ = .linear (.wire 560192) (.constant (1 : K)) true
  node_560194 : g.nodes ⟨560194, by omega⟩ = .product (.wire 560192) (.wire 560193)
  node_560195 : g.nodes ⟨560195, by omega⟩ = .bit (.wire 7215) 1
  node_560196 : g.nodes ⟨560196, by omega⟩ = .linear (.wire 560195) (.constant (1 : K)) true
  node_560197 : g.nodes ⟨560197, by omega⟩ = .product (.wire 560195) (.wire 560196)
  node_560198 : g.nodes ⟨560198, by omega⟩ = .product (.wire 560195) (.constant (2 : K))
  node_560199 : g.nodes ⟨560199, by omega⟩ = .linear (.wire 560192) (.wire 560198) false
  node_560200 : g.nodes ⟨560200, by omega⟩ = .bit (.wire 7215) 2
  node_560201 : g.nodes ⟨560201, by omega⟩ = .linear (.wire 560200) (.constant (1 : K)) true
  node_560202 : g.nodes ⟨560202, by omega⟩ = .product (.wire 560200) (.wire 560201)
  node_560203 : g.nodes ⟨560203, by omega⟩ = .product (.wire 560200) (.constant (4 : K))
  node_560204 : g.nodes ⟨560204, by omega⟩ = .linear (.wire 560199) (.wire 560203) false
  node_560205 : g.nodes ⟨560205, by omega⟩ = .bit (.wire 7215) 3
  node_560206 : g.nodes ⟨560206, by omega⟩ = .linear (.wire 560205) (.constant (1 : K)) true
  node_560207 : g.nodes ⟨560207, by omega⟩ = .product (.wire 560205) (.wire 560206)
  node_560208 : g.nodes ⟨560208, by omega⟩ = .product (.wire 560205) (.constant (8 : K))
  node_560209 : g.nodes ⟨560209, by omega⟩ = .linear (.wire 560204) (.wire 560208) false
  node_560210 : g.nodes ⟨560210, by omega⟩ = .bit (.wire 7215) 4
  node_560211 : g.nodes ⟨560211, by omega⟩ = .linear (.wire 560210) (.constant (1 : K)) true
  node_560212 : g.nodes ⟨560212, by omega⟩ = .product (.wire 560210) (.wire 560211)
  node_560213 : g.nodes ⟨560213, by omega⟩ = .product (.wire 560210) (.constant (16 : K))
  node_560214 : g.nodes ⟨560214, by omega⟩ = .linear (.wire 560209) (.wire 560213) false
  node_560215 : g.nodes ⟨560215, by omega⟩ = .bit (.wire 7215) 5
  node_560216 : g.nodes ⟨560216, by omega⟩ = .linear (.wire 560215) (.constant (1 : K)) true
  node_560217 : g.nodes ⟨560217, by omega⟩ = .product (.wire 560215) (.wire 560216)
  node_560218 : g.nodes ⟨560218, by omega⟩ = .product (.wire 560215) (.constant (32 : K))
  node_560219 : g.nodes ⟨560219, by omega⟩ = .linear (.wire 560214) (.wire 560218) false
  node_560220 : g.nodes ⟨560220, by omega⟩ = .bit (.wire 7215) 6
  node_560221 : g.nodes ⟨560221, by omega⟩ = .linear (.wire 560220) (.constant (1 : K)) true
  node_560222 : g.nodes ⟨560222, by omega⟩ = .product (.wire 560220) (.wire 560221)
  node_560223 : g.nodes ⟨560223, by omega⟩ = .product (.wire 560220) (.constant (64 : K))
  node_560224 : g.nodes ⟨560224, by omega⟩ = .linear (.wire 560219) (.wire 560223) false
  node_560225 : g.nodes ⟨560225, by omega⟩ = .bit (.wire 7215) 7
  node_560226 : g.nodes ⟨560226, by omega⟩ = .linear (.wire 560225) (.constant (1 : K)) true
  node_560227 : g.nodes ⟨560227, by omega⟩ = .product (.wire 560225) (.wire 560226)
  node_560228 : g.nodes ⟨560228, by omega⟩ = .product (.wire 560225) (.constant (128 : K))
  node_560229 : g.nodes ⟨560229, by omega⟩ = .linear (.wire 560224) (.wire 560228) false
  node_560230 : g.nodes ⟨560230, by omega⟩ = .bit (.wire 7215) 8
  node_560231 : g.nodes ⟨560231, by omega⟩ = .linear (.wire 560230) (.constant (1 : K)) true
  node_560232 : g.nodes ⟨560232, by omega⟩ = .product (.wire 560230) (.wire 560231)
  node_560233 : g.nodes ⟨560233, by omega⟩ = .product (.wire 560230) (.constant (256 : K))
  node_560234 : g.nodes ⟨560234, by omega⟩ = .linear (.wire 560229) (.wire 560233) false
  node_560235 : g.nodes ⟨560235, by omega⟩ = .bit (.wire 7215) 9
  node_560236 : g.nodes ⟨560236, by omega⟩ = .linear (.wire 560235) (.constant (1 : K)) true
  node_560237 : g.nodes ⟨560237, by omega⟩ = .product (.wire 560235) (.wire 560236)
  node_560238 : g.nodes ⟨560238, by omega⟩ = .product (.wire 560235) (.constant (512 : K))
  node_560239 : g.nodes ⟨560239, by omega⟩ = .linear (.wire 560234) (.wire 560238) false
  node_560240 : g.nodes ⟨560240, by omega⟩ = .bit (.wire 7215) 10
  node_560241 : g.nodes ⟨560241, by omega⟩ = .linear (.wire 560240) (.constant (1 : K)) true
  node_560242 : g.nodes ⟨560242, by omega⟩ = .product (.wire 560240) (.wire 560241)
  node_560243 : g.nodes ⟨560243, by omega⟩ = .product (.wire 560240) (.constant (1024 : K))
  node_560244 : g.nodes ⟨560244, by omega⟩ = .linear (.wire 560239) (.wire 560243) false
  node_560245 : g.nodes ⟨560245, by omega⟩ = .bit (.wire 7215) 11
  node_560246 : g.nodes ⟨560246, by omega⟩ = .linear (.wire 560245) (.constant (1 : K)) true
  node_560247 : g.nodes ⟨560247, by omega⟩ = .product (.wire 560245) (.wire 560246)
  node_560248 : g.nodes ⟨560248, by omega⟩ = .product (.wire 560245) (.constant (2048 : K))
  node_560249 : g.nodes ⟨560249, by omega⟩ = .linear (.wire 560244) (.wire 560248) false
  node_560250 : g.nodes ⟨560250, by omega⟩ = .bit (.wire 7215) 12
  node_560251 : g.nodes ⟨560251, by omega⟩ = .linear (.wire 560250) (.constant (1 : K)) true
  node_560252 : g.nodes ⟨560252, by omega⟩ = .product (.wire 560250) (.wire 560251)
  node_560253 : g.nodes ⟨560253, by omega⟩ = .product (.wire 560250) (.constant (4096 : K))
  node_560254 : g.nodes ⟨560254, by omega⟩ = .linear (.wire 560249) (.wire 560253) false
  node_560255 : g.nodes ⟨560255, by omega⟩ = .bit (.wire 7215) 13
  node_560256 : g.nodes ⟨560256, by omega⟩ = .linear (.wire 560255) (.constant (1 : K)) true
  node_560257 : g.nodes ⟨560257, by omega⟩ = .product (.wire 560255) (.wire 560256)
  node_560258 : g.nodes ⟨560258, by omega⟩ = .product (.wire 560255) (.constant (8192 : K))
  node_560259 : g.nodes ⟨560259, by omega⟩ = .linear (.wire 560254) (.wire 560258) false
  node_560260 : g.nodes ⟨560260, by omega⟩ = .bit (.wire 7215) 14
  node_560261 : g.nodes ⟨560261, by omega⟩ = .linear (.wire 560260) (.constant (1 : K)) true
  node_560262 : g.nodes ⟨560262, by omega⟩ = .product (.wire 560260) (.wire 560261)
  node_560263 : g.nodes ⟨560263, by omega⟩ = .product (.wire 560260) (.constant (16384 : K))
  node_560264 : g.nodes ⟨560264, by omega⟩ = .linear (.wire 560259) (.wire 560263) false
  node_560265 : g.nodes ⟨560265, by omega⟩ = .bit (.wire 7215) 15
  node_560266 : g.nodes ⟨560266, by omega⟩ = .linear (.wire 560265) (.constant (1 : K)) true
  node_560267 : g.nodes ⟨560267, by omega⟩ = .product (.wire 560265) (.wire 560266)
  node_560268 : g.nodes ⟨560268, by omega⟩ = .product (.wire 560265) (.constant (32768 : K))
  node_560269 : g.nodes ⟨560269, by omega⟩ = .linear (.wire 560264) (.wire 560268) false
  node_560270 : g.nodes ⟨560270, by omega⟩ = .bit (.wire 7215) 16
  node_560271 : g.nodes ⟨560271, by omega⟩ = .linear (.wire 560270) (.constant (1 : K)) true
  node_560272 : g.nodes ⟨560272, by omega⟩ = .product (.wire 560270) (.wire 560271)
  node_560273 : g.nodes ⟨560273, by omega⟩ = .product (.wire 560270) (.constant (65536 : K))
  node_560274 : g.nodes ⟨560274, by omega⟩ = .linear (.wire 560269) (.wire 560273) false
  node_560275 : g.nodes ⟨560275, by omega⟩ = .bit (.wire 7215) 17
  node_560276 : g.nodes ⟨560276, by omega⟩ = .linear (.wire 560275) (.constant (1 : K)) true
  node_560277 : g.nodes ⟨560277, by omega⟩ = .product (.wire 560275) (.wire 560276)
  node_560278 : g.nodes ⟨560278, by omega⟩ = .product (.wire 560275) (.constant (131072 : K))
  node_560279 : g.nodes ⟨560279, by omega⟩ = .linear (.wire 560274) (.wire 560278) false
  node_560280 : g.nodes ⟨560280, by omega⟩ = .bit (.wire 7215) 18
  node_560281 : g.nodes ⟨560281, by omega⟩ = .linear (.wire 560280) (.constant (1 : K)) true
  node_560282 : g.nodes ⟨560282, by omega⟩ = .product (.wire 560280) (.wire 560281)
  node_560283 : g.nodes ⟨560283, by omega⟩ = .product (.wire 560280) (.constant (262144 : K))
  node_560284 : g.nodes ⟨560284, by omega⟩ = .linear (.wire 560279) (.wire 560283) false
  node_560285 : g.nodes ⟨560285, by omega⟩ = .bit (.wire 7215) 19
  node_560286 : g.nodes ⟨560286, by omega⟩ = .linear (.wire 560285) (.constant (1 : K)) true
  node_560287 : g.nodes ⟨560287, by omega⟩ = .product (.wire 560285) (.wire 560286)
  node_560288 : g.nodes ⟨560288, by omega⟩ = .product (.wire 560285) (.constant (524288 : K))
  node_560289 : g.nodes ⟨560289, by omega⟩ = .linear (.wire 560284) (.wire 560288) false
  node_560290 : g.nodes ⟨560290, by omega⟩ = .bit (.wire 7215) 20
  node_560291 : g.nodes ⟨560291, by omega⟩ = .linear (.wire 560290) (.constant (1 : K)) true
  node_560292 : g.nodes ⟨560292, by omega⟩ = .product (.wire 560290) (.wire 560291)
  node_560293 : g.nodes ⟨560293, by omega⟩ = .product (.wire 560290) (.constant (1048576 : K))
  node_560294 : g.nodes ⟨560294, by omega⟩ = .linear (.wire 560289) (.wire 560293) false
  node_560295 : g.nodes ⟨560295, by omega⟩ = .bit (.wire 7215) 21
  node_560296 : g.nodes ⟨560296, by omega⟩ = .linear (.wire 560295) (.constant (1 : K)) true
  node_560297 : g.nodes ⟨560297, by omega⟩ = .product (.wire 560295) (.wire 560296)
  node_560298 : g.nodes ⟨560298, by omega⟩ = .product (.wire 560295) (.constant (2097152 : K))
  node_560299 : g.nodes ⟨560299, by omega⟩ = .linear (.wire 560294) (.wire 560298) false
  node_560300 : g.nodes ⟨560300, by omega⟩ = .bit (.wire 7215) 22
  node_560301 : g.nodes ⟨560301, by omega⟩ = .linear (.wire 560300) (.constant (1 : K)) true
  node_560302 : g.nodes ⟨560302, by omega⟩ = .product (.wire 560300) (.wire 560301)
  node_560303 : g.nodes ⟨560303, by omega⟩ = .product (.wire 560300) (.constant (4194304 : K))
  node_560304 : g.nodes ⟨560304, by omega⟩ = .linear (.wire 560299) (.wire 560303) false
  node_560305 : g.nodes ⟨560305, by omega⟩ = .bit (.wire 7215) 23
  node_560306 : g.nodes ⟨560306, by omega⟩ = .linear (.wire 560305) (.constant (1 : K)) true
  node_560307 : g.nodes ⟨560307, by omega⟩ = .product (.wire 560305) (.wire 560306)
  node_560308 : g.nodes ⟨560308, by omega⟩ = .product (.wire 560305) (.constant (8388608 : K))
  node_560309 : g.nodes ⟨560309, by omega⟩ = .linear (.wire 560304) (.wire 560308) false
  node_560310 : g.nodes ⟨560310, by omega⟩ = .bit (.wire 7215) 24
  node_560311 : g.nodes ⟨560311, by omega⟩ = .linear (.wire 560310) (.constant (1 : K)) true
  node_560312 : g.nodes ⟨560312, by omega⟩ = .product (.wire 560310) (.wire 560311)
  node_560313 : g.nodes ⟨560313, by omega⟩ = .product (.wire 560310) (.constant (16777216 : K))
  node_560314 : g.nodes ⟨560314, by omega⟩ = .linear (.wire 560309) (.wire 560313) false
  node_560315 : g.nodes ⟨560315, by omega⟩ = .bit (.wire 7215) 25
  node_560316 : g.nodes ⟨560316, by omega⟩ = .linear (.wire 560315) (.constant (1 : K)) true
  node_560317 : g.nodes ⟨560317, by omega⟩ = .product (.wire 560315) (.wire 560316)
  node_560318 : g.nodes ⟨560318, by omega⟩ = .product (.wire 560315) (.constant (33554432 : K))
  node_560319 : g.nodes ⟨560319, by omega⟩ = .linear (.wire 560314) (.wire 560318) false
  node_560320 : g.nodes ⟨560320, by omega⟩ = .bit (.wire 7215) 26
  node_560321 : g.nodes ⟨560321, by omega⟩ = .linear (.wire 560320) (.constant (1 : K)) true
  node_560322 : g.nodes ⟨560322, by omega⟩ = .product (.wire 560320) (.wire 560321)
  node_560323 : g.nodes ⟨560323, by omega⟩ = .product (.wire 560320) (.constant (67108864 : K))
  node_560324 : g.nodes ⟨560324, by omega⟩ = .linear (.wire 560319) (.wire 560323) false
  node_560325 : g.nodes ⟨560325, by omega⟩ = .bit (.wire 7215) 27
  node_560326 : g.nodes ⟨560326, by omega⟩ = .linear (.wire 560325) (.constant (1 : K)) true
  node_560327 : g.nodes ⟨560327, by omega⟩ = .product (.wire 560325) (.wire 560326)
  node_560328 : g.nodes ⟨560328, by omega⟩ = .product (.wire 560325) (.constant (134217728 : K))
  node_560329 : g.nodes ⟨560329, by omega⟩ = .linear (.wire 560324) (.wire 560328) false
  node_560330 : g.nodes ⟨560330, by omega⟩ = .bit (.wire 7215) 28
  node_560331 : g.nodes ⟨560331, by omega⟩ = .linear (.wire 560330) (.constant (1 : K)) true
  node_560332 : g.nodes ⟨560332, by omega⟩ = .product (.wire 560330) (.wire 560331)
  node_560333 : g.nodes ⟨560333, by omega⟩ = .product (.wire 560330) (.constant (268435456 : K))
  node_560334 : g.nodes ⟨560334, by omega⟩ = .linear (.wire 560329) (.wire 560333) false
  node_560335 : g.nodes ⟨560335, by omega⟩ = .bit (.wire 7215) 29
  node_560336 : g.nodes ⟨560336, by omega⟩ = .linear (.wire 560335) (.constant (1 : K)) true
  node_560337 : g.nodes ⟨560337, by omega⟩ = .product (.wire 560335) (.wire 560336)
  node_560338 : g.nodes ⟨560338, by omega⟩ = .product (.wire 560335) (.constant (536870912 : K))
  node_560339 : g.nodes ⟨560339, by omega⟩ = .linear (.wire 560334) (.wire 560338) false
  node_560340 : g.nodes ⟨560340, by omega⟩ = .bit (.wire 7215) 30
  node_560341 : g.nodes ⟨560341, by omega⟩ = .linear (.wire 560340) (.constant (1 : K)) true
  node_560342 : g.nodes ⟨560342, by omega⟩ = .product (.wire 560340) (.wire 560341)
  node_560343 : g.nodes ⟨560343, by omega⟩ = .product (.wire 560340) (.constant (1073741824 : K))
  node_560344 : g.nodes ⟨560344, by omega⟩ = .linear (.wire 560339) (.wire 560343) false
  node_560345 : g.nodes ⟨560345, by omega⟩ = .bit (.wire 7215) 31
  node_560346 : g.nodes ⟨560346, by omega⟩ = .linear (.wire 560345) (.constant (1 : K)) true
  node_560347 : g.nodes ⟨560347, by omega⟩ = .product (.wire 560345) (.wire 560346)
  node_560348 : g.nodes ⟨560348, by omega⟩ = .product (.wire 560345) (.constant (2147483648 : K))
  node_560349 : g.nodes ⟨560349, by omega⟩ = .linear (.wire 560344) (.wire 560348) false
  eq_0 : ((.wire 6935), (.constant (1 : K))) ∈ g.equalities
  eq_1 : ((.wire 458112), (.constant (0 : K))) ∈ g.equalities
  eq_2 : ((.wire 458115), (.constant (0 : K))) ∈ g.equalities
  eq_3 : ((.wire 458120), (.constant (0 : K))) ∈ g.equalities
  eq_4 : ((.wire 458125), (.constant (0 : K))) ∈ g.equalities
  eq_5 : ((.wire 458130), (.constant (0 : K))) ∈ g.equalities
  eq_6 : ((.wire 458135), (.constant (0 : K))) ∈ g.equalities
  eq_7 : ((.wire 458140), (.constant (0 : K))) ∈ g.equalities
  eq_8 : ((.wire 458145), (.constant (0 : K))) ∈ g.equalities
  eq_9 : ((.wire 458150), (.constant (0 : K))) ∈ g.equalities
  eq_10 : ((.wire 458155), (.constant (0 : K))) ∈ g.equalities
  eq_11 : ((.wire 458160), (.constant (0 : K))) ∈ g.equalities
  eq_12 : ((.wire 458165), (.constant (0 : K))) ∈ g.equalities
  eq_13 : ((.wire 458170), (.constant (0 : K))) ∈ g.equalities
  eq_14 : ((.wire 458175), (.constant (0 : K))) ∈ g.equalities
  eq_15 : ((.wire 458180), (.constant (0 : K))) ∈ g.equalities
  eq_16 : ((.wire 458185), (.constant (0 : K))) ∈ g.equalities
  eq_17 : ((.wire 458190), (.constant (0 : K))) ∈ g.equalities
  eq_18 : ((.wire 458195), (.constant (0 : K))) ∈ g.equalities
  eq_19 : ((.wire 458200), (.constant (0 : K))) ∈ g.equalities
  eq_20 : ((.wire 458205), (.constant (0 : K))) ∈ g.equalities
  eq_21 : ((.wire 458210), (.constant (0 : K))) ∈ g.equalities
  eq_22 : ((.wire 458215), (.constant (0 : K))) ∈ g.equalities
  eq_23 : ((.wire 458220), (.constant (0 : K))) ∈ g.equalities
  eq_24 : ((.wire 458225), (.constant (0 : K))) ∈ g.equalities
  eq_25 : ((.wire 458230), (.constant (0 : K))) ∈ g.equalities
  eq_26 : ((.wire 458235), (.constant (0 : K))) ∈ g.equalities
  eq_27 : ((.wire 458240), (.constant (0 : K))) ∈ g.equalities
  eq_28 : ((.wire 458245), (.constant (0 : K))) ∈ g.equalities
  eq_29 : ((.wire 458250), (.constant (0 : K))) ∈ g.equalities
  eq_30 : ((.wire 458255), (.constant (0 : K))) ∈ g.equalities
  eq_31 : ((.wire 458260), (.constant (0 : K))) ∈ g.equalities
  eq_32 : ((.wire 458265), (.constant (0 : K))) ∈ g.equalities
  eq_33 : ((.wire 6960), (.wire 458267)) ∈ g.equalities
  eq_34 : ((.wire 560194), (.constant (0 : K))) ∈ g.equalities
  eq_35 : ((.wire 560197), (.constant (0 : K))) ∈ g.equalities
  eq_36 : ((.wire 560202), (.constant (0 : K))) ∈ g.equalities
  eq_37 : ((.wire 560207), (.constant (0 : K))) ∈ g.equalities
  eq_38 : ((.wire 560212), (.constant (0 : K))) ∈ g.equalities
  eq_39 : ((.wire 560217), (.constant (0 : K))) ∈ g.equalities
  eq_40 : ((.wire 560222), (.constant (0 : K))) ∈ g.equalities
  eq_41 : ((.wire 560227), (.constant (0 : K))) ∈ g.equalities
  eq_42 : ((.wire 560232), (.constant (0 : K))) ∈ g.equalities
  eq_43 : ((.wire 560237), (.constant (0 : K))) ∈ g.equalities
  eq_44 : ((.wire 560242), (.constant (0 : K))) ∈ g.equalities
  eq_45 : ((.wire 560247), (.constant (0 : K))) ∈ g.equalities
  eq_46 : ((.wire 560252), (.constant (0 : K))) ∈ g.equalities
  eq_47 : ((.wire 560257), (.constant (0 : K))) ∈ g.equalities
  eq_48 : ((.wire 560262), (.constant (0 : K))) ∈ g.equalities
  eq_49 : ((.wire 560267), (.constant (0 : K))) ∈ g.equalities
  eq_50 : ((.wire 560272), (.constant (0 : K))) ∈ g.equalities
  eq_51 : ((.wire 560277), (.constant (0 : K))) ∈ g.equalities
  eq_52 : ((.wire 560282), (.constant (0 : K))) ∈ g.equalities
  eq_53 : ((.wire 560287), (.constant (0 : K))) ∈ g.equalities
  eq_54 : ((.wire 560292), (.constant (0 : K))) ∈ g.equalities
  eq_55 : ((.wire 560297), (.constant (0 : K))) ∈ g.equalities
  eq_56 : ((.wire 560302), (.constant (0 : K))) ∈ g.equalities
  eq_57 : ((.wire 560307), (.constant (0 : K))) ∈ g.equalities
  eq_58 : ((.wire 560312), (.constant (0 : K))) ∈ g.equalities
  eq_59 : ((.wire 560317), (.constant (0 : K))) ∈ g.equalities
  eq_60 : ((.wire 560322), (.constant (0 : K))) ∈ g.equalities
  eq_61 : ((.wire 560327), (.constant (0 : K))) ∈ g.equalities
  eq_62 : ((.wire 560332), (.constant (0 : K))) ∈ g.equalities
  eq_63 : ((.wire 560337), (.constant (0 : K))) ∈ g.equalities
  eq_64 : ((.wire 560342), (.constant (0 : K))) ∈ g.equalities
  eq_65 : ((.wire 560347), (.constant (0 : K))) ∈ g.equalities
  eq_66 : ((.wire 7215), (.wire 560349)) ∈ g.equalities

def currentModes : Fin 6 → Word K := ![(.wire 6913), (.wire 6914), (.wire 6915), (.wire 6916), (.wire 6917), (.wire 6918)]

def selector (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) (base : NativePrivateSpendCurrentFiniteConstructors.SliceFacts g count) : SelectorData g currentModes := {
  prefixes := ![(.constant (0 : K)), (.wire 6913), (.wire 6931), (.wire 6932), (.wire 6933), (.wire 6934), (.wire 6935)]
  start := rfl
  guards := Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_0 g count base) (Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_1 g count base) (Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_2 g count base) (Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_3 g count base) (Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_4 g count base) (Fin.cases (NativePrivateSpendCurrentFiniteConstructors.certificate_5 g count base) ((fun i => Fin.elim0 i)))))))
  add := by
    intro i
    fin_cases i
    · exact (by norm_num [AddData, NativePrivateSpendLocalSemantics.modulus] : AddData g (.constant (0 : K)) (.wire 6913) (.wire 6913))
    · exact (Or.inl ⟨⟨6931, by omega⟩, f.node_6931, rfl⟩ : AddData g (.wire 6913) (.wire 6914) (.wire 6931))
    · exact (Or.inl ⟨⟨6932, by omega⟩, f.node_6932, rfl⟩ : AddData g (.wire 6931) (.wire 6915) (.wire 6932))
    · exact (Or.inl ⟨⟨6933, by omega⟩, f.node_6933, rfl⟩ : AddData g (.wire 6932) (.wire 6916) (.wire 6933))
    · exact (Or.inl ⟨⟨6934, by omega⟩, f.node_6934, rfl⟩ : AddData g (.wire 6933) (.wire 6917) (.wire 6934))
    · exact (Or.inl ⟨⟨6935, by omega⟩, f.node_6935, rfl⟩ : AddData g (.wire 6934) (.wire 6918) (.wire 6935))
  finish := f.eq_0
}

def certificate_0 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458110) := {
  difference := (.wire 458111)
  product := (.wire 458112)
  subtract := Or.inl ⟨⟨458111, by omega⟩, f.node_458111, rfl⟩
  multiply := Or.inl ⟨⟨458112, by omega⟩, f.node_458112, rfl⟩
  zero := f.eq_1
}

def certificate_1 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458113) := {
  difference := (.wire 458114)
  product := (.wire 458115)
  subtract := Or.inl ⟨⟨458114, by omega⟩, f.node_458114, rfl⟩
  multiply := Or.inl ⟨⟨458115, by omega⟩, f.node_458115, rfl⟩
  zero := f.eq_2
}

def certificate_2 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458118) := {
  difference := (.wire 458119)
  product := (.wire 458120)
  subtract := Or.inl ⟨⟨458119, by omega⟩, f.node_458119, rfl⟩
  multiply := Or.inl ⟨⟨458120, by omega⟩, f.node_458120, rfl⟩
  zero := f.eq_3
}

def certificate_3 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458123) := {
  difference := (.wire 458124)
  product := (.wire 458125)
  subtract := Or.inl ⟨⟨458124, by omega⟩, f.node_458124, rfl⟩
  multiply := Or.inl ⟨⟨458125, by omega⟩, f.node_458125, rfl⟩
  zero := f.eq_4
}

def certificate_4 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458128) := {
  difference := (.wire 458129)
  product := (.wire 458130)
  subtract := Or.inl ⟨⟨458129, by omega⟩, f.node_458129, rfl⟩
  multiply := Or.inl ⟨⟨458130, by omega⟩, f.node_458130, rfl⟩
  zero := f.eq_5
}

def certificate_5 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458133) := {
  difference := (.wire 458134)
  product := (.wire 458135)
  subtract := Or.inl ⟨⟨458134, by omega⟩, f.node_458134, rfl⟩
  multiply := Or.inl ⟨⟨458135, by omega⟩, f.node_458135, rfl⟩
  zero := f.eq_6
}

def certificate_6 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458138) := {
  difference := (.wire 458139)
  product := (.wire 458140)
  subtract := Or.inl ⟨⟨458139, by omega⟩, f.node_458139, rfl⟩
  multiply := Or.inl ⟨⟨458140, by omega⟩, f.node_458140, rfl⟩
  zero := f.eq_7
}

def certificate_7 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458143) := {
  difference := (.wire 458144)
  product := (.wire 458145)
  subtract := Or.inl ⟨⟨458144, by omega⟩, f.node_458144, rfl⟩
  multiply := Or.inl ⟨⟨458145, by omega⟩, f.node_458145, rfl⟩
  zero := f.eq_8
}

def certificate_8 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458148) := {
  difference := (.wire 458149)
  product := (.wire 458150)
  subtract := Or.inl ⟨⟨458149, by omega⟩, f.node_458149, rfl⟩
  multiply := Or.inl ⟨⟨458150, by omega⟩, f.node_458150, rfl⟩
  zero := f.eq_9
}

def certificate_9 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458153) := {
  difference := (.wire 458154)
  product := (.wire 458155)
  subtract := Or.inl ⟨⟨458154, by omega⟩, f.node_458154, rfl⟩
  multiply := Or.inl ⟨⟨458155, by omega⟩, f.node_458155, rfl⟩
  zero := f.eq_10
}

def certificate_10 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458158) := {
  difference := (.wire 458159)
  product := (.wire 458160)
  subtract := Or.inl ⟨⟨458159, by omega⟩, f.node_458159, rfl⟩
  multiply := Or.inl ⟨⟨458160, by omega⟩, f.node_458160, rfl⟩
  zero := f.eq_11
}

def certificate_11 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458163) := {
  difference := (.wire 458164)
  product := (.wire 458165)
  subtract := Or.inl ⟨⟨458164, by omega⟩, f.node_458164, rfl⟩
  multiply := Or.inl ⟨⟨458165, by omega⟩, f.node_458165, rfl⟩
  zero := f.eq_12
}

def certificate_12 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458168) := {
  difference := (.wire 458169)
  product := (.wire 458170)
  subtract := Or.inl ⟨⟨458169, by omega⟩, f.node_458169, rfl⟩
  multiply := Or.inl ⟨⟨458170, by omega⟩, f.node_458170, rfl⟩
  zero := f.eq_13
}

def certificate_13 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458173) := {
  difference := (.wire 458174)
  product := (.wire 458175)
  subtract := Or.inl ⟨⟨458174, by omega⟩, f.node_458174, rfl⟩
  multiply := Or.inl ⟨⟨458175, by omega⟩, f.node_458175, rfl⟩
  zero := f.eq_14
}

def certificate_14 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458178) := {
  difference := (.wire 458179)
  product := (.wire 458180)
  subtract := Or.inl ⟨⟨458179, by omega⟩, f.node_458179, rfl⟩
  multiply := Or.inl ⟨⟨458180, by omega⟩, f.node_458180, rfl⟩
  zero := f.eq_15
}

def certificate_15 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458183) := {
  difference := (.wire 458184)
  product := (.wire 458185)
  subtract := Or.inl ⟨⟨458184, by omega⟩, f.node_458184, rfl⟩
  multiply := Or.inl ⟨⟨458185, by omega⟩, f.node_458185, rfl⟩
  zero := f.eq_16
}

def certificate_16 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458188) := {
  difference := (.wire 458189)
  product := (.wire 458190)
  subtract := Or.inl ⟨⟨458189, by omega⟩, f.node_458189, rfl⟩
  multiply := Or.inl ⟨⟨458190, by omega⟩, f.node_458190, rfl⟩
  zero := f.eq_17
}

def certificate_17 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458193) := {
  difference := (.wire 458194)
  product := (.wire 458195)
  subtract := Or.inl ⟨⟨458194, by omega⟩, f.node_458194, rfl⟩
  multiply := Or.inl ⟨⟨458195, by omega⟩, f.node_458195, rfl⟩
  zero := f.eq_18
}

def certificate_18 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458198) := {
  difference := (.wire 458199)
  product := (.wire 458200)
  subtract := Or.inl ⟨⟨458199, by omega⟩, f.node_458199, rfl⟩
  multiply := Or.inl ⟨⟨458200, by omega⟩, f.node_458200, rfl⟩
  zero := f.eq_19
}

def certificate_19 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458203) := {
  difference := (.wire 458204)
  product := (.wire 458205)
  subtract := Or.inl ⟨⟨458204, by omega⟩, f.node_458204, rfl⟩
  multiply := Or.inl ⟨⟨458205, by omega⟩, f.node_458205, rfl⟩
  zero := f.eq_20
}

def certificate_20 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458208) := {
  difference := (.wire 458209)
  product := (.wire 458210)
  subtract := Or.inl ⟨⟨458209, by omega⟩, f.node_458209, rfl⟩
  multiply := Or.inl ⟨⟨458210, by omega⟩, f.node_458210, rfl⟩
  zero := f.eq_21
}

def certificate_21 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458213) := {
  difference := (.wire 458214)
  product := (.wire 458215)
  subtract := Or.inl ⟨⟨458214, by omega⟩, f.node_458214, rfl⟩
  multiply := Or.inl ⟨⟨458215, by omega⟩, f.node_458215, rfl⟩
  zero := f.eq_22
}

def certificate_22 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458218) := {
  difference := (.wire 458219)
  product := (.wire 458220)
  subtract := Or.inl ⟨⟨458219, by omega⟩, f.node_458219, rfl⟩
  multiply := Or.inl ⟨⟨458220, by omega⟩, f.node_458220, rfl⟩
  zero := f.eq_23
}

def certificate_23 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458223) := {
  difference := (.wire 458224)
  product := (.wire 458225)
  subtract := Or.inl ⟨⟨458224, by omega⟩, f.node_458224, rfl⟩
  multiply := Or.inl ⟨⟨458225, by omega⟩, f.node_458225, rfl⟩
  zero := f.eq_24
}

def certificate_24 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458228) := {
  difference := (.wire 458229)
  product := (.wire 458230)
  subtract := Or.inl ⟨⟨458229, by omega⟩, f.node_458229, rfl⟩
  multiply := Or.inl ⟨⟨458230, by omega⟩, f.node_458230, rfl⟩
  zero := f.eq_25
}

def certificate_25 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458233) := {
  difference := (.wire 458234)
  product := (.wire 458235)
  subtract := Or.inl ⟨⟨458234, by omega⟩, f.node_458234, rfl⟩
  multiply := Or.inl ⟨⟨458235, by omega⟩, f.node_458235, rfl⟩
  zero := f.eq_26
}

def certificate_26 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458238) := {
  difference := (.wire 458239)
  product := (.wire 458240)
  subtract := Or.inl ⟨⟨458239, by omega⟩, f.node_458239, rfl⟩
  multiply := Or.inl ⟨⟨458240, by omega⟩, f.node_458240, rfl⟩
  zero := f.eq_27
}

def certificate_27 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458243) := {
  difference := (.wire 458244)
  product := (.wire 458245)
  subtract := Or.inl ⟨⟨458244, by omega⟩, f.node_458244, rfl⟩
  multiply := Or.inl ⟨⟨458245, by omega⟩, f.node_458245, rfl⟩
  zero := f.eq_28
}

def certificate_28 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458248) := {
  difference := (.wire 458249)
  product := (.wire 458250)
  subtract := Or.inl ⟨⟨458249, by omega⟩, f.node_458249, rfl⟩
  multiply := Or.inl ⟨⟨458250, by omega⟩, f.node_458250, rfl⟩
  zero := f.eq_29
}

def certificate_29 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458253) := {
  difference := (.wire 458254)
  product := (.wire 458255)
  subtract := Or.inl ⟨⟨458254, by omega⟩, f.node_458254, rfl⟩
  multiply := Or.inl ⟨⟨458255, by omega⟩, f.node_458255, rfl⟩
  zero := f.eq_30
}

def certificate_30 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458258) := {
  difference := (.wire 458259)
  product := (.wire 458260)
  subtract := Or.inl ⟨⟨458259, by omega⟩, f.node_458259, rfl⟩
  multiply := Or.inl ⟨⟨458260, by omega⟩, f.node_458260, rfl⟩
  zero := f.eq_31
}

def certificate_31 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 458263) := {
  difference := (.wire 458264)
  product := (.wire 458265)
  subtract := Or.inl ⟨⟨458264, by omega⟩, f.node_458264, rfl⟩
  multiply := Or.inl ⟨⟨458265, by omega⟩, f.node_458265, rfl⟩
  zero := f.eq_32
}

def positionRange0 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : RangeData g (.wire 6960) 32 := {
  bits := ![⟨458110, by omega⟩, ⟨458113, by omega⟩, ⟨458118, by omega⟩, ⟨458123, by omega⟩, ⟨458128, by omega⟩, ⟨458133, by omega⟩, ⟨458138, by omega⟩, ⟨458143, by omega⟩, ⟨458148, by omega⟩, ⟨458153, by omega⟩, ⟨458158, by omega⟩, ⟨458163, by omega⟩, ⟨458168, by omega⟩, ⟨458173, by omega⟩, ⟨458178, by omega⟩, ⟨458183, by omega⟩, ⟨458188, by omega⟩, ⟨458193, by omega⟩, ⟨458198, by omega⟩, ⟨458203, by omega⟩, ⟨458208, by omega⟩, ⟨458213, by omega⟩, ⟨458218, by omega⟩, ⟨458223, by omega⟩, ⟨458228, by omega⟩, ⟨458233, by omega⟩, ⟨458238, by omega⟩, ⟨458243, by omega⟩, ⟨458248, by omega⟩, ⟨458253, by omega⟩, ⟨458258, by omega⟩, ⟨458263, by omega⟩]
  isBit := by
    intro i
    fin_cases i
    · exact f.node_458110
    · exact f.node_458113
    · exact f.node_458118
    · exact f.node_458123
    · exact f.node_458128
    · exact f.node_458133
    · exact f.node_458138
    · exact f.node_458143
    · exact f.node_458148
    · exact f.node_458153
    · exact f.node_458158
    · exact f.node_458163
    · exact f.node_458168
    · exact f.node_458173
    · exact f.node_458178
    · exact f.node_458183
    · exact f.node_458188
    · exact f.node_458193
    · exact f.node_458198
    · exact f.node_458203
    · exact f.node_458208
    · exact f.node_458213
    · exact f.node_458218
    · exact f.node_458223
    · exact f.node_458228
    · exact f.node_458233
    · exact f.node_458238
    · exact f.node_458243
    · exact f.node_458248
    · exact f.node_458253
    · exact f.node_458258
    · exact f.node_458263
  guards := Fin.cases (certificate_0 g count f) (Fin.cases (certificate_1 g count f) (Fin.cases (certificate_2 g count f) (Fin.cases (certificate_3 g count f) (Fin.cases (certificate_4 g count f) (Fin.cases (certificate_5 g count f) (Fin.cases (certificate_6 g count f) (Fin.cases (certificate_7 g count f) (Fin.cases (certificate_8 g count f) (Fin.cases (certificate_9 g count f) (Fin.cases (certificate_10 g count f) (Fin.cases (certificate_11 g count f) (Fin.cases (certificate_12 g count f) (Fin.cases (certificate_13 g count f) (Fin.cases (certificate_14 g count f) (Fin.cases (certificate_15 g count f) (Fin.cases (certificate_16 g count f) (Fin.cases (certificate_17 g count f) (Fin.cases (certificate_18 g count f) (Fin.cases (certificate_19 g count f) (Fin.cases (certificate_20 g count f) (Fin.cases (certificate_21 g count f) (Fin.cases (certificate_22 g count f) (Fin.cases (certificate_23 g count f) (Fin.cases (certificate_24 g count f) (Fin.cases (certificate_25 g count f) (Fin.cases (certificate_26 g count f) (Fin.cases (certificate_27 g count f) (Fin.cases (certificate_28 g count f) (Fin.cases (certificate_29 g count f) (Fin.cases (certificate_30 g count f) (Fin.cases (certificate_31 g count f) ((fun i => Fin.elim0 i)))))))))))))))))))))))))))))))))
  scaled := ![(.wire 458110), (.wire 458116), (.wire 458121), (.wire 458126), (.wire 458131), (.wire 458136), (.wire 458141), (.wire 458146), (.wire 458151), (.wire 458156), (.wire 458161), (.wire 458166), (.wire 458171), (.wire 458176), (.wire 458181), (.wire 458186), (.wire 458191), (.wire 458196), (.wire 458201), (.wire 458206), (.wire 458211), (.wire 458216), (.wire 458221), (.wire 458226), (.wire 458231), (.wire 458236), (.wire 458241), (.wire 458246), (.wire 458251), (.wire 458256), (.wire 458261), (.wire 458266)]
  prefixes := ![(.constant (0 : K)), (.wire 458110), (.wire 458117), (.wire 458122), (.wire 458127), (.wire 458132), (.wire 458137), (.wire 458142), (.wire 458147), (.wire 458152), (.wire 458157), (.wire 458162), (.wire 458167), (.wire 458172), (.wire 458177), (.wire 458182), (.wire 458187), (.wire 458192), (.wire 458197), (.wire 458202), (.wire 458207), (.wire 458212), (.wire 458217), (.wire 458222), (.wire 458227), (.wire 458232), (.wire 458237), (.wire 458242), (.wire 458247), (.wire 458252), (.wire 458257), (.wire 458262), (.wire 458267)]
  start := rfl
  scale := by
    intro i
    fin_cases i
    · change MulData g (.wire 458110) (.constant ((2 : K)^0)) (.wire 458110)
      have power : (2 : K)^0 = (1 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus] : MulData g (.wire 458110) (.constant (1 : K)) (.wire 458110))
    · change MulData g (.wire 458113) (.constant ((2 : K)^1)) (.wire 458116)
      have power : (2 : K)^1 = (2 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458116, by omega⟩, f.node_458116, rfl⟩ : MulData g (.wire 458113) (.constant (2 : K)) (.wire 458116))
    · change MulData g (.wire 458118) (.constant ((2 : K)^2)) (.wire 458121)
      have power : (2 : K)^2 = (4 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458121, by omega⟩, f.node_458121, rfl⟩ : MulData g (.wire 458118) (.constant (4 : K)) (.wire 458121))
    · change MulData g (.wire 458123) (.constant ((2 : K)^3)) (.wire 458126)
      have power : (2 : K)^3 = (8 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458126, by omega⟩, f.node_458126, rfl⟩ : MulData g (.wire 458123) (.constant (8 : K)) (.wire 458126))
    · change MulData g (.wire 458128) (.constant ((2 : K)^4)) (.wire 458131)
      have power : (2 : K)^4 = (16 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458131, by omega⟩, f.node_458131, rfl⟩ : MulData g (.wire 458128) (.constant (16 : K)) (.wire 458131))
    · change MulData g (.wire 458133) (.constant ((2 : K)^5)) (.wire 458136)
      have power : (2 : K)^5 = (32 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458136, by omega⟩, f.node_458136, rfl⟩ : MulData g (.wire 458133) (.constant (32 : K)) (.wire 458136))
    · change MulData g (.wire 458138) (.constant ((2 : K)^6)) (.wire 458141)
      have power : (2 : K)^6 = (64 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458141, by omega⟩, f.node_458141, rfl⟩ : MulData g (.wire 458138) (.constant (64 : K)) (.wire 458141))
    · change MulData g (.wire 458143) (.constant ((2 : K)^7)) (.wire 458146)
      have power : (2 : K)^7 = (128 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458146, by omega⟩, f.node_458146, rfl⟩ : MulData g (.wire 458143) (.constant (128 : K)) (.wire 458146))
    · change MulData g (.wire 458148) (.constant ((2 : K)^8)) (.wire 458151)
      have power : (2 : K)^8 = (256 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458151, by omega⟩, f.node_458151, rfl⟩ : MulData g (.wire 458148) (.constant (256 : K)) (.wire 458151))
    · change MulData g (.wire 458153) (.constant ((2 : K)^9)) (.wire 458156)
      have power : (2 : K)^9 = (512 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458156, by omega⟩, f.node_458156, rfl⟩ : MulData g (.wire 458153) (.constant (512 : K)) (.wire 458156))
    · change MulData g (.wire 458158) (.constant ((2 : K)^10)) (.wire 458161)
      have power : (2 : K)^10 = (1024 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458161, by omega⟩, f.node_458161, rfl⟩ : MulData g (.wire 458158) (.constant (1024 : K)) (.wire 458161))
    · change MulData g (.wire 458163) (.constant ((2 : K)^11)) (.wire 458166)
      have power : (2 : K)^11 = (2048 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458166, by omega⟩, f.node_458166, rfl⟩ : MulData g (.wire 458163) (.constant (2048 : K)) (.wire 458166))
    · change MulData g (.wire 458168) (.constant ((2 : K)^12)) (.wire 458171)
      have power : (2 : K)^12 = (4096 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458171, by omega⟩, f.node_458171, rfl⟩ : MulData g (.wire 458168) (.constant (4096 : K)) (.wire 458171))
    · change MulData g (.wire 458173) (.constant ((2 : K)^13)) (.wire 458176)
      have power : (2 : K)^13 = (8192 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458176, by omega⟩, f.node_458176, rfl⟩ : MulData g (.wire 458173) (.constant (8192 : K)) (.wire 458176))
    · change MulData g (.wire 458178) (.constant ((2 : K)^14)) (.wire 458181)
      have power : (2 : K)^14 = (16384 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458181, by omega⟩, f.node_458181, rfl⟩ : MulData g (.wire 458178) (.constant (16384 : K)) (.wire 458181))
    · change MulData g (.wire 458183) (.constant ((2 : K)^15)) (.wire 458186)
      have power : (2 : K)^15 = (32768 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458186, by omega⟩, f.node_458186, rfl⟩ : MulData g (.wire 458183) (.constant (32768 : K)) (.wire 458186))
    · change MulData g (.wire 458188) (.constant ((2 : K)^16)) (.wire 458191)
      have power : (2 : K)^16 = (65536 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458191, by omega⟩, f.node_458191, rfl⟩ : MulData g (.wire 458188) (.constant (65536 : K)) (.wire 458191))
    · change MulData g (.wire 458193) (.constant ((2 : K)^17)) (.wire 458196)
      have power : (2 : K)^17 = (131072 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458196, by omega⟩, f.node_458196, rfl⟩ : MulData g (.wire 458193) (.constant (131072 : K)) (.wire 458196))
    · change MulData g (.wire 458198) (.constant ((2 : K)^18)) (.wire 458201)
      have power : (2 : K)^18 = (262144 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458201, by omega⟩, f.node_458201, rfl⟩ : MulData g (.wire 458198) (.constant (262144 : K)) (.wire 458201))
    · change MulData g (.wire 458203) (.constant ((2 : K)^19)) (.wire 458206)
      have power : (2 : K)^19 = (524288 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458206, by omega⟩, f.node_458206, rfl⟩ : MulData g (.wire 458203) (.constant (524288 : K)) (.wire 458206))
    · change MulData g (.wire 458208) (.constant ((2 : K)^20)) (.wire 458211)
      have power : (2 : K)^20 = (1048576 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458211, by omega⟩, f.node_458211, rfl⟩ : MulData g (.wire 458208) (.constant (1048576 : K)) (.wire 458211))
    · change MulData g (.wire 458213) (.constant ((2 : K)^21)) (.wire 458216)
      have power : (2 : K)^21 = (2097152 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458216, by omega⟩, f.node_458216, rfl⟩ : MulData g (.wire 458213) (.constant (2097152 : K)) (.wire 458216))
    · change MulData g (.wire 458218) (.constant ((2 : K)^22)) (.wire 458221)
      have power : (2 : K)^22 = (4194304 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458221, by omega⟩, f.node_458221, rfl⟩ : MulData g (.wire 458218) (.constant (4194304 : K)) (.wire 458221))
    · change MulData g (.wire 458223) (.constant ((2 : K)^23)) (.wire 458226)
      have power : (2 : K)^23 = (8388608 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458226, by omega⟩, f.node_458226, rfl⟩ : MulData g (.wire 458223) (.constant (8388608 : K)) (.wire 458226))
    · change MulData g (.wire 458228) (.constant ((2 : K)^24)) (.wire 458231)
      have power : (2 : K)^24 = (16777216 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458231, by omega⟩, f.node_458231, rfl⟩ : MulData g (.wire 458228) (.constant (16777216 : K)) (.wire 458231))
    · change MulData g (.wire 458233) (.constant ((2 : K)^25)) (.wire 458236)
      have power : (2 : K)^25 = (33554432 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458236, by omega⟩, f.node_458236, rfl⟩ : MulData g (.wire 458233) (.constant (33554432 : K)) (.wire 458236))
    · change MulData g (.wire 458238) (.constant ((2 : K)^26)) (.wire 458241)
      have power : (2 : K)^26 = (67108864 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458241, by omega⟩, f.node_458241, rfl⟩ : MulData g (.wire 458238) (.constant (67108864 : K)) (.wire 458241))
    · change MulData g (.wire 458243) (.constant ((2 : K)^27)) (.wire 458246)
      have power : (2 : K)^27 = (134217728 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458246, by omega⟩, f.node_458246, rfl⟩ : MulData g (.wire 458243) (.constant (134217728 : K)) (.wire 458246))
    · change MulData g (.wire 458248) (.constant ((2 : K)^28)) (.wire 458251)
      have power : (2 : K)^28 = (268435456 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458251, by omega⟩, f.node_458251, rfl⟩ : MulData g (.wire 458248) (.constant (268435456 : K)) (.wire 458251))
    · change MulData g (.wire 458253) (.constant ((2 : K)^29)) (.wire 458256)
      have power : (2 : K)^29 = (536870912 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458256, by omega⟩, f.node_458256, rfl⟩ : MulData g (.wire 458253) (.constant (536870912 : K)) (.wire 458256))
    · change MulData g (.wire 458258) (.constant ((2 : K)^30)) (.wire 458261)
      have power : (2 : K)^30 = (1073741824 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458261, by omega⟩, f.node_458261, rfl⟩ : MulData g (.wire 458258) (.constant (1073741824 : K)) (.wire 458261))
    · change MulData g (.wire 458263) (.constant ((2 : K)^31)) (.wire 458266)
      have power : (2 : K)^31 = (2147483648 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨458266, by omega⟩, f.node_458266, rfl⟩ : MulData g (.wire 458263) (.constant (2147483648 : K)) (.wire 458266))
  accumulate := by
    intro i
    fin_cases i
    · exact by norm_num [AddData, NativePrivateSpendLocalSemantics.modulus]
    · exact Or.inl ⟨⟨458117, by omega⟩, f.node_458117, rfl⟩
    · exact Or.inl ⟨⟨458122, by omega⟩, f.node_458122, rfl⟩
    · exact Or.inl ⟨⟨458127, by omega⟩, f.node_458127, rfl⟩
    · exact Or.inl ⟨⟨458132, by omega⟩, f.node_458132, rfl⟩
    · exact Or.inl ⟨⟨458137, by omega⟩, f.node_458137, rfl⟩
    · exact Or.inl ⟨⟨458142, by omega⟩, f.node_458142, rfl⟩
    · exact Or.inl ⟨⟨458147, by omega⟩, f.node_458147, rfl⟩
    · exact Or.inl ⟨⟨458152, by omega⟩, f.node_458152, rfl⟩
    · exact Or.inl ⟨⟨458157, by omega⟩, f.node_458157, rfl⟩
    · exact Or.inl ⟨⟨458162, by omega⟩, f.node_458162, rfl⟩
    · exact Or.inl ⟨⟨458167, by omega⟩, f.node_458167, rfl⟩
    · exact Or.inl ⟨⟨458172, by omega⟩, f.node_458172, rfl⟩
    · exact Or.inl ⟨⟨458177, by omega⟩, f.node_458177, rfl⟩
    · exact Or.inl ⟨⟨458182, by omega⟩, f.node_458182, rfl⟩
    · exact Or.inl ⟨⟨458187, by omega⟩, f.node_458187, rfl⟩
    · exact Or.inl ⟨⟨458192, by omega⟩, f.node_458192, rfl⟩
    · exact Or.inl ⟨⟨458197, by omega⟩, f.node_458197, rfl⟩
    · exact Or.inl ⟨⟨458202, by omega⟩, f.node_458202, rfl⟩
    · exact Or.inl ⟨⟨458207, by omega⟩, f.node_458207, rfl⟩
    · exact Or.inl ⟨⟨458212, by omega⟩, f.node_458212, rfl⟩
    · exact Or.inl ⟨⟨458217, by omega⟩, f.node_458217, rfl⟩
    · exact Or.inl ⟨⟨458222, by omega⟩, f.node_458222, rfl⟩
    · exact Or.inl ⟨⟨458227, by omega⟩, f.node_458227, rfl⟩
    · exact Or.inl ⟨⟨458232, by omega⟩, f.node_458232, rfl⟩
    · exact Or.inl ⟨⟨458237, by omega⟩, f.node_458237, rfl⟩
    · exact Or.inl ⟨⟨458242, by omega⟩, f.node_458242, rfl⟩
    · exact Or.inl ⟨⟨458247, by omega⟩, f.node_458247, rfl⟩
    · exact Or.inl ⟨⟨458252, by omega⟩, f.node_458252, rfl⟩
    · exact Or.inl ⟨⟨458257, by omega⟩, f.node_458257, rfl⟩
    · exact Or.inl ⟨⟨458262, by omega⟩, f.node_458262, rfl⟩
    · exact Or.inl ⟨⟨458267, by omega⟩, f.node_458267, rfl⟩
  finish := f.eq_33
}

def certificate_32 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560192) := {
  difference := (.wire 560193)
  product := (.wire 560194)
  subtract := Or.inl ⟨⟨560193, by omega⟩, f.node_560193, rfl⟩
  multiply := Or.inl ⟨⟨560194, by omega⟩, f.node_560194, rfl⟩
  zero := f.eq_34
}

def certificate_33 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560195) := {
  difference := (.wire 560196)
  product := (.wire 560197)
  subtract := Or.inl ⟨⟨560196, by omega⟩, f.node_560196, rfl⟩
  multiply := Or.inl ⟨⟨560197, by omega⟩, f.node_560197, rfl⟩
  zero := f.eq_35
}

def certificate_34 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560200) := {
  difference := (.wire 560201)
  product := (.wire 560202)
  subtract := Or.inl ⟨⟨560201, by omega⟩, f.node_560201, rfl⟩
  multiply := Or.inl ⟨⟨560202, by omega⟩, f.node_560202, rfl⟩
  zero := f.eq_36
}

def certificate_35 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560205) := {
  difference := (.wire 560206)
  product := (.wire 560207)
  subtract := Or.inl ⟨⟨560206, by omega⟩, f.node_560206, rfl⟩
  multiply := Or.inl ⟨⟨560207, by omega⟩, f.node_560207, rfl⟩
  zero := f.eq_37
}

def certificate_36 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560210) := {
  difference := (.wire 560211)
  product := (.wire 560212)
  subtract := Or.inl ⟨⟨560211, by omega⟩, f.node_560211, rfl⟩
  multiply := Or.inl ⟨⟨560212, by omega⟩, f.node_560212, rfl⟩
  zero := f.eq_38
}

def certificate_37 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560215) := {
  difference := (.wire 560216)
  product := (.wire 560217)
  subtract := Or.inl ⟨⟨560216, by omega⟩, f.node_560216, rfl⟩
  multiply := Or.inl ⟨⟨560217, by omega⟩, f.node_560217, rfl⟩
  zero := f.eq_39
}

def certificate_38 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560220) := {
  difference := (.wire 560221)
  product := (.wire 560222)
  subtract := Or.inl ⟨⟨560221, by omega⟩, f.node_560221, rfl⟩
  multiply := Or.inl ⟨⟨560222, by omega⟩, f.node_560222, rfl⟩
  zero := f.eq_40
}

def certificate_39 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560225) := {
  difference := (.wire 560226)
  product := (.wire 560227)
  subtract := Or.inl ⟨⟨560226, by omega⟩, f.node_560226, rfl⟩
  multiply := Or.inl ⟨⟨560227, by omega⟩, f.node_560227, rfl⟩
  zero := f.eq_41
}

def certificate_40 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560230) := {
  difference := (.wire 560231)
  product := (.wire 560232)
  subtract := Or.inl ⟨⟨560231, by omega⟩, f.node_560231, rfl⟩
  multiply := Or.inl ⟨⟨560232, by omega⟩, f.node_560232, rfl⟩
  zero := f.eq_42
}

def certificate_41 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560235) := {
  difference := (.wire 560236)
  product := (.wire 560237)
  subtract := Or.inl ⟨⟨560236, by omega⟩, f.node_560236, rfl⟩
  multiply := Or.inl ⟨⟨560237, by omega⟩, f.node_560237, rfl⟩
  zero := f.eq_43
}

def certificate_42 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560240) := {
  difference := (.wire 560241)
  product := (.wire 560242)
  subtract := Or.inl ⟨⟨560241, by omega⟩, f.node_560241, rfl⟩
  multiply := Or.inl ⟨⟨560242, by omega⟩, f.node_560242, rfl⟩
  zero := f.eq_44
}

def certificate_43 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560245) := {
  difference := (.wire 560246)
  product := (.wire 560247)
  subtract := Or.inl ⟨⟨560246, by omega⟩, f.node_560246, rfl⟩
  multiply := Or.inl ⟨⟨560247, by omega⟩, f.node_560247, rfl⟩
  zero := f.eq_45
}

def certificate_44 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560250) := {
  difference := (.wire 560251)
  product := (.wire 560252)
  subtract := Or.inl ⟨⟨560251, by omega⟩, f.node_560251, rfl⟩
  multiply := Or.inl ⟨⟨560252, by omega⟩, f.node_560252, rfl⟩
  zero := f.eq_46
}

def certificate_45 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560255) := {
  difference := (.wire 560256)
  product := (.wire 560257)
  subtract := Or.inl ⟨⟨560256, by omega⟩, f.node_560256, rfl⟩
  multiply := Or.inl ⟨⟨560257, by omega⟩, f.node_560257, rfl⟩
  zero := f.eq_47
}

def certificate_46 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560260) := {
  difference := (.wire 560261)
  product := (.wire 560262)
  subtract := Or.inl ⟨⟨560261, by omega⟩, f.node_560261, rfl⟩
  multiply := Or.inl ⟨⟨560262, by omega⟩, f.node_560262, rfl⟩
  zero := f.eq_48
}

def certificate_47 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560265) := {
  difference := (.wire 560266)
  product := (.wire 560267)
  subtract := Or.inl ⟨⟨560266, by omega⟩, f.node_560266, rfl⟩
  multiply := Or.inl ⟨⟨560267, by omega⟩, f.node_560267, rfl⟩
  zero := f.eq_49
}

def certificate_48 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560270) := {
  difference := (.wire 560271)
  product := (.wire 560272)
  subtract := Or.inl ⟨⟨560271, by omega⟩, f.node_560271, rfl⟩
  multiply := Or.inl ⟨⟨560272, by omega⟩, f.node_560272, rfl⟩
  zero := f.eq_50
}

def certificate_49 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560275) := {
  difference := (.wire 560276)
  product := (.wire 560277)
  subtract := Or.inl ⟨⟨560276, by omega⟩, f.node_560276, rfl⟩
  multiply := Or.inl ⟨⟨560277, by omega⟩, f.node_560277, rfl⟩
  zero := f.eq_51
}

def certificate_50 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560280) := {
  difference := (.wire 560281)
  product := (.wire 560282)
  subtract := Or.inl ⟨⟨560281, by omega⟩, f.node_560281, rfl⟩
  multiply := Or.inl ⟨⟨560282, by omega⟩, f.node_560282, rfl⟩
  zero := f.eq_52
}

def certificate_51 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560285) := {
  difference := (.wire 560286)
  product := (.wire 560287)
  subtract := Or.inl ⟨⟨560286, by omega⟩, f.node_560286, rfl⟩
  multiply := Or.inl ⟨⟨560287, by omega⟩, f.node_560287, rfl⟩
  zero := f.eq_53
}

def certificate_52 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560290) := {
  difference := (.wire 560291)
  product := (.wire 560292)
  subtract := Or.inl ⟨⟨560291, by omega⟩, f.node_560291, rfl⟩
  multiply := Or.inl ⟨⟨560292, by omega⟩, f.node_560292, rfl⟩
  zero := f.eq_54
}

def certificate_53 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560295) := {
  difference := (.wire 560296)
  product := (.wire 560297)
  subtract := Or.inl ⟨⟨560296, by omega⟩, f.node_560296, rfl⟩
  multiply := Or.inl ⟨⟨560297, by omega⟩, f.node_560297, rfl⟩
  zero := f.eq_55
}

def certificate_54 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560300) := {
  difference := (.wire 560301)
  product := (.wire 560302)
  subtract := Or.inl ⟨⟨560301, by omega⟩, f.node_560301, rfl⟩
  multiply := Or.inl ⟨⟨560302, by omega⟩, f.node_560302, rfl⟩
  zero := f.eq_56
}

def certificate_55 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560305) := {
  difference := (.wire 560306)
  product := (.wire 560307)
  subtract := Or.inl ⟨⟨560306, by omega⟩, f.node_560306, rfl⟩
  multiply := Or.inl ⟨⟨560307, by omega⟩, f.node_560307, rfl⟩
  zero := f.eq_57
}

def certificate_56 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560310) := {
  difference := (.wire 560311)
  product := (.wire 560312)
  subtract := Or.inl ⟨⟨560311, by omega⟩, f.node_560311, rfl⟩
  multiply := Or.inl ⟨⟨560312, by omega⟩, f.node_560312, rfl⟩
  zero := f.eq_58
}

def certificate_57 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560315) := {
  difference := (.wire 560316)
  product := (.wire 560317)
  subtract := Or.inl ⟨⟨560316, by omega⟩, f.node_560316, rfl⟩
  multiply := Or.inl ⟨⟨560317, by omega⟩, f.node_560317, rfl⟩
  zero := f.eq_59
}

def certificate_58 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560320) := {
  difference := (.wire 560321)
  product := (.wire 560322)
  subtract := Or.inl ⟨⟨560321, by omega⟩, f.node_560321, rfl⟩
  multiply := Or.inl ⟨⟨560322, by omega⟩, f.node_560322, rfl⟩
  zero := f.eq_60
}

def certificate_59 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560325) := {
  difference := (.wire 560326)
  product := (.wire 560327)
  subtract := Or.inl ⟨⟨560326, by omega⟩, f.node_560326, rfl⟩
  multiply := Or.inl ⟨⟨560327, by omega⟩, f.node_560327, rfl⟩
  zero := f.eq_61
}

def certificate_60 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560330) := {
  difference := (.wire 560331)
  product := (.wire 560332)
  subtract := Or.inl ⟨⟨560331, by omega⟩, f.node_560331, rfl⟩
  multiply := Or.inl ⟨⟨560332, by omega⟩, f.node_560332, rfl⟩
  zero := f.eq_62
}

def certificate_61 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560335) := {
  difference := (.wire 560336)
  product := (.wire 560337)
  subtract := Or.inl ⟨⟨560336, by omega⟩, f.node_560336, rfl⟩
  multiply := Or.inl ⟨⟨560337, by omega⟩, f.node_560337, rfl⟩
  zero := f.eq_63
}

def certificate_62 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560340) := {
  difference := (.wire 560341)
  product := (.wire 560342)
  subtract := Or.inl ⟨⟨560341, by omega⟩, f.node_560341, rfl⟩
  multiply := Or.inl ⟨⟨560342, by omega⟩, f.node_560342, rfl⟩
  zero := f.eq_64
}

def certificate_63 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : BooleanData g (.wire 560345) := {
  difference := (.wire 560346)
  product := (.wire 560347)
  subtract := Or.inl ⟨⟨560346, by omega⟩, f.node_560346, rfl⟩
  multiply := Or.inl ⟨⟨560347, by omega⟩, f.node_560347, rfl⟩
  zero := f.eq_65
}

def positionRange1 (g : Graph K) (count : g.count = 676622) (f : SliceFacts g count) : RangeData g (.wire 7215) 32 := {
  bits := ![⟨560192, by omega⟩, ⟨560195, by omega⟩, ⟨560200, by omega⟩, ⟨560205, by omega⟩, ⟨560210, by omega⟩, ⟨560215, by omega⟩, ⟨560220, by omega⟩, ⟨560225, by omega⟩, ⟨560230, by omega⟩, ⟨560235, by omega⟩, ⟨560240, by omega⟩, ⟨560245, by omega⟩, ⟨560250, by omega⟩, ⟨560255, by omega⟩, ⟨560260, by omega⟩, ⟨560265, by omega⟩, ⟨560270, by omega⟩, ⟨560275, by omega⟩, ⟨560280, by omega⟩, ⟨560285, by omega⟩, ⟨560290, by omega⟩, ⟨560295, by omega⟩, ⟨560300, by omega⟩, ⟨560305, by omega⟩, ⟨560310, by omega⟩, ⟨560315, by omega⟩, ⟨560320, by omega⟩, ⟨560325, by omega⟩, ⟨560330, by omega⟩, ⟨560335, by omega⟩, ⟨560340, by omega⟩, ⟨560345, by omega⟩]
  isBit := by
    intro i
    fin_cases i
    · exact f.node_560192
    · exact f.node_560195
    · exact f.node_560200
    · exact f.node_560205
    · exact f.node_560210
    · exact f.node_560215
    · exact f.node_560220
    · exact f.node_560225
    · exact f.node_560230
    · exact f.node_560235
    · exact f.node_560240
    · exact f.node_560245
    · exact f.node_560250
    · exact f.node_560255
    · exact f.node_560260
    · exact f.node_560265
    · exact f.node_560270
    · exact f.node_560275
    · exact f.node_560280
    · exact f.node_560285
    · exact f.node_560290
    · exact f.node_560295
    · exact f.node_560300
    · exact f.node_560305
    · exact f.node_560310
    · exact f.node_560315
    · exact f.node_560320
    · exact f.node_560325
    · exact f.node_560330
    · exact f.node_560335
    · exact f.node_560340
    · exact f.node_560345
  guards := Fin.cases (certificate_32 g count f) (Fin.cases (certificate_33 g count f) (Fin.cases (certificate_34 g count f) (Fin.cases (certificate_35 g count f) (Fin.cases (certificate_36 g count f) (Fin.cases (certificate_37 g count f) (Fin.cases (certificate_38 g count f) (Fin.cases (certificate_39 g count f) (Fin.cases (certificate_40 g count f) (Fin.cases (certificate_41 g count f) (Fin.cases (certificate_42 g count f) (Fin.cases (certificate_43 g count f) (Fin.cases (certificate_44 g count f) (Fin.cases (certificate_45 g count f) (Fin.cases (certificate_46 g count f) (Fin.cases (certificate_47 g count f) (Fin.cases (certificate_48 g count f) (Fin.cases (certificate_49 g count f) (Fin.cases (certificate_50 g count f) (Fin.cases (certificate_51 g count f) (Fin.cases (certificate_52 g count f) (Fin.cases (certificate_53 g count f) (Fin.cases (certificate_54 g count f) (Fin.cases (certificate_55 g count f) (Fin.cases (certificate_56 g count f) (Fin.cases (certificate_57 g count f) (Fin.cases (certificate_58 g count f) (Fin.cases (certificate_59 g count f) (Fin.cases (certificate_60 g count f) (Fin.cases (certificate_61 g count f) (Fin.cases (certificate_62 g count f) (Fin.cases (certificate_63 g count f) ((fun i => Fin.elim0 i)))))))))))))))))))))))))))))))))
  scaled := ![(.wire 560192), (.wire 560198), (.wire 560203), (.wire 560208), (.wire 560213), (.wire 560218), (.wire 560223), (.wire 560228), (.wire 560233), (.wire 560238), (.wire 560243), (.wire 560248), (.wire 560253), (.wire 560258), (.wire 560263), (.wire 560268), (.wire 560273), (.wire 560278), (.wire 560283), (.wire 560288), (.wire 560293), (.wire 560298), (.wire 560303), (.wire 560308), (.wire 560313), (.wire 560318), (.wire 560323), (.wire 560328), (.wire 560333), (.wire 560338), (.wire 560343), (.wire 560348)]
  prefixes := ![(.constant (0 : K)), (.wire 560192), (.wire 560199), (.wire 560204), (.wire 560209), (.wire 560214), (.wire 560219), (.wire 560224), (.wire 560229), (.wire 560234), (.wire 560239), (.wire 560244), (.wire 560249), (.wire 560254), (.wire 560259), (.wire 560264), (.wire 560269), (.wire 560274), (.wire 560279), (.wire 560284), (.wire 560289), (.wire 560294), (.wire 560299), (.wire 560304), (.wire 560309), (.wire 560314), (.wire 560319), (.wire 560324), (.wire 560329), (.wire 560334), (.wire 560339), (.wire 560344), (.wire 560349)]
  start := rfl
  scale := by
    intro i
    fin_cases i
    · change MulData g (.wire 560192) (.constant ((2 : K)^0)) (.wire 560192)
      have power : (2 : K)^0 = (1 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (by norm_num [MulData, NativePrivateSpendLocalSemantics.modulus] : MulData g (.wire 560192) (.constant (1 : K)) (.wire 560192))
    · change MulData g (.wire 560195) (.constant ((2 : K)^1)) (.wire 560198)
      have power : (2 : K)^1 = (2 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560198, by omega⟩, f.node_560198, rfl⟩ : MulData g (.wire 560195) (.constant (2 : K)) (.wire 560198))
    · change MulData g (.wire 560200) (.constant ((2 : K)^2)) (.wire 560203)
      have power : (2 : K)^2 = (4 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560203, by omega⟩, f.node_560203, rfl⟩ : MulData g (.wire 560200) (.constant (4 : K)) (.wire 560203))
    · change MulData g (.wire 560205) (.constant ((2 : K)^3)) (.wire 560208)
      have power : (2 : K)^3 = (8 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560208, by omega⟩, f.node_560208, rfl⟩ : MulData g (.wire 560205) (.constant (8 : K)) (.wire 560208))
    · change MulData g (.wire 560210) (.constant ((2 : K)^4)) (.wire 560213)
      have power : (2 : K)^4 = (16 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560213, by omega⟩, f.node_560213, rfl⟩ : MulData g (.wire 560210) (.constant (16 : K)) (.wire 560213))
    · change MulData g (.wire 560215) (.constant ((2 : K)^5)) (.wire 560218)
      have power : (2 : K)^5 = (32 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560218, by omega⟩, f.node_560218, rfl⟩ : MulData g (.wire 560215) (.constant (32 : K)) (.wire 560218))
    · change MulData g (.wire 560220) (.constant ((2 : K)^6)) (.wire 560223)
      have power : (2 : K)^6 = (64 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560223, by omega⟩, f.node_560223, rfl⟩ : MulData g (.wire 560220) (.constant (64 : K)) (.wire 560223))
    · change MulData g (.wire 560225) (.constant ((2 : K)^7)) (.wire 560228)
      have power : (2 : K)^7 = (128 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560228, by omega⟩, f.node_560228, rfl⟩ : MulData g (.wire 560225) (.constant (128 : K)) (.wire 560228))
    · change MulData g (.wire 560230) (.constant ((2 : K)^8)) (.wire 560233)
      have power : (2 : K)^8 = (256 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560233, by omega⟩, f.node_560233, rfl⟩ : MulData g (.wire 560230) (.constant (256 : K)) (.wire 560233))
    · change MulData g (.wire 560235) (.constant ((2 : K)^9)) (.wire 560238)
      have power : (2 : K)^9 = (512 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560238, by omega⟩, f.node_560238, rfl⟩ : MulData g (.wire 560235) (.constant (512 : K)) (.wire 560238))
    · change MulData g (.wire 560240) (.constant ((2 : K)^10)) (.wire 560243)
      have power : (2 : K)^10 = (1024 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560243, by omega⟩, f.node_560243, rfl⟩ : MulData g (.wire 560240) (.constant (1024 : K)) (.wire 560243))
    · change MulData g (.wire 560245) (.constant ((2 : K)^11)) (.wire 560248)
      have power : (2 : K)^11 = (2048 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560248, by omega⟩, f.node_560248, rfl⟩ : MulData g (.wire 560245) (.constant (2048 : K)) (.wire 560248))
    · change MulData g (.wire 560250) (.constant ((2 : K)^12)) (.wire 560253)
      have power : (2 : K)^12 = (4096 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560253, by omega⟩, f.node_560253, rfl⟩ : MulData g (.wire 560250) (.constant (4096 : K)) (.wire 560253))
    · change MulData g (.wire 560255) (.constant ((2 : K)^13)) (.wire 560258)
      have power : (2 : K)^13 = (8192 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560258, by omega⟩, f.node_560258, rfl⟩ : MulData g (.wire 560255) (.constant (8192 : K)) (.wire 560258))
    · change MulData g (.wire 560260) (.constant ((2 : K)^14)) (.wire 560263)
      have power : (2 : K)^14 = (16384 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560263, by omega⟩, f.node_560263, rfl⟩ : MulData g (.wire 560260) (.constant (16384 : K)) (.wire 560263))
    · change MulData g (.wire 560265) (.constant ((2 : K)^15)) (.wire 560268)
      have power : (2 : K)^15 = (32768 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560268, by omega⟩, f.node_560268, rfl⟩ : MulData g (.wire 560265) (.constant (32768 : K)) (.wire 560268))
    · change MulData g (.wire 560270) (.constant ((2 : K)^16)) (.wire 560273)
      have power : (2 : K)^16 = (65536 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560273, by omega⟩, f.node_560273, rfl⟩ : MulData g (.wire 560270) (.constant (65536 : K)) (.wire 560273))
    · change MulData g (.wire 560275) (.constant ((2 : K)^17)) (.wire 560278)
      have power : (2 : K)^17 = (131072 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560278, by omega⟩, f.node_560278, rfl⟩ : MulData g (.wire 560275) (.constant (131072 : K)) (.wire 560278))
    · change MulData g (.wire 560280) (.constant ((2 : K)^18)) (.wire 560283)
      have power : (2 : K)^18 = (262144 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560283, by omega⟩, f.node_560283, rfl⟩ : MulData g (.wire 560280) (.constant (262144 : K)) (.wire 560283))
    · change MulData g (.wire 560285) (.constant ((2 : K)^19)) (.wire 560288)
      have power : (2 : K)^19 = (524288 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560288, by omega⟩, f.node_560288, rfl⟩ : MulData g (.wire 560285) (.constant (524288 : K)) (.wire 560288))
    · change MulData g (.wire 560290) (.constant ((2 : K)^20)) (.wire 560293)
      have power : (2 : K)^20 = (1048576 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560293, by omega⟩, f.node_560293, rfl⟩ : MulData g (.wire 560290) (.constant (1048576 : K)) (.wire 560293))
    · change MulData g (.wire 560295) (.constant ((2 : K)^21)) (.wire 560298)
      have power : (2 : K)^21 = (2097152 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560298, by omega⟩, f.node_560298, rfl⟩ : MulData g (.wire 560295) (.constant (2097152 : K)) (.wire 560298))
    · change MulData g (.wire 560300) (.constant ((2 : K)^22)) (.wire 560303)
      have power : (2 : K)^22 = (4194304 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560303, by omega⟩, f.node_560303, rfl⟩ : MulData g (.wire 560300) (.constant (4194304 : K)) (.wire 560303))
    · change MulData g (.wire 560305) (.constant ((2 : K)^23)) (.wire 560308)
      have power : (2 : K)^23 = (8388608 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560308, by omega⟩, f.node_560308, rfl⟩ : MulData g (.wire 560305) (.constant (8388608 : K)) (.wire 560308))
    · change MulData g (.wire 560310) (.constant ((2 : K)^24)) (.wire 560313)
      have power : (2 : K)^24 = (16777216 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560313, by omega⟩, f.node_560313, rfl⟩ : MulData g (.wire 560310) (.constant (16777216 : K)) (.wire 560313))
    · change MulData g (.wire 560315) (.constant ((2 : K)^25)) (.wire 560318)
      have power : (2 : K)^25 = (33554432 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560318, by omega⟩, f.node_560318, rfl⟩ : MulData g (.wire 560315) (.constant (33554432 : K)) (.wire 560318))
    · change MulData g (.wire 560320) (.constant ((2 : K)^26)) (.wire 560323)
      have power : (2 : K)^26 = (67108864 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560323, by omega⟩, f.node_560323, rfl⟩ : MulData g (.wire 560320) (.constant (67108864 : K)) (.wire 560323))
    · change MulData g (.wire 560325) (.constant ((2 : K)^27)) (.wire 560328)
      have power : (2 : K)^27 = (134217728 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560328, by omega⟩, f.node_560328, rfl⟩ : MulData g (.wire 560325) (.constant (134217728 : K)) (.wire 560328))
    · change MulData g (.wire 560330) (.constant ((2 : K)^28)) (.wire 560333)
      have power : (2 : K)^28 = (268435456 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560333, by omega⟩, f.node_560333, rfl⟩ : MulData g (.wire 560330) (.constant (268435456 : K)) (.wire 560333))
    · change MulData g (.wire 560335) (.constant ((2 : K)^29)) (.wire 560338)
      have power : (2 : K)^29 = (536870912 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560338, by omega⟩, f.node_560338, rfl⟩ : MulData g (.wire 560335) (.constant (536870912 : K)) (.wire 560338))
    · change MulData g (.wire 560340) (.constant ((2 : K)^30)) (.wire 560343)
      have power : (2 : K)^30 = (1073741824 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560343, by omega⟩, f.node_560343, rfl⟩ : MulData g (.wire 560340) (.constant (1073741824 : K)) (.wire 560343))
    · change MulData g (.wire 560345) (.constant ((2 : K)^31)) (.wire 560348)
      have power : (2 : K)^31 = (2147483648 : K) := by norm_num [NativePrivateSpendLocalSemantics.modulus]
      rw [power]
      exact (Or.inl ⟨⟨560348, by omega⟩, f.node_560348, rfl⟩ : MulData g (.wire 560345) (.constant (2147483648 : K)) (.wire 560348))
  accumulate := by
    intro i
    fin_cases i
    · exact by norm_num [AddData, NativePrivateSpendLocalSemantics.modulus]
    · exact Or.inl ⟨⟨560199, by omega⟩, f.node_560199, rfl⟩
    · exact Or.inl ⟨⟨560204, by omega⟩, f.node_560204, rfl⟩
    · exact Or.inl ⟨⟨560209, by omega⟩, f.node_560209, rfl⟩
    · exact Or.inl ⟨⟨560214, by omega⟩, f.node_560214, rfl⟩
    · exact Or.inl ⟨⟨560219, by omega⟩, f.node_560219, rfl⟩
    · exact Or.inl ⟨⟨560224, by omega⟩, f.node_560224, rfl⟩
    · exact Or.inl ⟨⟨560229, by omega⟩, f.node_560229, rfl⟩
    · exact Or.inl ⟨⟨560234, by omega⟩, f.node_560234, rfl⟩
    · exact Or.inl ⟨⟨560239, by omega⟩, f.node_560239, rfl⟩
    · exact Or.inl ⟨⟨560244, by omega⟩, f.node_560244, rfl⟩
    · exact Or.inl ⟨⟨560249, by omega⟩, f.node_560249, rfl⟩
    · exact Or.inl ⟨⟨560254, by omega⟩, f.node_560254, rfl⟩
    · exact Or.inl ⟨⟨560259, by omega⟩, f.node_560259, rfl⟩
    · exact Or.inl ⟨⟨560264, by omega⟩, f.node_560264, rfl⟩
    · exact Or.inl ⟨⟨560269, by omega⟩, f.node_560269, rfl⟩
    · exact Or.inl ⟨⟨560274, by omega⟩, f.node_560274, rfl⟩
    · exact Or.inl ⟨⟨560279, by omega⟩, f.node_560279, rfl⟩
    · exact Or.inl ⟨⟨560284, by omega⟩, f.node_560284, rfl⟩
    · exact Or.inl ⟨⟨560289, by omega⟩, f.node_560289, rfl⟩
    · exact Or.inl ⟨⟨560294, by omega⟩, f.node_560294, rfl⟩
    · exact Or.inl ⟨⟨560299, by omega⟩, f.node_560299, rfl⟩
    · exact Or.inl ⟨⟨560304, by omega⟩, f.node_560304, rfl⟩
    · exact Or.inl ⟨⟨560309, by omega⟩, f.node_560309, rfl⟩
    · exact Or.inl ⟨⟨560314, by omega⟩, f.node_560314, rfl⟩
    · exact Or.inl ⟨⟨560319, by omega⟩, f.node_560319, rfl⟩
    · exact Or.inl ⟨⟨560324, by omega⟩, f.node_560324, rfl⟩
    · exact Or.inl ⟨⟨560329, by omega⟩, f.node_560329, rfl⟩
    · exact Or.inl ⟨⟨560334, by omega⟩, f.node_560334, rfl⟩
    · exact Or.inl ⟨⟨560339, by omega⟩, f.node_560339, rfl⟩
    · exact Or.inl ⟨⟨560344, by omega⟩, f.node_560344, rfl⟩
    · exact Or.inl ⟨⟨560349, by omega⟩, f.node_560349, rfl⟩
  finish := f.eq_66
}

end
end HegemonCrypto.NativePrivateSpendCurrentSelectorRanges
