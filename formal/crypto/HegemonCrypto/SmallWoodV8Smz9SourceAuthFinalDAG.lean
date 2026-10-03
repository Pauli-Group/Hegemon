import HegemonCrypto.SmallWoodV8Smz9SourceAuthMoreDAG
namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section
theorem actual_root_257 (pub rows : Nat → F) :
    (exactNonlinearRoots[257]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * ((rows 76) - (rows 117))) := by
  rw [show exactNonlinearRoots[257]? = some 1424 by decide, Option.map_some]
  have e200 := actual_node_field_equation pub rows (show exactNonlinearExpressions[200]? = some (.witnessRow 76) by decide)
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e241 := actual_node_field_equation pub rows (show exactNonlinearExpressions[241]? = some (.witnessRow 117) by decide)
  have e1423 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1423]? = some (.sub 200 241) by decide)
  have e1424 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1424]? = some (.mul 217 1423) by decide)
  simp only [expressionField] at e200 e217 e241 e1423 e1424
  rw [e1423, e241, e217, e200] at e1424
  exact congrArg some e1424

theorem actual_root_258 (pub rows : Nat → F) :
    (exactNonlinearRoots[258]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * ((rows 77) - (rows 118))) := by
  rw [show exactNonlinearRoots[258]? = some 1426 by decide, Option.map_some]
  have e201 := actual_node_field_equation pub rows (show exactNonlinearExpressions[201]? = some (.witnessRow 77) by decide)
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e242 := actual_node_field_equation pub rows (show exactNonlinearExpressions[242]? = some (.witnessRow 118) by decide)
  have e1425 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1425]? = some (.sub 201 242) by decide)
  have e1426 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1426]? = some (.mul 217 1425) by decide)
  simp only [expressionField] at e201 e217 e242 e1425 e1426
  rw [e1425, e242, e217, e201] at e1426
  exact congrArg some e1426

theorem actual_root_259 (pub rows : Nat → F) :
    (exactNonlinearRoots[259]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * ((rows 78) - (rows 119))) := by
  rw [show exactNonlinearRoots[259]? = some 1428 by decide, Option.map_some]
  have e202 := actual_node_field_equation pub rows (show exactNonlinearExpressions[202]? = some (.witnessRow 78) by decide)
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e243 := actual_node_field_equation pub rows (show exactNonlinearExpressions[243]? = some (.witnessRow 119) by decide)
  have e1427 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1427]? = some (.sub 202 243) by decide)
  have e1428 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1428]? = some (.mul 217 1427) by decide)
  simp only [expressionField] at e202 e217 e243 e1427 e1428
  rw [e1427, e243, e217, e202] at e1428
  exact congrArg some e1428

theorem actual_root_260 (pub rows : Nat → F) :
    (exactNonlinearRoots[260]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * ((rows 79) - (rows 120))) := by
  rw [show exactNonlinearRoots[260]? = some 1430 by decide, Option.map_some]
  have e203 := actual_node_field_equation pub rows (show exactNonlinearExpressions[203]? = some (.witnessRow 79) by decide)
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e244 := actual_node_field_equation pub rows (show exactNonlinearExpressions[244]? = some (.witnessRow 120) by decide)
  have e1429 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1429]? = some (.sub 203 244) by decide)
  have e1430 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1430]? = some (.mul 217 1429) by decide)
  simp only [expressionField] at e203 e217 e244 e1429 e1430
  rw [e1429, e244, e217, e203] at e1430
  exact congrArg some e1430

theorem actual_root_310 (pub rows : Nat → F) :
    (exactNonlinearRoots[310]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (((rows 93) + (rows 94)) * ((rows 154) - ((rows 160) + ((rows 159) + ((rows 158) + ((rows 157) + ((rows 155) + (rows 156)))))))) := by
  rw [show exactNonlinearRoots[310]? = some 1656 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e278 := actual_node_field_equation pub rows (show exactNonlinearExpressions[278]? = some (.witnessRow 154) by decide)
  have e279 := actual_node_field_equation pub rows (show exactNonlinearExpressions[279]? = some (.witnessRow 155) by decide)
  have e280 := actual_node_field_equation pub rows (show exactNonlinearExpressions[280]? = some (.witnessRow 156) by decide)
  have e281 := actual_node_field_equation pub rows (show exactNonlinearExpressions[281]? = some (.witnessRow 157) by decide)
  have e282 := actual_node_field_equation pub rows (show exactNonlinearExpressions[282]? = some (.witnessRow 158) by decide)
  have e283 := actual_node_field_equation pub rows (show exactNonlinearExpressions[283]? = some (.witnessRow 159) by decide)
  have e284 := actual_node_field_equation pub rows (show exactNonlinearExpressions[284]? = some (.witnessRow 160) by decide)
  have e1234 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1650 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1650]? = some (.add 279 280) by decide)
  have e1651 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1651]? = some (.add 281 1650) by decide)
  have e1652 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1652]? = some (.add 282 1651) by decide)
  have e1653 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1653]? = some (.add 283 1652) by decide)
  have e1654 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1654]? = some (.add 284 1653) by decide)
  have e1655 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1655]? = some (.sub 278 1654) by decide)
  have e1656 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1656]? = some (.mul 1234 1655) by decide)
  simp only [expressionField] at e217 e218 e278 e279 e280 e281 e282 e283 e284 e1234 e1650 e1651 e1652 e1653 e1654 e1655 e1656
  rw [e1655, e1654, e1653, e1652, e1651, e1650, e1234, e284, e283, e282, e281, e280, e279, e278, e218, e217] at e1656
  exact congrArg some e1656

theorem actual_root_323 (pub rows : Nat → F) :
    (exactNonlinearRoots[323]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * ((rows 161) - ((rows 167) + ((rows 166) + ((rows 165) + ((rows 164) + ((rows 162) + (rows 163)))))))) := by
  rw [show exactNonlinearRoots[323]? = some 1693 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e285 := actual_node_field_equation pub rows (show exactNonlinearExpressions[285]? = some (.witnessRow 161) by decide)
  have e286 := actual_node_field_equation pub rows (show exactNonlinearExpressions[286]? = some (.witnessRow 162) by decide)
  have e287 := actual_node_field_equation pub rows (show exactNonlinearExpressions[287]? = some (.witnessRow 163) by decide)
  have e288 := actual_node_field_equation pub rows (show exactNonlinearExpressions[288]? = some (.witnessRow 164) by decide)
  have e289 := actual_node_field_equation pub rows (show exactNonlinearExpressions[289]? = some (.witnessRow 165) by decide)
  have e290 := actual_node_field_equation pub rows (show exactNonlinearExpressions[290]? = some (.witnessRow 166) by decide)
  have e291 := actual_node_field_equation pub rows (show exactNonlinearExpressions[291]? = some (.witnessRow 167) by decide)
  have e1687 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1687]? = some (.add 286 287) by decide)
  have e1688 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1688]? = some (.add 288 1687) by decide)
  have e1689 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1689]? = some (.add 289 1688) by decide)
  have e1690 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1690]? = some (.add 290 1689) by decide)
  have e1691 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1691]? = some (.add 291 1690) by decide)
  have e1692 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1692]? = some (.sub 285 1691) by decide)
  have e1693 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1693]? = some (.mul 217 1692) by decide)
  simp only [expressionField] at e217 e285 e286 e287 e288 e289 e290 e291 e1687 e1688 e1689 e1690 e1691 e1692 e1693
  rw [e1692, e1691, e1690, e1689, e1688, e1687, e291, e290, e289, e288, e287, e286, e285, e217] at e1693
  exact congrArg some e1693

theorem actual_root_324 (pub rows : Nat → F) :
    (exactNonlinearRoots[324]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 155) * ((rows 93) * (rows 226))) := by
  rw [show exactNonlinearRoots[324]? = some 1695 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e279 := actual_node_field_equation pub rows (show exactNonlinearExpressions[279]? = some (.witnessRow 155) by decide)
  have e350 := actual_node_field_equation pub rows (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1695 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1695]? = some (.mul 279 1694) by decide)
  simp only [expressionField] at e217 e279 e350 e1694 e1695
  rw [e1694, e350, e279, e217] at e1695
  exact congrArg some e1695

theorem actual_root_325 (pub rows : Nat → F) :
    (exactNonlinearRoots[325]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 162) - (rows 155)) - (rows 226))) := by
  rw [show exactNonlinearRoots[325]? = some 1698 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e279 := actual_node_field_equation pub rows (show exactNonlinearExpressions[279]? = some (.witnessRow 155) by decide)
  have e286 := actual_node_field_equation pub rows (show exactNonlinearExpressions[286]? = some (.witnessRow 162) by decide)
  have e350 := actual_node_field_equation pub rows (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1696 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1696]? = some (.sub 286 279) by decide)
  have e1697 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1697]? = some (.sub 1696 350) by decide)
  have e1698 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1698]? = some (.mul 217 1697) by decide)
  simp only [expressionField] at e217 e279 e286 e350 e1696 e1697 e1698
  rw [e1697, e1696, e350, e286, e279, e217] at e1698
  exact congrArg some e1698

theorem actual_root_326 (pub rows : Nat → F) :
    (exactNonlinearRoots[326]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 156) * ((rows 93) * (rows 227))) := by
  rw [show exactNonlinearRoots[326]? = some 1700 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e280 := actual_node_field_equation pub rows (show exactNonlinearExpressions[280]? = some (.witnessRow 156) by decide)
  have e351 := actual_node_field_equation pub rows (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1700 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1700]? = some (.mul 280 1699) by decide)
  simp only [expressionField] at e217 e280 e351 e1699 e1700
  rw [e1699, e351, e280, e217] at e1700
  exact congrArg some e1700

theorem actual_root_327 (pub rows : Nat → F) :
    (exactNonlinearRoots[327]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 163) - (rows 156)) - (rows 227))) := by
  rw [show exactNonlinearRoots[327]? = some 1703 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e280 := actual_node_field_equation pub rows (show exactNonlinearExpressions[280]? = some (.witnessRow 156) by decide)
  have e287 := actual_node_field_equation pub rows (show exactNonlinearExpressions[287]? = some (.witnessRow 163) by decide)
  have e351 := actual_node_field_equation pub rows (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1701 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1701]? = some (.sub 287 280) by decide)
  have e1702 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1702]? = some (.sub 1701 351) by decide)
  have e1703 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1703]? = some (.mul 217 1702) by decide)
  simp only [expressionField] at e217 e280 e287 e351 e1701 e1702 e1703
  rw [e1702, e1701, e351, e287, e280, e217] at e1703
  exact congrArg some e1703

theorem actual_root_328 (pub rows : Nat → F) :
    (exactNonlinearRoots[328]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 157) * ((rows 93) * (rows 228))) := by
  rw [show exactNonlinearRoots[328]? = some 1705 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e281 := actual_node_field_equation pub rows (show exactNonlinearExpressions[281]? = some (.witnessRow 157) by decide)
  have e352 := actual_node_field_equation pub rows (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1705 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1705]? = some (.mul 281 1704) by decide)
  simp only [expressionField] at e217 e281 e352 e1704 e1705
  rw [e1704, e352, e281, e217] at e1705
  exact congrArg some e1705

theorem actual_root_329 (pub rows : Nat → F) :
    (exactNonlinearRoots[329]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 164) - (rows 157)) - (rows 228))) := by
  rw [show exactNonlinearRoots[329]? = some 1708 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e281 := actual_node_field_equation pub rows (show exactNonlinearExpressions[281]? = some (.witnessRow 157) by decide)
  have e288 := actual_node_field_equation pub rows (show exactNonlinearExpressions[288]? = some (.witnessRow 164) by decide)
  have e352 := actual_node_field_equation pub rows (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1706 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1706]? = some (.sub 288 281) by decide)
  have e1707 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1707]? = some (.sub 1706 352) by decide)
  have e1708 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1708]? = some (.mul 217 1707) by decide)
  simp only [expressionField] at e217 e281 e288 e352 e1706 e1707 e1708
  rw [e1707, e1706, e352, e288, e281, e217] at e1708
  exact congrArg some e1708

theorem actual_root_330 (pub rows : Nat → F) :
    (exactNonlinearRoots[330]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 158) * ((rows 93) * (rows 229))) := by
  rw [show exactNonlinearRoots[330]? = some 1710 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e282 := actual_node_field_equation pub rows (show exactNonlinearExpressions[282]? = some (.witnessRow 158) by decide)
  have e353 := actual_node_field_equation pub rows (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1710 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1710]? = some (.mul 282 1709) by decide)
  simp only [expressionField] at e217 e282 e353 e1709 e1710
  rw [e1709, e353, e282, e217] at e1710
  exact congrArg some e1710

theorem actual_root_331 (pub rows : Nat → F) :
    (exactNonlinearRoots[331]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 165) - (rows 158)) - (rows 229))) := by
  rw [show exactNonlinearRoots[331]? = some 1713 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e282 := actual_node_field_equation pub rows (show exactNonlinearExpressions[282]? = some (.witnessRow 158) by decide)
  have e289 := actual_node_field_equation pub rows (show exactNonlinearExpressions[289]? = some (.witnessRow 165) by decide)
  have e353 := actual_node_field_equation pub rows (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1711 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1711]? = some (.sub 289 282) by decide)
  have e1712 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1712]? = some (.sub 1711 353) by decide)
  have e1713 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1713]? = some (.mul 217 1712) by decide)
  simp only [expressionField] at e217 e282 e289 e353 e1711 e1712 e1713
  rw [e1712, e1711, e353, e289, e282, e217] at e1713
  exact congrArg some e1713

theorem actual_root_332 (pub rows : Nat → F) :
    (exactNonlinearRoots[332]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 159) * ((rows 93) * (rows 230))) := by
  rw [show exactNonlinearRoots[332]? = some 1715 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e283 := actual_node_field_equation pub rows (show exactNonlinearExpressions[283]? = some (.witnessRow 159) by decide)
  have e354 := actual_node_field_equation pub rows (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1715 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1715]? = some (.mul 283 1714) by decide)
  simp only [expressionField] at e217 e283 e354 e1714 e1715
  rw [e1714, e354, e283, e217] at e1715
  exact congrArg some e1715

theorem actual_root_333 (pub rows : Nat → F) :
    (exactNonlinearRoots[333]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 166) - (rows 159)) - (rows 230))) := by
  rw [show exactNonlinearRoots[333]? = some 1718 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e283 := actual_node_field_equation pub rows (show exactNonlinearExpressions[283]? = some (.witnessRow 159) by decide)
  have e290 := actual_node_field_equation pub rows (show exactNonlinearExpressions[290]? = some (.witnessRow 166) by decide)
  have e354 := actual_node_field_equation pub rows (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1716 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1716]? = some (.sub 290 283) by decide)
  have e1717 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1717]? = some (.sub 1716 354) by decide)
  have e1718 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1718]? = some (.mul 217 1717) by decide)
  simp only [expressionField] at e217 e283 e290 e354 e1716 e1717 e1718
  rw [e1717, e1716, e354, e290, e283, e217] at e1718
  exact congrArg some e1718

theorem actual_root_334 (pub rows : Nat → F) :
    (exactNonlinearRoots[334]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 160) * ((rows 93) * (rows 231))) := by
  rw [show exactNonlinearRoots[334]? = some 1720 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e284 := actual_node_field_equation pub rows (show exactNonlinearExpressions[284]? = some (.witnessRow 160) by decide)
  have e355 := actual_node_field_equation pub rows (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1720 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1720]? = some (.mul 284 1719) by decide)
  simp only [expressionField] at e217 e284 e355 e1719 e1720
  rw [e1719, e355, e284, e217] at e1720
  exact congrArg some e1720

theorem actual_root_335 (pub rows : Nat → F) :
    (exactNonlinearRoots[335]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 167) - (rows 160)) - (rows 231))) := by
  rw [show exactNonlinearRoots[335]? = some 1723 by decide, Option.map_some]
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e284 := actual_node_field_equation pub rows (show exactNonlinearExpressions[284]? = some (.witnessRow 160) by decide)
  have e291 := actual_node_field_equation pub rows (show exactNonlinearExpressions[291]? = some (.witnessRow 167) by decide)
  have e355 := actual_node_field_equation pub rows (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1721 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1721]? = some (.sub 291 284) by decide)
  have e1722 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1722]? = some (.sub 1721 355) by decide)
  have e1723 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1723]? = some (.mul 217 1722) by decide)
  simp only [expressionField] at e217 e284 e291 e355 e1721 e1722 e1723
  rw [e1722, e1721, e355, e291, e284, e217] at e1723
  exact congrArg some e1723

theorem actual_root_344 (pub rows : Nat → F) :
    (exactNonlinearRoots[344]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93) * (((rows 231) + ((rows 230) + ((rows 229) + ((rows 228) + ((rows 226) + (rows 227)))))) - 1)) := by
  rw [show exactNonlinearRoots[344]? = some 1750 by decide, Option.map_some]
  have e1 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e350 := actual_node_field_equation pub rows (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e351 := actual_node_field_equation pub rows (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e352 := actual_node_field_equation pub rows (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e353 := actual_node_field_equation pub rows (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e354 := actual_node_field_equation pub rows (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e355 := actual_node_field_equation pub rows (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1744 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1744]? = some (.add 350 351) by decide)
  have e1745 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1745]? = some (.add 352 1744) by decide)
  have e1746 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1746]? = some (.add 353 1745) by decide)
  have e1747 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1747]? = some (.add 354 1746) by decide)
  have e1748 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1748]? = some (.add 355 1747) by decide)
  have e1749 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1749]? = some (.sub 1748 1) by decide)
  have e1750 := actual_node_field_equation pub rows (show exactNonlinearExpressions[1750]? = some (.mul 217 1749) by decide)
  simp only [expressionField, Nat.cast_one] at e1 e217 e350 e351 e352 e353 e354 e355 e1744 e1745 e1746 e1747 e1748 e1749 e1750
  rw [e1749, e1748, e1747, e1746, e1745, e1744, e355, e354, e353, e352, e351, e350, e217, e1] at e1750
  exact congrArg some e1750

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalDAG
