import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_root_298 (pub rows : Nat → F) :
    (exactNonlinearRoots[298]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 155 * (rows 155 - 1))) := by
  rw [show exactNonlinearRoots[298]? = some 1606 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e279 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[279]? = some (.witnessRow 155) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1604 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1604]? = some (.sub 279 1) by decide)
  have e1605 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1605]? = some (.mul 279 1604) by decide)
  have e1606 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1606]? = some (.mul 1234 1605) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e279 e1234 e1604 e1605 e1606
  rw [e1605,e1604,e1234,e279,e218,e217,e1] at e1606
  exact congrArg some e1606

theorem actual_root_300 (pub rows : Nat → F) :
    (exactNonlinearRoots[300]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 156 * (rows 156 - 1))) := by
  rw [show exactNonlinearRoots[300]? = some 1612 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e280 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[280]? = some (.witnessRow 156) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1610 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1610]? = some (.sub 280 1) by decide)
  have e1611 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1611]? = some (.mul 280 1610) by decide)
  have e1612 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1612]? = some (.mul 1234 1611) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e280 e1234 e1610 e1611 e1612
  rw [e1611,e1610,e1234,e280,e218,e217,e1] at e1612
  exact congrArg some e1612

theorem actual_root_302 (pub rows : Nat → F) :
    (exactNonlinearRoots[302]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 157 * (rows 157 - 1))) := by
  rw [show exactNonlinearRoots[302]? = some 1622 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e281 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[281]? = some (.witnessRow 157) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1620 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1620]? = some (.sub 281 1) by decide)
  have e1621 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1621]? = some (.mul 281 1620) by decide)
  have e1622 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1622]? = some (.mul 1234 1621) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e281 e1234 e1620 e1621 e1622
  rw [e1621,e1620,e1234,e281,e218,e217,e1] at e1622
  exact congrArg some e1622

theorem actual_root_304 (pub rows : Nat → F) :
    (exactNonlinearRoots[304]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 158 * (rows 158 - 1))) := by
  rw [show exactNonlinearRoots[304]? = some 1631 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e282 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[282]? = some (.witnessRow 158) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1629 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1629]? = some (.sub 282 1) by decide)
  have e1630 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1630]? = some (.mul 282 1629) by decide)
  have e1631 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1631]? = some (.mul 1234 1630) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e282 e1234 e1629 e1630 e1631
  rw [e1630,e1629,e1234,e282,e218,e217,e1] at e1631
  exact congrArg some e1631

theorem actual_root_306 (pub rows : Nat → F) :
    (exactNonlinearRoots[306]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 159 * (rows 159 - 1))) := by
  rw [show exactNonlinearRoots[306]? = some 1639 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e283 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[283]? = some (.witnessRow 159) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1637 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1637]? = some (.sub 283 1) by decide)
  have e1638 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1638]? = some (.mul 283 1637) by decide)
  have e1639 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1639]? = some (.mul 1234 1638) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e283 e1234 e1637 e1638 e1639
  rw [e1638,e1637,e1234,e283,e218,e217,e1] at e1639
  exact congrArg some e1639

theorem actual_root_308 (pub rows : Nat → F) :
    (exactNonlinearRoots[308]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 160 * (rows 160 - 1))) := by
  rw [show exactNonlinearRoots[308]? = some 1646 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e284 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[284]? = some (.witnessRow 160) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1644 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1644]? = some (.sub 284 1) by decide)
  have e1645 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1645]? = some (.mul 284 1644) by decide)
  have e1646 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1646]? = some (.mul 1234 1645) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e284 e1234 e1644 e1645 e1646
  rw [e1645,e1644,e1234,e284,e218,e217,e1] at e1646
  exact congrArg some e1646

theorem actual_root_311 (pub rows : Nat → F) :
    (exactNonlinearRoots[311]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 162 * (rows 162 - 1))) := by
  rw [show exactNonlinearRoots[311]? = some 1659 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e286 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[286]? = some (.witnessRow 162) by decide)
  have e1657 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1657]? = some (.sub 286 1) by decide)
  have e1658 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1658]? = some (.mul 286 1657) by decide)
  have e1659 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1659]? = some (.mul 217 1658) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e286 e1657 e1658 e1659
  rw [e1658,e1657,e286,e217,e1] at e1659
  exact congrArg some e1659

theorem actual_root_313 (pub rows : Nat → F) :
    (exactNonlinearRoots[313]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 163 * (rows 163 - 1))) := by
  rw [show exactNonlinearRoots[313]? = some 1664 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e287 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[287]? = some (.witnessRow 163) by decide)
  have e1662 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1662]? = some (.sub 287 1) by decide)
  have e1663 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1663]? = some (.mul 287 1662) by decide)
  have e1664 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1664]? = some (.mul 217 1663) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e287 e1662 e1663 e1664
  rw [e1663,e1662,e287,e217,e1] at e1664
  exact congrArg some e1664

theorem actual_root_315 (pub rows : Nat → F) :
    (exactNonlinearRoots[315]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 164 * (rows 164 - 1))) := by
  rw [show exactNonlinearRoots[315]? = some 1669 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e288 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[288]? = some (.witnessRow 164) by decide)
  have e1667 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1667]? = some (.sub 288 1) by decide)
  have e1668 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1668]? = some (.mul 288 1667) by decide)
  have e1669 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1669]? = some (.mul 217 1668) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e288 e1667 e1668 e1669
  rw [e1668,e1667,e288,e217,e1] at e1669
  exact congrArg some e1669

theorem actual_root_317 (pub rows : Nat → F) :
    (exactNonlinearRoots[317]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 165 * (rows 165 - 1))) := by
  rw [show exactNonlinearRoots[317]? = some 1674 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e289 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[289]? = some (.witnessRow 165) by decide)
  have e1672 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1672]? = some (.sub 289 1) by decide)
  have e1673 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1673]? = some (.mul 289 1672) by decide)
  have e1674 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1674]? = some (.mul 217 1673) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e289 e1672 e1673 e1674
  rw [e1673,e1672,e289,e217,e1] at e1674
  exact congrArg some e1674

theorem actual_root_319 (pub rows : Nat → F) :
    (exactNonlinearRoots[319]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 166 * (rows 166 - 1))) := by
  rw [show exactNonlinearRoots[319]? = some 1679 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e290 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[290]? = some (.witnessRow 166) by decide)
  have e1677 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1677]? = some (.sub 290 1) by decide)
  have e1678 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1678]? = some (.mul 290 1677) by decide)
  have e1679 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1679]? = some (.mul 217 1678) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e290 e1677 e1678 e1679
  rw [e1678,e1677,e290,e217,e1] at e1679
  exact congrArg some e1679

theorem actual_root_321 (pub rows : Nat → F) :
    (exactNonlinearRoots[321]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 167 * (rows 167 - 1))) := by
  rw [show exactNonlinearRoots[321]? = some 1684 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e291 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[291]? = some (.witnessRow 167) by decide)
  have e1682 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1682]? = some (.sub 291 1) by decide)
  have e1683 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1683]? = some (.mul 291 1682) by decide)
  have e1684 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1684]? = some (.mul 217 1683) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e291 e1682 e1683 e1684
  rw [e1683,e1682,e291,e217,e1] at e1684
  exact congrArg some e1684

theorem actual_root_346 (pub rows : Nat → F) :
    (exactNonlinearRoots[346]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 226) * (rows 105 - rows 196)) := by
  rw [show exactNonlinearRoots[346]? = some 1753 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1752 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1752]? = some (.sub 229 320) by decide)
  have e1753 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1753]? = some (.mul 1694 1752) by decide)
  simp only [expressionField] at e217 e229 e320 e350 e1694 e1752 e1753
  rw [e1752,e1694,e350,e320,e229,e217] at e1753
  exact congrArg some e1753

theorem actual_root_347 (pub rows : Nat → F) :
    (exactNonlinearRoots[347]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 226) * (rows 106 - rows 197)) := by
  rw [show exactNonlinearRoots[347]? = some 1755 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e321 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[321]? = some (.witnessRow 197) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1754 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1754]? = some (.sub 230 321) by decide)
  have e1755 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1755]? = some (.mul 1694 1754) by decide)
  simp only [expressionField] at e217 e230 e321 e350 e1694 e1754 e1755
  rw [e1754,e1694,e350,e321,e230,e217] at e1755
  exact congrArg some e1755

theorem actual_root_348 (pub rows : Nat → F) :
    (exactNonlinearRoots[348]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 226) * (rows 107 - rows 198)) := by
  rw [show exactNonlinearRoots[348]? = some 1757 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e322 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[322]? = some (.witnessRow 198) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1756 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1756]? = some (.sub 231 322) by decide)
  have e1757 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1757]? = some (.mul 1694 1756) by decide)
  simp only [expressionField] at e217 e231 e322 e350 e1694 e1756 e1757
  rw [e1756,e1694,e350,e322,e231,e217] at e1757
  exact congrArg some e1757

theorem actual_root_349 (pub rows : Nat → F) :
    (exactNonlinearRoots[349]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 226) * (rows 108 - rows 199)) := by
  rw [show exactNonlinearRoots[349]? = some 1759 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e323 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[323]? = some (.witnessRow 199) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1758 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1758]? = some (.sub 232 323) by decide)
  have e1759 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1759]? = some (.mul 1694 1758) by decide)
  simp only [expressionField] at e217 e232 e323 e350 e1694 e1758 e1759
  rw [e1758,e1694,e350,e323,e232,e217] at e1759
  exact congrArg some e1759

theorem actual_root_350 (pub rows : Nat → F) :
    (exactNonlinearRoots[350]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 226) * (rows 109 - rows 200)) := by
  rw [show exactNonlinearRoots[350]? = some 1761 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e324 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[324]? = some (.witnessRow 200) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1760 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1760]? = some (.sub 233 324) by decide)
  have e1761 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1761]? = some (.mul 1694 1760) by decide)
  simp only [expressionField] at e217 e233 e324 e350 e1694 e1760 e1761
  rw [e1760,e1694,e350,e324,e233,e217] at e1761
  exact congrArg some e1761

theorem actual_root_352 (pub rows : Nat → F) :
    (exactNonlinearRoots[352]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 227) * (rows 105 - rows 201)) := by
  rw [show exactNonlinearRoots[352]? = some 1764 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1763 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1763]? = some (.sub 229 325) by decide)
  have e1764 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1764]? = some (.mul 1699 1763) by decide)
  simp only [expressionField] at e217 e229 e325 e351 e1699 e1763 e1764
  rw [e1763,e1699,e351,e325,e229,e217] at e1764
  exact congrArg some e1764

theorem actual_root_353 (pub rows : Nat → F) :
    (exactNonlinearRoots[353]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 227) * (rows 106 - rows 202)) := by
  rw [show exactNonlinearRoots[353]? = some 1766 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e326 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[326]? = some (.witnessRow 202) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1765 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1765]? = some (.sub 230 326) by decide)
  have e1766 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1766]? = some (.mul 1699 1765) by decide)
  simp only [expressionField] at e217 e230 e326 e351 e1699 e1765 e1766
  rw [e1765,e1699,e351,e326,e230,e217] at e1766
  exact congrArg some e1766

theorem actual_root_354 (pub rows : Nat → F) :
    (exactNonlinearRoots[354]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 227) * (rows 107 - rows 203)) := by
  rw [show exactNonlinearRoots[354]? = some 1768 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e327 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[327]? = some (.witnessRow 203) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1767 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1767]? = some (.sub 231 327) by decide)
  have e1768 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1768]? = some (.mul 1699 1767) by decide)
  simp only [expressionField] at e217 e231 e327 e351 e1699 e1767 e1768
  rw [e1767,e1699,e351,e327,e231,e217] at e1768
  exact congrArg some e1768

theorem actual_root_355 (pub rows : Nat → F) :
    (exactNonlinearRoots[355]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 227) * (rows 108 - rows 204)) := by
  rw [show exactNonlinearRoots[355]? = some 1770 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e328 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[328]? = some (.witnessRow 204) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1769 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1769]? = some (.sub 232 328) by decide)
  have e1770 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1770]? = some (.mul 1699 1769) by decide)
  simp only [expressionField] at e217 e232 e328 e351 e1699 e1769 e1770
  rw [e1769,e1699,e351,e328,e232,e217] at e1770
  exact congrArg some e1770

theorem actual_root_356 (pub rows : Nat → F) :
    (exactNonlinearRoots[356]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 227) * (rows 109 - rows 205)) := by
  rw [show exactNonlinearRoots[356]? = some 1772 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e329 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[329]? = some (.witnessRow 205) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1771 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1771]? = some (.sub 233 329) by decide)
  have e1772 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1772]? = some (.mul 1699 1771) by decide)
  simp only [expressionField] at e217 e233 e329 e351 e1699 e1771 e1772
  rw [e1771,e1699,e351,e329,e233,e217] at e1772
  exact congrArg some e1772

theorem actual_root_358 (pub rows : Nat → F) :
    (exactNonlinearRoots[358]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 228) * (rows 105 - rows 206)) := by
  rw [show exactNonlinearRoots[358]? = some 1775 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1774 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1774]? = some (.sub 229 330) by decide)
  have e1775 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1775]? = some (.mul 1704 1774) by decide)
  simp only [expressionField] at e217 e229 e330 e352 e1704 e1774 e1775
  rw [e1774,e1704,e352,e330,e229,e217] at e1775
  exact congrArg some e1775

theorem actual_root_359 (pub rows : Nat → F) :
    (exactNonlinearRoots[359]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 228) * (rows 106 - rows 207)) := by
  rw [show exactNonlinearRoots[359]? = some 1777 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e331 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[331]? = some (.witnessRow 207) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1776 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1776]? = some (.sub 230 331) by decide)
  have e1777 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1777]? = some (.mul 1704 1776) by decide)
  simp only [expressionField] at e217 e230 e331 e352 e1704 e1776 e1777
  rw [e1776,e1704,e352,e331,e230,e217] at e1777
  exact congrArg some e1777

theorem actual_root_360 (pub rows : Nat → F) :
    (exactNonlinearRoots[360]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 228) * (rows 107 - rows 208)) := by
  rw [show exactNonlinearRoots[360]? = some 1779 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e332 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[332]? = some (.witnessRow 208) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1778 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1778]? = some (.sub 231 332) by decide)
  have e1779 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1779]? = some (.mul 1704 1778) by decide)
  simp only [expressionField] at e217 e231 e332 e352 e1704 e1778 e1779
  rw [e1778,e1704,e352,e332,e231,e217] at e1779
  exact congrArg some e1779

theorem actual_root_361 (pub rows : Nat → F) :
    (exactNonlinearRoots[361]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 228) * (rows 108 - rows 209)) := by
  rw [show exactNonlinearRoots[361]? = some 1781 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e333 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[333]? = some (.witnessRow 209) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1780 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1780]? = some (.sub 232 333) by decide)
  have e1781 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1781]? = some (.mul 1704 1780) by decide)
  simp only [expressionField] at e217 e232 e333 e352 e1704 e1780 e1781
  rw [e1780,e1704,e352,e333,e232,e217] at e1781
  exact congrArg some e1781

theorem actual_root_362 (pub rows : Nat → F) :
    (exactNonlinearRoots[362]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 228) * (rows 109 - rows 210)) := by
  rw [show exactNonlinearRoots[362]? = some 1783 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e334 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[334]? = some (.witnessRow 210) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1782 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1782]? = some (.sub 233 334) by decide)
  have e1783 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1783]? = some (.mul 1704 1782) by decide)
  simp only [expressionField] at e217 e233 e334 e352 e1704 e1782 e1783
  rw [e1782,e1704,e352,e334,e233,e217] at e1783
  exact congrArg some e1783

theorem actual_root_364 (pub rows : Nat → F) :
    (exactNonlinearRoots[364]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 229) * (rows 105 - rows 211)) := by
  rw [show exactNonlinearRoots[364]? = some 1786 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1785 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1785]? = some (.sub 229 335) by decide)
  have e1786 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1786]? = some (.mul 1709 1785) by decide)
  simp only [expressionField] at e217 e229 e335 e353 e1709 e1785 e1786
  rw [e1785,e1709,e353,e335,e229,e217] at e1786
  exact congrArg some e1786

theorem actual_root_365 (pub rows : Nat → F) :
    (exactNonlinearRoots[365]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 229) * (rows 106 - rows 212)) := by
  rw [show exactNonlinearRoots[365]? = some 1788 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e336 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[336]? = some (.witnessRow 212) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1787 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1787]? = some (.sub 230 336) by decide)
  have e1788 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1788]? = some (.mul 1709 1787) by decide)
  simp only [expressionField] at e217 e230 e336 e353 e1709 e1787 e1788
  rw [e1787,e1709,e353,e336,e230,e217] at e1788
  exact congrArg some e1788

theorem actual_root_366 (pub rows : Nat → F) :
    (exactNonlinearRoots[366]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 229) * (rows 107 - rows 213)) := by
  rw [show exactNonlinearRoots[366]? = some 1790 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e337 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[337]? = some (.witnessRow 213) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1789 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1789]? = some (.sub 231 337) by decide)
  have e1790 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1790]? = some (.mul 1709 1789) by decide)
  simp only [expressionField] at e217 e231 e337 e353 e1709 e1789 e1790
  rw [e1789,e1709,e353,e337,e231,e217] at e1790
  exact congrArg some e1790

theorem actual_root_367 (pub rows : Nat → F) :
    (exactNonlinearRoots[367]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 229) * (rows 108 - rows 214)) := by
  rw [show exactNonlinearRoots[367]? = some 1792 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e338 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[338]? = some (.witnessRow 214) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1791 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1791]? = some (.sub 232 338) by decide)
  have e1792 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1792]? = some (.mul 1709 1791) by decide)
  simp only [expressionField] at e217 e232 e338 e353 e1709 e1791 e1792
  rw [e1791,e1709,e353,e338,e232,e217] at e1792
  exact congrArg some e1792

theorem actual_root_368 (pub rows : Nat → F) :
    (exactNonlinearRoots[368]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 229) * (rows 109 - rows 215)) := by
  rw [show exactNonlinearRoots[368]? = some 1794 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e339 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[339]? = some (.witnessRow 215) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1793 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1793]? = some (.sub 233 339) by decide)
  have e1794 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1794]? = some (.mul 1709 1793) by decide)
  simp only [expressionField] at e217 e233 e339 e353 e1709 e1793 e1794
  rw [e1793,e1709,e353,e339,e233,e217] at e1794
  exact congrArg some e1794

theorem actual_root_370 (pub rows : Nat → F) :
    (exactNonlinearRoots[370]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 230) * (rows 105 - rows 216)) := by
  rw [show exactNonlinearRoots[370]? = some 1797 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1796 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1796]? = some (.sub 229 340) by decide)
  have e1797 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1797]? = some (.mul 1714 1796) by decide)
  simp only [expressionField] at e217 e229 e340 e354 e1714 e1796 e1797
  rw [e1796,e1714,e354,e340,e229,e217] at e1797
  exact congrArg some e1797

theorem actual_root_371 (pub rows : Nat → F) :
    (exactNonlinearRoots[371]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 230) * (rows 106 - rows 217)) := by
  rw [show exactNonlinearRoots[371]? = some 1799 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e341 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[341]? = some (.witnessRow 217) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1798 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1798]? = some (.sub 230 341) by decide)
  have e1799 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1799]? = some (.mul 1714 1798) by decide)
  simp only [expressionField] at e217 e230 e341 e354 e1714 e1798 e1799
  rw [e1798,e1714,e354,e341,e230,e217] at e1799
  exact congrArg some e1799

theorem actual_root_372 (pub rows : Nat → F) :
    (exactNonlinearRoots[372]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 230) * (rows 107 - rows 218)) := by
  rw [show exactNonlinearRoots[372]? = some 1801 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e342 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[342]? = some (.witnessRow 218) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1800 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1800]? = some (.sub 231 342) by decide)
  have e1801 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1801]? = some (.mul 1714 1800) by decide)
  simp only [expressionField] at e217 e231 e342 e354 e1714 e1800 e1801
  rw [e1800,e1714,e354,e342,e231,e217] at e1801
  exact congrArg some e1801

theorem actual_root_373 (pub rows : Nat → F) :
    (exactNonlinearRoots[373]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 230) * (rows 108 - rows 219)) := by
  rw [show exactNonlinearRoots[373]? = some 1803 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e343 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[343]? = some (.witnessRow 219) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1802 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1802]? = some (.sub 232 343) by decide)
  have e1803 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1803]? = some (.mul 1714 1802) by decide)
  simp only [expressionField] at e217 e232 e343 e354 e1714 e1802 e1803
  rw [e1802,e1714,e354,e343,e232,e217] at e1803
  exact congrArg some e1803

theorem actual_root_374 (pub rows : Nat → F) :
    (exactNonlinearRoots[374]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 230) * (rows 109 - rows 220)) := by
  rw [show exactNonlinearRoots[374]? = some 1805 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e344 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[344]? = some (.witnessRow 220) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1804 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1804]? = some (.sub 233 344) by decide)
  have e1805 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1805]? = some (.mul 1714 1804) by decide)
  simp only [expressionField] at e217 e233 e344 e354 e1714 e1804 e1805
  rw [e1804,e1714,e354,e344,e233,e217] at e1805
  exact congrArg some e1805

theorem actual_root_376 (pub rows : Nat → F) :
    (exactNonlinearRoots[376]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 231) * (rows 105 - rows 221)) := by
  rw [show exactNonlinearRoots[376]? = some 1808 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e229 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[229]? = some (.witnessRow 105) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1807 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1807]? = some (.sub 229 345) by decide)
  have e1808 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1808]? = some (.mul 1719 1807) by decide)
  simp only [expressionField] at e217 e229 e345 e355 e1719 e1807 e1808
  rw [e1807,e1719,e355,e345,e229,e217] at e1808
  exact congrArg some e1808

theorem actual_root_377 (pub rows : Nat → F) :
    (exactNonlinearRoots[377]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 231) * (rows 106 - rows 222)) := by
  rw [show exactNonlinearRoots[377]? = some 1810 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e230 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[230]? = some (.witnessRow 106) by decide)
  have e346 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[346]? = some (.witnessRow 222) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1809 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1809]? = some (.sub 230 346) by decide)
  have e1810 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1810]? = some (.mul 1719 1809) by decide)
  simp only [expressionField] at e217 e230 e346 e355 e1719 e1809 e1810
  rw [e1809,e1719,e355,e346,e230,e217] at e1810
  exact congrArg some e1810

theorem actual_root_378 (pub rows : Nat → F) :
    (exactNonlinearRoots[378]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 231) * (rows 107 - rows 223)) := by
  rw [show exactNonlinearRoots[378]? = some 1812 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e231 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[231]? = some (.witnessRow 107) by decide)
  have e347 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[347]? = some (.witnessRow 223) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1811 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1811]? = some (.sub 231 347) by decide)
  have e1812 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1812]? = some (.mul 1719 1811) by decide)
  simp only [expressionField] at e217 e231 e347 e355 e1719 e1811 e1812
  rw [e1811,e1719,e355,e347,e231,e217] at e1812
  exact congrArg some e1812

theorem actual_root_379 (pub rows : Nat → F) :
    (exactNonlinearRoots[379]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 231) * (rows 108 - rows 224)) := by
  rw [show exactNonlinearRoots[379]? = some 1814 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e232 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[232]? = some (.witnessRow 108) by decide)
  have e348 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[348]? = some (.witnessRow 224) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1813 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1813]? = some (.sub 232 348) by decide)
  have e1814 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1814]? = some (.mul 1719 1813) by decide)
  simp only [expressionField] at e217 e232 e348 e355 e1719 e1813 e1814
  rw [e1813,e1719,e355,e348,e232,e217] at e1814
  exact congrArg some e1814

theorem actual_root_380 (pub rows : Nat → F) :
    (exactNonlinearRoots[380]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 * rows 231) * (rows 109 - rows 225)) := by
  rw [show exactNonlinearRoots[380]? = some 1816 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e233 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[233]? = some (.witnessRow 109) by decide)
  have e349 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[349]? = some (.witnessRow 225) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1815 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1815]? = some (.sub 233 349) by decide)
  have e1816 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1816]? = some (.mul 1719 1815) by decide)
  simp only [expressionField] at e217 e233 e349 e355 e1719 e1815 e1816
  rw [e1815,e1719,e355,e349,e233,e217] at e1816
  exact congrArg some e1816

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreDAG
