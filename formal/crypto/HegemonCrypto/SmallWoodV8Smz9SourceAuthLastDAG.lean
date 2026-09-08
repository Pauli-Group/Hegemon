import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_root_299 (pub rows : Nat → F) :
    (exactNonlinearRoots[299]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 155 * (rows 93 + rows 94)) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))))) := by
  rw [show exactNonlinearRoots[299]? = some 1609 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e279 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[279]? = some (.witnessRow 155) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1607 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1607]? = some (.mul 279 1234) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1609 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1609]? = some (.mul 1607 1608) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e279 e300 e301 e302 e303 e304 e305 e1234 e1489 e1490 e1491 e1492 e1493 e1607 e1608 e1609
  rw [e1608,e1607,e1493,e1492,e1491,e1490,e1489,e1234,e305,e304,e303,e302,e301,e300,e279,e218,e217,e1] at e1609
  exact congrArg some e1609

theorem actual_root_301 (pub rows : Nat → F) :
    (exactNonlinearRoots[301]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 156 * (rows 93 + rows 94)) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178)))))) := by
  rw [show exactNonlinearRoots[301]? = some 1619 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e280 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[280]? = some (.witnessRow 156) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1613 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1613]? = some (.mul 280 1234) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1619 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1619]? = some (.mul 1613 1618) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e280 e301 e302 e303 e304 e305 e1234 e1613 e1614 e1615 e1616 e1617 e1618 e1619
  rw [e1618,e1617,e1616,e1615,e1614,e1613,e1234,e305,e304,e303,e302,e301,e280,e218,e217,e1] at e1619
  exact congrArg some e1619

theorem actual_root_303 (pub rows : Nat → F) :
    (exactNonlinearRoots[303]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 157 * (rows 93 + rows 94)) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179))))) := by
  rw [show exactNonlinearRoots[303]? = some 1628 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e281 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[281]? = some (.witnessRow 157) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1623 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1623]? = some (.mul 281 1234) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1628 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1628]? = some (.mul 1623 1627) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e281 e302 e303 e304 e305 e1234 e1623 e1624 e1625 e1626 e1627 e1628
  rw [e1627,e1626,e1625,e1624,e1623,e1234,e305,e304,e303,e302,e281,e218,e217,e1] at e1628
  exact congrArg some e1628

theorem actual_root_305 (pub rows : Nat → F) :
    (exactNonlinearRoots[305]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 158 * (rows 93 + rows 94)) * (1 - (rows 181 + (rows 179 + rows 180)))) := by
  rw [show exactNonlinearRoots[305]? = some 1636 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e282 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[282]? = some (.witnessRow 158) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1632 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1632]? = some (.mul 282 1234) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1636 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1636]? = some (.mul 1632 1635) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e282 e303 e304 e305 e1234 e1632 e1633 e1634 e1635 e1636
  rw [e1635,e1634,e1633,e1632,e1234,e305,e304,e303,e282,e218,e217,e1] at e1636
  exact congrArg some e1636

theorem actual_root_307 (pub rows : Nat → F) :
    (exactNonlinearRoots[307]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 159 * (rows 93 + rows 94)) * (1 - (rows 180 + rows 181))) := by
  rw [show exactNonlinearRoots[307]? = some 1643 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e283 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[283]? = some (.witnessRow 159) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1640 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1640]? = some (.mul 283 1234) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1643 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1643]? = some (.mul 1640 1642) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e283 e304 e305 e1234 e1640 e1641 e1642 e1643
  rw [e1642,e1641,e1640,e1234,e305,e304,e283,e218,e217,e1] at e1643
  exact congrArg some e1643

theorem actual_root_309 (pub rows : Nat → F) :
    (exactNonlinearRoots[309]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 160 * (rows 93 + rows 94)) * (1 - rows 181)) := by
  rw [show exactNonlinearRoots[309]? = some 1649 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e284 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[284]? = some (.witnessRow 160) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1647 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1647]? = some (.mul 284 1234) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1649 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1649]? = some (.mul 1647 1648) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e284 e305 e1234 e1647 e1648 e1649
  rw [e1648,e1647,e1234,e305,e284,e218,e217,e1] at e1649
  exact congrArg some e1649

theorem actual_root_312 (pub rows : Nat → F) :
    (exactNonlinearRoots[312]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))) * (rows 93 * rows 162)) := by
  rw [show exactNonlinearRoots[312]? = some 1661 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e286 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[286]? = some (.witnessRow 162) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1660 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1660]? = some (.mul 217 286) by decide)
  have e1661 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1661]? = some (.mul 1608 1660) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e286 e300 e301 e302 e303 e304 e305 e1489 e1490 e1491 e1492 e1493 e1608 e1660 e1661
  rw [e1660,e1608,e1493,e1492,e1491,e1490,e1489,e305,e304,e303,e302,e301,e300,e286,e217,e1] at e1661
  exact congrArg some e1661

theorem actual_root_314 (pub rows : Nat → F) :
    (exactNonlinearRoots[314]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))) * (rows 93 * rows 163)) := by
  rw [show exactNonlinearRoots[314]? = some 1666 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e287 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[287]? = some (.witnessRow 163) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1665 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1665]? = some (.mul 217 287) by decide)
  have e1666 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1666]? = some (.mul 1618 1665) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e287 e301 e302 e303 e304 e305 e1614 e1615 e1616 e1617 e1618 e1665 e1666
  rw [e1665,e1618,e1617,e1616,e1615,e1614,e305,e304,e303,e302,e301,e287,e217,e1] at e1666
  exact congrArg some e1666

theorem actual_root_316 (pub rows : Nat → F) :
    (exactNonlinearRoots[316]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))) * (rows 93 * rows 164)) := by
  rw [show exactNonlinearRoots[316]? = some 1671 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e288 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[288]? = some (.witnessRow 164) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1670 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1670]? = some (.mul 217 288) by decide)
  have e1671 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1671]? = some (.mul 1627 1670) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e288 e302 e303 e304 e305 e1624 e1625 e1626 e1627 e1670 e1671
  rw [e1670,e1627,e1626,e1625,e1624,e305,e304,e303,e302,e288,e217,e1] at e1671
  exact congrArg some e1671

theorem actual_root_318 (pub rows : Nat → F) :
    (exactNonlinearRoots[318]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 179 + rows 180))) * (rows 93 * rows 165)) := by
  rw [show exactNonlinearRoots[318]? = some 1676 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e289 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[289]? = some (.witnessRow 165) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1675 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1675]? = some (.mul 217 289) by decide)
  have e1676 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1676]? = some (.mul 1635 1675) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e289 e303 e304 e305 e1633 e1634 e1635 e1675 e1676
  rw [e1675,e1635,e1634,e1633,e305,e304,e303,e289,e217,e1] at e1676
  exact congrArg some e1676

theorem actual_root_320 (pub rows : Nat → F) :
    (exactNonlinearRoots[320]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 180 + rows 181)) * (rows 93 * rows 166)) := by
  rw [show exactNonlinearRoots[320]? = some 1681 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e290 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[290]? = some (.witnessRow 166) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1680 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1680]? = some (.mul 217 290) by decide)
  have e1681 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1681]? = some (.mul 1642 1680) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e290 e304 e305 e1641 e1642 e1680 e1681
  rw [e1680,e1642,e1641,e305,e304,e290,e217,e1] at e1681
  exact congrArg some e1681

theorem actual_root_322 (pub rows : Nat → F) :
    (exactNonlinearRoots[322]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - rows 181) * (rows 93 * rows 167)) := by
  rw [show exactNonlinearRoots[322]? = some 1686 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e291 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[291]? = some (.witnessRow 167) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1685 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1685]? = some (.mul 217 291) by decide)
  have e1686 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1686]? = some (.mul 1648 1685) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e291 e305 e1648 e1685 e1686
  rw [e1685,e1648,e305,e291,e217,e1] at e1686
  exact congrArg some e1686

theorem actual_root_345 (pub rows : Nat → F) :
    (exactNonlinearRoots[345]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))) * (rows 93 * rows 226)) := by
  rw [show exactNonlinearRoots[345]? = some 1751 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1694 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1694]? = some (.mul 217 350) by decide)
  have e1751 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1751]? = some (.mul 1608 1694) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e300 e301 e302 e303 e304 e305 e350 e1489 e1490 e1491 e1492 e1493 e1608 e1694 e1751
  rw [e1694,e1608,e1493,e1492,e1491,e1490,e1489,e350,e305,e304,e303,e302,e301,e300,e217,e1] at e1751
  exact congrArg some e1751

theorem actual_root_351 (pub rows : Nat → F) :
    (exactNonlinearRoots[351]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))) * (rows 93 * rows 227)) := by
  rw [show exactNonlinearRoots[351]? = some 1762 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1699 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1699]? = some (.mul 217 351) by decide)
  have e1762 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1762]? = some (.mul 1618 1699) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e301 e302 e303 e304 e305 e351 e1614 e1615 e1616 e1617 e1618 e1699 e1762
  rw [e1699,e1618,e1617,e1616,e1615,e1614,e351,e305,e304,e303,e302,e301,e217,e1] at e1762
  exact congrArg some e1762

theorem actual_root_357 (pub rows : Nat → F) :
    (exactNonlinearRoots[357]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))) * (rows 93 * rows 228)) := by
  rw [show exactNonlinearRoots[357]? = some 1773 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1704 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1704]? = some (.mul 217 352) by decide)
  have e1773 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1773]? = some (.mul 1627 1704) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e302 e303 e304 e305 e352 e1624 e1625 e1626 e1627 e1704 e1773
  rw [e1704,e1627,e1626,e1625,e1624,e352,e305,e304,e303,e302,e217,e1] at e1773
  exact congrArg some e1773

theorem actual_root_363 (pub rows : Nat → F) :
    (exactNonlinearRoots[363]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 181 + (rows 179 + rows 180))) * (rows 93 * rows 229)) := by
  rw [show exactNonlinearRoots[363]? = some 1784 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1709 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1709]? = some (.mul 217 353) by decide)
  have e1784 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1784]? = some (.mul 1635 1709) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e303 e304 e305 e353 e1633 e1634 e1635 e1709 e1784
  rw [e1709,e1635,e1634,e1633,e353,e305,e304,e303,e217,e1] at e1784
  exact congrArg some e1784

theorem actual_root_369 (pub rows : Nat → F) :
    (exactNonlinearRoots[369]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - (rows 180 + rows 181)) * (rows 93 * rows 230)) := by
  rw [show exactNonlinearRoots[369]? = some 1795 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1714 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1714]? = some (.mul 217 354) by decide)
  have e1795 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1795]? = some (.mul 1642 1714) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e304 e305 e354 e1641 e1642 e1714 e1795
  rw [e1714,e1642,e1641,e354,e305,e304,e217,e1] at e1795
  exact congrArg some e1795

theorem actual_root_375 (pub rows : Nat → F) :
    (exactNonlinearRoots[375]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((1 - rows 181) * (rows 93 * rows 231)) := by
  rw [show exactNonlinearRoots[375]? = some 1806 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1719 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1719]? = some (.mul 217 355) by decide)
  have e1806 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1806]? = some (.mul 1648 1719) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e305 e355 e1648 e1719 e1806
  rw [e1719,e1648,e355,e305,e217,e1] at e1806
  exact congrArg some e1806

theorem actual_root_381 (pub rows : Nat → F) :
    (exactNonlinearRoots[381]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 196 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))))) := by
  rw [show exactNonlinearRoots[381]? = some 1818 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e320 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[320]? = some (.witnessRow 196) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1817 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1817]? = some (.mul 1234 1608) by decide)
  have e1818 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1818]? = some (.mul 320 1817) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e320 e1234 e1489 e1490 e1491 e1492 e1493 e1608 e1817 e1818
  rw [e1817,e1608,e1493,e1492,e1491,e1490,e1489,e1234,e320,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1818
  exact congrArg some e1818

theorem actual_root_382 (pub rows : Nat → F) :
    (exactNonlinearRoots[382]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 197 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))))) := by
  rw [show exactNonlinearRoots[382]? = some 1819 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e321 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[321]? = some (.witnessRow 197) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1817 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1817]? = some (.mul 1234 1608) by decide)
  have e1819 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1819]? = some (.mul 321 1817) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e321 e1234 e1489 e1490 e1491 e1492 e1493 e1608 e1817 e1819
  rw [e1817,e1608,e1493,e1492,e1491,e1490,e1489,e1234,e321,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1819
  exact congrArg some e1819

theorem actual_root_383 (pub rows : Nat → F) :
    (exactNonlinearRoots[383]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 198 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))))) := by
  rw [show exactNonlinearRoots[383]? = some 1820 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e322 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[322]? = some (.witnessRow 198) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1817 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1817]? = some (.mul 1234 1608) by decide)
  have e1820 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1820]? = some (.mul 322 1817) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e322 e1234 e1489 e1490 e1491 e1492 e1493 e1608 e1817 e1820
  rw [e1817,e1608,e1493,e1492,e1491,e1490,e1489,e1234,e322,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1820
  exact congrArg some e1820

theorem actual_root_384 (pub rows : Nat → F) :
    (exactNonlinearRoots[384]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 199 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))))) := by
  rw [show exactNonlinearRoots[384]? = some 1821 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e323 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[323]? = some (.witnessRow 199) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1817 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1817]? = some (.mul 1234 1608) by decide)
  have e1821 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1821]? = some (.mul 323 1817) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e323 e1234 e1489 e1490 e1491 e1492 e1493 e1608 e1817 e1821
  rw [e1817,e1608,e1493,e1492,e1491,e1490,e1489,e1234,e323,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1821
  exact congrArg some e1821

theorem actual_root_385 (pub rows : Nat → F) :
    (exactNonlinearRoots[385]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 200 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177)))))))) := by
  rw [show exactNonlinearRoots[385]? = some 1822 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e324 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[324]? = some (.witnessRow 200) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1489 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1489]? = some (.add 300 301) by decide)
  have e1490 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1490]? = some (.add 302 1489) by decide)
  have e1491 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1491]? = some (.add 303 1490) by decide)
  have e1492 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1492]? = some (.add 304 1491) by decide)
  have e1493 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1493]? = some (.add 305 1492) by decide)
  have e1608 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1608]? = some (.sub 1 1493) by decide)
  have e1817 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1817]? = some (.mul 1234 1608) by decide)
  have e1822 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1822]? = some (.mul 324 1817) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e324 e1234 e1489 e1490 e1491 e1492 e1493 e1608 e1817 e1822
  rw [e1817,e1608,e1493,e1492,e1491,e1490,e1489,e1234,e324,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1822
  exact congrArg some e1822

theorem actual_root_386 (pub rows : Nat → F) :
    (exactNonlinearRoots[386]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 201 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))))) := by
  rw [show exactNonlinearRoots[386]? = some 1824 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e325 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[325]? = some (.witnessRow 201) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1823 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1823]? = some (.mul 1234 1618) by decide)
  have e1824 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1824]? = some (.mul 325 1823) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e325 e1234 e1614 e1615 e1616 e1617 e1618 e1823 e1824
  rw [e1823,e1618,e1617,e1616,e1615,e1614,e1234,e325,e305,e304,e303,e302,e301,e218,e217,e1] at e1824
  exact congrArg some e1824

theorem actual_root_387 (pub rows : Nat → F) :
    (exactNonlinearRoots[387]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 202 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))))) := by
  rw [show exactNonlinearRoots[387]? = some 1825 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e326 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[326]? = some (.witnessRow 202) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1823 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1823]? = some (.mul 1234 1618) by decide)
  have e1825 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1825]? = some (.mul 326 1823) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e326 e1234 e1614 e1615 e1616 e1617 e1618 e1823 e1825
  rw [e1823,e1618,e1617,e1616,e1615,e1614,e1234,e326,e305,e304,e303,e302,e301,e218,e217,e1] at e1825
  exact congrArg some e1825

theorem actual_root_388 (pub rows : Nat → F) :
    (exactNonlinearRoots[388]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 203 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))))) := by
  rw [show exactNonlinearRoots[388]? = some 1826 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e327 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[327]? = some (.witnessRow 203) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1823 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1823]? = some (.mul 1234 1618) by decide)
  have e1826 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1826]? = some (.mul 327 1823) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e327 e1234 e1614 e1615 e1616 e1617 e1618 e1823 e1826
  rw [e1823,e1618,e1617,e1616,e1615,e1614,e1234,e327,e305,e304,e303,e302,e301,e218,e217,e1] at e1826
  exact congrArg some e1826

theorem actual_root_389 (pub rows : Nat → F) :
    (exactNonlinearRoots[389]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 204 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))))) := by
  rw [show exactNonlinearRoots[389]? = some 1827 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e328 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[328]? = some (.witnessRow 204) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1823 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1823]? = some (.mul 1234 1618) by decide)
  have e1827 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1827]? = some (.mul 328 1823) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e328 e1234 e1614 e1615 e1616 e1617 e1618 e1823 e1827
  rw [e1823,e1618,e1617,e1616,e1615,e1614,e1234,e328,e305,e304,e303,e302,e301,e218,e217,e1] at e1827
  exact congrArg some e1827

theorem actual_root_390 (pub rows : Nat → F) :
    (exactNonlinearRoots[390]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 205 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 179 + (rows 177 + rows 178))))))) := by
  rw [show exactNonlinearRoots[390]? = some 1828 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e329 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[329]? = some (.witnessRow 205) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1614 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1614]? = some (.add 301 302) by decide)
  have e1615 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1615]? = some (.add 303 1614) by decide)
  have e1616 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1616]? = some (.add 304 1615) by decide)
  have e1617 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1617]? = some (.add 305 1616) by decide)
  have e1618 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1618]? = some (.sub 1 1617) by decide)
  have e1823 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1823]? = some (.mul 1234 1618) by decide)
  have e1828 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1828]? = some (.mul 329 1823) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e302 e303 e304 e305 e329 e1234 e1614 e1615 e1616 e1617 e1618 e1823 e1828
  rw [e1823,e1618,e1617,e1616,e1615,e1614,e1234,e329,e305,e304,e303,e302,e301,e218,e217,e1] at e1828
  exact congrArg some e1828

theorem actual_root_391 (pub rows : Nat → F) :
    (exactNonlinearRoots[391]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 206 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))))) := by
  rw [show exactNonlinearRoots[391]? = some 1830 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e330 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[330]? = some (.witnessRow 206) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1829]? = some (.mul 1234 1627) by decide)
  have e1830 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1830]? = some (.mul 330 1829) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e330 e1234 e1624 e1625 e1626 e1627 e1829 e1830
  rw [e1829,e1627,e1626,e1625,e1624,e1234,e330,e305,e304,e303,e302,e218,e217,e1] at e1830
  exact congrArg some e1830

theorem actual_root_392 (pub rows : Nat → F) :
    (exactNonlinearRoots[392]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 207 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))))) := by
  rw [show exactNonlinearRoots[392]? = some 1831 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e331 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[331]? = some (.witnessRow 207) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1829]? = some (.mul 1234 1627) by decide)
  have e1831 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1831]? = some (.mul 331 1829) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e331 e1234 e1624 e1625 e1626 e1627 e1829 e1831
  rw [e1829,e1627,e1626,e1625,e1624,e1234,e331,e305,e304,e303,e302,e218,e217,e1] at e1831
  exact congrArg some e1831

theorem actual_root_393 (pub rows : Nat → F) :
    (exactNonlinearRoots[393]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 208 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))))) := by
  rw [show exactNonlinearRoots[393]? = some 1832 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e332 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[332]? = some (.witnessRow 208) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1829]? = some (.mul 1234 1627) by decide)
  have e1832 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1832]? = some (.mul 332 1829) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e332 e1234 e1624 e1625 e1626 e1627 e1829 e1832
  rw [e1829,e1627,e1626,e1625,e1624,e1234,e332,e305,e304,e303,e302,e218,e217,e1] at e1832
  exact congrArg some e1832

theorem actual_root_394 (pub rows : Nat → F) :
    (exactNonlinearRoots[394]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 209 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))))) := by
  rw [show exactNonlinearRoots[394]? = some 1833 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e333 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[333]? = some (.witnessRow 209) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1829]? = some (.mul 1234 1627) by decide)
  have e1833 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1833]? = some (.mul 333 1829) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e333 e1234 e1624 e1625 e1626 e1627 e1829 e1833
  rw [e1829,e1627,e1626,e1625,e1624,e1234,e333,e305,e304,e303,e302,e218,e217,e1] at e1833
  exact congrArg some e1833

theorem actual_root_395 (pub rows : Nat → F) :
    (exactNonlinearRoots[395]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 210 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 180 + (rows 178 + rows 179)))))) := by
  rw [show exactNonlinearRoots[395]? = some 1834 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e334 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[334]? = some (.witnessRow 210) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1624 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1624]? = some (.add 302 303) by decide)
  have e1625 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1625]? = some (.add 304 1624) by decide)
  have e1626 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1626]? = some (.add 305 1625) by decide)
  have e1627 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1627]? = some (.sub 1 1626) by decide)
  have e1829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1829]? = some (.mul 1234 1627) by decide)
  have e1834 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1834]? = some (.mul 334 1829) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e303 e304 e305 e334 e1234 e1624 e1625 e1626 e1627 e1829 e1834
  rw [e1829,e1627,e1626,e1625,e1624,e1234,e334,e305,e304,e303,e302,e218,e217,e1] at e1834
  exact congrArg some e1834

theorem actual_root_396 (pub rows : Nat → F) :
    (exactNonlinearRoots[396]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 211 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 179 + rows 180))))) := by
  rw [show exactNonlinearRoots[396]? = some 1836 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e335 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[335]? = some (.witnessRow 211) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1835 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1835]? = some (.mul 1234 1635) by decide)
  have e1836 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1836]? = some (.mul 335 1835) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e335 e1234 e1633 e1634 e1635 e1835 e1836
  rw [e1835,e1635,e1634,e1633,e1234,e335,e305,e304,e303,e218,e217,e1] at e1836
  exact congrArg some e1836

theorem actual_root_397 (pub rows : Nat → F) :
    (exactNonlinearRoots[397]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 212 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 179 + rows 180))))) := by
  rw [show exactNonlinearRoots[397]? = some 1837 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e336 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[336]? = some (.witnessRow 212) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1835 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1835]? = some (.mul 1234 1635) by decide)
  have e1837 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1837]? = some (.mul 336 1835) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e336 e1234 e1633 e1634 e1635 e1835 e1837
  rw [e1835,e1635,e1634,e1633,e1234,e336,e305,e304,e303,e218,e217,e1] at e1837
  exact congrArg some e1837

theorem actual_root_398 (pub rows : Nat → F) :
    (exactNonlinearRoots[398]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 213 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 179 + rows 180))))) := by
  rw [show exactNonlinearRoots[398]? = some 1838 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e337 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[337]? = some (.witnessRow 213) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1835 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1835]? = some (.mul 1234 1635) by decide)
  have e1838 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1838]? = some (.mul 337 1835) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e337 e1234 e1633 e1634 e1635 e1835 e1838
  rw [e1835,e1635,e1634,e1633,e1234,e337,e305,e304,e303,e218,e217,e1] at e1838
  exact congrArg some e1838

theorem actual_root_399 (pub rows : Nat → F) :
    (exactNonlinearRoots[399]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 214 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 179 + rows 180))))) := by
  rw [show exactNonlinearRoots[399]? = some 1839 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e338 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[338]? = some (.witnessRow 214) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1835 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1835]? = some (.mul 1234 1635) by decide)
  have e1839 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1839]? = some (.mul 338 1835) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e338 e1234 e1633 e1634 e1635 e1835 e1839
  rw [e1835,e1635,e1634,e1633,e1234,e338,e305,e304,e303,e218,e217,e1] at e1839
  exact congrArg some e1839

theorem actual_root_400 (pub rows : Nat → F) :
    (exactNonlinearRoots[400]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 215 * ((rows 93 + rows 94) * (1 - (rows 181 + (rows 179 + rows 180))))) := by
  rw [show exactNonlinearRoots[400]? = some 1840 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e339 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[339]? = some (.witnessRow 215) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1633 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1633]? = some (.add 303 304) by decide)
  have e1634 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1634]? = some (.add 305 1633) by decide)
  have e1635 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1635]? = some (.sub 1 1634) by decide)
  have e1835 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1835]? = some (.mul 1234 1635) by decide)
  have e1840 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1840]? = some (.mul 339 1835) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e304 e305 e339 e1234 e1633 e1634 e1635 e1835 e1840
  rw [e1835,e1635,e1634,e1633,e1234,e339,e305,e304,e303,e218,e217,e1] at e1840
  exact congrArg some e1840

theorem actual_root_401 (pub rows : Nat → F) :
    (exactNonlinearRoots[401]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 216 * ((rows 93 + rows 94) * (1 - (rows 180 + rows 181)))) := by
  rw [show exactNonlinearRoots[401]? = some 1842 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e340 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[340]? = some (.witnessRow 216) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1841 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1841]? = some (.mul 1234 1642) by decide)
  have e1842 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1842]? = some (.mul 340 1841) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e340 e1234 e1641 e1642 e1841 e1842
  rw [e1841,e1642,e1641,e1234,e340,e305,e304,e218,e217,e1] at e1842
  exact congrArg some e1842

theorem actual_root_402 (pub rows : Nat → F) :
    (exactNonlinearRoots[402]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 217 * ((rows 93 + rows 94) * (1 - (rows 180 + rows 181)))) := by
  rw [show exactNonlinearRoots[402]? = some 1843 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e341 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[341]? = some (.witnessRow 217) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1841 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1841]? = some (.mul 1234 1642) by decide)
  have e1843 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1843]? = some (.mul 341 1841) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e341 e1234 e1641 e1642 e1841 e1843
  rw [e1841,e1642,e1641,e1234,e341,e305,e304,e218,e217,e1] at e1843
  exact congrArg some e1843

theorem actual_root_403 (pub rows : Nat → F) :
    (exactNonlinearRoots[403]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 218 * ((rows 93 + rows 94) * (1 - (rows 180 + rows 181)))) := by
  rw [show exactNonlinearRoots[403]? = some 1844 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e342 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[342]? = some (.witnessRow 218) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1841 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1841]? = some (.mul 1234 1642) by decide)
  have e1844 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1844]? = some (.mul 342 1841) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e342 e1234 e1641 e1642 e1841 e1844
  rw [e1841,e1642,e1641,e1234,e342,e305,e304,e218,e217,e1] at e1844
  exact congrArg some e1844

theorem actual_root_404 (pub rows : Nat → F) :
    (exactNonlinearRoots[404]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 219 * ((rows 93 + rows 94) * (1 - (rows 180 + rows 181)))) := by
  rw [show exactNonlinearRoots[404]? = some 1845 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e343 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[343]? = some (.witnessRow 219) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1841 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1841]? = some (.mul 1234 1642) by decide)
  have e1845 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1845]? = some (.mul 343 1841) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e343 e1234 e1641 e1642 e1841 e1845
  rw [e1841,e1642,e1641,e1234,e343,e305,e304,e218,e217,e1] at e1845
  exact congrArg some e1845

theorem actual_root_405 (pub rows : Nat → F) :
    (exactNonlinearRoots[405]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 220 * ((rows 93 + rows 94) * (1 - (rows 180 + rows 181)))) := by
  rw [show exactNonlinearRoots[405]? = some 1846 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e344 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[344]? = some (.witnessRow 220) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1641 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1641]? = some (.add 304 305) by decide)
  have e1642 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1642]? = some (.sub 1 1641) by decide)
  have e1841 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1841]? = some (.mul 1234 1642) by decide)
  have e1846 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1846]? = some (.mul 344 1841) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e305 e344 e1234 e1641 e1642 e1841 e1846
  rw [e1841,e1642,e1641,e1234,e344,e305,e304,e218,e217,e1] at e1846
  exact congrArg some e1846

theorem actual_root_406 (pub rows : Nat → F) :
    (exactNonlinearRoots[406]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 221 * ((rows 93 + rows 94) * (1 - rows 181))) := by
  rw [show exactNonlinearRoots[406]? = some 1848 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e345 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[345]? = some (.witnessRow 221) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1847 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1847]? = some (.mul 1234 1648) by decide)
  have e1848 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1848]? = some (.mul 345 1847) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e345 e1234 e1648 e1847 e1848
  rw [e1847,e1648,e1234,e345,e305,e218,e217,e1] at e1848
  exact congrArg some e1848

theorem actual_root_407 (pub rows : Nat → F) :
    (exactNonlinearRoots[407]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 222 * ((rows 93 + rows 94) * (1 - rows 181))) := by
  rw [show exactNonlinearRoots[407]? = some 1849 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e346 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[346]? = some (.witnessRow 222) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1847 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1847]? = some (.mul 1234 1648) by decide)
  have e1849 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1849]? = some (.mul 346 1847) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e346 e1234 e1648 e1847 e1849
  rw [e1847,e1648,e1234,e346,e305,e218,e217,e1] at e1849
  exact congrArg some e1849

theorem actual_root_408 (pub rows : Nat → F) :
    (exactNonlinearRoots[408]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 223 * ((rows 93 + rows 94) * (1 - rows 181))) := by
  rw [show exactNonlinearRoots[408]? = some 1850 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e347 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[347]? = some (.witnessRow 223) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1847 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1847]? = some (.mul 1234 1648) by decide)
  have e1850 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1850]? = some (.mul 347 1847) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e347 e1234 e1648 e1847 e1850
  rw [e1847,e1648,e1234,e347,e305,e218,e217,e1] at e1850
  exact congrArg some e1850

theorem actual_root_409 (pub rows : Nat → F) :
    (exactNonlinearRoots[409]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 224 * ((rows 93 + rows 94) * (1 - rows 181))) := by
  rw [show exactNonlinearRoots[409]? = some 1851 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e348 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[348]? = some (.witnessRow 224) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1847 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1847]? = some (.mul 1234 1648) by decide)
  have e1851 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1851]? = some (.mul 348 1847) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e348 e1234 e1648 e1847 e1851
  rw [e1847,e1648,e1234,e348,e305,e218,e217,e1] at e1851
  exact congrArg some e1851

theorem actual_root_410 (pub rows : Nat → F) :
    (exactNonlinearRoots[410]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 225 * ((rows 93 + rows 94) * (1 - rows 181))) := by
  rw [show exactNonlinearRoots[410]? = some 1852 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e349 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[349]? = some (.witnessRow 225) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1648 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1648]? = some (.sub 1 305) by decide)
  have e1847 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1847]? = some (.mul 1234 1648) by decide)
  have e1852 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1852]? = some (.mul 349 1847) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e349 e1234 e1648 e1847 e1852
  rw [e1847,e1648,e1234,e349,e305,e218,e217,e1] at e1852
  exact congrArg some e1852

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastDAG
