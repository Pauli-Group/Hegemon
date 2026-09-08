import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_root_267 (pub rows : Nat → F) :
    (exactNonlinearRoots[267]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * ((rows 175 + (rows 174 + (rows 173 + (rows 172 + (rows 170 + rows 171))))) - 1)) := by
  rw [show exactNonlinearRoots[267]? = some 1455 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e294 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[294]? = some (.witnessRow 170) by decide)
  have e295 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[295]? = some (.witnessRow 171) by decide)
  have e296 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[296]? = some (.witnessRow 172) by decide)
  have e297 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[297]? = some (.witnessRow 173) by decide)
  have e298 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[298]? = some (.witnessRow 174) by decide)
  have e299 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[299]? = some (.witnessRow 175) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1449 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1449]? = some (.add 294 295) by decide)
  have e1450 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1450]? = some (.add 296 1449) by decide)
  have e1451 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1451]? = some (.add 297 1450) by decide)
  have e1452 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1452]? = some (.add 298 1451) by decide)
  have e1453 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1453]? = some (.add 299 1452) by decide)
  have e1454 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1454]? = some (.sub 1453 1) by decide)
  have e1455 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1455]? = some (.mul 1234 1454) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e294 e295 e296 e297 e298 e299 e1234 e1449 e1450 e1451 e1452 e1453 e1454 e1455
  rw [e1454,e1453,e1452,e1451,e1450,e1449,e1234,e299,e298,e297,e296,e295,e294,e218,e217,e1] at e1455
  exact congrArg some e1455

theorem actual_root_268 (pub rows : Nat → F) :
    (exactNonlinearRoots[268]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 152 - (((((rows 170 + (2 * rows 171)) + (rows 172 * 3)) + (rows 173 * 4)) + (rows 174 * 5)) + (rows 175 * 6)))) := by
  rw [show exactNonlinearRoots[268]? = some 1470 by decide,Option.map_some]
  have e2 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2]? = some (.constant 2) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e276 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[276]? = some (.witnessRow 152) by decide)
  have e294 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[294]? = some (.witnessRow 170) by decide)
  have e295 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[295]? = some (.witnessRow 171) by decide)
  have e296 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[296]? = some (.witnessRow 172) by decide)
  have e297 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[297]? = some (.witnessRow 173) by decide)
  have e298 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[298]? = some (.witnessRow 174) by decide)
  have e299 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[299]? = some (.witnessRow 175) by decide)
  have e829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[829]? = some (.constant 3) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1456 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1456]? = some (.mul 2 295) by decide)
  have e1457 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1457]? = some (.add 294 1456) by decide)
  have e1458 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1458]? = some (.mul 296 829) by decide)
  have e1459 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1459]? = some (.add 1457 1458) by decide)
  have e1460 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1460]? = some (.constant 4) by decide)
  have e1461 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1461]? = some (.mul 297 1460) by decide)
  have e1462 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1462]? = some (.add 1459 1461) by decide)
  have e1463 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1463]? = some (.constant 5) by decide)
  have e1464 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1464]? = some (.mul 298 1463) by decide)
  have e1465 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1465]? = some (.add 1462 1464) by decide)
  have e1466 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1466]? = some (.constant 6) by decide)
  have e1467 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1467]? = some (.mul 299 1466) by decide)
  have e1468 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1468]? = some (.add 1465 1467) by decide)
  have e1469 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1469]? = some (.sub 276 1468) by decide)
  have e1470 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1470]? = some (.mul 1234 1469) by decide)
  simp only [expressionField] at e2 e217 e218 e276 e294 e295 e296 e297 e298 e299 e829 e1234 e1456 e1457 e1458 e1459 e1460 e1461 e1462 e1463 e1464 e1465 e1466 e1467 e1468 e1469 e1470
  rw [e1469,e1468,e1467,e1466,e1465,e1464,e1463,e1462,e1461,e1460,e1459,e1458,e1457,e1456,e1234,e829,e299,e298,e297,e296,e295,e294,e276,e218,e217,e2] at e1470
  exact congrArg some e1470

theorem actual_root_275 (pub rows : Nat → F) :
    (exactNonlinearRoots[275]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * ((rows 181 + (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))) - 1)) := by
  rw [show exactNonlinearRoots[275]? = some 1495 by decide,Option.map_some]
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
  have e1494 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1494]? = some (.sub 1493 1) by decide)
  have e1495 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1495]? = some (.mul 1234 1494) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e301 e302 e303 e304 e305 e1234 e1489 e1490 e1491 e1492 e1493 e1494 e1495
  rw [e1494,e1493,e1492,e1491,e1490,e1489,e1234,e305,e304,e303,e302,e301,e300,e218,e217,e1] at e1495
  exact congrArg some e1495

theorem actual_root_276 (pub rows : Nat → F) :
    (exactNonlinearRoots[276]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 153 - (((((rows 176 + (2 * rows 177)) + (rows 178 * 3)) + (rows 179 * 4)) + (rows 180 * 5)) + (rows 181 * 6)))) := by
  rw [show exactNonlinearRoots[276]? = some 1507 by decide,Option.map_some]
  have e2 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2]? = some (.constant 2) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e277 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[277]? = some (.witnessRow 153) by decide)
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
  have e829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[829]? = some (.constant 3) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1460 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1460]? = some (.constant 4) by decide)
  have e1463 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1463]? = some (.constant 5) by decide)
  have e1466 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1466]? = some (.constant 6) by decide)
  have e1496 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1496]? = some (.mul 2 301) by decide)
  have e1497 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1497]? = some (.add 300 1496) by decide)
  have e1498 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1498]? = some (.mul 302 829) by decide)
  have e1499 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1499]? = some (.add 1497 1498) by decide)
  have e1500 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1500]? = some (.mul 303 1460) by decide)
  have e1501 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1501]? = some (.add 1499 1500) by decide)
  have e1502 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1502]? = some (.mul 304 1463) by decide)
  have e1503 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1503]? = some (.add 1501 1502) by decide)
  have e1504 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1504]? = some (.mul 305 1466) by decide)
  have e1505 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1505]? = some (.add 1503 1504) by decide)
  have e1506 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1506]? = some (.sub 277 1505) by decide)
  have e1507 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1507]? = some (.mul 1234 1506) by decide)
  simp only [expressionField] at e2 e217 e218 e277 e300 e301 e302 e303 e304 e305 e829 e1234 e1460 e1463 e1466 e1496 e1497 e1498 e1499 e1500 e1501 e1502 e1503 e1504 e1505 e1506 e1507
  rw [e1506,e1505,e1504,e1503,e1502,e1501,e1500,e1499,e1498,e1497,e1496,e1466,e1463,e1460,e1234,e829,e305,e304,e303,e302,e301,e300,e277,e218,e217,e2] at e1507
  exact congrArg some e1507

theorem actual_root_277 (pub rows : Nat → F) :
    (exactNonlinearRoots[277]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (((((rows 171 * rows 176) + (rows 172 * (rows 176 + rows 177))) + (rows 173 * (rows 178 + (rows 176 + rows 177)))) + (rows 174 * (rows 179 + (rows 178 + (rows 176 + rows 177))))) + (rows 175 * (rows 180 + (rows 179 + (rows 178 + (rows 176 + rows 177))))))) := by
  rw [show exactNonlinearRoots[277]? = some 1517 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e295 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[295]? = some (.witnessRow 171) by decide)
  have e296 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[296]? = some (.witnessRow 172) by decide)
  have e297 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[297]? = some (.witnessRow 173) by decide)
  have e298 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[298]? = some (.witnessRow 174) by decide)
  have e299 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[299]? = some (.witnessRow 175) by decide)
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
  have e1508 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1508]? = some (.mul 295 300) by decide)
  have e1509 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1509]? = some (.mul 296 1489) by decide)
  have e1510 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1510]? = some (.add 1508 1509) by decide)
  have e1511 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1511]? = some (.mul 297 1490) by decide)
  have e1512 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1512]? = some (.add 1510 1511) by decide)
  have e1513 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1513]? = some (.mul 298 1491) by decide)
  have e1514 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1514]? = some (.add 1512 1513) by decide)
  have e1515 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1515]? = some (.mul 299 1492) by decide)
  have e1516 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1516]? = some (.add 1514 1515) by decide)
  have e1517 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1517]? = some (.mul 1234 1516) by decide)
  simp only [expressionField] at e217 e218 e295 e296 e297 e298 e299 e300 e301 e302 e303 e304 e1234 e1489 e1490 e1491 e1492 e1508 e1509 e1510 e1511 e1512 e1513 e1514 e1515 e1516 e1517
  rw [e1516,e1515,e1514,e1513,e1512,e1511,e1510,e1509,e1508,e1492,e1491,e1490,e1489,e1234,e304,e303,e302,e301,e300,e299,e298,e297,e296,e295,e218,e217] at e1517
  exact congrArg some e1517

theorem actual_root_285 (pub rows : Nat → F) :
    (exactNonlinearRoots[285]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * ((rows 188 + (rows 187 + (rows 186 + (rows 185 + (rows 184 + (rows 182 + rows 183)))))) - 1)) := by
  rw [show exactNonlinearRoots[285]? = some 1546 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e306 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[306]? = some (.witnessRow 182) by decide)
  have e307 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[307]? = some (.witnessRow 183) by decide)
  have e308 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[308]? = some (.witnessRow 184) by decide)
  have e309 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[309]? = some (.witnessRow 185) by decide)
  have e310 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[310]? = some (.witnessRow 186) by decide)
  have e311 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[311]? = some (.witnessRow 187) by decide)
  have e312 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[312]? = some (.witnessRow 188) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1539 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1539]? = some (.add 306 307) by decide)
  have e1540 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1540]? = some (.add 308 1539) by decide)
  have e1541 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1541]? = some (.add 309 1540) by decide)
  have e1542 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1542]? = some (.add 310 1541) by decide)
  have e1543 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1543]? = some (.add 311 1542) by decide)
  have e1544 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1544]? = some (.add 312 1543) by decide)
  have e1545 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1545]? = some (.sub 1544 1) by decide)
  have e1546 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1546]? = some (.mul 1234 1545) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e306 e307 e308 e309 e310 e311 e312 e1234 e1539 e1540 e1541 e1542 e1543 e1544 e1545 e1546
  rw [e1545,e1544,e1543,e1542,e1541,e1540,e1539,e1234,e312,e311,e310,e309,e308,e307,e306,e218,e217,e1] at e1546
  exact congrArg some e1546

theorem actual_root_286 (pub rows : Nat → F) :
    (exactNonlinearRoots[286]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 154 - (((((rows 183 + (2 * rows 184)) + (rows 185 * 3)) + (rows 186 * 4)) + (rows 187 * 5)) + (rows 188 * 6)))) := by
  rw [show exactNonlinearRoots[286]? = some 1558 by decide,Option.map_some]
  have e2 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2]? = some (.constant 2) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e278 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[278]? = some (.witnessRow 154) by decide)
  have e307 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[307]? = some (.witnessRow 183) by decide)
  have e308 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[308]? = some (.witnessRow 184) by decide)
  have e309 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[309]? = some (.witnessRow 185) by decide)
  have e310 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[310]? = some (.witnessRow 186) by decide)
  have e311 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[311]? = some (.witnessRow 187) by decide)
  have e312 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[312]? = some (.witnessRow 188) by decide)
  have e829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[829]? = some (.constant 3) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1460 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1460]? = some (.constant 4) by decide)
  have e1463 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1463]? = some (.constant 5) by decide)
  have e1466 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1466]? = some (.constant 6) by decide)
  have e1547 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1547]? = some (.mul 2 308) by decide)
  have e1548 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1548]? = some (.add 307 1547) by decide)
  have e1549 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1549]? = some (.mul 309 829) by decide)
  have e1550 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1550]? = some (.add 1548 1549) by decide)
  have e1551 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1551]? = some (.mul 310 1460) by decide)
  have e1552 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1552]? = some (.add 1550 1551) by decide)
  have e1553 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1553]? = some (.mul 311 1463) by decide)
  have e1554 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1554]? = some (.add 1552 1553) by decide)
  have e1555 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1555]? = some (.mul 312 1466) by decide)
  have e1556 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1556]? = some (.add 1554 1555) by decide)
  have e1557 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1557]? = some (.sub 278 1556) by decide)
  have e1558 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1558]? = some (.mul 1234 1557) by decide)
  simp only [expressionField] at e2 e217 e218 e278 e307 e308 e309 e310 e311 e312 e829 e1234 e1460 e1463 e1466 e1547 e1548 e1549 e1550 e1551 e1552 e1553 e1554 e1555 e1556 e1557 e1558
  rw [e1557,e1556,e1555,e1554,e1553,e1552,e1551,e1550,e1549,e1548,e1547,e1466,e1463,e1460,e1234,e829,e312,e311,e310,e309,e308,e307,e278,e218,e217,e2] at e1558
  exact congrArg some e1558

theorem actual_root_294 (pub rows : Nat → F) :
    (exactNonlinearRoots[294]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * ((rows 195 + (rows 194 + (rows 193 + (rows 192 + (rows 191 + (rows 189 + rows 190)))))) - 1)) := by
  rw [show exactNonlinearRoots[294]? = some 1587 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e313 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[313]? = some (.witnessRow 189) by decide)
  have e314 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[314]? = some (.witnessRow 190) by decide)
  have e315 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[315]? = some (.witnessRow 191) by decide)
  have e316 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[316]? = some (.witnessRow 192) by decide)
  have e317 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[317]? = some (.witnessRow 193) by decide)
  have e318 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[318]? = some (.witnessRow 194) by decide)
  have e319 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[319]? = some (.witnessRow 195) by decide)
  have e1580 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1580]? = some (.add 313 314) by decide)
  have e1581 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1581]? = some (.add 315 1580) by decide)
  have e1582 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1582]? = some (.add 316 1581) by decide)
  have e1583 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1583]? = some (.add 317 1582) by decide)
  have e1584 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1584]? = some (.add 318 1583) by decide)
  have e1585 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1585]? = some (.add 319 1584) by decide)
  have e1586 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1586]? = some (.sub 1585 1) by decide)
  have e1587 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1587]? = some (.mul 217 1586) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e313 e314 e315 e316 e317 e318 e319 e1580 e1581 e1582 e1583 e1584 e1585 e1586 e1587
  rw [e1586,e1585,e1584,e1583,e1582,e1581,e1580,e319,e318,e317,e316,e315,e314,e313,e217,e1] at e1587
  exact congrArg some e1587

theorem actual_root_295 (pub rows : Nat → F) :
    (exactNonlinearRoots[295]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 161 - (((((rows 190 + (2 * rows 191)) + (rows 192 * 3)) + (rows 193 * 4)) + (rows 194 * 5)) + (rows 195 * 6)))) := by
  rw [show exactNonlinearRoots[295]? = some 1599 by decide,Option.map_some]
  have e2 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2]? = some (.constant 2) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e285 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[285]? = some (.witnessRow 161) by decide)
  have e314 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[314]? = some (.witnessRow 190) by decide)
  have e315 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[315]? = some (.witnessRow 191) by decide)
  have e316 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[316]? = some (.witnessRow 192) by decide)
  have e317 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[317]? = some (.witnessRow 193) by decide)
  have e318 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[318]? = some (.witnessRow 194) by decide)
  have e319 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[319]? = some (.witnessRow 195) by decide)
  have e829 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[829]? = some (.constant 3) by decide)
  have e1460 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1460]? = some (.constant 4) by decide)
  have e1463 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1463]? = some (.constant 5) by decide)
  have e1466 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1466]? = some (.constant 6) by decide)
  have e1588 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1588]? = some (.mul 2 315) by decide)
  have e1589 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1589]? = some (.add 314 1588) by decide)
  have e1590 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1590]? = some (.mul 316 829) by decide)
  have e1591 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1591]? = some (.add 1589 1590) by decide)
  have e1592 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1592]? = some (.mul 317 1460) by decide)
  have e1593 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1593]? = some (.add 1591 1592) by decide)
  have e1594 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1594]? = some (.mul 318 1463) by decide)
  have e1595 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1595]? = some (.add 1593 1594) by decide)
  have e1596 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1596]? = some (.mul 319 1466) by decide)
  have e1597 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1597]? = some (.add 1595 1596) by decide)
  have e1598 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1598]? = some (.sub 285 1597) by decide)
  have e1599 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1599]? = some (.mul 217 1598) by decide)
  simp only [expressionField] at e2 e217 e285 e314 e315 e316 e317 e318 e319 e829 e1460 e1463 e1466 e1588 e1589 e1590 e1591 e1592 e1593 e1594 e1595 e1596 e1597 e1598 e1599
  rw [e1598,e1597,e1596,e1595,e1594,e1593,e1592,e1591,e1590,e1589,e1588,e1466,e1463,e1460,e829,e319,e318,e317,e316,e315,e314,e285,e217,e2] at e1599
  exact congrArg some e1599

theorem actual_root_296 (pub rows : Nat → F) :
    (exactNonlinearRoots[296]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * ((rows 161 - rows 154) - 1)) := by
  rw [show exactNonlinearRoots[296]? = some 1602 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e278 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[278]? = some (.witnessRow 154) by decide)
  have e285 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[285]? = some (.witnessRow 161) by decide)
  have e1600 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1600]? = some (.sub 285 278) by decide)
  have e1601 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1601]? = some (.sub 1600 1) by decide)
  have e1602 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1602]? = some (.mul 217 1601) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e278 e285 e1600 e1601 e1602
  rw [e1601,e1600,e285,e278,e217,e1] at e1602
  exact congrArg some e1602

theorem actual_root_297 (pub rows : Nat → F) :
    (exactNonlinearRoots[297]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * rows 188) := by
  rw [show exactNonlinearRoots[297]? = some 1603 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e312 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[312]? = some (.witnessRow 188) by decide)
  have e1603 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1603]? = some (.mul 217 312) by decide)
  simp only [expressionField] at e217 e312 e1603
  rw [e312,e217] at e1603
  exact congrArg some e1603

theorem actual_root_441 (pub rows : Nat → F) :
    (exactNonlinearRoots[441]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * ((((((rows 170 * rows 182) + (rows 171 * (rows 182 + rows 183))) + (rows 172 * (rows 184 + (rows 182 + rows 183)))) + (rows 173 * (rows 185 + (rows 184 + (rows 182 + rows 183))))) + (rows 174 * (rows 186 + (rows 185 + (rows 184 + (rows 182 + rows 183)))))) + (rows 175 * (rows 187 + (rows 186 + (rows 185 + (rows 184 + (rows 182 + rows 183)))))))) := by
  rw [show exactNonlinearRoots[441]? = some 1999 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e294 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[294]? = some (.witnessRow 170) by decide)
  have e295 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[295]? = some (.witnessRow 171) by decide)
  have e296 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[296]? = some (.witnessRow 172) by decide)
  have e297 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[297]? = some (.witnessRow 173) by decide)
  have e298 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[298]? = some (.witnessRow 174) by decide)
  have e299 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[299]? = some (.witnessRow 175) by decide)
  have e306 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[306]? = some (.witnessRow 182) by decide)
  have e307 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[307]? = some (.witnessRow 183) by decide)
  have e308 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[308]? = some (.witnessRow 184) by decide)
  have e309 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[309]? = some (.witnessRow 185) by decide)
  have e310 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[310]? = some (.witnessRow 186) by decide)
  have e311 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[311]? = some (.witnessRow 187) by decide)
  have e1539 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1539]? = some (.add 306 307) by decide)
  have e1540 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1540]? = some (.add 308 1539) by decide)
  have e1541 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1541]? = some (.add 309 1540) by decide)
  have e1542 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1542]? = some (.add 310 1541) by decide)
  have e1543 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1543]? = some (.add 311 1542) by decide)
  have e1988 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1988]? = some (.mul 294 306) by decide)
  have e1989 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1989]? = some (.mul 295 1539) by decide)
  have e1990 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1990]? = some (.add 1988 1989) by decide)
  have e1991 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1991]? = some (.mul 296 1540) by decide)
  have e1992 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1992]? = some (.add 1990 1991) by decide)
  have e1993 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1993]? = some (.mul 297 1541) by decide)
  have e1994 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1994]? = some (.add 1992 1993) by decide)
  have e1995 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1995]? = some (.mul 298 1542) by decide)
  have e1996 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1996]? = some (.add 1994 1995) by decide)
  have e1997 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1997]? = some (.mul 299 1543) by decide)
  have e1998 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1998]? = some (.add 1996 1997) by decide)
  have e1999 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1999]? = some (.mul 218 1998) by decide)
  simp only [expressionField] at e218 e294 e295 e296 e297 e298 e299 e306 e307 e308 e309 e310 e311 e1539 e1540 e1541 e1542 e1543 e1988 e1989 e1990 e1991 e1992 e1993 e1994 e1995 e1996 e1997 e1998 e1999
  rw [e1998,e1997,e1996,e1995,e1994,e1993,e1992,e1991,e1990,e1989,e1988,e1543,e1542,e1541,e1540,e1539,e311,e310,e309,e308,e307,e306,e299,e298,e297,e296,e295,e294,e218] at e1999
  exact congrArg some e1999

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticDAG
