import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingDAG
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem actual_root_252 (pub rows : Nat → F) :
    (exactNonlinearRoots[252]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (pub 0 - 1)) := by
  rw [show exactNonlinearRoots[252]? = some 1418 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e4 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[4]? = some (.publicWord 0) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e810 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[810]? = some (.sub 4 1) by decide)
  have e1418 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1418]? = some (.mul 217 810) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e4 e217 e810 e1418
  rw [e810,e217,e4,e1] at e1418
  exact congrArg some e1418

theorem actual_root_253 (pub rows : Nat → F) :
    (exactNonlinearRoots[253]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (pub 1 - 1)) := by
  rw [show exactNonlinearRoots[253]? = some 1419 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e5 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[5]? = some (.publicWord 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e812 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[812]? = some (.sub 5 1) by decide)
  have e1419 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1419]? = some (.mul 217 812) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e5 e217 e812 e1419
  rw [e812,e217,e5,e1] at e1419
  exact congrArg some e1419

theorem actual_root_254 (pub rows : Nat → F) :
    (exactNonlinearRoots[254]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (pub 2 - 1)) := by
  rw [show exactNonlinearRoots[254]? = some 1420 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e6 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[6]? = some (.publicWord 2) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e814 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[814]? = some (.sub 6 1) by decide)
  have e1420 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1420]? = some (.mul 217 814) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e6 e217 e814 e1420
  rw [e814,e217,e6,e1] at e1420
  exact congrArg some e1420

theorem actual_root_255 (pub rows : Nat → F) :
    (exactNonlinearRoots[255]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (pub 0 - 1)) := by
  rw [show exactNonlinearRoots[255]? = some 1421 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e4 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[4]? = some (.publicWord 0) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e810 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[810]? = some (.sub 4 1) by decide)
  have e1421 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1421]? = some (.mul 218 810) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e4 e218 e810 e1421
  rw [e810,e218,e4,e1] at e1421
  exact congrArg some e1421

theorem actual_root_256 (pub rows : Nat → F) :
    (exactNonlinearRoots[256]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (pub 1 - 1)) := by
  rw [show exactNonlinearRoots[256]? = some 1422 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e5 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[5]? = some (.publicWord 1) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e812 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[812]? = some (.sub 5 1) by decide)
  have e1422 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1422]? = some (.mul 218 812) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e5 e218 e812 e1422
  rw [e812,e218,e5,e1] at e1422
  exact congrArg some e1422

theorem actual_root_261 (pub rows : Nat → F) :
    (exactNonlinearRoots[261]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 170 * (rows 170 - 1))) := by
  rw [show exactNonlinearRoots[261]? = some 1433 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e294 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[294]? = some (.witnessRow 170) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1431 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1431]? = some (.sub 294 1) by decide)
  have e1432 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1432]? = some (.mul 294 1431) by decide)
  have e1433 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1433]? = some (.mul 1234 1432) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e294 e1234 e1431 e1432 e1433
  rw [e1432,e1431,e1234,e294,e218,e217,e1] at e1433
  exact congrArg some e1433

theorem actual_root_262 (pub rows : Nat → F) :
    (exactNonlinearRoots[262]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 171 * (rows 171 - 1))) := by
  rw [show exactNonlinearRoots[262]? = some 1436 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e295 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[295]? = some (.witnessRow 171) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1434 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1434]? = some (.sub 295 1) by decide)
  have e1435 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1435]? = some (.mul 295 1434) by decide)
  have e1436 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1436]? = some (.mul 1234 1435) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e295 e1234 e1434 e1435 e1436
  rw [e1435,e1434,e1234,e295,e218,e217,e1] at e1436
  exact congrArg some e1436

theorem actual_root_263 (pub rows : Nat → F) :
    (exactNonlinearRoots[263]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 172 * (rows 172 - 1))) := by
  rw [show exactNonlinearRoots[263]? = some 1439 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e296 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[296]? = some (.witnessRow 172) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1437 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1437]? = some (.sub 296 1) by decide)
  have e1438 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1438]? = some (.mul 296 1437) by decide)
  have e1439 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1439]? = some (.mul 1234 1438) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e296 e1234 e1437 e1438 e1439
  rw [e1438,e1437,e1234,e296,e218,e217,e1] at e1439
  exact congrArg some e1439

theorem actual_root_264 (pub rows : Nat → F) :
    (exactNonlinearRoots[264]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 173 * (rows 173 - 1))) := by
  rw [show exactNonlinearRoots[264]? = some 1442 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e297 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[297]? = some (.witnessRow 173) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1440 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1440]? = some (.sub 297 1) by decide)
  have e1441 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1441]? = some (.mul 297 1440) by decide)
  have e1442 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1442]? = some (.mul 1234 1441) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e297 e1234 e1440 e1441 e1442
  rw [e1441,e1440,e1234,e297,e218,e217,e1] at e1442
  exact congrArg some e1442

theorem actual_root_265 (pub rows : Nat → F) :
    (exactNonlinearRoots[265]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 174 * (rows 174 - 1))) := by
  rw [show exactNonlinearRoots[265]? = some 1445 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e298 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[298]? = some (.witnessRow 174) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1443 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1443]? = some (.sub 298 1) by decide)
  have e1444 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1444]? = some (.mul 298 1443) by decide)
  have e1445 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1445]? = some (.mul 1234 1444) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e298 e1234 e1443 e1444 e1445
  rw [e1444,e1443,e1234,e298,e218,e217,e1] at e1445
  exact congrArg some e1445

theorem actual_root_266 (pub rows : Nat → F) :
    (exactNonlinearRoots[266]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 175 * (rows 175 - 1))) := by
  rw [show exactNonlinearRoots[266]? = some 1448 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e299 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[299]? = some (.witnessRow 175) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1446 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1446]? = some (.sub 299 1) by decide)
  have e1447 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1447]? = some (.mul 299 1446) by decide)
  have e1448 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1448]? = some (.mul 1234 1447) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e299 e1234 e1446 e1447 e1448
  rw [e1447,e1446,e1234,e299,e218,e217,e1] at e1448
  exact congrArg some e1448

theorem actual_root_269 (pub rows : Nat → F) :
    (exactNonlinearRoots[269]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 176 * (rows 176 - 1))) := by
  rw [show exactNonlinearRoots[269]? = some 1473 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e300 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[300]? = some (.witnessRow 176) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1471 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1471]? = some (.sub 300 1) by decide)
  have e1472 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1472]? = some (.mul 300 1471) by decide)
  have e1473 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1473]? = some (.mul 1234 1472) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e300 e1234 e1471 e1472 e1473
  rw [e1472,e1471,e1234,e300,e218,e217,e1] at e1473
  exact congrArg some e1473

theorem actual_root_270 (pub rows : Nat → F) :
    (exactNonlinearRoots[270]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 177 * (rows 177 - 1))) := by
  rw [show exactNonlinearRoots[270]? = some 1476 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e301 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[301]? = some (.witnessRow 177) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1474 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1474]? = some (.sub 301 1) by decide)
  have e1475 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1475]? = some (.mul 301 1474) by decide)
  have e1476 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1476]? = some (.mul 1234 1475) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e301 e1234 e1474 e1475 e1476
  rw [e1475,e1474,e1234,e301,e218,e217,e1] at e1476
  exact congrArg some e1476

theorem actual_root_271 (pub rows : Nat → F) :
    (exactNonlinearRoots[271]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 178 * (rows 178 - 1))) := by
  rw [show exactNonlinearRoots[271]? = some 1479 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e302 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[302]? = some (.witnessRow 178) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1477 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1477]? = some (.sub 302 1) by decide)
  have e1478 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1478]? = some (.mul 302 1477) by decide)
  have e1479 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1479]? = some (.mul 1234 1478) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e302 e1234 e1477 e1478 e1479
  rw [e1478,e1477,e1234,e302,e218,e217,e1] at e1479
  exact congrArg some e1479

theorem actual_root_272 (pub rows : Nat → F) :
    (exactNonlinearRoots[272]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 179 * (rows 179 - 1))) := by
  rw [show exactNonlinearRoots[272]? = some 1482 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e303 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[303]? = some (.witnessRow 179) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1480 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1480]? = some (.sub 303 1) by decide)
  have e1481 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1481]? = some (.mul 303 1480) by decide)
  have e1482 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1482]? = some (.mul 1234 1481) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e303 e1234 e1480 e1481 e1482
  rw [e1481,e1480,e1234,e303,e218,e217,e1] at e1482
  exact congrArg some e1482

theorem actual_root_273 (pub rows : Nat → F) :
    (exactNonlinearRoots[273]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 180 * (rows 180 - 1))) := by
  rw [show exactNonlinearRoots[273]? = some 1485 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e304 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[304]? = some (.witnessRow 180) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1483 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1483]? = some (.sub 304 1) by decide)
  have e1484 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1484]? = some (.mul 304 1483) by decide)
  have e1485 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1485]? = some (.mul 1234 1484) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e304 e1234 e1483 e1484 e1485
  rw [e1484,e1483,e1234,e304,e218,e217,e1] at e1485
  exact congrArg some e1485

theorem actual_root_274 (pub rows : Nat → F) :
    (exactNonlinearRoots[274]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 181 * (rows 181 - 1))) := by
  rw [show exactNonlinearRoots[274]? = some 1488 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e305 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[305]? = some (.witnessRow 181) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1486 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1486]? = some (.sub 305 1) by decide)
  have e1487 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1487]? = some (.mul 305 1486) by decide)
  have e1488 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1488]? = some (.mul 1234 1487) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e305 e1234 e1486 e1487 e1488
  rw [e1487,e1486,e1234,e305,e218,e217,e1] at e1488
  exact congrArg some e1488

theorem actual_root_278 (pub rows : Nat → F) :
    (exactNonlinearRoots[278]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 182 * (rows 182 - 1))) := by
  rw [show exactNonlinearRoots[278]? = some 1520 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e306 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[306]? = some (.witnessRow 182) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1518 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1518]? = some (.sub 306 1) by decide)
  have e1519 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1519]? = some (.mul 306 1518) by decide)
  have e1520 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1520]? = some (.mul 1234 1519) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e306 e1234 e1518 e1519 e1520
  rw [e1519,e1518,e1234,e306,e218,e217,e1] at e1520
  exact congrArg some e1520

theorem actual_root_279 (pub rows : Nat → F) :
    (exactNonlinearRoots[279]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 183 * (rows 183 - 1))) := by
  rw [show exactNonlinearRoots[279]? = some 1523 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e307 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[307]? = some (.witnessRow 183) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1521 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1521]? = some (.sub 307 1) by decide)
  have e1522 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1522]? = some (.mul 307 1521) by decide)
  have e1523 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1523]? = some (.mul 1234 1522) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e307 e1234 e1521 e1522 e1523
  rw [e1522,e1521,e1234,e307,e218,e217,e1] at e1523
  exact congrArg some e1523

theorem actual_root_280 (pub rows : Nat → F) :
    (exactNonlinearRoots[280]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 184 * (rows 184 - 1))) := by
  rw [show exactNonlinearRoots[280]? = some 1526 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e308 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[308]? = some (.witnessRow 184) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1524 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1524]? = some (.sub 308 1) by decide)
  have e1525 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1525]? = some (.mul 308 1524) by decide)
  have e1526 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1526]? = some (.mul 1234 1525) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e308 e1234 e1524 e1525 e1526
  rw [e1525,e1524,e1234,e308,e218,e217,e1] at e1526
  exact congrArg some e1526

theorem actual_root_281 (pub rows : Nat → F) :
    (exactNonlinearRoots[281]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 185 * (rows 185 - 1))) := by
  rw [show exactNonlinearRoots[281]? = some 1529 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e309 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[309]? = some (.witnessRow 185) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1527 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1527]? = some (.sub 309 1) by decide)
  have e1528 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1528]? = some (.mul 309 1527) by decide)
  have e1529 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1529]? = some (.mul 1234 1528) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e309 e1234 e1527 e1528 e1529
  rw [e1528,e1527,e1234,e309,e218,e217,e1] at e1529
  exact congrArg some e1529

theorem actual_root_282 (pub rows : Nat → F) :
    (exactNonlinearRoots[282]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 186 * (rows 186 - 1))) := by
  rw [show exactNonlinearRoots[282]? = some 1532 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e310 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[310]? = some (.witnessRow 186) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1530 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1530]? = some (.sub 310 1) by decide)
  have e1531 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1531]? = some (.mul 310 1530) by decide)
  have e1532 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1532]? = some (.mul 1234 1531) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e310 e1234 e1530 e1531 e1532
  rw [e1531,e1530,e1234,e310,e218,e217,e1] at e1532
  exact congrArg some e1532

theorem actual_root_283 (pub rows : Nat → F) :
    (exactNonlinearRoots[283]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 187 * (rows 187 - 1))) := by
  rw [show exactNonlinearRoots[283]? = some 1535 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e311 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[311]? = some (.witnessRow 187) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1533 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1533]? = some (.sub 311 1) by decide)
  have e1534 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1534]? = some (.mul 311 1533) by decide)
  have e1535 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1535]? = some (.mul 1234 1534) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e311 e1234 e1533 e1534 e1535
  rw [e1534,e1533,e1234,e311,e218,e217,e1] at e1535
  exact congrArg some e1535

theorem actual_root_284 (pub rows : Nat → F) :
    (exactNonlinearRoots[284]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some ((rows 93 + rows 94) * (rows 188 * (rows 188 - 1))) := by
  rw [show exactNonlinearRoots[284]? = some 1538 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e312 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[312]? = some (.witnessRow 188) by decide)
  have e1234 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1234]? = some (.add 217 218) by decide)
  have e1536 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1536]? = some (.sub 312 1) by decide)
  have e1537 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1537]? = some (.mul 312 1536) by decide)
  have e1538 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1538]? = some (.mul 1234 1537) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e218 e312 e1234 e1536 e1537 e1538
  rw [e1537,e1536,e1234,e312,e218,e217,e1] at e1538
  exact congrArg some e1538

theorem actual_root_287 (pub rows : Nat → F) :
    (exactNonlinearRoots[287]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 189 * (rows 189 - 1))) := by
  rw [show exactNonlinearRoots[287]? = some 1561 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e313 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[313]? = some (.witnessRow 189) by decide)
  have e1559 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1559]? = some (.sub 313 1) by decide)
  have e1560 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1560]? = some (.mul 313 1559) by decide)
  have e1561 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1561]? = some (.mul 217 1560) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e313 e1559 e1560 e1561
  rw [e1560,e1559,e313,e217,e1] at e1561
  exact congrArg some e1561

theorem actual_root_288 (pub rows : Nat → F) :
    (exactNonlinearRoots[288]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 190 * (rows 190 - 1))) := by
  rw [show exactNonlinearRoots[288]? = some 1564 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e314 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[314]? = some (.witnessRow 190) by decide)
  have e1562 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1562]? = some (.sub 314 1) by decide)
  have e1563 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1563]? = some (.mul 314 1562) by decide)
  have e1564 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1564]? = some (.mul 217 1563) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e314 e1562 e1563 e1564
  rw [e1563,e1562,e314,e217,e1] at e1564
  exact congrArg some e1564

theorem actual_root_289 (pub rows : Nat → F) :
    (exactNonlinearRoots[289]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 191 * (rows 191 - 1))) := by
  rw [show exactNonlinearRoots[289]? = some 1567 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e315 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[315]? = some (.witnessRow 191) by decide)
  have e1565 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1565]? = some (.sub 315 1) by decide)
  have e1566 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1566]? = some (.mul 315 1565) by decide)
  have e1567 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1567]? = some (.mul 217 1566) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e315 e1565 e1566 e1567
  rw [e1566,e1565,e315,e217,e1] at e1567
  exact congrArg some e1567

theorem actual_root_290 (pub rows : Nat → F) :
    (exactNonlinearRoots[290]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 192 * (rows 192 - 1))) := by
  rw [show exactNonlinearRoots[290]? = some 1570 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e316 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[316]? = some (.witnessRow 192) by decide)
  have e1568 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1568]? = some (.sub 316 1) by decide)
  have e1569 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1569]? = some (.mul 316 1568) by decide)
  have e1570 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1570]? = some (.mul 217 1569) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e316 e1568 e1569 e1570
  rw [e1569,e1568,e316,e217,e1] at e1570
  exact congrArg some e1570

theorem actual_root_291 (pub rows : Nat → F) :
    (exactNonlinearRoots[291]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 193 * (rows 193 - 1))) := by
  rw [show exactNonlinearRoots[291]? = some 1573 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e317 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[317]? = some (.witnessRow 193) by decide)
  have e1571 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1571]? = some (.sub 317 1) by decide)
  have e1572 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1572]? = some (.mul 317 1571) by decide)
  have e1573 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1573]? = some (.mul 217 1572) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e317 e1571 e1572 e1573
  rw [e1572,e1571,e317,e217,e1] at e1573
  exact congrArg some e1573

theorem actual_root_292 (pub rows : Nat → F) :
    (exactNonlinearRoots[292]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 194 * (rows 194 - 1))) := by
  rw [show exactNonlinearRoots[292]? = some 1576 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e318 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[318]? = some (.witnessRow 194) by decide)
  have e1574 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1574]? = some (.sub 318 1) by decide)
  have e1575 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1575]? = some (.mul 318 1574) by decide)
  have e1576 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1576]? = some (.mul 217 1575) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e318 e1574 e1575 e1576
  rw [e1575,e1574,e318,e217,e1] at e1576
  exact congrArg some e1576

theorem actual_root_293 (pub rows : Nat → F) :
    (exactNonlinearRoots[293]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 195 * (rows 195 - 1))) := by
  rw [show exactNonlinearRoots[293]? = some 1579 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e319 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[319]? = some (.witnessRow 195) by decide)
  have e1577 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1577]? = some (.sub 319 1) by decide)
  have e1578 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1578]? = some (.mul 319 1577) by decide)
  have e1579 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1579]? = some (.mul 217 1578) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e319 e1577 e1578 e1579
  rw [e1578,e1577,e319,e217,e1] at e1579
  exact congrArg some e1579

theorem actual_root_336 (pub rows : Nat → F) :
    (exactNonlinearRoots[336]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * rows 168) := by
  rw [show exactNonlinearRoots[336]? = some 1724 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e292 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[292]? = some (.witnessRow 168) by decide)
  have e1724 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1724]? = some (.mul 217 292) by decide)
  simp only [expressionField] at e217 e292 e1724
  rw [e292,e217] at e1724
  exact congrArg some e1724

theorem actual_root_337 (pub rows : Nat → F) :
    (exactNonlinearRoots[337]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * rows 169) := by
  rw [show exactNonlinearRoots[337]? = some 1725 by decide,Option.map_some]
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e293 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[293]? = some (.witnessRow 169) by decide)
  have e1725 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1725]? = some (.mul 217 293) by decide)
  simp only [expressionField] at e217 e293 e1725
  rw [e293,e217] at e1725
  exact congrArg some e1725

theorem actual_root_338 (pub rows : Nat → F) :
    (exactNonlinearRoots[338]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 226 * (rows 226 - 1))) := by
  rw [show exactNonlinearRoots[338]? = some 1728 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e350 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[350]? = some (.witnessRow 226) by decide)
  have e1726 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1726]? = some (.sub 350 1) by decide)
  have e1727 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1727]? = some (.mul 350 1726) by decide)
  have e1728 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1728]? = some (.mul 217 1727) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e350 e1726 e1727 e1728
  rw [e1727,e1726,e350,e217,e1] at e1728
  exact congrArg some e1728

theorem actual_root_339 (pub rows : Nat → F) :
    (exactNonlinearRoots[339]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 227 * (rows 227 - 1))) := by
  rw [show exactNonlinearRoots[339]? = some 1731 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e351 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[351]? = some (.witnessRow 227) by decide)
  have e1729 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1729]? = some (.sub 351 1) by decide)
  have e1730 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1730]? = some (.mul 351 1729) by decide)
  have e1731 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1731]? = some (.mul 217 1730) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e351 e1729 e1730 e1731
  rw [e1730,e1729,e351,e217,e1] at e1731
  exact congrArg some e1731

theorem actual_root_340 (pub rows : Nat → F) :
    (exactNonlinearRoots[340]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 228 * (rows 228 - 1))) := by
  rw [show exactNonlinearRoots[340]? = some 1734 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e352 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[352]? = some (.witnessRow 228) by decide)
  have e1732 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1732]? = some (.sub 352 1) by decide)
  have e1733 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1733]? = some (.mul 352 1732) by decide)
  have e1734 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1734]? = some (.mul 217 1733) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e352 e1732 e1733 e1734
  rw [e1733,e1732,e352,e217,e1] at e1734
  exact congrArg some e1734

theorem actual_root_341 (pub rows : Nat → F) :
    (exactNonlinearRoots[341]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 229 * (rows 229 - 1))) := by
  rw [show exactNonlinearRoots[341]? = some 1737 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e353 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[353]? = some (.witnessRow 229) by decide)
  have e1735 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1735]? = some (.sub 353 1) by decide)
  have e1736 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1736]? = some (.mul 353 1735) by decide)
  have e1737 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1737]? = some (.mul 217 1736) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e353 e1735 e1736 e1737
  rw [e1736,e1735,e353,e217,e1] at e1737
  exact congrArg some e1737

theorem actual_root_342 (pub rows : Nat → F) :
    (exactNonlinearRoots[342]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 230 * (rows 230 - 1))) := by
  rw [show exactNonlinearRoots[342]? = some 1740 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e354 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[354]? = some (.witnessRow 230) by decide)
  have e1738 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1738]? = some (.sub 354 1) by decide)
  have e1739 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1739]? = some (.mul 354 1738) by decide)
  have e1740 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1740]? = some (.mul 217 1739) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e354 e1738 e1739 e1740
  rw [e1739,e1738,e354,e217,e1] at e1740
  exact congrArg some e1740

theorem actual_root_343 (pub rows : Nat → F) :
    (exactNonlinearRoots[343]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 93 * (rows 231 * (rows 231 - 1))) := by
  rw [show exactNonlinearRoots[343]? = some 1743 by decide,Option.map_some]
  have e1 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1]? = some (.constant 1) by decide)
  have e217 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[217]? = some (.witnessRow 93) by decide)
  have e355 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[355]? = some (.witnessRow 231) by decide)
  have e1741 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1741]? = some (.sub 355 1) by decide)
  have e1742 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1742]? = some (.mul 355 1741) by decide)
  have e1743 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1743]? = some (.mul 217 1742) by decide)
  simp only [expressionField,Nat.cast_one] at e1 e217 e355 e1741 e1742 e1743
  rw [e1742,e1741,e355,e217,e1] at e1743
  exact congrArg some e1743

theorem actual_root_442 (pub rows : Nat → F) :
    (exactNonlinearRoots[442]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 145 - rows 131)) := by
  rw [show exactNonlinearRoots[442]? = some 2001 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e255 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[255]? = some (.witnessRow 131) by decide)
  have e269 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[269]? = some (.witnessRow 145) by decide)
  have e2000 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2000]? = some (.sub 269 255) by decide)
  have e2001 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2001]? = some (.mul 218 2000) by decide)
  simp only [expressionField] at e218 e255 e269 e2000 e2001
  rw [e2000,e269,e255,e218] at e2001
  exact congrArg some e2001

theorem actual_root_443 (pub rows : Nat → F) :
    (exactNonlinearRoots[443]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 146 - rows 132)) := by
  rw [show exactNonlinearRoots[443]? = some 2003 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e256 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[256]? = some (.witnessRow 132) by decide)
  have e270 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[270]? = some (.witnessRow 146) by decide)
  have e2002 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2002]? = some (.sub 270 256) by decide)
  have e2003 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2003]? = some (.mul 218 2002) by decide)
  simp only [expressionField] at e218 e256 e270 e2002 e2003
  rw [e2002,e270,e256,e218] at e2003
  exact congrArg some e2003

theorem actual_root_444 (pub rows : Nat → F) :
    (exactNonlinearRoots[444]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 147 - rows 133)) := by
  rw [show exactNonlinearRoots[444]? = some 2005 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e257 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[257]? = some (.witnessRow 133) by decide)
  have e271 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[271]? = some (.witnessRow 147) by decide)
  have e2004 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2004]? = some (.sub 271 257) by decide)
  have e2005 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2005]? = some (.mul 218 2004) by decide)
  simp only [expressionField] at e218 e257 e271 e2004 e2005
  rw [e2004,e271,e257,e218] at e2005
  exact congrArg some e2005

theorem actual_root_445 (pub rows : Nat → F) :
    (exactNonlinearRoots[445]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 148 - rows 134)) := by
  rw [show exactNonlinearRoots[445]? = some 2007 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e258 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[258]? = some (.witnessRow 134) by decide)
  have e272 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[272]? = some (.witnessRow 148) by decide)
  have e2006 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2006]? = some (.sub 272 258) by decide)
  have e2007 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2007]? = some (.mul 218 2006) by decide)
  simp only [expressionField] at e218 e258 e272 e2006 e2007
  rw [e2006,e272,e258,e218] at e2007
  exact congrArg some e2007

theorem actual_root_446 (pub rows : Nat → F) :
    (exactNonlinearRoots[446]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 149 - rows 135)) := by
  rw [show exactNonlinearRoots[446]? = some 2009 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e259 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[259]? = some (.witnessRow 135) by decide)
  have e273 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[273]? = some (.witnessRow 149) by decide)
  have e2008 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2008]? = some (.sub 273 259) by decide)
  have e2009 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2009]? = some (.mul 218 2008) by decide)
  simp only [expressionField] at e218 e259 e273 e2008 e2009
  rw [e2008,e273,e259,e218] at e2009
  exact congrArg some e2009

theorem actual_root_447 (pub rows : Nat → F) :
    (exactNonlinearRoots[447]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 150 - rows 136)) := by
  rw [show exactNonlinearRoots[447]? = some 2011 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e260 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[260]? = some (.witnessRow 136) by decide)
  have e274 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[274]? = some (.witnessRow 150) by decide)
  have e2010 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2010]? = some (.sub 274 260) by decide)
  have e2011 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2011]? = some (.mul 218 2010) by decide)
  simp only [expressionField] at e218 e260 e274 e2010 e2011
  rw [e2010,e274,e260,e218] at e2011
  exact congrArg some e2011

theorem actual_root_448 (pub rows : Nat → F) :
    (exactNonlinearRoots[448]?).map (fieldAt exactNonlinearExpressions pub rows) =
      some (rows 94 * (rows 151 - rows 137)) := by
  rw [show exactNonlinearRoots[448]? = some 2013 by decide,Option.map_some]
  have e218 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[218]? = some (.witnessRow 94) by decide)
  have e261 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[261]? = some (.witnessRow 137) by decide)
  have e275 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[275]? = some (.witnessRow 151) by decide)
  have e2012 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2012]? = some (.sub 275 261) by decide)
  have e2013 := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[2013]? = some (.mul 218 2012) by decide)
  simp only [expressionField] at e218 e261 e275 e2012 e2013
  rw [e2012,e275,e261,e218] at e2013
  exact congrArg some e2013

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingDAG
