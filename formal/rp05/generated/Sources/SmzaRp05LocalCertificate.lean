import SmzaRp05TypedRelation
import SmzaRp05Components
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Exact HGV8RP05 local AUTH root certificate, generated from SHA-pinned bytes.
    Every `Realizes` constructor below proves an exact list lookup/edge.
    This file has no arbitrary witness-to-semantics assumption. -/
namespace HegemonCrypto.SmallWood.SmzaRp05LocalCertificate
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def rootIndex : LocalCheck → Nat
  | .activityBoolean i => i.val
  | .modeBoolean i => 129 + i.val
  | .modeOneHot => 132
  | .t1 => 248
  | .t2 => 249
  | .t3 i => 250 + i.val
  | .t4 => 242
  | .t5 => 243
  | .approvalInputOne => 244
  | .approvalOutputZero => 245
  | .nextCount => 271
  | .membershipBoolean i => 310 + i.val
  | .membershipOneHot => 316
  | .membershipFresh i => 298 + 2 * i.val
  | .nextBitmap i => 299 + 2 * i.val
  | .fullTag i j => 318 + 8 * i.val + j.val
  | .policyDigestBridge _ => 128
  | .inputAuthorization i => 238 + 2 * i.val
  | .finalIntent i => 439 + i.val
  | .outputAuthorization => 256
  | .secondaryInput => 257

def rootFor (check : LocalCheck) : Nat :=
  exactNonlinearRoots.getD (rootIndex check) 0

private theorem realizes_activityBoolean_0 :
    Realizes exactNonlinearExpressions (rootFor (.activityBoolean 0))
      (localCheckTerm (.activityBoolean 0)) := by
  change Realizes exactNonlinearExpressions 811 (.mul (.publicInput 0) (.sub (.publicInput 0) (.constant 1)))
  exact (Realizes.mul (leftNode := 4) (rightNode := 810) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.sub (leftNode := 4) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_activityBoolean_1 :
    Realizes exactNonlinearExpressions (rootFor (.activityBoolean 1))
      (localCheckTerm (.activityBoolean 1)) := by
  change Realizes exactNonlinearExpressions 813 (.mul (.publicInput 1) (.sub (.publicInput 1) (.constant 1)))
  exact (Realizes.mul (leftNode := 5) (rightNode := 812) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.sub (leftNode := 5) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_activityBoolean_2 :
    Realizes exactNonlinearExpressions (rootFor (.activityBoolean 2))
      (localCheckTerm (.activityBoolean 2)) := by
  change Realizes exactNonlinearExpressions 815 (.mul (.publicInput 2) (.sub (.publicInput 2) (.constant 1)))
  exact (Realizes.mul (leftNode := 6) (rightNode := 814) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.sub (leftNode := 6) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_activityBoolean_3 :
    Realizes exactNonlinearExpressions (rootFor (.activityBoolean 3))
      (localCheckTerm (.activityBoolean 3)) := by
  change Realizes exactNonlinearExpressions 817 (.mul (.publicInput 3) (.sub (.publicInput 3) (.constant 1)))
  exact (Realizes.mul (leftNode := 7) (rightNode := 816) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.sub (leftNode := 7) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_modeBoolean_0 :
    Realizes exactNonlinearExpressions (rootFor (.modeBoolean 0))
      (localCheckTerm (.modeBoolean 0)) := by
  change Realizes exactNonlinearExpressions 1236 (.mul (.witness 92) (.sub (.witness 92) (.constant 1)))
  exact (Realizes.mul (leftNode := 216) (rightNode := 1235) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 216) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide))))

private theorem realizes_modeBoolean_1 :
    Realizes exactNonlinearExpressions (rootFor (.modeBoolean 1))
      (localCheckTerm (.modeBoolean 1)) := by
  change Realizes exactNonlinearExpressions 1238 (.mul (.witness 93) (.sub (.witness 93) (.constant 1)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1237) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 217) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide))))

private theorem realizes_modeBoolean_2 :
    Realizes exactNonlinearExpressions (rootFor (.modeBoolean 2))
      (localCheckTerm (.modeBoolean 2)) := by
  change Realizes exactNonlinearExpressions 1240 (.mul (.witness 94) (.sub (.witness 94) (.constant 1)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1239) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 218) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide))))

private theorem realizes_modeOneHot :
    Realizes exactNonlinearExpressions (rootFor (.modeOneHot))
      (localCheckTerm (.modeOneHot)) := by
  change Realizes exactNonlinearExpressions 1243 (.sub (.add (.witness 94) (.add (.witness 92) (.witness 93))) (.constant 1))
  exact (Realizes.sub (leftNode := 1242) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.add (leftNode := 218) (rightNode := 1241) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 216) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))) (Realizes.constant (by decide)))

private theorem realizes_t1 :
    Realizes exactNonlinearExpressions (rootFor (.t1))
      (localCheckTerm (.t1)) := by
  change Realizes exactNonlinearExpressions 1412 (.sub (.mul (.witness 229) (.mul (.add (.sub (.constant 1) (.mul (.publicInput 0) (.add (.witness 92) (.witness 94)))) (.mul (.witness 0) (.mul (.publicInput 0) (.add (.witness 92) (.witness 94))))) (.add (.sub (.constant 1) (.mul (.publicInput 1) (.add (.witness 92) (.witness 93)))) (.mul (.witness 34) (.mul (.publicInput 1) (.add (.witness 92) (.witness 93))))))) (.constant 1))
  exact (Realizes.sub (leftNode := 1411) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 353) (rightNode := 1410) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 1406) (rightNode := 1409) (by decide) (by decide) (by decide) (Realizes.add (leftNode := 1404) (rightNode := 1405) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 1) (rightNode := 1402) (by decide) (by decide) (by decide) (Realizes.constant (by decide)) (Realizes.mul (leftNode := 4) (rightNode := 1401) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))) (Realizes.mul (leftNode := 124) (rightNode := 1402) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 4) (rightNode := 1401) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))) (Realizes.add (leftNode := 1407) (rightNode := 1408) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 1) (rightNode := 1403) (by decide) (by decide) (by decide) (Realizes.constant (by decide)) (Realizes.mul (leftNode := 5) (rightNode := 1241) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))) (Realizes.mul (leftNode := 158) (rightNode := 1403) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 5) (rightNode := 1241) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))))) (Realizes.constant (by decide)))

private theorem realizes_t2 :
    Realizes exactNonlinearExpressions (rootFor (.t2))
      (localCheckTerm (.t2)) := by
  change Realizes exactNonlinearExpressions 1420 (.sub (.mul (.witness 230) (.mul (.add (.sub (.constant 1) (.mul (.publicInput 2) (.add (.witness 92) (.witness 94)))) (.mul (.witness 68) (.mul (.publicInput 2) (.add (.witness 92) (.witness 94))))) (.add (.sub (.constant 1) (.publicInput 3)) (.mul (.publicInput 3) (.witness 80))))) (.constant 1))
  exact (Realizes.sub (leftNode := 1419) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 354) (rightNode := 1418) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 1416) (rightNode := 1417) (by decide) (by decide) (by decide) (Realizes.add (leftNode := 1414) (rightNode := 1415) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 1) (rightNode := 1413) (by decide) (by decide) (by decide) (Realizes.constant (by decide)) (Realizes.mul (leftNode := 6) (rightNode := 1401) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))) (Realizes.mul (leftNode := 192) (rightNode := 1413) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 6) (rightNode := 1401) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 216) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))) (Realizes.add (leftNode := 1024) (rightNode := 1146) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 1) (rightNode := 7) (by decide) (by decide) (by decide) (Realizes.constant (by decide)) (Realizes.publicInput (by decide))) (Realizes.mul (leftNode := 7) (rightNode := 204) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.witness (by decide)))))) (Realizes.constant (by decide)))

private theorem realizes_t3_0 :
    Realizes exactNonlinearExpressions (rootFor (.t3 0))
      (localCheckTerm (.t3 0)) := by
  change Realizes exactNonlinearExpressions 1421 (.mul (.witness 0) (.witness 93))
  exact (Realizes.mul (leftNode := 124) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t3_1 :
    Realizes exactNonlinearExpressions (rootFor (.t3 1))
      (localCheckTerm (.t3 1)) := by
  change Realizes exactNonlinearExpressions 1422 (.mul (.witness 1) (.witness 93))
  exact (Realizes.mul (leftNode := 125) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t3_2 :
    Realizes exactNonlinearExpressions (rootFor (.t3 2))
      (localCheckTerm (.t3 2)) := by
  change Realizes exactNonlinearExpressions 1423 (.mul (.witness 68) (.witness 93))
  exact (Realizes.mul (leftNode := 192) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t3_3 :
    Realizes exactNonlinearExpressions (rootFor (.t3 3))
      (localCheckTerm (.t3 3)) := by
  change Realizes exactNonlinearExpressions 1424 (.mul (.witness 69) (.witness 93))
  exact (Realizes.mul (leftNode := 193) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t3_4 :
    Realizes exactNonlinearExpressions (rootFor (.t3 4))
      (localCheckTerm (.t3 4)) := by
  change Realizes exactNonlinearExpressions 1425 (.mul (.witness 34) (.witness 94))
  exact (Realizes.mul (leftNode := 158) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t3_5 :
    Realizes exactNonlinearExpressions (rootFor (.t3 5))
      (localCheckTerm (.t3 5)) := by
  change Realizes exactNonlinearExpressions 1426 (.mul (.witness 35) (.witness 94))
  exact (Realizes.mul (leftNode := 159) (rightNode := 218) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))

private theorem realizes_t4 :
    Realizes exactNonlinearExpressions (rootFor (.t4))
      (localCheckTerm (.t4)) := by
  change Realizes exactNonlinearExpressions 1380 (.mul (.witness 138) (.mul (.witness 93) (.sub (.constant 1) (.publicInput 0))))
  exact (Realizes.mul (leftNode := 262) (rightNode := 1379) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 1378) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1) (rightNode := 4) (by decide) (by decide) (by decide) (Realizes.constant (by decide)) (Realizes.publicInput (by decide)))))

private theorem realizes_t5 :
    Realizes exactNonlinearExpressions (rootFor (.t5))
      (localCheckTerm (.t5)) := by
  change Realizes exactNonlinearExpressions 1396 (.mul (.mul (.publicInput 0) (.witness 93)) (.mul (.mul (.mul (.mul (.mul (.sub (.witness 138) (.constant 1)) (.sub (.witness 138) (.constant 2))) (.sub (.witness 138) (.constant 3))) (.sub (.witness 138) (.constant 4))) (.sub (.witness 138) (.constant 5))) (.sub (.witness 138) (.constant 6))))
  exact (Realizes.mul (leftNode := 1381) (rightNode := 1395) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 4) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.witness (by decide))) (Realizes.mul (leftNode := 1392) (rightNode := 1394) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 1389) (rightNode := 1391) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 1386) (rightNode := 1388) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 1384) (rightNode := 1385) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 1382) (rightNode := 1383) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 262) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide))) (Realizes.sub (leftNode := 262) (rightNode := 2) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))) (Realizes.sub (leftNode := 262) (rightNode := 829) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))) (Realizes.sub (leftNode := 262) (rightNode := 1387) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))) (Realizes.sub (leftNode := 262) (rightNode := 1390) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))) (Realizes.sub (leftNode := 262) (rightNode := 1393) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_approvalInputOne :
    Realizes exactNonlinearExpressions (rootFor (.approvalInputOne))
      (localCheckTerm (.approvalInputOne)) := by
  change Realizes exactNonlinearExpressions 1397 (.mul (.witness 93) (.sub (.publicInput 1) (.constant 1)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 812) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 5) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_approvalOutputZero :
    Realizes exactNonlinearExpressions (rootFor (.approvalOutputZero))
      (localCheckTerm (.approvalOutputZero)) := by
  change Realizes exactNonlinearExpressions 1398 (.mul (.witness 93) (.sub (.publicInput 2) (.constant 1)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 814) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 6) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.constant (by decide))))

private theorem realizes_nextCount :
    Realizes exactNonlinearExpressions (rootFor (.nextCount))
      (localCheckTerm (.nextCount)) := by
  change Realizes exactNonlinearExpressions 1518 (.mul (.witness 93) (.sub (.sub (.witness 145) (.witness 138)) (.constant 1)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1517) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1516) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 269) (rightNode := 262) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.constant (by decide))))

private theorem realizes_membershipBoolean_0 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 0))
      (localCheckTerm (.membershipBoolean 0)) := by
  change Realizes exactNonlinearExpressions 1641 (.mul (.witness 93) (.mul (.witness 206) (.sub (.witness 206) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1640) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 330) (rightNode := 1639) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 330) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_0 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 0))
      (localCheckTerm (.membershipFresh 0)) := by
  change Realizes exactNonlinearExpressions 1610 (.mul (.witness 139) (.mul (.witness 93) (.witness 206)))
  exact (Realizes.mul (leftNode := 263) (rightNode := 1609) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_0 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 0))
      (localCheckTerm (.nextBitmap 0)) := by
  change Realizes exactNonlinearExpressions 1613 (.mul (.witness 93) (.sub (.sub (.witness 146) (.witness 139)) (.witness 206)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1612) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1611) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 270) (rightNode := 263) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 0))
      (localCheckTerm (.fullTag 0 0)) := by
  change Realizes exactNonlinearExpressions 1666 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 99) (.witness 164)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1665) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 288) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 1))
      (localCheckTerm (.fullTag 0 1)) := by
  change Realizes exactNonlinearExpressions 1668 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 100) (.witness 165)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1667) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 289) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 2))
      (localCheckTerm (.fullTag 0 2)) := by
  change Realizes exactNonlinearExpressions 1670 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 101) (.witness 166)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1669) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 290) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 3))
      (localCheckTerm (.fullTag 0 3)) := by
  change Realizes exactNonlinearExpressions 1672 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 102) (.witness 167)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1671) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 291) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 4))
      (localCheckTerm (.fullTag 0 4)) := by
  change Realizes exactNonlinearExpressions 1674 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 103) (.witness 168)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1673) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 292) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 5))
      (localCheckTerm (.fullTag 0 5)) := by
  change Realizes exactNonlinearExpressions 1676 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 104) (.witness 169)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1675) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 293) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_0_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 0 6))
      (localCheckTerm (.fullTag 0 6)) := by
  change Realizes exactNonlinearExpressions 1678 (.mul (.mul (.witness 93) (.witness 206)) (.sub (.witness 105) (.witness 170)))
  exact (Realizes.mul (leftNode := 1609) (rightNode := 1677) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 330) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 294) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipBoolean_1 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 1))
      (localCheckTerm (.membershipBoolean 1)) := by
  change Realizes exactNonlinearExpressions 1644 (.mul (.witness 93) (.mul (.witness 207) (.sub (.witness 207) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1643) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 331) (rightNode := 1642) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 331) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_1 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 1))
      (localCheckTerm (.membershipFresh 1)) := by
  change Realizes exactNonlinearExpressions 1615 (.mul (.witness 140) (.mul (.witness 93) (.witness 207)))
  exact (Realizes.mul (leftNode := 264) (rightNode := 1614) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_1 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 1))
      (localCheckTerm (.nextBitmap 1)) := by
  change Realizes exactNonlinearExpressions 1618 (.mul (.witness 93) (.sub (.sub (.witness 147) (.witness 140)) (.witness 207)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1617) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1616) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 271) (rightNode := 264) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 0))
      (localCheckTerm (.fullTag 1 0)) := by
  change Realizes exactNonlinearExpressions 1681 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 99) (.witness 171)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1680) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 295) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 1))
      (localCheckTerm (.fullTag 1 1)) := by
  change Realizes exactNonlinearExpressions 1683 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 100) (.witness 172)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1682) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 296) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 2))
      (localCheckTerm (.fullTag 1 2)) := by
  change Realizes exactNonlinearExpressions 1685 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 101) (.witness 173)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1684) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 297) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 3))
      (localCheckTerm (.fullTag 1 3)) := by
  change Realizes exactNonlinearExpressions 1687 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 102) (.witness 174)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1686) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 298) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 4))
      (localCheckTerm (.fullTag 1 4)) := by
  change Realizes exactNonlinearExpressions 1689 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 103) (.witness 175)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1688) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 299) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 5))
      (localCheckTerm (.fullTag 1 5)) := by
  change Realizes exactNonlinearExpressions 1691 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 104) (.witness 176)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1690) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 300) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_1_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 1 6))
      (localCheckTerm (.fullTag 1 6)) := by
  change Realizes exactNonlinearExpressions 1693 (.mul (.mul (.witness 93) (.witness 207)) (.sub (.witness 105) (.witness 177)))
  exact (Realizes.mul (leftNode := 1614) (rightNode := 1692) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 301) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipBoolean_2 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 2))
      (localCheckTerm (.membershipBoolean 2)) := by
  change Realizes exactNonlinearExpressions 1647 (.mul (.witness 93) (.mul (.witness 208) (.sub (.witness 208) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1646) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 332) (rightNode := 1645) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 332) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_2 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 2))
      (localCheckTerm (.membershipFresh 2)) := by
  change Realizes exactNonlinearExpressions 1620 (.mul (.witness 141) (.mul (.witness 93) (.witness 208)))
  exact (Realizes.mul (leftNode := 265) (rightNode := 1619) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_2 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 2))
      (localCheckTerm (.nextBitmap 2)) := by
  change Realizes exactNonlinearExpressions 1623 (.mul (.witness 93) (.sub (.sub (.witness 148) (.witness 141)) (.witness 208)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1622) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1621) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 272) (rightNode := 265) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 0))
      (localCheckTerm (.fullTag 2 0)) := by
  change Realizes exactNonlinearExpressions 1696 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 99) (.witness 178)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1695) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 302) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 1))
      (localCheckTerm (.fullTag 2 1)) := by
  change Realizes exactNonlinearExpressions 1698 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 100) (.witness 179)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1697) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 303) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 2))
      (localCheckTerm (.fullTag 2 2)) := by
  change Realizes exactNonlinearExpressions 1700 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 101) (.witness 180)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1699) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 304) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 3))
      (localCheckTerm (.fullTag 2 3)) := by
  change Realizes exactNonlinearExpressions 1702 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 102) (.witness 181)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1701) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 305) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 4))
      (localCheckTerm (.fullTag 2 4)) := by
  change Realizes exactNonlinearExpressions 1704 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 103) (.witness 182)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1703) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 306) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 5))
      (localCheckTerm (.fullTag 2 5)) := by
  change Realizes exactNonlinearExpressions 1706 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 104) (.witness 183)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1705) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 307) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_2_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 2 6))
      (localCheckTerm (.fullTag 2 6)) := by
  change Realizes exactNonlinearExpressions 1708 (.mul (.mul (.witness 93) (.witness 208)) (.sub (.witness 105) (.witness 184)))
  exact (Realizes.mul (leftNode := 1619) (rightNode := 1707) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 332) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 308) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipBoolean_3 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 3))
      (localCheckTerm (.membershipBoolean 3)) := by
  change Realizes exactNonlinearExpressions 1650 (.mul (.witness 93) (.mul (.witness 209) (.sub (.witness 209) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1649) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 333) (rightNode := 1648) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 333) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_3 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 3))
      (localCheckTerm (.membershipFresh 3)) := by
  change Realizes exactNonlinearExpressions 1625 (.mul (.witness 142) (.mul (.witness 93) (.witness 209)))
  exact (Realizes.mul (leftNode := 266) (rightNode := 1624) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_3 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 3))
      (localCheckTerm (.nextBitmap 3)) := by
  change Realizes exactNonlinearExpressions 1628 (.mul (.witness 93) (.sub (.sub (.witness 149) (.witness 142)) (.witness 209)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1627) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1626) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 273) (rightNode := 266) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 0))
      (localCheckTerm (.fullTag 3 0)) := by
  change Realizes exactNonlinearExpressions 1711 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 99) (.witness 185)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1710) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 309) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 1))
      (localCheckTerm (.fullTag 3 1)) := by
  change Realizes exactNonlinearExpressions 1713 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 100) (.witness 186)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1712) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 310) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 2))
      (localCheckTerm (.fullTag 3 2)) := by
  change Realizes exactNonlinearExpressions 1715 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 101) (.witness 187)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1714) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 311) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 3))
      (localCheckTerm (.fullTag 3 3)) := by
  change Realizes exactNonlinearExpressions 1717 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 102) (.witness 188)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1716) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 312) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 4))
      (localCheckTerm (.fullTag 3 4)) := by
  change Realizes exactNonlinearExpressions 1719 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 103) (.witness 189)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1718) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 313) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 5))
      (localCheckTerm (.fullTag 3 5)) := by
  change Realizes exactNonlinearExpressions 1721 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 104) (.witness 190)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1720) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 314) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_3_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 3 6))
      (localCheckTerm (.fullTag 3 6)) := by
  change Realizes exactNonlinearExpressions 1723 (.mul (.mul (.witness 93) (.witness 209)) (.sub (.witness 105) (.witness 191)))
  exact (Realizes.mul (leftNode := 1624) (rightNode := 1722) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 333) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 315) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipBoolean_4 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 4))
      (localCheckTerm (.membershipBoolean 4)) := by
  change Realizes exactNonlinearExpressions 1653 (.mul (.witness 93) (.mul (.witness 210) (.sub (.witness 210) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1652) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 334) (rightNode := 1651) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 334) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_4 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 4))
      (localCheckTerm (.membershipFresh 4)) := by
  change Realizes exactNonlinearExpressions 1630 (.mul (.witness 143) (.mul (.witness 93) (.witness 210)))
  exact (Realizes.mul (leftNode := 267) (rightNode := 1629) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_4 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 4))
      (localCheckTerm (.nextBitmap 4)) := by
  change Realizes exactNonlinearExpressions 1633 (.mul (.witness 93) (.sub (.sub (.witness 150) (.witness 143)) (.witness 210)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1632) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1631) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 274) (rightNode := 267) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 0))
      (localCheckTerm (.fullTag 4 0)) := by
  change Realizes exactNonlinearExpressions 1726 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 99) (.witness 192)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1725) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 316) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 1))
      (localCheckTerm (.fullTag 4 1)) := by
  change Realizes exactNonlinearExpressions 1728 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 100) (.witness 193)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1727) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 317) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 2))
      (localCheckTerm (.fullTag 4 2)) := by
  change Realizes exactNonlinearExpressions 1730 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 101) (.witness 194)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1729) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 318) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 3))
      (localCheckTerm (.fullTag 4 3)) := by
  change Realizes exactNonlinearExpressions 1732 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 102) (.witness 195)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1731) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 319) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 4))
      (localCheckTerm (.fullTag 4 4)) := by
  change Realizes exactNonlinearExpressions 1734 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 103) (.witness 196)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1733) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 320) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 5))
      (localCheckTerm (.fullTag 4 5)) := by
  change Realizes exactNonlinearExpressions 1736 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 104) (.witness 197)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1735) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 321) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_4_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 4 6))
      (localCheckTerm (.fullTag 4 6)) := by
  change Realizes exactNonlinearExpressions 1738 (.mul (.mul (.witness 93) (.witness 210)) (.sub (.witness 105) (.witness 198)))
  exact (Realizes.mul (leftNode := 1629) (rightNode := 1737) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 334) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 322) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipBoolean_5 :
    Realizes exactNonlinearExpressions (rootFor (.membershipBoolean 5))
      (localCheckTerm (.membershipBoolean 5)) := by
  change Realizes exactNonlinearExpressions 1656 (.mul (.witness 93) (.mul (.witness 211) (.sub (.witness 211) (.constant 1))))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1655) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 335) (rightNode := 1654) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 335) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.constant (by decide)))))

private theorem realizes_membershipFresh_5 :
    Realizes exactNonlinearExpressions (rootFor (.membershipFresh 5))
      (localCheckTerm (.membershipFresh 5)) := by
  change Realizes exactNonlinearExpressions 1635 (.mul (.witness 144) (.mul (.witness 93) (.witness 211)))
  exact (Realizes.mul (leftNode := 268) (rightNode := 1634) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_nextBitmap_5 :
    Realizes exactNonlinearExpressions (rootFor (.nextBitmap 5))
      (localCheckTerm (.nextBitmap 5)) := by
  change Realizes exactNonlinearExpressions 1638 (.mul (.witness 93) (.sub (.sub (.witness 151) (.witness 144)) (.witness 211)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1637) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1636) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.sub (leftNode := 275) (rightNode := 268) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_0 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 0))
      (localCheckTerm (.fullTag 5 0)) := by
  change Realizes exactNonlinearExpressions 1741 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 99) (.witness 199)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1740) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 223) (rightNode := 323) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_1 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 1))
      (localCheckTerm (.fullTag 5 1)) := by
  change Realizes exactNonlinearExpressions 1743 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 100) (.witness 200)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1742) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 224) (rightNode := 324) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_2 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 2))
      (localCheckTerm (.fullTag 5 2)) := by
  change Realizes exactNonlinearExpressions 1745 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 101) (.witness 201)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1744) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 225) (rightNode := 325) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_3 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 3))
      (localCheckTerm (.fullTag 5 3)) := by
  change Realizes exactNonlinearExpressions 1747 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 102) (.witness 202)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1746) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 226) (rightNode := 326) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_4 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 4))
      (localCheckTerm (.fullTag 5 4)) := by
  change Realizes exactNonlinearExpressions 1749 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 103) (.witness 203)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1748) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 227) (rightNode := 327) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_5 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 5))
      (localCheckTerm (.fullTag 5 5)) := by
  change Realizes exactNonlinearExpressions 1751 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 104) (.witness 204)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1750) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 228) (rightNode := 328) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_fullTag_5_6 :
    Realizes exactNonlinearExpressions (rootFor (.fullTag 5 6))
      (localCheckTerm (.fullTag 5 6)) := by
  change Realizes exactNonlinearExpressions 1753 (.mul (.mul (.witness 93) (.witness 211)) (.sub (.witness 105) (.witness 205)))
  exact (Realizes.mul (leftNode := 1634) (rightNode := 1752) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 335) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.sub (leftNode := 229) (rightNode := 329) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_membershipOneHot :
    Realizes exactNonlinearExpressions (rootFor (.membershipOneHot))
      (localCheckTerm (.membershipOneHot)) := by
  change Realizes exactNonlinearExpressions 1663 (.mul (.witness 93) (.sub (.add (.witness 211) (.add (.witness 210) (.add (.witness 209) (.add (.witness 208) (.add (.witness 206) (.witness 207)))))) (.constant 1)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1662) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 1661) (rightNode := 1) (by decide) (by decide) (by decide) (Realizes.add (leftNode := 335) (rightNode := 1660) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 334) (rightNode := 1659) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 333) (rightNode := 1658) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 332) (rightNode := 1657) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 330) (rightNode := 331) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))))) (Realizes.constant (by decide))))

private theorem realizes_policyDigestBridge_0 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 0))
      (localCheckTerm (.policyDigestBridge 0)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_1 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 1))
      (localCheckTerm (.policyDigestBridge 1)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_2 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 2))
      (localCheckTerm (.policyDigestBridge 2)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_3 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 3))
      (localCheckTerm (.policyDigestBridge 3)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_4 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 4))
      (localCheckTerm (.policyDigestBridge 4)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_5 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 5))
      (localCheckTerm (.policyDigestBridge 5)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_policyDigestBridge_6 :
    Realizes exactNonlinearExpressions (rootFor (.policyDigestBridge 6))
      (localCheckTerm (.policyDigestBridge 6)) := by
  change Realizes exactNonlinearExpressions 1233 (.mul (.witness 282) (.sub (.witness 280) (.witness 281)))
  exact (Realizes.mul (leftNode := 406) (rightNode := 1232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 404) (rightNode := 405) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_inputAuthorization_0 :
    Realizes exactNonlinearExpressions (rootFor (.inputAuthorization 0))
      (localCheckTerm (.inputAuthorization 0)) := by
  change Realizes exactNonlinearExpressions 1363 (.sub (.witness 95) (.mul (.publicInput 0) (.add (.mul (.witness 92) (.witness 106)) (.add (.mul (.witness 93) (.witness 110)) (.mul (.witness 94) (.witness 111))))))
  exact (Realizes.sub (leftNode := 219) (rightNode := 1362) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 4) (rightNode := 1361) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 1357) (rightNode := 1360) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 216) (rightNode := 230) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.add (leftNode := 1358) (rightNode := 1359) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 234) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.mul (leftNode := 218) (rightNode := 235) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))))

private theorem realizes_inputAuthorization_1 :
    Realizes exactNonlinearExpressions (rootFor (.inputAuthorization 1))
      (localCheckTerm (.inputAuthorization 1)) := by
  change Realizes exactNonlinearExpressions 1373 (.sub (.witness 96) (.mul (.publicInput 1) (.add (.mul (.witness 92) (.witness 106)) (.add (.mul (.witness 93) (.witness 106)) (.mul (.witness 94) (.witness 110))))))
  exact (Realizes.sub (leftNode := 220) (rightNode := 1372) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.mul (leftNode := 5) (rightNode := 1371) (by decide) (by decide) (by decide) (Realizes.publicInput (by decide)) (Realizes.add (leftNode := 1357) (rightNode := 1370) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 216) (rightNode := 230) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.add (leftNode := 1368) (rightNode := 1369) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 217) (rightNode := 230) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))) (Realizes.mul (leftNode := 218) (rightNode := 234) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))))

private theorem realizes_finalIntent_0 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 0))
      (localCheckTerm (.finalIntent 0)) := by
  change Realizes exactNonlinearExpressions 1952 (.mul (.witness 94) (.sub (.witness 129) (.witness 115)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1951) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 253) (rightNode := 239) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_1 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 1))
      (localCheckTerm (.finalIntent 1)) := by
  change Realizes exactNonlinearExpressions 1954 (.mul (.witness 94) (.sub (.witness 130) (.witness 116)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1953) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 254) (rightNode := 240) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_2 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 2))
      (localCheckTerm (.finalIntent 2)) := by
  change Realizes exactNonlinearExpressions 1956 (.mul (.witness 94) (.sub (.witness 131) (.witness 117)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1955) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 255) (rightNode := 241) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_3 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 3))
      (localCheckTerm (.finalIntent 3)) := by
  change Realizes exactNonlinearExpressions 1958 (.mul (.witness 94) (.sub (.witness 132) (.witness 118)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1957) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 256) (rightNode := 242) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_4 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 4))
      (localCheckTerm (.finalIntent 4)) := by
  change Realizes exactNonlinearExpressions 1960 (.mul (.witness 94) (.sub (.witness 133) (.witness 119)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1959) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 257) (rightNode := 243) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_5 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 5))
      (localCheckTerm (.finalIntent 5)) := by
  change Realizes exactNonlinearExpressions 1962 (.mul (.witness 94) (.sub (.witness 134) (.witness 120)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1961) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 258) (rightNode := 244) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_finalIntent_6 :
    Realizes exactNonlinearExpressions (rootFor (.finalIntent 6))
      (localCheckTerm (.finalIntent 6)) := by
  change Realizes exactNonlinearExpressions 1964 (.mul (.witness 94) (.sub (.witness 135) (.witness 121)))
  exact (Realizes.mul (leftNode := 218) (rightNode := 1963) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 259) (rightNode := 245) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_outputAuthorization :
    Realizes exactNonlinearExpressions (rootFor (.outputAuthorization))
      (localCheckTerm (.outputAuthorization)) := by
  change Realizes exactNonlinearExpressions 1428 (.mul (.witness 93) (.sub (.witness 112) (.witness 111)))
  exact (Realizes.mul (leftNode := 217) (rightNode := 1427) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.sub (leftNode := 236) (rightNode := 235) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide))))

private theorem realizes_secondaryInput :
    Realizes exactNonlinearExpressions (rootFor (.secondaryInput))
      (localCheckTerm (.secondaryInput)) := by
  change Realizes exactNonlinearExpressions 1432 (.sub (.witness 109) (.add (.mul (.witness 107) (.add (.witness 92) (.witness 93))) (.mul (.witness 94) (.witness 108))))
  exact (Realizes.sub (leftNode := 233) (rightNode := 1431) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 1429) (rightNode := 1430) (by decide) (by decide) (by decide) (Realizes.mul (leftNode := 231) (rightNode := 1241) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.add (leftNode := 216) (rightNode := 217) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))) (Realizes.mul (leftNode := 218) (rightNode := 232) (by decide) (by decide) (by decide) (Realizes.witness (by decide)) (Realizes.witness (by decide)))))

private theorem exact_canonical : program.nonlinearExecutable.Canonical true := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

private theorem root_member (check : LocalCheck) :
    rootFor check ∈ exactNonlinearRoots := by
  cases check with
  | activityBoolean a =>
      fin_cases a <;> decide
  | modeBoolean a =>
      fin_cases a <;> decide
  | modeOneHot =>
      decide
  | t1 =>
      decide
  | t2 =>
      decide
  | t3 a =>
      fin_cases a <;> decide
  | t4 =>
      decide
  | t5 =>
      decide
  | approvalInputOne =>
      decide
  | approvalOutputZero =>
      decide
  | nextCount =>
      decide
  | membershipBoolean a =>
      fin_cases a <;> decide
  | membershipOneHot =>
      decide
  | membershipFresh a =>
      fin_cases a <;> decide
  | nextBitmap a =>
      fin_cases a <;> decide
  | fullTag a b =>
      fin_cases a <;> fin_cases b <;> decide
  | policyDigestBridge a =>
      fin_cases a <;> decide
  | inputAuthorization a =>
      fin_cases a <;> decide
  | finalIntent a =>
      fin_cases a <;> decide
  | outputAuthorization =>
      decide
  | secondaryInput =>
      decide

private theorem realizes_check (check : LocalCheck) :
    Realizes exactNonlinearExpressions (rootFor check) (localCheckTerm check) := by
  cases check with
  | activityBoolean a =>
      fin_cases a
      · exact realizes_activityBoolean_0
      · exact realizes_activityBoolean_1
      · exact realizes_activityBoolean_2
      · exact realizes_activityBoolean_3
  | modeBoolean a =>
      fin_cases a
      · exact realizes_modeBoolean_0
      · exact realizes_modeBoolean_1
      · exact realizes_modeBoolean_2
  | modeOneHot =>
      exact realizes_modeOneHot
  | t1 =>
      exact realizes_t1
  | t2 =>
      exact realizes_t2
  | t3 a =>
      fin_cases a
      · exact realizes_t3_0
      · exact realizes_t3_1
      · exact realizes_t3_2
      · exact realizes_t3_3
      · exact realizes_t3_4
      · exact realizes_t3_5
  | t4 =>
      exact realizes_t4
  | t5 =>
      exact realizes_t5
  | approvalInputOne =>
      exact realizes_approvalInputOne
  | approvalOutputZero =>
      exact realizes_approvalOutputZero
  | nextCount =>
      exact realizes_nextCount
  | membershipBoolean a =>
      fin_cases a
      · exact realizes_membershipBoolean_0
      · exact realizes_membershipBoolean_1
      · exact realizes_membershipBoolean_2
      · exact realizes_membershipBoolean_3
      · exact realizes_membershipBoolean_4
      · exact realizes_membershipBoolean_5
  | membershipOneHot =>
      exact realizes_membershipOneHot
  | membershipFresh a =>
      fin_cases a
      · exact realizes_membershipFresh_0
      · exact realizes_membershipFresh_1
      · exact realizes_membershipFresh_2
      · exact realizes_membershipFresh_3
      · exact realizes_membershipFresh_4
      · exact realizes_membershipFresh_5
  | nextBitmap a =>
      fin_cases a
      · exact realizes_nextBitmap_0
      · exact realizes_nextBitmap_1
      · exact realizes_nextBitmap_2
      · exact realizes_nextBitmap_3
      · exact realizes_nextBitmap_4
      · exact realizes_nextBitmap_5
  | fullTag a b =>
      fin_cases a <;> fin_cases b
      all_goals first
        | exact realizes_fullTag_0_0
        | exact realizes_fullTag_0_1
        | exact realizes_fullTag_0_2
        | exact realizes_fullTag_0_3
        | exact realizes_fullTag_0_4
        | exact realizes_fullTag_0_5
        | exact realizes_fullTag_0_6
        | exact realizes_fullTag_1_0
        | exact realizes_fullTag_1_1
        | exact realizes_fullTag_1_2
        | exact realizes_fullTag_1_3
        | exact realizes_fullTag_1_4
        | exact realizes_fullTag_1_5
        | exact realizes_fullTag_1_6
        | exact realizes_fullTag_2_0
        | exact realizes_fullTag_2_1
        | exact realizes_fullTag_2_2
        | exact realizes_fullTag_2_3
        | exact realizes_fullTag_2_4
        | exact realizes_fullTag_2_5
        | exact realizes_fullTag_2_6
        | exact realizes_fullTag_3_0
        | exact realizes_fullTag_3_1
        | exact realizes_fullTag_3_2
        | exact realizes_fullTag_3_3
        | exact realizes_fullTag_3_4
        | exact realizes_fullTag_3_5
        | exact realizes_fullTag_3_6
        | exact realizes_fullTag_4_0
        | exact realizes_fullTag_4_1
        | exact realizes_fullTag_4_2
        | exact realizes_fullTag_4_3
        | exact realizes_fullTag_4_4
        | exact realizes_fullTag_4_5
        | exact realizes_fullTag_4_6
        | exact realizes_fullTag_5_0
        | exact realizes_fullTag_5_1
        | exact realizes_fullTag_5_2
        | exact realizes_fullTag_5_3
        | exact realizes_fullTag_5_4
        | exact realizes_fullTag_5_5
        | exact realizes_fullTag_5_6
  | policyDigestBridge a =>
      fin_cases a
      · exact realizes_policyDigestBridge_0
      · exact realizes_policyDigestBridge_1
      · exact realizes_policyDigestBridge_2
      · exact realizes_policyDigestBridge_3
      · exact realizes_policyDigestBridge_4
      · exact realizes_policyDigestBridge_5
      · exact realizes_policyDigestBridge_6
  | inputAuthorization a =>
      fin_cases a
      · exact realizes_inputAuthorization_0
      · exact realizes_inputAuthorization_1
  | finalIntent a =>
      fin_cases a
      · exact realizes_finalIntent_0
      · exact realizes_finalIntent_1
      · exact realizes_finalIntent_2
      · exact realizes_finalIntent_3
      · exact realizes_finalIntent_4
      · exact realizes_finalIntent_5
      · exact realizes_finalIntent_6
  | outputAuthorization =>
      exact realizes_outputAuthorization
  | secondaryInput =>
      exact realizes_secondaryInput

def certificate : CurrentLocalArtifactCertificate program :=
  { nonlinearRoots := by decide
    canonical := exact_canonical
    rootFor := rootFor
    rootMember := root_member
    realizes := realizes_check
    witnessRows := by decide
    packingLanes := by decide }

end HegemonCrypto.SmallWood.SmzaRp05LocalCertificate
