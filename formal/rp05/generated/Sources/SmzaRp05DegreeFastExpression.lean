import SmzaRp05DegreeCertificateData
import SmzaRp05ChunkedListLookup
import Lean.Elab.Tactic.Omega

/-! Exact 32-word chunked access to the SHA-pinned RP05 nonlinear expression list.
    The fast checker is definitionally separate until its source equality is checked. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials
open SmzaRp05Components
open SmzaRp05ChunkedListLookup

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def fullExpressionChunks : List (List FieldExpression) := [
  exactNonlinearExpressionsChunk0000, exactNonlinearExpressionsChunk0001, exactNonlinearExpressionsChunk0002, exactNonlinearExpressionsChunk0003, exactNonlinearExpressionsChunk0004, exactNonlinearExpressionsChunk0005, exactNonlinearExpressionsChunk0006, exactNonlinearExpressionsChunk0007,
  exactNonlinearExpressionsChunk0008, exactNonlinearExpressionsChunk0009, exactNonlinearExpressionsChunk0010, exactNonlinearExpressionsChunk0011, exactNonlinearExpressionsChunk0012, exactNonlinearExpressionsChunk0013, exactNonlinearExpressionsChunk0014, exactNonlinearExpressionsChunk0015,
  exactNonlinearExpressionsChunk0016, exactNonlinearExpressionsChunk0017, exactNonlinearExpressionsChunk0018, exactNonlinearExpressionsChunk0019, exactNonlinearExpressionsChunk0020, exactNonlinearExpressionsChunk0021, exactNonlinearExpressionsChunk0022, exactNonlinearExpressionsChunk0023,
  exactNonlinearExpressionsChunk0024, exactNonlinearExpressionsChunk0025, exactNonlinearExpressionsChunk0026, exactNonlinearExpressionsChunk0027, exactNonlinearExpressionsChunk0028, exactNonlinearExpressionsChunk0029, exactNonlinearExpressionsChunk0030, exactNonlinearExpressionsChunk0031,
  exactNonlinearExpressionsChunk0032, exactNonlinearExpressionsChunk0033, exactNonlinearExpressionsChunk0034, exactNonlinearExpressionsChunk0035, exactNonlinearExpressionsChunk0036, exactNonlinearExpressionsChunk0037, exactNonlinearExpressionsChunk0038, exactNonlinearExpressionsChunk0039,
  exactNonlinearExpressionsChunk0040, exactNonlinearExpressionsChunk0041, exactNonlinearExpressionsChunk0042, exactNonlinearExpressionsChunk0043, exactNonlinearExpressionsChunk0044, exactNonlinearExpressionsChunk0045, exactNonlinearExpressionsChunk0046, exactNonlinearExpressionsChunk0047,
  exactNonlinearExpressionsChunk0048, exactNonlinearExpressionsChunk0049, exactNonlinearExpressionsChunk0050, exactNonlinearExpressionsChunk0051, exactNonlinearExpressionsChunk0052, exactNonlinearExpressionsChunk0053, exactNonlinearExpressionsChunk0054, exactNonlinearExpressionsChunk0055,
  exactNonlinearExpressionsChunk0056, exactNonlinearExpressionsChunk0057, exactNonlinearExpressionsChunk0058, exactNonlinearExpressionsChunk0059, exactNonlinearExpressionsChunk0060, exactNonlinearExpressionsChunk0061, exactNonlinearExpressionsChunk0062, exactNonlinearExpressionsChunk0063,
  exactNonlinearExpressionsChunk0064, exactNonlinearExpressionsChunk0065, exactNonlinearExpressionsChunk0066, exactNonlinearExpressionsChunk0067, exactNonlinearExpressionsChunk0068, exactNonlinearExpressionsChunk0069, exactNonlinearExpressionsChunk0070, exactNonlinearExpressionsChunk0071,
  exactNonlinearExpressionsChunk0072, exactNonlinearExpressionsChunk0073, exactNonlinearExpressionsChunk0074, exactNonlinearExpressionsChunk0075, exactNonlinearExpressionsChunk0076, exactNonlinearExpressionsChunk0077, exactNonlinearExpressionsChunk0078, exactNonlinearExpressionsChunk0079,
  exactNonlinearExpressionsChunk0080, exactNonlinearExpressionsChunk0081, exactNonlinearExpressionsChunk0082, exactNonlinearExpressionsChunk0083, exactNonlinearExpressionsChunk0084, exactNonlinearExpressionsChunk0085, exactNonlinearExpressionsChunk0086, exactNonlinearExpressionsChunk0087,
  exactNonlinearExpressionsChunk0088, exactNonlinearExpressionsChunk0089, exactNonlinearExpressionsChunk0090, exactNonlinearExpressionsChunk0091, exactNonlinearExpressionsChunk0092, exactNonlinearExpressionsChunk0093, exactNonlinearExpressionsChunk0094, exactNonlinearExpressionsChunk0095,
  exactNonlinearExpressionsChunk0096, exactNonlinearExpressionsChunk0097, exactNonlinearExpressionsChunk0098, exactNonlinearExpressionsChunk0099, exactNonlinearExpressionsChunk0100, exactNonlinearExpressionsChunk0101, exactNonlinearExpressionsChunk0102, exactNonlinearExpressionsChunk0103,
  exactNonlinearExpressionsChunk0104, exactNonlinearExpressionsChunk0105, exactNonlinearExpressionsChunk0106, exactNonlinearExpressionsChunk0107, exactNonlinearExpressionsChunk0108, exactNonlinearExpressionsChunk0109, exactNonlinearExpressionsChunk0110, exactNonlinearExpressionsChunk0111,
  exactNonlinearExpressionsChunk0112, exactNonlinearExpressionsChunk0113, exactNonlinearExpressionsChunk0114, exactNonlinearExpressionsChunk0115, exactNonlinearExpressionsChunk0116, exactNonlinearExpressionsChunk0117, exactNonlinearExpressionsChunk0118, exactNonlinearExpressionsChunk0119,
  exactNonlinearExpressionsChunk0120, exactNonlinearExpressionsChunk0121, exactNonlinearExpressionsChunk0122, exactNonlinearExpressionsChunk0123, exactNonlinearExpressionsChunk0124, exactNonlinearExpressionsChunk0125, exactNonlinearExpressionsChunk0126, exactNonlinearExpressionsChunk0127,
  exactNonlinearExpressionsChunk0128, exactNonlinearExpressionsChunk0129, exactNonlinearExpressionsChunk0130, exactNonlinearExpressionsChunk0131, exactNonlinearExpressionsChunk0132, exactNonlinearExpressionsChunk0133, exactNonlinearExpressionsChunk0134, exactNonlinearExpressionsChunk0135,
  exactNonlinearExpressionsChunk0136, exactNonlinearExpressionsChunk0137, exactNonlinearExpressionsChunk0138, exactNonlinearExpressionsChunk0139, exactNonlinearExpressionsChunk0140, exactNonlinearExpressionsChunk0141, exactNonlinearExpressionsChunk0142, exactNonlinearExpressionsChunk0143,
  exactNonlinearExpressionsChunk0144, exactNonlinearExpressionsChunk0145, exactNonlinearExpressionsChunk0146, exactNonlinearExpressionsChunk0147, exactNonlinearExpressionsChunk0148, exactNonlinearExpressionsChunk0149, exactNonlinearExpressionsChunk0150, exactNonlinearExpressionsChunk0151,
  exactNonlinearExpressionsChunk0152, exactNonlinearExpressionsChunk0153, exactNonlinearExpressionsChunk0154, exactNonlinearExpressionsChunk0155, exactNonlinearExpressionsChunk0156, exactNonlinearExpressionsChunk0157, exactNonlinearExpressionsChunk0158, exactNonlinearExpressionsChunk0159,
  exactNonlinearExpressionsChunk0160, exactNonlinearExpressionsChunk0161, exactNonlinearExpressionsChunk0162, exactNonlinearExpressionsChunk0163, exactNonlinearExpressionsChunk0164, exactNonlinearExpressionsChunk0165, exactNonlinearExpressionsChunk0166, exactNonlinearExpressionsChunk0167,
  exactNonlinearExpressionsChunk0168, exactNonlinearExpressionsChunk0169, exactNonlinearExpressionsChunk0170, exactNonlinearExpressionsChunk0171, exactNonlinearExpressionsChunk0172, exactNonlinearExpressionsChunk0173, exactNonlinearExpressionsChunk0174, exactNonlinearExpressionsChunk0175,
  exactNonlinearExpressionsChunk0176, exactNonlinearExpressionsChunk0177, exactNonlinearExpressionsChunk0178, exactNonlinearExpressionsChunk0179, exactNonlinearExpressionsChunk0180, exactNonlinearExpressionsChunk0181, exactNonlinearExpressionsChunk0182, exactNonlinearExpressionsChunk0183,
  exactNonlinearExpressionsChunk0184, exactNonlinearExpressionsChunk0185, exactNonlinearExpressionsChunk0186, exactNonlinearExpressionsChunk0187, exactNonlinearExpressionsChunk0188, exactNonlinearExpressionsChunk0189, exactNonlinearExpressionsChunk0190, exactNonlinearExpressionsChunk0191,
  exactNonlinearExpressionsChunk0192, exactNonlinearExpressionsChunk0193, exactNonlinearExpressionsChunk0194, exactNonlinearExpressionsChunk0195, exactNonlinearExpressionsChunk0196, exactNonlinearExpressionsChunk0197, exactNonlinearExpressionsChunk0198, exactNonlinearExpressionsChunk0199,
  exactNonlinearExpressionsChunk0200, exactNonlinearExpressionsChunk0201, exactNonlinearExpressionsChunk0202, exactNonlinearExpressionsChunk0203, exactNonlinearExpressionsChunk0204, exactNonlinearExpressionsChunk0205, exactNonlinearExpressionsChunk0206, exactNonlinearExpressionsChunk0207,
  exactNonlinearExpressionsChunk0208, exactNonlinearExpressionsChunk0209, exactNonlinearExpressionsChunk0210, exactNonlinearExpressionsChunk0211, exactNonlinearExpressionsChunk0212, exactNonlinearExpressionsChunk0213, exactNonlinearExpressionsChunk0214, exactNonlinearExpressionsChunk0215,
  exactNonlinearExpressionsChunk0216, exactNonlinearExpressionsChunk0217, exactNonlinearExpressionsChunk0218, exactNonlinearExpressionsChunk0219, exactNonlinearExpressionsChunk0220, exactNonlinearExpressionsChunk0221, exactNonlinearExpressionsChunk0222, exactNonlinearExpressionsChunk0223,
  exactNonlinearExpressionsChunk0224, exactNonlinearExpressionsChunk0225, exactNonlinearExpressionsChunk0226, exactNonlinearExpressionsChunk0227, exactNonlinearExpressionsChunk0228, exactNonlinearExpressionsChunk0229, exactNonlinearExpressionsChunk0230, exactNonlinearExpressionsChunk0231,
  exactNonlinearExpressionsChunk0232, exactNonlinearExpressionsChunk0233, exactNonlinearExpressionsChunk0234, exactNonlinearExpressionsChunk0235, exactNonlinearExpressionsChunk0236, exactNonlinearExpressionsChunk0237, exactNonlinearExpressionsChunk0238, exactNonlinearExpressionsChunk0239,
  exactNonlinearExpressionsChunk0240, exactNonlinearExpressionsChunk0241, exactNonlinearExpressionsChunk0242, exactNonlinearExpressionsChunk0243, exactNonlinearExpressionsChunk0244, exactNonlinearExpressionsChunk0245, exactNonlinearExpressionsChunk0246, exactNonlinearExpressionsChunk0247,
  exactNonlinearExpressionsChunk0248, exactNonlinearExpressionsChunk0249, exactNonlinearExpressionsChunk0250, exactNonlinearExpressionsChunk0251, exactNonlinearExpressionsChunk0252, exactNonlinearExpressionsChunk0253, exactNonlinearExpressionsChunk0254, exactNonlinearExpressionsChunk0255
]

def expressionChunks : List (List FieldExpression) :=
  fullExpressionChunks ++ [exactNonlinearExpressionsChunk0256]

private theorem expressionShape :
    exactNonlinearExpressions = expressionChunks.flatten := rfl

private theorem fullLengthsChecked :
    fullExpressionChunks.all (fun chunk => decide (chunk.length = 32)) = true := by
  decide

private theorem fullLength (chunk : List FieldExpression)
    (member : chunk ∈ fullExpressionChunks) : chunk.length = 32 := by
  have checked := (List.all_eq_true.mp fullLengthsChecked) chunk member
  simpa only [decide_eq_true_eq] using checked

private theorem tailLength : exactNonlinearExpressionsChunk0256.length ≤ 32 := by
  decide

theorem sourceLength : exactNonlinearExpressions.length = 8213 := by
  decide

def fastExpressionAt (node : Nat) : FieldExpression :=
  (expressionChunks.getD (node / 32) []).getD (node % 32) (.constant 0)

theorem fastExpressionAt_eq_source (node : Nat) (bound : node < 8213) :
    fastExpressionAt node = exactNonlinearExpressions.getD node (.constant 0) := by
  have inRange : node < expressionChunks.flatten.length := by
    rw [← expressionShape, sourceLength]
    exact bound
  have lookup := getD_flatten_fixed_prefix fullExpressionChunks
    exactNonlinearExpressionsChunk0256 32 (by decide) fullLength
    tailLength (.constant 0) node (by simpa [expressionChunks] using inRange)
  calc
    fastExpressionAt node =
        (expressionChunks.getD (node / 32) []).getD (node % 32)
          (.constant 0) := rfl
    _ = expressionChunks.flatten.getD node (.constant 0) := by
      simpa only [expressionChunks] using lookup.symm
    _ = exactNonlinearExpressions.getD node (.constant 0) := by
      rw [expressionShape]

def fastDegreeCheck (node : Nat) : Bool :=
  if node < 8213 then
    decide (expressionDegree nodeDegree (fastExpressionAt node) ≤ nodeDegree node ∧
      expressionSafe nodeDegree (fastExpressionAt node))
  else false

theorem fastDegreeCheck_eq_degreeCheck (node : Nat) :
    fastDegreeCheck node = degreeCheck node := by
  by_cases bound : node < 8213
  · have sourceBound : node < exactNonlinearExpressions.length := by
      simpa only [sourceLength] using bound
    have found : exactNonlinearExpressions[node]? =
        some (exactNonlinearExpressions[node]'sourceBound) :=
      (List.getElem?_eq_some_getElem_iff sourceBound).mpr trivial
    have valueEq : fastExpressionAt node =
        (exactNonlinearExpressions[node]'sourceBound) := by
      rw [fastExpressionAt_eq_source node bound,
        List.getD_eq_getElem?_getD, found]
      rfl
    simp [fastDegreeCheck, degreeCheck, bound, found, valueEq]
  · have sourceBound : exactNonlinearExpressions.length ≤ node := by
      rw [sourceLength]
      omega
    have absent : exactNonlinearExpressions[node]? = none :=
      List.getElem?_eq_none sourceBound
    simp [fastDegreeCheck, degreeCheck, bound, absent]

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
