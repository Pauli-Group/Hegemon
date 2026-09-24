import SmzaRp04DegreeData
import SmzaRp04DegreePart00
import SmzaRp04DegreePart01
import SmzaRp04DegreePart02
import SmzaRp04DegreePart03
import SmzaRp04DegreePart04
import SmzaRp04DegreePart05

namespace HegemonCrypto.SmallWood.SmzaRp04Degree
open SmzaRp04Components V8Smz9ProgramPolynomials V8Smz9ProgramCanonicality
set_option maxRecDepth 200000
set_option maxHeartbeats 800000

theorem certificate : DegreeCertificate exactNonlinearExpressions degree := by
  have hlen00 : expressionChunks00.flatten.length = 1376 := by decide
  have hlen01 : expressionChunks01.flatten.length = 1376 := by decide
  have hlen02 : expressionChunks02.flatten.length = 1376 := by decide
  have hlen03 : expressionChunks03.flatten.length = 1376 := by decide
  have hlen04 : expressionChunks04.flatten.length = 1376 := by decide
  have hprefix01 : (expressionChunks00 ++ expressionChunks01).flatten.length = 2752 := by
    simp only [List.flatten_append, List.length_append, hlen00, hlen01,
      Nat.reduceAdd]
  have hprefix02 : (expressionChunks00 ++ expressionChunks01 ++ expressionChunks02).flatten.length = 4128 := by
    simp only [List.flatten_append, List.length_append, hlen00, hlen01, hlen02,
      Nat.reduceAdd]
  have hprefix03 : (expressionChunks00 ++ expressionChunks01 ++ expressionChunks02 ++ expressionChunks03).flatten.length = 5504 := by
    simp only [List.flatten_append, List.length_append, hlen00, hlen01, hlen02,
      hlen03, Nat.reduceAdd]
  have hprefix04 : (expressionChunks00 ++ expressionChunks01 ++ expressionChunks02 ++ expressionChunks03 ++ expressionChunks04).flatten.length = 6880 := by
    simp only [List.flatten_append, List.length_append, hlen00, hlen01, hlen02,
      hlen03, hlen04, Nat.reduceAdd]
  have checked : checkIndexed_chunks degreePredicate 0 expressionChunks = true := by
    simp only [expressionChunks, checkIndexed_chunks_append, checked00,
      checked01, checked02, checked03, checked04, checked05,
      hlen00, hprefix01, hprefix02, hprefix03, hprefix04,
      Nat.zero_add, Bool.true_and]
  have checkedFlatten : checkIndexed degreePredicate 0 expressionChunks.flatten = true := by
    rw [checkIndexed_flatten]
    exact checked
  have hExpressions : expressionChunks.flatten = exactNonlinearExpressions := by
    unfold exactNonlinearExpressions
    apply congrArg List.flatten
    rfl
  have checkedExact : checkIndexed degreePredicate 0 exactNonlinearExpressions = true := by
    simpa only [hExpressions] using checkedFlatten
  simpa [DegreeCertificate, degreePredicate, checkIndexed_eq_true] using checkedExact

theorem root_degree : ∀ root, root ∈ exactNonlinearRoots → degree root ≤ 8 := by
  have checked : exactNonlinearRoots.all (fun root => decide (degree root ≤ 8)) = true := by decide
  simpa using checked

end HegemonCrypto.SmallWood.SmzaRp04Degree
