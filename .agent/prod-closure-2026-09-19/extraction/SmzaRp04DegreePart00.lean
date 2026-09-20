import SmzaRp04DegreeData

namespace HegemonCrypto.SmallWood.SmzaRp04Degree
open SmzaRp04Components V8Smz9ProgramPolynomials V8Smz9ProgramCanonicality

theorem checked00 :
    checkIndexed_chunks degreePredicate 0 expressionChunks00 = true := by
  simp only [expressionChunks00, checkIndexed_chunks, Bool.and_eq_true]
  repeat' constructor

end HegemonCrypto.SmallWood.SmzaRp04Degree
