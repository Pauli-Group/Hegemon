import SmzaRp04ComponentsPart05

namespace HegemonCrypto.SmallWood.SmzaRp04Components
open Hegemon.Transaction.Poseidon2V8RelationProgram

def program : RelationProgramComponents :=
  { geometryWords := exactGeometryWords, publicMapVersionDomain := exactPublicMapVersionDomain
    poseidonParameterManifestDigest := exactPoseidonParameterManifestDigest
    nonlinearIdentities := exactNonlinearIdentities, linearCsrCompilerFamilies := exactLinearCsrCompilerFamilies
    hashScheduleAndCallRoles := exactHashScheduleAndCallRoles, bindingDescriptors := exactBindingDescriptors
    nonlinearExecutable := { expressions := exactNonlinearExpressions, roots := exactNonlinearRoots }
    csrExpressions := exactCsrExpressions, csrAttempts := exactCsrAttempts }

end HegemonCrypto.SmallWood.SmzaRp04Components
