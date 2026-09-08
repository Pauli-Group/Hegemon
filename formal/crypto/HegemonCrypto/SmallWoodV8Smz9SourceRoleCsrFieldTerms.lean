import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrCoefficients

namespace HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms

open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

/-- Pure field-accessor algebra. No candidate construction is unfolded here. -/
def fieldTermSum (pub rowField : Nat → F) (terms : List (Nat × Nat)) : F :=
  (terms.map fun term => actualCsrCoefficients pub term.2 * rowField term.1).sum

def roleCsrFieldKernel (pub rowField : Nat → F) (role limb : Nat) : F :=
  rowField (41536 + role + 64 * limb) +
    fieldTermSum pub rowField (liveRoleExtraTerms role limb) -
    actualCsrCoefficients pub (liveRoleTarget role limb)

theorem field_term_sum_matches_actual (pub : Nat → F) (words : List Nat)
    (terms : List (Nat × Nat)) :
    fieldTermSum pub (fun index => (words.getD index 0 : F)) terms =
      actualCsrTerms pub words terms := by rfl

theorem actual_role_csr_as_field_kernel (pub : Nat → F) (words : List Nat)
    (role : Fin 30) (limb : Fin 7) :
    actualCsrResidual pub words (expectedLiveCsrAttempt .roles (role.val * 7 + limb.val)) =
      roleCsrFieldKernel pub (fun index => (words.getD index 0 : F)) role.val limb.val := by
  have quotient : (role.val * 7 + limb.val) / 7 = role.val := by omega
  have remainder : (role.val * 7 + limb.val) % 7 = limb.val := by omega
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actual_csr_terms_cons,
    quotient,remainder,live_coefficient_1,one_mul,roleCsrFieldKernel,
    field_term_sum_matches_actual]

theorem actual_global_role_csr_as_field_kernel (pub : Nat → F) (words : List Nat)
    (role : Fin 30) (limb : Fin 7) :
    (exactCsrAttempts[19344 + role.val * 7 + limb.val]?).map
      (actualCsrResidual pub words) =
      some (roleCsrFieldKernel pub (fun index => (words.getD index 0 : F)) role.val limb.val) := by
  have address : 19344 + role.val * 7 + limb.val =
      LiveCsrFamily.roles.start + (role.val * 7 + limb.val) := by simp only [LiveCsrFamily.start]; omega
  rw [address,actual_live_csr_entry .roles
    ⟨role.val * 7 + limb.val,by change role.val * 7 + limb.val < 210; omega⟩,
    Option.map_some,actual_role_csr_as_field_kernel]


end
end HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
