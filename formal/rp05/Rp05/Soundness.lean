import SmzaRp05CurrentAcceptedSoundnessEndpoint

namespace HegemonCrypto.SmallWood.Rp05

/-- Public, type-preserving alias of the checked current accepted-invalid endpoint. -/
abbrev soundness :=
  @HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSoundnessEndpoint.actual_accepted_invalid_branch_mass_below_130_bits

example : @soundness =
    @HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSoundnessEndpoint.actual_accepted_invalid_branch_mass_below_130_bits :=
  rfl

end HegemonCrypto.SmallWood.Rp05
