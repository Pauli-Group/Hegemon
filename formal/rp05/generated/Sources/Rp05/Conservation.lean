import SmzaRp05CurrentInitializedHistoryConservationEndpoint

namespace HegemonCrypto.SmallWood.Rp05

/-- Public, type-preserving alias of the checked initialized-history conservation endpoint. -/
abbrev conservation :=
  @HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryConservationEndpoint.actual_current_initialized_history_conservation_failure_mass_bound

example : @conservation =
    @HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryConservationEndpoint.actual_current_initialized_history_conservation_failure_mass_bound :=
  rfl

end HegemonCrypto.SmallWood.Rp05
