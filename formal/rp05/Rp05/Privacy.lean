import Q38Rp05ZeroKnowledgeEndpoint

namespace HegemonCrypto.SmallWood.Rp05

/-- Explicit name for the checked initialized adaptive two-witness WI endpoint. -/
abbrev privacy_two_witness :=
  @HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint.current_rp05_initialized_two_witness_privacy

/-- Backwards-compatible alias retained for existing privacy callers. -/
abbrev privacy := @privacy_two_witness

example : @privacy_two_witness =
    @HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint.current_rp05_initialized_two_witness_privacy :=
  rfl

example : @privacy =
    @HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint.current_rp05_initialized_two_witness_privacy :=
  rfl

/-- The public current-RP05 real-versus-witness-free-simulator endpoint. -/
abbrev zero_knowledge :=
  @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator

example : @zero_knowledge =
    @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator :=
  rfl

/-- Exact program equality certifying that the public simulator is independent
of which witness schedule represents the same public strategy. -/
abbrev simulator_witness_independence :=
  @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.public_simulator_program_independent_of_witnesses

example : @simulator_witness_independence =
    @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.public_simulator_program_independent_of_witnesses :=
  rfl

/-- Rounded public loss derived from the exact endpoint and existing ledger. -/
abbrev zero_knowledge_loss_bound :=
  @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator_loss_bound

example : @zero_knowledge_loss_bound =
    @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator_loss_bound :=
  rfl

/-- Lifetime-cap specialization of the rounded public zero-knowledge bound. -/
abbrev zero_knowledge_lifetime_cap :=
  @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator_lifetime_cap

example : @zero_knowledge_lifetime_cap =
    @HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint.current_rp05_initialized_real_vs_public_simulator_lifetime_cap :=
  rfl

end HegemonCrypto.SmallWood.Rp05
