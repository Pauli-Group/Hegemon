import SmzaRp05CurrentNullifierCertificates
import SmzaRp05PrimitiveCollisionGameLuna
import Mathlib.Data.Real.Basic

/-!
The current generated RP05 relation supplies the source certificate needed
by the canonical primitive game. The adapter below derives the complete
twelve-word canonical input and all seven output words from the same accepted
packed witness. Input slots may differ across the two spends.

The probability endpoint is a reduction to the induced Poseidon2 collision
game, not a numerical hardness claim. It does not replace accepted-execution
extraction, historical authorization, or the primitive-security assumption.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open HegemonCrypto.SmallWood.SmzaRp05NullifierSource
open HegemonCrypto.SmallWood.SmzaRp05CurrentNullifierCertificates
open HegemonCrypto.SmallWood.SmzaRp05PrimitiveCollisionGameLuna
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open scoped Classical

set_option autoImplicit false

/-- The actual accepted active-slot data. No semantic digest equality,
canonical-preimage certificate, or position-range premise is supplied. -/
structure AcceptedActiveSpend where
  publicWords : List Nat
  packed : List Nat
  input : Fin 2
  accepted : program.AcceptsPacked publicWords packed
  active : publicWords.getD input.val 0 = 1

private theorem preimage_word_canonical (packed : List Nat) (input : Fin 2)
    (wordBound : ∀ n, packed.getD n 0 < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus)
    (rhoBound : ∀ n, spongeSourceWord packed (inputNoteFirstCall input) n < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus)
    (positionBound : projectPosition packed input.val < 2 ^ 32)
    (index : Fin 12) :
    (nullifierPreimage packed input).getD index.val 0 <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  have zeroBound : 0 <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by decide
  have memberBound : ∀ word ∈ nullifierPreimage packed input,
      word < Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
    intro word member
    unfold nullifierPreimage at member
    rcases List.mem_append.mp member with earlier | rho
    · rcases List.mem_append.mp earlier with key | fixed
      · obtain ⟨limb, _, equal⟩ := List.mem_map.mp key
        rw [← equal]
        exact wordBound _
      · rcases List.mem_cons.mp fixed with rfl | fixed
        · exact zeroBound
        · rcases List.mem_cons.mp fixed with rfl | fixed
          · exact zeroBound
          · have equal := List.mem_singleton.mp fixed
            rw [equal]
            exact lt_trans positionBound (by decide)
    · obtain ⟨limb, _, equal⟩ := List.mem_map.mp rho
      rw [← equal]
      exact rhoBound _
  have indexBound : index.val < (nullifierPreimage packed input).length := by
    rw [nullifier_preimage_length]
    exact index.isLt
  rw [List.getD_eq_getElem _ _ indexBound]
  exact memberBound _ (List.getElem_mem indexBound)

theorem accepted_preimage_word_canonical (spend : AcceptedActiveSpend)
    (index : Fin 12) :
    (nullifierPreimage spend.packed spend.input).getD index.val 0 <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus :=
  preimage_word_canonical spend.packed spend.input
    (fun n => packed_word_canonical spend.accepted.2.1 n)
    (fun n => sponge_source_word_canonical spend.accepted.2.1
      (inputNoteFirstCall spend.input) n)
    (accepted_position_lt_32 directionCertificate spend.accepted spend.input) index

def canonicalPreimage (spend : AcceptedActiveSpend) : CanonicalPreimage :=
  ⟨fun index => ⟨(nullifierPreimage spend.packed spend.input).getD index.val 0,
    accepted_preimage_word_canonical spend index⟩⟩

/-- The game receives the source's exact list, not merely an equal-length
or truncated projection. -/
theorem canonicalPreimage_toWords (spend : AcceptedActiveSpend) :
    (canonicalPreimage spend).toWords =
      nullifierPreimage spend.packed spend.input := by
  apply List.ext_getElem
  · simp
  · intro index leftBound rightBound
    simp only [CanonicalPreimage.toWords, List.getElem_ofFn, canonicalPreimage]
    exact List.getD_eq_getElem _ _ rightBound

def sourceCertifiedSpend (spend : AcceptedActiveSpend) :
    SourceCertifiedActiveSpend AcceptedActiveSpend where
  acceptance := spend
  preimage := canonicalPreimage spend
  publicNullifier := fun limb =>
    spend.publicWords.getD (4 + spend.input.val * 7 + limb.val) 0
  sourceCertificate := by
    intro limb
    unfold nullifierOutput
    rw [canonicalPreimage_toWords]
    exact accepted_current_active_public_nullifier spend.accepted
      spend.input spend.active limb

abbrev AcceptedSpendPair := AcceptedActiveSpend × AcceptedActiveSpend

def sourcePair (pair : AcceptedSpendPair) : ReplayPair AcceptedActiveSpend :=
  (sourceCertifiedSpend pair.1, sourceCertifiedSpend pair.2)

/-- Cross-slot equality of the complete public nullifier with different
source positions is the actual accepted-spend collision event. -/
def acceptedReplay (pair : AcceptedSpendPair) : Prop :=
  (∀ limb : Fin 7,
    pair.1.publicWords.getD (4 + pair.1.input.val * 7 + limb.val) 0 =
      pair.2.publicWords.getD (4 + pair.2.input.val * 7 + limb.val) 0) ∧
  projectPosition pair.1.packed pair.1.input.val ≠
    projectPosition pair.2.packed pair.2.input.val

/-- The general aliasing event also covers different key or rho words at
the same position; restricting to different positions would miss it. -/
def acceptedPreimageAlias (pair : AcceptedSpendPair) : Prop :=
  (∀ limb : Fin 7,
    pair.1.publicWords.getD (4 + pair.1.input.val * 7 + limb.val) 0 =
      pair.2.publicWords.getD (4 + pair.2.input.val * 7 + limb.val) 0) ∧
  nullifierPreimage pair.1.packed pair.1.input ≠
    nullifierPreimage pair.2.packed pair.2.input

theorem acceptedPreimageAlias_wins_primitive_game (pair : AcceptedSpendPair)
    (aliasing : acceptedPreimageAlias pair) :
    wins (toCollisionGameOutput (sourcePair pair)) := by
  constructor
  · intro equalInput
    have equalWords := congrArg CanonicalPreimage.toWords equalInput
    change (canonicalPreimage pair.1).toWords =
      (canonicalPreimage pair.2).toWords at equalWords
    rw [canonicalPreimage_toWords, canonicalPreimage_toWords] at equalWords
    exact aliasing.2 equalWords
  · intro limb
    change nullifierOutput (canonicalPreimage pair.1) limb =
      nullifierOutput (canonicalPreimage pair.2) limb
    exact ((sourceCertifiedSpend pair.1).sourceCertificate limb).symm.trans
      ((aliasing.1 limb).trans ((sourceCertifiedSpend pair.2).sourceCertificate limb))

theorem acceptedReplay_iff_sourceReplayWins (pair : AcceptedSpendPair) :
    acceptedReplay pair ↔ sourceReplayWins (sourcePair pair) := by
  constructor
  · rintro ⟨same, different⟩
    refine ⟨funext same, ?_⟩
    intro equalPosition
    apply different
    have equalNat := congrArg Fin.val equalPosition
    simpa [sourcePair, sourceCertifiedSpend, canonicalPreimage,
      nullifierPreimage] using equalNat
  · rintro ⟨same, different⟩
    refine ⟨fun limb => congrFun same limb, ?_⟩
    intro equalPosition
    apply different
    apply Fin.ext
    simpa [sourcePair, sourceCertifiedSpend, canonicalPreimage,
      nullifierPreimage] using equalPosition

/-- The primitive collision is obtained from the literal accepted RP05
source certificate even when the two active input slots differ. -/
theorem acceptedReplay_wins_primitive_game (pair : AcceptedSpendPair)
    (replay : acceptedReplay pair) :
    wins (toCollisionGameOutput (sourcePair pair)) :=
  sourceReplayWins_maps_to_primitiveWin (sourcePair pair)
    ((acceptedReplay_iff_sourceReplayWins pair).mp replay)

/-- The distribution stays on the original execution outcomes; the reduction
changes only their outputs and introduces no independence hypothesis. -/
structure FiniteAcceptedSpendAdversary where
  coins : Type
  [finiteCoins : Fintype coins]
  output : coins → AcceptedSpendPair
  mass : coins → ℚ
  mass_nonnegative : ∀ coin, 0 ≤ mass coin
  mass_normalized : ∑ coin, mass coin = 1

def inducedAdversary (adversary : FiniteAcceptedSpendAdversary) :
    FiniteReplayAdversary AcceptedActiveSpend where
  coins := adversary.coins
  finiteCoins := adversary.finiteCoins
  output := fun coin => sourcePair (adversary.output coin)
  mass := adversary.mass
  mass_nonnegative := adversary.mass_nonnegative
  mass_normalized := adversary.mass_normalized

noncomputable def acceptedReplayProbability
    (adversary : FiniteAcceptedSpendAdversary) : ℚ := by
  classical
  letI := adversary.finiteCoins
  exact ∑ coin, if acceptedReplay (adversary.output coin)
    then adversary.mass coin else 0

noncomputable def acceptedPreimageAliasProbability
    (adversary : FiniteAcceptedSpendAdversary) : ℚ := by
  classical
  letI := adversary.finiteCoins
  exact ∑ coin, if acceptedPreimageAlias (adversary.output coin)
    then adversary.mass coin else 0

/-- General distinct-preimage aliasing is charged to one induced primitive
adversary on the same coins and masses, including adaptive selection of the
pair. There is no unjustified birthday or independent-pair estimate. -/
theorem acceptedPreimageAliasProbability_le_primitiveCollisionProbability
    (adversary : FiniteAcceptedSpendAdversary) :
    acceptedPreimageAliasProbability adversary ≤
      primitiveCollisionProbability (inducedAdversary adversary) := by
  classical
  letI := adversary.finiteCoins
  unfold acceptedPreimageAliasProbability primitiveCollisionProbability eventProbability
  apply Finset.sum_le_sum
  intro coin _
  change (if acceptedPreimageAlias (adversary.output coin)
      then adversary.mass coin else 0) ≤
    (if wins (toCollisionGameOutput (sourcePair (adversary.output coin)))
      then adversary.mass coin else 0)
  by_cases aliasing : acceptedPreimageAlias (adversary.output coin)
  · have wins := acceptedPreimageAlias_wins_primitive_game
      (adversary.output coin) aliasing
    simp [aliasing, wins]
  · simp only [if_neg aliasing]
    split_ifs
    · exact adversary.mass_nonnegative coin
    · exact le_rfl

theorem acceptedReplayProbability_eq_sourceReplayProbability
    (adversary : FiniteAcceptedSpendAdversary) :
    acceptedReplayProbability adversary =
      sourceReplayProbability (inducedAdversary adversary) := by
  classical
  letI := adversary.finiteCoins
  unfold acceptedReplayProbability sourceReplayProbability eventProbability
  apply Finset.sum_congr rfl
  intro coin _
  simp only [inducedAdversary]
  rw [acceptedReplay_iff_sourceReplayWins]

/-- Source extraction and probability transport to the exact induced
primitive game. No unproved output-width security estimate is inserted. -/
theorem acceptedReplayProbability_le_primitiveCollisionProbability
    (adversary : FiniteAcceptedSpendAdversary) :
    acceptedReplayProbability adversary ≤
      primitiveCollisionProbability (inducedAdversary adversary) := by
  rw [acceptedReplayProbability_eq_sourceReplayProbability]
  exact sourceReplayProbability_le_primitiveCollisionProbability
    (inducedAdversary adversary)

/-- Conditional quantitative endpoint: the external assumption is exactly
the canonical current-domain primitive game for the induced adversary. It is
not inferred from seven output words or from permutation bijectivity. -/
theorem acceptedPreimageAliasProbability_le_primitiveAssumption
    (adversary : FiniteAcceptedSpendAdversary) (epsilon : ℚ)
    (primitiveAssumption : PrimitiveAdvantageAtMost
      (inducedAdversary adversary) epsilon) :
    acceptedPreimageAliasProbability adversary ≤ epsilon :=
  le_trans (acceptedPreimageAliasProbability_le_primitiveCollisionProbability adversary)
    primitiveAssumption

/-- Original execution outcomes can abort or fail to yield an accepted pair.
Such outcomes stay in the probability space and contribute zero to both
events; successful executions are never renormalized. -/
def originalAliasEvent (output : Option AcceptedSpendPair) : Prop :=
  ∃ pair, output = some pair ∧ acceptedPreimageAlias pair

def originalPrimitiveEvent (output : Option AcceptedSpendPair) : Prop :=
  ∃ pair, output = some pair ∧
    wins (toCollisionGameOutput (sourcePair pair))

theorem originalAliasEvent_implies_primitiveEvent
    (output : Option AcceptedSpendPair) (aliasing : originalAliasEvent output) :
    originalPrimitiveEvent output := by
  obtain ⟨pair, exactOutput, collision⟩ := aliasing
  exact ⟨pair, exactOutput, acceptedPreimageAlias_wins_primitive_game pair collision⟩

/-- Real Born weights on arbitrary finite original outcomes. The same
nonnegative mass appears on both sides. No rationality, normalization,
independence, or conditioning-on-acceptance premise is used. -/
theorem original_outcome_alias_mass_le_primitive_mass
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option AcceptedSpendPair) (mass : Outcome → ℝ)
    (nonnegative : ∀ outcome, 0 ≤ mass outcome) :
    (∑ outcome, if originalAliasEvent (output outcome) then mass outcome else 0) ≤
      ∑ outcome, if originalPrimitiveEvent (output outcome) then mass outcome else 0 := by
  classical
  apply Finset.sum_le_sum
  intro outcome _
  by_cases aliasing : originalAliasEvent (output outcome)
  · have primitive := originalAliasEvent_implies_primitiveEvent (output outcome) aliasing
    simp [aliasing, primitive]
  · simp only [if_neg aliasing]
    split_ifs
    · exact nonnegative outcome
    · exact le_rfl

/-- The external primitive assumption is placed on the very same real-valued
original outcome measure, including aborted and unsuccessful executions. -/
theorem original_outcome_alias_mass_le_primitive_assumption
    {Outcome : Type} [Fintype Outcome]
    (output : Outcome → Option AcceptedSpendPair) (mass : Outcome → ℝ)
    (nonnegative : ∀ outcome, 0 ≤ mass outcome) (epsilon : ℝ)
    (primitiveAssumption :
      (∑ outcome, if originalPrimitiveEvent (output outcome) then mass outcome else 0) ≤
        epsilon) :
    (∑ outcome, if originalAliasEvent (output outcome) then mass outcome else 0) ≤
      epsilon := by
  exact le_trans (original_outcome_alias_mass_le_primitive_mass output mass nonnegative)
    primitiveAssumption

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureNullifier
