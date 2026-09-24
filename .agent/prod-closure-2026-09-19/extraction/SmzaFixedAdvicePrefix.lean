import SmzaChallengeStageTargets

/-! The selected-stage prefix vector determines every queried label, including
arbitrary postprocessing by the independently fixed other-stage oracle tables.
No selected-stage oracle answer is an input to the postprocessing operation.
This is the exact equality needed in the controlled-permutation proof. -/

namespace HegemonCrypto.SmallWood.SmzaFixedAdvicePrefix

open SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false

abbrev Stage := V8SmzaOracleParser.Stage
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Records (Input Output : Type*) :=
  V8Smz9CoherentMerkleGeometry.Records Input Output
abbrev Next := Stage → RawInput → Option (List (Stage × RawDigest))

def prefixTrace (next : Next) (role : Role) (fuel : Nat)
    (records : Records RawInput RawDigest) (queries : List RawInput) :=
  V8Smz9CoherentMerkleGeometry.extractTargets next records fuel (selectedTargets role queries)

def singleTrace (next : Next) (role : Role) (fuel : Nat)
    (records : Records RawInput RawDigest) (raw : RawInput) :
    V8Smz9CoherentMerkleGeometry.ExtractionTrace RawInput :=
  match selectedTarget role raw with
  | none => .missing
  | some target => V8Smz9CoherentMerkleGeometry.extract next records fuel target.1 target.2

/-- Equality of complete traces, not equality merely of a root digest or of
a successful-extraction bit. Malformed/nonselected raw queries return missing. -/
theorem prefix_equality_preserves_every_selected_trace
    (next : Next) (role : Role) (fuel : Nat)
    (left right : Records RawInput RawDigest) (queries : List RawInput)
    (same : prefixTrace next role fuel left queries = prefixTrace next role fuel right queries)
    (raw : RawInput) (member : raw ∈ queries) :
    singleTrace next role fuel left raw = singleTrace next role fuel right raw := by
  have all : ∀ inputs : List RawInput,
      prefixTrace next role fuel left inputs = prefixTrace next role fuel right inputs →
      ∀ input ∈ inputs, singleTrace next role fuel left input =
        singleTrace next role fuel right input := by
    intro inputs
    induction inputs with
    | nil => intro _ input impossible; simp at impossible
    | cons head tail ih =>
        intro equal input included
        cases parsed : selectedTarget role head with
        | none =>
            have tailEqual : prefixTrace next role fuel left tail =
                prefixTrace next role fuel right tail := by
              simp [prefixTrace, selectedTargets, parsed,
                V8Smz9CoherentMerkleGeometry.extractTargets] at equal ⊢
              exact equal
            rcases List.mem_cons.mp included with isHead | inTail
            · subst input
              simp [singleTrace, parsed]
            · exact ih tailEqual input inTail
        | some target =>
            have parts : V8Smz9CoherentMerkleGeometry.extract next left fuel target.1 target.2 =
                V8Smz9CoherentMerkleGeometry.extract next right fuel target.1 target.2 ∧
                prefixTrace next role fuel left tail = prefixTrace next role fuel right tail := by
                simpa [prefixTrace, selectedTargets, parsed,
                  V8Smz9CoherentMerkleGeometry.extractTargets] using equal
            rcases List.mem_cons.mp included with isHead | inTail
            · subst input
              simpa [singleTrace, parsed] using parts.1
            · exact ih parts.2 input inTail
  exact all queries same raw member

def enrichedLabel {Advice Label : Type*}
    (next : Next) (role : Role) (fuel : Nat)
    (code : Advice → RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace RawInput → Label) (advice : Advice)
    (records : Records RawInput RawDigest) (raw : RawInput) : Label :=
  code advice raw (singleTrace next role fuel records raw)

/-- Other independent oracle tables may be the entire Advice value. They
are fixed uniformly for both sides, so no extra instability is introduced. -/
theorem fixed_advice_postprocessing_preserves_prefix_equality
    {Advice Label : Type*} (next : Next) (role : Role) (fuel : Nat)
    (code : Advice → RawInput →
      V8Smz9CoherentMerkleGeometry.ExtractionTrace RawInput → Label) (advice : Advice)
    (left right : Records RawInput RawDigest) (queries : List RawInput)
    (same : prefixTrace next role fuel left queries = prefixTrace next role fuel right queries)
    (raw : RawInput) (member : raw ∈ queries) :
    enrichedLabel next role fuel code advice left raw =
      enrichedLabel next role fuel code advice right raw := by
  unfold enrichedLabel
  rw [prefix_equality_preserves_every_selected_trace next role fuel left right queries same raw member]

end

end HegemonCrypto.SmallWood.SmzaFixedAdvicePrefix
